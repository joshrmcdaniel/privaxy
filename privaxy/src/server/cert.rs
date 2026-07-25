use http::uri::Authority;
use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    hash::MessageDigest,
    pkey::{PKey, PKeyRef, Private},
    rsa::Rsa,
    x509::{
        extension::{
            AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectAlternativeName,
            SubjectKeyIdentifier,
        },
        X509NameBuilder, X509Ref, X509Req, X509ReqBuilder, X509,
    },
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{str::FromStr, sync::Arc};
use tokio::sync::Mutex;
use uluru::LRUCache;

const MAX_CACHED_CERTIFICATES: usize = 1_000;

#[derive(Clone)]
pub struct SignedWithCaCert {
    authority: Authority,
    pub server_configuration: ServerConfig,
}

impl SignedWithCaCert {
    pub(super) fn new(
        authority: Authority,
        private_key: PKey<Private>,
        ca_certificate: X509,
        ca_private_key: PKey<Private>,
    ) -> Self {
        let x509 =
            Self::build_ca_signed_cert(&ca_certificate, &ca_private_key, &authority, &private_key);

        let certs = vec![
            CertificateDer::from(x509.to_der().unwrap()),
            CertificateDer::from(ca_certificate.to_der().unwrap()),
        ];

        // rustls 0.23 folded the cipher-suite / kx-group / protocol-version
        // selection into safe defaults on `ServerConfig::builder()`, so the
        // explicit `with_safe_default_*` chain is gone. The crypto provider
        // (ring) is installed once as the process default at startup.
        let private_key =
            PrivateKeyDer::try_from(private_key.private_key_to_der().unwrap()).unwrap();
        let server_configuration = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, private_key)
            .unwrap();

        Self {
            authority,
            server_configuration,
        }
    }

    fn build_certificate_request(key_pair: &PKey<Private>, authority: &Authority) -> X509Req {
        let mut request_builder = X509ReqBuilder::new().unwrap();
        request_builder.set_pubkey(key_pair).unwrap();

        let mut x509_name = X509NameBuilder::new().unwrap();

        // Only 64 characters are allowed in the CN field.
        // (ub-common-name INTEGER ::= 64), browsers are not using CN anymore but uses SANs instead.
        // Let's use a shorter entry.
        // RFC 3280.
        let authority_host = authority.host();
        let common_name = if authority_host.len() > 64 {
            "privaxy_cn_too_long.local"
        } else {
            authority_host
        };

        x509_name.append_entry_by_text("CN", common_name).unwrap();
        let x509_name = x509_name.build();
        request_builder.set_subject_name(&x509_name).unwrap();

        request_builder
            .sign(key_pair, MessageDigest::sha256())
            .unwrap();

        request_builder.build()
    }

    fn build_ca_signed_cert(
        ca_cert: &X509Ref,
        ca_key_pair: &PKeyRef<Private>,
        authority: &Authority,
        private_key: &PKey<Private>,
    ) -> X509 {
        let req = Self::build_certificate_request(private_key, authority);

        let mut cert_builder = X509::builder().unwrap();
        cert_builder.set_version(2).unwrap();

        let serial_number = {
            let mut serial = BigNum::new().unwrap();
            serial.rand(159, MsbOption::MAYBE_ZERO, false).unwrap();
            serial.to_asn1_integer().unwrap()
        };

        cert_builder.set_serial_number(&serial_number).unwrap();
        cert_builder.set_subject_name(req.subject_name()).unwrap();
        cert_builder
            .set_issuer_name(ca_cert.subject_name())
            .unwrap();
        cert_builder.set_pubkey(private_key).unwrap();

        let not_before = {
            let current_time = SystemTime::now();
            let since_epoch = current_time
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards");
            // patch NotValidBefore
            // try_into() coerces to the platform's time_t (i64 on 64-bit
            // targets, i32 on 32-bit MIPS glibc) instead of a hardcoded cast.
            #[allow(clippy::useless_conversion)]
            Asn1Time::from_unix((since_epoch.as_secs() as i64 - 60).try_into().unwrap()).unwrap()
        };
        cert_builder.set_not_before(&not_before).unwrap();

        let not_after = Asn1Time::days_from_now(365).unwrap();
        cert_builder.set_not_after(&not_after).unwrap();

        cert_builder
            .append_extension(BasicConstraints::new().build().unwrap())
            .unwrap();

        cert_builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .non_repudiation()
                    .digital_signature()
                    .key_encipherment()
                    .build()
                    .unwrap(),
            )
            .unwrap();

        let subject_alternative_name = match std::net::IpAddr::from_str(authority.host()) {
            Ok(_ip_addr) => {
                let mut san = SubjectAlternativeName::new();
                san.ip(authority.host());

                san
            }
            Err(_err) => {
                let mut san = SubjectAlternativeName::new();
                san.dns(authority.host());
                san
            }
        }
        .build(&cert_builder.x509v3_context(Some(ca_cert), None))
        .unwrap();

        cert_builder
            .append_extension(subject_alternative_name)
            .unwrap();

        let subject_key_identifier = SubjectKeyIdentifier::new()
            .build(&cert_builder.x509v3_context(Some(ca_cert), None))
            .unwrap();
        cert_builder
            .append_extension(subject_key_identifier)
            .unwrap();

        let auth_key_identifier = AuthorityKeyIdentifier::new()
            .keyid(false)
            .issuer(false)
            .build(&cert_builder.x509v3_context(Some(ca_cert), None))
            .unwrap();
        cert_builder.append_extension(auth_key_identifier).unwrap();

        cert_builder
            .sign(ca_key_pair, MessageDigest::sha256())
            .unwrap();

        cert_builder.build()
    }
}

#[derive(Clone)]
pub struct CertCache {
    cache: Arc<Mutex<LRUCache<SignedWithCaCert, MAX_CACHED_CERTIFICATES>>>,
    // We use a single RSA key for all certificates.
    private_key: PKey<Private>,
    ca_certificate: X509,
    ca_private_key: PKey<Private>,
}

impl CertCache {
    pub fn new(ca_certificate: X509, ca_private_key: PKey<Private>) -> Self {
        Self {
            cache: Arc::new(Mutex::new(LRUCache::default())),
            private_key: {
                let rsa: Rsa<Private> = Rsa::generate(2048).unwrap();
                PKey::from_rsa(rsa).unwrap()
            },
            ca_certificate,
            ca_private_key,
        }
    }

    async fn insert(&self, certificate: SignedWithCaCert) {
        let mut cache = self.cache.lock().await;
        cache.insert(certificate);
    }

    pub async fn get(&self, authority: Authority) -> SignedWithCaCert {
        let mut cache = self.cache.lock().await;

        match cache.find(|cert| cert.authority == authority) {
            Some(certificate) => certificate.clone(),
            None => {
                // We release the previously acquired lock early as `insert`, which we will call just
                // afterwards also waits to acquire a lock.
                std::mem::drop(cache);

                let private_key = self.private_key.clone();

                let ca_certificate = self.ca_certificate.clone();
                let ca_private_key = self.ca_private_key.clone();

                // This operation is somewhat CPU intensive and on some lower powered machines,
                // not running it inside of a thread pool may cause it to block the executor for too long.
                let certificate = tokio::task::spawn_blocking(move || {
                    SignedWithCaCert::new(authority, private_key, ca_certificate, ca_private_key)
                })
                .await
                .unwrap();

                self.insert(certificate.clone()).await;
                certificate
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::rsa::Rsa;

    /// Building a leaf certificate signed by the CA and assembling its rustls
    /// `ServerConfig` must succeed without panicking. Post-upgrade to rustls
    /// 0.23 this also exercises that a `CryptoProvider` is installed before the
    /// `ServerConfig` builder runs.
    #[test]
    fn builds_ca_signed_server_config() {
        // rustls 0.23 requires a process-default CryptoProvider before any
        // `ServerConfig::builder()`; production installs this once at startup.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let (ca_certificate, ca_private_key) = crate::ca::make_ca_certificate();
        let leaf_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let authority = Authority::from_static("example.com");

        let signed =
            SignedWithCaCert::new(authority.clone(), leaf_key, ca_certificate, ca_private_key);

        assert_eq!(signed.authority, authority);
    }
}
