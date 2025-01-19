use dashmap::DashMap;
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
use parking_lot::RwLock;
use rustls::{Certificate, PrivateKey, ServerConfig};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{str::FromStr, sync::Arc};
use tokio::sync::oneshot;

// Metrics for monitoring cache performance
#[derive(Default)]
struct CacheMetrics {
    hits: std::sync::atomic::AtomicU64,
    misses: std::sync::atomic::AtomicU64,
}

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
            Certificate(x509.to_der().unwrap()),
            Certificate(ca_certificate.to_der().unwrap()),
        ];

        let server_configuration = ServerConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, PrivateKey(private_key.private_key_to_der().unwrap()))
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
        let authority_host = authority.host();
        let common_name = if authority_host.len() > 64 {
            "privaxy_cn_too_long.local"
        } else {
            authority_host
        };

        x509_name.append_entry_by_text("CN", common_name).unwrap();
        let x509_name = x509_name.build();
        request_builder.set_subject_name(&x509_name).unwrap();
        request_builder.sign(key_pair, MessageDigest::sha256()).unwrap();
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
        cert_builder.set_issuer_name(ca_cert.subject_name()).unwrap();
        cert_builder.set_pubkey(private_key).unwrap();

        let not_before = {
            let current_time = SystemTime::now();
            let since_epoch = current_time
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards");
            Asn1Time::from_unix(since_epoch.as_secs() as i64 - 60).unwrap()
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

        cert_builder.append_extension(subject_alternative_name).unwrap();

        let subject_key_identifier = SubjectKeyIdentifier::new()
            .build(&cert_builder.x509v3_context(Some(ca_cert), None))
            .unwrap();
        cert_builder.append_extension(subject_key_identifier).unwrap();

        let auth_key_identifier = AuthorityKeyIdentifier::new()
            .keyid(false)
            .issuer(false)
            .build(&cert_builder.x509v3_context(Some(ca_cert), None))
            .unwrap();
        cert_builder.append_extension(auth_key_identifier).unwrap();

        cert_builder.sign(ca_key_pair, MessageDigest::sha256()).unwrap();
        cert_builder.build()
    }
}

type PendingCertificates = Arc<DashMap<Authority, oneshot::Sender<SignedWithCaCert>>>;

#[derive(Clone)]
pub struct CertCache {
    cache: Arc<DashMap<Authority, SignedWithCaCert>>,
    pending: PendingCertificates,
    metrics: Arc<CacheMetrics>,
    private_key: Arc<RwLock<PKey<Private>>>,
    ca_certificate: Arc<RwLock<X509>>,
    ca_private_key: Arc<RwLock<PKey<Private>>>,
}

impl CertCache {
    pub fn new(ca_certificate: X509, ca_private_key: PKey<Private>) -> Self {
        let cache = Arc::new(DashMap::new());
        let pending = Arc::new(DashMap::new());
        let metrics = Arc::new(CacheMetrics::default());
        
        let private_key = Arc::new(RwLock::new({
            let rsa = Rsa::generate(2048).unwrap();
            PKey::from_rsa(rsa).unwrap()
        }));

        let instance = Self {
            cache,
            pending,
            metrics,
            private_key,
            ca_certificate: Arc::new(RwLock::new(ca_certificate)),
            ca_private_key: Arc::new(RwLock::new(ca_private_key)),
        };

        // create cert in bg
        let cache_clone = instance.clone();
        tokio::spawn(async move {
            cache_clone.certificate_generator().await;
        });

        instance
    }

    async fn certificate_generator(&self) {
        loop {
            // check active cert gens
            for entry in self.pending.iter() {
                let authority = entry.key().clone();
                if !self.cache.contains_key(&authority) {
                    let certificate = self.generate_certificate(authority.clone()).await;
                    if let Some((_, sender)) = self.pending.remove(&authority) {
                        let _ = sender.send(certificate.clone());
                    }
                    self.cache.insert(authority, certificate);
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    async fn generate_certificate(&self, authority: Authority) -> SignedWithCaCert {
        let private_key = self.private_key.read().clone();
        let ca_certificate = self.ca_certificate.read().clone();
        let ca_private_key = self.ca_private_key.read().clone();

        tokio::task::spawn_blocking(move || {
            SignedWithCaCert::new(authority, private_key, ca_certificate, ca_private_key)
        })
        .await
        .unwrap()
    }

    pub async fn get(&self, authority: Authority) -> SignedWithCaCert {
        // check cache first
        if let Some(cert) = self.cache.get(&authority) {
            self.metrics.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return cert.clone();
        }

        self.metrics.misses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // check if certificate generation is pending
        if let Some(_) = self.pending.get(&authority) {
            let (tx, rx) = oneshot::channel();
            self.pending.insert(authority.clone(), tx);
            return rx.await.unwrap();
        }

        // generate new cert
        let certificate = self.generate_certificate(authority.clone()).await;
        self.cache.insert(authority, certificate.clone());
        certificate
    }

    pub fn get_metrics(&self) -> (u64, u64) {
        (
            self.metrics.hits.load(std::sync::atomic::Ordering::Relaxed),
            self.metrics.misses.load(std::sync::atomic::Ordering::Relaxed),
        )
    }
}
