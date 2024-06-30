use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::fs;

use super::ConfigurationResult;
use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    hash::MessageDigest,
    pkey::{PKey, PKeyRef, Private},
    x509::{
        extension::{
            AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectAlternativeName,
            SubjectKeyIdentifier,
        },
        X509NameBuilder, X509Ref, X509Req, X509ReqBuilder, X509,
    },
};
use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde_as]
/// Network configuration for Privaxy
pub struct NetworkConfig {
    /// Bind address for the proxy server.
    pub bind_addr: String,
    /// Port for the proxy server.
    pub proxy_port: u16,
    /// Port for the web server.
    pub web_port: u16,
    /// Enable TLS for the web server.
    pub tls: bool,
    /// Path to user specified TLS certificate
    /// If not set, a self-signed certificate will be generated
    /// using the root CA.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_cert_path: Option<String>,
    /// Path to user specified TLS certificate key
    /// If not set, a self-signed key will be generated
    /// using the root CA.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_key_path: Option<String>,
    /// URL to listen on. Only used when TLS is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen_url: Option<String>,
}

#[derive(Error, Debug)]
pub enum NetworkConfigError {
    #[error("bind address error: {0}")]
    BindAddressError(String),
    #[error("proxy port error: {0}")]
    ProxyPortError(String),
    #[error("web port error: {0}")]
    WebPortError(String),
    #[error("port collision: {0}")]
    PortCollisionError(String),
    #[error("failed to read TLS certificate: {0}")]
    TlsCertError(String),
    #[error("failed to read TLS certificate key: {0}")]
    TlsKeyError(String),
}

impl NetworkConfig {
    pub(crate) fn validate(&self) -> super::ConfigurationResult<()> {
        if self.proxy_port == 0 {
            return Err(
                NetworkConfigError::ProxyPortError("Proxy port cannot be 0".to_string()).into(),
            );
        };
        if self.web_port == 0 {
            return Err(
                NetworkConfigError::WebPortError("Web port cannot be 0".to_string()).into(),
            );
        };
        if self.proxy_port == self.web_port {
            return Err(NetworkConfigError::PortCollisionError(
                "Proxy and web ports cannot be the same".to_string(),
            )
            .into());
        };
        if self.bind_addr.is_empty() {
            return Err(NetworkConfigError::BindAddressError(
                "Bind address cannot be empty".to_string(),
            )
            .into());
        };
        let addr_regex = Regex::new(r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$");
        if !addr_regex.unwrap().is_match(&self.bind_addr) {
            return Err(NetworkConfigError::BindAddressError(
                format!("Invalid bind address: {}", self.bind_addr).to_string(),
            )
            .into());
        };
        Ok(())
    }

    async fn read_tls_cert(&self) -> ConfigurationResult<X509> {
        if let Some(cert_path) = &self.tls_cert_path {
            match fs::try_exists(cert_path).await {
                Ok(exists) => {
                    if !exists {
                        return Err(NetworkConfigError::TlsCertError(
                            "TLS cert does not exist in path".to_string(),
                        )
                        .into());
                    }
                }
                Err(err) => {
                    return Err(err.into());
                }
            };
            if let Ok(cert) = fs::read(cert_path).await {
                if cert.is_empty() {
                    panic!("TLS cert is empty")
                }
                let pem_cert = match X509::from_pem(&cert) {
                    Ok(key) => key,
                    Err(err) => {
                        panic!("Failed to parse TLS cert: {err}");
                    }
                };
                Ok(pem_cert)
            } else {
                panic!("Failed to read TLS cert");
            }
        } else {
            Err(NetworkConfigError::TlsCertError("No TLS cert in path".to_string()).into())
        }
    }

    pub(crate) async fn write_tls_cert(&self, cert: X509) -> ConfigurationResult<()> {
        if let Some(cert_path) = &self.tls_cert_path {
            fs::write(cert_path, cert.to_pem().unwrap()).await?;
            Ok(())
        } else {
            Err(NetworkConfigError::TlsCertError("No TLS cert in path".to_string()).into())
        }
    }

    async fn read_tls_key(&self) -> ConfigurationResult<PKey<Private>> {
        if let Some(key_path) = &self.tls_key_path {
            match fs::try_exists(key_path).await {
                Ok(exists) => {
                    if !exists {
                        return Err(NetworkConfigError::TlsKeyError(
                            "TLS key does not exist in path".to_string(),
                        )
                        .into());
                    }
                }
                Err(err) => {
                    return Err(err.into());
                }
            };
            if let Ok(cert) = fs::read(key_path).await {
                if cert.is_empty() {
                    panic!("TLS key is empty")
                }
                let pem_key = match PKey::private_key_from_pem(&cert) {
                    Ok(key) => key,
                    Err(err) => {
                        panic!("Failed to parse TLS key: {err}");
                    }
                };
                Ok(pem_key)
            } else {
                panic!("Failed to read TLS Key");
            }
        } else {
            Err(NetworkConfigError::TlsKeyError("No TLS key in path".to_string()).into())
        }
    }
    pub(crate) async fn write_tls_key(&self, key: PKey<Private>) -> ConfigurationResult<()> {
        if let Some(key_path) = &self.tls_key_path {
            fs::write(key_path, key.private_key_to_pem_pkcs8().unwrap()).await?;
            Ok(())
        } else {
            Err(NetworkConfigError::TlsKeyError("No TLS key in path".to_string()).into())
        }
    }
    pub(crate) async fn get_tls_cert(&self) -> ConfigurationResult<X509> {
        match self.read_tls_cert().await {
            Ok(cert) => Ok(cert),
            Err(err) => {
                log::error!("Failed to read TLS certificate: {err}");
                return Err(err);
            }
        }
    }

    pub(crate) async fn get_tls_key(&self) -> ConfigurationResult<PKey<Private>> {
        let key = match self.read_tls_key().await {
            Ok(key) => Ok(key),
            Err(err) => {
                log::error!("Failed to read TLS key: {err}");
                return Err(err);
            }
        };
        key
    }

    pub(crate) async fn gen_self_signed_tls_cert(
        &self,
        ca_cert: X509,
        ca_key: PKey<Private>,
    ) -> ConfigurationResult<X509> {
        let rsa_key = openssl::rsa::Rsa::generate(2048).unwrap();
        let private_key = PKey::from_rsa(rsa_key).unwrap();
        self.write_tls_key(private_key.clone()).await.unwrap();
        let fqdn = self.listen_url.clone().unwrap_or("p.p".to_string());
        let csr = build_certificate_request(&private_key, fqdn.clone());
        let cert = build_ca_signed_cert(
            csr,
            self.bind_addr.to_string(),
            &ca_cert,
            &ca_key,
            &private_key,
        );
        self.write_tls_cert(cert.clone()).await.unwrap();
        Ok(cert)
    }

    pub(crate) async fn read_or_create_tls_cert(
        &self,
        ca_cert: X509,
        ca_key: PKey<Private>,
    ) -> ConfigurationResult<X509> {
        if let Ok(cert) = self.get_tls_cert().await {
            Ok(cert)
        } else {
            self.gen_self_signed_tls_cert(ca_cert, ca_key).await
        }
    }

    pub(crate) fn parsed_ip_address(&self) -> IpAddr {
        let ip_addr = match IpAddr::from_str(self.bind_addr.as_str()) {
            Ok(ip) => ip,
            Err(_) => Ipv4Addr::new(0, 0, 0, 0).into(),
        };
        ip_addr
    }
}

fn build_certificate_request(key_pair: &PKey<Private>, authority: String) -> X509Req {
    let mut request_builder = X509ReqBuilder::new().unwrap();
    request_builder.set_pubkey(key_pair).unwrap();

    let mut x509_name = X509NameBuilder::new().unwrap();

    // Only 64 characters are allowed in the CN field.
    // (ub-common-name INTEGER ::= 64), browsers are not using CN anymore but uses SANs instead.
    // Let's use a shorter entry.
    // RFC 3280.
    let common_name = if authority.len() > 64 {
        "privaxy_cn_too_long.local"
    } else {
        authority.as_ref()
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
    req: X509Req,
    bind_addr: String,
    ca_cert: &X509Ref,
    ca_key_pair: &PKeyRef<Private>,
    private_key: &PKey<Private>,
) -> X509 {
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
        let since_epoch = current_time.duration_since(UNIX_EPOCH).unwrap();
        // patch NotValidBefore
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
    let subject_alternative_name = SubjectAlternativeName::new()
        .ip(bind_addr.as_str().into())
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
