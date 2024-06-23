use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use thiserror::Error;
use tokio::fs;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Ca {
    #[serde(default)]
    pub(super) ca_certificate: Option<String>,
    #[serde(default)]
    pub(super) ca_private_key: Option<String>,
    #[serde(default)]
    pub(super) ca_certificate_path: Option<String>,
    #[serde(default)]
    pub(super) ca_private_key_path: Option<String>,
}

#[derive(Error, Debug)]
pub enum CaError {
    #[error("failed to read CA certificate: {0}")]
    CaCertificateNotFound(String),
    #[error("failed to read CA private key: {0}")]
    CaPrivateKeyNotFound(String),
    #[error("issue with private key: {0}")]
    CaPrivateKeyError(String),
    #[error("private key does not match the certificate")]
    PrivateKeyMismatch,
}

impl Ca {
    pub(crate) async fn validate(&self) -> Result<(), super::ConfigurationError> {
        let ca_cert = match self.get_ca_certificate().await {
            Ok(cert) => cert,
            Err(err) => {
                return Err(CaError::CaCertificateNotFound(format!(
                    "Failed to read CA certificate: {err}"
                ))
                .into())
            }
        };
        let ca_pkey = match self.get_ca_private_key().await {
            Ok(pkey) => pkey,
            Err(err) => {
                return Err(CaError::CaPrivateKeyNotFound(format!(
                    "Failed to read CA private key: {err}"
                ))
                .into())
            }
        };
        let ca_pub_key = match ca_cert.public_key() {
            Ok(key) => key,
            Err(err) => {
                return Err(CaError::CaPrivateKeyError(format!(
                    "Failed to convert CA private key to PEM: {err}"
                ))
                .into())
            }
        };
        if ca_pkey.public_eq(&ca_pub_key) {
            Ok(())
        } else {
            Err(CaError::PrivateKeyMismatch.into())
        }
    }

    pub async fn get_ca_certificate(&self) -> super::ConfigurationResult<X509> {
        if let Some(ref ca_certificate_path) = self.ca_certificate_path {
            let ca_path = PathBuf::from(ca_certificate_path);
            match fs::read(&ca_path).await {
                Ok(ca_cert) => {
                    let cert = X509::from_pem(&ca_cert)
                        .map_err(|_| super::ConfigurationError::DirectoryNotFound)?;
                    Ok(cert)
                }
                Err(err) => Err(super::ConfigurationError::FileSystemError(err)),
            }
        } else if let Some(ref ca_certificate) = self.ca_certificate {
            let ca_cert = X509::from_pem(ca_certificate.as_bytes())
                .map_err(|_| super::ConfigurationError::DirectoryNotFound)?;
            Ok(ca_cert)
        } else {
            Err(super::ConfigurationError::DirectoryNotFound)
        }
    }

    pub async fn set_ca_certificate(
        &mut self,
        ca_certificate: &str,
    ) -> super::ConfigurationResult<()> {
        if let Some(ref ca_certificate_path) = &self.ca_certificate_path {
            let ca_path = PathBuf::from(ca_certificate_path);
            match fs::write(&ca_path, ca_certificate.as_bytes()).await {
                Ok(()) => Ok(()),
                Err(err) => Err(super::ConfigurationError::FileSystemError(err)),
            }
        } else {
            self.ca_certificate = Some(ca_certificate.to_string());
            Ok(())
        }
    }

    pub async fn get_ca_private_key(&self) -> super::ConfigurationResult<PKey<Private>> {
        if let Some(ref ca_private_key_path) = self.ca_private_key_path {
            let ca_path = PathBuf::from(ca_private_key_path);
            match fs::read(&ca_path).await {
                Ok(ca_key) => {
                    let pkey = PKey::private_key_from_pem(&ca_key)
                        .map_err(|_| super::ConfigurationError::DirectoryNotFound)?;
                    Ok(pkey)
                }
                Err(err) => Err(super::ConfigurationError::FileSystemError(err)),
            }
        } else if let Some(ref ca_private_key) = self.ca_private_key {
            let pkey = PKey::private_key_from_pem(ca_private_key.as_bytes())
                .map_err(|_| super::ConfigurationError::DirectoryNotFound)?;
            Ok(pkey)
        } else {
            Err(super::ConfigurationError::DirectoryNotFound)
        }
    }

    pub async fn set_ca_private_key(
        &mut self,
        ca_private_key: &str,
    ) -> super::ConfigurationResult<()> {
        if let Some(ref ca_private_key_path) = &self.ca_private_key_path {
            let ca_path = PathBuf::from(ca_private_key_path);
            match fs::write(&ca_path, ca_private_key.as_bytes()).await {
                Ok(()) => Ok(()),
                Err(err) => Err(super::ConfigurationError::FileSystemError(err)),
            }
        } else {
            self.ca_private_key = Some(ca_private_key.to_string());
            Ok(())
        }
    }
}
