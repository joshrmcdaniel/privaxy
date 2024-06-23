use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
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
}
