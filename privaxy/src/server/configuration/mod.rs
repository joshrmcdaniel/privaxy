use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, time::Duration};
use thiserror::Error;
use tokio::fs;
mod ca;
mod filter;
mod network;
mod updater;
pub use ca::*;
use dirs::home_dir;
pub use filter::*;
use futures::future::try_join_all;
pub use network::*;
use std::env;
use std::path::{Path, PathBuf};
pub use updater::*;
pub(crate) type ConfigurationResult<T> = Result<T, ConfigurationError>;
pub(crate) const FILTERS_UPDATE_AFTER: Duration = Duration::from_secs(60 * 10);

/// Filename of the configuration file.
pub(crate) const CONFIGURATION_FILE_NAME: &str = "config";

/// Default configuration directory name.
const CONFIGURATION_DIRECTORY_NAME: &str = ".privaxy";

#[derive(Error, Debug)]
pub enum ConfigurationError {
    #[error("NetworkConfigError error: {0}")]
    NetworkConfigError(#[from] NetworkConfigError),
    #[error("CaError error: {0}")]
    CaError(#[from] CaError),
    #[error("an error occured while trying to deserialize configuration file")]
    DeserializeError(#[from] toml::de::Error),
    #[error("this directory was not found")]
    DirectoryNotFound,
    #[error("file system error")]
    FileSystemError(#[from] std::io::Error),
    #[error("data store disconnected")]
    UnableToRetrieveDefaultFilters(#[from] reqwest::Error),
    #[error("unable to decode filter bytes, bad utf8 data")]
    UnableToDecodeFilterbytes(#[from] std::str::Utf8Error),
    #[error("unable to decode pem data")]
    UnableToDecodePem(#[from] openssl::error::ErrorStack),
    #[error("filter error: {0}")]
    FilterError(String),
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Configuration {
    pub exclusions: BTreeSet<String>,
    pub custom_filters: Vec<String>,
    pub ca: Ca,
    pub network: NetworkConfig,
    pub filters: Vec<Filter>,
}

#[derive(Error, Debug)]
pub enum PrivaxyError {
    #[error("ConfigurationError: {0}")]
    ConfigurationError(#[from] ConfigurationError),
}

impl Configuration {
    pub async fn read_from_home() -> ConfigurationResult<Self> {
        let configuration_directory = get_config_directory();
        let configuration_file_path = configuration_directory.join(CONFIGURATION_FILE_NAME);

        if let Err(err) = fs::metadata(&configuration_directory).await {
            if err.kind() == std::io::ErrorKind::NotFound {
                log::debug!("Configuration directory not found, creating one");

                fs::create_dir(&configuration_directory).await?;

                let configuration = Self::new_default().await?;
                configuration.save().await?;

                return Ok(configuration);
            } else {
                return Err(ConfigurationError::FileSystemError(err));
            }
        };

        match fs::read(&configuration_file_path).await {
            Ok(bytes) => Ok(toml::from_str(std::str::from_utf8(&bytes)?)?),
            Err(err) => {
                log::debug!("Configuration file not found, creating one");

                if err.kind() == std::io::ErrorKind::NotFound {
                    let configuration = Self::new_default().await?;
                    configuration.save().await?;

                    Ok(configuration)
                } else {
                    Err(ConfigurationError::FileSystemError(err))
                }
            }
        }
    }

    pub async fn save(&self) -> ConfigurationResult<()> {
        let configuration_directory = get_config_directory();
        let configuration_file_path = configuration_directory.join(CONFIGURATION_FILE_NAME);

        let configuration_serialized = toml::to_string_pretty(&self).unwrap();

        fs::write(configuration_file_path, configuration_serialized).await?;

        Ok(())
    }

    pub async fn set_custom_filters(&mut self, custom_filters: &str) -> ConfigurationResult<()> {
        self.custom_filters = Self::deserialize_lines(custom_filters);

        self.save().await?;

        Ok(())
    }

    fn deserialize_lines<T>(lines: &str) -> T
    where
        T: FromIterator<String>,
    {
        lines
            .lines()
            .filter_map(|s_| {
                let s_ = s_.trim();

                // Removing empty lines
                if s_.is_empty() {
                    None
                } else {
                    Some(s_.to_string())
                }
            })
            .collect::<T>()
    }

    pub async fn set_exclusions(
        &mut self,
        exclusions: &str,
        mut local_exclusion_store: crate::exclusions::LocalExclusionStore,
    ) -> ConfigurationResult<()> {
        self.exclusions = Self::deserialize_lines(exclusions);

        self.save().await?;

        local_exclusion_store
            .replace_exclusions(Vec::from_iter(self.exclusions.clone().into_iter()));

        Ok(())
    }

    pub async fn set_filter_enabled_status(
        &mut self,
        filter_file_name: &str,
        enabled: bool,
    ) -> ConfigurationResult<()> {
        let filter = self
            .filters
            .iter_mut()
            .find(|filter| filter.file_name == filter_file_name);

        if let Some(filter) = filter {
            filter.enabled = enabled;
        }

        self.save().await?;
        Ok(())
    }

    pub fn get_enabled_filters(&mut self) -> impl Iterator<Item = &mut Filter> {
        self.filters.iter_mut().filter(|f| f.enabled)
    }

    pub async fn update_filters(
        &mut self,
        http_client: reqwest::Client,
    ) -> ConfigurationResult<()> {
        log::debug!("Updating filters");

        let futures = self.filters.iter_mut().filter_map(|filter| {
            if filter.enabled {
                Some(filter.update(&http_client))
            } else {
                None
            }
        });

        try_join_all(futures).await?;

        Ok(())
    }

    pub async fn add_filter(
        &mut self,
        filter: &mut Filter,
        http_client: &reqwest::Client,
    ) -> ConfigurationResult<()> {
        match filter.update(http_client).await {
            Ok(_) => {
                self.filters.push(filter.clone());
                Ok(())
            }
            Err(err) => {
                log::error!("Failed to add filter: {err}");
                filter.enabled = false;
                Err(ConfigurationError::FilterError(
                    "Unable to add filter".to_string(),
                ))
            }
        }
    }

    pub async fn set_network_settings(
        &mut self,
        network_config: &NetworkConfig,
    ) -> ConfigurationResult<()> {
        if let Err(err) = network_config.validate() {
            log::error!("Failed to validate network settings: {err}");
            return Err(err);
        };
        self.network = network_config.clone();
        Ok(())
    }

    pub async fn set_ca_settings(&mut self, ca_config: &Ca) -> ConfigurationResult<()> {
        if let Err(err) = ca_config.validate().await {
            log::error!("Failed to validate ca settings: {err}");
            return Err(err);
        };
        self.ca = ca_config.clone();
        Ok(())
    }

    async fn new_default() -> ConfigurationResult<Self> {
        let (x509, private_key) = crate::ca::make_ca_certificate();

        let x509_pem = std::str::from_utf8(&x509.to_pem().unwrap())
            .unwrap()
            .to_string();

        let private_key_pem = std::str::from_utf8(&private_key.private_key_to_pem_pkcs8().unwrap())
            .unwrap()
            .to_string();

        let default_filters = DefaultFilters::new();
        Ok(Configuration {
            filters: default_filters
                .list()
                .into_iter()
                .map(|filter| filter.into())
                .collect(),
            ca: Ca {
                ca_certificate: Some(x509_pem),
                ca_certificate_path: None,
                ca_private_key: Some(private_key_pem),
                ca_private_key_path: None,
            },
            network: NetworkConfig {
                bind_addr: "127.0.0.1".to_string(),
                proxy_port: 8100,
                web_port: 8200,
                tls: false,
                tls_cert_path: None,
                tls_key_path: None,
                listen_url: None,
            },
            exclusions: BTreeSet::new(),
            custom_filters: Vec::new(),
        })
    }
}

pub(crate) fn get_config_directory() -> PathBuf {
    let config_dir: PathBuf = match env::var("PRIVAXY_CONFIG_PATH") {
        Ok(val) => PathBuf::from(&val),
        // Assume default directory
        Err(_) => PathBuf::from(CONFIGURATION_DIRECTORY_NAME),
    };
    return get_base_directory()
        .unwrap_or(get_home_directory().unwrap())
        .join(config_dir);
}

fn get_home_directory() -> ConfigurationResult<PathBuf> {
    match home_dir() {
        Some(home_directory) => Ok(home_directory),
        None => Err(ConfigurationError::DirectoryNotFound),
    }
}

fn get_base_directory() -> ConfigurationResult<PathBuf> {
    let base_directory: PathBuf = match env::var("PRIVAXY_BASE_PATH") {
        Ok(val) => PathBuf::from(&val),
        // Assume home directory
        Err(_) => get_home_directory()?,
    };
    match Path::exists(&base_directory) {
        true => Ok(base_directory),
        false => Err(ConfigurationError::DirectoryNotFound),
    }
}
