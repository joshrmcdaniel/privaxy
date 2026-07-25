use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, time::Duration};
use thiserror::Error;
use tokio::fs;
mod auth;
mod ca;
mod filter;
mod filter_failures;
mod network;
mod updater;
pub use auth::*;
pub use ca::*;
pub use filter::*;
pub use filter_failures::*;
use futures::future::join_all;
pub use network::*;
use std::env;
use std::path::{Path, PathBuf};
pub use updater::*;

use crate::proxy::exclusions::recommended_exclusions;
use crate::proxy::tls_failures::TlsFailureStore;
pub(crate) type ConfigurationResult<T> = Result<T, ConfigurationError>;
pub(crate) const FILTERS_UPDATE_AFTER: Duration = Duration::from_secs(60 * 60 * 24); // 24h

/// Filename of the configuration file.
pub(crate) const CONFIGURATION_FILE_NAME: &str = "config";

/// Default configuration directory name.
const CONFIGURATION_DIRECTORY_NAME: &str = "/etc/privaxy";

#[derive(Error, Debug)]
pub enum ConfigurationError {
    #[error("NetworkConfigError error: {0}")]
    NetworkConfigError(#[from] NetworkConfigError),
    #[error("CaError error: {0}")]
    CaError(#[from] CaError),
    #[error("an error occured while trying to deserialize configuration file")]
    DeserializeError(#[from] toml::de::Error),
    #[error("an error occured while trying to serialize configuration")]
    SerializeError(#[from] toml::ser::Error),
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
    #[error("filter validation error: {0}")]
    FilterValidationError(String),
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Configuration {
    pub exclusions: BTreeSet<String>,
    /// Hosts the operator chose to hide from the TLS-failure report in the
    /// web UI. Absent from configuration files written before this feature
    /// existed, hence the serde default.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub ignored_tls_failures: BTreeSet<String>,
    pub custom_filters: Vec<String>,
    pub ca: Ca,
    pub network: NetworkConfig,
    pub filters: Vec<Filter>,
    #[serde(default)]
    pub auth: Auth,
    #[serde(default)]
    pub debug: DebugConfig,
}

/// Opt-in diagnostics. Off by default — these add visible/observable behavior to
/// proxied pages, so they should only be enabled while troubleshooting.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct DebugConfig {
    /// Surface errors thrown by injected uBO scriptlets to the page console
    /// (`console.error('[privaxy scriptlet]', e)`) instead of swallowing them.
    /// Useful for spotting a silently-failing scriptlet; noisy and reveals
    /// Privaxy is in the path, so default off.
    #[serde(default)]
    pub scriptlet_console_logging: bool,
    /// Verbosity of Privaxy's own logs, applied live (no restart). Dependency
    /// logs remain governed by `RUST_LOG`. Defaults to `info`.
    #[serde(default)]
    pub log_level: crate::logging::LogLevel,
}

#[derive(Error, Debug)]
pub enum PrivaxyError {
    #[error("ConfigurationError: {0}")]
    ConfigurationError(#[from] ConfigurationError),
}

impl Configuration {
    pub async fn read_from_home() -> ConfigurationResult<Self> {
        let configuration_directory = get_base_directory().unwrap();
        let configuration_file_path = get_config_file();

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
            Ok(bytes) => {
                let mut configuration: Configuration =
                    toml::from_str(std::str::from_utf8(&bytes)?)?;
                if configuration.ensure_auth_keys() {
                    configuration.save().await?;
                }
                Ok(configuration)
            }
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

    /// Populate `auth.api_key` and `auth.session_signing_key` if missing
    /// (e.g. legacy config from before auth was added). Returns true if any
    /// change was made and the caller should persist the configuration.
    fn ensure_auth_keys(&mut self) -> bool {
        let mut changed = false;
        if self.auth.api_key.is_empty() {
            self.auth.api_key = generate_random_hex(32);
            changed = true;
        }
        if self.auth.session_signing_key.is_empty() {
            self.auth.session_signing_key = generate_random_hex(64);
            changed = true;
        }
        changed
    }

    pub async fn save(&self) -> ConfigurationResult<()> {
        let configuration_file_path = get_config_file();

        let configuration_serialized = toml::to_string_pretty(&self)?;

        // Write to a temporary file in the same directory, then atomically
        // rename it over the target. This guarantees the live config is never
        // observed in a half-written state: readers see either the old file or
        // the fully-written new one, even if the process crashes mid-write.
        let temp_file_path = get_base_directory()?.join(format!(
            "{CONFIGURATION_FILE_NAME}.{}.tmp",
            generate_random_hex(8)
        ));

        if let Err(err) = fs::write(&temp_file_path, configuration_serialized).await {
            let _ = fs::remove_file(&temp_file_path).await;
            return Err(ConfigurationError::FileSystemError(err));
        }

        if let Err(err) = fs::rename(&temp_file_path, &configuration_file_path).await {
            let _ = fs::remove_file(&temp_file_path).await;
            return Err(ConfigurationError::FileSystemError(err));
        }

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

        local_exclusion_store.replace_exclusions(Vec::from_iter(self.exclusions.clone()));

        Ok(())
    }

    /// Persist `host` into the ignored TLS-failure list and update the
    /// in-memory store immediately, so the report reflects the change without
    /// a reload.
    pub async fn ignore_tls_failure(
        &mut self,
        host: &str,
        tls_failure_store: TlsFailureStore,
    ) -> ConfigurationResult<()> {
        let host = host.trim();

        self.ignored_tls_failures.insert(host.to_string());

        self.save().await?;

        tls_failure_store.ignore(host);

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

    /// Refresh every enabled filter from its URL. Per-filter failures are
    /// expected here (remote lists go stale or move); they are recorded in
    /// `filter_failure_store` for the web UI and logged, while the remaining
    /// filters keep updating.
    pub async fn update_filters(
        &mut self,
        http_client: reqwest::Client,
        filter_failure_store: &FilterFailureStore,
    ) {
        log::debug!("Updating filters");

        let futures = self
            .filters
            .iter_mut()
            .filter(|filter| filter.enabled)
            .map(|filter| {
                let http_client = http_client.clone();
                async move {
                    let result = filter.update(&http_client).await;
                    (filter, result)
                }
            });

        for (filter, result) in join_all(futures).await {
            match result {
                Ok(_) => filter_failure_store.clear(&filter.file_name),
                Err(err) => {
                    log::error!("Failed to update filter '{}': {err}", filter.title);
                    filter_failure_store.record(filter, &err.to_string());
                }
            }
        }
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
            Err(err @ ConfigurationError::FilterValidationError(_)) => {
                log::warn!("Rejected invalid filter: {err}");
                filter.enabled = false;
                Err(err)
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

    /// Replace the filter identified by `old_file_name` with `filter`,
    /// keeping its enabled status. The replacement is validated the same way
    /// an added filter is: its URL must serve a parseable filter list.
    pub async fn replace_filter(
        &mut self,
        old_file_name: &str,
        filter: &mut Filter,
        http_client: &reqwest::Client,
    ) -> ConfigurationResult<()> {
        let index = self
            .filters
            .iter()
            .position(|existing| existing.file_name == old_file_name)
            .ok_or_else(|| {
                ConfigurationError::FilterError(format!("no filter with file name {old_file_name}"))
            })?;

        filter.enabled = self.filters[index].enabled;
        filter.update(http_client).await?;
        self.filters[index] = filter.clone();

        Ok(())
    }

    pub async fn set_network_settings(
        &mut self,
        network_config: &NetworkConfig,
    ) -> ConfigurationResult<()> {
        if let Err(err) = network_config.validate().await {
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
                bind_addr: "0.0.0.0".to_string(),
                proxy_port: 8100,
                web_port: 8200,
                tls: false,
                tls_cert_path: None,
                tls_key_path: None,
                listen_url: None,
                pac_enabled: false,
                pac_proxy_host: None,
                pac_direct_ips: Vec::new(),
                pac_direct_cidrs: std::collections::BTreeMap::new(),
                pac_direct_fqdns: Vec::new(),
                doh: DohConfig::default(),
            },
            exclusions: BTreeSet::from_iter(
                recommended_exclusions()
                    .iter()
                    .map(|entry| entry.to_string()),
            ),
            ignored_tls_failures: BTreeSet::new(),
            custom_filters: Vec::new(),
            auth: Auth::new_initialized(),
            debug: DebugConfig::default(),
        })
    }
}

pub(crate) fn get_config_file() -> PathBuf {
    get_base_directory().unwrap().join(CONFIGURATION_FILE_NAME)
}

fn get_base_directory() -> ConfigurationResult<PathBuf> {
    let base_directory: PathBuf = match env::var("PRIVAXY_BASE_PATH") {
        Ok(val) => PathBuf::from(&val),
        // Assume home directory
        Err(_) => PathBuf::from(CONFIGURATION_DIRECTORY_NAME),
    };
    match Path::exists(&base_directory) {
        true => Ok(base_directory),
        false => Err(ConfigurationError::DirectoryNotFound),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A freshly generated default configuration must survive a
    /// `to_string_pretty` -> `from_str` round-trip unchanged. This guards the
    /// TOML (de)serialization behavior across the toml crate upgrade.
    #[tokio::test]
    async fn configuration_toml_round_trips() {
        let configuration = Configuration::new_default()
            .await
            .expect("default configuration");

        let serialized = toml::to_string_pretty(&configuration).expect("serialize");
        let deserialized: Configuration = toml::from_str(&serialized).expect("deserialize");

        assert_eq!(configuration, deserialized);
    }

    /// Configuration files written before the TLS-failure ignore list existed
    /// carry no `ignored_tls_failures` key; they must keep parsing, yielding
    /// an empty set (serde default). The empty set is also omitted on save so
    /// untouched configurations stay byte-identical.
    #[tokio::test]
    async fn configuration_without_ignored_tls_failures_parses() {
        let configuration = Configuration::new_default()
            .await
            .expect("default configuration");

        let serialized = toml::to_string_pretty(&configuration).expect("serialize");
        assert!(
            !serialized.contains("ignored_tls_failures"),
            "empty ignore set must be omitted from the serialized configuration"
        );

        let deserialized: Configuration = toml::from_str(&serialized).expect("deserialize");
        assert!(deserialized.ignored_tls_failures.is_empty());
    }

    /// A populated ignore list survives a TOML round-trip unchanged.
    #[tokio::test]
    async fn configuration_round_trips_ignored_tls_failures() {
        let mut configuration = Configuration::new_default()
            .await
            .expect("default configuration");
        configuration.ignored_tls_failures = BTreeSet::from([
            "pinned.example.com".to_string(),
            "other.example.org".to_string(),
        ]);

        let serialized = toml::to_string_pretty(&configuration).expect("serialize");
        let deserialized: Configuration = toml::from_str(&serialized).expect("deserialize");

        assert_eq!(configuration, deserialized);
    }

    /// Blank lines and surrounding whitespace are stripped when turning the
    /// textarea contents into the stored list.
    #[test]
    fn deserialize_lines_trims_and_drops_blanks() {
        let parsed: Vec<String> = Configuration::deserialize_lines("  a \n\n b\n   \nc\n");
        assert_eq!(
            parsed,
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );
    }
}
