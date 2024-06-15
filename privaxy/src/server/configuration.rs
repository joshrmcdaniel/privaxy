use crate::{
    blocker::AdblockRequester, ca::make_ca_certificate, proxy::exclusions::LocalExclusionStore,
};
use dirs::home_dir;
use futures::future::{try_join_all, AbortHandle, Abortable};
use hex;
use openssl::{
    pkey::{PKey, Private},
    x509::X509,
};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use sha2::{Digest, Sha256};
use std::env;
use std::path::{Path, PathBuf};
use std::{collections::BTreeSet, time::Duration};
use thiserror::Error;
use tokio::sync::{self, mpsc::Sender};
use tokio::{fs, sync::mpsc::Receiver};
use url::Url;

const CONFIGURATION_DIRECTORY_NAME: &str = ".privaxy";
const CONFIGURATION_FILE_NAME: &str = "config";
const FILTERS_DIRECTORY_NAME: &str = "filters";

// Update filters every 10 minutes.
const FILTERS_UPDATE_AFTER: Duration = Duration::from_secs(60 * 10);

type ConfigurationResult<T> = Result<T, ConfigurationError>;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub enum FilterGroup {
    Default,
    Regional,
    Ads,
    Privacy,
    Malware,
    Social,
}
impl ToString for FilterGroup {
    fn to_string(&self) -> String {
        match self {
            FilterGroup::Default => "default",
            FilterGroup::Regional => "regional",
            FilterGroup::Ads => "ads",
            FilterGroup::Privacy => "privacy",
            FilterGroup::Malware => "malware",
            FilterGroup::Social => "social",
        }
        .to_string()
    }
}

#[serde_as]
#[derive(Deserialize)]
pub struct DefaultFilter {
    enabled_by_default: bool,
    file_name: String,
    group: String,
    title: String,
    #[serde_as(as = "DisplayFromStr")]
    url: Url,
}

#[serde_as]
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Filter {
    pub enabled: bool,
    pub title: String,
    pub group: FilterGroup,
    pub file_name: String,
    #[serde_as(as = "DisplayFromStr")]
    pub url: Url,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct NetworkConfig {
    pub bind_addr: String,
    pub proxy_port: u16,
    pub web_port: u16,
    pub api_port: u16,
}

pub struct DefaultFilters(Vec<DefaultFilter>);

impl DefaultFilters {
    pub fn new() -> Self {
        let filters = Self::get_default_filters()
            .into_iter()
            .chain(Self::get_ads_filters().into_iter())
            .chain(Self::get_privacy_filters().into_iter())
            .chain(Self::get_malware_filters().into_iter())
            .chain(Self::get_social_filters().into_iter())
            .chain(Self::get_regional_filters().into_iter())
            .collect();

        DefaultFilters(filters)
    }

    fn parse_filter(
        url: &'static str,
        title: &'static str,
        group: FilterGroup,
        enabled_by_default: bool,
    ) -> Option<DefaultFilter> {
        match Url::parse(url) {
            Ok(parsed_url) => {
                let file_name = calculate_sha256_hex(url);
                Some(DefaultFilter {
                    enabled_by_default,
                    file_name,
                    group: group.to_string(),
                    title: title.to_string(),
                    url: parsed_url,
                })
            }
            Err(e) => {
                log::warn!("Failed to parse URL {}: {}", url, e);
                None
            }
        }
    }

    fn get_default_filters() -> Vec<DefaultFilter> {
        vec![
            ("https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt", "uBlock filters", FilterGroup::Default, true),
            ("https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt", "uBlock filters - Badware risks", FilterGroup::Default, true),
            ("https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt", "uBlock filters - Privacy", FilterGroup::Default, true),
            ("https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/resource-abuse.txt", "uBlock filters - Resource abuse", FilterGroup::Default, true),
            ("https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt", "uBlock filters - Unbreak", FilterGroup::Default, true),
        ].into_iter()
        .filter_map(|(url, title, group, enabled_by_default)| Self::parse_filter(url, title, group, enabled_by_default))
        .collect()
    }

    fn get_ads_filters() -> Vec<DefaultFilter> {
        vec![
            (
                "https://filters.adtidy.org/extension/ublock/filters/2_without_easylist.txt",
                "AdGuard Base",
                FilterGroup::Ads,
                false,
            ),
            (
                "https://filters.adtidy.org/extension/ublock/filters/11.txt",
                "AdGuard Mobile Ads",
                FilterGroup::Ads,
                false,
            ),
            (
                "https://easylist.to/easylist/easylist.txt",
                "EasyList",
                FilterGroup::Ads,
                true,
            ),
        ]
        .into_iter()
        .filter_map(|(url, title, group, enabled_by_default)| {
            Self::parse_filter(url, title, group, enabled_by_default)
        })
        .collect()
    }

    fn get_privacy_filters() -> Vec<DefaultFilter> {
        vec![
            ("https://filters.adtidy.org/extension/ublock/filters/3.txt", "AdGuard Tracking Protection", FilterGroup::Privacy, false),
            ("https://filters.adtidy.org/extension/ublock/filters/17.txt", "AdGuard URL Tracking Protection", FilterGroup::Privacy, false),
            ("https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/lan-block.txt", "Block Outsider Intrusion into LAN", FilterGroup::Privacy, false),
            ("https://easylist.to/easylist/easyprivacy.txt", "EasyPrivacy", FilterGroup::Privacy, true),
        ].into_iter()
        .filter_map(|(url, title, group, enabled_by_default)| Self::parse_filter(url, title, group, enabled_by_default))
        .collect()
    }

    fn get_malware_filters() -> Vec<DefaultFilter> {
        vec![
            (
                "https://curben.gitlab.io/malware-filter/phishing-filter.txt",
                "Phishing URL Blocklist",
                FilterGroup::Malware,
                false,
            ),
            (
                "https://curben.gitlab.io/malware-filter/pup-filter.txt",
                "PUP Domains Blocklist",
                FilterGroup::Malware,
                false,
            ),
        ]
        .into_iter()
        .filter_map(|(url, title, group, enabled_by_default)| {
            Self::parse_filter(url, title, group, enabled_by_default)
        })
        .collect()
    }

    fn get_social_filters() -> Vec<DefaultFilter> {
        vec![
            ("https://filters.adtidy.org/extension/ublock/filters/14.txt", "AdGuard Annoyances", FilterGroup::Social, false),
            ("https://filters.adtidy.org/extension/ublock/filters/4.txt", "AdGuard Social Media", FilterGroup::Social, false),
            ("https://secure.fanboy.co.nz/fanboy-antifacebook.txt", "Anti-Facebook", FilterGroup::Social, false),
            ("https://secure.fanboy.co.nz/fanboy-annoyance.txt", "Fanboy's Annoyance", FilterGroup::Social, false),
            ("https://secure.fanboy.co.nz/fanboy-cookiemonster.txt", "EasyList Cookie", FilterGroup::Social, false),
            ("https://easylist.to/easylist/fanboy-social.txt", "Fanboy's Social", FilterGroup::Social, false),
            ("https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/annoyances.txt", "uBlock filters - Annoyances", FilterGroup::Social, false),
        ].into_iter()
        .filter_map(|(url, title, group, enabled_by_default)| Self::parse_filter(url, title, group, enabled_by_default))
        .collect()
    }

    fn get_regional_filters() -> Vec<DefaultFilter> {
        vec![
            ("https://easylist-downloads.adblockplus.org/Liste_AR.txt", "ara: Liste AR", FilterGroup::Regional, false),
            ("https://stanev.org/abp/adblock_bg.txt", "BGR: Bulgarian Adblock list", FilterGroup::Regional, false),
            ("https://filters.adtidy.org/extension/ublock/filters/224.txt", "CHN: AdGuard Chinese (中文)", FilterGroup::Regional, false),
            ("https://raw.githubusercontent.com/tomasko126/easylistczechandslovak/master/filters.txt", "CZE, SVK: EasyList Czech and Slovak", FilterGroup::Regional, false),
            ("https://easylist.to/easylistgermany/easylistgermany.txt", "DEU: EasyList Germany", FilterGroup::Regional, false),
            ("https://adblock.ee/list.php", "EST: Eesti saitidele kohandatud filter", FilterGroup::Regional, false),
            ("https://raw.githubusercontent.com/finnish-easylist-addition/finnish-easylist-addition/master/Finland_adb.txt", "FIN: Adblock List for Finland", FilterGroup::Regional, false),
            ("https://filters.adtidy.org/extension/ublock/filters/16.txt", "FRA: AdGuard Français", FilterGroup::Regional, false),
            ("https://www.void.gr/kargig/void-gr-filters.txt", "GRC: Greek AdBlock Filter", FilterGroup::Regional, false),
            ("https://raw.githubusercontent.com/hufilter/hufilter/master/hufilter-ublock.txt", "HUN: hufilter", FilterGroup::Regional, false),
            ("https://raw.githubusercontent.com/ABPindo/indonesianadblockrules/master/subscriptions/abpindo.txt", "IDN, MYS: ABPindo", FilterGroup::Regional, false),
            ("https://raw.githubusercontent.com/farrokhi/adblock-iran/master/filter.txt", "IRN: Adblock-Iran", FilterGroup::Regional, false),
            ("https://adblock.gardar.net/is.abp.txt", "ISL: Icelandic ABP List", FilterGroup::Regional, false),
            ("https://raw.githubusercontent.com/easylist/EasyListHebrew/master/EasyListHebrew.txt", "ISR: EasyList Hebrew", FilterGroup::Regional, false),
            ("https://easylist-downloads.adblockplus.org/easylistitaly.txt", "ITA: EasyList Italy", FilterGroup::Regional, false),
            ("https://raw.githubusercontent.com/gioxx/xfiles/master/filtri.txt", "ITA: ABP X Files", FilterGroup::Regional, false),
            ("https://filters.adtidy.org/extension/ublock/filters/7.txt", "JPN: AdGuard Japanese", FilterGroup::Regional, false),
            ("https://raw.githubusercontent.com/yous/YousList/master/youslist.txt", "KOR: YousList", FilterGroup::Regional, false),
            ("https://raw.githubusercontent.com/EasyList-Lithuania/easylist_lithuania/master/easylistlithuania.txt", "LTU: EasyList Lithuania", FilterGroup::Regional, false),
            ("https://notabug.org/latvian-list/adblock-latvian/raw/master/lists/latvian-list.txt", "LVA: Latvian List", FilterGroup::Regional, false),
            ("https://easylist-downloads.adblockplus.org/easylistdutch.txt", "NLD: EasyList Dutch", FilterGroup::Regional, false),
            ("https://raw.githubusercontent.com/DandelionSprout/adfilt/master/NorwegianList.txt", "NOR, DNK, ISL: Dandelion Sprouts nordiske filtre", FilterGroup::Regional, false),
            ("https://raw.githubusercontent.com/MajkiIT/polish-ads-filter/master/polish-adblock-filters/adblock.txt", "POL: Oficjalne Polskie Filtry do AdBlocka, uBlocka Origin i AdGuarda", FilterGroup::Regional, false),
            ("https://raw.githubusercontent.com/olegwukr/polish-privacy-filters/master/anti-adblock.txt", "POL: Oficjalne polskie filtry przeciwko alertom o Adblocku", FilterGroup::Regional, false),
            ("https://road.adblock.ro/lista.txt", "ROU: Romanian Ad (ROad) Block List Light", FilterGroup::Regional, false),
            ("https://easylist-downloads.adblockplus.org/advblock+cssfixes.txt", "RUS: RU AdList", FilterGroup::Regional, false),
            ("https://easylist-downloads.adblockplus.org/easylistspanish.txt", "spa: EasyList Spanish", FilterGroup::Regional, false),
            ("https://filters.adtidy.org/extension/ublock/filters/9.txt", "spa, por: AdGuard Spanish/Portuguese", FilterGroup::Regional, false),
            ("https://raw.githubusercontent.com/betterwebleon/slovenian-list/master/filters.txt", "SVN: Slovenian List", FilterGroup::Regional, false),
            ("https://raw.githubusercontent.com/lassekongo83/Frellwits-filter-lists/master/Frellwits-Swedish-Filter.txt", "SWE: Frellwit's Swedish Filter", FilterGroup::Regional, false),
            ("https://raw.githubusercontent.com/easylist-thailand/easylist-thailand/master/subscription/easylist-thailand.txt", "THA: EasyList Thailand", FilterGroup::Regional, false),
            ("https://filters.adtidy.org/extension/ublock/filters/13.txt", "TUR: AdGuard Turkish", FilterGroup::Regional, false),
            ("https://raw.githubusercontent.com/abpvn/abpvn/master/filter/abpvn_ublock.txt", "VIE: ABPVN List", FilterGroup::Regional, false),
        ].into_iter()
        .filter_map(|(url, title, group, enabled_by_default)| Self::parse_filter(url, title, group, enabled_by_default))
        .collect()
    }
}

pub(crate) fn calculate_sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hex::encode(hasher.finalize())
}

impl Filter {
    async fn update(&mut self, http_client: &reqwest::Client) -> ConfigurationResult<String> {
        log::debug!("Updating filter: {}", self.title);

        let filters_directory = get_filter_directory();

        fs::create_dir_all(&filters_directory).await?;

        let filter = get_filter(self, http_client).await?;

        fs::write(filters_directory.join(&self.file_name), &filter).await?;

        Ok(filter)
    }

    pub async fn get_contents(
        &mut self,
        http_client: &reqwest::Client,
    ) -> ConfigurationResult<String> {
        let filter_path = get_filter_directory().join(&self.file_name);
        match fs::read(filter_path).await {
            Err(err) => {
                if err.kind() == std::io::ErrorKind::NotFound {
                    self.update(http_client).await
                } else {
                    Err(ConfigurationError::FileSystemError(err))
                }
            }
            Ok(filter) => Ok(std::str::from_utf8(&filter)?.to_string()),
        }
    }
}

impl From<DefaultFilter> for Filter {
    fn from(default_filter: DefaultFilter) -> Self {
        Self {
            enabled: default_filter.enabled_by_default,
            title: default_filter.title,
            group: match default_filter.group.as_str() {
                "default" => FilterGroup::Default,
                "regional" => FilterGroup::Regional,
                "ads" => FilterGroup::Ads,
                "privacy" => FilterGroup::Privacy,
                "malware" => FilterGroup::Malware,
                "social" => FilterGroup::Social,
                _ => unreachable!(),
            },
            file_name: default_filter.file_name,
            url: default_filter.url,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Ca {
    ca_certificate: Option<String>,
    ca_private_key: Option<String>,
    ca_certificate_path: Option<String>,
    ca_private_key_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Configuration {
    pub exclusions: BTreeSet<String>,
    pub custom_filters: Vec<String>,
    ca: Ca,
    pub network: NetworkConfig,
    pub filters: Vec<Filter>,
}

#[derive(Error, Debug)]
pub enum ConfigurationError {
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
        mut local_exclusion_store: LocalExclusionStore,
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

    pub async fn ca_certificate(&self) -> ConfigurationResult<X509> {
        if let Some(ref ca_certificate_path) = self.ca.ca_certificate_path {
            let ca_path = PathBuf::from(ca_certificate_path);
            match fs::read(&ca_path).await {
                Ok(ca_cert) => {
                    let cert = X509::from_pem(&ca_cert)
                        .map_err(|_| ConfigurationError::DirectoryNotFound)?;
                    Ok(cert)
                }
                Err(err) => Err(ConfigurationError::FileSystemError(err)),
            }
        } else if let Some(ref ca_certificate) = self.ca.ca_certificate {
            let ca_cert = X509::from_pem(ca_certificate.as_bytes())
                .map_err(|_| ConfigurationError::DirectoryNotFound)?;
            Ok(ca_cert)
        } else {
            Err(ConfigurationError::DirectoryNotFound)
        }
    }

    pub async fn ca_private_key(&self) -> ConfigurationResult<PKey<Private>> {
        if let Some(ref ca_private_key_path) = self.ca.ca_private_key_path {
            let ca_path = PathBuf::from(ca_private_key_path);
            match fs::read(&ca_path).await {
                Ok(ca_key) => {
                    let pkey = PKey::private_key_from_pem(&ca_key)
                        .map_err(|_| ConfigurationError::DirectoryNotFound)?;
                    Ok(pkey)
                }
                Err(err) => Err(ConfigurationError::FileSystemError(err)),
            }
        } else if let Some(ref ca_private_key) = self.ca.ca_private_key {
            let pkey = PKey::private_key_from_pem(ca_private_key.as_bytes())
                .map_err(|_| ConfigurationError::DirectoryNotFound)?;
            Ok(pkey)
        } else {
            Err(ConfigurationError::DirectoryNotFound)
        }
    }

    async fn new_default() -> ConfigurationResult<Self> {
        let (x509, private_key) = make_ca_certificate();

        let x509_pem = std::str::from_utf8(&x509.to_pem().unwrap())
            .unwrap()
            .to_string();

        let private_key_pem = std::str::from_utf8(&private_key.private_key_to_pem_pkcs8().unwrap())
            .unwrap()
            .to_string();

        let default_filters = DefaultFilters::new();
        Ok(Configuration {
            filters: default_filters
                .0
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
                api_port: 8200,
                proxy_port: 8100,
                web_port: 8000,
            },
            exclusions: BTreeSet::new(),
            custom_filters: Vec::new(),
        })
    }
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

fn get_config_directory() -> PathBuf {
    let config_dir: PathBuf = match env::var("PRIVAXY_CONFIG_PATH") {
        Ok(val) => PathBuf::from(&val),
        // Assume default directory
        Err(_) => PathBuf::from(CONFIGURATION_DIRECTORY_NAME),
    };
    return get_base_directory()
        .unwrap_or(get_home_directory().unwrap())
        .join(config_dir);
}

fn get_filter_directory() -> PathBuf {
    let filter_dir: PathBuf = match env::var("PRIVAXY_FILTER_PATH") {
        Ok(val) => PathBuf::from(&val),
        // Assume home directory
        Err(_) => PathBuf::from(FILTERS_DIRECTORY_NAME),
    };
    return get_config_directory().join(filter_dir);
}

async fn get_filter(
    filter: &mut Filter,
    http_client: &reqwest::Client,
) -> ConfigurationResult<String> {
    let response = match http_client.get(filter.url.as_str()).send().await {
        Ok(response) => {
            if response.status().is_success() {
                match response.text().await {
                    Ok(content) => content,
                    Err(err) => {
                        log::error!("Failed to read filter content: {err}");
                        return Err(ConfigurationError::FilterError(format!(
                            "Failed to read filter content: {}",
                            err
                        )));
                    }
                }
            } else {
                log::error!("Failed to fetch filter content: {}", response.status());
                return Err(ConfigurationError::FilterError(format!(
                    "Failed to fetch filter content: {}",
                    response.status()
                )));
            }
        }
        Err(err) => {
            log::error!("Failed to fetch filter URL: {err}");
            return Err(ConfigurationError::FilterError(format!(
                "Failed to fetch filter URL: {}",
                err
            )));
        }
    };
    Ok(response)
}

pub struct ConfigurationUpdater {
    filters_updater_abort_handle: AbortHandle,
    rx: Receiver<Configuration>,
    pub tx: Sender<Configuration>,
    http_client: reqwest::Client,
    adblock_requester: AdblockRequester,
}

impl ConfigurationUpdater {
    pub(crate) async fn new(
        configuration: Configuration,
        http_client: reqwest::Client,
        adblock_requester: AdblockRequester,
        tx_rx: Option<(
            sync::mpsc::Sender<Configuration>,
            sync::mpsc::Receiver<Configuration>,
        )>,
    ) -> Self {
        let (abort_handle, abort_registration) = AbortHandle::new_pair();

        let (tx, rx) = match tx_rx {
            Some((tx, rx)) => (tx, rx),
            None => sync::mpsc::channel(1),
        };

        let http_client_clone = http_client.clone();
        let adblock_requester_clone = adblock_requester.clone();

        let filters_updater = Abortable::new(
            async move {
                Self::filters_updater(
                    configuration,
                    adblock_requester_clone,
                    http_client_clone.clone(),
                )
                .await
            },
            abort_registration,
        );

        tokio::spawn(filters_updater);

        Self {
            filters_updater_abort_handle: abort_handle,
            rx,
            tx,
            http_client,
            adblock_requester,
        }
    }

    pub(crate) fn start(mut self) {
        tokio::spawn(async move {
            if let Some(mut configuration) = self.rx.recv().await {
                self.filters_updater_abort_handle.abort();

                let filters = get_filters_content(&mut configuration, &self.http_client).await;

                self.adblock_requester.replace_engine(filters).await;

                let new_self = Self::new(
                    configuration,
                    self.http_client,
                    self.adblock_requester,
                    Some((self.tx, self.rx)),
                )
                .await;
                new_self.start();

                log::info!("Applied new configuration");
            }
        });
    }

    async fn filters_updater(
        mut configuration: Configuration,
        adblock_requester: AdblockRequester,
        http_client: reqwest::Client,
    ) {
        loop {
            tokio::time::sleep(FILTERS_UPDATE_AFTER).await;

            if let Err(err) = configuration.update_filters(http_client.clone()).await {
                log::error!("An error occured while trying to update filters: {:?}", err);
            }

            // We don't bother diffing the filters as replacing the engine is very cheap and
            // filters are not updated often enough that the cost would matter.
            let filters = get_filters_content(&mut configuration, &http_client).await;
            adblock_requester.replace_engine(filters).await;

            log::info!("Updated filters");
        }
    }
}

async fn get_filters_content(
    configuration: &mut Configuration,
    http_client: &reqwest::Client,
) -> Vec<String> {
    let mut filters = Vec::new();

    for filter in configuration.get_enabled_filters() {
        match filter.get_contents(http_client).await {
            Ok(filter_content) => filters.push(filter_content),
            Err(err) => {
                log::error!("Unable to retrieve filter: {:?}, skipping.", err)
            }
        }
    }

    filters.append(&mut configuration.custom_filters.clone());

    filters
}
