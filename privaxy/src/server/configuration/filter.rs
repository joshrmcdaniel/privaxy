use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::env;
use std::path::PathBuf;
use tokio::fs;
use url::Url;

use serde_with::{serde_as, DisplayFromStr};
pub(crate) const FILTERS_DIRECTORY_NAME: &str = "filters";

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub enum FilterGroup {
    Default,
    Regional,
    Ads,
    Privacy,
    Malware,
    Social,
}

impl std::fmt::Display for FilterGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            FilterGroup::Default => "default",
            FilterGroup::Regional => "regional",
            FilterGroup::Ads => "ads",
            FilterGroup::Privacy => "privacy",
            FilterGroup::Malware => "malware",
            FilterGroup::Social => "social",
        };
        write!(f, "{name}")
    }
}

#[serde_as]
#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DefaultFilter {
    enabled_by_default: bool,
    file_name: String,
    group: String,
    title: String,
    #[serde_as(as = "DisplayFromStr")]
    url: Url,
}

#[serde_as]
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Filter {
    /// If the filter is enabled
    pub enabled: bool,
    /// Title of the filter
    pub title: String,
    /// Group of the filter
    pub group: FilterGroup,
    /// Local file name of the filter
    pub file_name: String,
    #[serde_as(as = "DisplayFromStr")]
    /// Remote URL of the filter
    pub url: Url,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct DefaultFilters(Vec<DefaultFilter>);

impl Default for DefaultFilters {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultFilters {
    pub fn new() -> Self {
        let mut filters = Vec::new();
        filters.extend(Self::get_default_filters());
        filters.extend(Self::get_ads_filters());
        filters.extend(Self::get_privacy_filters());
        filters.extend(Self::get_malware_filters());
        filters.extend(Self::get_social_filters());
        filters.extend(Self::get_regional_filters());
        DefaultFilters(filters)
    }

    pub fn list(&self) -> Vec<DefaultFilter> {
        self.0.clone()
    }

    /// File names (derived from the URLs) of the filter lists shipped with
    /// the package. Configuration entries matching one of these are built-in:
    /// they can be enabled or disabled, but not edited or removed.
    pub fn file_names(&self) -> BTreeSet<String> {
        self.0
            .iter()
            .map(|filter| filter.file_name.clone())
            .collect()
    }

    fn parse_filter(
        url: &'static str,
        title: &'static str,
        group: FilterGroup,
        enabled_by_default: bool,
    ) -> Option<DefaultFilter> {
        match Url::parse(url) {
            Ok(parsed_url) => {
                let file_name = calc_filter_filename(url);
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
            ("https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters-mobile.txt", "uBlock mobile filters", FilterGroup::Default, true),
            ("https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt", "uBlock filters - Badware risks", FilterGroup::Default, true),
            ("https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt", "uBlock filters - Privacy", FilterGroup::Default, true),
            ("https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/resource-abuse.txt", "uBlock filters - Resource abuse", FilterGroup::Default, true),
            ("https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt", "uBlock filters - Unbreak", FilterGroup::Default, true),
            ("https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/quick-fixes.txt", "uBlock filters - Quick Fixes", FilterGroup::Default, true),
        ]
        .into_iter()
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
        ]
        .into_iter()
        .filter_map(|(url, title, group, enabled_by_default)| Self::parse_filter(url, title, group, enabled_by_default))
        .collect()
    }

    fn get_malware_filters() -> Vec<DefaultFilter> {
        vec![
            (
                "https://malware-filter.gitlab.io/malware-filter/phishing-filter.txt",
                "Phishing URL Blocklist",
                FilterGroup::Malware,
                false,
            ),
            (
                "https://malware-filter.gitlab.io/pup-filter/pup-filter.txt",
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
            ("https://raw.githubusercontent.com/uBlockOrigin/uAssets/refs/heads/master/filters/annoyances-others.txt", "uBlock filters - Annoyances", FilterGroup::Social, false),
        ]
        .into_iter()
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
        ]
        .into_iter()
        .filter_map(|(url, title, group, enabled_by_default)| Self::parse_filter(url, title, group, enabled_by_default))
        .collect()
    }
}

fn calculate_sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hex::encode(hasher.finalize())
}

pub(crate) fn calc_filter_filename(filename: &str) -> String {
    format!("{}.txt", calculate_sha256_hex(filename))
}

impl Filter {
    pub(super) async fn update(
        &mut self,
        http_client: &reqwest::Client,
    ) -> super::ConfigurationResult<String> {
        log::debug!("Updating filter: {}", self.title);

        let filters_directory = get_filter_directory();
        fs::create_dir_all(&filters_directory).await?;

        // `get_filter` rejects responses that are not served as a filter list (see its
        // Content-Type check), so an invalid URL never reaches disk.
        let filter = get_filter(self, http_client).await?;

        let filter_path = filters_directory.join(&self.file_name);
        fs::write(&filter_path, &filter).await?;

        Ok(filter)
    }

    pub async fn get_contents(
        &mut self,
        http_client: &reqwest::Client,
    ) -> super::ConfigurationResult<String> {
        let filter_path = get_filter_directory().join(&self.file_name);
        match fs::read(&filter_path).await {
            Err(err) => {
                if err.kind() == std::io::ErrorKind::NotFound {
                    self.update(http_client).await
                } else {
                    Err(super::ConfigurationError::FileSystemError(err))
                }
            }
            Ok(filter) => Ok(std::str::from_utf8(&filter)?.to_string()),
        }
    }
}

impl std::fmt::Display for Filter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Filter {{ enabled: {}, title: {}, group: {}, file_name: {}, url: {} }}",
            self.enabled,
            self.title,
            self.group,
            self.file_name,
            self.url.as_str()
        )
    }
}

impl std::fmt::Debug for Filter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Filter {{ enabled: {}, title: {}, group: {}, file_name: {}, url: {} }}",
            self.enabled,
            self.title,
            self.group,
            self.file_name,
            self.url.as_str()
        )
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

/// Returns `Ok(())` only when the response is served as a `text/plain` filter list.
///
/// A URL returning a `200` is not sufficient on its own: it may serve an HTML error page, a
/// redirect landing page or any other content. Filter lists are served as `text/plain`, so a
/// different Content-Type (most commonly `text/html`) means the URL does not point to a list.
fn validate_filter_content_type(
    filter: &Filter,
    response: &reqwest::Response,
) -> super::ConfigurationResult<()> {
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();

    // `starts_with` so that a charset suffix (e.g. `text/plain; charset=utf-8`) still matches.
    if content_type.starts_with("text/plain") {
        return Ok(());
    }

    Err(super::ConfigurationError::FilterValidationError(format!(
        "The URL for '{}' does not point to a filter list (expected a \"text/plain\" response, got \"{}\")",
        filter.title,
        if content_type.is_empty() {
            "no Content-Type"
        } else {
            &content_type
        }
    )))
}

/// Verifies at least one rule is present.
fn validate_filter_rules(filter: &Filter, contents: &str) -> super::ConfigurationResult<()> {
    let (network_filters, cosmetic_filters) = adblock::lists::parse_filters(
        contents.lines(),
        false,
        adblock::lists::ParseOptions::default(),
    );

    if network_filters.is_empty() && cosmetic_filters.is_empty() {
        return Err(super::ConfigurationError::FilterValidationError(format!(
            "The URL for '{}' returned no parseable filter rules",
            filter.title
        )));
    }

    Ok(())
}

pub(crate) async fn get_filter(
    filter: &mut Filter,
    http_client: &reqwest::Client,
) -> super::ConfigurationResult<String> {
    let response = http_client.get(filter.url.as_str()).send().await?;
    if response.status().is_success() {
        validate_filter_content_type(filter, &response)?;
        let content = response.text().await?;
        validate_filter_rules(filter, &content)?;
        Ok(content)
    } else {
        log::error!(
            "Failed to fetch filter content for {}: {}",
            filter.title,
            response.status()
        );
        Err(super::ConfigurationError::FilterError(format!(
            "Failed to fetch filter content for {}: {}",
            filter.title,
            response.status()
        )))
    }
}

fn get_filter_directory() -> PathBuf {
    let filter_dir: PathBuf = match env::var("PRIVAXY_FILTER_PATH") {
        Ok(val) => PathBuf::from(&val),
        // Assume home directory
        Err(_) => PathBuf::from(FILTERS_DIRECTORY_NAME),
    };
    super::get_base_directory().unwrap().join(filter_dir)
}

pub(crate) async fn get_filters_content(
    configuration: &mut super::Configuration,
    http_client: &reqwest::Client,
    filter_failure_store: &super::FilterFailureStore,
) -> Vec<String> {
    let mut filters = Vec::new();

    let futures = configuration.get_enabled_filters().map(|filter| {
        let http_client = http_client.clone();
        async move {
            let result = filter.get_contents(&http_client).await;
            (filter, result)
        }
    });

    let results = futures::future::join_all(futures).await;
    for (filter, result) in results {
        match result {
            Ok(filter_content) => filters.push(filter_content),
            // A fetch failure here includes a filter whose URL has stopped serving a
            // `text/plain` list (see `validate_filter_content_type`); we record it for the
            // web UI and drop it from the engine rather than aborting the whole rebuild.
            // No entry is cleared on success: a filter can load fine from its on-disk
            // copy while its URL is still failing to update.
            Err(err) => {
                log::warn!("Dropping filter that could not be loaded: {err:?}");
                filter_failure_store.record(filter, &err.to_string());
            }
        }
    }

    filters.extend(configuration.custom_filters.iter().cloned());
    filters.sort_unstable();
    // Filter out duplicate lines, if present
    filters.dedup();
    filters
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `is_default` API check identifies built-in lists by file name, so
    /// every default filter's file name must stay derived from its URL and
    /// the set must not silently collapse through duplicates.
    #[test]
    fn default_filter_file_names_are_derived_from_urls() {
        let defaults = DefaultFilters::new();
        let list = defaults.list();
        let file_names = defaults.file_names();

        assert!(!list.is_empty());
        assert_eq!(file_names.len(), list.len());
        for filter in list {
            assert_eq!(filter.file_name, calc_filter_filename(filter.url.as_str()));
        }
    }
}
