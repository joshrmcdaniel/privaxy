use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::env;
use std::path::{Path, PathBuf};
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

pub(crate) fn calculate_sha256_hex(input: &str) -> String {
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
        self.update_in_directory(http_client, &get_filter_directory())
            .await
    }

    async fn update_in_directory(
        &mut self,
        http_client: &reqwest::Client,
        filters_directory: &Path,
    ) -> super::ConfigurationResult<String> {
        log::debug!("Updating filter: {}", self.title);

        fs::create_dir_all(filters_directory).await?;

        // `get_filter` rejects responses that are not served as a filter list (see its
        // Content-Type check), so an invalid URL never reaches disk.
        let filter = get_filter(self, http_client).await?;

        let filter_path = filters_directory.join(&self.file_name);
        write_filter_cache(&filter_path, &filter).await?;

        Ok(filter)
    }

    pub async fn get_contents(
        &mut self,
        http_client: &reqwest::Client,
    ) -> super::ConfigurationResult<String> {
        self.get_contents_in_directory(http_client, &get_filter_directory())
            .await
    }

    async fn get_contents_in_directory(
        &mut self,
        http_client: &reqwest::Client,
        filters_directory: &Path,
    ) -> super::ConfigurationResult<String> {
        let filter_path = filters_directory.join(&self.file_name);
        if let Some(contents) = self.read_valid_cache(&filter_path).await? {
            return Ok(contents);
        }

        // Recover installations with an empty/missing <hash>.txt alongside a
        // populated <hash>. Only consider the exact hash-named sibling, and
        // preserve it while repairing the configured cache filename.
        if let Some(hash) = self
            .file_name
            .strip_suffix(".txt")
            .filter(|hash| hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            let alternate_path = filters_directory.join(hash);
            if let Some(contents) = self.read_valid_cache(&alternate_path).await? {
                log::warn!(
                    "Recovering filter '{}' from {}",
                    self.title,
                    alternate_path.display()
                );
                // A read-only cache must not stop us using the recovered rules.
                if let Err(err) = write_filter_cache(&filter_path, &contents).await {
                    log::warn!(
                        "Unable to repair filter cache {}: {err}",
                        filter_path.display()
                    );
                }
                return Ok(contents);
            }
        }

        self.update_in_directory(http_client, filters_directory)
            .await
    }

    async fn read_valid_cache(&self, path: &Path) -> super::ConfigurationResult<Option<String>> {
        let bytes = match fs::read(path).await {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        let contents = std::str::from_utf8(&bytes)
            .map_err(super::ConfigurationError::from)
            .and_then(|contents| {
                validate_filter_rules(self, contents)?;
                Ok(contents.to_owned())
            });
        match contents {
            Ok(contents) => Ok(Some(contents)),
            Err(err) => {
                log::warn!("Ignoring invalid filter cache {}: {err}", path.display());
                Ok(None)
            }
        }
    }
}

/// Never truncate the live cache during an update. A reader sees either the
/// previous complete list or the new one, even if an update is interrupted.
async fn write_filter_cache(path: &Path, contents: &str) -> std::io::Result<()> {
    let mut temporary_name = path.as_os_str().to_owned();
    temporary_name.push(format!(".{}.tmp", super::generate_random_hex(8)));
    let temporary_path = PathBuf::from(temporary_name);
    if let Err(err) = fs::write(&temporary_path, contents).await {
        let _ = fs::remove_file(&temporary_path).await;
        return Err(err);
    }
    if let Err(err) = fs::rename(&temporary_path, path).await {
        let _ = fs::remove_file(&temporary_path).await;
        return Err(err);
    }
    Ok(())
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
    // Validation also runs on cache hits. Stop at the first usable rule rather
    // than parsing every list twice before building the blocking engine.
    let has_rule = contents.lines().any(|line| {
        adblock::lists::parse_filter(line, false, adblock::lists::ParseOptions::default()).is_ok()
    });
    if !has_rule {
        return Err(super::ConfigurationError::FilterValidationError(format!(
            "Filter '{}' contains no parseable filter rules",
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
    let enabled_count = configuration
        .filters
        .iter()
        .filter(|filter| filter.enabled)
        .count();
    log::info!("Loading {enabled_count} enabled filter lists");

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
            Ok(filter_content) => {
                log::debug!(
                    "Loaded filter '{}': {} bytes",
                    filter.title,
                    filter_content.len()
                );
                filters.push(filter_content);
            }
            // A fetch failure here includes a filter whose URL has stopped serving a
            // `text/plain` list (see `validate_filter_content_type`); we record it for the
            // web UI and drop it from the engine rather than aborting the whole rebuild.
            // No entry is cleared on success: a filter can load fine from its on-disk
            // copy while its URL is still failing to update.
            Err(err) => {
                log::warn!("Unable to load filter '{}': {err}", filter.title);
                filter_failure_store.record(filter, &err.to_string());
            }
        }
    }

    log::info!(
        "Loaded {} of {enabled_count} enabled filter lists; {} custom rules",
        filters.len(),
        configuration.custom_filters.len()
    );
    if enabled_count > 0 && filters.is_empty() {
        log::error!("No enabled filter lists could be loaded; only custom rules are available");
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

    struct TestCache(PathBuf);

    impl TestCache {
        fn new() -> Self {
            let directory = std::env::temp_dir().join(format!(
                "privaxy-filter-cache-{}",
                super::super::generate_random_hex(8)
            ));
            std::fs::create_dir(&directory).unwrap();
            Self(directory)
        }
    }

    impl Drop for TestCache {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn cached_filter() -> Filter {
        // An unsupported download scheme makes unintended network fallbacks
        // fail immediately, without a listener or a process-global env override.
        let url = Url::parse("file:///filter-cache-test.txt").unwrap();
        Filter {
            enabled: true,
            title: "Cache fixture".into(),
            group: FilterGroup::Ads,
            file_name: calc_filter_filename(url.as_str()),
            url,
        }
    }

    #[tokio::test]
    async fn missing_or_invalid_cache_recovers_matching_extensionless_rules() {
        let cache = TestCache::new();
        let mut filter = cached_filter();
        let path = cache.0.join(&filter.file_name);
        let alternate = path.with_extension("");
        let rules = "||ads.example.com^\nexample.com##.banner\n";
        fs::write(&alternate, rules).await.unwrap();
        let client = reqwest::Client::new();

        for invalid in [
            None,
            Some(b"".as_slice()),
            Some(b" \r\n\t".as_slice()),
            Some(b"[Adblock Plus 2.0]\n! No rules\n".as_slice()),
            Some(b"\xff\xfe".as_slice()),
        ] {
            if let Some(bytes) = invalid {
                fs::write(&path, bytes).await.unwrap();
            }
            let contents = filter
                .get_contents_in_directory(&client, &cache.0)
                .await
                .unwrap();
            assert_eq!(contents, rules);
            assert_eq!(fs::read_to_string(&path).await.unwrap(), rules);
            assert_eq!(fs::read_to_string(&alternate).await.unwrap(), rules);
        }
    }

    #[tokio::test]
    async fn valid_configured_cache_takes_precedence_over_extensionless_copy() {
        let cache = TestCache::new();
        let mut filter = cached_filter();
        let path = cache.0.join(&filter.file_name);
        let rules = "||current.example.com^\n";
        fs::write(&path, rules).await.unwrap();
        fs::write(path.with_extension(""), "||old.example.com^\n")
            .await
            .unwrap();
        assert_eq!(
            filter
                .get_contents_in_directory(&reqwest::Client::new(), &cache.0)
                .await
                .unwrap(),
            rules
        );
    }

    #[tokio::test]
    async fn unusable_caches_trigger_download_and_surface_its_failure() {
        let cache = TestCache::new();
        let mut filter = cached_filter();
        let path = cache.0.join(&filter.file_name);
        fs::write(&path, "").await.unwrap();
        fs::write(path.with_extension(""), "! Also has no rules\n")
            .await
            .unwrap();
        let error = filter
            .get_contents_in_directory(&reqwest::Client::new(), &cache.0)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            super::super::ConfigurationError::UnableToRetrieveDefaultFilters(_)
        ));
    }

    #[tokio::test]
    async fn cache_replacement_preserves_the_complete_file_for_existing_readers() {
        use std::io::Read;

        let cache = TestCache::new();
        let path = cache.0.join("filter.txt");
        let old_rules = "||old.example.com^\n";
        let new_rules = "||new.example.com^\n";
        fs::write(&path, old_rules).await.unwrap();
        let mut reader = std::fs::File::open(&path).unwrap();

        write_filter_cache(&path, new_rules).await.unwrap();

        let mut contents = String::new();
        reader.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, old_rules);
        assert_eq!(fs::read_to_string(&path).await.unwrap(), new_rules);
        assert_eq!(std::fs::read_dir(&cache.0).unwrap().count(), 1);
    }

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
