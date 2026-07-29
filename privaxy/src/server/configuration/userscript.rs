//! Userscript storage, metadata parsing and URL matching.
//!
//! A userscript is arbitrary JavaScript injected into pages whose URL matches
//! the script's own `@match`/`@include` declarations, in the style of
//! Greasemonkey / Tampermonkey / Violentmonkey. Privaxy injects them from the
//! HTML rewriter, so they run in the page's main world (there is no isolated
//! world available to a proxy) as early as `<head>`.
//!
//! Storage mirrors [`super::Filter`]: metadata lives in the configuration file
//! and the script body lives on disk under `userscripts/`, keyed by a
//! content-independent, stable file name. This keeps script bodies — routinely
//! tens of kilobytes — out of the TOML, and lets a script installed from a URL
//! be re-fetched without rewriting the configuration.

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use std::env;
use std::path::PathBuf;
use thiserror::Error;
use tokio::fs;
use url::Url;

use super::generate_random_hex;

/// Directory, relative to the configuration base directory, holding script
/// bodies.
pub(crate) const USERSCRIPTS_DIRECTORY_NAME: &str = "userscripts";

/// Directory, relative to the userscripts directory, caching fetched
/// `@require` libraries and `@resource` payloads.
const USERSCRIPT_ASSETS_DIRECTORY_NAME: &str = "assets";

/// File, relative to the userscripts directory, holding `GM_setValue` data.
const USERSCRIPT_STORAGE_FILE_NAME: &str = "gm_storage.json";

/// Content type assumed for an asset served without one.
const DEFAULT_ASSET_CONTENT_TYPE: &str = "application/octet-stream";

/// Largest resource inlined as text into a script's descriptor. Beyond this the
/// page is handed a URL instead, so a multi-megabyte asset is not re-serialized
/// into every matching page load.
const MAX_INLINE_RESOURCE_BYTES: usize = 256 * 1024;

/// Cap on a fetched script body. Userscripts are hand-written JavaScript; a
/// response far past this is not a userscript and we refuse to hold it in
/// memory for every matching page load.
const MAX_USERSCRIPT_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum UserScriptError {
    #[error("the script has no `// ==UserScript==` metadata block")]
    MissingMetadataBlock,
    #[error("the script's metadata block has no closing `// ==/UserScript==`")]
    UnterminatedMetadataBlock,
    #[error("invalid @match pattern: {0}")]
    InvalidMatchPattern(String),
    #[error("invalid regular expression in @include/@exclude: {0}")]
    InvalidRegex(String),
    #[error("the script declares neither @match nor @include, so it would never run")]
    NoMatchDeclared,
    #[error("the script declares no @name")]
    MissingName,
    #[error("@require is not a valid URL: {0}")]
    InvalidRequireUrl(String),
    #[error("the script body is empty")]
    EmptyBody,
    #[error("the script body exceeds the {MAX_USERSCRIPT_BYTES} byte limit")]
    BodyTooLarge,
    #[error("'{0}' is not a valid userscript file name")]
    InvalidFileName(String),
}

/// Whether `file_name` has the shape this module generates: 64 hex characters
/// followed by `.user.js`.
///
/// Enforced wherever a path is built from a file name, so that a name reaching
/// [`UserScript`] from anywhere other than [`calc_userscript_filename`] cannot
/// escape the userscripts directory. Callers currently only ever resolve names
/// through the configuration, but that invariant lives in the callers; this one
/// lives next to the `join` it protects, where a later refactor cannot lose it.
/// No traversal sequence, path separator or absolute path can satisfy this shape.
fn is_valid_userscript_file_name(file_name: &str) -> bool {
    match file_name.strip_suffix(".user.js") {
        Some(stem) => stem.len() == 64 && stem.bytes().all(|byte| byte.is_ascii_hexdigit()),
        None => false,
    }
}

/// Global userscript settings plus the installed scripts.
///
/// `enabled` is a master switch: when false no script is injected regardless of
/// its own `enabled` flag, without having to disable each one. Absent from
/// configuration files written before userscripts existed, hence the `serde`
/// defaults on [`super::Configuration`].
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct UserScriptsConfig {
    /// Master switch for the whole engine.
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
    /// Installed scripts, in injection order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scripts: Vec<UserScript>,
    /// Whether `GM_xmlhttpRequest` may reach private, loopback and link-local
    /// addresses.
    ///
    /// Off by default, and deliberately so: the relay runs server-side, and the
    /// proxy usually sits *inside* a LAN where it can reach routers, admin
    /// panels and metadata endpoints that the requesting browser could never
    /// contact. Turning this on makes the proxy a confused deputy for every
    /// origin an installed script matches.
    #[serde(default)]
    pub allow_private_network_requests: bool,
}

fn enabled_by_default() -> bool {
    true
}

impl Default for UserScriptsConfig {
    fn default() -> Self {
        Self {
            enabled: enabled_by_default(),
            scripts: Vec::new(),
            allow_private_network_requests: false,
        }
    }
}

impl UserScriptsConfig {
    /// The scripts eligible for injection: every enabled script, or none at all
    /// when the master switch is off.
    pub fn active_scripts(&self) -> impl Iterator<Item = &UserScript> {
        let engine_enabled = self.enabled;

        self.scripts
            .iter()
            .filter(move |script| engine_enabled && script.enabled)
    }

    pub fn find(&self, file_name: &str) -> Option<&UserScript> {
        self.scripts
            .iter()
            .find(|script| script.file_name == file_name)
    }
}

/// An installed userscript, as persisted in the configuration file. The body is
/// not held here; it lives on disk (see [`UserScript::read_body`]).
#[serde_as]
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct UserScript {
    /// Whether the script is injected. Independent of
    /// [`UserScriptsConfig::enabled`], which gates all scripts at once.
    pub enabled: bool,
    /// Display name, taken from `@name` at install time.
    pub title: String,
    /// Local file name of the script body; the stable identifier for a script
    /// across edits, including edits that change its `@name` or URL.
    pub file_name: String,
    /// Remote URL the script was installed from, if any. `None` for a script
    /// pasted directly into the web UI, which therefore has no upstream to
    /// re-fetch.
    #[serde_as(as = "Option<DisplayFromStr>")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<Url>,
}

impl UserScript {
    /// Path of this script's body on disk.
    ///
    /// Refuses to build a path from a file name that is not one this module
    /// generated, so a name that reached here by any route cannot escape the
    /// userscripts directory.
    fn body_path(&self) -> super::ConfigurationResult<PathBuf> {
        if !is_valid_userscript_file_name(&self.file_name) {
            return Err(UserScriptError::InvalidFileName(self.file_name.clone()).into());
        }

        Ok(get_userscript_directory().join(&self.file_name))
    }

    /// Persist `body` for this script, creating the userscripts directory if
    /// needed.
    pub async fn write_body(&self, body: &str) -> super::ConfigurationResult<()> {
        let path = self.body_path()?;

        fs::create_dir_all(get_userscript_directory()).await?;
        fs::write(path, body).await?;

        Ok(())
    }

    /// Read this script's body from disk.
    pub async fn read_body(&self) -> super::ConfigurationResult<String> {
        let bytes = fs::read(self.body_path()?).await?;

        Ok(std::str::from_utf8(&bytes)?.to_string())
    }

    /// Remove this script's body from disk. A missing file is not an error:
    /// the caller's intent (no body on disk) is already satisfied.
    pub async fn delete_body(&self) -> super::ConfigurationResult<()> {
        match fs::remove_file(self.body_path()?).await {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(super::ConfigurationError::FileSystemError(err)),
        }
    }

    /// Re-fetch this script from upstream and persist the result.
    ///
    /// Honors `@updateURL` and `@downloadURL`, both defaulting to the URL the
    /// script was installed from. When `@updateURL` points somewhere separate,
    /// it is fetched first purely to read `@version`; the (potentially much
    /// larger) body is only downloaded when that version is actually newer. This
    /// is what those directives are for, and scripts in the wild do split them.
    ///
    /// Errors if the script has no URL (it was pasted locally, so there is
    /// nothing to fetch) or if what comes back does not parse as a userscript —
    /// a body that no longer parses must not overwrite a working one on disk.
    pub async fn update(
        &mut self,
        http_client: &reqwest::Client,
    ) -> super::ConfigurationResult<UserScriptUpdate> {
        let install_url = self.url.clone().ok_or_else(|| {
            super::ConfigurationError::UserScript(UserScriptError::InvalidRequireUrl(
                "script has no remote URL to update from".to_string(),
            ))
        })?;

        // The directives live in the body we already have, so the local copy is
        // what tells us where to look for a newer one.
        let local = match self.read_body().await {
            Ok(body) => UserScriptMetadata::parse(&body).ok(),
            Err(_) => None,
        };

        let update_url = local
            .as_ref()
            .and_then(|metadata| metadata.update_url.clone())
            .unwrap_or_else(|| install_url.clone());
        let download_url = local
            .as_ref()
            .and_then(|metadata| metadata.download_url.clone())
            .unwrap_or_else(|| install_url.clone());

        // Only worth a separate request when it would save downloading the body.
        if update_url != download_url {
            let probe = fetch_userscript(&update_url, http_client).await?;
            let remote = UserScriptMetadata::parse(&probe)?;

            let local_version = local.as_ref().and_then(|metadata| metadata.version.clone());
            if !is_newer_version(remote.version.as_deref(), local_version.as_deref()) {
                return Ok(UserScriptUpdate::AlreadyCurrent);
            }
        }

        let body = fetch_userscript(&download_url, http_client).await?;
        let metadata = UserScriptMetadata::parse(&body)?;

        // Nothing changed upstream: skip the write so mtimes stay meaningful.
        let unchanged = local
            .as_ref()
            .and_then(|previous| previous.version.as_deref())
            .zip(metadata.version.as_deref())
            .map(|(previous, current)| previous == current)
            .unwrap_or(false);

        self.title = metadata.name.clone();

        if unchanged {
            return Ok(UserScriptUpdate::AlreadyCurrent);
        }

        self.write_body(&body).await?;

        Ok(UserScriptUpdate::Updated {
            version: metadata.version,
        })
    }
}

/// What happened to one script during a refresh, for reporting to the web UI.
#[derive(Debug, Clone, Serialize)]
pub struct UserScriptRefresh {
    pub file_name: String,
    pub title: String,
    #[serde(flatten)]
    pub outcome: RefreshOutcome,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum RefreshOutcome {
    Updated { version: Option<String> },
    AlreadyCurrent,
    Failed { error: String },
}

/// Outcome of refreshing one script from upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserScriptUpdate {
    Updated { version: Option<String> },
    AlreadyCurrent,
}

/// Whether `remote` supersedes `local`, by the dotted-numeric convention
/// userscript versions follow (`1.2.10` is newer than `1.2.9`).
///
/// Falls back to plain inequality when either side is missing or not dotted
/// numbers: re-downloading a script whose version scheme we cannot order is
/// harmless, whereas skipping a genuine update is not.
fn is_newer_version(remote: Option<&str>, local: Option<&str>) -> bool {
    let (Some(remote), Some(local)) = (remote, local) else {
        // Nothing to compare against; treat it as an update and let the body
        // comparison decide.
        return true;
    };

    fn numeric_parts(version: &str) -> Option<Vec<u64>> {
        version
            .split(['.', '-'])
            .map(|part| part.parse::<u64>().ok())
            .collect()
    }

    match (numeric_parts(remote), numeric_parts(local)) {
        (Some(remote_parts), Some(local_parts)) => {
            // Compare positionally, treating a missing trailing segment as 0 so
            // `1.2` and `1.2.0` are equal rather than ordered arbitrarily.
            let length = remote_parts.len().max(local_parts.len());
            for index in 0..length {
                let remote_part = remote_parts.get(index).copied().unwrap_or(0);
                let local_part = local_parts.get(index).copied().unwrap_or(0);
                if remote_part != local_part {
                    return remote_part > local_part;
                }
            }
            false
        }
        _ => remote != local,
    }
}

/// Fetch a script body over HTTP, enforcing the size cap.
pub(crate) async fn fetch_userscript(
    url: &Url,
    http_client: &reqwest::Client,
) -> super::ConfigurationResult<String> {
    let response = http_client.get(url.as_str()).send().await?;

    if !response.status().is_success() {
        return Err(super::ConfigurationError::UserScriptFetchError(format!(
            "{} returned {}",
            url,
            response.status()
        )));
    }

    let body = response.text().await?;
    if body.len() > MAX_USERSCRIPT_BYTES {
        return Err(UserScriptError::BodyTooLarge.into());
    }

    Ok(body)
}

/// File name for a script body. `seed` is the remote URL for an installed
/// script, or random bytes for a pasted one, so that two scripts never collide
/// and a script's identity survives edits to its contents.
pub(crate) fn calc_userscript_filename(seed: &str) -> String {
    format!("{}.user.js", super::calculate_sha256_hex(seed))
}

/// File name for a script with no remote URL.
pub(crate) fn calc_local_userscript_filename() -> String {
    calc_userscript_filename(&generate_random_hex(16))
}

/// Directory holding script bodies, or `None` when the configuration base
/// directory does not exist.
fn try_get_userscript_directory() -> Option<PathBuf> {
    let directory: PathBuf = match env::var("PRIVAXY_USERSCRIPT_PATH") {
        Ok(value) => PathBuf::from(&value),
        Err(_) => PathBuf::from(USERSCRIPTS_DIRECTORY_NAME),
    };

    super::get_base_directory()
        .ok()
        .map(|base| base.join(directory))
}

fn get_userscript_directory() -> PathBuf {
    try_get_userscript_directory().expect("configuration base directory must exist")
}

/// Cache directory for fetched assets, or `None` when the configuration base
/// directory does not exist — in which case callers fetch without caching
/// rather than failing.
fn try_get_userscript_asset_directory() -> Option<PathBuf> {
    try_get_userscript_directory().map(|directory| directory.join(USERSCRIPT_ASSETS_DIRECTORY_NAME))
}

/// Where `GM_setValue` data is persisted, or `None` when there is no
/// configuration directory — in which case values are kept in memory only.
///
/// Deliberately a separate file rather than a configuration key: these are
/// written far too often to re-serialize the whole configuration each time.
pub(crate) fn userscript_storage_path() -> Option<PathBuf> {
    try_get_userscript_directory().map(|directory| directory.join(USERSCRIPT_STORAGE_FILE_NAME))
}

/// Fetch a `@require` library or `@resource` payload, caching it on disk.
///
/// Cached assets are never re-fetched. The userscript convention is to pin a
/// versioned URL, and both Tampermonkey and Violentmonkey treat these as
/// immutable for the lifetime of a script version — re-downloading jQuery on
/// every configuration change would be pure waste. Delete the `assets`
/// directory to force a refresh.
pub(crate) async fn get_userscript_asset(
    url: &Url,
    http_client: &reqwest::Client,
) -> super::ConfigurationResult<String> {
    let asset = get_userscript_asset_bytes(url, http_client).await?;

    Ok(std::str::from_utf8(&asset.bytes)?.to_string())
}

/// A fetched `@resource`/`@require` payload with the content type it was served
/// as, so binary resources can be handed back to the page faithfully.
#[derive(Debug, Clone)]
pub struct UserScriptAsset {
    pub bytes: Vec<u8>,
    pub content_type: String,
}

/// Byte-oriented form of [`get_userscript_asset`], used for `@resource` where
/// the payload may be an image or a font rather than text.
///
/// The content type is cached alongside the body in a sibling `.type` file:
/// re-deriving it would mean re-fetching, which defeats the cache.
pub(crate) async fn get_userscript_asset_bytes(
    url: &Url,
    http_client: &reqwest::Client,
) -> super::ConfigurationResult<UserScriptAsset> {
    let cache_path = try_get_userscript_asset_directory()
        .map(|directory| directory.join(super::calculate_sha256_hex(url.as_str())));

    if let Some(path) = &cache_path {
        match fs::read(path).await {
            Ok(bytes) => {
                let content_type = fs::read_to_string(path.with_extension("type"))
                    .await
                    .unwrap_or_else(|_| DEFAULT_ASSET_CONTENT_TYPE.to_string());

                return Ok(UserScriptAsset {
                    bytes,
                    content_type,
                });
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(super::ConfigurationError::FileSystemError(err)),
        }
    }

    let response = http_client.get(url.as_str()).send().await?;
    if !response.status().is_success() {
        return Err(super::ConfigurationError::UserScriptFetchError(format!(
            "{} returned {}",
            url,
            response.status()
        )));
    }

    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or(DEFAULT_ASSET_CONTENT_TYPE)
        .to_string();

    let bytes = response.bytes().await?.to_vec();
    if bytes.len() > MAX_USERSCRIPT_BYTES {
        return Err(UserScriptError::BodyTooLarge.into());
    }

    let asset = UserScriptAsset {
        bytes,
        content_type,
    };

    if let Some(path) = &cache_path {
        // A cache write failure is not worth failing the fetch over: the asset
        // is in hand, it will simply be fetched again next time.
        if let Some(directory) = path.parent() {
            if let Err(err) = fs::create_dir_all(directory).await {
                log::warn!("Unable to create the userscript asset cache directory: {err}");
                return Ok(asset);
            }
        }
        if let Err(err) = fs::write(path, &asset.bytes).await {
            log::warn!("Unable to cache userscript asset {url}: {err}");
        } else if let Err(err) = fs::write(path.with_extension("type"), &asset.content_type).await {
            log::warn!("Unable to cache the content type for {url}: {err}");
        }
    }

    Ok(asset)
}

/// When a script runs relative to document parsing, mirroring `@run-at`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunAt {
    /// As soon as the document starts parsing — before any of the page's own
    /// scripts run.
    DocumentStart,
    /// As soon as `document.body` exists.
    DocumentBody,
    /// On `DOMContentLoaded`. The `@run-at` default, and therefore ours.
    #[default]
    DocumentEnd,
    /// On `window.load`.
    DocumentIdle,
}

impl RunAt {
    /// The `@run-at` token, as understood by the in-page shim.
    pub fn as_token(&self) -> &'static str {
        match self {
            Self::DocumentStart => "document-start",
            Self::DocumentBody => "document-body",
            Self::DocumentEnd => "document-end",
            Self::DocumentIdle => "document-idle",
        }
    }

    fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "document-start" => Self::DocumentStart,
            "document-body" => Self::DocumentBody,
            "document-idle" => Self::DocumentIdle,
            // Unknown values fall back to the `@run-at` default rather than
            // refusing the script.
            _ => Self::DocumentEnd,
        }
    }
}

/// Glob matcher honoring `*` only.
///
/// [`wildmatch::WildMatch`] (used for host exclusions) additionally treats `?`
/// as a single-character wildcard, which is wrong here: `?` is the query
/// separator and appears literally in `@include` patterns such as
/// `https://example.com/watch?v=*`. Userscript globs only ever define `*`.
fn glob_star_match(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();

    let mut pattern_index = 0;
    let mut text_index = 0;
    let mut last_star: Option<usize> = None;
    let mut text_index_at_star = 0;

    while text_index < text.len() {
        if pattern_index < pattern.len() && pattern[pattern_index] == '*' {
            last_star = Some(pattern_index);
            text_index_at_star = text_index;
            pattern_index += 1;
        } else if pattern_index < pattern.len() && (pattern[pattern_index] == text[text_index]) {
            pattern_index += 1;
            text_index += 1;
        } else if let Some(star_index) = last_star {
            // Backtrack: let the last `*` consume one more character.
            pattern_index = star_index + 1;
            text_index_at_star += 1;
            text_index = text_index_at_star;
        } else {
            return false;
        }
    }

    pattern[pattern_index..].iter().all(|char| *char == '*')
}

/// Scheme component of a match pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
enum MatchScheme {
    /// `*`, which in match-pattern syntax means `http` or `https` only.
    HttpOrHttps,
    Exact(String),
}

/// Host component of a match pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
enum MatchHost {
    /// `*` — any host.
    Any,
    /// `*.example.com` — `example.com` and any of its subdomains.
    WithSubdomains(String),
    Exact(String),
}

/// A Chrome-style match pattern: `<scheme>://<host><path>`, plus the
/// `<all_urls>` special case. This is `@match` (and `@exclude-match`) syntax,
/// which is stricter and less surprising than `@include` globbing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchPattern {
    scheme: MatchScheme,
    host: MatchHost,
    path: String,
    /// The pattern as written, for diagnostics.
    source: String,
}

impl MatchPattern {
    pub fn parse(pattern: &str) -> Result<Self, UserScriptError> {
        let source = pattern.trim().to_string();

        if source == "<all_urls>" {
            return Ok(Self {
                scheme: MatchScheme::HttpOrHttps,
                host: MatchHost::Any,
                path: "/*".to_string(),
                source,
            });
        }

        let (scheme_part, remainder) = source
            .split_once("://")
            .ok_or_else(|| UserScriptError::InvalidMatchPattern(source.clone()))?;

        let scheme = match scheme_part {
            "*" => MatchScheme::HttpOrHttps,
            "" => return Err(UserScriptError::InvalidMatchPattern(source.clone())),
            scheme => MatchScheme::Exact(scheme.to_ascii_lowercase()),
        };

        // Everything up to the first `/` is the host; the rest is the path.
        // A pattern with no path at all is invalid in Chrome but common in the
        // wild, so it is read as "any path".
        let (host_part, path) = match remainder.split_once('/') {
            Some((host_part, path)) => (host_part, format!("/{path}")),
            None => (remainder, "/*".to_string()),
        };

        let host_part = host_part.to_ascii_lowercase();
        let host = if host_part == "*" {
            MatchHost::Any
        } else if let Some(suffix) = host_part.strip_prefix("*.") {
            if suffix.is_empty() || suffix.contains('*') {
                return Err(UserScriptError::InvalidMatchPattern(source.clone()));
            }
            MatchHost::WithSubdomains(suffix.to_string())
        } else if host_part.is_empty() || host_part.contains('*') {
            // A bare `*` is handled above; any other `*` in a host is invalid.
            return Err(UserScriptError::InvalidMatchPattern(source.clone()));
        } else {
            MatchHost::Exact(host_part)
        };

        Ok(Self {
            scheme,
            host,
            path,
            source,
        })
    }

    /// Whether `url` satisfies every component of this pattern.
    pub fn matches(&self, url: &Url) -> bool {
        let scheme_matches = match &self.scheme {
            MatchScheme::HttpOrHttps => url.scheme() == "http" || url.scheme() == "https",
            MatchScheme::Exact(scheme) => url.scheme() == scheme,
        };
        if !scheme_matches {
            return false;
        }

        // `Url` normalizes the host to lowercase, and pattern hosts are
        // lowercased at parse time, so both sides are already comparable.
        let Some(host) = url.host_str() else {
            return false;
        };
        let host_matches = match &self.host {
            MatchHost::Any => true,
            MatchHost::WithSubdomains(suffix) => {
                host == suffix
                    || host
                        .strip_suffix(suffix)
                        .is_some_and(|prefix| prefix.ends_with('.'))
            }
            MatchHost::Exact(expected) => host == expected,
        };
        if !host_matches {
            return false;
        }

        glob_star_match(&self.path, &path_with_query(url))
    }

    pub fn as_str(&self) -> &str {
        &self.source
    }
}

/// The portion of a URL that match-pattern and `@include` paths are tested
/// against: path plus query string, excluding the fragment (which is not sent
/// to the server and is not part of the document's identity for matching).
fn path_with_query(url: &Url) -> String {
    match url.query() {
        Some(query) => format!("{}?{}", url.path(), query),
        None => url.path().to_string(),
    }
}

/// An `@include` / `@exclude` value. These are matched against the whole URL
/// and, unlike `@match`, may be a regular expression when written `/…/`.
#[derive(Debug, Clone)]
pub enum UrlPattern {
    Glob { pattern: String },
    Regex { regex: Regex, source: String },
}

impl UrlPattern {
    pub fn parse(pattern: &str) -> Result<Self, UserScriptError> {
        let pattern = pattern.trim();

        // `/…/` delimits a regular expression, as in Greasemonkey. Requires at
        // least one character between the slashes so a lone `/` stays a glob.
        if pattern.len() > 2 && pattern.starts_with('/') && pattern.ends_with('/') {
            let source = &pattern[1..pattern.len() - 1];
            let regex = Regex::new(source)
                .map_err(|_| UserScriptError::InvalidRegex(pattern.to_string()))?;

            return Ok(Self::Regex {
                regex,
                source: source.to_string(),
            });
        }

        Ok(Self::Glob {
            pattern: pattern.to_string(),
        })
    }

    pub fn matches(&self, url: &Url) -> bool {
        match self {
            // `Url::as_str` is already scheme- and host-normalized to
            // lowercase, so a pattern written in the conventional lowercase
            // form compares directly.
            Self::Glob { pattern } => glob_star_match(pattern, url.as_str()),
            Self::Regex { regex, .. } => regex.is_match(url.as_str()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Glob { pattern } => pattern,
            Self::Regex { source, .. } => source,
        }
    }
}

/// A `@resource` declaration: a name the script looks up via
/// `GM_getResourceText`, and the URL to fetch it from.
#[derive(Debug, Clone)]
pub struct ResourceDeclaration {
    pub name: String,
    pub url: Url,
}

/// The parsed `// ==UserScript==` header block.
#[derive(Debug, Clone)]
pub struct UserScriptMetadata {
    pub name: String,
    pub description: Option<String>,
    pub version: Option<String>,
    pub namespace: Option<String>,
    pub matches: Vec<MatchPattern>,
    pub exclude_matches: Vec<MatchPattern>,
    pub includes: Vec<UrlPattern>,
    pub excludes: Vec<UrlPattern>,
    pub run_at: RunAt,
    pub grants: Vec<String>,
    /// `@require` URLs, injected ahead of the script body in declaration order.
    pub requires: Vec<Url>,
    pub resources: Vec<ResourceDeclaration>,
    /// `@noframes` — run only in the top-level document.
    pub no_frames: bool,
    /// `@connect` hosts the script declares it will contact via
    /// `GM_xmlhttpRequest`. The relay refuses anything not listed here.
    pub connects: Vec<String>,
    /// `@updateURL` — where to look for a newer `@version` without downloading
    /// the whole script. Defaults to the install URL.
    pub update_url: Option<Url>,
    /// `@downloadURL` — where the full script is fetched from. Defaults to the
    /// install URL.
    pub download_url: Option<Url>,
}

impl UserScriptMetadata {
    /// Parse the metadata block out of a script body.
    ///
    /// Rejects a script that could never run (no `@match` and no `@include`)
    /// or whose patterns are malformed, so that a broken script is refused at
    /// install time rather than silently never firing.
    pub fn parse(body: &str) -> Result<Self, UserScriptError> {
        if body.trim().is_empty() {
            return Err(UserScriptError::EmptyBody);
        }

        let entries = parse_metadata_entries(body)?;

        let mut metadata = Self {
            name: String::new(),
            description: None,
            version: None,
            namespace: None,
            matches: Vec::new(),
            exclude_matches: Vec::new(),
            includes: Vec::new(),
            excludes: Vec::new(),
            run_at: RunAt::default(),
            grants: Vec::new(),
            requires: Vec::new(),
            resources: Vec::new(),
            no_frames: false,
            connects: Vec::new(),
            update_url: None,
            download_url: None,
        };

        for (key, value) in entries {
            match key.as_str() {
                "name" => metadata.name = value,
                "description" => metadata.description = Some(value),
                "version" => metadata.version = Some(value),
                "namespace" => metadata.namespace = Some(value),
                "match" => metadata.matches.push(MatchPattern::parse(&value)?),
                "exclude-match" => metadata.exclude_matches.push(MatchPattern::parse(&value)?),
                "include" => metadata.includes.push(UrlPattern::parse(&value)?),
                "exclude" => metadata.excludes.push(UrlPattern::parse(&value)?),
                "run-at" => metadata.run_at = RunAt::parse(&value),
                "grant" => metadata.grants.push(value),
                "noframes" => metadata.no_frames = true,
                "connect" => metadata.connects.push(value.trim().to_ascii_lowercase()),
                // A malformed update/download URL is ignored rather than fatal:
                // the script still runs, it just falls back to the install URL.
                "updateurl" => metadata.update_url = Url::parse(value.trim()).ok(),
                "downloadurl" => metadata.download_url = Url::parse(value.trim()).ok(),
                "require" => {
                    let url = Url::parse(&value)
                        .map_err(|_| UserScriptError::InvalidRequireUrl(value.clone()))?;
                    metadata.requires.push(url);
                }
                "resource" => {
                    // `@resource <name> <url>`
                    let (name, url) = value
                        .split_once(char::is_whitespace)
                        .ok_or_else(|| UserScriptError::InvalidRequireUrl(value.clone()))?;
                    let url = Url::parse(url.trim())
                        .map_err(|_| UserScriptError::InvalidRequireUrl(value.clone()))?;
                    metadata.resources.push(ResourceDeclaration {
                        name: name.to_string(),
                        url,
                    });
                }
                _ => {}
            }
        }

        if metadata.name.trim().is_empty() {
            return Err(UserScriptError::MissingName);
        }

        if metadata.matches.is_empty() && metadata.includes.is_empty() {
            return Err(UserScriptError::NoMatchDeclared);
        }

        Ok(metadata)
    }

    /// Whether `host` is covered by one of this script's `@connect` entries.
    ///
    /// Follows Tampermonkey's semantics: an entry matches the host itself and
    /// any subdomain of it, `*` permits everything, and matching is
    /// case-insensitive. `self` and `localhost` are not treated specially —
    /// reaching loopback is governed by
    /// [`UserScriptsConfig::allow_private_network_requests`] instead.
    pub fn permits_connection_to(&self, host: &str) -> bool {
        let host = host.trim().to_ascii_lowercase();

        self.connects.iter().any(|entry| {
            if entry == "*" {
                return true;
            }
            // A leading `*.` is accepted as a synonym for the bare domain form,
            // which already covers subdomains.
            let entry = entry.strip_prefix("*.").unwrap_or(entry);

            host == entry
                || host
                    .strip_suffix(entry)
                    .is_some_and(|prefix| prefix.ends_with('.'))
        })
    }

    /// Whether a script with this metadata should be injected into `url`.
    ///
    /// Exclusions win over inclusions, and `@match`/`@include` are additive —
    /// the same precedence userscript managers use.
    pub fn matches_url(&self, url: &Url) -> bool {
        if self.excludes.iter().any(|pattern| pattern.matches(url)) {
            return false;
        }
        if self
            .exclude_matches
            .iter()
            .any(|pattern| pattern.matches(url))
        {
            return false;
        }

        self.matches.iter().any(|pattern| pattern.matches(url))
            || self.includes.iter().any(|pattern| pattern.matches(url))
    }
}

/// Extract `(key, value)` pairs from the `// ==UserScript==` block.
///
/// Keys are returned without their `@`, lowercased. A key with no value (e.g.
/// `@noframes`) yields an empty value.
fn parse_metadata_entries(body: &str) -> Result<Vec<(String, String)>, UserScriptError> {
    let mut lines = body.lines();

    // The block may be preceded by anything (a shebang, a license header), so
    // scan rather than requiring it first.
    let found_opening = lines.any(|line| is_metadata_delimiter(line, "==UserScript=="));
    if !found_opening {
        return Err(UserScriptError::MissingMetadataBlock);
    }

    let mut entries = Vec::new();
    for line in lines {
        if is_metadata_delimiter(line, "==/UserScript==") {
            return Ok(entries);
        }

        let Some(directive) = line.trim().strip_prefix("//") else {
            continue;
        };
        let Some(directive) = directive.trim_start().strip_prefix('@') else {
            continue;
        };

        let (key, value) = match directive.split_once(char::is_whitespace) {
            Some((key, value)) => (key, value.trim()),
            None => (directive, ""),
        };
        if key.is_empty() {
            continue;
        }

        entries.push((key.to_ascii_lowercase(), value.to_string()));
    }

    Err(UserScriptError::UnterminatedMetadataBlock)
}

/// Whether `line` is the given metadata block delimiter, tolerating the
/// whitespace variations found in real scripts (`//==UserScript==`,
/// `// ==UserScript==`).
fn is_metadata_delimiter(line: &str, delimiter: &str) -> bool {
    line.trim()
        .strip_prefix("//")
        .map(|rest| rest.trim() == delimiter)
        .unwrap_or(false)
}

/// A script ready for injection: its parsed metadata plus the body (and any
/// `@require`d libraries) as they will be emitted into the page.
#[derive(Debug, Clone)]
pub struct CompiledUserScript {
    /// Stable identifier, matching [`UserScript::file_name`].
    pub file_name: String,
    pub title: String,
    pub metadata: UserScriptMetadata,
    pub body: String,
    /// Contents of the script's `@require` libraries, in declaration order.
    pub requires: Vec<String>,
    /// `@resource` payloads keyed by the name the script declared.
    pub resources: Vec<(String, UserScriptAsset)>,
    /// Non-fatal problems found while compiling — an unreachable `@require`,
    /// say. The script still runs; the web UI surfaces these so a script
    /// running without its library is visibly degraded rather than mysteriously
    /// broken.
    pub warnings: Vec<String>,
}

impl UserScriptAsset {
    /// The payload as text, when it decodes as UTF-8 and is small enough to be
    /// worth inlining into every matching page.
    pub fn inline_text(&self) -> Option<&str> {
        if self.bytes.len() > MAX_INLINE_RESOURCE_BYTES {
            return None;
        }

        std::str::from_utf8(&self.bytes).ok()
    }
}

impl CompiledUserScript {
    /// One resolved `@resource` payload by declared name.
    pub fn resource(&self, name: &str) -> Option<&UserScriptAsset> {
        self.resources
            .iter()
            .find(|(resource_name, _)| resource_name == name)
            .map(|(_, asset)| asset)
    }

    /// Compile a stored script and its body, resolving nothing over the
    /// network — call [`Self::resolve_assets`] to populate `requires` and
    /// `resources`.
    pub fn new(script: &UserScript, body: String) -> Result<Self, UserScriptError> {
        let metadata = UserScriptMetadata::parse(&body)?;

        Ok(Self {
            file_name: script.file_name.clone(),
            title: script.title.clone(),
            metadata,
            body,
            requires: Vec::new(),
            resources: Vec::new(),
            warnings: Vec::new(),
        })
    }

    /// Fetch (or read from cache) the script's `@require` libraries and
    /// `@resource` payloads.
    ///
    /// A failure to obtain one asset is recorded as a warning rather than
    /// returned as an error: dropping the whole script because a CDN is
    /// momentarily unreachable is worse than running it degraded, and the
    /// warning gives the operator something to act on.
    pub async fn resolve_assets(&mut self, http_client: &reqwest::Client) {
        // The URL lists are cloned up front so the fetch loops can push into
        // `self` without holding a borrow of `self.metadata`.
        let require_urls = self.metadata.requires.clone();
        let resource_declarations = self.metadata.resources.clone();

        for url in require_urls {
            match get_userscript_asset(&url, http_client).await {
                Ok(contents) => self.requires.push(contents),
                Err(err) => self.warnings.push(format!(
                    "@require {url} could not be loaded ({err}); the script may not work"
                )),
            }
        }

        for declaration in resource_declarations {
            match get_userscript_asset_bytes(&declaration.url, http_client).await {
                Ok(asset) => self.resources.push((declaration.name, asset)),
                Err(err) => self.warnings.push(format!(
                    "@resource {} ({}) could not be loaded ({err}); GM_getResourceText will return null for it",
                    declaration.name, declaration.url
                )),
            }
        }
    }

    pub fn matches(&self, url: &Url) -> bool {
        self.metadata.matches_url(url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(value: &str) -> Url {
        Url::parse(value).unwrap()
    }

    const MINIMAL_SCRIPT: &str = r#"// ==UserScript==
// @name         Test script
// @match        https://example.com/*
// ==/UserScript==
console.log("hi");
"#;

    #[test]
    fn parses_a_minimal_script() {
        let metadata = UserScriptMetadata::parse(MINIMAL_SCRIPT).expect("parses");

        assert_eq!(metadata.name, "Test script");
        assert_eq!(metadata.matches.len(), 1);
        // `@run-at` defaults to document-end, as in every userscript manager.
        assert_eq!(metadata.run_at, RunAt::DocumentEnd);
        assert!(!metadata.no_frames);
    }

    #[test]
    fn parses_the_full_header_block() {
        let script = r#"#!/usr/bin/env node
// some preamble
// ==UserScript==
// @name        Full
// @namespace   https://privaxy.test/
// @version     1.2.3
// @description Does things
// @match       *://*.example.com/*
// @exclude-match https://example.com/admin/*
// @include     /^https?:\/\/regex\.test\//
// @exclude     https://example.com/logout*
// @run-at      document-start
// @grant       GM_setValue
// @grant       GM_getValue
// @require     https://cdn.test/lib.js
// @resource    styles https://cdn.test/style.css
// @noframes
// ==/UserScript==
body();
"#;

        let metadata = UserScriptMetadata::parse(script).expect("parses");

        assert_eq!(metadata.name, "Full");
        assert_eq!(metadata.namespace.as_deref(), Some("https://privaxy.test/"));
        assert_eq!(metadata.version.as_deref(), Some("1.2.3"));
        assert_eq!(metadata.description.as_deref(), Some("Does things"));
        assert_eq!(metadata.run_at, RunAt::DocumentStart);
        assert_eq!(metadata.grants, vec!["GM_setValue", "GM_getValue"]);
        assert_eq!(metadata.requires.len(), 1);
        assert_eq!(metadata.resources.len(), 1);
        assert_eq!(metadata.resources[0].name, "styles");
        assert!(metadata.no_frames);
        assert_eq!(metadata.exclude_matches.len(), 1);
        assert_eq!(metadata.includes.len(), 1);
        assert_eq!(metadata.excludes.len(), 1);
    }

    #[test]
    fn rejects_scripts_that_could_never_run() {
        let no_block = "console.log('hi');";
        assert!(matches!(
            UserScriptMetadata::parse(no_block),
            Err(UserScriptError::MissingMetadataBlock)
        ));

        let unterminated = "// ==UserScript==\n// @name x\n// @match https://a.test/*\n";
        assert!(matches!(
            UserScriptMetadata::parse(unterminated),
            Err(UserScriptError::UnterminatedMetadataBlock)
        ));

        let no_match = "// ==UserScript==\n// @name x\n// ==/UserScript==\n";
        assert!(matches!(
            UserScriptMetadata::parse(no_match),
            Err(UserScriptError::NoMatchDeclared)
        ));

        let no_name = "// ==UserScript==\n// @match https://a.test/*\n// ==/UserScript==\n";
        assert!(matches!(
            UserScriptMetadata::parse(no_name),
            Err(UserScriptError::MissingName)
        ));

        assert!(matches!(
            UserScriptMetadata::parse("   "),
            Err(UserScriptError::EmptyBody)
        ));
    }

    #[test]
    fn match_pattern_host_wildcards() {
        let pattern = MatchPattern::parse("*://*.example.com/*").unwrap();

        // `*.example.com` covers the bare domain and any subdomain, but must
        // not match a domain that merely ends with the same text.
        assert!(pattern.matches(&url("https://example.com/")));
        assert!(pattern.matches(&url("http://www.example.com/page")));
        assert!(pattern.matches(&url("https://deep.sub.example.com/a/b")));
        assert!(!pattern.matches(&url("https://notexample.com/")));
        assert!(!pattern.matches(&url("https://example.com.evil.test/")));
    }

    #[test]
    fn match_pattern_scheme_and_path() {
        let https_only = MatchPattern::parse("https://example.com/app/*").unwrap();
        assert!(https_only.matches(&url("https://example.com/app/x")));
        assert!(!https_only.matches(&url("http://example.com/app/x")));
        assert!(!https_only.matches(&url("https://example.com/other")));

        // `*` as a scheme means http or https only, never another scheme.
        let any_scheme = MatchPattern::parse("*://example.com/*").unwrap();
        assert!(any_scheme.matches(&url("http://example.com/")));
        assert!(!any_scheme.matches(&url("ftp://example.com/")));

        // `<all_urls>` matches any http(s) URL.
        let all = MatchPattern::parse("<all_urls>").unwrap();
        assert!(all.matches(&url("https://anything.test/deep/path")));
    }

    #[test]
    fn match_pattern_path_is_tested_against_path_and_query() {
        let pattern = MatchPattern::parse("https://example.com/watch?v=*").unwrap();

        assert!(pattern.matches(&url("https://example.com/watch?v=abc123")));
        assert!(!pattern.matches(&url("https://example.com/watch")));
    }

    #[test]
    fn match_pattern_rejects_malformed_input() {
        for pattern in [
            "example.com/*",
            "://example.com/*",
            "https://*example.com/*",
            "https://*./*",
        ] {
            assert!(
                MatchPattern::parse(pattern).is_err(),
                "expected {pattern} to be rejected"
            );
        }
    }

    /// `?` must be a literal, not a single-character wildcard — the reason
    /// `glob_star_match` exists instead of reusing `WildMatch`.
    #[test]
    fn glob_treats_question_mark_literally() {
        assert!(glob_star_match(
            "https://a.test/x?y=1",
            "https://a.test/x?y=1"
        ));
        assert!(!glob_star_match("https://a.test/x?", "https://a.test/xz"));
        assert!(glob_star_match("*", "anything"));
        assert!(glob_star_match("a*c", "abbbc"));
        assert!(glob_star_match("a*b*c", "axxbyyc"));
        assert!(!glob_star_match("a*c", "abd"));
        assert!(glob_star_match("a**", "a"));
    }

    #[test]
    fn include_supports_globs_and_regex() {
        let glob = UrlPattern::parse("https://example.com/*").unwrap();
        assert!(glob.matches(&url("https://example.com/page")));
        assert!(!glob.matches(&url("https://other.test/page")));

        let regex = UrlPattern::parse(r"/^https:\/\/(a|b)\.test\//").unwrap();
        assert!(regex.matches(&url("https://a.test/x")));
        assert!(regex.matches(&url("https://b.test/y")));
        assert!(!regex.matches(&url("https://c.test/z")));

        assert!(UrlPattern::parse("/(unclosed/").is_err());
    }

    #[test]
    fn exclusions_take_precedence_over_inclusions() {
        let script = r#"// ==UserScript==
// @name    Precedence
// @match   https://example.com/*
// @exclude https://example.com/admin*
// ==/UserScript==
"#;
        let metadata = UserScriptMetadata::parse(script).expect("parses");

        assert!(metadata.matches_url(&url("https://example.com/page")));
        assert!(!metadata.matches_url(&url("https://example.com/admin/users")));
    }

    #[test]
    fn master_switch_suppresses_every_script() {
        let script = UserScript {
            enabled: true,
            title: "x".to_string(),
            file_name: "x.user.js".to_string(),
            url: None,
        };

        let mut config = UserScriptsConfig {
            enabled: true,
            scripts: vec![script],
            ..UserScriptsConfig::default()
        };
        assert_eq!(config.active_scripts().count(), 1);

        config.enabled = false;
        assert_eq!(config.active_scripts().count(), 0);
    }

    #[test]
    fn disabled_scripts_are_not_active() {
        let config = UserScriptsConfig {
            enabled: true,
            scripts: vec![UserScript {
                enabled: false,
                title: "x".to_string(),
                file_name: "x.user.js".to_string(),
                url: None,
            }],
            ..UserScriptsConfig::default()
        };

        assert_eq!(config.active_scripts().count(), 0);
    }

    /// File names must be stable for a given URL (so re-installing the same
    /// script reuses its body) and unique for pasted scripts.
    #[test]
    fn file_names_are_stable_per_url_and_unique_per_paste() {
        let first = calc_userscript_filename("https://example.com/a.user.js");
        let second = calc_userscript_filename("https://example.com/a.user.js");
        assert_eq!(first, second);
        assert!(first.ends_with(".user.js"));

        assert_ne!(
            calc_local_userscript_filename(),
            calc_local_userscript_filename()
        );
    }

    /// The file-name guard is the last line of defense for the one path join
    /// that takes a non-constant component. Nothing containing a separator, a
    /// traversal sequence or an absolute path may satisfy it.
    #[test]
    fn only_generated_file_names_can_build_a_path() {
        let valid = calc_userscript_filename("https://example.com/a.user.js");
        assert!(is_valid_userscript_file_name(&valid));
        assert!(is_valid_userscript_file_name(
            &calc_local_userscript_filename()
        ));

        for candidate in [
            "../../../../etc/passwd",
            "../../etc/passwd.user.js",
            "/etc/passwd",
            "/etc/passwd.user.js",
            "..%2f..%2fetc%2fpasswd.user.js",
            "config",
            "",
            ".user.js",
            // Right length, wrong alphabet.
            &format!("{}.user.js", "z".repeat(64)),
            // Right alphabet, wrong length.
            &format!("{}.user.js", "a".repeat(63)),
            &format!("{}.user.js", "a".repeat(65)),
            // A separator smuggled into an otherwise valid-looking name.
            &format!("{}/{}.user.js", "a".repeat(32), "b".repeat(31)),
            // Correct shape but no suffix.
            &"a".repeat(64),
        ] {
            assert!(
                !is_valid_userscript_file_name(candidate),
                "{candidate:?} must be rejected"
            );
        }
    }

    /// A script carrying a hand-written file name cannot reach the filesystem.
    #[tokio::test]
    async fn traversal_file_names_are_refused_before_any_io() {
        let script = UserScript {
            enabled: true,
            title: "Hostile".to_string(),
            file_name: "../../../../etc/passwd".to_string(),
            url: None,
        };

        let err = script.read_body().await.expect_err("must be refused");
        assert!(
            matches!(
                err,
                super::super::ConfigurationError::UserScript(UserScriptError::InvalidFileName(_))
            ),
            "expected InvalidFileName, got {err:?}"
        );

        assert!(script.delete_body().await.is_err());
        assert!(script.write_body("x").await.is_err());
    }

    /// A resource small enough and valid UTF-8 is inlined; binary or oversized
    /// payloads are not, so the page is handed a URL instead of a base64 blob.
    #[test]
    fn only_small_text_resources_are_inlined() {
        let text = UserScriptAsset {
            bytes: b".a{color:red}".to_vec(),
            content_type: "text/css".to_string(),
        };
        assert_eq!(text.inline_text(), Some(".a{color:red}"));

        // Invalid UTF-8 (a PNG header) is never inlined as text.
        let binary = UserScriptAsset {
            bytes: vec![0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0xff, 0xfe],
            content_type: "image/png".to_string(),
        };
        assert_eq!(binary.inline_text(), None);

        let oversized = UserScriptAsset {
            bytes: vec![b'a'; MAX_INLINE_RESOURCE_BYTES + 1],
            content_type: "text/plain".to_string(),
        };
        assert_eq!(oversized.inline_text(), None);

        let at_limit = UserScriptAsset {
            bytes: vec![b'a'; MAX_INLINE_RESOURCE_BYTES],
            content_type: "text/plain".to_string(),
        };
        assert!(at_limit.inline_text().is_some());
    }

    #[test]
    fn connect_matching_covers_subdomains_and_wildcards() {
        let script = |connect: &str| {
            let body = format!(
                "// ==UserScript==\n// @name C\n// @match <all_urls>\n// @connect {connect}\n// ==/UserScript==\n"
            );
            UserScriptMetadata::parse(&body).expect("parses")
        };

        let exact = script("api.example.com");
        assert!(exact.permits_connection_to("api.example.com"));
        assert!(!exact.permits_connection_to("example.com"));
        assert!(!exact.permits_connection_to("evil.test"));

        // A bare domain covers its subdomains, as in Tampermonkey.
        let domain = script("example.com");
        assert!(domain.permits_connection_to("example.com"));
        assert!(domain.permits_connection_to("api.example.com"));
        // ...but must not match a domain that merely ends with the same text.
        assert!(!domain.permits_connection_to("notexample.com"));

        let wildcard = script("*");
        assert!(wildcard.permits_connection_to("anything.test"));

        // A script with no @connect at all reaches nothing.
        let none = UserScriptMetadata::parse(
            "// ==UserScript==\n// @name N\n// @match <all_urls>\n// ==/UserScript==\n",
        )
        .expect("parses");
        assert!(!none.permits_connection_to("example.com"));
    }

    #[test]
    fn version_comparison_orders_dotted_numbers() {
        // The case string comparison gets wrong.
        assert!(is_newer_version(Some("1.2.10"), Some("1.2.9")));
        assert!(!is_newer_version(Some("1.2.9"), Some("1.2.10")));

        assert!(is_newer_version(Some("2.0"), Some("1.9.9")));
        assert!(!is_newer_version(Some("1.0"), Some("2.0")));

        // Equal, including when written with different numbers of segments.
        assert!(!is_newer_version(Some("1.2"), Some("1.2")));
        assert!(!is_newer_version(Some("1.2"), Some("1.2.0")));
        assert!(!is_newer_version(Some("1.2.0"), Some("1.2")));
        assert!(is_newer_version(Some("1.2.1"), Some("1.2")));
    }

    #[test]
    fn version_comparison_falls_back_to_inequality() {
        // Not orderable as numbers: any difference counts as an update, since
        // re-downloading is harmless but skipping a real update is not.
        assert!(is_newer_version(Some("2.0-beta"), Some("1.0-alpha")));
        assert!(is_newer_version(Some("1.0-alpha"), Some("2.0-beta")));
        assert!(!is_newer_version(Some("same"), Some("same")));

        // A missing version on either side means we cannot tell; try.
        assert!(is_newer_version(None, Some("1.0")));
        assert!(is_newer_version(Some("1.0"), None));
        assert!(is_newer_version(None, None));
    }

    #[test]
    fn update_and_download_urls_are_parsed() {
        let script = "// ==UserScript==\n// @name U\n// @match <all_urls>\n\
                      // @updateURL   https://example.com/s.meta.js\n\
                      // @downloadURL https://example.com/s.user.js\n// ==/UserScript==\n";
        let metadata = UserScriptMetadata::parse(script).expect("parses");

        assert_eq!(
            metadata.update_url.as_ref().map(Url::as_str),
            Some("https://example.com/s.meta.js")
        );
        assert_eq!(
            metadata.download_url.as_ref().map(Url::as_str),
            Some("https://example.com/s.user.js")
        );
    }

    /// A malformed update URL must not make the script unusable — it just falls
    /// back to the URL it was installed from.
    #[test]
    fn malformed_update_urls_are_ignored_not_fatal() {
        let script = "// ==UserScript==\n// @name U\n// @match <all_urls>\n\
                      // @updateURL not-a-url\n// ==/UserScript==\n";
        let metadata = UserScriptMetadata::parse(script).expect("still parses");

        assert!(metadata.update_url.is_none());
    }

    #[test]
    fn run_at_tokens_round_trip() {
        for (token, expected) in [
            ("document-start", RunAt::DocumentStart),
            ("document-body", RunAt::DocumentBody),
            ("document-end", RunAt::DocumentEnd),
            ("document-idle", RunAt::DocumentIdle),
            // Unrecognized values fall back to the default.
            ("nonsense", RunAt::DocumentEnd),
        ] {
            assert_eq!(RunAt::parse(token), expected);
        }

        assert_eq!(RunAt::DocumentStart.as_token(), "document-start");
        assert_eq!(RunAt::DocumentIdle.as_token(), "document-idle");
    }
}
