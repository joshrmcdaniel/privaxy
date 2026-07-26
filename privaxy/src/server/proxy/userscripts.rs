//! Runtime store of compiled userscripts.
//!
//! Userscript changes made in the web UI must take effect on the next request,
//! not on the next reload. The proxy loop reads most configuration once per
//! (re)start — `scriptlet_debug_logging` is read that way in `lib.rs` — so
//! userscripts instead live behind this cheaply-cloneable handle, following the
//! same pattern as [`crate::proxy::exclusions::LocalExclusionStore`] and
//! [`crate::proxy::tls_failures::TlsFailureStore`]. Each API mutation replaces
//! the contents in place and every subsequent page load sees the new set.

use super::gm::storage::GmStorageStore;
use crate::configuration::{CompiledUserScript, Configuration};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use url::Url;

/// Everything the request path needs in order to serve userscripts.
///
/// Bundled rather than passed as three more arguments through
/// `serve_mitm_session` -> `serve` -> `Rewriter`, which already carry more
/// parameters than is comfortable.
#[derive(Debug, Clone)]
pub struct UserScriptContext {
    /// Compiled scripts, replaced in place whenever the configuration changes.
    pub store: UserScriptStore,
    /// Persistent `GM_setValue` data.
    pub gm_storage: GmStorageStore,
    /// Key the reserved-endpoint tokens are derived from. Read once per proxy
    /// (re)start, so both minting and verification always use the same value.
    pub endpoint_signing_key: String,
    /// Mirrors `userscripts.allow_private_network_requests`, consulted by the
    /// `GM_xmlhttpRequest` relay.
    ///
    /// Shared and atomic rather than a captured `bool`: the API updates it in
    /// place so toggling it in the web UI takes effect immediately, like every
    /// other userscript setting, instead of waiting for a reload.
    pub allow_private_network_requests: PrivateNetworkAccess,
}

/// Live switch for the relay's private-address filter.
#[derive(Debug, Clone, Default)]
pub struct PrivateNetworkAccess(Arc<AtomicBool>);

impl PrivateNetworkAccess {
    pub fn new(allowed: bool) -> Self {
        Self(Arc::new(AtomicBool::new(allowed)))
    }

    pub fn is_allowed(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }

    pub fn set(&self, allowed: bool) {
        self.0.store(allowed, Ordering::Relaxed);
    }
}

/// Shared, cheaply-cloneable set of compiled userscripts.
///
/// Scripts are held behind an `Arc` so matching a URL only clones pointers,
/// never script bodies, and the read lock is released before any of them is
/// used. Lock scopes are short and never held across an await point.
#[derive(Debug, Clone, Default)]
pub struct UserScriptStore(Arc<RwLock<Vec<Arc<CompiledUserScript>>>>);

impl UserScriptStore {
    pub fn new(scripts: Vec<CompiledUserScript>) -> Self {
        Self(Arc::new(RwLock::new(
            scripts.into_iter().map(Arc::new).collect(),
        )))
    }

    /// Swap in a freshly compiled set, discarding the previous one.
    pub fn replace(&self, scripts: Vec<CompiledUserScript>) {
        let mut guard = self.0.write().unwrap();
        *guard = scripts.into_iter().map(Arc::new).collect();
    }

    /// Scripts whose `@match`/`@include` declarations select `url`, in
    /// configuration order.
    pub fn matching(&self, url: &Url) -> Vec<Arc<CompiledUserScript>> {
        let guard = self.0.read().unwrap();

        guard
            .iter()
            .filter(|script| script.matches(url))
            .cloned()
            .collect()
    }

    /// Whether any script is loaded. Lets the request path skip URL parsing
    /// entirely in the common case of no userscripts installed.
    pub fn is_empty(&self) -> bool {
        self.0.read().unwrap().is_empty()
    }

    /// The compiled form of one script, by file name. Used by the API to report
    /// compile warnings without redoing the work.
    pub fn find(&self, file_name: &str) -> Option<Arc<CompiledUserScript>> {
        self.0
            .read()
            .unwrap()
            .iter()
            .find(|script| script.file_name == file_name)
            .cloned()
    }
}

/// Compile every active script in `configuration`, reading bodies from disk and
/// resolving each script's `@require`/`@resource` assets (cached on disk after
/// the first fetch).
///
/// A script that fails to load or no longer parses is logged and dropped rather
/// than aborting the whole rebuild — the same policy
/// [`crate::configuration::get_filters_content`] applies to filter lists. An
/// asset that fails to load only degrades its own script; see
/// [`CompiledUserScript::resolve_assets`].
pub async fn compile_active_userscripts(
    configuration: &Configuration,
    http_client: &reqwest::Client,
) -> Vec<CompiledUserScript> {
    let mut compiled = Vec::new();

    for script in configuration.userscripts.active_scripts() {
        let body = match script.read_body().await {
            Ok(body) => body,
            Err(err) => {
                log::warn!(
                    "Dropping userscript '{}' whose body could not be read: {err}",
                    script.title
                );
                continue;
            }
        };

        match CompiledUserScript::new(script, body) {
            Ok(mut compiled_script) => {
                compiled_script.resolve_assets(http_client).await;

                for warning in &compiled_script.warnings {
                    log::warn!("Userscript '{}': {warning}", compiled_script.title);
                }

                compiled.push(compiled_script);
            }
            Err(err) => log::warn!(
                "Dropping userscript '{}' that no longer parses: {err}",
                script.title
            ),
        }
    }

    log::debug!("Compiled {} userscript(s)", compiled.len());

    compiled
}

/// Rebuild the store from `configuration`. Called at startup and after every
/// mutation from the API so changes apply without a proxy restart.
pub async fn reload_userscripts(
    store: &UserScriptStore,
    configuration: &Configuration,
    http_client: &reqwest::Client,
) {
    store.replace(compile_active_userscripts(configuration, http_client).await);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::UserScript;

    fn compiled(name: &str, match_pattern: &str) -> CompiledUserScript {
        let body = format!(
            "// ==UserScript==\n// @name {name}\n// @match {match_pattern}\n// ==/UserScript==\nvoid 0;\n"
        );
        let script = UserScript {
            enabled: true,
            title: name.to_string(),
            file_name: format!("{name}.user.js"),
            url: None,
        };

        CompiledUserScript::new(&script, body).expect("compiles")
    }

    #[test]
    fn matching_selects_only_scripts_whose_patterns_match() {
        let store = UserScriptStore::new(vec![
            compiled("example-only", "https://example.com/*"),
            compiled("everywhere", "<all_urls>"),
        ]);

        let matched = store.matching(&Url::parse("https://example.com/page").unwrap());
        assert_eq!(matched.len(), 2);

        let matched = store.matching(&Url::parse("https://other.test/page").unwrap());
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].title, "everywhere");
    }

    /// A `@require` that cannot be fetched must degrade the script, not drop
    /// it: the body still runs and the failure is reported as a warning.
    #[tokio::test]
    async fn unreachable_require_becomes_a_warning() {
        let body = "// ==UserScript==\n// @name Needs a library\n// @match <all_urls>\n\
                    // @require http://127.0.0.1:1/never-listening.js\n// ==/UserScript==\nvoid 0;\n";
        let script = UserScript {
            enabled: true,
            title: "Needs a library".to_string(),
            file_name: "needs-a-library.user.js".to_string(),
            url: None,
        };

        let mut compiled = CompiledUserScript::new(&script, body.to_string()).expect("compiles");
        compiled.resolve_assets(&reqwest::Client::new()).await;

        assert!(compiled.requires.is_empty());
        assert_eq!(compiled.warnings.len(), 1);
        assert!(
            compiled.warnings[0].contains("@require"),
            "warning should name the failing directive: {}",
            compiled.warnings[0]
        );
        // Still injectable.
        assert!(compiled.matches(&Url::parse("https://anything.test/").unwrap()));
    }

    /// The store is what makes web-UI changes take effect without a reload, so
    /// a replacement must be visible through an already-cloned handle.
    #[test]
    fn replace_is_visible_through_existing_clones() {
        let store = UserScriptStore::new(Vec::new());
        let handle = store.clone();
        assert!(handle.is_empty());

        store.replace(vec![compiled("added", "<all_urls>")]);

        assert!(!handle.is_empty());
        assert_eq!(
            handle
                .matching(&Url::parse("https://anything.test/").unwrap())
                .len(),
            1
        );
    }
}
