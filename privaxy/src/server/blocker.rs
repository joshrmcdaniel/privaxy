use crate::blocker_utils::{build_resource_from_file_contents, read_redirectable_resource_mapping};
use crate::filter_list::{preprocess, FilterList, TRUSTED_SCRIPTLETS};
use adblock::lists::FilterSet;
use adblock::request::Request;
use adblock::resources::Resource;
use adblock::Engine;
use include_dir::{include_dir, Dir};
use lazy_static::lazy_static;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone)]
pub struct BlockingDisabledStore(pub Arc<RwLock<bool>>);

impl BlockingDisabledStore {
    pub fn is_enabled(&self) -> bool {
        !*self.0.read().unwrap()
    }

    pub fn set(&self, enabled: bool) {
        *self.0.write().unwrap() = !enabled
    }
}

#[derive(Debug)]
pub struct CosmeticBlockerResult {
    pub hidden_selectors: Vec<String>,
    pub style_selectors: HashMap<String, Vec<String>>,
    pub injected_script: Option<String>,
    /// JSON-encoded `ProceduralOrActionFilter` records that cannot be reduced to
    /// plain CSS (`:has-text`, `:matches-css`, `:upward`, `:xpath`, `:remove()`,
    /// …). These are handed to the in-page procedural shim, which evaluates them
    /// against the live DOM. Empty for the vast majority of hosts.
    pub procedural_filters: Vec<String>,
    /// Class/id exception selectors for this URL, to be passed back to
    /// `get_generic_class_id_selectors` once the document's ids and classes have
    /// been collected. Carrying them here is what lets the expensive
    /// `url_cosmetic_resources` lookup run once per page instead of twice.
    pub exceptions: HashSet<String>,
    /// Whether a `$generichide` exception filter applies to this URL, in which
    /// case the end-of-body generic class/id lookup must be skipped entirely.
    pub generichide: bool,
}

impl CosmeticBlockerResult {
    fn empty() -> Self {
        Self {
            hidden_selectors: Vec::new(),
            style_selectors: HashMap::new(),
            injected_script: None,
            procedural_filters: Vec::new(),
            exceptions: HashSet::new(),
            generichide: false,
        }
    }
}

lazy_static! {
    static ref ADBLOCKING_RESOURCES: Vec<Resource> = {
        // uBO's modern `scriptlets.js` is preprocessed at build time into the
        // adblock-rust Resource JSON schema (see build.rs / build-scriptlets.mjs).
        // The legacy `/// name`-header parser in `blocker_utils` no longer
        // matches the upstream format and would yield an empty list.
        let mut resources: Vec<Resource> = serde_json::from_str(include_str!(concat!(
            env!("OUT_DIR"),
            "/scriptlets-resources.json"
        )))
        .expect("generated scriptlets-resources.json must be valid JSON");

        static WEB_ACCESSIBLE_RESOURCES: Dir = include_dir!(
            "$CARGO_MANIFEST_DIR/src/resources/vendor/ublock/web_accessible_resources/"
        );

        let resource_properties = read_redirectable_resource_mapping(include_str!(
            "../resources/vendor/ublock/redirect-resources.js"
        ));

        resources.extend(resource_properties.iter().filter_map(|resource_info| {
            WEB_ACCESSIBLE_RESOURCES
                .get_file(&resource_info.name)
                .map(|resource| {
                    build_resource_from_file_contents(resource.contents(), resource_info)
                })
        }));

        resources
    };
}

/// A `BlockerResult` representing "no filter matched", used whenever matching is
/// bypassed (blocking disabled, unparseable request).
fn unmatched_result() -> adblock::blocker::BlockerResult {
    adblock::blocker::BlockerResult::default()
}

/// Build an engine from raw filter lists. CPU-heavy — seconds for full-size
/// lists — so callers must not run it on an async task directly.
fn build_engine(filters: Vec<FilterList>) -> Engine {
    log::debug!("Configuring blocking engine.");

    let mut filter_set = FilterSet::new(true);
    let mut sources = Vec::new();

    for filter in filters {
        let parsed = match preprocess(&filter.contents) {
            Ok(parsed) => parsed,
            Err(error) => {
                log::warn!("Skipping filter list '{}': {error}", filter.name);
                continue;
            }
        };
        if parsed.unknown_conditions > 0 {
            log::warn!(
                "Filter list '{}': {} unknown conditions left unfiltered",
                filter.name,
                parsed.unknown_conditions
            );
        }
        let options = adblock::lists::ParseOptions {
            permissions: if filter.trusted {
                TRUSTED_SCRIPTLETS
            } else {
                Default::default()
            },
            ..Default::default()
        };
        // The engine parses complete lists iteratively. Preserve their trust
        // permissions and use its source metadata for rejection diagnostics.
        let contents = parsed
            .lines
            .into_iter()
            .filter(|line| {
                !line.is_empty()
                    && !line.starts_with('!')
                    && !line.starts_with("[Adblock")
                    && !line.strip_prefix('#').is_some_and(|rest| {
                        rest.is_empty() || rest.starts_with(char::is_whitespace)
                    })
            })
            .collect::<Vec<_>>()
            .join("\n");
        filter_set.add_filter_list(contents, options);
        sources.push((filter.name, options));
    }

    let mut adblock_engine = Engine::new_with_filter_set(filter_set);
    for (source, (name, options)) in adblock_engine
        .get_debug_info()
        .source_info
        .into_iter()
        .zip(sources)
    {
        if source.parse_error == 0 {
            continue;
        }
        let mut rejection_reasons = BTreeMap::<String, usize>::new();
        // Reparse only rejected rules to obtain the individual error reasons.
        for line in source.invalid_lines {
            if let Err(error) = adblock::lists::parse_filter(&line, false, options) {
                // Regex errors can include private URLs from custom filters.
                let reason = match error {
                    adblock::lists::FilterParseError::Network(
                        adblock::filters::network::NetworkFilterError::RegexParsingError(_),
                    ) => "network filter error: invalid regular expression".to_owned(),
                    error => error.to_string(),
                };
                *rejection_reasons.entry(reason).or_default() += 1;
            }
        }
        let supported = source.network_filter_count + source.cosmetic_filter_count;
        let unsupported = source.parse_error;
        let reasons = rejection_reasons
            .iter()
            .map(|(reason, count)| format!("{count} {reason}"))
            .collect::<Vec<_>>()
            .join("; ");
        log::warn!(
            "Filter list '{name}': loaded {supported} rules; skipped {unsupported} unsupported or invalid rules ({reasons})"
        );
    }
    adblock_engine.use_resources(ADBLOCKING_RESOURCES.clone());

    adblock_engine
}

/// The URL-scoped cosmetic lookup: hide/style selectors, scriptlets and
/// procedural filters for one page, plus the exception set and `generichide`
/// flag the end-of-body generic class/id lookup needs.
fn cosmetic_response(engine: &Engine, url: &str) -> CosmeticBlockerResult {
    let url_specific_resources = engine.url_cosmetic_resources(url);

    let hidden_selectors: Vec<String> = url_specific_resources.hide_selectors.into_iter().collect();

    let injected_script = if !url_specific_resources.injected_script.is_empty() {
        Some(url_specific_resources.injected_script)
    } else {
        None
    };

    // adblock 0.12 replaced UrlSpecificResources::style_selectors
    // with `procedural_actions`, a HashSet of JSON-encoded
    // ProceduralOrActionFilter records. Records that reduce to
    // pure CSS via `as_css()` are applied server-side as a
    // (selector -> style) map. The rest need in-page JS to
    // evaluate (`:has-text`, `:matches-css`, `:upward`, `:xpath`,
    // `:remove()`, …); their raw JSON is forwarded to the
    // procedural shim injected into the page.
    let mut style_selectors: HashMap<String, Vec<String>> = HashMap::new();
    let mut procedural_filters: Vec<String> = Vec::new();
    for raw in url_specific_resources.procedural_actions.iter() {
        let Ok(filter) =
            serde_json::from_str::<adblock::cosmetic_filter_cache::ProceduralOrActionFilter>(raw)
        else {
            continue;
        };
        match filter.as_css() {
            Some((selector, style)) => {
                style_selectors.entry(selector).or_default().push(style);
            }
            None => procedural_filters.push(raw.clone()),
        }
    }

    CosmeticBlockerResult {
        hidden_selectors,
        style_selectors,
        injected_script,
        procedural_filters,
        exceptions: url_specific_resources.exceptions,
        generichide: url_specific_resources.generichide,
    }
}

/// Shared handle to the adblock engine.
///
/// adblock 0.12's `Engine` is `Send + Sync` (the crate statically asserts it),
/// so matching no longer needs the historical dedicated blocker thread and its
/// per-request channel round-trip: network checks run inline on the calling
/// task (they are microsecond-scale), while the heavier cosmetic lookups and
/// engine rebuilds run on the blocking pool. Engine replacement builds the new
/// engine off to the side and swaps the `Arc` atomically, so requests keep
/// matching against the previous engine during a multi-second list rebuild
/// instead of queueing behind it.
#[derive(Clone)]
pub(crate) struct AdblockRequester {
    engine: Arc<RwLock<Arc<Engine>>>,
    blocking_disabled: BlockingDisabledStore,
}

impl AdblockRequester {
    pub(crate) fn new(blocking_disabled: BlockingDisabledStore) -> Self {
        // Use an empty filter set until the configured lists finish loading.
        Self {
            engine: Arc::new(RwLock::new(Arc::new(Engine::new_with_filter_set(
                FilterSet::new(true),
            )))),
            blocking_disabled,
        }
    }

    fn current_engine(&self) -> Arc<Engine> {
        self.engine.read().unwrap().clone()
    }

    pub(crate) async fn replace_engine(&self, filters: Vec<FilterList>) {
        let new_engine = tokio::task::spawn_blocking(move || build_engine(filters))
            .await
            .expect("engine build task panicked");

        *self.engine.write().unwrap() = Arc::new(new_engine);
    }

    pub(crate) async fn get_cosmetic_response(&self, url: String) -> CosmeticBlockerResult {
        if !self.blocking_disabled.is_enabled() {
            return CosmeticBlockerResult::empty();
        }

        let engine = self.current_engine();

        tokio::task::spawn_blocking(move || cosmetic_response(&engine, &url))
            .await
            .expect("cosmetic lookup task panicked")
    }

    /// The end-of-body half of the cosmetic lookup: generic hide selectors
    /// indexed by the classes and ids actually present in the document.
    /// `exceptions` must come from this page's `get_cosmetic_response`.
    pub(crate) async fn get_generic_class_id_selectors(
        &self,
        classes: Vec<String>,
        ids: Vec<String>,
        exceptions: HashSet<String>,
    ) -> Vec<String> {
        if !self.blocking_disabled.is_enabled() {
            return Vec::new();
        }

        let engine = self.current_engine();

        tokio::task::spawn_blocking(move || {
            engine.hidden_class_id_selectors(&classes, &ids, &exceptions)
        })
        .await
        .expect("generic selector lookup task panicked")
    }

    pub(crate) fn is_network_url_blocked(
        &self,
        network_url: &str,
        // adblock-rust request type string (e.g. "script", "xmlhttprequest",
        // "image", "sub_frame", "document"). Required for the engine to honour
        // type-scoped filter and exception rules ($script, $xhr, $image, …);
        // passing a constant here silently defeats those rules.
        referer: &str,
        request_type: &str,
        method: &str,
    ) -> (bool, adblock::blocker::BlockerResult) {
        if !self.blocking_disabled.is_enabled() {
            return (false, unmatched_result());
        }

        let request = match Request::new(network_url, referer, request_type, method) {
            Ok(request) => request,
            // An unparseable URL cannot be matched against filters; let it
            // through rather than failing the whole request.
            Err(_) => return (false, unmatched_result()),
        };

        let blocker_result = self.current_engine().check_network_request(&request);

        (blocker_result.should_block(), blocker_result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(contents: &str) -> FilterList {
        FilterList {
            name: "Test list".to_owned(),
            contents: contents.to_owned(),
            trusted: false,
        }
    }

    #[test]
    fn conditional_blocks_affect_matching_and_do_not_leak_between_lists() {
        let engine = build_engine(vec![
            list("!#if cap_html_filtering\n||html.example^\n!#else\n||fallback.example^\n!#endif"),
            list("||other.example^"),
        ]);
        for (host, expected) in [
            ("html.example", false),
            ("fallback.example", true),
            ("other.example", true),
        ] {
            let request = Request::new(
                &format!("https://{host}/ad.js"),
                "https://site.example/",
                "script",
                "GET",
            )
            .unwrap();
            assert_eq!(
                engine.check_network_request(&request).should_block(),
                expected
            );
        }
    }

    #[test]
    fn modern_json_edit_scriptlets_include_their_shared_dependencies() {
        let engine = build_engine(vec![list("m.youtube.com##+js(json-edit-fetch-response, ..itemSectionRenderer.contents.*[?.adSlotRenderer], propsToMatch, /get_watch)")]);
        let result = cosmetic_response(&engine, "https://m.youtube.com/");
        let script = result.injected_script.unwrap();
        assert!(script.contains("function jsonEditFetchResponse("));
        assert!(script.contains("class JSONPath"));
        assert!(script.contains("function safeSelf("));
        assert!(script.contains("jsonEditFetchResponse(\"..itemSectionRenderer.contents.*[?.adSlotRenderer]\", \"propsToMatch\", \"/get_watch\")"));
    }

    #[test]
    fn trusted_scriptlets_require_trusted_list_permissions() {
        let rules =
            "example.com##+js(trusted-replace-fetch-response, adPlacements, no_ads, player?)";
        let engine = build_engine(vec![list(rules)]);
        assert!(cosmetic_response(&engine, "https://example.com/")
            .injected_script
            .is_none());
        let mut trusted = list(rules);
        trusted.trusted = true;
        let engine = build_engine(vec![trusted]);
        assert!(cosmetic_response(&engine, "https://example.com/")
            .injected_script
            .is_some());
    }

    #[test]
    fn scriptlets_receive_more_than_nine_arguments_and_no_literal_placeholders() {
        let engine = build_engine(vec![list("example.com##+js(json-prune-fetch-response, ads, , propsToMatch, player, log, 1, stackToMatch, test, extra, tenth, eleventh)")]);
        let script = cosmetic_response(&engine, "https://example.com/")
            .injected_script
            .unwrap();
        assert!(script.contains("\"tenth\", \"eleventh\")"));
        assert!(!script.contains("{{1}}"));
    }

    fn requester() -> AdblockRequester {
        AdblockRequester::new(BlockingDisabledStore(Arc::new(RwLock::new(false))))
    }

    #[tokio::test]
    async fn empty_engine_blocks_nothing() {
        let (blocked, result) = requester().is_network_url_blocked(
            "https://ads.example.com/track.js",
            "https://example.com/",
            "script",
            "GET",
        );

        assert!(!blocked);
        assert!(!result.should_block());
    }

    #[tokio::test]
    async fn replace_engine_applies_network_filters() {
        let requester = requester();
        requester
            .replace_engine(vec![list("||ads.example.com^")])
            .await;

        let (blocked, result) = requester.is_network_url_blocked(
            "https://ads.example.com/track.js",
            "https://example.com/",
            "script",
            "GET",
        );

        assert!(blocked);
        assert!(result.should_block());

        let (blocked, _result) = requester.is_network_url_blocked(
            "https://example.com/site.js",
            "https://example.com/",
            "script",
            "GET",
        );

        assert!(!blocked);
    }

    #[tokio::test]
    async fn method_filters_and_exceptions_use_the_actual_request_method() {
        let requester = requester();
        requester
            .replace_engine(vec![list(
                "||example.test/ad$method=POST\n@@||example.test/ad/allowed$method=POST",
            )])
            .await;
        for (path, method, expected) in [
            ("ad", "POST", true),
            ("ad", "GET", false),
            ("ad", "HEAD", false),
            ("ad/allowed", "POST", false),
        ] {
            let (blocked, _) = requester.is_network_url_blocked(
                &format!("https://example.test/{path}"),
                "https://example.test/",
                "xmlhttprequest",
                method,
            );
            assert_eq!(blocked, expected, "{method} {path}");
        }
    }

    #[tokio::test]
    async fn disabling_blocking_bypasses_matching() {
        let requester = requester();
        requester
            .replace_engine(vec![list("||ads.example.com^")])
            .await;
        requester.blocking_disabled.set(false);

        let (blocked, _result) = requester.is_network_url_blocked(
            "https://ads.example.com/track.js",
            "https://example.com/",
            "script",
            "GET",
        );

        assert!(!blocked);

        let cosmetic = requester
            .get_cosmetic_response(String::from("https://example.com/"))
            .await;
        assert!(cosmetic.hidden_selectors.is_empty());
    }

    #[tokio::test]
    async fn cosmetic_lookup_splits_url_scoped_and_generic_selectors() {
        let requester = requester();
        requester
            .replace_engine(vec![list("example.com###site-ad\n##.generic-ad-class")])
            .await;

        // The URL-scoped lookup carries the specific selector but not the
        // class-indexed generic one, which only the end-of-body lookup —
        // fed with the classes present in the document — should return.
        let cosmetic = requester
            .get_cosmetic_response(String::from("https://example.com/"))
            .await;
        assert!(cosmetic
            .hidden_selectors
            .contains(&String::from("#site-ad")));
        assert!(!cosmetic.generichide);

        let generic = requester
            .get_generic_class_id_selectors(
                vec![String::from("generic-ad-class")],
                Vec::new(),
                cosmetic.exceptions,
            )
            .await;
        assert_eq!(generic, vec![String::from(".generic-ad-class")]);
    }
}
