use super::gm::storage::GmStorageStore;
use super::BodySender;
use crate::configuration::CompiledUserScript;
use crate::{blocker::AdblockRequester, statistics::Statistics};
use bytes::Bytes;
use crossbeam_channel::Receiver;
use hyper::body::Frame;
use lol_html::html_content::ContentType;
use lol_html::{element, HtmlRewriter, Settings};
use regex::Regex;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

type InternalBodyChannel = (
    mpsc::UnboundedSender<(Bytes, Option<AdblockProperties>)>,
    mpsc::UnboundedReceiver<(Bytes, Option<AdblockProperties>)>,
);

struct AdblockProperties {
    url: String,
    ids: HashSet<String>,
    classes: HashSet<String>,
}

pub struct Rewriter {
    url: String,
    adblock_requester: AdblockRequester,
    receiver: Receiver<Bytes>,
    body_sender: BodySender,
    statistics: Statistics,
    internal_body_channel: InternalBodyChannel,
    csp_nonce: String,
    // Scriptlets (uBO `##+js(...)`) need to run before page scripts get a
    // reference to the globals they hook (setTimeout, eval, etc.), so this is
    // injected early into `<head>` rather than appended at end-of-body.
    injected_script: Option<String>,
    // Procedural cosmetic filters (`:has-text`, `:upward`, `:xpath`, …) that
    // can't be reduced to plain CSS. Each entry is one JSON-encoded
    // `ProceduralOrActionFilter`; they're handed to the in-page shim injected
    // into `<head>` alongside the scriptlets.
    procedural_filters: Vec<String>,
    // When set (config `debug.scriptlet_console_logging`), the empty
    // per-scriptlet `catch` emitted by adblock-rust is rewritten to log the
    // caught error to the page console instead of swallowing it.
    scriptlet_debug_logging: bool,
    // Userscripts whose `@match`/`@include` select this URL, resolved from the
    // runtime store before the rewriter was built.
    user_scripts: Vec<Arc<CompiledUserScript>>,
    // Persisted `GM_setValue` data. `GM_getValue` is synchronous in the GM API,
    // so each script's values are preloaded into its descriptor rather than
    // fetched in-page.
    gm_storage: GmStorageStore,
    // Token authorizing this page's writes back to the reserved endpoint.
    // `None` when the request URI had no derivable origin, in which case
    // persistence is unavailable and the runtime falls back to memory.
    endpoint_token: Option<String>,
}

/// In-page evaluator for procedural cosmetic filters. Defines the idempotent
/// `window.__privaxyApplyProcedural(filters)` global; see the source file for
/// the supported operators and actions.
const PROCEDURAL_COSMETICS_SHIM: &str = include_str!("../../resources/procedural_cosmetics.js");

/// In-page userscript runtime; defines `window.__privaxyRunUserScript`.
const USERSCRIPT_SHIM: &str = include_str!("../../resources/userscript_shim.js");

/// The `GM_*` names handed to every userscript, in the order they are passed.
///
/// This list is authored here and emitted twice into the page — once as the
/// wrapper function's parameter list, once as the array the shim uses to look
/// up implementations by name — so the two can never drift. A name the shim
/// does not implement arrives as `undefined`, which lets scripts feature-detect
/// rather than die on a `ReferenceError`.
const USERSCRIPT_API_NAMES: &[&str] = &[
    "GM_info",
    "unsafeWindow",
    "GM_addStyle",
    "GM_log",
    "GM_setValue",
    "GM_getValue",
    "GM_deleteValue",
    "GM_listValues",
    "GM_openInTab",
    "GM_setClipboard",
    "GM_notification",
    "GM_registerMenuCommand",
    "GM_unregisterMenuCommand",
    "GM_getResourceText",
    "GM_getResourceURL",
    "GM_addValueChangeListener",
    "GM_removeValueChangeListener",
    "GM_xmlhttpRequest",
    "GM_xmlHttpRequest",
    "GM",
];

/// Neutralize any `</script` sequence in JavaScript destined for an inline
/// `<script>` element: the HTML parser ends the element at the first such
/// sequence regardless of JavaScript string quoting.
fn escape_inline_script(source: &str) -> String {
    source.replace("</", "<\\/")
}

/// Wrap JavaScript in a nonce-carrying inline `<script>` element.
fn inline_script_tag(source: &str, csp_nonce: &str) -> String {
    format!(
        "<script type=\"application/javascript\" nonce=\"{}\">{}</script>",
        csp_nonce,
        escape_inline_script(source)
    )
}

impl Rewriter {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        url: String,
        adblock_requester: AdblockRequester,
        receiver: Receiver<Bytes>,
        body_sender: BodySender,
        statistics: Statistics,
        csp_nonce: String,
        injected_script: Option<String>,
        procedural_filters: Vec<String>,
        scriptlet_debug_logging: bool,
        user_scripts: Vec<Arc<CompiledUserScript>>,
        gm_storage: GmStorageStore,
        endpoint_token: Option<String>,
    ) -> Self {
        Self {
            url,
            body_sender,
            statistics,
            adblock_requester,
            receiver,
            internal_body_channel: mpsc::unbounded_channel(),
            csp_nonce,
            injected_script,
            procedural_filters,
            scriptlet_debug_logging,
            user_scripts,
            gm_storage,
            endpoint_token,
        }
    }

    /// Combine the uBO scriptlet payload and the procedural-filter shim into a
    /// single `<head>` script body, or `None` when there's nothing to inject.
    /// Scriptlets come first so they hook globals before page scripts run; the
    /// procedural shim follows and sets up its own DOM observer.
    fn build_head_script(
        injected_script: Option<String>,
        procedural_filters: &[String],
        scriptlet_debug_logging: bool,
    ) -> Option<String> {
        if injected_script.is_none() && procedural_filters.is_empty() {
            return None;
        }

        let mut payload = String::new();

        if let Some(mut script) = injected_script {
            // adblock-rust isolates each scriptlet in an empty `catch ( e ) { }`.
            // When debugging is enabled, surface what was caught rather than
            // swallowing it (this is what hid the missing `scriptletGlobals`).
            if scriptlet_debug_logging {
                script = script.replace(
                    "} catch ( e ) { }",
                    "} catch (e) { console.error('[privaxy scriptlet]', e); }",
                );
            }
            // adblock-rust emits scriptlet bodies that reference an ambient
            // `scriptletGlobals` object — uBO supplies it in its own injection
            // wrapper, but adblock-rust leaves that to the embedder. Without it
            // every scriptlet hits `ReferenceError: scriptletGlobals is not
            // defined` on its first `safeSelf()`/`shouldDebug()` call, which the
            // scriptlet's own `try { … } catch {}` swallows — so all scriptlets
            // silently no-op. Defining it once at the top of the payload (the
            // scriptlet bodies use dot-access, so it must be an object)
            // so the scriptlets actually work.
            payload.push_str("const scriptletGlobals = {};\n");
            payload.push_str(&script);
        }

        if !procedural_filters.is_empty() {
            if !payload.is_empty() {
                payload.push('\n');
            }
            payload.push_str(PROCEDURAL_COSMETICS_SHIM);
            // Each filter is already valid JSON, so they're spliced straight
            // into an array literal without re-serialization.
            payload.push_str(";window.__privaxyApplyProcedural([");
            payload.push_str(&procedural_filters.join(","));
            payload.push_str("]);");
        }

        Some(payload)
    }

    /// Build the `<script>` elements carrying the matched userscripts, or `None`
    /// when none matched.
    ///
    /// The runtime goes in its own element and each script gets another, so a
    /// syntax error in one userscript is contained: the browser abandons only
    /// that element. Sharing a single element with the blocking payload would
    /// let one malformed script disable ad blocking for the whole page.
    ///
    /// The runtime is wrapped in an IIFE taking the CSP nonce as an argument so
    /// the nonce stays in a closure. Publishing it on `window` would hand page
    /// scripts a way around the page's own Content-Security-Policy.
    fn build_userscript_tags(
        user_scripts: &[Arc<CompiledUserScript>],
        csp_nonce: &str,
        gm_storage: &GmStorageStore,
        endpoint_token: Option<&str>,
    ) -> Option<String> {
        if user_scripts.is_empty() {
            return None;
        }

        // The nonce and the endpoint token are passed as IIFE arguments so
        // they stay in the runtime's closure rather than on `window`.
        let runtime = format!(
            "(function(PRIVAXY_NONCE, PRIVAXY_ENDPOINT_TOKEN){{\n{}\n}})({}, {});",
            USERSCRIPT_SHIM,
            serde_json::to_string(csp_nonce).unwrap(),
            serde_json::to_string(&endpoint_token).unwrap()
        );
        let mut tags = inline_script_tag(&runtime, csp_nonce);

        let api_names = serde_json::to_string(USERSCRIPT_API_NAMES).unwrap();
        let api_parameters = USERSCRIPT_API_NAMES.join(", ");

        for script in user_scripts {
            // `@require` libraries are evaluated inside the same wrapper, ahead
            // of the body, which is what userscript managers do: the library's
            // top-level declarations become function-scoped locals the script
            // can see, without leaking into the page.
            let mut payload = String::new();
            for library in &script.requires {
                payload.push_str(library);
                // A library ending in a line comment or lacking a trailing
                // newline would otherwise swallow the start of the next one.
                payload.push('\n');
            }
            payload.push_str(&script.body);

            // The body is placed inside a function so that each script gets its
            // own scope and a top-level `return` — a common early-exit idiom in
            // userscripts — stays legal.
            let invocation = format!(
                "window.__privaxyRunUserScript({}, {}, function({}) {{\n{}\n}});",
                Self::build_userscript_info(script, gm_storage),
                api_names,
                api_parameters,
                payload
            );

            tags.push_str(&inline_script_tag(&invocation, csp_nonce));
        }

        Some(tags)
    }

    /// The descriptor handed to the in-page runtime: scheduling inputs plus the
    /// `GM_info` object the script itself can read.
    fn build_userscript_info(
        script: &Arc<CompiledUserScript>,
        gm_storage: &GmStorageStore,
    ) -> String {
        let metadata = &script.metadata;

        let info = serde_json::json!({
            "id": script.file_name,
            "name": metadata.name,
            "runAt": metadata.run_at.as_token(),
            "noFrames": metadata.no_frames,
            // Preloaded `GM_getValue` data, so the in-page accessor can stay
            // synchronous as the GM API requires.
            "values": gm_storage.snapshot(&script.file_name),
            // `@resource` payloads keyed by the name the script declared.
            // Text is inlined so `GM_getResourceText` stays synchronous; a
            // binary or oversized payload carries only a URL, served from the
            // reserved path, so a multi-megabyte asset is not re-encoded into
            // every matching page load.
            "resources": metadata
                .resources
                .iter()
                .filter_map(|declaration| {
                    script.resource(&declaration.name).map(|asset| {
                        (
                            declaration.name.clone(),
                            serde_json::json!({
                                "text": asset.inline_text(),
                                "contentType": asset.content_type,
                            }),
                        )
                    })
                })
                .collect::<std::collections::BTreeMap<_, _>>(),
            "gmInfo": {
                "scriptHandler": "Privaxy",
                "version": env!("CARGO_PKG_VERSION"),
                "uuid": script.file_name,
                "scriptMetaStr": serde_json::Value::Null,
                "script": {
                    "name": metadata.name,
                    "namespace": metadata.namespace,
                    "version": metadata.version,
                    "description": metadata.description,
                    "runAt": metadata.run_at.as_token(),
                    "grant": metadata.grants,
                    "matches": metadata
                        .matches
                        .iter()
                        .map(|pattern| pattern.as_str())
                        .collect::<Vec<_>>(),
                    "includes": metadata
                        .includes
                        .iter()
                        .map(|pattern| pattern.as_str())
                        .collect::<Vec<_>>(),
                    "excludes": metadata
                        .excludes
                        .iter()
                        .map(|pattern| pattern.as_str())
                        .collect::<Vec<_>>(),
                },
            },
        });

        info.to_string()
    }

    /// Everything the rewriter prepends to `<head>`: the blocking payload
    /// (scriptlets plus the procedural-cosmetics shim) followed by any matched
    /// userscripts. Returns `None` when there is nothing to inject.
    fn build_head_html(
        injected_script: Option<String>,
        procedural_filters: &[String],
        scriptlet_debug_logging: bool,
        user_scripts: &[Arc<CompiledUserScript>],
        csp_nonce: &str,
        gm_storage: &GmStorageStore,
        endpoint_token: Option<&str>,
    ) -> Option<String> {
        let blocking_payload =
            Self::build_head_script(injected_script, procedural_filters, scriptlet_debug_logging)
                .map(|payload| inline_script_tag(&payload, csp_nonce));

        let userscript_tags =
            Self::build_userscript_tags(user_scripts, csp_nonce, gm_storage, endpoint_token);

        match (blocking_payload, userscript_tags) {
            (None, None) => None,
            (blocking_payload, userscript_tags) => Some(format!(
                "<!-- privaxy proxy -->{}{}<!-- privaxy proxy -->",
                blocking_payload.unwrap_or_default(),
                userscript_tags.unwrap_or_default()
            )),
        }
    }

    pub(crate) fn rewrite(self) {
        let (internal_body_sender, internal_body_receiver) = self.internal_body_channel;
        let body_sender = self.body_sender;
        let adblock_requester = self.adblock_requester.clone();
        let statistics = self.statistics.clone();
        let csp_nonce = self.csp_nonce.clone();

        let internal_body_sender = Arc::new(Mutex::new(internal_body_sender));

        let classes = Arc::new(Mutex::new(HashSet::new()));
        let ids = Arc::new(Mutex::new(HashSet::new()));

        tokio::spawn(Self::write_body(
            internal_body_receiver,
            body_sender,
            adblock_requester,
            statistics.clone(),
            csp_nonce.clone(),
        ));

        let re = Regex::new(r"\s+").unwrap();
        let classes_clone = Arc::clone(&classes);
        let ids_clone = Arc::clone(&ids);
        let internal_body_sender_clone = Arc::clone(&internal_body_sender);

        // Mutex<Option<_>> + take() = inject at most once even if the document
        // somehow contains multiple <head> openings.
        let pending_script = Arc::new(Mutex::new(Self::build_head_html(
            self.injected_script,
            &self.procedural_filters,
            self.scriptlet_debug_logging,
            &self.user_scripts,
            &csp_nonce,
            &self.gm_storage,
            self.endpoint_token.as_deref(),
        )));
        let head_statistics = statistics.clone();

        let mut rewriter = HtmlRewriter::new(
            Settings {
                element_content_handlers: vec![
                    element!("*", move |element| {
                        if let Some(id) = element.get_attribute("id") {
                            ids_clone.lock().unwrap().insert(id);
                        }
                        Ok(())
                    }),
                    element!("*", move |element| {
                        if let Some(class) = element.get_attribute("class") {
                            let classes_without_duplicate_spaces = re.replace_all(&class, " ");
                            let class_set: HashSet<_> = classes_without_duplicate_spaces
                                .split_whitespace()
                                .map(String::from)
                                .collect();
                            classes_clone.lock().unwrap().extend(class_set);
                        }
                        Ok(())
                    }),
                    // Strip meta-tag CSP. Header CSP gets nonce-augmented by the
                    // proxy; meta CSP would intersect with that and re-block our
                    // injected <style>/<script>, so it has to go.
                    element!("meta", |element| {
                        if let Some(http_equiv) = element.get_attribute("http-equiv") {
                            let name = http_equiv.trim().to_ascii_lowercase();
                            if name == "content-security-policy"
                                || name == "content-security-policy-report-only"
                                || name == "x-content-security-policy"
                                || name == "x-webkit-csp"
                            {
                                element.remove();
                            }
                        }
                        Ok(())
                    }),
                    element!("html, body", |element| {
                        if let Some(handlers) = element.end_tag_handlers() {
                            handlers.push(Box::new(move |end| {
                                end.remove();
                                Ok(())
                            }))
                        }
                        Ok(())
                    }),
                    // Prepend the uBO scriptlet payload and any matched
                    // userscripts to <head> so they run before any of the
                    // page's own scripts. Late-injection at </body> would miss
                    // things like `setTimeout`-boosting scriptlets, whose Proxy
                    // replacement has to be in place before the page schedules
                    // its timers, as well as `@run-at document-start`
                    // userscripts.
                    element!("head", move |element| {
                        if let Some(html) = pending_script.lock().unwrap().take() {
                            element.prepend(&html, ContentType::Html);
                            head_statistics.increment_modified_responses();
                        }
                        Ok(())
                    }),
                ],
                ..Settings::default()
            },
            move |c: &[u8]| {
                let _ = internal_body_sender_clone
                    .lock()
                    .unwrap()
                    .send((Bytes::copy_from_slice(c), None));
            },
        );

        for message in self.receiver {
            rewriter.write(&message).unwrap();
        }
        rewriter.end().unwrap();

        let _ = internal_body_sender.lock().unwrap().send((
            Bytes::new(),
            Some(AdblockProperties {
                ids: ids.lock().unwrap().clone(),
                classes: classes.lock().unwrap().clone(),
                url: self.url,
            }),
        ));
    }

    async fn write_body(
        mut receiver: mpsc::UnboundedReceiver<(Bytes, Option<AdblockProperties>)>,
        body_sender: BodySender,
        adblock_requester: AdblockRequester,
        statistics: Statistics,
        csp_nonce: String,
    ) {
        while let Some((bytes, adblock_properties)) = receiver.recv().await {
            if let Err(_err) = body_sender.send(Ok(Frame::data(bytes))).await {
                break;
            }
            if let Some(adblock_properties) = adblock_properties {
                let blocker_result = adblock_requester
                    .get_cosmetic_response(
                        adblock_properties.url,
                        adblock_properties.ids.into_iter().collect(),
                        adblock_properties.classes.into_iter().collect(),
                    )
                    .await;

                let hidden_selectors: String = blocker_result
                    .hidden_selectors
                    .into_iter()
                    .map(|selector| format!("{} {{ display: none !important; }}", selector))
                    .collect();

                let style_selectors: String = blocker_result
                    .style_selectors
                    .into_iter()
                    .map(|(selector, content)| format!("{} {{ {} }}", selector, content.join(";")))
                    .collect();

                // Count the response as modified whenever we inject any cosmetic
                // rules — hide selectors as well as style selectors. Previously
                // only style selectors flipped this flag, so pages where we hid
                // ad elements via `display: none` were undercounted.
                let response_has_been_modified =
                    !hidden_selectors.is_empty() || !style_selectors.is_empty();

                // Scriptlets (`blocker_result.injected_script`) are intentionally
                // ignored here: they're injected into <head> from the rewriter
                // path so they run before the page's own scripts.
                let _ = blocker_result.injected_script;

                let mut to_append_to_response = format!(
                    r#"
<!-- privaxy proxy -->
<style nonce="{csp_nonce}">{hidden_selectors}
{style_selectors}
</style>
<!-- privaxy proxy -->"#
                );

                // The element handler above strips </body></html> so our injection
                // lands inside <body>; put them back so the document is well-formed.
                to_append_to_response.push_str("</body></html>");

                if response_has_been_modified {
                    statistics.increment_modified_responses();
                }

                let bytes = Bytes::copy_from_slice(to_append_to_response.as_bytes());

                if let Err(_err) = body_sender.send(Ok(Frame::data(bytes))).await {
                    break;
                }
            }
        }
    }
}
