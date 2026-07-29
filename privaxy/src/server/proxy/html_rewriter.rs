use super::gm::storage::GmStorageStore;
use super::BodySender;
use crate::configuration::CompiledUserScript;
use crate::{
    blocker::{AdblockRequester, CosmeticBlockerResult},
    statistics::Statistics,
};
use bytes::Bytes;
use hyper::body::Frame;
use lol_html::html_content::ContentType;
use lol_html::{element, HtmlRewriter, Settings};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Capacity of the rewriter-to-body channel. Bounded so a slow client
/// backpressures the rewriter thread (via `blocking_send`) instead of the
/// whole document buffering in memory.
const INTERNAL_BODY_CHANNEL_CAPACITY: usize = 32;

type InternalBodyChannel = (
    mpsc::Sender<(Bytes, Option<AdblockProperties>)>,
    mpsc::Receiver<(Bytes, Option<AdblockProperties>)>,
);

struct AdblockProperties {
    ids: HashSet<String>,
    classes: HashSet<String>,
}

pub struct Rewriter {
    adblock_requester: AdblockRequester,
    receiver: mpsc::Receiver<Bytes>,
    body_sender: BodySender,
    statistics: Statistics,
    internal_body_channel: InternalBodyChannel,
    csp_nonce: String,
    // The page's URL-scoped cosmetic lookup, resolved once before the body is
    // parsed. Scriptlets and procedural filters are injected into <head>; the
    // hide/style selectors and the exception set travel to the end-of-body
    // pass, which only adds the generic class/id-indexed selectors on top.
    head_cosmetics: CosmeticBlockerResult,
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

/// In-page evaluator for procedural cosmetic filters, and the only path by which
/// plain cosmetic CSS reaches a shadow root. Defines the idempotent
/// `window.__privaxyApplyProcedural(filters, expectCosmeticCss)` global; see the
/// source file for the supported operators and actions.
///
/// Taken from `OUT_DIR`, not `src/resources`: `build.rs` strips the comments out
/// first, because this is injected inline into most HTML responses and the proxy
/// sends them uncompressed. Read `src/resources/procedural_cosmetics.js` for the
/// commented original.
const PROCEDURAL_COSMETICS_SHIM: &str =
    include_str!(concat!(env!("OUT_DIR"), "/procedural_cosmetics.js"));

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

/// Marks the end-of-body cosmetic `<style>` block so the in-page shim can find
/// it and adopt its rules into shadow roots.
///
/// The shim looks this attribute up by name (`procedural_cosmetics.js`, see
/// `cosmeticCss`); the two must stay in step. Reading the block back is what
/// keeps the rules from being serialized into the page twice, and it also means
/// roots receive the class/id-indexed generic selectors, which only exist once
/// the document has been scanned.
const COSMETIC_STYLE_MARKER: &str = "data-privaxy-cosmetics";

/// Render cosmetic selectors as a CSS payload: the hide selectors first, then
/// the ones that set styles.
fn build_cosmetic_css(
    hidden_selectors: &[String],
    style_selectors: &HashMap<String, Vec<String>>,
) -> String {
    let hidden: String = hidden_selectors
        .iter()
        .map(|selector| format!("{} {{ display: none !important; }}", selector))
        .collect();

    let styles: String = style_selectors
        .iter()
        .map(|(selector, content)| format!("{} {{ {} }}", selector, content.join(";")))
        .collect();

    format!("{hidden}\n{styles}")
}

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
        adblock_requester: AdblockRequester,
        receiver: mpsc::Receiver<Bytes>,
        body_sender: BodySender,
        statistics: Statistics,
        csp_nonce: String,
        head_cosmetics: CosmeticBlockerResult,
        scriptlet_debug_logging: bool,
        user_scripts: Vec<Arc<CompiledUserScript>>,
        gm_storage: GmStorageStore,
        endpoint_token: Option<String>,
    ) -> Self {
        Self {
            body_sender,
            statistics,
            adblock_requester,
            receiver,
            internal_body_channel: mpsc::channel(INTERNAL_BODY_CHANNEL_CAPACITY),
            csp_nonce,
            head_cosmetics,
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
        expect_cosmetic_css: bool,
        scriptlet_debug_logging: bool,
    ) -> Option<String> {
        // The shim is needed for plain CSS as well as procedural rules now: it is
        // the only way plain rules reach a shadow root. Procedural rules are rare
        // (most hosts have none), so gating solely on them would leave shadow
        // roots unstyled on essentially every page.
        let shim_needed = !procedural_filters.is_empty() || expect_cosmetic_css;

        if injected_script.is_none() && !shim_needed {
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

        if shim_needed {
            if !payload.is_empty() {
                payload.push('\n');
            }
            payload.push_str(PROCEDURAL_COSMETICS_SHIM);
            // Each filter is already valid JSON, so they're spliced straight
            // into an array literal without re-serialization. The second argument
            // tells the shim to expect a cosmetic `<style>` block later in the
            // document; without it a page whose only cosmetic rules are plain CSS
            // would look like nothing to do.
            payload.push_str(";window.__privaxyApplyProcedural([");
            payload.push_str(&procedural_filters.join(","));
            payload.push_str("],");
            payload.push_str(if expect_cosmetic_css { "true" } else { "false" });
            payload.push_str(");");
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
    #[allow(clippy::too_many_arguments)]
    fn build_head_html(
        injected_script: Option<String>,
        procedural_filters: &[String],
        expect_cosmetic_css: bool,
        scriptlet_debug_logging: bool,
        user_scripts: &[Arc<CompiledUserScript>],
        csp_nonce: &str,
        gm_storage: &GmStorageStore,
        endpoint_token: Option<&str>,
    ) -> Option<String> {
        let blocking_payload = Self::build_head_script(
            injected_script,
            procedural_filters,
            expect_cosmetic_css,
            scriptlet_debug_logging,
        )
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

    /// Runs on a blocking thread (`spawn_blocking`): both channel ends here use
    /// the blocking variants of send/recv.
    pub(crate) fn rewrite(self) {
        let Rewriter {
            adblock_requester,
            mut receiver,
            body_sender,
            statistics,
            internal_body_channel: (internal_body_sender, internal_body_receiver),
            csp_nonce,
            head_cosmetics,
            scriptlet_debug_logging,
            user_scripts,
            gm_storage,
            endpoint_token,
        } = self;

        let CosmeticBlockerResult {
            hidden_selectors,
            style_selectors,
            injected_script,
            procedural_filters,
            exceptions,
            generichide,
        } = head_cosmetics;

        // Whether the end-of-body lookup will produce a non-empty cosmetic
        // `<style>` block. The shim reads its rules out of that block to adopt
        // them into shadow roots — author-origin CSS cannot cross a shadow
        // boundary — but the block only exists after the body has been parsed, so
        // the decision to inject the shim at all has to be made up-front.
        //
        // This is a prediction, and an exact one in practice: the end-of-body
        // lookup adds the class/id-indexed generic selectors on top of what is
        // seen here, and those are only collected when `generichide` is off — in
        // which case the URL-scoped set already carries the generic selectors that
        // are not class/id-indexable, and is non-empty.
        let expect_cosmetic_css = !hidden_selectors.is_empty() || !style_selectors.is_empty();

        tokio::spawn(Self::write_body(
            internal_body_receiver,
            body_sender,
            adblock_requester,
            statistics.clone(),
            csp_nonce.clone(),
            hidden_selectors,
            style_selectors,
            exceptions,
            generichide,
        ));

        // The rewriter and all its handlers live on this one thread, so the
        // shared collections are Rc<RefCell> rather than locks.
        let ids = Rc::new(RefCell::new(HashSet::new()));
        let classes = Rc::new(RefCell::new(HashSet::new()));
        let ids_clone = Rc::clone(&ids);
        let classes_clone = Rc::clone(&classes);

        // Set when the body channel is gone (client disconnected), so the input
        // loop below can stop pulling — and thereby stop the upstream download —
        // instead of rewriting into the void.
        let aborted = Rc::new(Cell::new(false));
        let sink_aborted = Rc::clone(&aborted);
        let sink_sender = internal_body_sender.clone();

        // RefCell<Option<_>> + take() = inject at most once even if the document
        // somehow contains multiple <head> openings.
        let pending_script = Rc::new(RefCell::new(Self::build_head_html(
            injected_script,
            &procedural_filters,
            expect_cosmetic_css,
            scriptlet_debug_logging,
            &user_scripts,
            &csp_nonce,
            &gm_storage,
            endpoint_token.as_deref(),
        )));
        let head_statistics = statistics.clone();

        let mut rewriter = HtmlRewriter::new(
            Settings {
                element_content_handlers: vec![
                    element!("*", move |element| {
                        if let Some(id) = element.get_attribute("id") {
                            ids_clone.borrow_mut().insert(id);
                        }
                        if let Some(class) = element.get_attribute("class") {
                            classes_clone
                                .borrow_mut()
                                .extend(class.split_whitespace().map(String::from));
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
                        if let Some(html) = pending_script.borrow_mut().take() {
                            element.prepend(&html, ContentType::Html);
                            head_statistics.increment_modified_responses();
                        }
                        Ok(())
                    }),
                ],
                ..Settings::default()
            },
            move |c: &[u8]| {
                if sink_sender
                    .blocking_send((Bytes::copy_from_slice(c), None))
                    .is_err()
                {
                    sink_aborted.set(true);
                }
            },
        );

        while let Some(message) = receiver.blocking_recv() {
            rewriter.write(&message).unwrap();
            if aborted.get() {
                return;
            }
        }
        rewriter.end().unwrap();

        let _ = internal_body_sender.blocking_send((
            Bytes::new(),
            Some(AdblockProperties {
                ids: ids.take(),
                classes: classes.take(),
            }),
        ));
    }

    #[allow(clippy::too_many_arguments)]
    async fn write_body(
        mut receiver: mpsc::Receiver<(Bytes, Option<AdblockProperties>)>,
        body_sender: BodySender,
        adblock_requester: AdblockRequester,
        statistics: Statistics,
        csp_nonce: String,
        url_hidden_selectors: Vec<String>,
        style_selectors: HashMap<String, Vec<String>>,
        exceptions: HashSet<String>,
        generichide: bool,
    ) {
        let mut end_of_body_cosmetics = Some((url_hidden_selectors, style_selectors, exceptions));

        while let Some((bytes, adblock_properties)) = receiver.recv().await {
            if let Err(_err) = body_sender.send(Ok(Frame::data(bytes))).await {
                break;
            }
            if let Some(adblock_properties) = adblock_properties {
                let Some((mut hidden_selectors, style_selectors, exceptions)) =
                    end_of_body_cosmetics.take()
                else {
                    continue;
                };

                // The URL-scoped selectors were resolved before the body was
                // parsed; only the generic class/id-indexed selectors — which
                // depend on the ids and classes actually collected from the
                // document — are resolved here, unless a $generichide
                // exception told us not to.
                if !generichide {
                    hidden_selectors.extend(
                        adblock_requester
                            .get_generic_class_id_selectors(
                                adblock_properties.classes.into_iter().collect(),
                                adblock_properties.ids.into_iter().collect(),
                                exceptions,
                            )
                            .await,
                    );
                }

                let cosmetic_css = build_cosmetic_css(&hidden_selectors, &style_selectors);

                // Count the response as modified whenever we inject any cosmetic
                // rules — hide selectors as well as style selectors. Previously
                // only style selectors flipped this flag, so pages where we hid
                // ad elements via `display: none` were undercounted.
                let response_has_been_modified = !cosmetic_css.trim().is_empty();

                // The marker attribute is what lets the in-page shim find this
                // block and adopt its rules into shadow roots, which
                // author-origin CSS cannot reach on its own.
                let mut to_append_to_response = format!(
                    r#"
<!-- privaxy proxy -->
<style nonce="{csp_nonce}" {COSMETIC_STYLE_MARKER}>{cosmetic_css}
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
