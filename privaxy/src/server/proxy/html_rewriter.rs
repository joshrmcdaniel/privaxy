use super::BodySender;
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
}

/// In-page evaluator for procedural cosmetic filters. Defines the idempotent
/// `window.__privaxyApplyProcedural(filters)` global; see the source file for
/// the supported operators and actions.
const PROCEDURAL_COSMETICS_SHIM: &str = include_str!("../../resources/procedural_cosmetics.js");

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
        let pending_script = Arc::new(Mutex::new(Self::build_head_script(
            self.injected_script,
            &self.procedural_filters,
            self.scriptlet_debug_logging,
        )));
        let head_csp_nonce = csp_nonce.clone();
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
                    // Prepend the uBO scriptlet payload to <head> so it runs
                    // before any of the page's own scripts. Late-injection at
                    // </body> would miss things like `setTimeout`-boosting
                    // scriptlets, whose Proxy replacement has to be in place
                    // before the page schedules its timers.
                    element!("head", move |element| {
                        if let Some(script) = pending_script.lock().unwrap().take() {
                            let escaped = script.replace("</", "<\\/");
                            let tag = format!(
                                "<!-- privaxy proxy --><script type=\"application/javascript\" nonce=\"{}\">{}</script><!-- privaxy proxy -->",
                                head_csp_nonce, escaped
                            );
                            element.prepend(&tag, ContentType::Html);
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
