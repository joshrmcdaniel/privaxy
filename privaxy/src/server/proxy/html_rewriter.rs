use crate::{blocker::AdblockRequester, statistics::Statistics};
use crossbeam_channel::Receiver;
use hyper::body::Bytes;
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
    body_sender: hyper::body::Sender,
    statistics: Statistics,
    internal_body_channel: InternalBodyChannel,
    csp_nonce: String,
    // Scriptlets (uBO `##+js(...)`) need to run before page scripts get a
    // reference to the globals they hook (setTimeout, eval, etc.), so this is
    // injected early into `<head>` rather than appended at end-of-body.
    injected_script: Option<String>,
}

impl Rewriter {
    pub(crate) fn new(
        url: String,
        adblock_requester: AdblockRequester,
        receiver: Receiver<Bytes>,
        body_sender: hyper::body::Sender,
        statistics: Statistics,
        csp_nonce: String,
        injected_script: Option<String>,
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
        let pending_script = Arc::new(Mutex::new(self.injected_script));
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
        mut body_sender: hyper::body::Sender,
        adblock_requester: AdblockRequester,
        statistics: Statistics,
        csp_nonce: String,
    ) {
        while let Some((bytes, adblock_properties)) = receiver.recv().await {
            if let Err(_err) = body_sender.send_data(bytes).await {
                break;
            }
            if let Some(adblock_properties) = adblock_properties {
                let mut response_has_been_modified = false;

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
                    .map(|(selector, content)| {
                        response_has_been_modified = true;
                        format!("{} {{ {} }}", selector, content.join(";"))
                    })
                    .collect();

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

                if let Err(_err) = body_sender.send_data(bytes).await {
                    break;
                }
            }
        }
    }
}
