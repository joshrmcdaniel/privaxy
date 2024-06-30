use crate::{blocker::AdblockRequester, statistics::Statistics};
use crossbeam_channel::Receiver;
use hyper::body::Bytes;
use lol_html::{element, HtmlRewriter, Settings};
use regex::Regex;
use std::collections::HashSet;
use std::fmt::Write;
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
}

impl Rewriter {
    pub(crate) fn new(
        url: String,
        adblock_requester: AdblockRequester,
        receiver: Receiver<Bytes>,
        body_sender: hyper::body::Sender,
        statistics: Statistics,
    ) -> Self {
        Self {
            url,
            body_sender,
            statistics,
            adblock_requester,
            receiver,
            internal_body_channel: mpsc::unbounded_channel(),
        }
    }

    pub(crate) fn rewrite(self) {
        let (internal_body_sender, internal_body_receiver) = self.internal_body_channel;
        let body_sender = self.body_sender;
        let adblock_requester = self.adblock_requester.clone();
        let statistics = self.statistics.clone();

        let internal_body_sender = Arc::new(Mutex::new(internal_body_sender));

        let classes = Arc::new(Mutex::new(HashSet::new()));
        let ids = Arc::new(Mutex::new(HashSet::new()));

        tokio::spawn(Self::write_body(
            internal_body_receiver,
            body_sender,
            adblock_requester,
            statistics,
        ));

        let re = Regex::new(r"\s+").unwrap();
        let classes_clone = Arc::clone(&classes);
        let ids_clone = Arc::clone(&ids);
        let internal_body_sender_clone = Arc::clone(&internal_body_sender);

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
                    element!("html, body", |element| {
                        if let Some(handlers) = element.end_tag_handlers() {
                            handlers.push(Box::new(move |end| {
                                end.remove();
                                Ok(())
                            }))
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

                let mut to_append_to_response = format!(
                    r#"
<!-- privaxy proxy -->
<style>{hidden_selectors}
{style_selectors}
</style>
<!-- privaxy proxy -->"#
                );

                if let Some(injected_script) = blocker_result.injected_script {
                    response_has_been_modified = true;
                    write!(
                        to_append_to_response,
                        r#"
<!-- Privaxy proxy -->
<script type="application/javascript">{}</script>
<!-- privaxy proxy -->
"#,
                        injected_script
                    )
                    .unwrap();
                }

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
