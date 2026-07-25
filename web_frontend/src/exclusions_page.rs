use crate::settings_textarea::SettingsTextarea;
use crate::tls_failures::TlsFailuresPanel;
use yew::{html, Component, Context, Html};

pub enum Message {
    HostExcluded(String),
}

/// Exclusions settings page: the "Recent TLS interception failures" panel on
/// top of the exclusion list textarea. Hosts excluded from the panel are
/// passed to the textarea as `merge_lines`, which appends them to its
/// contents in place — keeping the list current without remounting the
/// component, so unsaved draft edits survive.
pub struct ExclusionsPage {
    excluded_hosts: Vec<String>,
}

impl Component for ExclusionsPage {
    type Message = Message;
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        Self {
            excluded_hosts: Vec::new(),
        }
    }

    fn update(&mut self, _ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Message::HostExcluded(host) => {
                self.excluded_hosts.push(host);
                true
            }
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let on_excluded = ctx.link().callback(Message::HostExcluded);

        let resource_url = "/api/exclusions";

        let description = html! {<div class="text-gray-600">
                <p>
                    {"Exclusions are hosts or domains that are not passed through the MITM pipeline. "}
                    {"Excluded entries will be transparently tunneled."}
                </p>
                <p class="mt-2">
                    {"Use "}<span class="font-medium">{"Reset to defaults"}</span>
                    {" to populate the textarea with a list of commonly cert-pinned hosts. You can then edit it and click Save."}
                </p>
            </div>
        };
        let textarea_description = "Insert one entry per line";
        let defaults_url = Some("/api/exclusions/defaults".to_string());

        html! {
            <>
                <TlsFailuresPanel {on_excluded} />
                <div class="mt-8">
                    <SettingsTextarea h1="Exclusions" {description} input_name="exclusions" {textarea_description} {resource_url} {defaults_url} merge_lines={self.excluded_hosts.clone()} />
                </div>
            </>
        }
    }
}
