use crate::save_button;
use crate::submit_banner;
use gloo_net::http::Request;
use wasm_bindgen_futures::spawn_local;
use web_sys::HtmlInputElement;
use yew::virtual_dom::VNode;
use yew::{html, Component, Context, Html, InputEvent, Properties, TargetCast};

#[derive(Properties, PartialEq)]
pub struct Props {
    pub h1: String,
    pub description: VNode,
    pub input_name: String,
    pub textarea_description: String,
    pub resource_url: String,
    #[prop_or_default]
    pub defaults_url: Option<String>,
    #[prop_or_default]
    pub defaults_button_label: Option<String>,
    /// Lines added to the resource elsewhere (e.g. the TLS-failures panel's
    /// Exclude action) that should appear in the textarea without a reload.
    /// New entries are appended in place, preserving unsaved draft edits.
    #[prop_or_default]
    pub merge_lines: Vec<String>,
}

pub struct SettingsTextarea {
    is_save_button_enabled: bool,
    changes_saved: bool,
    input_data: String,
    previous_input_data: String,
}

/// Append `line` to `target` unless an existing (trimmed) line already
/// matches it.
fn merge_missing_line(target: &mut String, line: &str) {
    if target.lines().any(|existing| existing.trim() == line) {
        return;
    }

    let trimmed = target.trim_end();
    *target = if trimmed.is_empty() {
        line.to_string()
    } else {
        format!("{trimmed}\n{line}")
    };
}

pub enum Message {
    LoadCurrentState,
    UpdateInput(String),
    UpdatePreviousInputData,
    Save,
    Saved,
    AckChanges,
    LoadDefaults,
}

impl Component for SettingsTextarea {
    type Message = Message;
    type Properties = Props;

    fn create(ctx: &Context<Self>) -> Self {
        ctx.link().send_message(Message::LoadCurrentState);

        Self {
            is_save_button_enabled: false,
            input_data: String::new(),
            previous_input_data: String::new(),
            changes_saved: false,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Message::UpdateInput(input_value) => {
                self.changes_saved = false;
                self.is_save_button_enabled = true;

                self.input_data = input_value;
            }
            Message::Save => {
                if !self.is_save_button_enabled {
                    return false;
                }

                let request = Request::put(&ctx.props().resource_url)
                    .header("Content-Type", "application/json")
                    .body(serde_json::to_string(&self.input_data).unwrap())
                    .unwrap();

                spawn_local(async move {
                    if let Ok(response) = request.send().await {
                        // Todo: Handle errors
                        if response.ok() {}
                    }
                });

                ctx.link().send_message(Message::Saved);
            }
            Message::Saved => {
                ctx.link().send_message(Message::UpdatePreviousInputData);

                self.changes_saved = true;
                self.is_save_button_enabled = false;
            }
            Message::AckChanges => {
                self.changes_saved = false;
            }
            Message::LoadCurrentState => {
                let request = Request::get(&ctx.props().resource_url);

                let message_callback = ctx.link().callback(|message: Message| message);

                spawn_local(async move {
                    if let Ok(response) = request.send().await {
                        // Todo: Handle errors
                        if response.ok() {
                            if let Ok(response_content) = response.json::<String>().await {
                                message_callback.emit(Message::UpdateInput(response_content));
                                message_callback.emit(Message::UpdatePreviousInputData)
                            };
                        }
                    }
                });
            }
            Message::UpdatePreviousInputData => {
                self.previous_input_data = self.input_data.clone();
            }
            Message::LoadDefaults => {
                let Some(defaults_url) = ctx.props().defaults_url.clone() else {
                    return false;
                };

                let request = Request::get(&defaults_url);
                let message_callback = ctx.link().callback(|message: Message| message);

                spawn_local(async move {
                    if let Ok(response) = request.send().await {
                        if response.ok() {
                            if let Ok(response_content) = response.json::<String>().await {
                                message_callback.emit(Message::UpdateInput(response_content));
                            };
                        }
                    }
                });
            }
        }
        true
    }

    fn changed(&mut self, ctx: &Context<Self>, old_props: &Self::Properties) -> bool {
        let props = ctx.props();

        // A pure `merge_lines` change appends the new entries in place: the
        // server already has them, so both the draft and the saved-state
        // snapshot gain the lines, and unsaved user edits are preserved
        // (a reload here would silently discard them).
        if props.resource_url == old_props.resource_url
            && props.merge_lines != old_props.merge_lines
        {
            for line in &props.merge_lines {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                merge_missing_line(&mut self.input_data, line);
                merge_missing_line(&mut self.previous_input_data, line);
            }

            return true;
        }

        ctx.link().send_message(Message::UpdateInput(String::new()));
        ctx.link().send_message(Message::LoadCurrentState);

        self.changes_saved = false;

        true
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let button_state =
            if !self.is_save_button_enabled || (self.input_data == self.previous_input_data) {
                save_button::SaveButtonState::Disabled
            } else {
                save_button::SaveButtonState::Enabled
            };

        let success_banner = if self.changes_saved {
            let icon = html! {
                <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-white" fill="none"
                    viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                        d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
            };
            html! {
                <submit_banner::SubmitBanner
                message="Changes saved"
                {icon}
                on_hide={ctx.link().callback(|_| Message::AckChanges)}
                visible={true} color={submit_banner::Color::Green}/>
            }
        } else {
            html! {}
        };

        let oninput = ctx.link().callback(|e: InputEvent| {
            let input = e.target_unchecked_into::<HtmlInputElement>();
            let value = input.value();

            Message::UpdateInput(value)
        });

        let onclick = ctx.link().callback(|_| Message::Save);

        let props = ctx.props();

        let defaults_button = if props.defaults_url.is_some() {
            let on_defaults_click = ctx.link().callback(|_| Message::LoadDefaults);
            let label = props
                .defaults_button_label
                .clone()
                .unwrap_or_else(|| "Reset to defaults".to_string());
            html! {
                <button onclick={on_defaults_click} type="button"
                    class="ml-2 mt-5 inline-flex items-center justify-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md shadow-sm text-gray-700 bg-white hover:bg-gray-50 transition ease-in-out duration-150 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-gray-100 focus:ring-blue-500">
                    <svg xmlns="http://www.w3.org/2000/svg" class="-ml-0.5 mr-2 h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                    </svg>
                    {label}
                </button>
            }
        } else {
            html! {}
        };

        html! {
            <>
            <div class="pt-1.5 mb-4">
                <h1 class="text-2xl font-bold text-gray-900">{ &props.h1 }</h1>
            </div>
            {props.description.clone()}

            {success_banner}

            <div class="mt-4">
                <label for={props.input_name.clone()} class="block text-sm font-medium text-gray-700">{&props.textarea_description}</label>
                <div class="mt-1">
                    <textarea {oninput} value={self.input_data.clone()} rows="8" name={props.input_name.clone()} id={props.input_name.clone()} class="shadow-sm focus:ring-blue-500 focus:border-blue-500 block w-full sm:text-sm border-gray-300 rounded-md" />
                </div>
            </div>
            <div class="flex items-center">
                <save_button::SaveButton state={button_state} {onclick} />
                {defaults_button}
            </div>
            </>
        }
    }
}
