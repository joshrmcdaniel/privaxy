use crate::submit_banner;
use crate::{api, save_button};
use gloo_net::http::Request;
use wasm_bindgen_futures::spawn_local;
use web_sys::HtmlTextAreaElement;
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
    loading: bool,
    loaded: bool,
    saving: bool,
    loading_defaults: bool,
    generation: u64,
    error: Option<String>,
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
    Loaded(u64, Result<String, String>),
    UpdateInput(String),
    Save,
    Saved(u64, String, Result<(), String>),
    AckChanges,
    LoadDefaults,
    DefaultsLoaded(u64, Result<String, String>),
}

impl Component for SettingsTextarea {
    type Message = Message;
    type Properties = Props;

    fn create(ctx: &Context<Self>) -> Self {
        ctx.link().send_message(Message::LoadCurrentState);
        Self {
            loading: true,
            loaded: false,
            saving: false,
            loading_defaults: false,
            generation: 0,
            error: None,
            input_data: String::new(),
            previous_input_data: String::new(),
            changes_saved: false,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Message) -> bool {
        match msg {
            Message::UpdateInput(value) => {
                self.changes_saved = false;
                self.input_data = value;
            }
            Message::LoadCurrentState => {
                self.generation += 1;
                let generation = self.generation;
                self.loading = true;
                self.error = None;
                let url = ctx.props().resource_url.clone();
                let link = ctx.link().clone();
                spawn_local(async move {
                    link.send_message(Message::Loaded(generation, api::get_json(&url).await));
                });
            }
            Message::Loaded(generation, result) => {
                if generation != self.generation {
                    return false;
                }
                self.loading = false;
                match result {
                    Ok(mut value) => {
                        for line in &ctx.props().merge_lines {
                            merge_missing_line(&mut value, line.trim());
                        }
                        self.previous_input_data = value.clone();
                        self.input_data = value;
                        self.loaded = true;
                    }
                    Err(error) => self.error = Some(format!("Could not load settings: {error}")),
                }
            }
            Message::Save => {
                if !self.loaded
                    || self.loading
                    || self.saving
                    || self.loading_defaults
                    || self.input_data == self.previous_input_data
                {
                    return false;
                }
                self.saving = true;
                self.changes_saved = false;
                self.error = None;
                let generation = self.generation;
                let value = self.input_data.clone();
                let url = ctx.props().resource_url.clone();
                let link = ctx.link().clone();
                spawn_local(async move {
                    let result = api::send_json(Request::put(&url), &value).await;
                    link.send_message(Message::Saved(generation, value, result));
                });
            }
            Message::Saved(generation, value, result) => {
                if generation != self.generation {
                    return false;
                }
                self.saving = false;
                match result {
                    Ok(()) => {
                        // Only acknowledge the submitted snapshot. Edits made
                        // while saving remain unsaved and available to retry.
                        self.previous_input_data = value;
                        self.changes_saved = self.input_data == self.previous_input_data;
                    }
                    Err(error) => self.error = Some(format!("Could not save settings: {error}")),
                }
            }
            Message::AckChanges => self.changes_saved = false,
            Message::LoadDefaults => {
                if !self.loaded || self.loading || self.saving || self.loading_defaults {
                    return false;
                }
                let Some(url) = ctx.props().defaults_url.clone() else {
                    return false;
                };
                self.loading_defaults = true;
                self.changes_saved = false;
                self.error = None;
                let generation = self.generation;
                let link = ctx.link().clone();
                spawn_local(async move {
                    link.send_message(Message::DefaultsLoaded(
                        generation,
                        api::get_json(&url).await,
                    ));
                });
            }
            Message::DefaultsLoaded(generation, result) => {
                if generation != self.generation {
                    return false;
                }
                self.loading_defaults = false;
                match result {
                    Ok(value) => self.input_data = value,
                    Err(error) => self.error = Some(format!("Could not load defaults: {error}")),
                }
            }
        }
        true
    }

    fn changed(&mut self, ctx: &Context<Self>, old_props: &Self::Properties) -> bool {
        let props = ctx.props();
        if props.resource_url != old_props.resource_url {
            // Invalidate responses belonging to the previous settings page.
            self.generation += 1;
            self.loaded = false;
            self.loading = true;
            self.saving = false;
            self.loading_defaults = false;
            self.input_data.clear();
            self.previous_input_data.clear();
            self.changes_saved = false;
            self.error = None;
            ctx.link().send_message(Message::LoadCurrentState);
        } else {
            for line in props
                .merge_lines
                .iter()
                .filter(|line| !old_props.merge_lines.contains(line))
            {
                let line = line.trim();
                if !line.is_empty() {
                    merge_missing_line(&mut self.input_data, line);
                    merge_missing_line(&mut self.previous_input_data, line);
                }
            }
        }
        true
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let button_state = if self.saving {
            save_button::SaveButtonState::Loading
        } else if !self.loaded
            || self.loading
            || self.loading_defaults
            || self.input_data == self.previous_input_data
        {
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
            let input = e.target_unchecked_into::<HtmlTextAreaElement>();
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
                    disabled={!self.loaded || self.loading || self.saving || self.loading_defaults}
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
            if let Some(error) = &self.error {
                <p role="alert" class="mt-4 text-sm text-red-700">{error}</p>
                if !self.loaded {
                    <button type="button" class="mt-2 text-blue-600 underline" onclick={ctx.link().callback(|_| Message::LoadCurrentState)} disabled={self.loading}>{"Retry loading settings"}</button>
                }
            }
            if self.loading {
                <p role="status" class="mt-4 text-gray-500">{"Loading settings…"}</p>
            }

            <div class="mt-4">
                <label for={props.input_name.clone()} class="block text-sm font-medium text-gray-700">{&props.textarea_description}</label>
                <div class="mt-1">
                    <textarea disabled={!self.loaded || self.loading || self.loading_defaults} {oninput} value={self.input_data.clone()} rows="8" name={props.input_name.clone()} id={props.input_name.clone()} class="shadow-sm focus:ring-blue-500 focus:border-blue-500 block w-full sm:text-sm border-gray-300 rounded-md" />
                </div>
            </div>
            <div class="flex flex-wrap items-center">
                <save_button::SaveButton state={button_state} {onclick} />
                {defaults_button}
            </div>
            </>
        }
    }
}
