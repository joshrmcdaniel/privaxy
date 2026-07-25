use crate::logs::LogStream;
use gloo_net::http::Request;
use serde::{Deserialize, Serialize};
use wasm_bindgen_futures::spawn_local;
use web_sys::{HtmlInputElement, HtmlSelectElement};
use yew::prelude::*;
use yew::{html, Component, Context, Html};

/// Selectable log verbosities, matching the backend `logging::LogLevel`
/// (serialized lowercase).
const LOG_LEVELS: [&str; 6] = ["off", "error", "warn", "info", "debug", "trace"];

fn default_log_level() -> String {
    "info".to_string()
}

/// Mirrors the backend `configuration::DebugConfig`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct DebugConfig {
    #[serde(default)]
    pub scriptlet_console_logging: bool,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

impl Default for DebugConfig {
    fn default() -> Self {
        Self {
            scriptlet_console_logging: false,
            log_level: default_log_level(),
        }
    }
}

pub enum Message {
    Loaded(DebugConfig),
    ToggleScriptletLogging(bool),
    SetLogLevel(String),
    SaveSucceeded(DebugConfig),
    SaveFailed(String),
}

pub struct DebugSettingsPage {
    config: DebugConfig,
    loaded: bool,
    saving: bool,
    saved: bool,
    error: Option<String>,
}

impl Component for DebugSettingsPage {
    type Message = Message;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        let link = ctx.link().clone();
        spawn_local(async move {
            match Request::get("/api/settings/debug").send().await {
                Ok(response) if response.ok() => {
                    if let Ok(config) = response.json::<DebugConfig>().await {
                        link.send_message(Message::Loaded(config));
                    }
                }
                _ => log::error!("Failed to load debug settings"),
            }
        });

        Self {
            config: DebugConfig::default(),
            loaded: false,
            saving: false,
            saved: false,
            error: None,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Message::Loaded(config) => {
                self.config = config;
                self.loaded = true;
                true
            }
            Message::ToggleScriptletLogging(value) => {
                // Optimistically reflect the new value, then persist. The PUT
                // triggers a backend reload, so it takes effect on newly served
                // pages.
                self.config.scriptlet_console_logging = value;
                self.persist(ctx);
                true
            }
            Message::SetLogLevel(level) => {
                // The backend applies the level live (no reload needed) on the
                // PUT; we persist it so it survives restarts.
                self.config.log_level = level;
                self.persist(ctx);
                true
            }
            Message::SaveSucceeded(config) => {
                self.config = config;
                self.saving = false;
                self.saved = true;
                self.error = None;
                true
            }
            Message::SaveFailed(message) => {
                self.saving = false;
                self.saved = false;
                self.error = Some(message);
                true
            }
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        if !self.loaded {
            return html! { <div>{"Loading..."}</div> };
        }

        let on_toggle = ctx.link().callback(|e: MouseEvent| {
            let input: HtmlInputElement = e.target_unchecked_into();
            Message::ToggleScriptletLogging(input.checked())
        });

        let status = if self.saving {
            html! { <span class="text-sm text-gray-400 ml-2">{"Saving..."}</span> }
        } else if self.saved {
            html! { <span class="text-sm text-green-600 ml-2">{"Saved"}</span> }
        } else {
            html! {}
        };

        let on_level_change = ctx.link().callback(|e: Event| {
            let select: HtmlSelectElement = e.target_unchecked_into();
            Message::SetLogLevel(select.value())
        });
        let current_level = self.config.log_level.clone();

        html! {
            <>
                <div class="pt-1.5 mb-4">
                    <h1 class="text-2xl font-bold text-gray-900">{ "Debug" }</h1>
                </div>

                <fieldset class="mb-8" style="width: 100%;">
                    <legend class="text-lg font-medium text-gray-900">{ "Scriptlet diagnostics" }</legend>
                    <div class="mt-4 border-t border-b border-gray-200 divide-y divide-gray-200">
                        <div class="mb-4" style="display: flex; flex-direction: column; width: 100%; padding: 2px 0;">
                            <div style="display: flex; align-items: center; width: 100%;">
                                <div class="text-gray-500" style="width: 260px; text-align: left; padding-right: 4px;">
                                    { "Log scriptlet errors to console" }
                                </div>
                                <div style="flex-grow: 1;">
                                    <input
                                        checked={self.config.scriptlet_console_logging}
                                        onclick={on_toggle}
                                        disabled={self.saving}
                                        type="checkbox"
                                        class="focus:ring-blue-500 h-4 w-4 text-blue-600 border-gray-300 rounded"
                                    />
                                    { status.clone() }
                                </div>
                            </div>
                            <div style="margin-left: 260px;">
                                <p class="text-gray-400 text-sm">
                                    { "Surface errors thrown by injected uBO scriptlets in the page's developer console as " }
                                    <span class="font-mono bg-gray-100 px-1">{ "[privaxy scriptlet]" }</span>
                                    { " entries, instead of silently swallowing them. Noisy and reveals that Privaxy is intercepting the page \u{2014} leave off unless troubleshooting." }
                                </p>
                                if let Some(error) = &self.error {
                                    <p class="text-red-500 text-xs italic">{ error.clone() }</p>
                                }
                            </div>
                        </div>
                    </div>
                </fieldset>

                <fieldset class="mb-8" style="width: 100%;">
                    <legend class="text-lg font-medium text-gray-900">{ "Logging" }</legend>
                    <div class="mt-4 border-t border-b border-gray-200 divide-y divide-gray-200">
                        <div class="mb-4" style="display: flex; flex-direction: column; width: 100%; padding: 2px 0;">
                            <div style="display: flex; align-items: center; width: 100%;">
                                <div class="text-gray-500" style="width: 260px; text-align: left; padding-right: 4px;">
                                    { "Log level" }
                                </div>
                                <div style="flex-grow: 1;">
                                    <select
                                        onchange={on_level_change}
                                        disabled={self.saving}
                                        class="block pl-3 pr-8 py-1.5 text-sm border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500">
                                        { for LOG_LEVELS.iter().map(|level| html! {
                                            <option value={*level} selected={current_level == *level}>
                                                { level.to_uppercase() }
                                            </option>
                                        }) }
                                    </select>
                                    { status }
                                </div>
                            </div>
                            <div style="margin-left: 260px;">
                                <p class="text-gray-400 text-sm">
                                    { "Verbosity of Privaxy's own logs, applied immediately and persisted. Dependency logs stay governed by the " }
                                    <span class="font-mono bg-gray-100 px-1">{ "RUST_LOG" }</span>
                                    { " environment variable." }
                                </p>
                            </div>
                        </div>
                    </div>
                </fieldset>

                <LogStream />
            </>
        }
    }
}

impl DebugSettingsPage {
    /// Persists the current config to the backend, reflecting save state via
    /// `SaveSucceeded`/`SaveFailed` messages.
    fn persist(&mut self, ctx: &Context<Self>) {
        self.saving = true;
        self.saved = false;
        self.error = None;

        let config = self.config.clone();
        let link = ctx.link().clone();
        spawn_local(async move {
            let body = serde_json::to_string(&config).unwrap();
            match Request::put("/api/settings/debug")
                .header("Content-Type", "application/json")
                .body(body)
                .unwrap()
                .send()
                .await
            {
                Ok(response) if response.ok() => {
                    link.send_message(Message::SaveSucceeded(config));
                }
                Ok(response) => {
                    link.send_message(Message::SaveFailed(format!(
                        "Failed to save (HTTP {})",
                        response.status()
                    )));
                }
                Err(err) => link.send_message(Message::SaveFailed(format!("{err}"))),
            }
        });
    }
}
