use crate::userscript_edit::UserScriptEditModal;
use crate::{failure_banner, submit_banner, ApiError};
use gloo_net::http::Request;
use serde::{Deserialize, Serialize};
use wasm_bindgen_futures::spawn_local;
use web_sys::{HtmlInputElement, HtmlTextAreaElement};
use yew::prelude::*;
use yew::{html, Component, Context, Html};

/// One installed userscript, as served by `GET /api/userscripts`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct UserScript {
    pub enabled: bool,
    pub title: String,
    pub file_name: String,
    pub url: Option<String>,
    pub version: Option<String>,
    pub description: Option<String>,
    pub run_at: Option<String>,
    pub matches: Vec<String>,
    pub grants: Vec<String>,
    pub no_frames: bool,
    /// Set when the stored body cannot be read or no longer parses; such a
    /// script is skipped at injection time.
    pub error: Option<String>,
    /// Non-fatal problems, e.g. a `@require` library that could not be fetched.
    /// The script still runs, degraded.
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// The `[userscripts]` configuration section, as served by the API.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct UserScriptsConfig {
    pub enabled: bool,
    #[serde(default)]
    pub allow_private_network_requests: bool,
    pub scripts: Vec<UserScript>,
}

/// Both fields optional so each toggle sends only what it changed.
#[derive(Debug, Default, Serialize)]
struct EngineSettingsRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allow_private_network_requests: Option<bool>,
}

#[derive(Debug, Serialize)]
struct StatusChangeRequest {
    file_name: String,
    enabled: bool,
}

#[derive(Debug, Serialize)]
struct RefreshRequest {
    /// Absent means "every URL-installed script".
    #[serde(skip_serializing_if = "Option::is_none")]
    file_name: Option<String>,
}

/// One entry of the refresh report.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RefreshResult {
    title: String,
    outcome: String,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct AddUserScriptRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    enabled: bool,
}

pub enum Message {
    Load,
    Loaded(UserScriptsConfig),
    LoadFailed(String),
    ToggleEngine(bool),
    TogglePrivateNetwork(bool),
    ToggleScript(String, bool),
    OpenAdd,
    CloseAdd,
    AddUrlChanged(String),
    AddBodyChanged(String),
    SubmitAdd,
    RefreshAll,
    Refreshed(Vec<RefreshResult>),
    Saved(&'static str),
    Failed(String),
    AckError,
    AckSaved,
    OpenEdit(Box<UserScript>),
    CloseEdit,
    EditCompleted,
}

pub struct UserScriptsPage {
    config: Option<UserScriptsConfig>,
    add_open: bool,
    add_url: String,
    add_body: String,
    submitting: bool,
    saved_message: Option<&'static str>,
    error: Option<String>,
    editing: Option<UserScript>,
    /// Per-script outcome of the last on-demand refresh.
    refresh_report: Option<Vec<RefreshResult>>,
}

impl Component for UserScriptsPage {
    type Message = Message;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        ctx.link().send_message(Message::Load);

        Self {
            config: None,
            add_open: false,
            add_url: String::new(),
            add_body: String::new(),
            submitting: false,
            saved_message: None,
            error: None,
            editing: None,
            refresh_report: None,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Message::Load => {
                let link = ctx.link().clone();
                spawn_local(async move {
                    match Request::get("/api/userscripts").send().await {
                        Ok(response) if response.ok() => {
                            match response.json::<UserScriptsConfig>().await {
                                Ok(config) => link.send_message(Message::Loaded(config)),
                                Err(err) => link.send_message(Message::LoadFailed(format!(
                                    "Unable to read the userscript list: {err}"
                                ))),
                            }
                        }
                        Ok(response) => link.send_message(Message::LoadFailed(format!(
                            "Unable to load userscripts (HTTP {})",
                            response.status()
                        ))),
                        Err(err) => link.send_message(Message::LoadFailed(format!("{err}"))),
                    }
                });
            }
            Message::Loaded(config) => {
                self.config = Some(config);
                self.submitting = false;
            }
            Message::LoadFailed(message) => {
                log::error!("{message}");
                self.error = Some(message);
                self.submitting = false;
            }
            Message::ToggleEngine(enabled) => {
                // Reflect the new value immediately; the request that follows
                // both persists it and swaps the proxy's live script set, so it
                // applies to the next page load.
                if let Some(config) = self.config.as_mut() {
                    config.enabled = enabled;
                }

                let body = serde_json::to_string(&EngineSettingsRequest {
                    enabled: Some(enabled),
                    ..EngineSettingsRequest::default()
                })
                .unwrap();
                self.send(
                    ctx,
                    Request::put("/api/userscripts/enabled"),
                    body,
                    "Userscript setting saved",
                );
            }
            Message::TogglePrivateNetwork(allowed) => {
                if let Some(config) = self.config.as_mut() {
                    config.allow_private_network_requests = allowed;
                }

                let body = serde_json::to_string(&EngineSettingsRequest {
                    allow_private_network_requests: Some(allowed),
                    ..EngineSettingsRequest::default()
                })
                .unwrap();
                self.send(
                    ctx,
                    Request::put("/api/userscripts/enabled"),
                    body,
                    "Userscript setting saved",
                );
            }
            Message::ToggleScript(file_name, enabled) => {
                if let Some(config) = self.config.as_mut() {
                    if let Some(script) = config
                        .scripts
                        .iter_mut()
                        .find(|script| script.file_name == file_name)
                    {
                        script.enabled = enabled;
                    }
                }

                let body = serde_json::to_string(&vec![StatusChangeRequest { file_name, enabled }])
                    .unwrap();
                self.send(ctx, Request::put("/api/userscripts"), body, "Changes saved");
            }
            Message::OpenAdd => {
                self.add_open = true;
                self.add_url = String::new();
                self.add_body = String::new();
                self.error = None;
            }
            Message::CloseAdd => self.add_open = false,
            Message::AddUrlChanged(url) => self.add_url = url,
            Message::AddBodyChanged(body) => self.add_body = body,
            Message::SubmitAdd => {
                let url = self.add_url.trim().to_string();
                let body = self.add_body.trim().to_string();

                if url.is_empty() && body.is_empty() {
                    self.error =
                        Some("Paste a script or provide a URL to install from.".to_string());
                    return true;
                }

                let request_body = serde_json::to_string(&AddUserScriptRequest {
                    body: if url.is_empty() { Some(body) } else { None },
                    url: if url.is_empty() { None } else { Some(url) },
                    enabled: true,
                })
                .unwrap();

                self.send(
                    ctx,
                    Request::post("/api/userscripts"),
                    request_body,
                    "Userscript installed",
                );
            }
            Message::RefreshAll => {
                let body = serde_json::to_string(&RefreshRequest { file_name: None }).unwrap();
                self.submitting = true;
                self.error = None;

                let link = ctx.link().clone();
                let request = Request::post("/api/userscripts/update")
                    .header("Content-Type", "application/json")
                    .body(body)
                    .unwrap();

                spawn_local(async move {
                    match request.send().await {
                        Ok(response) if response.ok() => {
                            match response.json::<Vec<RefreshResult>>().await {
                                Ok(results) => link.send_message(Message::Refreshed(results)),
                                Err(err) => link.send_message(Message::Failed(format!(
                                    "Unable to read the refresh report: {err}"
                                ))),
                            }
                        }
                        Ok(response) => {
                            let status = response.status();
                            let message = match response.json::<ApiError>().await {
                                Ok(api_error) => api_error.error,
                                Err(_) => format!("Refresh failed (HTTP {status})"),
                            };
                            link.send_message(Message::Failed(message));
                        }
                        Err(err) => link.send_message(Message::Failed(format!("{err}"))),
                    }
                });
            }
            Message::Refreshed(results) => {
                self.submitting = false;
                self.refresh_report = Some(results);
                ctx.link().send_message(Message::Load);
            }
            Message::Saved(message) => {
                self.submitting = false;
                self.add_open = false;
                self.error = None;
                self.saved_message = Some(message);
                ctx.link().send_message(Message::Load);
            }
            Message::Failed(message) => {
                log::error!("Userscript request failed: {message}");
                self.submitting = false;
                self.error = Some(message);
                // The optimistic toggle above may no longer reflect what was
                // persisted, so re-read rather than leaving a stale checkbox.
                ctx.link().send_message(Message::Load);
            }
            Message::AckError => self.error = None,
            Message::AckSaved => self.saved_message = None,
            Message::OpenEdit(script) => self.editing = Some(*script),
            Message::CloseEdit => self.editing = None,
            Message::EditCompleted => {
                self.editing = None;
                ctx.link().send_message(Message::Load);
            }
        }

        true
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let title = html! {
            <div class="pt-1.5 mb-4">
                <h1 class="text-2xl font-bold text-gray-900">{ "Userscripts" }</h1>
            </div>
        };

        let Some(config) = &self.config else {
            return html! { <>{ title }{ self.render_error(ctx) }</> };
        };

        html! {
            <>
                { title }
                { self.render_scope_warning() }
                { self.render_error(ctx) }
                { self.render_saved_banner(ctx) }
                { self.render_edit_modal(ctx) }
                { self.render_engine_switch(ctx, config) }
                <fieldset class="mb-8" style="width: 100%;">
                    <legend class="text-lg font-medium text-gray-900">{ "Installed scripts" }</legend>
                    <div class="mb-5 flex space-x-4">
                        { self.render_add_button(ctx) }
                        { self.render_refresh_button(ctx) }
                    </div>
                    { self.render_refresh_report() }
                    { self.render_script_list(ctx, config) }
                </fieldset>
                { self.render_add_modal(ctx) }
            </>
        }
    }
}

impl UserScriptsPage {
    /// Issue a mutating request and translate the outcome into a message.
    fn send(
        &mut self,
        ctx: &Context<Self>,
        builder: gloo_net::http::RequestBuilder,
        body: String,
        success_message: &'static str,
    ) {
        self.submitting = true;
        self.error = None;

        let link = ctx.link().clone();
        let request = builder
            .header("Content-Type", "application/json")
            .body(body)
            .unwrap();

        spawn_local(async move {
            match request.send().await {
                Ok(response) if response.ok() => link.send_message(Message::Saved(success_message)),
                Ok(response) => {
                    let status = response.status();
                    let message = match response.json::<ApiError>().await {
                        Ok(api_error) => api_error.error,
                        Err(_) => format!("Request failed (HTTP {status})"),
                    };
                    link.send_message(Message::Failed(message));
                }
                Err(err) => link.send_message(Message::Failed(format!("{err}"))),
            }
        });
    }

    /// Userscripts are arbitrary JavaScript injected into every matching page
    /// for every client behind the proxy, which is a wider blast radius than a
    /// browser extension installed in one profile. Say so where scripts are
    /// added rather than burying it in documentation.
    fn render_scope_warning(&self) -> Html {
        html! {
            <div class="mb-6 rounded-md bg-amber-50 border border-amber-200 p-4">
                <div class="flex">
                    <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-amber-500 flex-shrink-0"
                        fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                            d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                    </svg>
                    <div class="ml-3">
                        <h3 class="text-sm font-medium text-amber-800">{ "Userscripts run on every client behind this proxy" }</h3>
                        <p class="mt-1 text-sm text-amber-700">
                            { "A script installed here is injected into every matching page on every device using Privaxy, and runs in the page's main world with full access to its contents. Only install scripts you have read and trust." }
                        </p>
                    </div>
                </div>
            </div>
        }
    }

    fn render_error(&self, ctx: &Context<Self>) -> Html {
        match &self.error {
            Some(message) => failure_banner!(
                true,
                ctx.link().callback(|_| Message::AckError),
                message.clone()
            ),
            None => html! {},
        }
    }

    fn render_saved_banner(&self, ctx: &Context<Self>) -> Html {
        let Some(message) = self.saved_message else {
            return html! {};
        };

        let icon = html! {
            <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-white" fill="none"
                viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                    d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
        };

        html! {
            <submit_banner::SubmitBanner {message} {icon}
                visible={true}
                on_hide={ctx.link().callback(|_| Message::AckSaved)}
                color={submit_banner::Color::Green} />
        }
    }

    fn render_engine_switch(&self, ctx: &Context<Self>, config: &UserScriptsConfig) -> Html {
        let on_toggle = ctx.link().callback(|event: MouseEvent| {
            let input: HtmlInputElement = event.target_unchecked_into();
            Message::ToggleEngine(input.checked())
        });

        html! {
            <fieldset class="mb-8" style="width: 100%;">
                <legend class="text-lg font-medium text-gray-900">{ "Userscript engine" }</legend>
                <div class="mt-4 border-t border-b border-gray-200 divide-y divide-gray-200">
                    <div class="mb-4" style="display: flex; flex-direction: column; width: 100%; padding: 2px 0;">
                        <div style="display: flex; align-items: center; width: 100%;">
                            <div class="text-gray-500" style="width: 260px; text-align: left; padding-right: 4px;">
                                { "Enable userscripts" }
                            </div>
                            <div style="flex-grow: 1;">
                                <input
                                    checked={config.enabled}
                                    onclick={on_toggle}
                                    disabled={self.submitting}
                                    type="checkbox"
                                    class="focus:ring-blue-500 h-4 w-4 text-blue-600 border-gray-300 rounded" />
                            </div>
                        </div>
                        <div style="margin-left: 260px;">
                            <p class="text-gray-400 text-sm">
                                { "Master switch. When off, no script is injected regardless of its own setting, and each script keeps its state for when you switch it back on." }
                            </p>
                        </div>
                    </div>
                    { self.render_private_network_switch(ctx, config) }
                </div>
            </fieldset>
        }
    }

    /// `GM_xmlhttpRequest` is relayed server-side, so it reaches the network the
    /// proxy sits on rather than the browser's. Spell out what turning this on
    /// exposes.
    fn render_private_network_switch(
        &self,
        ctx: &Context<Self>,
        config: &UserScriptsConfig,
    ) -> Html {
        let on_toggle = ctx.link().callback(|event: MouseEvent| {
            let input: HtmlInputElement = event.target_unchecked_into();
            Message::TogglePrivateNetwork(input.checked())
        });

        html! {
            <div class="mb-4" style="display: flex; flex-direction: column; width: 100%; padding: 2px 0;">
                <div style="display: flex; align-items: center; width: 100%;">
                    <div class="text-gray-500" style="width: 260px; text-align: left; padding-right: 4px;">
                        { "Allow requests to private addresses" }
                    </div>
                    <div style="flex-grow: 1;">
                        <input
                            checked={config.allow_private_network_requests}
                            onclick={on_toggle}
                            disabled={self.submitting}
                            type="checkbox"
                            class="focus:ring-blue-500 h-4 w-4 text-blue-600 border-gray-300 rounded" />
                    </div>
                </div>
                <div style="margin-left: 260px;">
                    <p class="text-gray-400 text-sm">
                        { "Lets " }
                        <span class="font-mono bg-gray-100 px-1">{ "GM_xmlhttpRequest" }</span>
                        { " reach loopback, LAN and link-local addresses. Those requests are made by Privaxy, not by the browser, so they can reach routers, admin panels and cloud metadata endpoints that no page could contact. Leave off unless a script genuinely needs it." }
                    </p>
                </div>
            </div>
        }
    }

    fn render_add_button(&self, ctx: &Context<Self>) -> Html {
        html! {
            <button onclick={ctx.link().callback(|_| Message::OpenAdd)} type="button"
                class="mt-5 inline-flex items-center justify-center focus:ring-green-500 bg-green-600 hover:bg-green-700 px-4 py-2 border transition ease-in-out duration-150 border-transparent text-sm font-medium rounded-md shadow-sm text-white focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-gray-100">
                <svg xmlns="http://www.w3.org/2000/svg" class="-ml-0.5 mr-2 h-5 w-5" fill="none"
                    viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
                </svg>
                { "Add userscript" }
            </button>
        }
    }

    fn render_refresh_button(&self, ctx: &Context<Self>) -> Html {
        html! {
            <button onclick={ctx.link().callback(|_| Message::RefreshAll)} type="button"
                disabled={self.submitting}
                title="Re-fetch every userscript installed from a URL"
                class="mt-5 inline-flex items-center justify-center px-4 py-2 border border-gray-300 transition ease-in-out duration-150 text-sm font-medium rounded-md shadow-sm text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50">
                <svg xmlns="http://www.w3.org/2000/svg" class="-ml-0.5 mr-2 h-5 w-5" fill="none"
                    viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                        d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                </svg>
                { if self.submitting { "Checking..." } else { "Check for updates" } }
            </button>
        }
    }

    /// Report what the last refresh actually did, per script. Without this a
    /// refresh that found nothing new is indistinguishable from one that failed.
    fn render_refresh_report(&self) -> Html {
        let Some(results) = &self.refresh_report else {
            return html! {};
        };

        if results.is_empty() {
            return html! {
                <p class="mt-2 text-gray-500 text-sm">
                    { "No userscripts are installed from a URL, so there was nothing to check." }
                </p>
            };
        }

        html! {
            <div class="mt-2 mb-4 rounded-md bg-gray-50 border border-gray-200 p-3">
                { for results.iter().map(|result| {
                    let (classes, detail) = match result.outcome.as_str() {
                        "updated" => (
                            "text-green-700",
                            result.version.as_ref().map_or_else(
                                || "updated".to_string(),
                                |version| format!("updated to {version}"),
                            ),
                        ),
                        "already_current" => ("text-gray-500", "already up to date".to_string()),
                        _ => (
                            "text-red-600",
                            result.error.clone().unwrap_or_else(|| "failed".to_string()),
                        ),
                    };

                    html! {
                        <p class={classes!("text-xs", classes)}>
                            <span class="font-medium">{ &result.title }</span>
                            { " \u{2014} " }{ detail }
                        </p>
                    }
                }) }
            </div>
        }
    }

    fn render_script_list(&self, ctx: &Context<Self>, config: &UserScriptsConfig) -> Html {
        if config.scripts.is_empty() {
            return html! {
                <p class="mt-4 text-gray-500 text-sm">
                    { "No userscripts installed. Paste one, or install it from a URL." }
                </p>
            };
        }

        html! {
            <div class="mt-4 border-t border-b border-gray-200 divide-y divide-gray-200">
                { for config.scripts.iter().map(|script| self.render_script(ctx, script)) }
            </div>
        }
    }

    fn render_script(&self, ctx: &Context<Self>, script: &UserScript) -> Html {
        let file_name = script.file_name.clone();
        let enabled = script.enabled;
        let on_toggle = ctx
            .link()
            .callback(move |_| Message::ToggleScript(file_name.clone(), !enabled));

        let script_to_edit = script.clone();
        let on_edit = ctx
            .link()
            .callback(move |_| Message::OpenEdit(Box::new(script_to_edit.clone())));

        let subtitle = {
            let mut parts = Vec::new();
            if let Some(version) = &script.version {
                parts.push(format!("v{version}"));
            }
            if let Some(run_at) = &script.run_at {
                parts.push(run_at.clone());
            }
            if script.no_frames {
                parts.push("top frame only".to_string());
            }
            if !script.grants.is_empty() {
                parts.push(format!("{} grant(s)", script.grants.len()));
            }
            parts.join(" \u{2022} ")
        };

        html! {
            <div class="relative flex items-start py-4">
                <div class="min-w-0 flex-1 text-sm">
                    <label class="select-none font-medium text-gray-900">{ &script.title }</label>
                    if !subtitle.is_empty() {
                        <p class="text-gray-400 text-xs mt-0.5">{ subtitle }</p>
                    }
                    if let Some(description) = &script.description {
                        <p class="text-gray-500 text-xs mt-0.5">{ description }</p>
                    }
                    if !script.matches.is_empty() {
                        <p class="text-gray-400 text-xs mt-1 font-mono break-all">
                            { script.matches.join(", ") }
                        </p>
                    }
                    if let Some(url) = &script.url {
                        <p class="text-gray-400 text-xs mt-1 break-all">{ url }</p>
                    }
                    if let Some(error) = &script.error {
                        <p class="text-red-500 text-xs mt-1">
                            { "This script is not being injected: " }{ error }
                        </p>
                    }
                    { for script.warnings.iter().map(|warning| html! {
                        <p class="text-amber-600 text-xs mt-1">{ warning }</p>
                    }) }
                </div>
                <div class="ml-3 flex items-center h-5">
                    <button type="button" class="mr-4 text-gray-400 hover:text-blue-600"
                        title="Edit or remove this userscript" onclick={on_edit}>
                        <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none"
                            viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                        </svg>
                    </button>
                    <input checked={script.enabled} onchange={on_toggle}
                        disabled={self.submitting}
                        name={script.file_name.clone()} type="checkbox"
                        class="focus:ring-blue-500 h-4 w-4 text-blue-600 border-gray-300 rounded" />
                </div>
            </div>
        }
    }

    fn render_add_modal(&self, ctx: &Context<Self>) -> Html {
        if !self.add_open {
            return html! {};
        }

        let on_url_input = ctx.link().callback(|event: InputEvent| {
            let input: HtmlInputElement = event.target_unchecked_into();
            Message::AddUrlChanged(input.value())
        });
        let on_body_input = ctx.link().callback(|event: InputEvent| {
            let textarea: HtmlTextAreaElement = event.target_unchecked_into();
            Message::AddBodyChanged(textarea.value())
        });

        html! {
            <div class="fixed inset-0 bg-gray-600 bg-opacity-75 flex items-center justify-center z-50">
                <div class="bg-white p-6 rounded-lg shadow-lg z-60 w-full max-w-2xl">
                    <h2 class="text-lg font-medium text-gray-900 mb-4">{ "Add userscript" }</h2>
                    <div class="flex flex-col space-y-4">
                        <div>
                            <label class="font-bold text-sm">{ "Install from URL" }</label>
                            <input type="text" placeholder="https://example.com/script.user.js"
                                class="mt-1 w-full bg-white border border-gray-300 text-gray-700 py-2 px-4 rounded leading-tight focus:outline-none focus:border-gray-500"
                                value={self.add_url.clone()} oninput={on_url_input} />
                            <p class="text-gray-400 text-xs mt-1">
                                { "Re-fetched with the other remote lists so upstream updates are picked up." }
                            </p>
                        </div>
                        <div class="text-center text-gray-400 text-sm">{ "or" }</div>
                        <div>
                            <label class="font-bold text-sm">{ "Paste the script" }</label>
                            <textarea rows="14"
                                placeholder="// ==UserScript==\n// @name    My script\n// @match   https://example.com/*\n// ==/UserScript==="
                                class="mt-1 w-full font-mono text-xs bg-white border border-gray-300 text-gray-700 py-2 px-4 rounded leading-tight focus:outline-none focus:border-gray-500"
                                value={self.add_body.clone()} oninput={on_body_input} />
                            <p class="text-gray-400 text-xs mt-1">
                                { "Must contain a " }
                                <span class="font-mono bg-gray-100 px-1">{ "==UserScript==" }</span>
                                { " block declaring at least one " }
                                <span class="font-mono bg-gray-100 px-1">{ "@match" }</span>
                                { " or " }
                                <span class="font-mono bg-gray-100 px-1">{ "@include" }</span>
                                { "." }
                            </p>
                        </div>
                        <div class="flex space-x-4">
                            <button onclick={ctx.link().callback(|_| Message::SubmitAdd)}
                                disabled={self.submitting}
                                class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded z-60 disabled:opacity-50">
                                { if self.submitting { "Installing..." } else { "Install" } }
                            </button>
                            <button onclick={ctx.link().callback(|_| Message::CloseAdd)}
                                class="bg-gray-500 hover:bg-gray-700 text-white font-bold py-2 px-4 rounded z-60">
                                { "Cancel" }
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        }
    }

    fn render_edit_modal(&self, ctx: &Context<Self>) -> Html {
        match &self.editing {
            Some(script) => html! {
                <UserScriptEditModal
                    file_name={script.file_name.clone()}
                    title={script.title.clone()}
                    on_close={ctx.link().callback(|_| Message::CloseEdit)}
                    on_changed={ctx.link().callback(|_| Message::EditCompleted)} />
            },
            None => html! {},
        }
    }
}
