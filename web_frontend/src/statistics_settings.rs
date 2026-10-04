use crate::api;
use gloo_net::http::Request;
use serde::{Deserialize, Serialize};
use wasm_bindgen_futures::spawn_local;
use web_sys::{HtmlInputElement, HtmlSelectElement, HtmlTextAreaElement};
use yew::prelude::*;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct StatisticsConfig {
    pub enabled: bool,
    pub privacy: String,
    pub retention_days: u16,
    pub max_entries: u32,
    #[serde(default)]
    pub excluded_domains: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct HistoryStatus {
    pub active: bool,
    pub error: Option<String>,
    pub dropped_events: u64,
    pub stored_requests: u64,
    pub database_bytes: u64,
}

#[derive(Clone, Deserialize)]
pub struct StatisticsSettings {
    pub config: StatisticsConfig,
    pub status: HistoryStatus,
}

pub enum Message {
    Load,
    Loaded(Result<StatisticsSettings, String>),
    Enabled(bool),
    Privacy(String),
    Days(String),
    Limit(String),
    Exclusions(String),
    Save,
    Saved(Result<StatisticsSettings, String>),
    ConfirmClear(bool),
    Clear,
    Cleared(Result<(), String>),
}

pub struct StatisticsSettingsPage {
    settings: Option<StatisticsSettings>,
    days: String,
    limit: String,
    exclusions: String,
    busy: bool,
    confirm_clear: bool,
    error: Option<String>,
    notice: Option<String>,
}

impl Component for StatisticsSettingsPage {
    type Message = Message;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        ctx.link().send_message(Message::Load);
        Self {
            settings: None,
            days: String::new(),
            limit: String::new(),
            exclusions: String::new(),
            busy: false,
            confirm_clear: false,
            error: None,
            notice: None,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, message: Message) -> bool {
        match message {
            Message::Load => {
                self.busy = true;
                self.error = None;
                let link = ctx.link().clone();
                spawn_local(async move {
                    link.send_message(Message::Loaded(
                        api::get_json("/api/settings/statistics").await,
                    ));
                });
            }
            Message::Loaded(result) | Message::Saved(result) => {
                self.busy = false;
                match result {
                    Ok(settings) => {
                        self.days = settings.config.retention_days.to_string();
                        self.limit = settings.config.max_entries.to_string();
                        self.exclusions = settings.config.excluded_domains.join("\n");
                        self.error = settings.status.error.clone();
                        self.settings = Some(settings);
                    }
                    Err(error) => {
                        self.error = Some(error);
                        self.notice = None;
                    }
                }
            }
            Message::Enabled(value) => {
                if self.busy {
                    return false;
                }
                if let Some(settings) = &mut self.settings {
                    settings.config.enabled = value;
                }
                self.notice = None;
            }
            Message::Privacy(value) => {
                if self.busy {
                    return false;
                }
                if let Some(settings) = &mut self.settings {
                    settings.config.privacy = value;
                }
                self.notice = None;
            }
            Message::Days(value) => {
                if self.busy {
                    return false;
                }
                self.days = value;
                self.notice = None;
            }
            Message::Limit(value) => {
                if self.busy {
                    return false;
                }
                self.limit = value;
                self.notice = None;
            }
            Message::Exclusions(value) => {
                if self.busy {
                    return false;
                }
                self.exclusions = value;
                self.notice = None;
            }
            Message::Save => {
                if self.busy {
                    return false;
                }
                let Some(settings) = &self.settings else {
                    return false;
                };
                let (Ok(days @ 1..=365), Ok(limit @ 100..=1_000_000)) =
                    (self.days.parse::<u16>(), self.limit.parse::<u32>())
                else {
                    self.error = Some("Choose 1–365 days and 100–1,000,000 requests.".into());
                    return true;
                };
                let mut config = settings.config.clone();
                config.retention_days = days;
                config.max_entries = limit;
                config.excluded_domains = self
                    .exclusions
                    .lines()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(|s| s.trim_end_matches('.').to_ascii_lowercase())
                    .collect();
                self.busy = true;
                self.error = None;
                self.notice = None;
                let link = ctx.link().clone();
                spawn_local(async move {
                    let result = async {
                        let response = Request::put("/api/settings/statistics")
                            .json(&config)
                            .map_err(|e| e.to_string())?
                            .send()
                            .await
                            .map_err(|e| e.to_string())?;
                        if !response.ok() {
                            return Err(api::response_error(response).await);
                        }
                        response
                            .json::<StatisticsSettings>()
                            .await
                            .map_err(|e| e.to_string())
                    }
                    .await;
                    link.send_message(Message::Saved(result));
                });
                self.notice = Some("Settings saved".into());
            }
            Message::ConfirmClear(value) => {
                if self.busy {
                    return false;
                }
                self.confirm_clear = value;
            }
            Message::Clear => {
                if self.busy || !self.confirm_clear {
                    return false;
                }
                self.busy = true;
                self.error = None;
                self.notice = None;
                let link = ctx.link().clone();
                spawn_local(async move {
                    let result = async {
                        let response = Request::delete("/api/history")
                            .send()
                            .await
                            .map_err(|e| e.to_string())?;
                        if response.ok() {
                            Ok(())
                        } else {
                            Err(api::response_error(response).await)
                        }
                    }
                    .await;
                    link.send_message(Message::Cleared(result));
                });
            }
            Message::Cleared(result) => {
                self.busy = false;
                self.confirm_clear = false;
                match result {
                    Ok(()) => {
                        self.notice = Some("Saved history deleted".into());
                        if let Some(settings) = &mut self.settings {
                            settings.status.stored_requests = 0;
                            settings.status.database_bytes = 0;
                            settings.status.dropped_events = 0;
                            settings.status.error = None;
                        }
                    }
                    Err(error) => self.error = Some(error),
                }
            }
        }
        true
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let Some(settings) = &self.settings else {
            return html! { <>
                <h1 class="text-2xl font-bold">{"Statistics"}</h1>
                if let Some(error) = &self.error {
                    <p role="alert" class="mt-4 text-red-700">{error}</p>
                    <button class="mt-2 text-blue-600 underline" disabled={self.busy} onclick={ctx.link().callback(|_| Message::Load)}>{"Retry loading statistics settings"}</button>
                } else { <p role="status">{"Loading…"}</p> }
            </> };
        };
        let config = &settings.config;
        let on_enabled = ctx.link().callback(|e: Event| {
            Message::Enabled(e.target_unchecked_into::<HtmlInputElement>().checked())
        });
        let on_privacy = ctx.link().callback(|e: Event| {
            Message::Privacy(e.target_unchecked_into::<HtmlSelectElement>().value())
        });
        let on_days = ctx.link().callback(|e: InputEvent| {
            Message::Days(e.target_unchecked_into::<HtmlInputElement>().value())
        });
        let on_limit = ctx.link().callback(|e: InputEvent| {
            Message::Limit(e.target_unchecked_into::<HtmlInputElement>().value())
        });
        let on_exclusions = ctx.link().callback(|e: InputEvent| {
            Message::Exclusions(e.target_unchecked_into::<HtmlTextAreaElement>().value())
        });
        html! { <>
            <h1 class="text-2xl font-bold text-gray-900 mb-4">{"Statistics"}</h1>
            <p class="text-sm text-gray-600 mb-4">{"History is off by default. When enabled, it stays on this server and survives restarts. It records request times, hostnames, client IPs, and blocking decisions according to your privacy level. Full URLs, query strings, headers, and bodies are never saved in statistics."}</p>
            if let Some(error) = &self.error { <p role="alert" class="mb-4 text-sm text-red-700">{error}</p> }
            <fieldset disabled={self.busy} class="border-t border-gray-200 divide-y divide-gray-200">
                <div class="settings-field">
                    <div class="settings-field-row">
                        <label for="history-enabled" class="settings-field-label">{"Enable persistent statistics"}</label>
                        <div class="settings-field-control"><input id="history-enabled" type="checkbox" checked={config.enabled} onchange={on_enabled} class="h-4 w-4 rounded text-blue-600 border-gray-300" /></div>
                    </div>
                    <p class="settings-field-help text-sm text-gray-500">{"Disabling stops recording. Previously saved history remains until you delete it or re-enable recording and retention removes it."}</p>
                </div>
                <div class="settings-field">
                    <div class="settings-field-row">
                        <label for="history-privacy" class="settings-field-label">{"Privacy level"}</label>
                        <select id="history-privacy" class="settings-field-control rounded-md border-gray-300 text-sm" onchange={on_privacy}>
                            {for [("full", "Show domains and clients"), ("hide_domains", "Hide domains"), ("hide_domains_and_clients", "Hide domains and clients"), ("anonymous", "Anonymous — no saved history")].into_iter().map(|(value, label)| html! {<option value={value} selected={config.privacy == value}>{label}</option>})}
                        </select>
                    </div>
                    <p class="settings-field-help text-sm text-gray-500">{"Hidden identifiers are removed before collection. While enabled, increasing privacy also removes those identifiers from saved history. They cannot be recovered by lowering privacy. Anonymous mode keeps only session counters and does not record history."}</p>
                </div>
                <div class="settings-field"><div class="settings-field-row">
                    <label for="history-days" class="settings-field-label">{"Retention (days)"}</label>
                    <input id="history-days" class="settings-field-control rounded-md border-gray-300 text-sm" type="number" min="1" max="365" value={self.days.clone()} oninput={on_days} />
                </div></div>
                <div class="settings-field"><div class="settings-field-row">
                    <label for="history-limit" class="settings-field-label">{"Maximum saved requests"}</label>
                    <input id="history-limit" class="settings-field-control rounded-md border-gray-300 text-sm" type="number" min="100" max="1000000" value={self.limit.clone()} oninput={on_limit} />
                </div><p class="settings-field-help text-sm text-gray-500">{"The oldest requests are removed when either limit is reached. Reducing a limit deletes older history when saved."}</p></div>
                <div class="settings-field">
                    <label for="statistics-exclusions" class="block text-sm font-medium text-gray-700 mb-2">{"Exclude domains from statistics and request logs"}</label>
                    <textarea id="statistics-exclusions" rows="5" value={self.exclusions.clone()} oninput={on_exclusions} placeholder={"example.com\n*.example.com"} class="w-full rounded-md border-gray-300 text-sm font-mono" />
                    <p class="mt-2 text-sm text-gray-500">{"One domain or wildcard pattern per line, without a scheme, port, or path. An exact domain matches only that domain; *.example.com matches its subdomains. Matching new requests are omitted from session statistics, saved history, and the live Requests log, even when persistence is off. Filtering still applies. Existing history and diagnostic logs are unaffected."}</p>
                </div>
            </fieldset>
            <div class="mt-4 flex items-center gap-3">
                <button type="button" disabled={self.busy} onclick={ctx.link().callback(|_| Message::Save)} class="px-4 py-2 rounded-md bg-blue-600 text-white text-sm disabled:opacity-50">{if self.busy {"Working…"} else {"Save statistics settings"}}</button>
                if !self.busy { if let Some(notice) = &self.notice { <span role="status" class="text-sm text-green-700">{notice}</span> } }
            </div>
            <p class="mt-4 text-sm text-gray-600">{format!("{} saved requests · {:.1} MiB on disk", settings.status.stored_requests, settings.status.database_bytes as f64 / 1_048_576.0)}</p>
            if settings.status.dropped_events > 0 { <p role="alert" class="mt-2 text-sm text-amber-700">{format!("{} events could not be saved this session. Check free disk space and save settings again to retry.", settings.status.dropped_events)}</p> }
            <p class="mt-4 text-sm text-gray-600">{"These privacy controls cover statistics. The live Requests view and diagnostic logs are separate and can contain full URLs. Database deletion cannot erase filesystem snapshots or backups."}</p>
            <div class="mt-6 border-t border-gray-200 pt-4">
                if self.confirm_clear {
                    <p class="text-sm mb-3">{"Delete all saved request history and historical statistics? This cannot be undone. Recording will continue if enabled."}</p>
                    <button type="button" disabled={self.busy} onclick={ctx.link().callback(|_| Message::Clear)} class="px-4 py-2 bg-red-700 text-white text-sm rounded-md disabled:opacity-50">{"Delete saved history"}</button>
                    <button type="button" disabled={self.busy} onclick={ctx.link().callback(|_| Message::ConfirmClear(false))} class="ml-4 text-sm text-gray-600 underline">{"Cancel"}</button>
                } else { <button type="button" disabled={self.busy} onclick={ctx.link().callback(|_| Message::ConfirmClear(true))} class="text-sm text-red-700 underline">{"Clear saved history…"}</button> }
            </div>
        </> }
    }
}
