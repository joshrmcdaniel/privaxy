use crate::save_button;
use crate::{failure_banner, success_banner, ApiError};
use reqwasm::http::Request;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use wasm_bindgen_futures::spawn_local;
use web_sys::{HtmlInputElement, HtmlTextAreaElement};
use yew::{html, Component, Context, Html, InputEvent, TargetCast};

const PAC_RESOURCE_URL: &str = "/api/settings/pac";

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct PacSettings {
    pub pac_enabled: bool,
    #[serde(default)]
    pub pac_proxy_host: Option<String>,
    #[serde(default)]
    pub pac_direct_ips: Vec<String>,
    #[serde(default)]
    pub pac_direct_cidrs: BTreeMap<String, String>,
    #[serde(default)]
    pub pac_direct_fqdns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PacFormState {
    enabled: bool,
    proxy_host: String,
    direct_ips: String,
    direct_cidrs: String,
    direct_fqdns: String,
    cidrs_error: Option<String>,
}

impl PacFormState {
    fn from_settings(settings: &PacSettings) -> Self {
        let direct_ips = settings.pac_direct_ips.join("\n");
        let direct_fqdns = settings.pac_direct_fqdns.join("\n");
        let direct_cidrs = settings
            .pac_direct_cidrs
            .iter()
            .map(|(subnet, netmask)| format!("{subnet} {netmask}"))
            .collect::<Vec<_>>()
            .join("\n");
        Self {
            enabled: settings.pac_enabled,
            proxy_host: settings.pac_proxy_host.clone().unwrap_or_default(),
            direct_ips,
            direct_cidrs,
            direct_fqdns,
            cidrs_error: None,
        }
    }

    fn parse_lines(value: &str) -> Vec<String> {
        value
            .lines()
            .map(|line| line.trim().to_string())
            .filter(|line| !line.is_empty())
            .collect()
    }

    fn parse_cidrs(value: &str) -> Result<BTreeMap<String, String>, String> {
        let mut map = BTreeMap::new();
        for (idx, line) in value.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let (subnet, netmask) = if let Some((s, n)) = trimmed.split_once('/') {
                (s.trim(), n.trim())
            } else {
                let mut parts = trimmed.split_whitespace();
                let s = parts.next().unwrap_or("");
                let n = parts.next().unwrap_or("");
                if parts.next().is_some() {
                    return Err(format!(
                        "Line {}: expected 'subnet netmask' or 'subnet/netmask'",
                        idx + 1
                    ));
                }
                (s, n)
            };
            if subnet.is_empty() || netmask.is_empty() {
                return Err(format!(
                    "Line {}: expected 'subnet netmask' or 'subnet/netmask'",
                    idx + 1
                ));
            }
            map.insert(subnet.to_string(), netmask.to_string());
        }
        Ok(map)
    }

    fn to_settings(&self) -> Result<PacSettings, String> {
        let cidrs = Self::parse_cidrs(&self.direct_cidrs)?;
        let proxy_host = {
            let trimmed = self.proxy_host.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        };
        Ok(PacSettings {
            pac_enabled: self.enabled,
            pac_proxy_host: proxy_host,
            pac_direct_ips: Self::parse_lines(&self.direct_ips),
            pac_direct_cidrs: cidrs,
            pac_direct_fqdns: Self::parse_lines(&self.direct_fqdns),
        })
    }
}

pub enum Message {
    Load,
    LoadSuccess(PacSettings),
    UpdateEnabled(bool),
    UpdateProxyHost(String),
    UpdateDirectIps(String),
    UpdateDirectCidrs(String),
    UpdateDirectFqdns(String),
    Save,
    SaveSuccess,
    SaveFailed(ApiError),
    AcknowledgeSuccess,
    AcknowledgeError,
}

pub struct PacSettingsPage {
    form: Option<PacFormState>,
    remote: Option<PacFormState>,
    loading: bool,
    show_success: bool,
    show_error: bool,
    err_msg: String,
}

impl PacSettingsPage {
    fn config_has_changed(&self) -> bool {
        match (&self.form, &self.remote) {
            (Some(form), Some(remote)) => form != remote,
            _ => false,
        }
    }

    fn validate(&self) -> bool {
        match &self.form {
            Some(form) => form.cidrs_error.is_none(),
            None => false,
        }
    }
}

impl Component for PacSettingsPage {
    type Message = Message;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        ctx.link().send_message(Message::Load);
        Self {
            form: None,
            remote: None,
            loading: true,
            show_success: false,
            show_error: false,
            err_msg: String::new(),
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Message::Load => {
                let link = ctx.link().clone();
                spawn_local(async move {
                    let request = Request::get(PAC_RESOURCE_URL);
                    match request.send().await {
                        Ok(response) if response.ok() => {
                            if let Ok(settings) = response.json::<PacSettings>().await {
                                link.send_message(Message::LoadSuccess(settings));
                            }
                        }
                        Ok(response) => {
                            log::error!("Failed to load PAC settings: {:?}", response.status());
                        }
                        Err(err) => {
                            log::error!("Request error: {:?}", err);
                        }
                    }
                });
            }
            Message::LoadSuccess(settings) => {
                let form = PacFormState::from_settings(&settings);
                self.form = Some(form.clone());
                self.remote = Some(form);
                self.loading = false;
            }
            Message::UpdateEnabled(value) => {
                if let Some(form) = self.form.as_mut() {
                    form.enabled = value;
                }
            }
            Message::UpdateProxyHost(value) => {
                if let Some(form) = self.form.as_mut() {
                    form.proxy_host = value;
                }
            }
            Message::UpdateDirectIps(value) => {
                if let Some(form) = self.form.as_mut() {
                    form.direct_ips = value;
                }
            }
            Message::UpdateDirectCidrs(value) => {
                if let Some(form) = self.form.as_mut() {
                    form.direct_cidrs = value;
                    form.cidrs_error = match PacFormState::parse_cidrs(&form.direct_cidrs) {
                        Ok(_) => None,
                        Err(err) => Some(err),
                    };
                }
            }
            Message::UpdateDirectFqdns(value) => {
                if let Some(form) = self.form.as_mut() {
                    form.direct_fqdns = value;
                }
            }
            Message::Save => {
                let form = match self.form.clone() {
                    Some(form) => form,
                    None => return false,
                };
                let settings = match form.to_settings() {
                    Ok(settings) => settings,
                    Err(err) => {
                        ctx.link()
                            .send_message(Message::SaveFailed(ApiError { error: err }));
                        return true;
                    }
                };
                let link = ctx.link().clone();
                spawn_local(async move {
                    let body = match serde_json::to_string(&settings) {
                        Ok(body) => body,
                        Err(err) => {
                            link.send_message(Message::SaveFailed(ApiError {
                                error: format!("{err:?}"),
                            }));
                            return;
                        }
                    };
                    let request = Request::put(PAC_RESOURCE_URL)
                        .header("Content-Type", "application/json")
                        .body(body);
                    match request.send().await {
                        Ok(response) if response.ok() => {
                            link.send_message(Message::LoadSuccess(settings));
                            link.send_message(Message::SaveSuccess);
                        }
                        Ok(response) => {
                            let err = response.json::<ApiError>().await.unwrap_or(ApiError {
                                error: format!("HTTP {}", response.status()),
                            });
                            link.send_message(Message::SaveFailed(err));
                        }
                        Err(err) => {
                            link.send_message(Message::SaveFailed(ApiError {
                                error: format!("{err:?}"),
                            }));
                        }
                    }
                });
            }
            Message::SaveSuccess => {
                self.show_success = true;
                self.show_error = false;
                self.err_msg = String::new();
            }
            Message::SaveFailed(err) => {
                self.show_success = false;
                self.show_error = true;
                self.err_msg = err.error;
            }
            Message::AcknowledgeSuccess => {
                self.show_success = false;
            }
            Message::AcknowledgeError => {
                self.show_error = false;
            }
        }
        true
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let title = html! {
            <div class="pt-1.5 mb-4">
                <h1 class="text-2xl font-bold text-gray-900">{ "PAC" }</h1>
            </div>
        };
        let description = html! {
            <div class="text-gray-600">
                <p>
                    {"When enabled, Privaxy serves a Proxy Auto-Config script at "}
                    <span class="font-mono bg-gray-100">{"/proxy.pac"}</span>
                    {". Point your browser or system at that URL to route traffic through Privaxy, with the optional bypass rules below."}
                </p>
            </div>
        };

        let success_banner = if self.show_success {
            success_banner!(true, ctx.link().callback(|_| Message::AcknowledgeSuccess))
        } else {
            html! {}
        };
        let failure_banner = if self.show_error {
            failure_banner!(
                true,
                ctx.link().callback(|_| Message::AcknowledgeError),
                self.err_msg.clone()
            )
        } else {
            html! {}
        };

        if self.loading || self.form.is_none() {
            return html! {
                <>
                    { title }
                    { description }
                    <div class="mt-6 text-gray-500">{"Loading..."}</div>
                </>
            };
        }
        let form = self.form.as_ref().unwrap();

        let on_enabled = ctx.link().callback(|e: web_sys::MouseEvent| {
            let input = e.target_unchecked_into::<HtmlInputElement>();
            Message::UpdateEnabled(input.checked())
        });
        let on_proxy_host = ctx.link().callback(|e: InputEvent| {
            let input = e.target_unchecked_into::<HtmlInputElement>();
            Message::UpdateProxyHost(input.value())
        });
        let on_ips = ctx.link().callback(|e: InputEvent| {
            let input = e.target_unchecked_into::<HtmlTextAreaElement>();
            Message::UpdateDirectIps(input.value())
        });
        let on_cidrs = ctx.link().callback(|e: InputEvent| {
            let input = e.target_unchecked_into::<HtmlTextAreaElement>();
            Message::UpdateDirectCidrs(input.value())
        });
        let on_fqdns = ctx.link().callback(|e: InputEvent| {
            let input = e.target_unchecked_into::<HtmlTextAreaElement>();
            Message::UpdateDirectFqdns(input.value())
        });

        let save_state = if self.config_has_changed() && self.validate() {
            save_button::SaveButtonState::Enabled
        } else {
            save_button::SaveButtonState::Disabled
        };
        let on_save = ctx.link().callback(|_| Message::Save);

        html! {
            <>
                { title }
                { description }
                { success_banner }
                { failure_banner }

                <fieldset class="mt-6">
                    <div class="border-t border-b border-gray-200 divide-y divide-gray-200">
                        <div class="py-4 flex items-center">
                            <div class="text-gray-500" style="width: 220px;">{"Serve proxy.pac"}</div>
                            <div class="flex-grow">
                                <input type="checkbox" checked={form.enabled} onclick={on_enabled}
                                    class="focus:ring-blue-500 h-4 w-4 text-blue-600 border-gray-300 rounded" />
                                <p class="text-gray-400 text-sm mt-1">
                                    {"Expose the auto-config file at /proxy.pac (no auth)."}
                                </p>
                            </div>
                        </div>
                        <div class="py-4 flex items-start">
                            <div class="text-gray-500 pt-2" style="width: 220px;">{"Advertised proxy host"}</div>
                            <div class="flex-grow">
                                <input type="text" value={form.proxy_host.clone()} oninput={on_proxy_host}
                                    placeholder="e.g. 192.168.1.10:8100"
                                    class="shadow appearance-none border rounded w-80 py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline" />
                                <p class="text-gray-400 text-sm mt-1">
                                    {"host:port emitted as the PROXY directive. Leave blank to use the bind address and proxy port."}
                                </p>
                            </div>
                        </div>
                    </div>
                </fieldset>

                <fieldset class="mt-6">
                    <legend class="text-lg font-medium text-gray-900">{"Direct (bypass) rules"}</legend>
                    <p class="text-gray-500 text-sm mt-1">
                        {"Hosts matching any rule below are returned to clients as DIRECT instead of PROXY. One entry per line."}
                    </p>
                    <div class="mt-3">
                        <label class="block text-sm font-medium text-gray-700">
                            {"Local IPs (matched against myIpAddress())"}
                        </label>
                        <textarea
                            rows="4" value={form.direct_ips.clone()} oninput={on_ips}
                            placeholder="10.0.0.5"
                            class="mt-1 shadow-sm focus:ring-blue-500 focus:border-blue-500 block w-full sm:text-sm border-gray-300 rounded-md" />
                    </div>
                    <div class="mt-4">
                        <label class="block text-sm font-medium text-gray-700">
                            {"IP subnets (subnet netmask, or subnet/netmask, per line)"}
                        </label>
                        <textarea
                            rows="4" value={form.direct_cidrs.clone()} oninput={on_cidrs}
                            placeholder="10.0.0.0 255.0.0.0"
                            class="mt-1 shadow-sm focus:ring-blue-500 focus:border-blue-500 block w-full sm:text-sm border-gray-300 rounded-md" />
                        if let Some(err) = form.cidrs_error.as_ref() {
                            <p class="text-red-500 text-xs italic mt-1">{err}</p>
                        }
                    </div>
                    <div class="mt-4">
                        <label class="block text-sm font-medium text-gray-700">
                            {"FQDNs (host and its subdomains)"}
                        </label>
                        <textarea
                            rows="4" value={form.direct_fqdns.clone()} oninput={on_fqdns}
                            placeholder="example.com"
                            class="mt-1 shadow-sm focus:ring-blue-500 focus:border-blue-500 block w-full sm:text-sm border-gray-300 rounded-md" />
                    </div>
                </fieldset>

                <save_button::SaveButton state={save_state} onclick={on_save} />
            </>
        }
    }
}
