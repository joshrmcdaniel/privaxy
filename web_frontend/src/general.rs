use crate::button::ButtonState;
use crate::button::{get_css, ButtonColor};
use crate::failure_banner;
use crate::success_banner;
use crate::{save_button, ApiError};
use gloo_utils::format::JsValueSerdeExt;
use regex::Regex;
use reqwasm::http::Request;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;
use web_sys::{File, FileReader};
use yew::prelude::*;
use yew::{html, Callback, Component, Context, Html};

#[wasm_bindgen(module = "/static/validate_cert.js")]
extern "C" {
    #[wasm_bindgen(catch)]
    async fn validateCertificate(cert_pem: &str, key_pem: &str) -> Result<JsValue, JsValue>;
}

pub enum Message {
    Load,
    Save,
    NetworkLoadSuccess(NetworkConfig),
    UpdateProxyPort(String),
    UpdateBindAddr(String),
    UpdateWebPort(String),
    UpdateCaCert(String),
    UpdateCaKey(String),
    UploadCaCert(web_sys::File),
    UploadCaKey(web_sys::File),
    ValidateCertificates,
    ValidationFailed(String),
    UpdateTls(bool),
    SaveSuccess,
    SaveFailed(ApiError),
    AcknowledgeError,
    AcknowledgeSuccess,
}
enum SettingType {
    Text(String),
    Checkbox(bool),
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
/// Network configuration for Privaxy
pub struct NetworkConfig {
    /// Bind address for the proxy server.
    pub bind_addr: String,
    /// Port for the proxy server.
    pub proxy_port: u16,
    /// Port for the web server.
    pub web_port: u16,
    /// Enable TLS for the web server.
    pub tls: bool,
}

#[derive(Debug, Clone, PartialEq)]
struct CaConfig {
    private_key_pem: String,
    ca_cert_pem: String,
    ca_cert_error: Option<String>,
    private_key_error: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
struct ExternCaCertificateValidation {
    valid: bool,
    error: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
struct NetworkSettings {
    current_config: NetworkConfig,
    remote_config: NetworkConfig,
    raw_proxy_port: String,
    raw_bind_addr: String,
    raw_web_port: String,
    proxy_port_error: Option<String>,
    bind_addr_error: Option<String>,
    web_port_error: Option<String>,
}

impl NetworkSettings {
    fn validate(&self) -> bool {
        self.proxy_port_error.is_none()
            && self.bind_addr_error.is_none()
            && self.web_port_error.is_none()
    }
    fn config_has_changed(&self) -> bool {
        self.current_config.clone() != self.remote_config
    }
    async fn save(&mut self) -> Result<(), ApiError> {
        let body = serde_json::to_string(&self.remote_config).unwrap();
        let req = reqwasm::http::Request::put("/api/settings/network")
            .body(body)
            .header("Content-Type", "application/json");
        match req.send().await {
            Ok(resp) => {
                if resp.ok() {
                    return Ok(());
                } else {
                    log::error!("Failed to save network config");
                    return Err(resp.json::<ApiError>().await.unwrap());
                }
            }
            Err(err) => {
                log::error!("{}", err);
                Err(ApiError {
                    error: format!("{:?}", err),
                })
            }
        }
    }
}

enum SettingCategories {
    Network(NetworkSettings),
    Certificate(CaConfig),
    Other,
}

pub(crate) struct GeneralSettings {
    changes_saved: bool,
    network_settings: Option<NetworkSettings>,
    ca_config: CaConfig,
    loading: bool,
    save_callback: Callback<()>,
    show_error: bool,
    show_success: bool,
    err_msg: String,
}

impl GeneralSettings {
    fn save(&self) {
        self.save_callback.emit(());
    }

    fn config_has_changed(&self) -> bool {
        let net_changed = match &self.network_settings {
            None => return false,
            Some(network_settings) => {
                network_settings.current_config != network_settings.remote_config
            }
        };
        net_changed
    }
    fn validate(&self) -> bool {
        match &self.network_settings {
            None => false,
            Some(network_settings) => network_settings.validate(),
        }
    }
}

impl Component for GeneralSettings {
    type Message = Message;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        ctx.link().send_message(Message::Load);
        Self {
            changes_saved: true,
            ca_config: CaConfig {
                private_key_pem: String::new(),
                ca_cert_pem: String::new(),
                ca_cert_error: None,
                private_key_error: None,
            },
            network_settings: None,
            loading: true,
            save_callback: Callback::noop(),
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
                    let request = Request::get("/api/settings/network");
                    match request.send().await {
                        Ok(response) => {
                            if response.ok() {
                                if let Ok(network_config) = response.json::<NetworkConfig>().await {
                                    link.send_message(Message::NetworkLoadSuccess(network_config));
                                }
                            } else {
                                log::error!(
                                    "Failed to load network config: {:?}",
                                    response.status()
                                );
                            }
                        }
                        Err(err) => {
                            log::error!("Request error: {:?}", err);
                        }
                    }
                });
                self.loading = false;
                self.changes_saved = true;
            }
            Message::Save => {
                let link = ctx.link().clone();
                let network_settings = self.network_settings.clone();
                spawn_local(async move {
                    if let Some(mut network_settings) = network_settings {
                        if network_settings.config_has_changed() {
                            match network_settings.save().await {
                                Ok(_) => {
                                    link.send_message(Message::NetworkLoadSuccess(
                                        network_settings.current_config,
                                    ));
                                }
                                Err(err) => {
                                    log::error!("Failed to save network config: {:?}", err);
                                    link.send_message(Message::SaveFailed(err.clone()));
                                    return;
                                }
                            }
                        } else {
                            link.send_message(Message::NetworkLoadSuccess(
                                network_settings.remote_config,
                            ));
                        }
                    }
                    link.send_message(Message::SaveSuccess);
                });
            }
            Message::SaveFailed(err) => {
                let error_msg = err.clone().error.to_string();
                self.changes_saved = false;
                self.show_success = false;
                self.show_error = true;
                self.err_msg = error_msg;
            }
            Message::SaveSuccess => {
                self.changes_saved = true;
                self.show_success = true;
                self.show_error = false;
                self.err_msg = String::new();
            }
            Message::AcknowledgeSuccess => {
                self.show_success = false;
            }
            Message::AcknowledgeError => {
                self.show_error = false;
            }
            Message::NetworkLoadSuccess(network_config) => {
                self.network_settings = {
                    Some(NetworkSettings {
                        current_config: network_config.clone(),
                        remote_config: network_config.clone(),
                        raw_proxy_port: network_config.proxy_port.to_string(),
                        raw_bind_addr: network_config.bind_addr.clone(),
                        raw_web_port: network_config.web_port.to_string(),
                        proxy_port_error: None,
                        bind_addr_error: None,
                        web_port_error: None,
                    })
                };
                self.loading = false;
            }
            Message::UpdateProxyPort(value) => {
                if let Some(ref mut network_settings) = self.network_settings {
                    network_settings.raw_proxy_port = value.clone();
                    network_settings.proxy_port_error = match value.parse::<u16>() {
                        Ok(p) if p >= 1 => {
                            network_settings.current_config.proxy_port = p;
                            None
                        }
                        _ => Some("Invalid proxy port".to_string()),
                    };
                }
            }
            Message::UpdateBindAddr(value) => {
                if let Some(ref mut network_settings) = self.network_settings {
                    network_settings.raw_bind_addr = value.clone();
                    let re = Regex::new(r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$").unwrap();
                    network_settings.bind_addr_error = if re.is_match(&value) {
                        network_settings.current_config.bind_addr = value.clone();
                        None
                    } else {
                        Some("Invalid IP address".to_string())
                    };
                }
            }
            Message::UpdateWebPort(value) => {
                if let Some(ref mut network_settings) = self.network_settings {
                    network_settings.raw_web_port = value.clone();
                    network_settings.web_port_error = match value.parse::<u16>() {
                        Ok(p) if p >= 1 => {
                            network_settings.current_config.web_port = p;
                            None
                        }
                        _ => Some("Invalid web port".to_string()),
                    };
                }
            }
            Message::UpdateTls(value) => {
                if let Some(ref mut network_settings) = self.network_settings {
                    network_settings.current_config.tls = value;
                }
            }
            Message::UpdateCaCert(value) => {
                let link = ctx.link().clone();
                link.send_message(Message::ValidateCertificates);
                self.ca_config.ca_cert_pem = value;
            }
            Message::UpdateCaKey(value) => {
                let link = ctx.link().clone();
                link.send_message(Message::ValidateCertificates);
                self.ca_config.private_key_pem = value;
            }
            Message::UploadCaCert(file) => {
                let link = ctx.link().clone();
                read_file(
                    file,
                    Callback::from(move |result: Result<String, String>| match result {
                        Ok(text) => link.send_message(Message::UpdateCaCert(text)),
                        Err(e) => log::error!("Failed to read CA cert file: {}", e),
                    }),
                );
            }
            Message::UploadCaKey(file) => {
                let link = ctx.link().clone();
                read_file(
                    file,
                    Callback::from(move |result: Result<String, String>| match result {
                        Ok(text) => link.send_message(Message::UpdateCaKey(text)),
                        Err(e) => log::error!("Failed to read CA key file: {}", e),
                    }),
                );
            }
            Message::ValidateCertificates => {
                let cert_pem = self.ca_config.ca_cert_pem.clone();
                let key_pem = self.ca_config.private_key_pem.clone();
                let link = ctx.link().clone();
                spawn_local(async move {
                    match validateCertificate(&cert_pem, &key_pem).await {
                        Ok(result) => {
                            let result =
                                JsValueSerdeExt::into_serde::<ExternCaCertificateValidation>(
                                    &result,
                                )
                                .unwrap();
                            if !result.valid {
                                link.send_message(Message::ValidationFailed(result.error.unwrap()));
                            }
                        }
                        Err(err) => {
                            log::error!("Failed to validate certificates: {:?}", err);
                            link.send_message(Message::ValidationFailed(format!("{:?}", err)));
                        }
                    }
                });
            }
            Message::ValidationFailed(err) => {
                log::error!("{}", err);
                self.ca_config.private_key_error = Some(err.clone());
                self.ca_config.ca_cert_error = Some(err);
            }
        }
        true
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let render_setting = |setting_name: &str,
                              setting_value: String,
                              oninput: Callback<InputEvent>,
                              error: Option<&String>,
                              description: &str| {
            html! {
                <div class="mb-4" style="display: flex; flex-direction: column; width: 100%; padding: 2px 0;">
                    <div style="display: flex; align-items: center; width: 100%;">
                        <div class="text-gray-500" style="width: 200px; text-align: left; padding-right: 4px;">{ setting_name }</div>
                        <div style="flex-grow: 1;">
                            <input value={setting_value} class="shadow appearance-none border rounded w-80 py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline" type="text" oninput={oninput} />
                        </div>
                    </div>
                    <div style="margin-left: 200px;">
                        <p class="text-gray-400 text-sm">{description}</p>
                        if let Some(error_msg) = error {
                            <p class="text-red-500 text-xs italic">{error_msg}</p>
                        }
                    </div>
                </div>
            }
        };

        let render_boolean_setting = |setting_name: &str,
                                      setting_value: bool,
                                      oninput: Callback<MouseEvent>,
                                      description: &str| {
            html! {
                <div class="mb-4" style="display: flex; flex-direction: column; width: 100%; padding: 2px 0;">
                    <div style="display: flex; align-items: center; width: 100%;">
                        <div class="text-gray-500" style="width: 200px; text-align: left; padding-right: 4px;">{ setting_name }</div>
                        <div style="flex-grow: 1;">
                            <input checked={setting_value} onclick={oninput} type="checkbox" class="focus:ring-blue-500 h-4 w-4 text-blue-600 border-gray-300 rounded" />
                        </div>
                    </div>
                    <div style="margin-left: 200px;">
                        <p class="text-gray-400 text-sm">{description}</p>
                    </div>
                </div>
            }
        };

        let render_category = |category_name: &str, category_settings: SettingCategories| {
            html! {
            <fieldset class="mb-8" style="width: 100%;">
                <legend class="text-lg font-medium text-gray-900">{category_name}</legend>
                    <div class="mt-4 border-t border-b border-gray-200 divide-y divide-gray-200">
                        { match category_settings {
                            SettingCategories::Network(network_settings) => {
                                html! {
                                    <>
                                    { render_setting(
                                        "Bind address",
                                        network_settings.raw_bind_addr.clone(),
                                        ctx.link().callback(|e: InputEvent| {
                                            let input: web_sys::HtmlInputElement = e.target_unchecked_into();
                                            Message::UpdateBindAddr(input.value())
                                        }),
                                        network_settings.bind_addr_error.as_ref(),
                                        "The IP address the proxy will bind to."
                                    ) }
                                    { render_setting(
                                        "Proxy port",
                                        network_settings.raw_proxy_port.clone(),
                                        ctx.link().callback(|e: InputEvent| {
                                            let input: web_sys::HtmlInputElement = e.target_unchecked_into();
                                            Message::UpdateProxyPort(input.value())
                                        }),
                                        network_settings.proxy_port_error.as_ref(),
                                        "The port number the proxy server will listen on"
                                    ) }
                                    { render_setting(
                                        "Web port",
                                        network_settings.raw_web_port.clone(),
                                        ctx.link().callback(|e: InputEvent| {
                                            let input: web_sys::HtmlInputElement = e.target_unchecked_into();
                                            Message::UpdateWebPort(input.value())
                                        }),
                                        network_settings.web_port_error.as_ref(),
                                        "The port number the web server will listen on"
                                    ) }
                                    { render_boolean_setting(
                                        "TLS",
                                        network_settings.current_config.tls,
                                        ctx.link().callback(|e: MouseEvent| {
                                            let input: web_sys::HtmlInputElement = e.target_unchecked_into();
                                            Message::UpdateTls(input.checked())
                                        }),
                                        "If the web server uses HTTPS") }
                                    </>
                                }
                            }
                            SettingCategories::Certificate(ca_config) => {
                                html! {
                                    <>
                                    { render_certificate_setting(
                                        "CA Certificate",
                                        ca_config.ca_cert_pem.clone(),
                                        ctx.link().callback(|e: InputEvent| {
                                            let input: web_sys::HtmlTextAreaElement = e.target_unchecked_into();
                                            Message::UpdateCaCert(input.value())
                                        }),
                                        ctx.link().callback(Message::UploadCaCert),
                                        ca_config.ca_cert_error.as_ref(),
                                        "Paste or upload the CA Certificate"
                                    ) }
                                    { render_certificate_setting(
                                        "CA Certificate Key",
                                        ca_config.private_key_pem.clone(),
                                        ctx.link().callback(|e: InputEvent| {
                                            let input: web_sys::HtmlTextAreaElement = e.target_unchecked_into();
                                            Message::UpdateCaKey(input.value())
                                        }),
                                        ctx.link().callback(Message::UploadCaKey),
                                        ca_config.private_key_error.as_ref(),
                                        "Paste or upload the CA Certificate Key"
                                    ) }
                                    </>
                                }
                            }

                            SettingCategories::Other => html! {<></>},
                        }}
                    </div>
                </fieldset>
            }
        };
        let save_button_state = if self.config_has_changed() && self.validate() {
            ButtonState::Enabled
        } else {
            ButtonState::Disabled
        };

        let save_callback = ctx.link().callback(|_| Message::Save);
        let title = html! {
            <div class="pt-1.5 mb-4">
                <h1 class="text-2xl font-bold text-gray-900">{ "General Settings" }</h1>
            </div>
        };
        let success_banner_html = if self.show_success {
            success_banner!(true, ctx.link().callback(|_| Message::AcknowledgeSuccess))
        } else {
            html! {}
        };
        let failure_banner_html = if self.show_error {
            failure_banner!(
                true,
                ctx.link().callback(|_| Message::AcknowledgeError),
                self.err_msg.clone()
            )
        } else {
            html! {}
        };
        html! {
            <>
            { title }
            { success_banner_html }
            { failure_banner_html }
                if let Some(network_settings) = &self.network_settings {
                    {render_category("Network", SettingCategories::Network(network_settings.clone()))}
                } else {
                    <div>{"Loading..."}</div>
                }
                    {render_category("Certificate", SettingCategories::Certificate(self.ca_config.clone()))}

            {save_button!(save_callback, save_button_state)}
            </>
        }
    }
}

fn render_certificate_setting(
    setting_name: &str,
    value: String,
    oninput: Callback<InputEvent>,
    onupload: Callback<web_sys::File>,
    error: Option<&String>,
    description: &str,
) -> Html {
    let input_id = setting_name.to_string().to_lowercase().replace(" ", "_");
    html! {
        <div class="mb-4" style="display: flex; flex-direction: column; width: 100%; padding: 2px 0;">
            <div style="display: flex; align-items: center; width: 100%;">
                <div class="text-gray-500" style="width: 200px; text-align: left; padding-right: 4px;">{ setting_name }</div>
                <div style="flex-grow: 1;">
                    <textarea
                        value={value}
                        class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
                        oninput={oninput}
                    />
                </div>
            </div>
            <div class="ml-200" style="margin-left: 200px;">
                <input
                    type="file"
                    id={input_id.clone()}
                    name={input_id.clone()}
                    class={ get_css(ButtonColor::Blue) }
                    onchange={Callback::from(move |e: Event| {
                        let input: web_sys::HtmlInputElement = e.target_unchecked_into();
                        if let Some(file) = input.files().and_then(|files| files.get(0)) {
                            onupload.emit(file);
                        }
                    })}
                    accept=".pem"
                    />
                <p class="text-gray-400 text-sm mt-1">{description}</p>
                if let Some(error_msg) = error {
                    <p class="text-red-500 text-xs italic">{error_msg}</p>
                }
            </div>
        </div>
    }
}

use std::cell::RefCell;
use std::rc::Rc;

fn read_file(file: File, callback: Callback<Result<String, String>>) {
    let file_reader = FileReader::new().unwrap();
    let callback = Rc::new(RefCell::new(callback));

    let onload = {
        let callback = callback.clone();
        Closure::wrap(Box::new(move |event: web_sys::Event| {
            let target = event.target().unwrap();
            let file_reader: FileReader = target.dyn_into().unwrap();
            match file_reader.result() {
                Ok(result) => {
                    if let Some(text) = result.as_string() {
                        callback.borrow().emit(Ok(text));
                    } else {
                        callback
                            .borrow()
                            .emit(Err("Failed to convert result to string".to_string()));
                    }
                }
                Err(_) => callback
                    .borrow()
                    .emit(Err("Failed to get result from FileReader".to_string())),
            }
        }) as Box<dyn FnMut(_)>)
    };

    let onerror = {
        let callback = callback.clone();
        Closure::wrap(Box::new(move |_error: web_sys::Event| {
            callback
                .borrow()
                .emit(Err("Error reading file".to_string()));
        }) as Box<dyn FnMut(_)>)
    };

    file_reader.set_onload(Some(onload.as_ref().unchecked_ref()));
    file_reader.set_onerror(Some(onerror.as_ref().unchecked_ref()));

    file_reader
        .read_as_text(&file)
        .expect("Could not read file");

    onload.forget();
    onerror.forget();
}
