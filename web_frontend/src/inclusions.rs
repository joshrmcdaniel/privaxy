use crate::save_button::{SaveButton, SaveButtonState};
use crate::{failure_banner, success_banner, ApiError};
use gloo_net::http::Request;
use serde::{Deserialize, Serialize};
use wasm_bindgen_futures::spawn_local;
use web_sys::{HtmlInputElement, HtmlTextAreaElement};
use yew::prelude::*;

const RESOURCE_URL: &str = "/api/inclusions";

#[derive(Clone, Deserialize, Serialize)]
pub struct InclusionSettings {
    include_only: bool,
    inclusions: Vec<String>,
}

#[derive(Clone, PartialEq)]
pub struct Form {
    include_only: bool,
    hosts: String,
}

pub enum Message {
    Load,
    Loaded(InclusionSettings),
    Toggle(bool),
    Hosts(String),
    Save,
    Saved(Form),
    Failed(String),
    Dismiss,
}

pub struct Inclusions {
    form: Option<Form>,
    saved: Option<Form>,
    saving: bool,
    success: bool,
    error: Option<String>,
}

async fn response_error(response: gloo_net::http::Response) -> String {
    let status = response.status();
    response
        .json::<ApiError>()
        .await
        .map(|error| error.error)
        .unwrap_or_else(|_| format!("HTTP {status}"))
}

impl Component for Inclusions {
    type Message = Message;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        ctx.link().send_message(Message::Load);
        Self {
            form: None,
            saved: None,
            saving: false,
            success: false,
            error: None,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Message) -> bool {
        match msg {
            Message::Load => {
                self.error = None;
                let link = ctx.link().clone();
                spawn_local(async move {
                    let result = async {
                        let response = Request::get(RESOURCE_URL)
                            .send()
                            .await
                            .map_err(|e| e.to_string())?;
                        if !response.ok() {
                            return Err(response_error(response).await);
                        }
                        response.json().await.map_err(|e| e.to_string())
                    }
                    .await;
                    link.send_message(match result {
                        Ok(settings) => Message::Loaded(settings),
                        Err(error) => Message::Failed(error),
                    });
                });
            }
            Message::Loaded(settings) => {
                let form = Form {
                    include_only: settings.include_only,
                    hosts: settings.inclusions.join("\n"),
                };
                self.saved = Some(form.clone());
                self.form = Some(form);
            }
            Message::Toggle(enabled) => {
                if self.saving {
                    return false;
                }
                if let Some(form) = &mut self.form {
                    form.include_only = enabled;
                }
                self.success = false;
            }
            Message::Hosts(hosts) => {
                if self.saving {
                    return false;
                }
                if let Some(form) = &mut self.form {
                    form.hosts = hosts;
                }
                self.success = false;
            }
            Message::Save => {
                if self.saving || self.form == self.saved {
                    return false;
                }
                let Some(form) = self.form.clone() else {
                    return false;
                };
                self.saving = true;
                self.success = false;
                self.error = None;
                let link = ctx.link().clone();
                spawn_local(async move {
                    let settings = InclusionSettings {
                        include_only: form.include_only,
                        inclusions: form
                            .hosts
                            .lines()
                            .map(str::trim)
                            .filter(|host| !host.is_empty())
                            .map(str::to_string)
                            .collect(),
                    };
                    let result = async {
                        let request = Request::put(RESOURCE_URL)
                            .json(&settings)
                            .map_err(|e| e.to_string())?;
                        let response = request.send().await.map_err(|e| e.to_string())?;
                        if !response.ok() {
                            return Err(response_error(response).await);
                        }
                        Ok(())
                    }
                    .await;
                    link.send_message(match result {
                        Ok(()) => Message::Saved(form),
                        Err(error) => Message::Failed(error),
                    });
                });
            }
            Message::Saved(form) => {
                self.saved = Some(form);
                self.saving = false;
                self.success = true;
            }
            Message::Failed(error) => {
                self.saving = false;
                self.error = Some(error);
            }
            Message::Dismiss => {
                self.success = false;
                self.error = None;
            }
        }
        true
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let error = self
            .error
            .as_ref()
            .map(|error| {
                failure_banner!(
                    true,
                    ctx.link().callback(|_| Message::Dismiss),
                    error.clone()
                )
            })
            .unwrap_or_default();
        let success = if self.success {
            success_banner!(true, ctx.link().callback(|_| Message::Dismiss))
        } else {
            html! {}
        };
        let contents = if let Some(form) = &self.form {
            let state = if self.saving {
                SaveButtonState::Loading
            } else if self.form != self.saved {
                SaveButtonState::Enabled
            } else {
                SaveButtonState::Disabled
            };
            let on_toggle = ctx.link().callback(|event: Event| {
                Message::Toggle(event.target_unchecked_into::<HtmlInputElement>().checked())
            });
            let on_hosts = ctx.link().callback(|event: InputEvent| {
                Message::Hosts(event.target_unchecked_into::<HtmlTextAreaElement>().value())
            });
            html! {
                <>
                    <label class="mt-5 flex items-center gap-2 text-gray-900" for="include-only">
                        <input id="include-only" type="checkbox" checked={form.include_only} onchange={on_toggle} disabled={self.saving}
                            class="h-4 w-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500" />
                        {"Only filter included hosts"}
                    </label>
                    <label for="inclusions" class="block mt-5 text-sm font-medium text-gray-700">{"Included hosts — one per line"}</label>
                    <textarea id="inclusions" name="inclusions" rows="6" value={form.hosts.clone()} oninput={on_hosts} disabled={self.saving}
                        placeholder={"example.com\n*.example.com"}
                        class="mt-2 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm" />
                    <p class="mt-2 text-sm text-gray-500">{"Use example.com for that host and *.example.com for its subdomains. Exclusions always take precedence. Third-party hosts must be included separately."}</p>
                    if form.include_only && form.hosts.trim().is_empty() {
                        <p class="mt-2 text-sm text-gray-700">{"The list is empty: all hosts will bypass filtering."}</p>
                    }
                    <SaveButton {state} onclick={ctx.link().callback(|_| Message::Save)} />
                </>
            }
        } else if self.error.is_some() {
            html! { <button type="button" class="mt-4 text-blue-600 underline" onclick={ctx.link().callback(|_| Message::Load)}>{"Retry loading inclusions"}</button> }
        } else {
            html! { <p class="mt-4 text-gray-500">{"Loading inclusions…"}</p> }
        };
        html! {
            <section>
                <h1 class="text-2xl font-bold text-gray-900 mb-4">{"Inclusions"}</h1>
                <p class="text-gray-600">{"Enable inclusion-only mode to filter just the hosts listed below. Other hosts pass through without filtering or HTTPS interception. Turn it off to filter all hosts except exclusions."}</p>
                {error}
                {success}
                {contents}
            </section>
        }
    }
}
