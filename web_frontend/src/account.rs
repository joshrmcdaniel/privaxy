use gloo_net::http::Request;
use serde::{Deserialize, Serialize};
use wasm_bindgen_futures::spawn_local;
use web_sys::{HtmlInputElement, SubmitEvent};
use yew::prelude::*;
use yew::{html, Callback, Component, Context, Html};

use crate::auth::AuthStatus;

#[derive(Serialize)]
struct ChangePasswordPayload {
    current_password: String,
    new_password: String,
}

#[derive(Deserialize)]
struct ApiKeyResponse {
    api_key: String,
}

pub enum Message {
    StatusLoaded(Option<String>),
    ApiKeyLoaded(String),
    UpdateCurrentPassword(String),
    UpdateNewPassword(String),
    UpdateConfirmPassword(String),
    SubmitPasswordChange,
    PasswordChangeSucceeded,
    PasswordChangeFailed(String),
    RotateApiKey,
    ApiKeyRotated(String),
    ApiKeyRotateFailed(String),
}

pub struct AccountSettings {
    username: Option<String>,
    api_key: Option<String>,
    current_password: String,
    new_password: String,
    confirm_password: String,
    password_error: Option<String>,
    password_success: bool,
    password_submitting: bool,
    api_key_error: Option<String>,
    api_key_busy: bool,
}

impl Component for AccountSettings {
    type Message = Message;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        let link = ctx.link().clone();
        spawn_local(async move {
            match Request::get("/api/auth/status").send().await {
                Ok(response) if response.ok() => {
                    if let Ok(status) = response.json::<AuthStatus>().await {
                        link.send_message(Message::StatusLoaded(status.username));
                    }
                }
                _ => link.send_message(Message::StatusLoaded(None)),
            }
        });

        let link = ctx.link().clone();
        spawn_local(async move {
            match Request::get("/api/auth/api-key").send().await {
                Ok(response) if response.ok() => {
                    if let Ok(payload) = response.json::<ApiKeyResponse>().await {
                        link.send_message(Message::ApiKeyLoaded(payload.api_key));
                    }
                }
                _ => {}
            }
        });

        Self {
            username: None,
            api_key: None,
            current_password: String::new(),
            new_password: String::new(),
            confirm_password: String::new(),
            password_error: None,
            password_success: false,
            password_submitting: false,
            api_key_error: None,
            api_key_busy: false,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Message::StatusLoaded(username) => {
                self.username = username;
                true
            }
            Message::ApiKeyLoaded(key) => {
                self.api_key = Some(key);
                true
            }
            Message::UpdateCurrentPassword(value) => {
                self.current_password = value;
                self.password_success = false;
                true
            }
            Message::UpdateNewPassword(value) => {
                self.new_password = value;
                self.password_success = false;
                true
            }
            Message::UpdateConfirmPassword(value) => {
                self.confirm_password = value;
                self.password_success = false;
                true
            }
            Message::SubmitPasswordChange => {
                if self.password_submitting {
                    return false;
                }
                if self.new_password.len() < 8 {
                    self.password_error =
                        Some("New password must be at least 8 characters".to_string());
                    return true;
                }
                if self.new_password != self.confirm_password {
                    self.password_error = Some("Passwords do not match".to_string());
                    return true;
                }
                self.password_submitting = true;
                self.password_error = None;
                let link = ctx.link().clone();
                let payload = ChangePasswordPayload {
                    current_password: self.current_password.clone(),
                    new_password: self.new_password.clone(),
                };
                spawn_local(async move {
                    match Request::post("/api/auth/change-password")
                        .header("Content-Type", "application/json")
                        .body(serde_json::to_string(&payload).unwrap())
                        .unwrap()
                        .send()
                        .await
                    {
                        Ok(response) if response.ok() => {
                            link.send_message(Message::PasswordChangeSucceeded);
                        }
                        Ok(response) => {
                            link.send_message(Message::PasswordChangeFailed(
                                parse_error(response).await,
                            ));
                        }
                        Err(err) => {
                            link.send_message(Message::PasswordChangeFailed(format!("{err}")));
                        }
                    }
                });
                true
            }
            Message::PasswordChangeSucceeded => {
                self.password_submitting = false;
                self.password_success = true;
                self.current_password = String::new();
                self.new_password = String::new();
                self.confirm_password = String::new();
                true
            }
            Message::PasswordChangeFailed(message) => {
                self.password_submitting = false;
                self.password_error = Some(message);
                true
            }
            Message::RotateApiKey => {
                if self.api_key_busy {
                    return false;
                }
                self.api_key_busy = true;
                self.api_key_error = None;
                let link = ctx.link().clone();
                spawn_local(async move {
                    match Request::post("/api/auth/rotate-api-key").send().await {
                        Ok(response) if response.ok() => {
                            if let Ok(payload) = response.json::<ApiKeyResponse>().await {
                                link.send_message(Message::ApiKeyRotated(payload.api_key));
                            } else {
                                link.send_message(Message::ApiKeyRotateFailed(
                                    "Could not parse response".to_string(),
                                ));
                            }
                        }
                        Ok(response) => {
                            link.send_message(Message::ApiKeyRotateFailed(
                                parse_error(response).await,
                            ));
                        }
                        Err(err) => {
                            link.send_message(Message::ApiKeyRotateFailed(format!("{err}")));
                        }
                    }
                });
                true
            }
            Message::ApiKeyRotated(key) => {
                self.api_key = Some(key);
                self.api_key_busy = false;
                true
            }
            Message::ApiKeyRotateFailed(message) => {
                self.api_key_error = Some(message);
                self.api_key_busy = false;
                true
            }
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = ctx.link();
        let on_current = link.callback(|e: InputEvent| {
            let input: HtmlInputElement = e.target_unchecked_into();
            Message::UpdateCurrentPassword(input.value())
        });
        let on_new = link.callback(|e: InputEvent| {
            let input: HtmlInputElement = e.target_unchecked_into();
            Message::UpdateNewPassword(input.value())
        });
        let on_confirm = link.callback(|e: InputEvent| {
            let input: HtmlInputElement = e.target_unchecked_into();
            Message::UpdateConfirmPassword(input.value())
        });
        let on_submit = link.callback(|e: SubmitEvent| {
            e.prevent_default();
            Message::SubmitPasswordChange
        });
        let on_rotate = link.callback(|_| Message::RotateApiKey);

        let username_display = self.username.clone().unwrap_or_else(|| "—".to_string());
        let api_key_display = self
            .api_key
            .clone()
            .unwrap_or_else(|| "Loading...".to_string());

        html! {
            <>
                <div class="pt-1.5 mb-4">
                    <h1 class="text-2xl font-bold text-gray-900">{ "Account" }</h1>
                </div>

                <fieldset class="mb-8">
                    <legend class="text-lg font-medium text-gray-900">{ "Signed in as" }</legend>
                    <div class="mt-2 border-t border-gray-200 pt-3 text-gray-700">
                        { username_display }
                    </div>
                </fieldset>

                <fieldset class="mb-8">
                    <legend class="text-lg font-medium text-gray-900">{ "Change password" }</legend>
                    <form onsubmit={on_submit} class="mt-4 max-w-md space-y-4">
                        { password_field("Current password", "current-password", &self.current_password, on_current) }
                        { password_field("New password", "new-password", &self.new_password, on_new) }
                        { password_field("Confirm new password", "new-password", &self.confirm_password, on_confirm) }
                        { if self.password_success {
                            html! { <div class="p-3 rounded bg-green-50 border border-green-200 text-sm text-green-700">{"Password updated."}</div> }
                        } else { html!{} } }
                        { if let Some(msg) = &self.password_error {
                            html! { <div class="p-3 rounded bg-red-50 border border-red-200 text-sm text-red-700">{msg.clone()}</div> }
                        } else { html!{} } }
                        <button
                            type="submit"
                            disabled={self.password_submitting}
                            class="inline-flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed">
                            { if self.password_submitting { "Updating..." } else { "Update password" } }
                        </button>
                    </form>
                </fieldset>

                <fieldset class="mb-8">
                    <legend class="text-lg font-medium text-gray-900">{ "API key" }</legend>
                    <p class="text-sm text-gray-500 mt-1">
                        { "Send this in the " }
                        <span class="font-mono bg-gray-100 px-1">{ "X-Api-Key" }</span>
                        { " header to authenticate API requests without a session cookie." }
                    </p>
                    <div class="mt-3 max-w-2xl">
                        <input
                            type="text"
                            readonly=true
                            value={api_key_display.clone()}
                            class="font-mono text-sm shadow-sm border rounded w-full py-2 px-3 text-gray-700 bg-gray-50"
                        />
                    </div>
                    { if let Some(msg) = &self.api_key_error {
                        html! { <div class="mt-3 p-3 rounded bg-red-50 border border-red-200 text-sm text-red-700">{msg.clone()}</div> }
                    } else { html!{} } }
                    <button
                        type="button"
                        onclick={on_rotate}
                        disabled={self.api_key_busy}
                        class="mt-3 inline-flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-red-600 hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 disabled:opacity-50 disabled:cursor-not-allowed">
                        { if self.api_key_busy { "Rotating..." } else { "Rotate API key" } }
                    </button>
                    <p class="text-xs text-gray-400 mt-2">
                        { "Rotating invalidates the previous key immediately." }
                    </p>
                </fieldset>
            </>
        }
    }
}

fn password_field(
    label: &str,
    autocomplete: &str,
    value: &str,
    oninput: Callback<InputEvent>,
) -> Html {
    let id = format!("account-{}", label.to_lowercase().replace(' ', "-"));
    html! {
        <div>
            <label for={id.clone()} class="block text-sm font-medium text-gray-700 mb-1">{label}</label>
            <input
                id={id}
                type="password"
                autocomplete={autocomplete.to_string()}
                value={value.to_string()}
                oninput={oninput}
                class="shadow-sm appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
        </div>
    }
}

async fn parse_error(response: gloo_net::http::Response) -> String {
    #[derive(Deserialize)]
    struct ApiError {
        error: String,
    }
    let status = response.status();
    match response.json::<ApiError>().await {
        Ok(payload) => payload.error,
        Err(_) => format!("Request failed ({status})"),
    }
}
