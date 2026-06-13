use gloo_net::http::Request;
use serde::{Deserialize, Serialize};
use wasm_bindgen_futures::spawn_local;
use web_sys::{HtmlInputElement, SubmitEvent};
use yew::prelude::*;
use yew::{html, Callback, Children, Component, Context, Html, Properties};

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct AuthStatus {
    pub authenticated: bool,
    pub setup_required: bool,
    pub username: Option<String>,
}

#[derive(Serialize)]
struct LoginPayload {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct SetupPayload {
    username: String,
    password: String,
}

#[derive(Debug, Clone, PartialEq)]
enum GateState {
    Loading,
    NeedsSetup,
    NeedsLogin,
    Authenticated(Option<String>),
}

pub enum GateMessage {
    LoadStatus,
    StatusLoaded(AuthStatus),
    StatusLoadFailed,
    SetupCompleted(String),
    LoginCompleted(String),
    LogoutCompleted,
}

#[derive(Properties, PartialEq)]
pub struct AuthGateProps {
    pub children: Children,
}

pub struct AuthGate {
    state: GateState,
}

impl Component for AuthGate {
    type Message = GateMessage;
    type Properties = AuthGateProps;

    fn create(ctx: &Context<Self>) -> Self {
        ctx.link().send_message(GateMessage::LoadStatus);
        Self {
            state: GateState::Loading,
        }
    }

    fn update(&mut self, _ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            GateMessage::LoadStatus => {
                self.state = GateState::Loading;
                let link = _ctx.link().clone();
                spawn_local(async move {
                    match fetch_status().await {
                        Some(status) => link.send_message(GateMessage::StatusLoaded(status)),
                        None => link.send_message(GateMessage::StatusLoadFailed),
                    }
                });
                true
            }
            GateMessage::StatusLoaded(status) => {
                self.state = if status.setup_required {
                    GateState::NeedsSetup
                } else if status.authenticated {
                    GateState::Authenticated(status.username)
                } else {
                    GateState::NeedsLogin
                };
                true
            }
            GateMessage::StatusLoadFailed => {
                self.state = GateState::NeedsLogin;
                true
            }
            GateMessage::SetupCompleted(username) => {
                self.state = GateState::Authenticated(Some(username));
                true
            }
            GateMessage::LoginCompleted(username) => {
                self.state = GateState::Authenticated(Some(username));
                true
            }
            GateMessage::LogoutCompleted => {
                self.state = GateState::NeedsLogin;
                true
            }
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        match &self.state {
            GateState::Loading => render_loading(),
            GateState::NeedsSetup => {
                let on_setup = ctx
                    .link()
                    .callback(|username: String| GateMessage::SetupCompleted(username));
                html! { <SetupPage {on_setup} /> }
            }
            GateState::NeedsLogin => {
                let on_login = ctx
                    .link()
                    .callback(|username: String| GateMessage::LoginCompleted(username));
                html! { <LoginPage {on_login} /> }
            }
            GateState::Authenticated(_) => {
                html! { <>{ for ctx.props().children.iter() }</> }
            }
        }
    }
}

async fn fetch_status() -> Option<AuthStatus> {
    let response = Request::get("/api/auth/status").send().await.ok()?;
    if !response.ok() {
        return None;
    }
    response.json::<AuthStatus>().await.ok()
}

pub async fn post_logout() -> bool {
    Request::post("/api/auth/logout")
        .send()
        .await
        .map(|r| r.ok() || r.status() == 401)
        .unwrap_or(false)
}

fn render_loading() -> Html {
    html! {
        <div class="min-h-screen flex items-center justify-center bg-gray-100">
            <div class="text-gray-500">{"Loading..."}</div>
        </div>
    }
}

#[derive(Properties, PartialEq)]
pub struct LoginProps {
    pub on_login: Callback<String>,
}

pub enum LoginMessage {
    UpdateUsername(String),
    UpdatePassword(String),
    Submit,
    Failed(String),
}

pub struct LoginPage {
    username: String,
    password: String,
    error: Option<String>,
    submitting: bool,
}

impl Component for LoginPage {
    type Message = LoginMessage;
    type Properties = LoginProps;

    fn create(_ctx: &Context<Self>) -> Self {
        Self {
            username: String::new(),
            password: String::new(),
            error: None,
            submitting: false,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            LoginMessage::UpdateUsername(value) => {
                self.username = value;
                true
            }
            LoginMessage::UpdatePassword(value) => {
                self.password = value;
                true
            }
            LoginMessage::Submit => {
                if self.submitting {
                    return false;
                }
                self.submitting = true;
                self.error = None;
                let link = ctx.link().clone();
                let on_login = ctx.props().on_login.clone();
                let payload = LoginPayload {
                    username: self.username.clone(),
                    password: self.password.clone(),
                };
                spawn_local(async move {
                    match Request::post("/api/auth/login")
                        .header("Content-Type", "application/json")
                        .body(serde_json::to_string(&payload).unwrap())
                        .unwrap()
                        .send()
                        .await
                    {
                        Ok(response) if response.ok() => {
                            on_login.emit(payload.username);
                        }
                        Ok(response) => {
                            let message = parse_error_message(response).await;
                            link.send_message(LoginMessage::Failed(message));
                        }
                        Err(err) => {
                            link.send_message(LoginMessage::Failed(format!("{err}")));
                        }
                    }
                });
                true
            }
            LoginMessage::Failed(message) => {
                self.submitting = false;
                self.error = Some(message);
                true
            }
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = ctx.link();
        let on_username = link.callback(|e: InputEvent| {
            let input: HtmlInputElement = e.target_unchecked_into();
            LoginMessage::UpdateUsername(input.value())
        });
        let on_password = link.callback(|e: InputEvent| {
            let input: HtmlInputElement = e.target_unchecked_into();
            LoginMessage::UpdatePassword(input.value())
        });
        let on_submit = link.callback(|e: SubmitEvent| {
            e.prevent_default();
            LoginMessage::Submit
        });

        render_card(
            "Sign in to Privaxy",
            html! {
                <form onsubmit={on_submit}>
                    {form_field("Username", "text", "username", &self.username, on_username)}
                    {form_field("Password", "password", "current-password", &self.password, on_password)}
                    {error_banner(&self.error)}
                    {primary_button("Sign in", self.submitting)}
                </form>
            },
        )
    }
}

#[derive(Properties, PartialEq)]
pub struct SetupProps {
    pub on_setup: Callback<String>,
}

pub enum SetupMessage {
    UpdateUsername(String),
    UpdatePassword(String),
    UpdateConfirm(String),
    Submit,
    Failed(String),
}

pub struct SetupPage {
    username: String,
    password: String,
    confirm: String,
    error: Option<String>,
    submitting: bool,
}

impl Component for SetupPage {
    type Message = SetupMessage;
    type Properties = SetupProps;

    fn create(_ctx: &Context<Self>) -> Self {
        Self {
            username: String::new(),
            password: String::new(),
            confirm: String::new(),
            error: None,
            submitting: false,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            SetupMessage::UpdateUsername(value) => {
                self.username = value;
                true
            }
            SetupMessage::UpdatePassword(value) => {
                self.password = value;
                true
            }
            SetupMessage::UpdateConfirm(value) => {
                self.confirm = value;
                true
            }
            SetupMessage::Submit => {
                if self.submitting {
                    return false;
                }
                if self.username.trim().is_empty() {
                    self.error = Some("Username is required".to_string());
                    return true;
                }
                if self.password.len() < 8 {
                    self.error = Some("Password must be at least 8 characters".to_string());
                    return true;
                }
                if self.password != self.confirm {
                    self.error = Some("Passwords do not match".to_string());
                    return true;
                }
                self.submitting = true;
                self.error = None;
                let link = ctx.link().clone();
                let on_setup = ctx.props().on_setup.clone();
                let payload = SetupPayload {
                    username: self.username.trim().to_string(),
                    password: self.password.clone(),
                };
                spawn_local(async move {
                    match Request::post("/api/auth/setup")
                        .header("Content-Type", "application/json")
                        .body(serde_json::to_string(&payload).unwrap())
                        .unwrap()
                        .send()
                        .await
                    {
                        Ok(response) if response.ok() => {
                            on_setup.emit(payload.username);
                        }
                        Ok(response) => {
                            let message = parse_error_message(response).await;
                            link.send_message(SetupMessage::Failed(message));
                        }
                        Err(err) => {
                            link.send_message(SetupMessage::Failed(format!("{err}")));
                        }
                    }
                });
                true
            }
            SetupMessage::Failed(message) => {
                self.submitting = false;
                self.error = Some(message);
                true
            }
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = ctx.link();
        let on_username = link.callback(|e: InputEvent| {
            let input: HtmlInputElement = e.target_unchecked_into();
            SetupMessage::UpdateUsername(input.value())
        });
        let on_password = link.callback(|e: InputEvent| {
            let input: HtmlInputElement = e.target_unchecked_into();
            SetupMessage::UpdatePassword(input.value())
        });
        let on_confirm = link.callback(|e: InputEvent| {
            let input: HtmlInputElement = e.target_unchecked_into();
            SetupMessage::UpdateConfirm(input.value())
        });
        let on_submit = link.callback(|e: SubmitEvent| {
            e.prevent_default();
            SetupMessage::Submit
        });

        let helper = html! {
            <p class="text-sm text-gray-500 mb-4">
                {"No account is configured yet. Create one to start using Privaxy."}
            </p>
        };

        render_card(
            "Set up your Privaxy account",
            html! {
                <form onsubmit={on_submit}>
                    {helper}
                    {form_field("Username", "text", "username", &self.username, on_username)}
                    {form_field("Password", "password", "new-password", &self.password, on_password)}
                    {form_field("Confirm password", "password", "new-password", &self.confirm, on_confirm)}
                    {error_banner(&self.error)}
                    {primary_button("Create account", self.submitting)}
                </form>
            },
        )
    }
}

async fn parse_error_message(response: gloo_net::http::Response) -> String {
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

fn render_card(title: &str, content: Html) -> Html {
    html! {
        <div class="min-h-screen flex items-center justify-center bg-gray-100 px-4">
            <div class="max-w-md w-full bg-white rounded-lg shadow p-8">
                <div class="flex items-center justify-center mb-6">
                    <img class="h-10 w-auto" src="/logo.svg" alt="Privaxy" />
                </div>
                <h1 class="text-xl font-semibold text-gray-900 text-center mb-6">{title}</h1>
                { content }
            </div>
        </div>
    }
}

fn form_field(
    label: &str,
    input_type: &str,
    autocomplete: &str,
    value: &str,
    oninput: Callback<InputEvent>,
) -> Html {
    let id = format!("auth-{}", label.to_lowercase().replace(' ', "-"));
    html! {
        <div class="mb-4">
            <label for={id.clone()} class="block text-sm font-medium text-gray-700 mb-1">{label}</label>
            <input
                id={id}
                type={input_type.to_string()}
                autocomplete={autocomplete.to_string()}
                value={value.to_string()}
                oninput={oninput}
                class="shadow-sm appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
        </div>
    }
}

fn error_banner(error: &Option<String>) -> Html {
    match error {
        Some(message) => html! {
            <div class="mb-4 p-3 rounded bg-red-50 border border-red-200 text-sm text-red-700">
                {message.clone()}
            </div>
        },
        None => html! {},
    }
}

fn primary_button(label: &str, busy: bool) -> Html {
    let mut classes = vec![
        "w-full",
        "inline-flex",
        "justify-center",
        "py-2",
        "px-4",
        "border",
        "border-transparent",
        "rounded-md",
        "shadow-sm",
        "text-sm",
        "font-medium",
        "text-white",
        "bg-blue-600",
        "hover:bg-blue-700",
        "focus:outline-none",
        "focus:ring-2",
        "focus:ring-offset-2",
        "focus:ring-blue-500",
    ];
    if busy {
        classes.push("opacity-50");
        classes.push("cursor-not-allowed");
    }
    html! {
        <button type="submit" class={classes.join(" ")} disabled={busy}>
            { if busy { "Working..." } else { label } }
        </button>
    }
}
