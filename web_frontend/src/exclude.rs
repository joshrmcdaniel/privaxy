use crate::auth::render_card;
use crate::button::{ButtonColor, ButtonState, PrivaxyButton};
use crate::{failure_banner, success_banner, ApiError, Route};
use gloo_net::http::Request;
use serde::Deserialize;
use wasm_bindgen_futures::spawn_local;
use yew::{html, Component, Context, Html};
use yew_router::prelude::*;

const EXCLUSIONS_ADD_URL: &str = "/api/exclusions/add";

pub(crate) enum AddOutcome {
    Added,
    AlreadyExcluded,
}

#[derive(Deserialize)]
struct AddExclusionResponse {
    added: bool,
}

/// Adds `host` to the exclusion list; no wildcard prefix is added. The append
/// happens server-side under the configuration save lock
/// (`POST /api/exclusions/add`), so concurrent adds — two panel rows, another
/// browser tab — cannot overwrite each other the way a client-side
/// GET-modify-PUT could. This is the single write path shared by
/// [`ExcludePage`] and the TLS failures panel.
pub(crate) async fn add_exclusion_exact(host: String) -> Result<AddOutcome, ApiError> {
    let host = host.trim().to_string();
    if host.is_empty() {
        return Err(ApiError {
            error: "No host provided".to_string(),
        });
    }

    let request = Request::post(EXCLUSIONS_ADD_URL)
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&host).unwrap())
        .unwrap();
    let response = request.send().await.map_err(|err| ApiError {
        error: format!("{err:?}"),
    })?;
    if !response.ok() {
        return Err(api_error_from_response(response).await);
    }

    let outcome = response
        .json::<AddExclusionResponse>()
        .await
        .map_err(|err| ApiError {
            error: format!("{err:?}"),
        })?;
    if outcome.added {
        Ok(AddOutcome::Added)
    } else {
        Ok(AddOutcome::AlreadyExcluded)
    }
}

async fn api_error_from_response(response: gloo_net::http::Response) -> ApiError {
    response.json::<ApiError>().await.unwrap_or(ApiError {
        error: format!("HTTP {}", response.status()),
    })
}

#[derive(Deserialize)]
struct ExcludeQuery {
    host: String,
}

#[derive(PartialEq, Eq)]
enum Status {
    Confirm,
    InFlight,
    AlreadyExcluded,
    Excluded,
}

pub enum Message {
    Submit,
    ExclusionAdded,
    HostAlreadyExcluded,
    ExclusionFailed(ApiError),
    AcknowledgeSuccess,
    AcknowledgeError,
}

pub struct ExcludePage {
    host: Option<String>,
    status: Status,
    show_success: bool,
    show_error: bool,
    error_message: String,
}

impl Component for ExcludePage {
    type Message = Message;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        let host = ctx
            .link()
            .location()
            .and_then(|location| location.query::<ExcludeQuery>().ok())
            .map(|query| query.host.trim().to_string())
            .filter(|host| !host.is_empty());

        Self {
            host,
            status: Status::Confirm,
            show_success: false,
            show_error: false,
            error_message: String::new(),
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Message::Submit => {
                if self.status == Status::InFlight {
                    return false;
                }
                let Some(host) = self.host.clone() else {
                    return false;
                };
                self.status = Status::InFlight;
                self.show_error = false;
                let link = ctx.link().clone();
                spawn_local(async move {
                    match add_exclusion_exact(host).await {
                        Ok(AddOutcome::Added) => link.send_message(Message::ExclusionAdded),
                        Ok(AddOutcome::AlreadyExcluded) => {
                            link.send_message(Message::HostAlreadyExcluded)
                        }
                        Err(err) => link.send_message(Message::ExclusionFailed(err)),
                    }
                });
            }
            Message::ExclusionAdded => {
                self.status = Status::Excluded;
                self.show_success = true;
            }
            Message::HostAlreadyExcluded => {
                self.status = Status::AlreadyExcluded;
            }
            Message::ExclusionFailed(err) => {
                self.status = Status::Confirm;
                self.show_error = true;
                self.error_message = err.error;
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
        let Some(host) = self.host.clone() else {
            return render_card(
                "Exclude host",
                html! {
                    <div class="text-gray-600 text-center">
                        <p>
                            {"No host was provided. Open this page from the proxy error page, or append "}
                            <span class="font-mono bg-gray-100 rounded-md">{"?host=example.com"}</span>
                            {" to the URL."}
                        </p>
                        { back_to_dashboard_link() }
                    </div>
                },
            );
        };

        match self.status {
            Status::Confirm | Status::InFlight => {
                let button_state = if self.status == Status::InFlight {
                    ButtonState::Loading
                } else {
                    ButtonState::Enabled
                };
                let onclick = ctx.link().callback(|_| Message::Submit);
                let failure_banner = if self.show_error {
                    failure_banner!(
                        true,
                        ctx.link().callback(|_| Message::AcknowledgeError),
                        self.error_message.clone()
                    )
                } else {
                    html! {}
                };

                render_card(
                    "Exclude host",
                    html! {
                        <>
                            { failure_banner }
                            <div class="text-gray-600">
                                <p>
                                    {"You are about to exclude "}
                                    <span class="font-mono bg-gray-100 rounded-md">{ host }</span>
                                    {" from Privaxy."}
                                </p>
                                <p class="mt-2">
                                    {"This host will bypass TLS interception and filtering."}
                                </p>
                            </div>
                            <div class="mt-6 flex justify-center">
                                <PrivaxyButton
                                    state={button_state}
                                    color={ButtonColor::Green}
                                    button_text={"Exclude this host".to_string()}
                                    {onclick} />
                            </div>
                        </>
                    },
                )
            }
            Status::AlreadyExcluded => render_card(
                "Already excluded",
                html! {
                    <div class="text-gray-600 text-center">
                        <p>
                            <span class="font-mono bg-gray-100 rounded-md">{ host }</span>
                            {" is already excluded. No changes were made."}
                        </p>
                        { back_to_dashboard_link() }
                    </div>
                },
            ),
            Status::Excluded => {
                let success_banner = if self.show_success {
                    success_banner!(true, ctx.link().callback(|_| Message::AcknowledgeSuccess))
                } else {
                    html! {}
                };

                render_card(
                    "Host excluded",
                    html! {
                        <>
                            { success_banner }
                            <div class="text-gray-600 text-center">
                                <p>
                                    <span class="font-mono bg-gray-100 rounded-md">{ host }</span>
                                    {" is now excluded. Privaxy will tunnel it without inspection. Reload the page that failed to load."}
                                </p>
                                { back_to_dashboard_link() }
                            </div>
                        </>
                    },
                )
            }
        }
    }
}

fn back_to_dashboard_link() -> Html {
    html! {
        <div class="mt-6">
            <Link<Route> classes="font-medium text-blue-600 hover:text-blue-500" to={Route::Dashboard}>
                {"Back to dashboard"}
            </Link<Route>>
        </div>
    }
}
