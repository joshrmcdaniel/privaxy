use crate::button::{ButtonColor, ButtonState, PrivaxyButton};
use crate::exclude::add_exclusion_exact;
use crate::{failure_banner, ApiError};
use gloo_net::http::Request;
use gloo_timers::callback::Interval;
use serde::Deserialize;
use std::collections::HashSet;
use wasm_bindgen_futures::spawn_local;
use yew::{html, Callback, Component, Context, Html, Properties};

const TLS_FAILURES_RESOURCE_URL: &str = "/api/tls-failures";
const TLS_FAILURES_IGNORE_URL: &str = "/api/tls-failures/ignore";
const REFRESH_INTERVAL_MILLISECONDS: u32 = 30_000;

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct TlsFailure {
    pub host: String,
    pub last_seen: String,
    pub count: u64,
    pub likely_pinning: bool,
    pub last_error: String,
}

#[derive(Properties, PartialEq)]
pub struct Props {
    /// Emitted with the excluded host after a successful Exclude action.
    pub on_excluded: Callback<String>,
}

pub enum Message {
    Refresh,
    Loaded(u64, Vec<TlsFailure>),
    LoadFailed(String),
    Exclude(String),
    Ignore(String),
    Excluded(String),
    Ignored(String),
    ActionFailed(String, String),
    AcknowledgeError,
}

pub struct TlsFailuresPanel {
    failures: Vec<TlsFailure>,
    in_flight: HashSet<String>,
    error_message: Option<String>,
    load_failed: bool,
    /// Bumped on every successful Exclude/Ignore; a refresh snapshot fetched
    /// under an older generation is stale (it may still contain the acted-on
    /// host) and is dropped instead of resurrecting removed rows.
    refresh_generation: u64,
    _refresh_interval: Interval,
}

impl Component for TlsFailuresPanel {
    type Message = Message;
    type Properties = Props;

    fn create(ctx: &Context<Self>) -> Self {
        ctx.link().send_message(Message::Refresh);

        let link = ctx.link().clone();
        let refresh_interval = Interval::new(REFRESH_INTERVAL_MILLISECONDS, move || {
            link.send_message(Message::Refresh)
        });

        Self {
            failures: Vec::new(),
            in_flight: HashSet::new(),
            error_message: None,
            load_failed: false,
            refresh_generation: 0,
            _refresh_interval: refresh_interval,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Message::Refresh => {
                let link = ctx.link().clone();
                let generation = self.refresh_generation;
                spawn_local(async move {
                    match Request::get(TLS_FAILURES_RESOURCE_URL).send().await {
                        Ok(response) if response.ok() => {
                            match response.json::<Vec<TlsFailure>>().await {
                                Ok(failures) => {
                                    link.send_message(Message::Loaded(generation, failures))
                                }
                                Err(err) => {
                                    link.send_message(Message::LoadFailed(format!("{err:?}")))
                                }
                            }
                        }
                        Ok(response) => {
                            link.send_message(Message::LoadFailed(format!(
                                "HTTP {}",
                                response.status()
                            )));
                        }
                        Err(err) => {
                            link.send_message(Message::LoadFailed(format!("{err:?}")));
                        }
                    }
                });
                false
            }
            Message::Loaded(generation, failures) => {
                if generation != self.refresh_generation {
                    return false;
                }
                self.failures = failures;
                self.load_failed = false;
                true
            }
            Message::LoadFailed(error) => {
                log::error!("Failed to load TLS failures: {error}");
                self.load_failed = true;
                true
            }
            Message::Exclude(host) => {
                if !self.in_flight.insert(host.clone()) {
                    return false;
                }
                let link = ctx.link().clone();
                spawn_local(async move {
                    match add_exclusion_exact(host.clone()).await {
                        Ok(_) => link.send_message(Message::Excluded(host)),
                        Err(err) => link.send_message(Message::ActionFailed(host, err.error)),
                    }
                });
                true
            }
            Message::Ignore(host) => {
                if !self.in_flight.insert(host.clone()) {
                    return false;
                }
                let link = ctx.link().clone();
                spawn_local(async move {
                    let request = Request::post(TLS_FAILURES_IGNORE_URL)
                        .header("Content-Type", "application/json")
                        .body(serde_json::to_string(&host).unwrap())
                        .unwrap();
                    match request.send().await {
                        Ok(response) if response.ok() => link.send_message(Message::Ignored(host)),
                        Ok(response) => {
                            let err = response.json::<ApiError>().await.unwrap_or(ApiError {
                                error: format!("HTTP {}", response.status()),
                            });
                            link.send_message(Message::ActionFailed(host, err.error));
                        }
                        Err(err) => {
                            link.send_message(Message::ActionFailed(host, format!("{err:?}")));
                        }
                    }
                });
                true
            }
            Message::Excluded(host) => {
                self.in_flight.remove(&host);
                self.failures.retain(|failure| failure.host != host);
                self.refresh_generation += 1;
                ctx.props().on_excluded.emit(host);
                true
            }
            Message::Ignored(host) => {
                self.in_flight.remove(&host);
                self.failures.retain(|failure| failure.host != host);
                self.refresh_generation += 1;
                true
            }
            Message::ActionFailed(host, error) => {
                self.in_flight.remove(&host);
                self.error_message = Some(error);
                true
            }
            Message::AcknowledgeError => {
                self.error_message = None;
                true
            }
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let failure_banner = match &self.error_message {
            Some(message) => failure_banner!(
                true,
                ctx.link().callback(|_| Message::AcknowledgeError),
                message.clone()
            ),
            None => html! {},
        };

        let content = if self.failures.is_empty() {
            // A failed load must not masquerade as the reassuring empty
            // state — the difference matters when diagnosing a pinned app.
            if self.load_failed {
                html! {
                    <p class="mt-4 text-sm text-red-700">
                        {"Could not load TLS interception failures. Reload the page to retry."}
                    </p>
                }
            } else {
                html! {
                    <p class="mt-4 text-sm text-gray-500">{"No recent TLS interception failures."}</p>
                }
            }
        } else {
            let rows = self
                .failures
                .iter()
                .map(|failure| self.render_row(ctx, failure));

            html! {
                <div class="mt-4 flex flex-col">
                    <div class="-my-2 overflow-x-auto sm:-mx-6 lg:-mx-8">
                        <div class="py-2 align-middle inline-block min-w-full sm:px-6 lg:px-8">
                            <div class="shadow overflow-hidden border-b border-gray-200 sm:rounded-lg">
                                <table class="min-w-full divide-y divide-gray-200">
                                    <thead class="bg-gray-50">
                                        <tr>
                                            <th scope="col"
                                                class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                {"Host"}
                                            </th>
                                            <th scope="col"
                                                class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                {"Last seen"}
                                            </th>
                                            <th scope="col"
                                                class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                {"Count"}
                                            </th>
                                            <th scope="col"
                                                class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                {"Actions"}
                                            </th>
                                        </tr>
                                    </thead>
                                    <tbody class="w-full bg-white divide-y divide-gray-200">
                                        { for rows }
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            }
        };

        html! {
            <>
                <div class="pt-1.5 mb-4">
                    <h2 class="text-xl font-bold text-gray-900">{"Recent TLS interception failures"}</h2>
                </div>
                <p class="text-gray-600">
                    {"These hosts recently failed the TLS handshake while being intercepted, which often means they use certificate pinning. Excluding a host makes Privaxy tunnel it without inspection; ignoring it only hides it from this list."}
                </p>
                { failure_banner }
                { content }
            </>
        }
    }
}

impl TlsFailuresPanel {
    fn render_row(&self, ctx: &Context<Self>, failure: &TlsFailure) -> Html {
        let is_in_flight = self.in_flight.contains(&failure.host);
        let exclude_state = if is_in_flight {
            ButtonState::Loading
        } else {
            ButtonState::Enabled
        };
        let ignore_state = if is_in_flight {
            ButtonState::Loading
        } else {
            ButtonState::Enabled
        };

        let on_exclude = {
            let host = failure.host.clone();
            ctx.link().callback(move |_| Message::Exclude(host.clone()))
        };
        let on_ignore = {
            let host = failure.host.clone();
            ctx.link().callback(move |_| Message::Ignore(host.clone()))
        };

        let pinning_badge = if failure.likely_pinning {
            html! {
                <span class="ml-2 inline-flex items-center px-2.5 py-0.5 rounded-md text-xs font-medium bg-gray-100 text-gray-800"
                    title="This host appears to use certificate pinning: it only accepts its own certificates and rejects the ones Privaxy generates.">
                    {"pinning?"}
                </span>
            }
        } else {
            html! {}
        };

        html! {
            <tr>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    <span class="font-mono" title={failure.last_error.clone()}>{&failure.host}</span>
                    { pinning_badge }
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {&failure.last_seen}
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {failure.count.to_string()}
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    <div class="flex space-x-2">
                        <PrivaxyButton
                            state={exclude_state}
                            color={ButtonColor::Green}
                            button_text={"Exclude".to_string()}
                            onclick={on_exclude} />
                        <PrivaxyButton
                            state={ignore_state}
                            color={ButtonColor::Gray}
                            button_text={"Ignore".to_string()}
                            onclick={on_ignore} />
                    </div>
                </td>
            </tr>
        }
    }
}
