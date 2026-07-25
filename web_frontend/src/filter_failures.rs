//! Notification panel for filter lists that fail to download or validate.
//!
//! Rendered at the top of the Filters page; hidden while every list is
//! healthy. Failing user-added lists can be edited (via the shared
//! [`FilterEditModal`]) or removed in place; built-in lists shipped with the
//! package can only be disabled.

use crate::button::{ButtonColor, ButtonState, PrivaxyButton};
use crate::filter_edit::FilterEditModal;
use crate::filters::{AddFilterRequest, FilterGroup, FilterStatusChangeRequest};
use crate::{failure_banner, ApiError};
use gloo_net::http::Request;
use gloo_timers::callback::Interval;
use serde::Deserialize;
use std::collections::HashSet;
use url::Url;
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;

const FILTER_FAILURES_RESOURCE_URL: &str = "/api/filters/failures";
const FILTERS_RESOURCE_URL: &str = "/api/filters";
const REFRESH_INTERVAL_MILLISECONDS: u32 = 30_000;

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct FilterFailure {
    pub file_name: String,
    pub title: String,
    pub url: String,
    pub group: FilterGroup,
    pub last_error: String,
    pub last_seen: String,
    pub count: u64,
    pub is_default: bool,
}

#[derive(Properties, PartialEq)]
pub struct Props {
    /// Emitted after a successful edit, removal or disable, so the
    /// surrounding page can reload its filter list.
    pub on_changed: Callback<()>,
}

pub enum Message {
    Refresh,
    Loaded(u64, Vec<FilterFailure>),
    LoadFailed(String),
    OpenEdit(FilterFailure),
    CloseEdit,
    EditCompleted,
    Remove(String),
    Disable(String),
    ActionSucceeded(String),
    ActionFailed(String, String),
    AcknowledgeError,
}

pub struct FilterFailuresPanel {
    failures: Vec<FilterFailure>,
    in_flight: HashSet<String>,
    error_message: Option<String>,
    editing: Option<FilterFailure>,
    /// Bumped on every successful edit/removal/disable; a refresh snapshot
    /// fetched under an older generation is stale (it may still contain the
    /// acted-on entry) and is dropped instead of resurrecting removed rows.
    refresh_generation: u64,
    _refresh_interval: Interval,
}

impl Component for FilterFailuresPanel {
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
            editing: None,
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
                    match Request::get(FILTER_FAILURES_RESOURCE_URL).send().await {
                        Ok(response) if response.ok() => {
                            match response.json::<Vec<FilterFailure>>().await {
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
                true
            }
            Message::LoadFailed(error) => {
                // The panel is a notification, not a page of its own; a
                // failed poll stays quiet instead of alarming the operator.
                log::error!("Failed to load filter failures: {error}");
                false
            }
            Message::OpenEdit(failure) => {
                self.editing = Some(failure);
                true
            }
            Message::CloseEdit => {
                self.editing = None;
                true
            }
            Message::EditCompleted => {
                if let Some(failure) = self.editing.take() {
                    self.failures
                        .retain(|entry| entry.file_name != failure.file_name);
                    self.refresh_generation += 1;
                    ctx.props().on_changed.emit(());
                }
                true
            }
            Message::Remove(file_name) => {
                let Some(failure) = self
                    .failures
                    .iter()
                    .find(|failure| failure.file_name == file_name)
                else {
                    return false;
                };
                let url = match Url::parse(&failure.url) {
                    Ok(url) => url,
                    Err(err) => {
                        self.error_message = Some(format!("Invalid URL: {err}"));
                        return true;
                    }
                };
                let request_body = AddFilterRequest::new(failure.title.clone(), failure.group, url);
                if !self.in_flight.insert(file_name.clone()) {
                    return false;
                }

                let link = ctx.link().clone();
                spawn_local(async move {
                    let request = Request::delete(FILTERS_RESOURCE_URL)
                        .header("Content-Type", "application/json")
                        .body(serde_json::to_string(&request_body).unwrap())
                        .unwrap();
                    report_action(request.send().await, file_name, &link).await;
                });
                true
            }
            Message::Disable(file_name) => {
                if !self.in_flight.insert(file_name.clone()) {
                    return false;
                }
                let request_body = vec![FilterStatusChangeRequest::new(file_name.clone(), false)];

                let link = ctx.link().clone();
                spawn_local(async move {
                    let request = Request::put(FILTERS_RESOURCE_URL)
                        .header("Content-Type", "application/json")
                        .body(serde_json::to_string(&request_body).unwrap())
                        .unwrap();
                    report_action(request.send().await, file_name, &link).await;
                });
                true
            }
            Message::ActionSucceeded(file_name) => {
                self.in_flight.remove(&file_name);
                self.failures
                    .retain(|failure| failure.file_name != file_name);
                self.refresh_generation += 1;
                ctx.props().on_changed.emit(());
                true
            }
            Message::ActionFailed(file_name, error) => {
                self.in_flight.remove(&file_name);
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
        if self.failures.is_empty() {
            return html! {};
        }

        let failure_banner = match &self.error_message {
            Some(message) => failure_banner!(
                true,
                ctx.link().callback(|_| Message::AcknowledgeError),
                message.clone()
            ),
            None => html! {},
        };

        let edit_modal = match &self.editing {
            Some(failure) => html! {
                <FilterEditModal
                    file_name={failure.file_name.clone()}
                    title={failure.title.clone()}
                    url={failure.url.clone()}
                    group={failure.group}
                    on_close={ctx.link().callback(|_| Message::CloseEdit)}
                    on_changed={ctx.link().callback(|_| Message::EditCompleted)} />
            },
            None => html! {},
        };

        let rows = self
            .failures
            .iter()
            .map(|failure| self.render_row(ctx, failure));

        let heading = if self.failures.len() == 1 {
            "A filter list is failing to update".to_string()
        } else {
            format!("{} filter lists are failing to update", self.failures.len())
        };

        html! {
            <>
                <div class="mb-8 rounded-md border border-red-300 bg-red-50 p-4">
                    <div class="flex items-center">
                        <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-red-600" fill="none"
                            viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                        </svg>
                        <h2 class="ml-2 text-lg font-medium text-red-800">{heading}</h2>
                    </div>
                    <p class="mt-2 text-sm text-red-700">
                        {"These lists could not be downloaded or no longer serve valid filter rules. \
                          Their previously downloaded rules stay active if a copy exists, but they will not receive updates. \
                          Edit an entry to fix its URL, or remove it. Built-in lists can only be disabled."}
                    </p>
                    { failure_banner }
                    <div class="mt-4 flex flex-col">
                        <div class="-my-2 overflow-x-auto sm:-mx-6 lg:-mx-8">
                            <div class="py-2 align-middle inline-block min-w-full sm:px-6 lg:px-8">
                                <div class="shadow overflow-hidden border-b border-gray-200 sm:rounded-lg">
                                    <table class="min-w-full divide-y divide-gray-200">
                                        <thead class="bg-gray-50">
                                            <tr>
                                                <th scope="col"
                                                    class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                    {"Filter list"}
                                                </th>
                                                <th scope="col"
                                                    class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                    {"Error"}
                                                </th>
                                                <th scope="col"
                                                    class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                    {"Last attempt"}
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
                </div>
                { edit_modal }
            </>
        }
    }
}

impl FilterFailuresPanel {
    fn render_row(&self, ctx: &Context<Self>, failure: &FilterFailure) -> Html {
        let is_in_flight = self.in_flight.contains(&failure.file_name);
        let state = |busy: bool| {
            if busy {
                ButtonState::Loading
            } else {
                ButtonState::Enabled
            }
        };

        let actions = if failure.is_default {
            // Built-in lists cannot be edited or removed (the backend
            // refuses); disabling resolves the failure until the package
            // ships a fixed URL.
            let on_disable = {
                let file_name = failure.file_name.clone();
                ctx.link()
                    .callback(move |_| Message::Disable(file_name.clone()))
            };
            html! {
                <div class="flex items-center space-x-2"
                    title="This list is built into Privaxy and cannot be edited or removed.">
                    <PrivaxyButton
                        state={state(is_in_flight)}
                        color={ButtonColor::Gray}
                        button_text={"Disable".to_string()}
                        onclick={on_disable} />
                </div>
            }
        } else {
            let on_edit = {
                let failure = failure.clone();
                ctx.link()
                    .callback(move |_| Message::OpenEdit(failure.clone()))
            };
            let on_remove = {
                let file_name = failure.file_name.clone();
                ctx.link()
                    .callback(move |_| Message::Remove(file_name.clone()))
            };
            html! {
                <div class="flex space-x-2">
                    <PrivaxyButton
                        state={state(is_in_flight)}
                        color={ButtonColor::Blue}
                        button_text={"Edit".to_string()}
                        onclick={on_edit} />
                    <PrivaxyButton
                        state={state(is_in_flight)}
                        color={ButtonColor::Red}
                        button_text={"Remove".to_string()}
                        onclick={on_remove} />
                </div>
            }
        };

        html! {
            <tr>
                <td class="px-6 py-4 text-sm text-gray-900">
                    <div>{&failure.title}</div>
                    <div class="font-mono text-xs text-gray-500 break-all">{&failure.url}</div>
                </td>
                <td class="px-6 py-4 text-sm text-gray-500">
                    <span title={failure.last_error.clone()}>{&failure.last_error}</span>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    <div>{&failure.last_seen}</div>
                    <div class="text-xs">
                        { if failure.count == 1 {
                            "1 failed attempt".to_string()
                        } else {
                            format!("{} failed attempts", failure.count)
                        }}
                    </div>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    { actions }
                </td>
            </tr>
        }
    }
}

async fn report_action(
    result: Result<gloo_net::http::Response, gloo_net::Error>,
    file_name: String,
    link: &yew::html::Scope<FilterFailuresPanel>,
) {
    match result {
        Ok(response) if response.ok() => {
            link.send_message(Message::ActionSucceeded(file_name));
        }
        Ok(response) => {
            let err = response.json::<ApiError>().await.unwrap_or(ApiError {
                error: format!("HTTP {}", response.status()),
            });
            link.send_message(Message::ActionFailed(file_name, err.error));
        }
        Err(err) => {
            link.send_message(Message::ActionFailed(file_name, format!("{err:?}")));
        }
    }
}
