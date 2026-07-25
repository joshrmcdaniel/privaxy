//! Modal for editing or deleting a configured filter list.
//!
//! Shared between the Filters page (per-entry edit button) and the
//! filter-failures panel. Never rendered for built-in lists — the backend
//! refuses to edit or remove those.

use crate::button::{ButtonColor, ButtonState, PrivaxyButton};
use crate::filters::{AddFilterRequest, FilterGroup};
use crate::{failure_banner, ApiError};
use gloo_net::http::Request;
use serde::Serialize;
use serde_with::{serde_as, DisplayFromStr};
use url::Url;
use wasm_bindgen_futures::spawn_local;
use web_sys::{HtmlInputElement, HtmlSelectElement};
use yew::prelude::*;

const FILTERS_RESOURCE_URL: &str = "/api/filters";

#[serde_as]
#[derive(Debug, Clone, Serialize)]
struct UpdateFilterRequest {
    old_file_name: String,
    title: String,
    group: FilterGroup,
    #[serde_as(as = "DisplayFromStr")]
    url: Url,
}

#[derive(Properties, PartialEq)]
pub struct Props {
    /// File name of the entry being edited; identifies it to the backend
    /// even when the URL (and thus the derived file name) changes.
    pub file_name: String,
    pub title: String,
    pub url: String,
    pub group: FilterGroup,
    /// Emitted when the modal is dismissed without a change.
    pub on_close: Callback<()>,
    /// Emitted after a successful save or delete; the parent should unmount
    /// the modal and reload its filter data.
    pub on_changed: Callback<()>,
}

pub enum Message {
    TitleChanged(String),
    UrlChanged(String),
    GroupChanged(FilterGroup),
    Save,
    Delete,
    Succeeded,
    Failed(String),
    AcknowledgeError,
}

pub struct FilterEditModal {
    title: String,
    url: String,
    group: FilterGroup,
    busy: bool,
    error: Option<String>,
}

impl FilterEditModal {
    fn seed_from_props(props: &Props) -> (String, String, FilterGroup) {
        (props.title.clone(), props.url.clone(), props.group)
    }
}

impl Component for FilterEditModal {
    type Message = Message;
    type Properties = Props;

    fn create(ctx: &Context<Self>) -> Self {
        let (title, url, group) = Self::seed_from_props(ctx.props());
        Self {
            title,
            url,
            group,
            busy: false,
            error: None,
        }
    }

    fn changed(&mut self, ctx: &Context<Self>, old_props: &Self::Properties) -> bool {
        // Re-seed the form when the modal is switched to a different entry
        // without being unmounted in between.
        if ctx.props().file_name != old_props.file_name {
            let (title, url, group) = Self::seed_from_props(ctx.props());
            self.title = title;
            self.url = url;
            self.group = group;
            self.busy = false;
            self.error = None;
        }
        true
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Message::TitleChanged(title) => {
                self.title = title;
                true
            }
            Message::UrlChanged(url) => {
                self.url = url;
                true
            }
            Message::GroupChanged(group) => {
                self.group = group;
                true
            }
            Message::Save => {
                if self.busy {
                    return false;
                }
                let url = match Url::parse(&self.url) {
                    Ok(url) => url,
                    Err(err) => {
                        self.error = Some(format!("Invalid URL: {err}"));
                        return true;
                    }
                };
                let request_body = UpdateFilterRequest {
                    old_file_name: ctx.props().file_name.clone(),
                    title: if self.title.is_empty() {
                        self.url.clone()
                    } else {
                        self.title.clone()
                    },
                    group: self.group,
                    url,
                };
                self.busy = true;
                self.error = None;

                let link = ctx.link().clone();
                spawn_local(async move {
                    let request = Request::patch(FILTERS_RESOURCE_URL)
                        .header("Content-Type", "application/json")
                        .body(serde_json::to_string(&request_body).unwrap())
                        .unwrap();
                    send_and_report(request.send().await, &link).await;
                });
                true
            }
            Message::Delete => {
                if self.busy {
                    return false;
                }
                // Delete by the entry's original URL, not the (possibly
                // edited) form value.
                let url = match Url::parse(&ctx.props().url) {
                    Ok(url) => url,
                    Err(err) => {
                        self.error = Some(format!("Invalid URL: {err}"));
                        return true;
                    }
                };
                let request_body =
                    AddFilterRequest::new(ctx.props().title.clone(), ctx.props().group, url);
                self.busy = true;
                self.error = None;

                let link = ctx.link().clone();
                spawn_local(async move {
                    let request = Request::delete(FILTERS_RESOURCE_URL)
                        .header("Content-Type", "application/json")
                        .body(serde_json::to_string(&request_body).unwrap())
                        .unwrap();
                    send_and_report(request.send().await, &link).await;
                });
                true
            }
            Message::Succeeded => {
                self.busy = false;
                ctx.props().on_changed.emit(());
                true
            }
            Message::Failed(error) => {
                self.busy = false;
                self.error = Some(error);
                true
            }
            Message::AcknowledgeError => {
                self.error = None;
                true
            }
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let failure_banner = match &self.error {
            Some(message) => failure_banner!(
                true,
                ctx.link().callback(|_| Message::AcknowledgeError),
                message.clone()
            ),
            None => html! {},
        };

        let group = self.group;
        let options: Html = FilterGroup::values()
            .into_iter()
            .map(|option| {
                html! {
                    <option value={option.as_str()} selected={option == group}>
                        {option.as_str()}
                    </option>
                }
            })
            .collect();

        let action_state = if self.busy {
            ButtonState::Loading
        } else {
            ButtonState::Enabled
        };
        let cancel_state = if self.busy {
            ButtonState::Disabled
        } else {
            ButtonState::Enabled
        };
        let on_cancel = {
            let on_close = ctx.props().on_close.clone();
            Callback::from(move |_| on_close.emit(()))
        };

        html! {
            <div class="fixed inset-0 bg-gray-600 bg-opacity-75 flex items-center justify-center z-50">
                <div class="bg-white p-6 rounded-lg shadow-lg z-60 w-full max-w-xl">
                    <div class="flex flex-col space-y-4">
                        <h3 class="text-lg font-medium text-gray-900">{"Edit filter list"}</h3>
                        { failure_banner }
                        <div class="flex items-center">
                            <div class="w-32">
                                <label class="font-bold">{"Category"}</label>
                            </div>
                            <select class="flex-1 bg-white border border-gray-300 text-gray-700 py-2 px-4 pr-8 rounded leading-tight focus:outline-none focus:bg-white focus:border-gray-500"
                                onchange={ctx.link().callback(|e: Event| {
                                    let select = e.target_dyn_into::<HtmlSelectElement>().expect("event target should be a select element");
                                    let value = select.value();
                                    Message::GroupChanged(FilterGroup::values().into_iter().find(|group| group.as_str() == value).expect("invalid category"))
                                })}
                            >
                                { options }
                            </select>
                        </div>
                        <div class="flex items-center">
                            <div class="w-32">
                                <label class="font-bold">{"Title"}</label>
                            </div>
                            <input
                                type="text"
                                class="flex-1 bg-white border border-gray-300 text-gray-700 py-2 px-4 rounded leading-tight focus:outline-none focus:bg-white focus:border-gray-500"
                                value={self.title.clone()}
                                oninput={ctx.link().callback(|e: InputEvent| {
                                    let input = e.target_dyn_into::<HtmlInputElement>().expect("event target should be an input element");
                                    Message::TitleChanged(input.value())
                                })}
                            />
                        </div>
                        <div class="flex items-center">
                            <div class="w-32">
                                <label class="font-bold">{"EasyList URL"}</label>
                            </div>
                            <input
                                type="text"
                                class="flex-1 bg-white border border-gray-300 text-gray-700 py-2 px-4 rounded leading-tight focus:outline-none focus:bg-white focus:border-gray-500"
                                value={self.url.clone()}
                                oninput={ctx.link().callback(|e: InputEvent| {
                                    let input = e.target_dyn_into::<HtmlInputElement>().expect("event target should be an input element");
                                    Message::UrlChanged(input.value())
                                })}
                            />
                        </div>
                        <div class="flex space-x-4">
                            <PrivaxyButton
                                state={action_state}
                                color={ButtonColor::Blue}
                                button_text={"Save".to_string()}
                                onclick={ctx.link().callback(|_| Message::Save)} />
                            <PrivaxyButton
                                state={cancel_state}
                                color={ButtonColor::Gray}
                                button_text={"Cancel".to_string()}
                                onclick={on_cancel} />
                            <div class="ml-auto">
                                <PrivaxyButton
                                    state={if self.busy { ButtonState::Loading } else { ButtonState::Enabled }}
                                    color={ButtonColor::Red}
                                    button_text={"Delete".to_string()}
                                    onclick={ctx.link().callback(|_| Message::Delete)} />
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        }
    }
}

async fn send_and_report(
    result: Result<gloo_net::http::Response, gloo_net::Error>,
    link: &yew::html::Scope<FilterEditModal>,
) {
    match result {
        Ok(response) if response.ok() => link.send_message(Message::Succeeded),
        Ok(response) => {
            let err = response.json::<ApiError>().await.unwrap_or(ApiError {
                error: format!("HTTP {}", response.status()),
            });
            link.send_message(Message::Failed(err.error));
        }
        Err(err) => {
            link.send_message(Message::Failed(format!("{err:?}")));
        }
    }
}
