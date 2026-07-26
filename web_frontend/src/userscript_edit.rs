//! Modal for editing or uninstalling a userscript.
//!
//! The body is fetched on open rather than passed in as a property: script
//! bodies are large and the list endpoint deliberately serves only metadata.

use crate::{failure_banner, ApiError};
use gloo_net::http::Request;
use serde::Serialize;
use wasm_bindgen_futures::spawn_local;
use web_sys::HtmlTextAreaElement;
use yew::prelude::*;

const USERSCRIPTS_RESOURCE_URL: &str = "/api/userscripts";

#[derive(Debug, Serialize)]
struct UpdateUserScriptRequest {
    file_name: String,
    body: String,
}

#[derive(Debug, Serialize)]
struct DeleteUserScriptRequest {
    file_name: String,
}

#[derive(Properties, PartialEq)]
pub struct Props {
    /// Identifies the script to the backend; stable across edits, including
    /// edits that change its `@name`.
    pub file_name: String,
    pub title: String,
    /// Emitted when the modal is dismissed without a change.
    pub on_close: Callback<()>,
    /// Emitted after a successful save or delete; the parent should unmount the
    /// modal and reload its script list.
    pub on_changed: Callback<()>,
}

pub enum Message {
    BodyLoaded(String),
    BodyChanged(String),
    Save,
    Delete,
    ConfirmDelete,
    CancelDelete,
    Succeeded,
    Failed(String),
    AcknowledgeError,
}

pub struct UserScriptEditModal {
    body: Option<String>,
    busy: bool,
    confirming_delete: bool,
    error: Option<String>,
}

impl Component for UserScriptEditModal {
    type Message = Message;
    type Properties = Props;

    fn create(ctx: &Context<Self>) -> Self {
        Self::fetch_body(ctx);

        Self {
            body: None,
            busy: false,
            confirming_delete: false,
            error: None,
        }
    }

    fn changed(&mut self, ctx: &Context<Self>, old_props: &Self::Properties) -> bool {
        // Re-fetch when the modal is pointed at a different script without
        // being unmounted in between.
        if ctx.props().file_name != old_props.file_name {
            self.body = None;
            self.busy = false;
            self.confirming_delete = false;
            self.error = None;
            Self::fetch_body(ctx);
        }
        true
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Message::BodyLoaded(body) => self.body = Some(body),
            Message::BodyChanged(body) => self.body = Some(body),
            Message::Save => {
                if self.busy {
                    return false;
                }
                let Some(body) = self.body.clone() else {
                    return false;
                };

                let request_body = serde_json::to_string(&UpdateUserScriptRequest {
                    file_name: ctx.props().file_name.clone(),
                    body,
                })
                .unwrap();

                self.dispatch(ctx, Request::patch(USERSCRIPTS_RESOURCE_URL), request_body);
            }
            Message::Delete => self.confirming_delete = true,
            Message::CancelDelete => self.confirming_delete = false,
            Message::ConfirmDelete => {
                if self.busy {
                    return false;
                }

                let request_body = serde_json::to_string(&DeleteUserScriptRequest {
                    file_name: ctx.props().file_name.clone(),
                })
                .unwrap();

                self.dispatch(ctx, Request::delete(USERSCRIPTS_RESOURCE_URL), request_body);
            }
            Message::Succeeded => {
                self.busy = false;
                ctx.props().on_changed.emit(());
            }
            Message::Failed(message) => {
                log::error!("Userscript edit failed: {message}");
                self.busy = false;
                self.confirming_delete = false;
                self.error = Some(message);
            }
            Message::AcknowledgeError => self.error = None,
        }

        true
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let on_body_input = ctx.link().callback(|event: InputEvent| {
            let textarea: HtmlTextAreaElement = event.target_unchecked_into();
            Message::BodyChanged(textarea.value())
        });

        let error_banner = match &self.error {
            Some(message) => failure_banner!(
                true,
                ctx.link().callback(|_| Message::AcknowledgeError),
                message.clone()
            ),
            None => html! {},
        };

        let body_editor = match &self.body {
            Some(body) => html! {
                <textarea rows="20"
                    class="mt-1 w-full font-mono text-xs bg-white border border-gray-300 text-gray-700 py-2 px-4 rounded leading-tight focus:outline-none focus:border-gray-500"
                    value={body.clone()} oninput={on_body_input} />
            },
            None => html! { <p class="text-gray-500 text-sm py-4">{ "Loading script..." }</p> },
        };

        html! {
            <div class="fixed inset-0 bg-gray-600 bg-opacity-75 flex items-center justify-center z-50">
                <div class="bg-white p-6 rounded-lg shadow-lg z-60 w-full max-w-3xl">
                    <h2 class="text-lg font-medium text-gray-900 mb-4">{ &ctx.props().title }</h2>
                    <div class="flex flex-col space-y-4">
                        { error_banner }
                        <div>
                            <label class="font-bold text-sm">{ "Script" }</label>
                            { body_editor }
                            <p class="text-gray-400 text-xs mt-1">
                                { "Saving re-reads the metadata block, so changes to " }
                                <span class="font-mono bg-gray-100 px-1">{ "@match" }</span>
                                { " or " }
                                <span class="font-mono bg-gray-100 px-1">{ "@name" }</span>
                                { " take effect on the next page load." }
                            </p>
                        </div>
                        { self.render_actions(ctx) }
                    </div>
                </div>
            </div>
        }
    }
}

impl UserScriptEditModal {
    fn fetch_body(ctx: &Context<Self>) {
        let link = ctx.link().clone();
        let file_name = ctx.props().file_name.clone();

        spawn_local(async move {
            let url = format!("{USERSCRIPTS_RESOURCE_URL}/{file_name}/body");
            match Request::get(&url).send().await {
                Ok(response) if response.ok() => match response.text().await {
                    Ok(body) => link.send_message(Message::BodyLoaded(body)),
                    Err(err) => link.send_message(Message::Failed(format!(
                        "Unable to read the script body: {err}"
                    ))),
                },
                Ok(response) => link.send_message(Message::Failed(format!(
                    "Unable to load the script body (HTTP {})",
                    response.status()
                ))),
                Err(err) => link.send_message(Message::Failed(format!("{err}"))),
            }
        });
    }

    /// Send a mutating request, mapping a non-2xx JSON body onto the error
    /// banner so validation failures (a script with no `@match`, say) are shown
    /// verbatim.
    fn dispatch(
        &mut self,
        ctx: &Context<Self>,
        builder: gloo_net::http::RequestBuilder,
        body: String,
    ) {
        self.busy = true;
        self.error = None;

        let link = ctx.link().clone();
        let request = builder
            .header("Content-Type", "application/json")
            .body(body)
            .unwrap();

        spawn_local(async move {
            match request.send().await {
                Ok(response) if response.ok() => link.send_message(Message::Succeeded),
                Ok(response) => {
                    let status = response.status();
                    let message = match response.json::<ApiError>().await {
                        Ok(api_error) => api_error.error,
                        Err(_) => format!("Request failed (HTTP {status})"),
                    };
                    link.send_message(Message::Failed(message));
                }
                Err(err) => link.send_message(Message::Failed(format!("{err}"))),
            }
        });
    }

    fn render_actions(&self, ctx: &Context<Self>) -> Html {
        if self.confirming_delete {
            return html! {
                <div class="flex items-center space-x-4">
                    <span class="text-sm text-gray-700">{ "Uninstall this userscript?" }</span>
                    <button onclick={ctx.link().callback(|_| Message::ConfirmDelete)}
                        disabled={self.busy}
                        class="bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-4 rounded z-60 disabled:opacity-50">
                        { "Uninstall" }
                    </button>
                    <button onclick={ctx.link().callback(|_| Message::CancelDelete)}
                        class="bg-gray-500 hover:bg-gray-700 text-white font-bold py-2 px-4 rounded z-60">
                        { "Keep" }
                    </button>
                </div>
            };
        }

        let on_close = ctx.props().on_close.clone();

        html! {
            <div class="flex space-x-4">
                <button onclick={ctx.link().callback(|_| Message::Save)}
                    disabled={self.busy || self.body.is_none()}
                    class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded z-60 disabled:opacity-50">
                    { if self.busy { "Saving..." } else { "Save" } }
                </button>
                <button onclick={Callback::from(move |_| on_close.emit(()))}
                    class="bg-gray-500 hover:bg-gray-700 text-white font-bold py-2 px-4 rounded z-60">
                    { "Cancel" }
                </button>
                <button onclick={ctx.link().callback(|_| Message::Delete)}
                    class="ml-auto text-red-600 hover:text-red-800 font-medium py-2 px-4 rounded z-60">
                    { "Uninstall" }
                </button>
            </div>
        }
    }
}
