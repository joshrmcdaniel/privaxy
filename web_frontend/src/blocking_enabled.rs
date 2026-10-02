use crate::api;
use crate::button::{ButtonColor, ButtonState, PrivaxyButton};
use gloo_net::http::Request;
use wasm_bindgen_futures::spawn_local;
use yew::{html, Component, Context, Html};

pub struct BlockingEnabled {
    enabled: Option<bool>,
    busy: bool,
    error: Option<String>,
}

pub enum Message {
    Load,
    Toggle,
    Completed(Result<bool, String>),
}

impl Component for BlockingEnabled {
    type Message = Message;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        ctx.link().send_message(Message::Load);
        Self {
            enabled: None,
            busy: true,
            error: None,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Message) -> bool {
        match msg {
            Message::Load => {
                self.busy = true;
                self.error = None;
                let link = ctx.link().clone();
                spawn_local(async move {
                    link.send_message(Message::Completed(
                        api::get_json("/api/blocking-enabled").await,
                    ));
                });
            }
            Message::Toggle => {
                if self.busy {
                    return false;
                }
                let Some(enabled) = self.enabled.map(|enabled| !enabled) else {
                    return false;
                };
                self.busy = true;
                self.error = None;
                let link = ctx.link().clone();
                spawn_local(async move {
                    let result =
                        api::send_json(Request::put("/api/blocking-enabled"), &enabled).await;
                    link.send_message(Message::Completed(result.map(|()| enabled)));
                });
            }
            Message::Completed(result) => {
                self.busy = false;
                match result {
                    Ok(enabled) => self.enabled = Some(enabled),
                    Err(error) => {
                        self.error = Some(format!("Could not update blocking status: {error}"))
                    }
                }
            }
        }
        true
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let state = if self.busy {
            ButtonState::Loading
        } else {
            ButtonState::Enabled
        };
        let (color, button_text) = match self.enabled {
            Some(true) => (ButtonColor::Red, "Pause blocking"),
            Some(false) => (ButtonColor::Green, "Resume blocking"),
            None => (ButtonColor::Gray, "Retry blocking status"),
        };
        let loaded = self.enabled.is_some();
        html! {
            <div>
                <PrivaxyButton {state} {color} {button_text}
                    onclick={ctx.link().callback(move |_| if loaded { Message::Toggle } else { Message::Load })} />
                if let Some(error) = &self.error {
                    <p role="alert" class="mt-2 text-sm text-red-700">{error}</p>
                }
            </div>
        }
    }
}
