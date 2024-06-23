use web_sys::MouseEvent;
use yew::{classes, html, Callback, Classes, Component, Context, Html, Properties};

pub const BASE_BUTTON_CSS: [&'static str; 20] = [
    "inline-flex",
    "items-center",
    "justify-center",
    "px-4",
    "py-2",
    "border",
    "transition",
    "ease-in-out",
    "duration-150",
    "border-transparent",
    "text-sm",
    "text-sm",
    "font-medium",
    "rounded-md",
    "shadow-sm",
    "text-white",
    "focus:outline-none",
    "focus:ring-2",
    "focus:ring-offset-2",
    "focus:ring-offset-gray-100",
];

#[derive(PartialEq, Eq, Clone)]
pub(crate) enum ButtonColor {
    Blue,
    Green,
    Red,
    Gray,
}

#[derive(PartialEq, Eq)]
pub enum ButtonState {
    Loading,
    Enabled,
    Disabled,
}

pub struct PrivaxyButton;

fn get_color_class(color: ButtonColor) -> Classes {
    match color {
        ButtonColor::Blue => classes!("focus:ring-blue-500", "bg-blue-600", "hover:bg-blue-700"),
        ButtonColor::Green => {
            classes!("focus:ring-green-500", "bg-green-600", "hover:bg-green-700")
        }
        ButtonColor::Red => classes!("focus:ring-red-500", "bg-red-600", "hover:bg-red-700"),
        ButtonColor::Gray => classes!("focus:ring-gray-500", "bg-gray-600", "hover:bg-gray-700",),
    }
}

pub fn get_css(color: ButtonColor) -> Classes {
    classes!(get_color_class(color), BASE_BUTTON_CSS.clone().to_vec())
}

#[derive(Properties, PartialEq)]
pub struct Props {
    pub state: ButtonState,
    pub color: ButtonColor,
    pub button_text: String,
    pub onclick: Callback<MouseEvent>,
    pub children: Option<Html>,
}

impl Component for PrivaxyButton {
    type Message = ();
    type Properties = Props;

    fn create(_ctx: &Context<Self>) -> Self {
        Self
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let properties = ctx.props();
        let onclick = ctx.props().onclick.clone();
        let mut css = get_css(properties.color.clone());

        if properties.state == ButtonState::Disabled || properties.state == ButtonState::Loading {
            css.push("opacity-50");
            css.push("cursor-not-allowed");
        }
        let button_text = if properties.state == ButtonState::Loading {
            html! {
                <svg class="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
            }
        } else {
            html! {
                <span>{properties.button_text.clone()}</span>
            }
        };
        html! {
            <button
                class={css}
                onclick={onclick}
            >
            if let Some(children) = properties.children.clone() {
                {children}
            }
                {button_text}
            </button>
        }
    }
}

#[macro_export]
macro_rules! save_button {
    ($callback:expr) => {
        html! {
            <div class="mt-5">
            <crate::button::PrivaxyButton
                state={crate::button::ButtonState::Enabled}
                onclick={$callback}
                color={crate::button::ButtonColor::Green}
                button_text={"Save changes".to_string()}
                children={Some(html!{
                    <svg xmlns="http://www.w3.org/2000/svg" class="-ml-0.5 mr-2 h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4" />
                    </svg>
                })}
            />
            </div>
        }
    };
    ($callback:expr, $enabled:expr) => {
        html! {
            <div class="mt-5">
            <crate::button::PrivaxyButton
                state={$enabled}
                onclick={$callback}
                color={crate::button::ButtonColor::Green}
                button_text={"Save changes".to_string()}
                children={Some(html!{
                    <svg xmlns="http://www.w3.org/2000/svg" class="-ml-0.5 mr-2 h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4" />
                    </svg>
                })}
            />
            </div>
        }
    };
    ($callback:expr, $text:expr) => {
        html! {
            <div class="mt-5">
            <PrivaxyButton
                state={ButtonState::Enabled}
                onclick={$callback}
                color={ButtonColor::Green}
                button_text={$text.to_string()}
                children={Some(html!{
                    <svg xmlns="http://www.w3.org/2000/svg" class="-ml-0.5 mr-2 h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4" />
                    </svg>
                })}
            />
            </div>
        }
    };
}
