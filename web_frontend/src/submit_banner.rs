use yew::{classes, html, virtual_dom::VNode, Component, Context, Html, Properties};

pub struct SubmitBanner;

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum Color {
    Green,
    Red,
}

#[derive(Properties, PartialEq)]
pub struct Props {
    pub message: String,
    pub color: Color,
    pub icon: VNode,
}

impl Component for SubmitBanner {
    type Message = ();
    type Properties = Props;

    fn create(_ctx: &Context<Self>) -> Self {
        Self
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let props = ctx.props();

        let first_color = match props.color {
            Color::Green => "bg-green-500",
            Color::Red => "bg-red-500",
        };

        let second_color = match props.color {
            Color::Green => "bg-green-700",
            Color::Red => "bg-red-700",
        };

        html! {
            <div class={classes!("mb-5", "p-2", "rounded-lg", "shadow-lg", "sm:p-3", first_color)}>
                <div class="flex items-center justify-between flex-wrap">
                    <div class="w-0 flex-1 flex items-center">
                        <span class={classes!("flex", "p-2", "rounded-lg", second_color)}>
                            {props.icon.clone()}
                        </span>
                        <p class="ml-3 font-medium text-white truncate">
                            {&props.message}
                        </p>
                    </div>
                </div>
            </div>
        }
    }
}

#[macro_export]
macro_rules! info_icon {
    () => {
        html! {
            <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-white" fill="none"
                viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                    d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
        }
    };
}

#[macro_export]
macro_rules! success_banner {
    () => {
        html! {
            <crate::submit_banner::SubmitBanner message="Changes saved" icon={crate::info_icon!()} color={crate::submit_banner::Color::Green}/>
        }
    };
}

#[macro_export]
macro_rules! failure_banner {
    () => {
        html! {
            <crate::submit_banner::SubmitBanner message="Error saving changes" icon={crate::info_icon!()} color={crate::submit_banner::Color::Red}/>
        }
    };
    ($message:expr) => {
        html! {
            <crate::submit_banner::SubmitBanner message={$message} icon={crate::info_icon!()} color={crate::submit_banner::Color::Red}/>
        }
    };
}
