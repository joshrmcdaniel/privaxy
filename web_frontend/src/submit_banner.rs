use gloo_timers::callback::Timeout;
use yew::{classes, html, Callback, Component, Context, Html, Properties};

pub struct SubmitBanner {
    hide_timeout: Option<Timeout>,
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum Color {
    Green,
    Red,
}

#[derive(Properties, PartialEq)]
pub struct Props {
    pub message: String,
    pub color: Color,
    pub icon: Html,
    pub visible: bool,
    pub on_hide: Callback<()>,
}

pub enum Msg {
    Hide,
}

impl Component for SubmitBanner {
    type Message = Msg;
    type Properties = Props;

    fn create(ctx: &Context<Self>) -> Self {
        let mut banner = Self { hide_timeout: None };

        if ctx.props().visible {
            banner.show(ctx);
        }

        banner
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Msg::Hide => {
                ctx.props().on_hide.emit(());
                true
            }
        }
    }

    fn changed(&mut self, ctx: &Context<Self>) -> bool {
        if ctx.props().visible {
            self.show(ctx);
        }
        true
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
            <div class={classes!(
                "mb-5", "p-2", "rounded-lg", "shadow-lg", "sm:p-3", "transition-opacity", "duration-1000",
                if props.visible { "opacity-100" } else { "opacity-0" },
                first_color
            )}>
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

impl SubmitBanner {
    fn show(&mut self, ctx: &Context<Self>) {
        let link = ctx.link().clone();
        self.hide_timeout = Some(Timeout::new(3000, move || {
            link.send_message(Msg::Hide);
        }));
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
    ($visible:expr, $on_hide:expr) => {
        html! {
            <crate::submit_banner::SubmitBanner message="Changes saved" icon={crate::info_icon!()} color={crate::submit_banner::Color::Green} visible={$visible} on_hide={$on_hide}/>
        }
    };
}

#[macro_export]
macro_rules! failure_banner {
    ($visible:expr, $on_hide:expr) => {
        html! {
            <crate::submit_banner::SubmitBanner message="Error saving changes" icon={crate::info_icon!()} color={crate::submit_banner::Color::Red} visible={$visible} on_hide={$on_hide}/>
        }
    };
    ($visible:expr, $on_hide:expr, $message:expr) => {
        html! {
            <crate::submit_banner::SubmitBanner message={$message} icon={crate::info_icon!()} color={crate::submit_banner::Color::Red} visible={$visible} on_hide={$on_hide}/>
        }
    };
}
