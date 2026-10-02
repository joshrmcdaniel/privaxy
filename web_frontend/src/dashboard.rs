use crate::blocking_enabled::BlockingEnabled;
use crate::live_stream;
use futures::future::AbortHandle;
use num_format::{Locale, ToFormattedString};
use serde::Deserialize;
use yew::{html, Component, Context, Html};

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct Statistics {
    proxied_requests: Option<u64>,
    blocked_requests: Option<u64>,
    modified_responses: Option<u64>,
    #[serde(with = "tuple_vec_map")]
    top_blocked_paths: Vec<(String, u64)>,
    #[serde(with = "tuple_vec_map")]
    top_clients: Vec<(String, u64)>,
}

pub enum Message {
    Received(Statistics),
    Connection(bool),
}

pub struct Dashboard {
    message: Statistics,
    connected: bool,
    ws_abort_handle: AbortHandle,
}

impl Component for Dashboard {
    type Message = Message;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        let abort_handle = live_stream::subscribe(
            "/api/statistics",
            ctx.link().callback(Message::Received),
            ctx.link().callback(Message::Connection),
        );

        Self {
            ws_abort_handle: abort_handle,
            connected: false,
            message: Statistics {
                proxied_requests: None,
                blocked_requests: None,
                modified_responses: None,
                top_blocked_paths: Vec::new(),
                top_clients: Vec::new(),
            },
        }
    }

    fn update(&mut self, _ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Message::Received(message) => {
                let changed = self.message != message;
                self.message = message;
                changed
            }
            Message::Connection(connected) => {
                self.connected = connected;
                true
            }
        }
    }

    fn view(&self, _ctx: &Context<Self>) -> Html {
        fn some_or_loading(s: Option<u64>) -> String {
            match s {
                Some(s) => s.to_formatted_string(&Locale::en),
                None => "Loading".to_string(),
            }
        }

        fn render_list_element(key: &str, count: u64) -> Html {
            html! {
            <li class="relative bg-white py-5 px-4">
                <div class="flex justify-between space-x-3">
                    <div class="min-w-0 flex-1">

                        <p class="text-sm font-medium text-gray-900 truncate">{ key }</p>
                    </div>
                    <div class="flex-shrink-0 whitespace-nowrap text-sm text-gray-500">{ count.to_formatted_string(&Locale::en) }</div>
                </div>
            </li>
                 }
        }

        html! {
            <>
                <div class="md:flex md:justify-between md:space-x-5">
                    <div class="pt-1.5">
                        <h1 class="text-2xl font-bold text-gray-900">{ "Dashboard" } if self.connected { <div class="mt-3 ml-3 inline pulsating-circle"></div> }
                        </h1>
                    </div>
                    <div
                        class="mt-6 flex flex-col-reverse justify-stretch space-y-4 space-y-reverse sm:flex-row-reverse sm:justify-end sm:space-x-reverse sm:space-y-0 sm:space-x-3 md:mt-0 md:flex-row md:space-x-3">
                        <a href="/api/settings/ca-certificate"
                        class="inline-flex items-center justify-center px-4 py-2 border border-gray-300 shadow-sm text-sm font-medium rounded-md text-white bg-gray-800 hover:bg-gray-900 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-gray-100 focus:ring-gray-500">
                        <svg xmlns="http://www.w3.org/2000/svg" class="ml-0.5 mr-2 h-5 w-5" fill="none"
                            viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                        </svg>
                        {"Download CA certificate"}
                    </a>
                        <BlockingEnabled />
                    </div>
                </div>

                if !self.connected {
                    <p role="status" class="mt-4 text-sm text-gray-600">{"Connecting to statistics… Retrying automatically. Displayed counts may be out of date."}</p>
                }
                <dl
                    class="mt-5 grid grid-cols-1 rounded-lg bg-white overflow-hidden shadow divide-y divide-gray-200 md:grid-cols-3 md:divide-y-0 md:divide-x">
                    <div class="px-4 py-5 sm:p-6">
                        <dt class="text-base font-normal text-gray-900">
                            {"Proxied requests"}
                        </dt>
                        <dd class="mt-1 flex justify-between items-baseline md:block lg:flex">
                            <div class="flex items-baseline text-2xl font-semibold text-blue-600">
                                { some_or_loading(self.message.proxied_requests) }
                            </div>
                        </dd>
                    </div>

                    <div class="px-4 py-5 sm:p-6">
                        <dt class="text-base font-normal text-gray-900">
                            {"Blocked requests"}
                        </dt>
                        <dd class="mt-1 flex justify-between items-baseline md:block lg:flex">
                            <div class="flex items-baseline text-2xl font-semibold text-blue-600">
                                { some_or_loading(self.message.blocked_requests) }
                            </div>
                        </dd>
                    </div>

                    <div class="px-4 py-5 sm:p-6">
                        <dt class="text-base font-normal text-gray-900">
                            {"Modified responses"}
                        </dt>
                        <dd class="mt-1 flex justify-between items-baseline md:block lg:flex">
                            <div class="flex items-baseline text-2xl font-semibold text-blue-600">
                                { some_or_loading(self.message.modified_responses) }
                            </div>
                        </dd>
                    </div>
                </dl>
                <div class="mt-4 lg:grid lg:gap-y-4 lg:gap-x-8 lg:grid-cols-2">
                    <div class="mt-4 bg-white overflow-hidden shadow rounded-lg divide-y divide-gray-200">
                        <div class="px-4 py-5 sm:px-6">
                            <h3 class="text-lg font-medium">{"Top blocked paths"}</h3>
                        </div>
                        <div class="px-4 py-5 sm:p-6">
                            <ol role="list" class="divide-y divide-gray-200">
                                { for self.message.top_blocked_paths.iter().map(|(path,
                                count)|render_list_element(path, *count)) }
                            </ol>

                        </div>
                    </div>
                    <div class="mt-4 bg-white overflow-hidden shadow rounded-lg divide-y divide-gray-200">
                        <div class="px-4 py-5 sm:px-6">
                            <h3 class="text-lg font-medium">{"Top clients"}</h3>
                        </div>
                        <div class="px-4 py-5 sm:p-6">
                            <ol role="list" class="divide-y divide-gray-200">
                                { for self.message.top_clients.iter().map(|(client,
                                count)|render_list_element(client, *count)) }
                            </ol>
                        </div>
                    </div>
                </div>
            </>
        }
    }

    fn destroy(&mut self, _ctx: &Context<Self>) {
        self.ws_abort_handle.abort()
    }
}
