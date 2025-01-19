use futures::future::{AbortHandle, Abortable};
use futures::StreamExt;
use gloo_timers::future::TimeoutFuture;
use num_format::{Locale, ToFormattedString};
use reqwasm::websocket::futures::WebSocket;
use serde::Deserialize;
use std::io::Cursor;
use wasm_bindgen_futures::spawn_local;
use yew::{html, Component, Context, Html};

/// Performance metrics for request processing and filter updates.
/// All time values are in milliseconds (ms).
#[derive(Debug, Deserialize, PartialEq)]
pub struct PerformanceMetrics {
    /// Average time to process a request (network + cosmetic)
    avg_request_time_ms: f64,
    /// Average time to process network requests
    avg_network_time_ms: f64,
    /// Average time to process cosmetic filters
    avg_cosmetic_time_ms: f64,
    /// Average time to update the filter engine
    avg_update_time_ms: f64,
    /// Exponential moving average of requests per second
    requests_per_second: f64,
}

/// Filter metrics tracking active filters and update statistics.
#[derive(Debug, Deserialize, PartialEq)]
pub struct FilterMetrics {
    /// Number of currently active filters
    active_filters: u64,
    /// Number of successful filter updates
    filter_updates: u64,
    /// Number of failed filter updates
    failed_updates: u64,
    /// Time taken for the last update in milliseconds
    last_update_time_ms: u64,
}

/// Memory usage metrics for the application.
/// All values are in kilobytes (KB).
#[derive(Debug, Deserialize, PartialEq)]
pub struct MemoryMetrics {
    /// Current memory usage of the process in KB
    current_usage_kb: u64,
    /// Peak memory usage of the process in KB
    peak_usage_kb: u64,
    /// Memory used by filter strings in KB
    filter_memory_kb: u64,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct Message {
    performance: PerformanceMetrics,
    filters: FilterMetrics,
    memory: MemoryMetrics,
}

pub struct Metrics {
    message: Message,
    ws_abort_handle: AbortHandle,
}

impl Component for Metrics {
    type Message = Message;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        let message_callback = ctx.link().callback(|message: Message| message);

        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        let future = Abortable::new(
            async move {
                loop {
                    let ws = match WebSocket::open("/api/metrics") {
                        Ok(ws) => ws,
                        Err(_err) => {
                            log::warn!("Unable to connect to metrics websocket, trying again.");
                            TimeoutFuture::new(1_000).await;
                            continue;
                        }
                    };

                    let (_write, mut read) = ws.split();

                    while let Some(result) = read.next().await {
                        match result {
                            Ok(msg) => {
                                let message = match msg {
                                    reqwasm::websocket::Message::Text(s) => {
                                        let cursor = Cursor::new(s.as_bytes());
                                        let mut deserializer =
                                            serde_json::Deserializer::from_reader(cursor)
                                                .into_iter::<Message>();

                                        match deserializer.next() {
                                            Some(Ok(message)) => message,
                                            Some(Err(e)) => {
                                                log::error!(
                                                    "Failed to deserialize metrics message: {:?}",
                                                    e
                                                );
                                                continue;
                                            }
                                            None => {
                                                log::warn!("No metrics message received");
                                                continue;
                                            }
                                        }
                                    }
                                    reqwasm::websocket::Message::Bytes(_) => unreachable!(),
                                };
                                message_callback.emit(message);
                            }
                            Err(e) => {
                                log::warn!("Metrics WebSocket error: {:?}", e);
                                break;
                            }
                        }
                    }
                    log::warn!("Lost connection to metrics websocket, trying again.");
                    TimeoutFuture::new(1_000).await;
                }
            },
            abort_registration,
        );

        spawn_local(async {
            let _result = future.await;
        });

        Self {
            ws_abort_handle: abort_handle,
            message: Message {
                performance: PerformanceMetrics {
                    avg_request_time_ms: 0.0,
                    avg_network_time_ms: 0.0,
                    avg_cosmetic_time_ms: 0.0,
                    avg_update_time_ms: 0.0,
                    requests_per_second: 0.0,
                },
                filters: FilterMetrics {
                    active_filters: 0,
                    filter_updates: 0,
                    failed_updates: 0,
                    last_update_time_ms: 0,
                },
                memory: MemoryMetrics {
                    current_usage_kb: 0,
                    peak_usage_kb: 0,
                    filter_memory_kb: 0,
                },
            },
        }
    }

    fn update(&mut self, _ctx: &Context<Self>, msg: Self::Message) -> bool {
        let update = self.message != msg;
        self.message = msg;
        update
    }

    fn view(&self, _ctx: &Context<Self>) -> Html {
        fn format_time(time: f64) -> String {
            format!("{:.2}ms", time)
        }

        fn format_memory(kb: u64) -> String {
            let mb = kb as f64 / 1024.0;
            if mb >= 1024.0 {
                format!("{:.2} GB", mb / 1024.0)
            } else if mb < 1.0 {
                format!("{:.0} KB", kb)
            } else {
                format!("{:.1} MB", mb)
            }
        }
        fn format_row(row_name: &str, row_val: String) -> Html {
            html! {
                <div class="flex justify-between">
                    <dt class="text-sm font-medium text-gray-500">{row_name}</dt>
                    <dd class="text-sm text-gray-900">{row_val}</dd>
                </div>
            }
        }

        html! {
            <>
                <div class="md:flex md:justify-between md:space-x-5">
                    <div class="pt-1.5">
                        <h1 class="text-2xl font-bold text-gray-900">{ "Metrics" }
                            <div class="mt-3 ml-3 inline pulsating-circle"></div>
                        </h1>
                    </div>
                </div>

                <div class="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
                    // Performance Metrics
                    <div class="bg-white overflow-hidden shadow rounded-lg divide-y divide-gray-200">
                        <div class="px-4 py-5 sm:px-6">
                            <h3 class="text-lg font-medium text-gray-900">{"Performance Metrics"}</h3>
                        </div>
                        <div class="px-4 py-5 sm:p-6">
                            <dl class="space-y-4">
                            {format_row("Average Request Time", format_time(self.message.performance.avg_request_time_ms))}
                            {format_row("Network Processing Time", format_time(self.message.performance.avg_network_time_ms))}
                            {format_row("Cosmetic Processing Time", format_time(self.message.performance.avg_cosmetic_time_ms))}
                            {format_row("Update Time", format_time(self.message.performance.avg_update_time_ms))}
                            {format_row("Requests per Second", format!("{:.1}", self.message.performance.requests_per_second))}
                            </dl>
                        </div>
                    </div>
                    // Filter Metrics
                    <div class="bg-white overflow-hidden shadow rounded-lg divide-y divide-gray-200">
                        <div class="px-4 py-5 sm:px-6">
                            <h3 class="text-lg font-medium text-gray-900">{"Filter Metrics"}</h3>
                        </div>
                        <div class="px-4 py-5 sm:p-6">
                            <dl class="space-y-4">
                            {format_row("Active Filters", self.message.filters.active_filters.to_formatted_string(&Locale::en))}
                            {format_row("Filter Updates", self.message.filters.filter_updates.to_formatted_string(&Locale::en))}
                            {format_row("Failed Updates", self.message.filters.failed_updates.to_formatted_string(&Locale::en))}
                            {format_row("Last Update Time", format_time(self.message.filters.last_update_time_ms as f64))}
                            </dl>
                        </div>
                    </div>

                    // Memory Metrics
                    <div class="bg-white overflow-hidden shadow rounded-lg divide-y divide-gray-200">
                        <div class="px-4 py-5 sm:px-6">
                            <h3 class="text-lg font-medium text-gray-900">{"Memory Metrics"}</h3>
                        </div>
                        <div class="px-4 py-5 sm:p-6">
                            <dl class="space-y-4">
                            {format_row("Current Memory Usage", format_memory(self.message.memory.current_usage_kb))}
                            {format_row("Peak Memory Usage", format_memory(self.message.memory.peak_usage_kb))}
                            {format_row("Filter Memory Usage", format_memory(self.message.memory.filter_memory_kb))}
                            </dl>
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
