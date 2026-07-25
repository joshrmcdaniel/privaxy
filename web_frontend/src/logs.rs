use futures::future::{AbortHandle, Abortable};
use futures::StreamExt;
use gloo_net::websocket::futures::WebSocket;
use serde::Deserialize;
use wasm_bindgen_futures::spawn_local;
use web_sys::HtmlSelectElement;
use yew::{html, Component, Context, Html, TargetCast};

/// Upper bound on retained rows in the browser, mirroring the requests feed so
/// a long-running session can't grow unbounded.
const MAX_LOGS_SHOWN: usize = 1000;

/// Mirrors the backend `logging::LogEntry`.
#[derive(Deserialize, Clone, PartialEq)]
pub struct LogEntry {
    now: String,
    level: String,
    target: String,
    message: String,
}

impl LogEntry {
    /// Severity rank, lower is more severe. Unknown levels sort last so they
    /// are only hidden by the most permissive ("All") filter.
    fn severity(&self) -> u8 {
        match self.level.as_str() {
            "ERROR" => 0,
            "WARN" => 1,
            "INFO" => 2,
            "DEBUG" => 3,
            "TRACE" => 4,
            _ => 5,
        }
    }
}

/// Minimum severity selected in the level dropdown.
#[derive(Clone, Copy, PartialEq)]
pub enum LevelFilter {
    All,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LevelFilter {
    fn from_value(value: &str) -> Self {
        match value {
            "ERROR" => Self::Error,
            "WARN" => Self::Warn,
            "INFO" => Self::Info,
            "DEBUG" => Self::Debug,
            "TRACE" => Self::Trace,
            _ => Self::All,
        }
    }

    /// Highest severity rank still shown. `All` keeps everything, including
    /// unknown levels.
    fn max_rank(&self) -> u8 {
        match self {
            Self::All => u8::MAX,
            Self::Error => 0,
            Self::Warn => 1,
            Self::Info => 2,
            Self::Debug => 3,
            Self::Trace => 4,
        }
    }
}

pub enum Message {
    Received(LogEntry),
    SetFilter(LevelFilter),
    TogglePause,
    Clear,
}

pub struct LogStream {
    entries: Vec<LogEntry>,
    filter: LevelFilter,
    paused: bool,
    ws_abort_handle: AbortHandle,
}

impl Component for LogStream {
    type Message = Message;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        let message_callback = ctx.link().callback(Message::Received);

        let ws = WebSocket::open("/api/logs").unwrap();
        let (_write, mut read) = ws.split();

        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        let future = Abortable::new(
            async move {
                while let Some(Ok(msg)) = read.next().await {
                    let entry = match msg {
                        gloo_net::websocket::Message::Text(s) => {
                            serde_json::from_str::<LogEntry>(&s).unwrap()
                        }
                        gloo_net::websocket::Message::Bytes(_) => unreachable!(),
                    };

                    message_callback.emit(entry);
                }
            },
            abort_registration,
        );

        spawn_local(async {
            let _result = future.await;
        });

        Self {
            entries: Vec::new(),
            filter: LevelFilter::All,
            paused: false,
            ws_abort_handle: abort_handle,
        }
    }

    fn update(&mut self, _ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Message::Received(entry) => {
                // While paused the live view is frozen; incoming records are
                // dropped rather than buffered.
                if self.paused {
                    return false;
                }

                self.entries.insert(0, entry);
                self.entries.truncate(MAX_LOGS_SHOWN);
                true
            }
            Message::SetFilter(filter) => {
                self.filter = filter;
                true
            }
            Message::TogglePause => {
                self.paused = !self.paused;
                true
            }
            Message::Clear => {
                self.entries.clear();
                true
            }
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = ctx.link();

        let on_filter_change = link.callback(|e: yew::events::Event| {
            let select: HtmlSelectElement = e.target_unchecked_into();
            Message::SetFilter(LevelFilter::from_value(&select.value()))
        });
        let on_toggle_pause = link.callback(|_| Message::TogglePause);
        let on_clear = link.callback(|_| Message::Clear);

        let max_rank = self.filter.max_rank();
        let visible = self
            .entries
            .iter()
            .filter(|entry| entry.severity() <= max_rank);

        let pause_label = if self.paused { "Resume" } else { "Pause" };
        let pause_classes = if self.paused {
            "inline-flex items-center px-3 py-1.5 border border-transparent text-sm font-medium rounded-md text-white bg-green-600 hover:bg-green-700"
        } else {
            "inline-flex items-center px-3 py-1.5 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50"
        };

        html! {
            <fieldset class="mb-8" style="width: 100%;">
                <legend class="text-lg font-medium text-gray-900">
                    { "Live logs" }
                    if !self.paused {
                        <div class="mt-2 ml-3 inline pulsating-circle"></div>
                    }
                </legend>
                <p class="text-gray-400 text-sm mt-1 mb-3">
                    { "Streams the server's log output (controlled by " }
                    <span class="font-mono bg-gray-100 px-1">{ "RUST_LOG" }</span>
                    { "). Filtering and pausing are local to this view and don't affect what the server records." }
                </p>

                <div class="flex items-center space-x-3 mb-3">
                    <label class="text-sm text-gray-500">{ "Minimum level" }</label>
                    <select
                        onchange={on_filter_change}
                        class="block pl-3 pr-8 py-1.5 text-sm border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500">
                        <option value="ALL" selected={self.filter == LevelFilter::All}>{ "All" }</option>
                        <option value="ERROR" selected={self.filter == LevelFilter::Error}>{ "Error" }</option>
                        <option value="WARN" selected={self.filter == LevelFilter::Warn}>{ "Warn" }</option>
                        <option value="INFO" selected={self.filter == LevelFilter::Info}>{ "Info" }</option>
                        <option value="DEBUG" selected={self.filter == LevelFilter::Debug}>{ "Debug" }</option>
                        <option value="TRACE" selected={self.filter == LevelFilter::Trace}>{ "Trace" }</option>
                    </select>
                    <button type="button" onclick={on_toggle_pause} class={pause_classes}>
                        { pause_label }
                    </button>
                    <button
                        type="button"
                        onclick={on_clear}
                        class="inline-flex items-center px-3 py-1.5 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50">
                        { "Clear" }
                    </button>
                </div>

                <div class="bg-gray-900 rounded-md overflow-x-auto" style="max-height: 32rem; overflow-y: auto;">
                    <table class="min-w-full text-xs font-mono">
                        <tbody>
                            { for visible.map(Self::render_row) }
                        </tbody>
                    </table>
                </div>
            </fieldset>
        }
    }

    fn destroy(&mut self, _ctx: &Context<Self>) {
        self.ws_abort_handle.abort()
    }
}

impl LogStream {
    fn render_row(entry: &LogEntry) -> Html {
        let level_classes = match entry.level.as_str() {
            "ERROR" => "text-red-400",
            "WARN" => "text-yellow-400",
            "INFO" => "text-green-400",
            "DEBUG" => "text-blue-400",
            "TRACE" => "text-gray-400",
            _ => "text-gray-300",
        };

        html! {
            <tr class="border-b border-gray-800 align-top">
                <td class="px-3 py-1 whitespace-nowrap text-gray-500">{ &entry.now }</td>
                <td class={classes_for_level(level_classes)}>{ &entry.level }</td>
                <td class="px-3 py-1 whitespace-nowrap text-gray-400">{ &entry.target }</td>
                <td class="px-3 py-1 text-gray-200" style="word-break: break-word;">{ &entry.message }</td>
            </tr>
        }
    }
}

fn classes_for_level(level_classes: &str) -> String {
    format!("px-3 py-1 whitespace-nowrap font-semibold {level_classes}")
}
