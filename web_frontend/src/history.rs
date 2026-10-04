use crate::button::{get_css, ButtonColor};
use crate::{api, statistics_settings::HistoryStatus};
use gloo_timers::callback::Interval;
use num_format::{Locale, ToFormattedString};
use serde::Deserialize;
use std::collections::BTreeMap;
use wasm_bindgen_futures::spawn_local;
use web_sys::HtmlSelectElement;
use yew::prelude::*;

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Counts {
    proxied_requests: u64,
    blocked_requests: u64,
    modified_responses: u64,
}

#[derive(Clone, Debug, Deserialize)]
struct Record {
    id: u64,
    timestamp: u64,
    domain: Option<String>,
    client: Option<String>,
    blocked: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Snapshot {
    status: HistoryStatus,
    totals: Counts,
    hourly: Vec<(u64, Counts)>,
    top_domains: Vec<(String, u64)>,
    top_blocked_domains: Vec<(String, u64)>,
    top_clients: Vec<(String, u64)>,
    requests: Vec<Record>,
    next_before: Option<u64>,
}

pub enum Message {
    Load,
    Poll,
    Loaded(u64, Result<Snapshot, String>),
    Hours(String),
    Filter(String),
    Older,
    Newest,
}

pub struct HistoryPage {
    snapshot: Option<Snapshot>,
    hours: u16,
    filter: String,
    before: Option<u64>,
    loading: bool,
    error: Option<String>,
    generation: u64,
    _interval: Interval,
}

impl Component for HistoryPage {
    type Message = Message;
    type Properties = ();
    fn create(ctx: &Context<Self>) -> Self {
        ctx.link().send_message(Message::Load);
        let link = ctx.link().clone();
        Self {
            snapshot: None,
            hours: 24,
            filter: String::new(),
            before: None,
            loading: false,
            error: None,
            generation: 0,
            _interval: Interval::new(30_000, move || link.send_message(Message::Poll)),
        }
    }

    fn update(&mut self, ctx: &Context<Self>, message: Message) -> bool {
        match message {
            Message::Poll if self.loading || self.before.is_some() => return false,
            Message::Load | Message::Poll => {
                self.load(ctx);
            }
            Message::Loaded(generation, result) => {
                if generation != self.generation {
                    return false;
                }
                self.loading = false;
                match result {
                    Ok(snapshot) => {
                        self.error = snapshot.status.error.clone();
                        self.snapshot = Some(snapshot);
                    }
                    Err(error) => self.error = Some(error),
                }
            }
            Message::Hours(hours) => {
                self.hours = hours.parse().unwrap_or(24);
                self.before = None;
                self.snapshot = None;
                self.load(ctx);
            }
            Message::Filter(filter) => {
                self.filter = filter;
                self.before = None;
                self.load(ctx);
            }
            Message::Older => {
                if self.loading {
                    return false;
                }
                self.before = self.snapshot.as_ref().and_then(|s| s.next_before);
                self.load(ctx);
            }
            Message::Newest => {
                self.before = None;
                self.load(ctx);
            }
        }
        true
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let on_hours = ctx.link().callback(|e: Event| {
            Message::Hours(e.target_unchecked_into::<HtmlSelectElement>().value())
        });
        let on_filter = ctx.link().callback(|e: Event| {
            Message::Filter(e.target_unchecked_into::<HtmlSelectElement>().value())
        });
        html! { <>
            <div class="flex flex-wrap justify-between items-center gap-3">
                <h1 class="text-2xl font-bold text-gray-900">{"History"}</h1>
                <div class="flex flex-wrap items-center gap-3">
                    <label for="history-range" class="text-sm text-gray-600">{"Time range"}</label>
                    <select id="history-range" class="rounded-md border-gray-300 text-sm" onchange={on_hours}>
                        {for [(24, "Last 24 hours"), (168, "Last 7 days"), (720, "Last 30 days"), (8760, "All retained history")].into_iter().map(|(hours, label)| html!{<option value={hours.to_string()} selected={self.hours == hours}>{label}</option>})}
                    </select>
                    <button type="button" disabled={self.loading} onclick={ctx.link().callback(|_| Message::Load)} class={classes!(get_css(ButtonColor::Gray), "disabled:opacity-50", "disabled:cursor-not-allowed")}>{"Refresh"}</button>
                    <a href="/settings/statistics" class={get_css(ButtonColor::Blue)}>{"Statistics settings"}</a>
                </div>
            </div>
            <p class="mt-3 text-sm text-gray-600">{"Saved statistics survive restarts. Totals and top lists cover retained requests in this window; the request filter and pagination only affect the log. Times are UTC. The latest page refreshes every 30 seconds."}</p>
            if let Some(error) = &self.error { <p role="alert" class="mt-4 text-red-700 text-sm">{format!("Could not load or save history: {error}")}</p> }
            if self.loading { <p role="status" class="mt-3 text-sm text-gray-500">{"Loading history…"}</p> }
            if let Some(snapshot) = &self.snapshot {
                if !snapshot.status.active && snapshot.status.error.is_none() {
                    <p role="status" class="mt-6 p-4 bg-white rounded-lg shadow text-gray-600">{"Persistent statistics are off or anonymous mode is selected. Enable history in Statistics settings to start collecting it."}</p>
                } else if snapshot.status.active {
                    if snapshot.status.dropped_events > 0 { <p role="alert" class="mt-4 text-sm text-amber-700">{format!("{} events were not saved this session; history is incomplete. Check Statistics settings for storage errors.", snapshot.status.dropped_events)}</p> }
                    <dl class="mt-5 grid grid-cols-1 sm:grid-cols-3 gap-4">
                        {for [("Proxied requests", snapshot.totals.proxied_requests), ("Blocked requests", snapshot.totals.blocked_requests), ("Modified responses", snapshot.totals.modified_responses)].into_iter().map(|(label, count)| html! {
                            <div class="p-5 bg-white rounded-lg shadow"><dt class="text-sm text-gray-600">{label}</dt><dd class="mt-2 text-2xl font-semibold text-blue-600">{count.to_formatted_string(&Locale::en)}</dd></div>
                        })}
                    </dl>
                    <div class="mt-5 p-5 bg-white rounded-lg shadow">
                        <h2 class="text-lg font-medium">{"Requests over time"}</h2>
                        {self.chart(snapshot)}
                    </div>
                    <div class="mt-5 grid grid-cols-1 lg:grid-cols-3 gap-4">
                        {top_list("Top domains", &snapshot.top_domains)}
                        {top_list("Top blocked domains", &snapshot.top_blocked_domains)}
                        {top_list("Top clients", &snapshot.top_clients)}
                    </div>
                    <div class="mt-5 p-4 sm:p-5 bg-white rounded-lg shadow">
                        <div class="flex flex-wrap justify-between items-center gap-3 mb-4">
                            <h2 class="text-lg font-medium">{"Request history"}</h2>
                            <select aria-label="Request history filter" class="rounded-md border-gray-300 text-sm" onchange={on_filter}>
                                <option value="" selected={self.filter.is_empty()}>{"All requests"}</option>
                                <option value="true" selected={self.filter == "true"}>{"Blocked only"}</option>
                                <option value="false" selected={self.filter == "false"}>{"Proxied only"}</option>
                            </select>
                        </div>
                        if snapshot.requests.is_empty() { <p class="py-4 text-sm text-gray-500">{"No saved requests in this window."}</p> }
                        <div class="overflow-x-auto">
                            <table class="w-full text-sm text-left" style="min-width: 640px">
                                <thead class="border-b text-gray-500"><tr><th scope="col" class="py-2 pr-4">{"Time (UTC)"}</th><th scope="col" class="pr-4">{"Domain"}</th><th scope="col" class="pr-4">{"Client"}</th><th scope="col">{"Result"}</th></tr></thead>
                                <tbody class="divide-y divide-gray-100">{for snapshot.requests.iter().map(|record| html! {
                                    <tr key={record.id}>
                                        <td class="py-3 pr-4 whitespace-nowrap text-gray-600">{timestamp(record.timestamp)}</td>
                                        <td class="pr-4 whitespace-nowrap">{record.domain.as_deref().unwrap_or("Hidden")}</td>
                                        <td class="pr-4 whitespace-nowrap">{record.client.as_deref().unwrap_or("Hidden")}</td>
                                        <td class={if record.blocked {"text-red-700"} else {"text-gray-700"}}>{if record.blocked {"Blocked"} else {"Proxied"}}</td>
                                    </tr>
                                })}</tbody>
                            </table>
                        </div>
                        <div class="flex justify-between gap-3 mt-4">
                            <button type="button" disabled={self.loading || self.before.is_none()} onclick={ctx.link().callback(|_| Message::Newest)} class="text-sm text-blue-600 underline disabled:opacity-50">{"Newest requests"}</button>
                            <button type="button" disabled={self.loading || snapshot.next_before.is_none()} onclick={ctx.link().callback(|_| Message::Older)} class="text-sm text-blue-600 underline disabled:opacity-50">{"Older requests"}</button>
                        </div>
                    </div>
                }
            }
        </> }
    }
}

impl HistoryPage {
    fn load(&mut self, ctx: &Context<Self>) {
        self.loading = true;
        self.error = None;
        self.generation += 1;
        let generation = self.generation;
        let mut url = format!("/api/history?hours={}&limit=50", self.hours);
        if let Some(before) = self.before {
            url.push_str(&format!("&before={before}"));
        }
        if !self.filter.is_empty() {
            url.push_str(&format!("&blocked={}", self.filter));
        }
        let link = ctx.link().clone();
        spawn_local(async move {
            link.send_message(Message::Loaded(generation, api::get_json(&url).await));
        });
    }

    fn chart(&self, snapshot: &Snapshot) -> Html {
        let bucket_ms = if self.hours <= 24 {
            3_600_000
        } else {
            86_400_000
        };
        let mut buckets = BTreeMap::<u64, (u64, u64)>::new();
        for (time, counts) in &snapshot.hourly {
            let bucket = buckets.entry(time / bucket_ms * bucket_ms).or_default();
            bucket.0 += counts.proxied_requests;
            bucket.1 += counts.blocked_requests;
        }
        if buckets.is_empty() {
            return html! {<p class="mt-4 text-sm text-gray-500">{"No saved activity yet."}</p>};
        }
        let now = js_sys::Date::now() as u64;
        let last = now / bucket_ms * bucket_ms;
        let first = if self.hours == 8760 {
            (*buckets.first_key_value().unwrap().0).min(last)
        } else {
            (now / 3_600_000 * 3_600_000).saturating_sub(u64::from(self.hours - 1) * 3_600_000)
                / bucket_ms
                * bucket_ms
        };
        let max = buckets
            .values()
            .map(|(p, b)| p + b)
            .max()
            .unwrap_or(1)
            .max(1) as f64;
        html! { <>
            <p class="mt-3 text-xs text-gray-500">{format!("Peak: {} requests per {}", max as u64, if self.hours <= 24 {"hour"} else {"day"})}</p>
            <div class="flex items-end h-40 mt-2 gap-px border-b border-gray-200" role="img" aria-label="Request counts over time. Blue is proxied; red is blocked.">
                {for (first..=last).step_by(bucket_ms as usize).map(|time| {
                    let (proxied, blocked) = buckets.get(&time).copied().unwrap_or_default();
                    let title = format!("{} UTC: {} proxied, {} blocked", timestamp(time), proxied, blocked);
                    html! {<div class="flex-1 min-w-0 flex flex-col justify-end h-full" title={title}>
                        <div class="bg-red-500" style={format!("height: {}%", blocked as f64 / max * 100.0)}></div>
                        <div class="bg-blue-500" style={format!("height: {}%", proxied as f64 / max * 100.0)}></div>
                    </div>}
                })}
            </div>
            <div class="flex flex-wrap justify-between gap-2 text-xs text-gray-500 mt-2"><span>{timestamp(first)}</span><span>{timestamp(last)}</span></div>
            <p class="text-xs text-gray-600 mt-3">{if self.hours <= 24 {"Hourly totals · Blue: proxied · Red: blocked"} else {"Daily totals · Blue: proxied · Red: blocked"}}</p>
        </> }
    }
}

fn top_list(title: &str, entries: &[(String, u64)]) -> Html {
    html! {<section class="p-5 bg-white rounded-lg shadow min-w-0">
        <h2 class="text-lg font-medium mb-3">{title}</h2>
        if entries.is_empty() {<p class="text-sm text-gray-500">{"No visible data at this privacy level or in this window."}</p>}
        <ol class="divide-y divide-gray-100">{for entries.iter().take(10).map(|(label, count)| html! {
            <li class="flex justify-between gap-3 py-2 text-sm"><span class="truncate" title={label.clone()}>{label}</span><span>{count.to_formatted_string(&Locale::en)}</span></li>
        })}</ol>
    </section>}
}

fn timestamp(value: u64) -> String {
    let iso = js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(value as f64))
        .to_iso_string()
        .as_string()
        .unwrap_or_default();
    iso.get(..19).unwrap_or(&iso).replace('T', " ")
}
