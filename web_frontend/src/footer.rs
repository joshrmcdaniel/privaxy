use crate::api;
use futures::future::{AbortHandle, Abortable};
use gloo_timers::callback::Interval;
use serde::{de::DeserializeOwned, Deserialize};
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;

const UPDATE_CHECK_INTERVAL_MS: u32 = 60 * 60 * 1000;

#[derive(Deserialize)]
pub struct VersionInfo {
    version: String,
    project_url: String,
}

#[derive(Deserialize)]
struct ReleaseInfo {
    version: String,
    url: String,
}

#[derive(Deserialize)]
pub struct UpdateCheck {
    current_version: String,
    latest_release: Option<ReleaseInfo>,
    update_available: bool,
    checked_at: i64,
}

pub enum Message {
    LoadVersion,
    VersionLoaded(Result<VersionInfo, String>),
    Check,
    Checked(Result<UpdateCheck, String>),
}

pub struct Footer {
    version: Option<VersionInfo>,
    version_error: Option<String>,
    update: Option<UpdateCheck>,
    version_request: Option<AbortHandle>,
    update_request: Option<AbortHandle>,
    _update_interval: Interval,
}

impl Component for Footer {
    type Message = Message;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        ctx.link().send_message(Message::LoadVersion);
        let link = ctx.link().clone();
        Self {
            version: None,
            version_error: None,
            update: None,
            version_request: None,
            update_request: None,
            _update_interval: Interval::new(UPDATE_CHECK_INTERVAL_MS, move || {
                link.send_message(Message::Check);
            }),
        }
    }

    fn update(&mut self, ctx: &Context<Self>, message: Message) -> bool {
        match message {
            Message::LoadVersion => {
                if self.version_request.is_some() {
                    return false;
                }
                self.version_error = None;
                self.version_request = Some(fetch(
                    "/api/version",
                    ctx.link().callback(Message::VersionLoaded),
                ));
            }
            Message::VersionLoaded(result) => {
                self.version_request = None;
                match result {
                    Ok(version) => {
                        self.version = Some(version);
                        ctx.link().send_message(Message::Check);
                    }
                    Err(error) => self.version_error = Some(error),
                }
            }
            Message::Check => {
                if self.version.is_none() || self.update_request.is_some() {
                    return false;
                }
                self.update_request =
                    Some(fetch("/api/updates", ctx.link().callback(Message::Checked)));
                return false;
            }
            Message::Checked(result) => {
                self.update_request = None;
                let update = match result {
                    Ok(update) => update,
                    Err(error) => {
                        log::warn!("Automatic update check failed: {error}");
                        return false;
                    }
                };
                if let Some(version) = &mut self.version {
                    version.version.clone_from(&update.current_version);
                }
                self.update = Some(update);
            }
        }
        true
    }

    fn destroy(&mut self, _ctx: &Context<Self>) {
        for request in [&mut self.version_request, &mut self.update_request] {
            if let Some(request) = request.take() {
                request.abort();
            }
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        html! {
            <footer class="mt-auto border-t border-gray-200 bg-gray-50 text-sm text-gray-500">
                <div class="max-w-7xl mx-auto px-4 py-4 sm:px-6 lg:px-8 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                    <div class="flex flex-wrap items-center gap-x-4 gap-y-2">
                        if let Some(version) = &self.version {
                            <a href={version.project_url.clone()} target="_blank" rel="noopener noreferrer" class="text-blue-600 hover:underline">{format!("Privaxy v{}", version.version)}</a>
                        } else {
                            <span>{"Privaxy"}</span>
                            if let Some(error) = &self.version_error {
                                <span role="alert" title={error.clone()}>{"Version unavailable"}</span>
                                <button type="button" onclick={ctx.link().callback(|_| Message::LoadVersion)} class="text-blue-600 hover:underline">{"Retry version"}</button>
                            } else {
                                <span role="status">{"Loading version…"}</span>
                            }
                        }
                    </div>
                    {self.update_status()}
                </div>
            </footer>
        }
    }
}

impl Footer {
    fn update_status(&self) -> Html {
        let Some(update) = self
            .update
            .as_ref()
            .filter(|update| update.update_available)
        else {
            return Html::default();
        };
        let Some(release) = &update.latest_release else {
            return Html::default();
        };
        let checked = js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(
            update.checked_at as f64 * 1000.0,
        ))
        .to_iso_string()
        .as_string()
        .unwrap_or_default();
        let title = format!(
            "Privaxy v{} is available. Last checked: {checked}",
            release.version
        );
        html! {
            <div role="status" aria-live="polite">
                <a href={release.url.clone()} {title} target="_blank" rel="noopener noreferrer" class="font-medium text-blue-600 hover:underline">{"Update available"}</a>
            </div>
        }
    }
}

fn fetch<T: DeserializeOwned + 'static>(
    url: &'static str,
    callback: Callback<Result<T, String>>,
) -> AbortHandle {
    let (handle, registration) = AbortHandle::new_pair();
    spawn_local(async move {
        if let Ok(result) = Abortable::new(api::get_json(url), registration).await {
            callback.emit(result);
        }
    });
    handle
}
