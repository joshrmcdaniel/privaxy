use futures::future::{AbortHandle, Abortable};
use futures::StreamExt;
use gloo_net::websocket::{futures::WebSocket, Message, State};
use gloo_timers::future::TimeoutFuture;
use serde::de::DeserializeOwned;
use wasm_bindgen_futures::spawn_local;
use yew::Callback;

/// Reconnect live views after a server restart or network interruption. The
/// caller aborts this task when its component is destroyed.
pub fn subscribe<T: DeserializeOwned + 'static>(
    url: &'static str,
    on_message: Callback<T>,
    on_connection: Callback<bool>,
) -> AbortHandle {
    let (handle, registration) = AbortHandle::new_pair();
    let future = Abortable::new(
        async move {
            loop {
                if let Ok(mut ws) = WebSocket::open(url) {
                    while matches!(ws.state(), State::Connecting) {
                        TimeoutFuture::new(50).await;
                    }
                    if matches!(ws.state(), State::Open) {
                        on_connection.emit(true);
                    }
                    while let Some(result) = ws.next().await {
                        match result {
                            Ok(Message::Text(text)) => match serde_json::from_str(&text) {
                                Ok(message) => on_message.emit(message),
                                Err(error) => log::warn!("Invalid message from {url}: {error}"),
                            },
                            Ok(Message::Bytes(_)) => {
                                log::warn!("Ignoring binary message from {url}");
                            }
                            Err(error) => {
                                log::warn!("Live connection to {url} failed: {error}");
                                break;
                            }
                        }
                    }
                }
                on_connection.emit(false);
                TimeoutFuture::new(1_000).await;
            }
        },
        registration,
    );
    spawn_local(async move {
        let _ = future.await;
    });
    handle
}
