use crate::logging::LogHandle;
use futures::{SinkExt, StreamExt};
use tokio::sync::broadcast::error::RecvError;
use warp::ws::{Message, WebSocket};

pub(super) async fn logs(websocket: WebSocket, log_handle: LogHandle) {
    let mut receiver = log_handle.sender.subscribe();

    let (mut tx, mut rx) = websocket.split();

    // To handle Ping / Pong messages
    tokio::spawn(async move { while let Some(_message) = rx.next().await {} });

    // Prime the client with recently retained records so the view isn't empty
    // until the next record is emitted.
    for entry in log_handle.backlog_snapshot() {
        let message = Message::text(serde_json::to_string(&entry).unwrap());

        if tx.send(message).await.is_err() {
            return;
        }
    }

    loop {
        match receiver.recv().await {
            Ok(entry) => {
                let message = Message::text(serde_json::to_string(&entry).unwrap());

                if tx.send(message).await.is_err() {
                    break;
                }
            }
            // The subscriber fell behind and the channel dropped records; keep
            // streaming from the most recent retained record.
            Err(RecvError::Lagged(_)) => continue,
            Err(RecvError::Closed) => break,
        }
    }
}
