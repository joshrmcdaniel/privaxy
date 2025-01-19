use futures::{SinkExt, StreamExt};
use log;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use warp::ws::{Message, WebSocket};
use serde::Serialize;

use crate::metrics::{FilterMetrics, MemoryMetrics, PerformanceMetrics, MetricsCollector};

#[derive(Debug, Serialize)]
struct MetricsResponse {
    performance: PerformanceMetrics,
    filters: FilterMetrics,
    memory: MemoryMetrics,
}

pub(super) async fn metrics(websocket: WebSocket, metrics_collector: Arc<MetricsCollector>) {
    let (mut tx, mut rx) = websocket.split();

    // To handle Ping / Pong messages
    tokio::spawn(async move { while let Some(_message) = rx.next().await {} });

    let mut last_message = Message::text(serde_json::to_string(&MetricsResponse {
        performance: metrics_collector.get_performance_metrics(),
        filters: metrics_collector.get_filter_metrics(),
        memory: metrics_collector.get_memory_metrics(),
    }).unwrap());

    log::debug!("Initial metrics message: {:?}", last_message);

    let _result = tx.send(last_message.clone()).await;

    loop {
        let message = Message::text(serde_json::to_string(&MetricsResponse {
            performance: metrics_collector.get_performance_metrics(),
            filters: metrics_collector.get_filter_metrics(),
            memory: metrics_collector.get_memory_metrics(),
        }).unwrap());

        // Let's not send the same message over and over again.
        if message != last_message && tx.send(message.clone()).await.is_err() {
            break;
        }

        last_message = message;

        sleep(Duration::from_millis(500)).await;
    }
}
