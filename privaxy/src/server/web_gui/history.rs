use super::{json_status, with_arc, with_configuration_save_lock};
use crate::{
    configuration::{Configuration, StatisticsConfig},
    statistics::{history::HistoryQuery, Statistics},
};
use http::StatusCode;
use serde::Serialize;
use std::{convert::Infallible, sync::Arc};
use warp::{filters::BoxedFilter, Filter, Reply};

#[derive(Serialize)]
struct SettingsResponse {
    config: StatisticsConfig,
    status: crate::statistics::history::HistoryStatus,
}

fn error(message: &str) -> Box<dyn Reply> {
    json_status(StatusCode::INTERNAL_SERVER_ERROR, message)
}

async fn get_settings(statistics: Statistics) -> Result<Box<dyn Reply>, Infallible> {
    let Some(history) = statistics.history else {
        return Ok(error("Statistics worker unavailable"));
    };
    Ok(match Configuration::read_from_home().await {
        Ok(configuration) => Box::new(warp::reply::json(&SettingsResponse {
            config: configuration.statistics,
            status: history.status(),
        })),
        Err(err) => error(&err.to_string()),
    })
}

async fn put_settings(
    config: StatisticsConfig,
    statistics: Statistics,
    lock: Arc<tokio::sync::Mutex<()>>,
) -> Result<Box<dyn Reply>, Infallible> {
    if let Err(message) = config.validate() {
        return Ok(json_status(StatusCode::UNPROCESSABLE_ENTITY, &message));
    }
    let _guard = lock.lock().await;
    let mut configuration = match Configuration::read_from_home().await {
        Ok(configuration) => configuration,
        Err(err) => return Ok(error(&err.to_string())),
    };
    configuration.statistics = config;
    if let Err(err) = configuration.save().await {
        return Ok(error(&err.to_string()));
    }
    // A saved opt-in and a working database are distinct; report disk errors
    // alongside the saved config. Saving again retries without proxy reloads.
    if let Err(err) = statistics.configure_history(configuration.statistics).await {
        log::error!("Could not apply statistics settings: {err}");
    }
    get_settings(statistics).await
}

async fn get_history(
    query: HistoryQuery,
    statistics: Statistics,
) -> Result<Box<dyn Reply>, Infallible> {
    if let Err(message) = query.validate() {
        return Ok(json_status(StatusCode::UNPROCESSABLE_ENTITY, &message));
    }
    let Some(history) = statistics.history else {
        return Ok(error("Statistics worker unavailable"));
    };
    Ok(match history.query(query).await {
        Ok(snapshot) => Box::new(warp::reply::json(&snapshot)),
        Err(err) => error(&err),
    })
}

async fn clear_history(
    statistics: Statistics,
    lock: Arc<tokio::sync::Mutex<()>>,
) -> Result<Box<dyn Reply>, Infallible> {
    let _guard = lock.lock().await;
    let Some(history) = statistics.history else {
        return Ok(error("Statistics worker unavailable"));
    };
    Ok(match history.clear().await {
        Ok(()) => Box::new(warp::reply::with_status("", StatusCode::NO_CONTENT)),
        Err(err) => error(&err),
    })
}

pub(super) fn settings_routes(
    statistics: Statistics,
    lock: Arc<tokio::sync::Mutex<()>>,
) -> BoxedFilter<(impl Reply,)> {
    let get = warp::get()
        .and(warp::path::end())
        .and(with_arc(statistics.clone()))
        .and_then(get_settings);
    let put = warp::put()
        .and(warp::path::end())
        .and(warp::body::content_length_limit(512 * 1024))
        .and(warp::body::json())
        .and(with_arc(statistics))
        .and(with_configuration_save_lock(lock))
        .and_then(put_settings);
    get.or(put).boxed()
}

pub(super) fn routes(
    statistics: Statistics,
    lock: Arc<tokio::sync::Mutex<()>>,
) -> BoxedFilter<(impl Reply,)> {
    let get = warp::get()
        .and(warp::path::end())
        .and(warp::query::<HistoryQuery>())
        .and(with_arc(statistics.clone()))
        .and_then(get_history);
    let delete = warp::delete()
        .and(warp::path::end())
        .and(with_arc(statistics))
        .and(with_configuration_save_lock(lock))
        .and_then(clear_history);
    get.or(delete).boxed()
}
