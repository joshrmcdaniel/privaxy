use super::{get_error_response, get_unprocessable_response};
use crate::{
    configuration::Configuration,
    proxy::exclusions::{recommended_exclusions, LocalExclusionStore},
};
use serde::Serialize;
use std::{convert::Infallible, sync::Arc};
use tokio::sync::mpsc::Sender;
use warp::filters::BoxedFilter;
use warp::http::StatusCode;
use warp::Filter as RouteFilter;

/// The body is a single JSON-encoded hostname; anything bigger is junk.
const ADD_BODY_LIMIT_BYTES: u64 = 4 * 1024;

#[derive(Debug, Serialize)]
struct AddExclusionResponse {
    added: bool,
}

async fn get_default_exclusions() -> Result<Box<dyn warp::Reply>, Infallible> {
    let defaults = recommended_exclusions().join("\n");
    Ok(Box::new(warp::reply::json(&defaults)))
}

async fn get_exclusions() -> Result<Box<dyn warp::Reply>, Infallible> {
    let configuration = match Configuration::read_from_home().await {
        Ok(configuration) => configuration,
        Err(err) => {
            log::error!("Failed to get exclusions: {err}");
            return Ok(Box::new(get_error_response(err)));
        }
    };

    let exclusions = Vec::from_iter(configuration.exclusions).join("\n");

    Ok(Box::new(warp::reply::json(&exclusions)))
}

async fn put_exclusions(
    exclusions: String,
    configuration_updater_sender: Sender<Configuration>,
    configuration_save_lock: Arc<tokio::sync::Mutex<()>>,
    local_exclusions_store: LocalExclusionStore,
) -> Result<Box<dyn warp::Reply>, Infallible> {
    let _guard = configuration_save_lock.lock().await;

    let mut configuration = match Configuration::read_from_home().await {
        Ok(configuration) => configuration,
        Err(err) => {
            log::error!("Failed to put exclusions: {err}");
            return Ok(Box::new(get_error_response(err)));
        }
    };

    if let Err(err) = configuration
        .set_exclusions(&exclusions, local_exclusions_store)
        .await
    {
        return Ok(Box::new(get_error_response(err)));
    }

    configuration_updater_sender
        .send(configuration.clone())
        .await
        .unwrap();

    Ok(Box::new(StatusCode::ACCEPTED))
}

/// Atomically add a single exclusion. Unlike `put_exclusions` (which replaces
/// the whole list from a client-held snapshot), the read-modify-write happens
/// entirely server-side under the save lock, so concurrent adds cannot lose
/// each other's entries.
async fn post_add_exclusion(
    host: String,
    configuration_updater_sender: Sender<Configuration>,
    configuration_save_lock: Arc<tokio::sync::Mutex<()>>,
    local_exclusions_store: LocalExclusionStore,
) -> Result<Box<dyn warp::Reply>, Infallible> {
    let host = host.trim().to_string();
    if host.is_empty() || host.chars().any(char::is_whitespace) {
        return Ok(Box::new(get_unprocessable_response("not a valid hostname")));
    }

    let _guard = configuration_save_lock.lock().await;

    let mut configuration = match Configuration::read_from_home().await {
        Ok(configuration) => configuration,
        Err(err) => {
            log::error!("Failed to add exclusion: {err}");
            return Ok(Box::new(get_error_response(err)));
        }
    };

    if configuration.exclusions.contains(&host) {
        return Ok(Box::new(warp::reply::json(&AddExclusionResponse {
            added: false,
        })));
    }

    // Reuse the whole-list write path so validation, persistence and the
    // exclusion-store refresh stay in one place.
    let mut exclusions = Vec::from_iter(configuration.exclusions.iter().cloned());
    exclusions.push(host);
    if let Err(err) = configuration
        .set_exclusions(&exclusions.join("\n"), local_exclusions_store)
        .await
    {
        return Ok(Box::new(get_error_response(err)));
    }

    configuration_updater_sender
        .send(configuration.clone())
        .await
        .unwrap();

    Ok(Box::new(warp::reply::json(&AddExclusionResponse {
        added: true,
    })))
}

pub fn create_routes(
    configuration_updater_sender: Sender<Configuration>,
    configuration_save_lock: Arc<tokio::sync::Mutex<()>>,
    local_exclusions_store: LocalExclusionStore,
) -> BoxedFilter<(impl warp::Reply,)> {
    let defaults_route = warp::path("defaults")
        .and(warp::path::end())
        .and(warp::get())
        .and_then(self::get_default_exclusions);

    let root_get = warp::path::end()
        .and(warp::get())
        .and_then(self::get_exclusions);

    let root_put = warp::path::end()
        .and(warp::put())
        .and(warp::body::json())
        .and(super::with_configuration_updater_sender(
            configuration_updater_sender.clone(),
        ))
        .and(super::with_configuration_save_lock(
            configuration_save_lock.clone(),
        ))
        .and(super::with_local_exclusions_store(
            local_exclusions_store.clone(),
        ))
        .and_then(self::put_exclusions);

    let add_post = warp::path("add")
        .and(warp::path::end())
        .and(warp::post())
        .and(warp::body::content_length_limit(ADD_BODY_LIMIT_BYTES))
        .and(warp::body::json::<String>())
        .and(super::with_configuration_updater_sender(
            configuration_updater_sender,
        ))
        .and(super::with_configuration_save_lock(configuration_save_lock))
        .and(super::with_local_exclusions_store(local_exclusions_store))
        .and_then(self::post_add_exclusion);

    defaults_route
        .or(root_get)
        .or(root_put)
        .or(add_post)
        .boxed()
}
