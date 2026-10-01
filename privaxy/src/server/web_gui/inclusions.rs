use super::{get_error_response, get_unprocessable_response};
use crate::{configuration::Configuration, proxy::exclusions::LocalExclusionStore};
use serde::{Deserialize, Serialize};
use std::{convert::Infallible, sync::Arc};
use tokio::sync::Mutex;
use warp::{filters::BoxedFilter, http::StatusCode, Filter};

#[derive(Deserialize, Serialize)]
struct InclusionSettings {
    include_only: bool,
    inclusions: Vec<String>,
}

async fn get_inclusions() -> Result<Box<dyn warp::Reply>, Infallible> {
    match Configuration::read_from_home().await {
        Ok(configuration) => Ok(Box::new(warp::reply::json(&InclusionSettings {
            include_only: configuration.include_only,
            inclusions: configuration.inclusions.into_iter().collect(),
        }))),
        Err(error) => Ok(Box::new(get_error_response(error))),
    }
}

async fn put_inclusions(
    settings: InclusionSettings,
    save_lock: Arc<Mutex<()>>,
    store: LocalExclusionStore,
) -> Result<Box<dyn warp::Reply>, Infallible> {
    let inclusions: Vec<String> = settings
        .inclusions
        .iter()
        .map(|host| host.trim().to_lowercase())
        .filter(|host| !host.is_empty())
        .collect();
    if inclusions
        .iter()
        .any(|host| host.chars().any(char::is_whitespace) || host.contains('/'))
    {
        return Ok(Box::new(get_unprocessable_response(
            "Use one hostname or wildcard pattern per entry, without a URL or path",
        )));
    }

    let _guard = save_lock.lock().await;
    let mut configuration = match Configuration::read_from_home().await {
        Ok(configuration) => configuration,
        Err(error) => return Ok(Box::new(get_error_response(error))),
    };
    configuration.include_only = settings.include_only;
    configuration.inclusions = inclusions.into_iter().collect();
    if let Err(error) = configuration.save().await {
        return Ok(Box::new(get_error_response(error)));
    }
    store.replace_configuration(&configuration);
    // No filter-engine rebuild or listener restart is needed. PAC requests
    // read the persisted configuration, and new proxy requests use this store.
    Ok(Box::new(StatusCode::ACCEPTED))
}

pub(super) fn create_routes(
    save_lock: Arc<Mutex<()>>,
    store: LocalExclusionStore,
) -> BoxedFilter<(impl warp::Reply,)> {
    let get = warp::path::end().and(warp::get()).and_then(get_inclusions);
    let put = warp::path::end()
        .and(warp::put())
        .and(warp::body::content_length_limit(1024 * 1024))
        .and(warp::body::json())
        .and(super::with_configuration_save_lock(save_lock))
        .and(super::with_local_exclusions_store(store))
        .and_then(put_inclusions);
    get.or(put).boxed()
}
