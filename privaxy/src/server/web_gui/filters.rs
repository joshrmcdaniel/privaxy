use super::get_error_response;
use crate::configuration::{calc_filter_filename, Configuration, Filter, FilterGroup};
use crate::web_gui::ApiError;
use serde::Deserialize;
use serde_with::{serde_as, DisplayFromStr};

use std::{convert::Infallible, sync::Arc};
use tokio::sync::mpsc::Sender;
use url::Url;
use warp::http::Response;
use warp::Filter as RouteFilter;

use warp::filters::BoxedFilter;
#[derive(Debug, Deserialize)]
pub struct FilterStatusChangeRequest {
    enabled: bool,
    file_name: String,
}

#[serde_as]
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct FilterRequest {
    pub enabled: bool,
    pub title: String,
    pub group: FilterGroup,
    #[serde_as(as = "DisplayFromStr")]
    pub url: Url,
}

async fn change_filter_status(
    filter_status_change_request: Vec<FilterStatusChangeRequest>,
    configuration_updater_sender: Sender<Configuration>,
    configuration_save_lock: Arc<tokio::sync::Mutex<()>>,
) -> Result<impl warp::Reply, Infallible> {
    let mut configuration = match Configuration::read_from_home().await {
        Ok(configuration) => configuration,
        Err(err) => {
            log::error!("Failed to change filter status: {err}");
            return Ok(get_error_response(err));
        }
    };

    for filter in filter_status_change_request {
        if let Err(err) = configuration
            .set_filter_enabled_status(&filter.file_name, filter.enabled)
            .await
        {
            log::error!("Failed to change filter status: {err}");
            return Ok(get_error_response(err));
        }
    }
    let guard = configuration_save_lock.lock().await;

    configuration_updater_sender
        .send(configuration.clone())
        .await
        .unwrap();
    drop(guard);
    Ok(Response::builder()
        .status(http::StatusCode::ACCEPTED)
        .body("".to_string())
        .unwrap())
}

async fn get_filters_configuration() -> Result<impl warp::Reply, Infallible> {
    let configuration = match Configuration::read_from_home().await {
        Ok(configuration) => configuration,
        Err(err) => {
            log::error!("Failed to get filters configuration: {err}");
            return Ok(get_error_response(err));
        }
    };

    let filters = configuration.filters;
    log::debug!("Filters: {:?}", filters);
    Ok(Response::builder()
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(serde_json::to_string(&filters).unwrap())
        .unwrap())
}

async fn add_filter(
    filter_request: FilterRequest,
    http_client: reqwest_impersonate::Client,
    configuration_updater_sender: Sender<Configuration>,
    configuration_save_lock: Arc<tokio::sync::Mutex<()>>,
) -> Result<impl warp::Reply, Infallible> {
    // Read the current configuration
    let mut configuration = match Configuration::read_from_home().await {
        Ok(configuration) => configuration,
        Err(err) => {
            log::error!("Failed to read configuration: {err}");
            return Ok(get_error_response(err));
        }
    };

    // Clone the URL to avoid moving the original value
    let filter_url = filter_request.url.clone();
    if configuration
        .filters
        .iter()
        .any(|filter| filter.url == filter_request.url)
    {
        log::warn!("Filter with URL {} already exists", filter_request.url);
        return Ok(Response::builder()
            .status(http::StatusCode::CONFLICT)
            .body(
                serde_json::to_string(&ApiError {
                    error: format!("Filter with URL {} already exists", filter_request.url),
                })
                .unwrap(),
            )
            .unwrap());
    }

    // Add the new filter to the configuration
    let mut new_filter = Filter {
        enabled: filter_request.enabled,
        url: filter_url,
        title: filter_request.title.clone(),
        group: filter_request.group,
        file_name: calc_filter_filename(&filter_request.url.to_string()),
    };

    match configuration
        .add_filter(&mut new_filter, &http_client)
        .await
    {
        Ok(_) => {}
        Err(err) => {
            log::error!("Failed to add filter: {err}");
            return Ok(get_error_response(err));
        }
    }
    let guard = configuration_save_lock.lock().await;
    configuration_updater_sender
        .send(configuration.clone())
        .await
        .unwrap();
    drop(guard);
    // Save the updated configuration
    if let Err(err) = configuration.save().await {
        log::error!("Failed to save configuration: {err}");
        return Ok(get_error_response(err));
    }

    // Send the updated configuration to the updater
    if let Err(err) = configuration_updater_sender
        .send(configuration.clone())
        .await
    {
        log::error!("Failed to send updated configuration: {err}");
        return Ok(get_error_response(err));
    }

    Ok(Response::builder()
        .status(http::StatusCode::CREATED)
        .body("".to_string())
        .unwrap())
}

async fn delete_filter(
    filter_request: FilterRequest,
    configuration_updater_sender: Sender<Configuration>,
    configuration_save_lock: Arc<tokio::sync::Mutex<()>>,
) -> Result<impl warp::Reply, Infallible> {
    let _guard = configuration_save_lock.lock().await;

    let configuration = match Configuration::read_from_home().await {
        Ok(configuration) => configuration,
        Err(err) => {
            log::error!("Failed to read configuration: {err}");
            return Ok(get_error_response(err));
        }
    };

    let mut new_configuration = configuration.clone();
    new_configuration
        .filters
        .retain(|filter| filter.url != filter_request.url);

    if let Err(err) = new_configuration.save().await {
        log::error!("Failed to save configuration: {err}");
        return Ok(get_error_response(err));
    }

    if let Err(err) = configuration_updater_sender
        .send(new_configuration.clone())
        .await
    {
        log::error!("Failed to send updated configuration: {err}");
        return Ok(get_error_response(err));
    }
    Ok(Response::builder()
        .status(http::StatusCode::NO_CONTENT)
        .body("".to_string())
        .unwrap())
}

pub(super) fn create_routes(
    configuration_updater_sender: Sender<Configuration>,
    configuration_save_lock: Arc<tokio::sync::Mutex<()>>,
    http_client: reqwest_impersonate::Client,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::get()
        .and_then(self::get_filters_configuration)
        .or(warp::put()
            .and(warp::body::json())
            .and(super::with_configuration_updater_sender(
                configuration_updater_sender.clone(),
            ))
            .and(super::with_configuration_save_lock(
                configuration_save_lock.clone(),
            ))
            .and_then(self::change_filter_status))
        .or(warp::post()
            .and(warp::body::json())
            .and(super::with_http_client(http_client.clone()))
            .and(super::with_configuration_updater_sender(
                configuration_updater_sender.clone(),
            ))
            .and(super::with_configuration_save_lock(
                configuration_save_lock.clone(),
            ))
            .and_then(self::add_filter))
        .or(warp::delete()
            .and(warp::body::json())
            .and(super::with_configuration_updater_sender(
                configuration_updater_sender.clone(),
            ))
            .and(super::with_configuration_save_lock(
                configuration_save_lock.clone(),
            ))
            .and_then(self::delete_filter))
        .boxed()
}
