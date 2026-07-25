use super::get_error_response;
use crate::configuration::{
    calc_filter_filename, Configuration, ConfigurationError, DefaultFilters, Filter,
    FilterFailureEntry, FilterFailureStore, FilterGroup,
};
use crate::web_gui::ApiError;
use serde::{Deserialize, Serialize};
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

/// A configuration filter as served to the web UI, annotated with whether it
/// is one of the built-in lists shipped with the package (those can only be
/// enabled/disabled, never edited or removed).
#[derive(Debug, Serialize)]
struct FilterResponse {
    enabled: bool,
    title: String,
    group: FilterGroup,
    file_name: String,
    url: String,
    is_default: bool,
}

/// A filter failure as served to the web UI; `is_default` tells the frontend
/// to offer disabling instead of editing/removing.
#[derive(Debug, Serialize)]
struct FilterFailureResponse {
    #[serde(flatten)]
    entry: FilterFailureEntry,
    is_default: bool,
}

#[serde_as]
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct UpdateFilterRequest {
    /// File name of the configuration entry being edited; the stable
    /// identifier, since the URL (and therefore the derived file name) may be
    /// exactly what the edit changes.
    pub old_file_name: String,
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

    let default_file_names = DefaultFilters::new().file_names();
    let filters: Vec<FilterResponse> = configuration
        .filters
        .iter()
        .map(|filter| FilterResponse {
            enabled: filter.enabled,
            title: filter.title.clone(),
            group: filter.group,
            file_name: filter.file_name.clone(),
            url: filter.url.to_string(),
            is_default: default_file_names.contains(&filter.file_name),
        })
        .collect();
    log::debug!("Filters: {:?}", filters);
    Ok(Response::builder()
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(serde_json::to_string(&filters).unwrap())
        .unwrap())
}

async fn add_filter(
    filter_request: FilterRequest,
    http_client: reqwest::Client,
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
        file_name: calc_filter_filename(filter_request.url.as_ref()),
    };

    match configuration
        .add_filter(&mut new_filter, &http_client)
        .await
    {
        Ok(_) => {}
        Err(ConfigurationError::FilterValidationError(message)) => {
            log::warn!("Rejected invalid filter: {message}");
            return Ok(Response::builder()
                .status(http::StatusCode::UNPROCESSABLE_ENTITY)
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(serde_json::to_string(&ApiError { error: message }).unwrap())
                .unwrap());
        }
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
    filter_failure_store: FilterFailureStore,
) -> Result<impl warp::Reply, Infallible> {
    let _guard = configuration_save_lock.lock().await;

    let configuration = match Configuration::read_from_home().await {
        Ok(configuration) => configuration,
        Err(err) => {
            log::error!("Failed to read configuration: {err}");
            return Ok(get_error_response(err));
        }
    };

    let deleted_file_names: Vec<String> = configuration
        .filters
        .iter()
        .filter(|filter| filter.url == filter_request.url)
        .map(|filter| filter.file_name.clone())
        .collect();

    let default_file_names = DefaultFilters::new().file_names();
    if deleted_file_names
        .iter()
        .any(|file_name| default_file_names.contains(file_name))
    {
        log::warn!(
            "Refusing to remove built-in filter list {}",
            filter_request.url
        );
        return Ok(super::get_forbidden_response(
            "Built-in filter lists cannot be removed. Disable them instead.",
        ));
    }

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

    // A deleted filter can no longer fail to update; drop it from the
    // failure report immediately rather than waiting for the updater to
    // reconcile.
    for file_name in deleted_file_names {
        filter_failure_store.clear(&file_name);
    }

    Ok(Response::builder()
        .status(http::StatusCode::NO_CONTENT)
        .body("".to_string())
        .unwrap())
}

async fn update_filter(
    update_request: UpdateFilterRequest,
    http_client: reqwest::Client,
    configuration_updater_sender: Sender<Configuration>,
    configuration_save_lock: Arc<tokio::sync::Mutex<()>>,
    filter_failure_store: FilterFailureStore,
) -> Result<impl warp::Reply, Infallible> {
    if DefaultFilters::new()
        .file_names()
        .contains(&update_request.old_file_name)
    {
        log::warn!(
            "Refusing to edit built-in filter list {}",
            update_request.old_file_name
        );
        return Ok(super::get_forbidden_response(
            "Built-in filter lists cannot be edited. Disable them instead.",
        ));
    }

    let _guard = configuration_save_lock.lock().await;

    let mut configuration = match Configuration::read_from_home().await {
        Ok(configuration) => configuration,
        Err(err) => {
            log::error!("Failed to read configuration: {err}");
            return Ok(get_error_response(err));
        }
    };

    if configuration.filters.iter().any(|filter| {
        filter.file_name != update_request.old_file_name && filter.url == update_request.url
    }) {
        log::warn!("Filter with URL {} already exists", update_request.url);
        return Ok(Response::builder()
            .status(http::StatusCode::CONFLICT)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(
                serde_json::to_string(&ApiError {
                    error: format!("Filter with URL {} already exists", update_request.url),
                })
                .unwrap(),
            )
            .unwrap());
    }

    // `enabled` is a placeholder here; `replace_filter` carries over the
    // enabled status of the entry being replaced.
    let mut new_filter = Filter {
        enabled: true,
        title: update_request.title.clone(),
        group: update_request.group,
        file_name: calc_filter_filename(update_request.url.as_ref()),
        url: update_request.url.clone(),
    };

    if let Err(err) = configuration
        .replace_filter(&update_request.old_file_name, &mut new_filter, &http_client)
        .await
    {
        let message = match err {
            ConfigurationError::FilterValidationError(message)
            | ConfigurationError::FilterError(message) => message,
            ConfigurationError::UnableToRetrieveDefaultFilters(err) => {
                format!("Failed to fetch the filter list: {err}")
            }
            err => {
                log::error!("Failed to update filter: {err}");
                return Ok(get_error_response(err));
            }
        };
        log::warn!("Rejected filter edit: {message}");
        return Ok(Response::builder()
            .status(http::StatusCode::UNPROCESSABLE_ENTITY)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(serde_json::to_string(&ApiError { error: message }).unwrap())
            .unwrap());
    }

    if let Err(err) = configuration.save().await {
        log::error!("Failed to save configuration: {err}");
        return Ok(get_error_response(err));
    }

    if let Err(err) = configuration_updater_sender
        .send(configuration.clone())
        .await
    {
        log::error!("Failed to send updated configuration: {err}");
        return Ok(get_error_response(err));
    }

    // The replacement was just validated against its URL, so the old entry's
    // failure record is resolved regardless of whether the URL changed.
    filter_failure_store.clear(&update_request.old_file_name);

    Ok(Response::builder()
        .status(http::StatusCode::OK)
        .body("".to_string())
        .unwrap())
}

async fn get_filter_failures(
    filter_failure_store: FilterFailureStore,
) -> Result<impl warp::Reply, Infallible> {
    let default_file_names = DefaultFilters::new().file_names();
    let failures: Vec<FilterFailureResponse> = filter_failure_store
        .entries()
        .into_iter()
        .map(|entry| FilterFailureResponse {
            is_default: default_file_names.contains(&entry.file_name),
            entry,
        })
        .collect();
    Ok(warp::reply::json(&failures))
}

pub(super) fn create_routes(
    configuration_updater_sender: Sender<Configuration>,
    configuration_save_lock: Arc<tokio::sync::Mutex<()>>,
    http_client: reqwest::Client,
    filter_failure_store: FilterFailureStore,
) -> BoxedFilter<(impl warp::Reply,)> {
    let failures_route = warp::path("failures")
        .and(warp::path::end())
        .and(warp::get())
        .and(super::with_arc(filter_failure_store.clone()))
        .and_then(self::get_filter_failures);

    failures_route
        .or(warp::path::end()
            .and(warp::get())
            .and_then(self::get_filters_configuration))
        .or(warp::path::end()
            .and(warp::put())
            .and(warp::body::json())
            .and(super::with_configuration_updater_sender(
                configuration_updater_sender.clone(),
            ))
            .and(super::with_configuration_save_lock(
                configuration_save_lock.clone(),
            ))
            .and_then(self::change_filter_status))
        .or(warp::path::end()
            .and(warp::post())
            .and(warp::body::json())
            .and(super::with_http_client(http_client.clone()))
            .and(super::with_configuration_updater_sender(
                configuration_updater_sender.clone(),
            ))
            .and(super::with_configuration_save_lock(
                configuration_save_lock.clone(),
            ))
            .and_then(self::add_filter))
        .or(warp::path::end()
            .and(warp::patch())
            .and(warp::body::json())
            .and(super::with_http_client(http_client))
            .and(super::with_configuration_updater_sender(
                configuration_updater_sender.clone(),
            ))
            .and(super::with_configuration_save_lock(
                configuration_save_lock.clone(),
            ))
            .and(super::with_arc(filter_failure_store.clone()))
            .and_then(self::update_filter))
        .or(warp::path::end()
            .and(warp::delete())
            .and(warp::body::json())
            .and(super::with_configuration_updater_sender(
                configuration_updater_sender,
            ))
            .and(super::with_configuration_save_lock(configuration_save_lock))
            .and(super::with_arc(filter_failure_store))
            .and_then(self::delete_filter))
        .boxed()
}
