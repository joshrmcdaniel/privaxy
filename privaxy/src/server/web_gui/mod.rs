use crate::configuration::FilterFailureStore;
use crate::logging::LogHandle;
use crate::proxy::exclusions::LocalExclusionStore;
use crate::proxy::gm::storage::GmStorageStore;
use crate::proxy::tls_failures::TlsFailureStore;
use crate::proxy::userscripts::{PrivateNetworkAccess, UserScriptStore};
use crate::statistics::Statistics;
use crate::WEBAPP_FRONTEND_DIR;
use crate::{blocker::BlockingDisabledStore, configuration::Configuration};
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::Notify;
use tokio::sync::{broadcast, mpsc::Sender};
use warp::filters::BoxedFilter;
use warp::http::Response;
use warp::path::Tail;
use warp::{http, Filter, Reply};

pub(crate) mod auth;
pub(crate) mod blocking_enabled;
pub(crate) mod custom_filters;
pub(crate) mod events;
pub(crate) mod exclusions;
mod filterlists;
pub(crate) mod filters;
pub(crate) mod logs;
mod pac;
pub(crate) mod settings;
pub(crate) mod statistics;
pub(crate) mod tls_failures;
pub(crate) mod userscripts;

#[derive(Debug, Serialize)]
pub(crate) struct ApiError {
    error: String,
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn get_frontend(
    events_sender: broadcast::Sender<events::Event>,
    statistics: Statistics,
    blocking_disabled_store: &BlockingDisabledStore,
    configuration_updater_sender: &Sender<Configuration>,
    configuration_save_lock: &Arc<tokio::sync::Mutex<()>>,
    local_exclusions_store: &LocalExclusionStore,
    tls_failure_store: &TlsFailureStore,
    filter_failure_store: &FilterFailureStore,
    user_script_store: &UserScriptStore,
    gm_storage: &GmStorageStore,
    private_network_access: &PrivateNetworkAccess,
    notify_reload: Arc<Notify>,
    log_handle: LogHandle,
) -> BoxedFilter<(impl warp::Reply,)> {
    let static_files_routes = create_static_routes();

    let cors = warp::cors()
        .allow_any_origin()
        .allow_methods(vec!["GET", "PUT", "POST", "PATCH", "DELETE"])
        .allow_headers(vec![
            http::header::CONTENT_TYPE,
            http::header::CONTENT_LENGTH,
            http::header::DATE,
        ]);

    let http_client = reqwest::Client::new();

    let api_routes = create_api_routes(
        events_sender,
        statistics,
        blocking_disabled_store,
        configuration_updater_sender,
        configuration_save_lock,
        local_exclusions_store,
        tls_failure_store,
        filter_failure_store,
        user_script_store,
        gm_storage,
        private_network_access,
        http_client,
        notify_reload,
        log_handle,
    );

    let pac_route = pac::create_routes(configuration_save_lock.clone());

    api_routes
        .or(pac_route)
        .or(static_files_routes)
        .with(cors)
        .boxed()
}

fn with_arc<T: Clone + Send + Sync + 'static>(
    value: T,
) -> impl Filter<Extract = (T,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || value.clone())
}

fn create_static_routes() -> BoxedFilter<(impl warp::Reply,)> {
    warp::get()
        .and(warp::path::tail())
        .map(move |tail: Tail| {
            let tail_str = tail.as_str();

            let file_contents = match WEBAPP_FRONTEND_DIR.get_file(tail_str) {
                Some(file) => file.contents().to_vec(),
                None => {
                    let index_html = WEBAPP_FRONTEND_DIR.get_file("index.html").unwrap();
                    index_html.contents().to_vec()
                }
            };

            let mime = mime_guess::from_path(tail_str).first_raw().unwrap_or("");

            Response::builder()
                .header(http::header::CONTENT_TYPE, mime)
                .body(file_contents)
        })
        .boxed()
}

#[allow(clippy::too_many_arguments)]
fn create_api_routes(
    events_sender: broadcast::Sender<events::Event>,
    statistics: Statistics,
    blocking_disabled_store: &BlockingDisabledStore,
    configuration_updater_sender: &Sender<Configuration>,
    configuration_save_lock: &Arc<tokio::sync::Mutex<()>>,
    local_exclusions_store: &LocalExclusionStore,
    tls_failure_store: &TlsFailureStore,
    filter_failure_store: &FilterFailureStore,
    user_script_store: &UserScriptStore,
    gm_storage: &GmStorageStore,
    private_network_access: &PrivateNetworkAccess,
    http_client: reqwest::Client,
    notify_reload: Arc<Notify>,
    log_handle: LogHandle,
) -> BoxedFilter<(impl Reply,)> {
    let def_headers =
        warp::filters::reply::default_header(http::header::CONTENT_TYPE, "application/json");
    let api_path = warp::path("api");

    let auth_routes = warp::path("auth").and(auth::routes::create_routes(
        configuration_updater_sender.clone(),
        configuration_save_lock.clone(),
    ));

    let require_auth = auth::require_auth(configuration_save_lock.clone());

    let events_route = warp::path("events")
        .and(require_auth.clone())
        .and(warp::ws())
        .map(move |ws: warp::ws::Ws| {
            let events_sender = events_sender.clone();
            ws.on_upgrade(move |websocket| events::events(websocket, events_sender))
        });

    let statistics_route = warp::path("statistics")
        .and(require_auth.clone())
        .and(warp::ws())
        .map(move |ws: warp::ws::Ws| {
            let statistics = statistics.clone();
            ws.on_upgrade(move |websocket| statistics::statistics(websocket, statistics))
        });

    let logs_handle = log_handle.clone();
    let logs_route = warp::path("logs")
        .and(require_auth.clone())
        .and(warp::ws())
        .map(move |ws: warp::ws::Ws| {
            let log_handle = logs_handle.clone();
            ws.on_upgrade(move |websocket| logs::logs(websocket, log_handle))
        });

    let filters_route =
        warp::path("filters")
            .and(require_auth.clone())
            .and(filters::create_routes(
                configuration_updater_sender.clone(),
                configuration_save_lock.clone(),
                http_client.clone(),
                filter_failure_store.clone(),
            ));

    let custom_filters_route =
        warp::path("custom-filters")
            .and(require_auth.clone())
            .and(custom_filters::create_routes(
                configuration_updater_sender.clone(),
                configuration_save_lock.clone(),
            ));

    let exclusions_route =
        warp::path("exclusions")
            .and(require_auth.clone())
            .and(exclusions::create_routes(
                configuration_updater_sender.clone(),
                configuration_save_lock.clone(),
                local_exclusions_store.clone(),
            ));

    let settings_route =
        warp::path("settings")
            .and(require_auth.clone())
            .and(settings::create_routes(
                configuration_updater_sender.clone(),
                configuration_save_lock.clone(),
                notify_reload.clone(),
                log_handle.clone(),
            ));

    let blocking_enabled_route = warp::path("blocking-enabled")
        .and(require_auth.clone())
        .and(blocking_enabled::create_routes(
            blocking_disabled_store.clone(),
        ));

    let tls_failures_route =
        warp::path("tls-failures")
            .and(require_auth.clone())
            .and(tls_failures::create_routes(
                tls_failure_store.clone(),
                local_exclusions_store.clone(),
                configuration_save_lock.clone(),
            ));

    let options_route = warp::options().map(|| "");

    let filterlists_route = warp::path("filterlists")
        .and(require_auth.clone())
        .and(filterlists::create_routes());

    let userscripts_route =
        warp::path("userscripts")
            .and(require_auth.clone())
            .and(userscripts::create_routes(
                configuration_save_lock.clone(),
                http_client.clone(),
                user_script_store.clone(),
                gm_storage.clone(),
                private_network_access.clone(),
            ));

    // Note: `.recover` is attached to the inner combinator, NOT to the
    // outer `api_path.and(...)`. If we attached it to the outer filter,
    // recover would also fire when `api_path` itself didn't match (e.g.
    // a request to `/`), turning every non-API request into a JSON 404
    // and preventing the static-files branch from serving the SPA.
    let api_inner = auth_routes
        .or(events_route)
        .or(statistics_route)
        .or(logs_route)
        .or(filters_route)
        .or(custom_filters_route)
        .or(exclusions_route)
        .or(blocking_enabled_route)
        .or(tls_failures_route)
        .or(settings_route)
        .or(options_route)
        .or(filterlists_route)
        .or(userscripts_route)
        .recover(handle_rejection);

    api_path.and(api_inner).with(def_headers).boxed()
}

async fn handle_rejection(err: warp::Rejection) -> Result<Box<dyn Reply>, warp::Rejection> {
    if err.find::<auth::Unauthorized>().is_some() {
        return Ok(json_status(
            http::StatusCode::UNAUTHORIZED,
            "unauthenticated",
        ));
    }
    if err.find::<auth::ConfigUnavailable>().is_some() {
        return Ok(json_status(
            http::StatusCode::INTERNAL_SERVER_ERROR,
            "configuration unavailable",
        ));
    }
    // Any other rejection inside the /api scope (path not found, method
    // not allowed, body deserialize failure, etc.) becomes a JSON 404 so
    // unmatched API paths don't fall through to the static-files
    // catch-all and accidentally serve index.html.
    Ok(json_status(http::StatusCode::NOT_FOUND, "Not found"))
}

fn json_status(status: http::StatusCode, message: &str) -> Box<dyn Reply> {
    let body = serde_json::to_string(&ApiError {
        error: message.to_string(),
    })
    .unwrap();
    let response = Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(body)
        .unwrap();
    Box::new(response)
}

pub(crate) fn with_local_exclusions_store(
    local_exclusions_store: LocalExclusionStore,
) -> impl Filter<Extract = (LocalExclusionStore,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || local_exclusions_store.clone())
}

pub(crate) fn with_configuration_save_lock(
    configuration_save_lock: Arc<tokio::sync::Mutex<()>>,
) -> impl Filter<Extract = (Arc<tokio::sync::Mutex<()>>,), Error = std::convert::Infallible> + Clone
{
    warp::any().map(move || configuration_save_lock.clone())
}

fn with_blocking_disabled_store(
    blocking_disabled: BlockingDisabledStore,
) -> impl Filter<Extract = (BlockingDisabledStore,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || blocking_disabled.clone())
}

fn with_configuration_updater_sender(
    sender: Sender<Configuration>,
) -> impl Filter<Extract = (Sender<Configuration>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || sender.clone())
}

fn with_http_client(
    http_client: reqwest::Client,
) -> impl Filter<Extract = (reqwest::Client,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || http_client.clone())
}

fn with_notify_reload(
    notify_reload: Arc<Notify>,
) -> impl Filter<Extract = (Arc<Notify>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || notify_reload.clone())
}

pub(crate) fn get_error_response(err: impl std::error::Error) -> Response<String> {
    log::debug!("Building error response: {:?}", err);
    Response::builder()
        .status(http::StatusCode::INTERNAL_SERVER_ERROR)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::to_string(&ApiError {
                error: format!("{:?}", err),
            })
            .unwrap(),
        )
        .unwrap()
}

/// JSON 422 for requests whose body was well-formed but semantically invalid
/// (e.g. a value that is not a hostname).
pub(crate) fn get_unprocessable_response(message: &str) -> Response<String> {
    Response::builder()
        .status(http::StatusCode::UNPROCESSABLE_ENTITY)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::to_string(&ApiError {
                error: message.to_string(),
            })
            .unwrap(),
        )
        .unwrap()
}

/// JSON 403 for operations the API refuses regardless of authentication
/// (e.g. editing a built-in filter list).
pub(crate) fn get_forbidden_response(message: &str) -> Response<String> {
    Response::builder()
        .status(http::StatusCode::FORBIDDEN)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::to_string(&ApiError {
                error: message.to_string(),
            })
            .unwrap(),
        )
        .unwrap()
}
