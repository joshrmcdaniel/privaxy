use crate::proxy::exclusions::LocalExclusionStore;
use crate::statistics::Statistics;
use crate::WEBAPP_FRONTEND_DIR;
use crate::{blocker::BlockingDisabledStore, configuration::Configuration};
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc::Sender};
use warp::filters::BoxedFilter;
use warp::http::Response;
use warp::path::Tail;
use warp::{http, Filter, Reply};

pub(crate) mod blocking_enabled;
pub(crate) mod custom_filters;
pub(crate) mod events;
pub(crate) mod exclusions;
mod filterlists;
pub(crate) mod filters;
pub(crate) mod settings;
pub(crate) mod statistics;

#[derive(Debug, Serialize)]
pub(crate) struct ApiError {
    error: String,
}

pub(crate) fn start_frontend(
    events_sender: broadcast::Sender<events::Event>,
    statistics: Statistics,
    blocking_disabled_store: BlockingDisabledStore,
    configuration_updater_sender: Sender<Configuration>,
    configuration_save_lock: Arc<tokio::sync::Mutex<()>>,
    local_exclusions_store: LocalExclusionStore,
    bind: SocketAddr,
    tls_cert: Option<X509>,
    tls_key: Option<PKey<Private>>,
    use_tls: bool,
) {
    let static_files_routes = warp::get().and(warp::path::tail()).map(move |tail: Tail| {
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
    });

    let cors = warp::cors()
        .allow_any_origin()
        .allow_methods(vec!["GET", "PUT", "POST", "DELETE"])
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
        http_client,
    )
    .with(cors);
    let combined_routes = api_routes.or(static_files_routes);

    if use_tls {
        let key = tls_key.unwrap();
        let cert = tls_cert.unwrap();
        let combined_routes_with_hsts = combined_routes.map(|reply| {
            warp::reply::with_header(
                reply,
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains; preload",
            )
        });

        tokio::spawn(async move {
            warp::serve(combined_routes_with_hsts)
                .tls()
                .cert(cert.to_pem().unwrap())
                .key(key.private_key_to_pem_pkcs8().unwrap())
                .run(bind)
                .await;
        });
    } else {
        tokio::spawn(async move {
            warp::serve(combined_routes).run(bind).await;
        });
    }
}

fn create_api_routes(
    events_sender: broadcast::Sender<events::Event>,
    statistics: Statistics,
    blocking_disabled_store: BlockingDisabledStore,
    configuration_updater_sender: Sender<Configuration>,
    configuration_save_lock: Arc<tokio::sync::Mutex<()>>,
    local_exclusions_store: LocalExclusionStore,
    http_client: reqwest::Client,
) -> BoxedFilter<(impl Reply,)> {
    let def_headers =
        warp::filters::reply::default_header(http::header::CONTENT_TYPE, "application/json");
    let api_path = warp::path("api");
    let events_route = warp::path("events")
        .and(warp::ws())
        .map(move |ws: warp::ws::Ws| {
            let events_sender = events_sender.clone();
            ws.on_upgrade(move |websocket| events::events(websocket, events_sender))
        });

    let statistics_route = warp::path("statistics")
        .and(warp::ws())
        .map(move |ws: warp::ws::Ws| {
            let statistics = statistics.clone();
            ws.on_upgrade(move |websocket| statistics::statistics(websocket, statistics))
        });

    let filters_route = warp::path("filters").and(filters::create_routes(
        configuration_updater_sender.clone(),
        configuration_save_lock.clone(),
        http_client.clone(),
    ));
    let custom_filters_route = warp::path("custom-filters").and(custom_filters::create_routes(
        configuration_updater_sender.clone(),
        configuration_save_lock.clone(),
    ));
    let exclusions_route = warp::path("exclusions").and(exclusions::create_routes(
        configuration_updater_sender.clone(),
        configuration_save_lock.clone(),
        local_exclusions_store.clone(),
    ));
    let settings_route = warp::path("settings").and(settings::create_routes(
        configuration_updater_sender.clone(),
        configuration_save_lock.clone(),
    ));

    let blocking_enabled_route = warp::path("blocking-enabled").and(
        blocking_enabled::create_routes(blocking_disabled_store.clone()),
    );

    let options_route = warp::options().map(|| "");

    let filterlists_route = warp::path("filterlists").and(filterlists::create_routes());

    let not_found = warp::path::tail()
        .map(move |tail: Tail| {
            let tail_str = tail.as_str();
            Response::builder()
                .status(http::StatusCode::NOT_FOUND)
                .body(
                    serde_json::to_string(&ApiError {
                        error: format!("Path not found: /api/{}", tail_str),
                    })
                    .unwrap(),
                )
                .unwrap()
        })
        .boxed();

    api_path
        .and(
            events_route
                .or(statistics_route)
                .or(filters_route)
                .or(custom_filters_route)
                .or(exclusions_route)
                .or(blocking_enabled_route)
                .or(settings_route)
                .or(options_route)
                .or(filterlists_route)
                .or(not_found),
        )
        .with(def_headers)
        .boxed()
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

pub(self) fn with_configuration_updater_sender(
    sender: Sender<Configuration>,
) -> impl Filter<Extract = (Sender<Configuration>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || sender.clone())
}

pub(self) fn with_http_client(
    http_client: reqwest::Client,
) -> impl Filter<Extract = (reqwest::Client,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || http_client.clone())
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
