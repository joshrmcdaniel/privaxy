use super::get_error_response;
use crate::configuration::NetworkConfig;
use crate::web_gui::with_configuration_save_lock;
use crate::web_gui::with_configuration_updater_sender;
use std::convert::Infallible;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use warp::filters::BoxedFilter;
use warp::http::Response;
use warp::Filter as RouteFilter;

use crate::configuration::Configuration;

async fn get_network_settings() -> Result<Box<dyn warp::Reply>, Infallible> {
    log::debug!("Getting network settings");
    let configuration = match Configuration::read_from_home().await {
        Ok(configuration) => configuration,
        Err(err) => {
            log::error!("Failed to get network settings: {err}");
            return Ok(Box::new(get_error_response(err)));
        }
    };
    Ok(Box::new(warp::reply::json(&configuration.network)))
}

async fn put_network_settings(
    network_settings: NetworkConfig,
    configuration_updater_sender: Sender<Configuration>,
    configuration_save_lock: Arc<tokio::sync::Mutex<()>>,
) -> Result<Box<dyn warp::Reply>, Infallible> {
    let _guard = configuration_save_lock.lock().await;
    let mut configuration = match Configuration::read_from_home().await {
        Ok(configuration) => configuration,
        Err(err) => {
            log::error!("Failed to get network settings: {err}");
            return Ok(Box::new(get_error_response(err)));
        }
    };
    if let Err(err) = configuration.set_network_settings(&network_settings).await {
        log::error!("Invalid network settings: {err}");
        return Ok(Box::new(get_error_response(err)));
    };

    configuration_updater_sender
        .send(configuration.clone())
        .await
        .unwrap();
    Ok(Box::new(
        Response::builder()
            .status(http::StatusCode::NO_CONTENT)
            .body("".to_string()),
    ))
}

pub(super) fn create_routes(
    configuration_updater_sender: Sender<Configuration>,
    configuration_save_lock: Arc<tokio::sync::Mutex<()>>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path::end()
        .and(
            warp::get().and_then(get_network_settings).or(warp::put()
                .and(warp::body::json())
                .and(with_configuration_updater_sender(
                    configuration_updater_sender.clone(),
                ))
                .and(with_configuration_save_lock(
                    configuration_save_lock.clone(),
                ))
                .and_then(put_network_settings)),
        )
        .boxed()
}
