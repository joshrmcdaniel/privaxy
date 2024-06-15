use super::get_error_response;
use crate::configuration::Configuration;
use std::{convert::Infallible, sync::Arc};
use tokio::sync::mpsc::Sender;
use warp::filters::BoxedFilter;
use warp::http::StatusCode;
use warp::Filter as RouteFilter;

async fn get_custom_filters() -> Result<Box<dyn warp::Reply>, Infallible> {
    let configuration = match Configuration::read_from_home().await {
        Ok(configuration) => configuration,
        Err(err) => {
            log::error!("Failed to get customs filters: {err}");
            return Ok(Box::new(get_error_response(err)));
        }
    };

    let custom_filters = configuration.custom_filters.join("\n");

    Ok(Box::new(warp::reply::json(&custom_filters)))
}

async fn put_custom_filters(
    custom_filters: String,
    configuration_updater_sender: Sender<Configuration>,
    configuration_save_lock: Arc<tokio::sync::Mutex<()>>,
) -> Result<Box<dyn warp::Reply>, Infallible> {
    let _guard = configuration_save_lock.lock().await;

    let mut configuration = match Configuration::read_from_home().await {
        Ok(configuration) => configuration,
        Err(err) => {
            log::error!("Failed to put customs filters: {err}");
            return Ok(Box::new(get_error_response(err)));
        }
    };

    if let Err(err) = configuration.set_custom_filters(&custom_filters).await {
        log::error!("Failed to set customs filters: {err}");
        return Ok(Box::new(get_error_response(err)));
    }

    configuration_updater_sender
        .send(configuration.clone())
        .await
        .unwrap();

    Ok(Box::new(StatusCode::ACCEPTED))
}

pub(super) fn create_routes(
    configuration_updater_sender: Sender<Configuration>,
    configuration_save_lock: Arc<tokio::sync::Mutex<()>>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::get()
        .and_then(self::get_custom_filters)
        .or(warp::put()
            .and(warp::body::json())
            .and(super::with_configuration_updater_sender(
                configuration_updater_sender.clone(),
            ))
            .and(super::with_configuration_save_lock(
                configuration_save_lock.clone(),
            ))
            .and_then(self::put_custom_filters))
        .boxed()
}
