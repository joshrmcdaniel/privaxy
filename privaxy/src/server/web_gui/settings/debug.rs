use super::get_error_response;
use crate::configuration::{Configuration, DebugConfig};
use crate::web_gui::with_configuration_save_lock;
use crate::web_gui::with_configuration_updater_sender;
use crate::web_gui::with_notify_reload;
use std::convert::Infallible;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use tokio::sync::Notify;
use warp::filters::BoxedFilter;
use warp::http::Response;
use warp::Filter as RouteFilter;

async fn get_debug_settings() -> Result<Box<dyn warp::Reply>, Infallible> {
    log::debug!("Getting debug settings");
    let configuration = match Configuration::read_from_home().await {
        Ok(configuration) => configuration,
        Err(err) => {
            log::error!("Failed to read debug settings: {err}");
            return Ok(Box::new(get_error_response(err)));
        }
    };
    Ok(Box::new(warp::reply::json(&configuration.debug)))
}

async fn put_debug_settings(
    debug_settings: DebugConfig,
    configuration_updater_sender: Sender<Configuration>,
    configuration_save_lock: Arc<tokio::sync::Mutex<()>>,
    notify_reload: Arc<Notify>,
) -> Result<Box<dyn warp::Reply>, Infallible> {
    let guard = configuration_save_lock.lock().await;
    let mut configuration = match Configuration::read_from_home().await {
        Ok(configuration) => configuration,
        Err(err) => {
            log::error!("Failed to read configuration for debug update: {err}");
            return Ok(Box::new(get_error_response(err)));
        }
    };

    configuration.debug = debug_settings;

    if let Err(err) = configuration.save().await {
        log::error!("Failed to save debug settings: {err}");
        drop(guard);
        return Ok(Box::new(get_error_response(err)));
    }
    configuration_updater_sender
        .send(configuration.clone())
        .await
        .unwrap();
    drop(guard);

    // The proxy reads `debug.scriptlet_console_logging` when it (re)starts, so a
    // reload is what makes the toggle take effect on newly served pages.
    notify_reload.notify_waiters();

    Ok(Box::new(
        Response::builder()
            .status(http::StatusCode::NO_CONTENT)
            .body("".to_string()),
    ))
}

pub(super) fn create_routes(
    configuration_updater_sender: Sender<Configuration>,
    configuration_save_lock: Arc<tokio::sync::Mutex<()>>,
    notify_reload: Arc<Notify>,
) -> BoxedFilter<(impl warp::Reply,)> {
    let get_route = warp::get()
        .and(warp::path::end())
        .and_then(get_debug_settings);

    let put_route = warp::put()
        .and(warp::path::end())
        .and(warp::body::json())
        .and(with_configuration_updater_sender(
            configuration_updater_sender.clone(),
        ))
        .and(with_configuration_save_lock(
            configuration_save_lock.clone(),
        ))
        .and(with_notify_reload(notify_reload.clone()))
        .and_then(put_debug_settings);

    get_route.or(put_route).boxed()
}
