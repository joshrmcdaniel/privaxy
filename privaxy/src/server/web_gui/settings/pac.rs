use super::get_error_response;
use crate::configuration::Configuration;
use crate::web_gui::with_configuration_save_lock;
use crate::web_gui::with_configuration_updater_sender;
use crate::web_gui::with_notify_reload;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use tokio::sync::Notify;
use warp::filters::BoxedFilter;
use warp::http::Response;
use warp::Filter as RouteFilter;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PacSettings {
    pub pac_enabled: bool,
    #[serde(default)]
    pub pac_proxy_host: Option<String>,
    #[serde(default)]
    pub pac_direct_ips: Vec<String>,
    #[serde(default)]
    pub pac_direct_cidrs: BTreeMap<String, String>,
    #[serde(default)]
    pub pac_direct_fqdns: Vec<String>,
}

async fn get_pac_settings() -> Result<Box<dyn warp::Reply>, Infallible> {
    log::debug!("Getting PAC settings");
    let configuration = match Configuration::read_from_home().await {
        Ok(configuration) => configuration,
        Err(err) => {
            log::error!("Failed to read PAC settings: {err}");
            return Ok(Box::new(get_error_response(err)));
        }
    };
    let network = &configuration.network;
    let body = PacSettings {
        pac_enabled: network.pac_enabled,
        pac_proxy_host: network.pac_proxy_host.clone(),
        pac_direct_ips: network.pac_direct_ips.clone(),
        pac_direct_cidrs: network.pac_direct_cidrs.clone(),
        pac_direct_fqdns: network.pac_direct_fqdns.clone(),
    };
    Ok(Box::new(warp::reply::json(&body)))
}

async fn put_pac_settings(
    pac_settings: PacSettings,
    configuration_updater_sender: Sender<Configuration>,
    configuration_save_lock: Arc<tokio::sync::Mutex<()>>,
    notify_reload: Arc<Notify>,
) -> Result<Box<dyn warp::Reply>, Infallible> {
    let guard = configuration_save_lock.lock().await;
    let mut configuration = match Configuration::read_from_home().await {
        Ok(configuration) => configuration,
        Err(err) => {
            log::error!("Failed to read configuration for PAC update: {err}");
            return Ok(Box::new(get_error_response(err)));
        }
    };

    let proxy_host = pac_settings
        .pac_proxy_host
        .as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    configuration.network.pac_enabled = pac_settings.pac_enabled;
    configuration.network.pac_proxy_host = proxy_host;
    configuration.network.pac_direct_ips = pac_settings
        .pac_direct_ips
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    configuration.network.pac_direct_cidrs = pac_settings
        .pac_direct_cidrs
        .into_iter()
        .map(|(subnet, netmask)| (subnet.trim().to_string(), netmask.trim().to_string()))
        .filter(|(subnet, netmask)| !subnet.is_empty() && !netmask.is_empty())
        .collect();
    configuration.network.pac_direct_fqdns = pac_settings
        .pac_direct_fqdns
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if let Err(err) = configuration.save().await {
        log::error!("Failed to save PAC settings: {err}");
        drop(guard);
        return Ok(Box::new(get_error_response(err)));
    }
    configuration_updater_sender
        .send(configuration.clone())
        .await
        .unwrap();
    drop(guard);

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
        .and_then(get_pac_settings);

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
        .and_then(put_pac_settings);

    get_route.or(put_route).boxed()
}
