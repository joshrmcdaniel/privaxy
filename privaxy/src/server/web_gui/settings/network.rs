use super::get_error_response;
use crate::configuration::{DohConfig, NetworkConfig};
use crate::web_gui::with_configuration_save_lock;
use crate::web_gui::with_configuration_updater_sender;
use crate::web_gui::with_notify_reload;
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

use std::convert::Infallible;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use warp::filters::BoxedFilter;
use warp::http::Response;
use warp::Filter as RouteFilter;

use crate::configuration::Configuration;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
/// Network configuration for Privaxy
pub struct NetworkConfigRequest {
    /// Bind address for the proxy server.
    pub bind_addr: String,
    /// Port for the proxy server.
    pub proxy_port: u16,
    /// Port for the web server.
    pub web_port: u16,
    /// Enable TLS for the web server.
    pub tls: bool,
    /// DNS-over-HTTPS interception policy. Omitted by older clients, in which
    /// case the current configuration is preserved.
    #[serde(default)]
    pub doh: Option<DohConfig>,
}

impl From<NetworkConfigRequest> for NetworkConfig {
    fn from(val: NetworkConfigRequest) -> Self {
        NetworkConfig {
            bind_addr: val.bind_addr,
            proxy_port: val.proxy_port,
            web_port: val.web_port,
            tls: val.tls,
            tls_cert_path: None,
            tls_key_path: None,
            listen_url: None,
            pac_enabled: false,
            pac_proxy_host: None,
            pac_direct_ips: Vec::new(),
            pac_direct_cidrs: std::collections::BTreeMap::new(),
            pac_direct_fqdns: Vec::new(),
            doh: DohConfig::default(),
        }
    }
}

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
    network_settings: NetworkConfigRequest,
    configuration_updater_sender: Sender<Configuration>,
    configuration_save_lock: Arc<tokio::sync::Mutex<()>>,
    notify_reload: Arc<Notify>,
) -> Result<Box<dyn warp::Reply>, Infallible> {
    let lock = configuration_save_lock.lock().await;
    let mut configuration = match Configuration::read_from_home().await {
        Ok(configuration) => configuration,
        Err(err) => {
            log::error!("Failed to get network settings: {}", err);
            return Ok(Box::new(get_error_response(err)));
        }
    };

    drop(lock);
    let requested_doh = network_settings.doh.clone();
    let mut net_cfg: NetworkConfig = network_settings.into();
    let current_cfg = configuration.network.clone();
    net_cfg.tls_cert_path = current_cfg.tls_cert_path;
    net_cfg.tls_key_path = current_cfg.tls_key_path;
    net_cfg.listen_url = current_cfg.listen_url;
    net_cfg.pac_enabled = current_cfg.pac_enabled;
    net_cfg.pac_proxy_host = current_cfg.pac_proxy_host;
    net_cfg.pac_direct_ips = current_cfg.pac_direct_ips;
    net_cfg.pac_direct_cidrs = current_cfg.pac_direct_cidrs;
    net_cfg.pac_direct_fqdns = current_cfg.pac_direct_fqdns;
    net_cfg.doh = requested_doh.unwrap_or(current_cfg.doh);
    if let Err(err) = &net_cfg.validate().await {
        log::error!("Invalid network settings: {}", err);
        return Ok(Box::new(get_error_response(err)));
    };
    configuration.network = net_cfg.clone();

    let guard = configuration_save_lock.lock().await;
    configuration.save().await.unwrap();
    configuration_updater_sender
        .send(configuration.clone())
        .await
        .unwrap();
    drop(guard);

    notify_reload.notify_waiters(); // Notify the reload signal

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
        .and_then(get_network_settings);

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
        .and_then(put_network_settings);

    get_route.or(put_route).boxed()
}
