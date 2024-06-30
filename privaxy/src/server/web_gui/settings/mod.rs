use super::get_error_response;
use crate::configuration::Configuration;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use warp::filters::BoxedFilter;
use warp::Filter as RouteFilter;

mod ca_certificate;
mod network;

pub(crate) fn create_routes(
    configuration_updater_sender: Sender<Configuration>,
    configuration_save_lock: Arc<tokio::sync::Mutex<()>>,
) -> BoxedFilter<(impl warp::Reply,)> {
    let network_settings_route = warp::path("network").and(network::create_routes(
        configuration_updater_sender.clone(),
        configuration_save_lock.clone(),
    ));

    let ca_cert_route = warp::path("ca-certificate").and(ca_certificate::create_routes(
        configuration_updater_sender.clone(),
        configuration_save_lock.clone(),
    ));

    network_settings_route.or(ca_cert_route).boxed()
}
