use crate::blocker::AdblockRequester;
use crate::proxy::exclusions::LocalExclusionStore;
use crate::web_gui::events::Event;
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Client, Server};
use include_dir::{include_dir, Dir};
use proxy::exclusions;
use reqwest::redirect::Policy;
use std::convert::Infallible;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tokio::sync::broadcast;
pub mod blocker;
mod blocker_utils;
mod ca;
mod cert;
pub mod configuration;
mod proxy;
pub mod statistics;
mod web_gui;

pub const WEBAPP_FRONTEND_DIR: Dir<'_> = include_dir!("web_frontend/dist");

#[derive(Debug, Clone)]
pub struct PrivaxyServer {
    pub ca_certificate_pem: String,
    pub configuration_updater_sender: tokio::sync::mpsc::Sender<configuration::Configuration>,
    pub configuration_save_lock: Arc<tokio::sync::Mutex<()>>,
    pub blocking_disabled_store: blocker::BlockingDisabledStore,
    pub statistics: statistics::Statistics,
    pub local_exclusion_store: exclusions::LocalExclusionStore,
    // A Sender is required to subscribe to broadcasted messages
    pub requests_broadcast_sender: broadcast::Sender<Event>,
}

// Helper function to parse the IP address string into an array of u8
fn parse_ip_address(ip_str: &str) -> [u8; 4] {
    let mut ip: [u8; 4] = [0, 0, 0, 0];
    let parts: Vec<&str> = ip_str.split('.').collect();
    for (i, part) in parts.iter().enumerate() {
        if let Ok(num) = part.parse::<u8>() {
            ip[i] = num;
        }
    }
    ip
}

pub async fn start_privaxy() -> PrivaxyServer {
    // We use reqwest instead of hyper's client to perform most of the proxying as it's more convenient
    // to handle compression as well as offers a more convenient interface.
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .redirect(Policy::none())
        .no_proxy()
        .gzip(true)
        .brotli(true)
        .deflate(true)
        .build()
        .unwrap();

    let configuration = match configuration::Configuration::read_from_home().await {
        Ok(configuration) => configuration,
        Err(err) => {
            println!(
                "An error occured while trying to process the configuration file: {:?}",
                err
            );
            std::process::exit(1)
        }
    };

    let local_exclusion_store =
        LocalExclusionStore::new(Vec::from_iter(configuration.exclusions.clone().into_iter()));
    let local_exclusion_store_clone = local_exclusion_store.clone();

    let ca_certificate = match configuration.ca_certificate().await {
        Ok(ca_certificate) => ca_certificate,
        Err(err) => {
            println!("Unable to decode ca certificate: {:?}", err);
            std::process::exit(1)
        }
    };

    let ca_certificate_pem = std::str::from_utf8(&ca_certificate.to_pem().unwrap())
        .unwrap()
        .to_string();

    let ca_private_key = match configuration.ca_private_key().await {
        Ok(ca_private_key) => ca_private_key,
        Err(err) => {
            println!("Unable to decode ca private key: {:?}", err);
            std::process::exit(1)
        }
    };

    let cert_cache = cert::CertCache::new(ca_certificate, ca_private_key);

    let statistics = statistics::Statistics::new();
    let statistics_clone = statistics.clone();

    let (broadcast_tx, _broadcast_rx) = broadcast::channel(32);
    let broadcast_tx_clone = broadcast_tx.clone();

    let blocking_disabled_store =
        blocker::BlockingDisabledStore(Arc::new(std::sync::RwLock::new(false)));
    let blocking_disabled_store_clone = blocking_disabled_store.clone();

    let (crossbeam_sender, crossbeam_receiver) = crossbeam_channel::unbounded();
    let blocker_sender = crossbeam_sender.clone();

    let blocker_requester = AdblockRequester::new(blocker_sender);

    let configuration_updater = configuration::ConfigurationUpdater::new(
        configuration.clone(),
        client.clone(),
        blocker_requester.clone(),
        None,
    )
    .await;

    let network_config = configuration.network.clone();
    let configuration_updater_tx = configuration_updater.tx.clone();
    configuration_updater_tx.send(configuration).await.unwrap();

    configuration_updater.start();

    let configuration_save_lock = Arc::new(tokio::sync::Mutex::new(()));
    let ip = match env::var("PRIVAXY_IP_ADDRESS") {
        Ok(val) =>
        // Parse the IP address from the environment variable string
        {
            parse_ip_address(&val)
        }
        Err(_) =>
        // Set a default IP address
        {
            parse_ip_address(&network_config.bind_addr.clone())
        }
    };
    let web_api_server_addr = SocketAddr::from((ip, network_config.api_port));

    web_gui::start_frontend(
        broadcast_tx.clone(),
        statistics.clone(),
        blocking_disabled_store.clone(),
        configuration_updater_tx.clone(),
        ca_certificate_pem.clone(),
        configuration_save_lock.clone(),
        local_exclusion_store.clone(),
        web_api_server_addr,
    );

    thread::spawn(move || {
        let blocker = blocker::Blocker::new(
            crossbeam_sender,
            crossbeam_receiver,
            blocking_disabled_store,
        );

        blocker.handle_requests()
    });

    let https_connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .build();

    // The hyper client is only used to perform upgrades. We don't need to
    // handle compression.
    // Hyper's client don't follow redirects, which is what we want, nothing to
    // disable here.
    let hyper_client = Client::builder().build(https_connector);

    let make_service = make_service_fn(move |conn: &AddrStream| {
        let client_ip_address = conn.remote_addr().ip();

        let client = client.clone();
        let hyper_client = hyper_client.clone();
        let cert_cache = cert_cache.clone();
        let blocker_requester = blocker_requester.clone();
        let broadcast_tx = broadcast_tx.clone();
        let statistics = statistics.clone();
        let local_exclusion_store = local_exclusion_store.clone();

        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                proxy::serve_mitm_session(
                    blocker_requester.clone(),
                    hyper_client.clone(),
                    client.clone(),
                    req,
                    cert_cache.clone(),
                    broadcast_tx.clone(),
                    statistics.clone(),
                    client_ip_address,
                    local_exclusion_store.clone(),
                )
            }))
        }
    });

    let proxy_server_addr = SocketAddr::from((ip, network_config.proxy_port));

    let server = Server::bind(&proxy_server_addr)
        .http1_preserve_header_case(true)
        .http1_title_case_headers(true)
        .tcp_keepalive(Some(Duration::from_secs(600)))
        .serve(make_service);

    log::info!("Proxy available at http://{}", proxy_server_addr);
    log::info!("Web server available at http://{}", web_api_server_addr);
    log::info!("API server available at http://{}/api", web_api_server_addr);

    if let Err(e) = server.await {
        log::error!("server error: {}", e);
    }

    PrivaxyServer {
        ca_certificate_pem,
        configuration_updater_sender: configuration_updater_tx,
        configuration_save_lock: configuration_save_lock,
        blocking_disabled_store: blocking_disabled_store_clone,
        statistics: statistics_clone,
        local_exclusion_store: local_exclusion_store_clone,
        requests_broadcast_sender: broadcast_tx_clone,
    }
}
