use crate::blocker::AdblockRequester;
use crate::configuration::NetworkConfig;
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
use std::net::IpAddr;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::broadcast;
use tokio::sync::Notify;

pub mod blocker;
mod blocker_utils;
mod ca;
mod cert;
pub mod configuration;
mod proxy;
pub mod statistics;
mod web_gui;
pub const WEBAPP_FRONTEND_DIR: Dir<'_> = include_dir!("web_frontend/dist");

#[derive(Debug)]
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

pub(crate) fn parse_ip_address(ip_str: &str) -> IpAddr {
    IpAddr::from_str(ip_str).unwrap()
}

async fn handle_signals() -> (Arc<Notify>, Arc<Notify>) {
    let notify_shutdown = Arc::new(Notify::new());
    let notify_reload = Arc::new(Notify::new());
    let notify_shutdown_clone = notify_shutdown.clone();
    let notify_reload_clone = notify_reload.clone();

    tokio::spawn(async move {
        let mut hup_signal =
            signal(SignalKind::hangup()).expect("failed to set up SIGHUP signal handler");
        let mut term_signal =
            signal(SignalKind::terminate()).expect("failed to set up SIGTERM signal handler");

        loop {
            tokio::select! {
                _ = hup_signal.recv() => {
                    log::info!("Received SIGHUP signal, restarting child processes...");
                    notify_reload_clone.notify_waiters();
                }
                _ = term_signal.recv() => {
                    log::info!("Received SIGTERM signal, shutting down gracefully...");
                    notify_shutdown_clone.notify_waiters();
                    std::process::exit(0);
                }
            }
        }
    });

    (notify_shutdown, notify_reload)
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

    let ca_certificate = match configuration.ca.get_ca_certificate().await {
        Ok(ca_certificate) => ca_certificate,
        Err(err) => {
            println!("Unable to decode ca certificate: {:?}", err);
            std::process::exit(1)
        }
    };

    let ca_certificate_pem = std::str::from_utf8(&ca_certificate.clone().to_pem().unwrap())
        .unwrap()
        .to_string();

    let ca_private_key = match configuration.ca.get_ca_private_key().await {
        Ok(ca_private_key) => ca_private_key,
        Err(err) => {
            println!("Unable to decode ca private key: {:?}", err);
            std::process::exit(1)
        }
    };

    let cert_cache = cert::CertCache::new(ca_certificate.clone(), ca_private_key.clone());

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

    let (_notify_shutdown, notify_reload) = handle_signals().await;

    let block_disable_ref = blocking_disabled_store.clone();
    let local_exclusion_store_ref = local_exclusion_store.clone();
    let stats_clone = statistics.clone();
    let configuration_updater_tx_ref = configuration_updater_tx.clone();
    let configuration_save_lock_ref = configuration_save_lock.clone();
    let broadcast_tx_ref = broadcast_tx.clone();

    tokio::spawn(async move {
        loop {
            let (_sig_tx, sig_rx) = tokio::sync::mpsc::channel::<tokio::signal::unix::Signal>(1);
            log::info!("Starting Privaxy frontend");
            privaxy_frontend(
                broadcast_tx_ref.clone(),
                local_exclusion_store_ref.clone(),
                stats_clone.clone(),
                block_disable_ref.clone(),
                configuration_updater_tx_ref.clone(),
                configuration_save_lock_ref.clone(),
                sig_rx,
                notify_reload.clone(),
            )
            .await;
            notify_reload.notified().await;
            log::info!("Stopping Privaxy frontend");
        }
    });

    let disabled_store_ref = blocking_disabled_store_clone.clone();
    thread::spawn(move || {
        let blocker =
            blocker::Blocker::new(crossbeam_sender, crossbeam_receiver, disabled_store_ref);

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

    let ip = env_or_config_ip(&network_config).await;
    let proxy_server_addr = SocketAddr::from((ip, network_config.proxy_port));

    let server = Server::bind(&proxy_server_addr)
        .http1_preserve_header_case(true)
        .http1_title_case_headers(true)
        .tcp_keepalive(Some(Duration::from_secs(600)))
        .serve(make_service);

    log::info!("Proxy available at http://{}", proxy_server_addr);
    if let Err(e) = server.await {
        log::error!("server error: {}", e);
    }

    PrivaxyServer {
        ca_certificate_pem,
        configuration_updater_sender: configuration_updater_tx,
        configuration_save_lock,
        blocking_disabled_store: blocking_disabled_store_clone,
        statistics: statistics_clone,
        local_exclusion_store: local_exclusion_store_clone,
        requests_broadcast_sender: broadcast_tx_clone,
    }
}

async fn privaxy_frontend(
    broadcast_tx: tokio::sync::broadcast::Sender<Event>,
    local_exclusion_store: LocalExclusionStore,
    statistics: statistics::Statistics,
    block_disable_ref: blocker::BlockingDisabledStore,
    configuration_updater_tx: tokio::sync::mpsc::Sender<configuration::Configuration>,
    configuration_save_lock: Arc<tokio::sync::Mutex<()>>,
    mut sig_rx: tokio::sync::mpsc::Receiver<tokio::signal::unix::Signal>,
    notify_reload: Arc<tokio::sync::Notify>,
) {
    let frontend = web_gui::get_frontend(
        broadcast_tx.clone(),
        statistics.clone(),
        &block_disable_ref,
        &configuration_updater_tx,
        &configuration_save_lock,
        &local_exclusion_store,
        notify_reload.clone(),
    );
    let frontend_server = warp::serve(frontend);
    let config = read_configuration(&configuration_save_lock).await;
    let ip = env_or_config_ip(&config.network).await;
    let web_api_server_addr = SocketAddr::from((ip, config.network.web_port));
    if config.network.tls {
        let lock = configuration_save_lock.lock().await;
        let ca_certificate = config.ca.get_ca_certificate().await.unwrap();
        let ca_private_key = config.ca.get_ca_private_key().await.unwrap();
        drop(lock);
        let tls_cert = match config
            .network
            .read_or_create_tls_cert(ca_certificate.clone(), ca_private_key.clone())
            .await
        {
            Ok(cert) => cert,
            Err(err) => {
                panic!("Failed to read or create TLS certificate: {err}");
            }
        };
        let tls_key = match config.network.get_tls_key().await {
            Ok(key) => key,
            Err(err) => {
                panic!("Failed to read or create TLS key: {err}");
            }
        };
        tokio::spawn(async move {
            let (_, task) = frontend_server
                .tls()
                .cert(tls_cert.to_pem().unwrap())
                .key(tls_key.private_key_to_pem_pkcs8().unwrap())
                .bind_with_graceful_shutdown(web_api_server_addr, async move {
                    notify_reload.clone().notified().await;
                });
            log::info!("Web server available at https://{web_api_server_addr}/");
            log::info!("API server available at https://{web_api_server_addr}/api");

            task.await;
        });
    } else {
        tokio::spawn(async move {
            let (_, task) =
                frontend_server.bind_with_graceful_shutdown(web_api_server_addr, async move {
                    let _ = sig_rx.recv().await;
                });
            log::info!("Web server available at http://{web_api_server_addr}/");
            log::info!("API server available at http://{web_api_server_addr}/api");
            task.await
        });
    }
}

async fn read_configuration(
    configuration_save_lock: &Arc<tokio::sync::Mutex<()>>,
) -> configuration::Configuration {
    let lock = configuration_save_lock.lock().await;
    let config = configuration::Configuration::read_from_home()
        .await
        .unwrap();
    drop(lock);
    config
}
async fn env_or_config_ip(network_config: &NetworkConfig) -> IpAddr {
    match env::var("PRIVAXY_IP_ADDRESS") {
        Ok(val) => parse_ip_address(&val),
        Err(_) => network_config.parsed_ip_address(),
    }
}
