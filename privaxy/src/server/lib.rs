use crate::blocker::AdblockRequester;
use crate::configuration::{FilterFailureStore, NetworkConfig};
use crate::proxy::exclusions::LocalExclusionStore;
use crate::web_gui::events::Event;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use hyper_util::server::graceful::GracefulShutdown;
use include_dir::{include_dir, Dir};
use proxy::exclusions;
use proxy::gm::storage::GmStorageStore;
use proxy::serve::UpgradeClient;
use proxy::tls_failures::TlsFailureStore;
use proxy::userscripts::{PrivateNetworkAccess, UserScriptContext, UserScriptStore};
use reqwest::redirect::Policy;
use std::env;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::broadcast;
use tokio::sync::Notify;

pub mod blocker;
mod blocker_utils;
mod ca;
mod cert;
pub mod configuration;
pub mod logging;
mod proxy;
pub mod statistics;
mod web_gui;

pub const WEBAPP_FRONTEND_DIR: Dir<'_> = include_dir!("web_frontend/dist");

/// Custom `getrandom` backend for the `mips{,el}-unknown-linux-gnu` cross
/// targets.
///
/// getrandom 0.3's default Linux backend for these targets calls the libc
/// `getrandom()` wrapper, which the cross-toolchain's pre-2.25 glibc does not
/// export — so the binary fails to link (`undefined reference to getrandom`).
/// We point getrandom at its `custom` backend for these triples (see
/// `.cargo/config.toml`) and service it here with the raw `SYS_getrandom`
/// syscall. The syscall is independent of the libc version, so the resulting
/// binary still runs on the old-glibc routers we target; pre-3.17 kernels that
/// lack the syscall fall back to `/dev/urandom`, matching getrandom 0.2's old
/// behavior. musl MIPS and every non-MIPS target keep getrandom's stock
/// backend and never reach this code.
#[cfg(all(target_os = "linux", target_arch = "mips", target_env = "gnu"))]
#[no_mangle]
unsafe extern "Rust" fn __getrandom_v03_custom(
    dest: *mut u8,
    len: usize,
) -> Result<(), getrandom::Error> {
    let mut filled = 0usize;
    while filled < len {
        let ret = libc::syscall(libc::SYS_getrandom, dest.add(filled), len - filled, 0u32);
        if ret < 0 {
            match std::io::Error::last_os_error().raw_os_error() {
                // Interrupted before any bytes were read; retry.
                Some(libc::EINTR) => continue,
                // Kernel predates getrandom(2) (pre-3.17): use /dev/urandom.
                Some(libc::ENOSYS) => return urandom_fallback(dest, len),
                _ => return Err(getrandom::Error::UNEXPECTED),
            }
        }
        filled += ret as usize;
    }
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "mips", target_env = "gnu"))]
unsafe fn urandom_fallback(dest: *mut u8, len: usize) -> Result<(), getrandom::Error> {
    use std::io::Read;

    let buf = std::slice::from_raw_parts_mut(dest, len);
    let mut file = std::fs::File::open("/dev/urandom").map_err(|_| getrandom::Error::UNEXPECTED)?;
    file.read_exact(buf)
        .map_err(|_| getrandom::Error::UNEXPECTED)?;
    Ok(())
}

#[derive(Debug)]
pub struct PrivaxyServer {
    pub ca_certificate_pem: String,
    pub configuration_updater_sender: tokio::sync::mpsc::Sender<configuration::Configuration>,
    pub configuration_save_lock: Arc<tokio::sync::Mutex<()>>,
    pub blocking_disabled_store: blocker::BlockingDisabledStore,
    pub statistics: statistics::Statistics,
    pub local_exclusion_store: exclusions::LocalExclusionStore,
    pub tls_failure_store: TlsFailureStore,
    pub filter_failure_store: FilterFailureStore,
    pub user_script_store: UserScriptStore,
    pub gm_storage: GmStorageStore,
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
    // rustls 0.23 no longer bakes in a crypto provider: a process-wide default
    // must be installed before any TLS config is built (the proxy's per-host
    // certs, the upstream HTTPS connector, the reqwest client, and the web GUI
    // TLS listener all rely on it). We pin the `ring` provider so the tier-3
    // MIPS/musl cross builds keep working (aws-lc-rs needs a C toolchain).
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Install the global logger first so every subsequent record is both
    // written to stderr and made available to the `/api/logs` stream. The
    // configured level is applied once the configuration is read below.
    let log_handle = logging::init(logging::LogLevel::default().to_level_filter());

    // We use reqwest instead of hyper's client to perform most of the proxying as it's more convenient
    // to handle compression as well as offers a more convenient interface.
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .redirect(Policy::none())
        .no_proxy()
        .gzip(true)
        .brotli(true)
        .deflate(true)
        // Without these, a proxied request can hang indefinitely on a pooled
        // keep-alive connection the remote has silently dropped: reqwest reuses
        // the dead connection and waits on a peer that will never answer.
        // Retiring idle connections quickly (well under typical server keep-alive
        // windows) plus OS-level keepalive probes bounds that. `connect_timeout`
        // additionally fails fast on unreachable hosts.
        .connect_timeout(Duration::from_secs(10))
        .pool_idle_timeout(Duration::from_secs(30))
        // Bounds a stalled read mid-response: a peer that stops sending without
        // closing would otherwise hang the proxied request forever. Generous
        // enough (5 minutes between reads) not to kill long-polls or quiet SSE
        // streams, which routinely idle for a minute or two between events.
        .read_timeout(Duration::from_secs(300))
        // h2-heavy origins multiplex every subresource over a
        // single connection whose flow-control window defaults to a small,
        // shared 64 KB. When we drain one stream's body slowly (the browser
        // reads slowly, or the HTML rewriter backpressures), that window fills
        // and stalls *every other stream* on the connection — head-of-line
        // stutter across the whole site. Adaptive flow control grows the
        // stream/connection windows based on the bandwidth-delay product,
        // relieving the stall while keeping multiplexing. (This overrides any
        // manual http2_initial_*_window_size, which is why none are set.)
        .http2_adaptive_window(true)
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

    // Apply the persisted application log level now that configuration is
    // available; the web UI can change it on the fly afterwards.
    log_handle.set_level(configuration.debug.log_level.to_level_filter());

    let local_exclusion_store =
        LocalExclusionStore::new(Vec::from_iter(configuration.exclusions.clone()));
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

    let statistics = statistics::Statistics::new();
    let statistics_clone = statistics.clone();

    let tls_failure_store = TlsFailureStore::new(configuration.ignored_tls_failures.clone());
    let tls_failure_store_clone = tls_failure_store.clone();

    let filter_failure_store = FilterFailureStore::new();
    let filter_failure_store_clone = filter_failure_store.clone();

    // Compiled up-front so the first page load already has its userscripts;
    // the store is then mutated in place by the API and re-read per request.
    let user_script_store = UserScriptStore::new(
        proxy::userscripts::compile_active_userscripts(&configuration, &client).await,
    );
    let user_script_store_clone = user_script_store.clone();

    // Persistent GM_setValue data, loaded once and flushed on a debounce.
    let gm_storage = GmStorageStore::load().await;
    let gm_storage_clone = gm_storage.clone();

    let private_network_access =
        PrivateNetworkAccess::new(configuration.userscripts.allow_private_network_requests);

    let (broadcast_tx, _broadcast_rx) = broadcast::channel(32);
    let broadcast_tx_clone = broadcast_tx.clone();

    let blocking_disabled_store =
        blocker::BlockingDisabledStore(Arc::new(std::sync::RwLock::new(false)));
    let blocking_disabled_store_clone = blocking_disabled_store.clone();

    // The adblock engine is shared directly with every request task (adblock's
    // `Engine` is Send + Sync); filter updates build a replacement engine on
    // the blocking pool and swap it in atomically.
    let blocker_requester = AdblockRequester::new(blocking_disabled_store.clone());

    let configuration_updater = configuration::ConfigurationUpdater::new(
        configuration.clone(),
        client.clone(),
        blocker_requester.clone(),
        filter_failure_store.clone(),
        user_script_store.clone(),
        None,
    )
    .await;

    let configuration_updater_tx = configuration_updater.tx.clone();
    configuration_updater_tx.send(configuration).await.unwrap();

    configuration_updater.start();

    let configuration_save_lock = Arc::new(tokio::sync::Mutex::new(()));

    let (_notify_shutdown, notify_reload) = handle_signals().await;

    let block_disable_ref = blocking_disabled_store.clone();
    let local_exclusion_store_ref = local_exclusion_store.clone();
    let tls_failure_store_ref = tls_failure_store.clone();
    let filter_failure_store_ref = filter_failure_store.clone();
    let user_script_store_ref = user_script_store.clone();
    let gm_storage_ref = gm_storage.clone();
    let private_network_access_ref = private_network_access.clone();
    let stats_clone = statistics.clone();
    let configuration_updater_tx_ref = configuration_updater_tx.clone();
    let configuration_save_lock_ref = configuration_save_lock.clone();
    let broadcast_tx_ref = broadcast_tx.clone();
    let log_handle_ref = log_handle.clone();
    let notify_reload_clone = notify_reload.clone();

    tokio::spawn(async move {
        let notify_reload_frontend = notify_reload_clone.clone();
        let cfg_lock_frontend = configuration_save_lock_ref.clone();
        loop {
            log::info!("Starting Privaxy frontend");
            privaxy_frontend(
                broadcast_tx_ref.clone(),
                local_exclusion_store_ref.clone(),
                tls_failure_store_ref.clone(),
                filter_failure_store_ref.clone(),
                user_script_store_ref.clone(),
                gm_storage_ref.clone(),
                private_network_access_ref.clone(),
                stats_clone.clone(),
                block_disable_ref.clone(),
                configuration_updater_tx_ref.clone(),
                cfg_lock_frontend.clone(),
                notify_reload_frontend.clone(),
                log_handle_ref.clone(),
            )
            .await;
            notify_reload_frontend.notified().await;
            log::info!("Stopping Privaxy frontend");
        }
    });

    let notify_reload_clone = notify_reload.clone();
    let configuration_save_lock_ref = configuration_save_lock.clone();

    tokio::spawn(async move {
        let notify_reload_backend = notify_reload_clone.clone();
        let cfg_lock_backend = configuration_save_lock_ref.clone();
        let mut local_exclusion_store = local_exclusion_store;
        let mut rt_cert_cache =
            cert::CertCache::new(ca_certificate.clone(), ca_private_key.clone());
        let mut rt_ca_certificate = ca_certificate;
        loop {
            log::info!("Starting Privaxy proxy");
            privaxy_backend(
                client.clone(),
                rt_cert_cache.clone(),
                blocker_requester.clone(),
                broadcast_tx.clone(),
                statistics.clone(),
                local_exclusion_store.clone(),
                tls_failure_store.clone(),
                user_script_store.clone(),
                gm_storage.clone(),
                private_network_access.clone(),
                cfg_lock_backend.clone(),
                notify_reload_backend.clone(),
            )
            .await;
            let cfg = match read_configuration(&cfg_lock_backend).await {
                Ok(cfg) => cfg,
                Err(err) => {
                    // Keep running with the stores as they are and try again on
                    // the next reload, rather than tearing down a working proxy
                    // because someone mistyped the configuration file.
                    log::error!(
                        "Not applying configuration on reload, it could not be read: {err}. \
                         Continuing with the previous settings."
                    );
                    continue;
                }
            };
            // The exclusion store is only otherwise mutated by the web UI
            // route; without this refresh, exclusions edited in the
            // configuration file never take effect on SIGHUP reload.
            local_exclusion_store.replace_exclusions(Vec::from_iter(cfg.exclusions.clone()));
            // Same for the TLS-failure ignore set: pick up hand-edited
            // `ignored_tls_failures` entries on SIGHUP reload.
            tls_failure_store.set_ignored(cfg.ignored_tls_failures.clone());
            // The API replaces the userscript store in place on every change,
            // so this refresh exists for the other path: a `[userscripts]`
            // section edited directly in the configuration file.
            proxy::userscripts::reload_userscripts(&user_script_store, &cfg, &client).await;
            private_network_access.set(cfg.userscripts.allow_private_network_requests);
            // A CA that no longer decodes must not bring the proxy down either;
            // the existing cert cache stays in use.
            match (
                cfg.ca.get_ca_certificate().await,
                cfg.ca.get_ca_private_key().await,
            ) {
                (Ok(ca_cert), Ok(ca_key)) => match rt_ca_certificate.public_key() {
                    Ok(current_public_key) if ca_key.public_eq(&current_public_key) => {}
                    _ => {
                        rt_ca_certificate = ca_cert.clone();
                        rt_cert_cache = cert::CertCache::new(ca_cert, ca_key);
                    }
                },
                _ => log::error!(
                    "Keeping the previous CA: the configured certificate or key could not be read"
                ),
            }
        }
    });
    PrivaxyServer {
        ca_certificate_pem,
        configuration_updater_sender: configuration_updater_tx,
        configuration_save_lock,
        blocking_disabled_store: blocking_disabled_store_clone,
        statistics: statistics_clone,
        local_exclusion_store: local_exclusion_store_clone,
        tls_failure_store: tls_failure_store_clone,
        filter_failure_store: filter_failure_store_clone,
        user_script_store: user_script_store_clone,
        gm_storage: gm_storage_clone,
        requests_broadcast_sender: broadcast_tx_clone,
    }
}

#[allow(clippy::too_many_arguments)]
async fn privaxy_frontend(
    broadcast_tx: tokio::sync::broadcast::Sender<Event>,
    local_exclusion_store: LocalExclusionStore,
    tls_failure_store: TlsFailureStore,
    filter_failure_store: FilterFailureStore,
    user_script_store: UserScriptStore,
    gm_storage: GmStorageStore,
    private_network_access: PrivateNetworkAccess,
    statistics: statistics::Statistics,
    block_disable_ref: blocker::BlockingDisabledStore,
    configuration_updater_tx: tokio::sync::mpsc::Sender<configuration::Configuration>,
    configuration_save_lock: Arc<tokio::sync::Mutex<()>>,
    notify_reload: Arc<tokio::sync::Notify>,
    log_handle: logging::LogHandle,
) {
    let frontend = web_gui::get_frontend(
        broadcast_tx.clone(),
        statistics.clone(),
        &block_disable_ref,
        &configuration_updater_tx,
        &configuration_save_lock,
        &local_exclusion_store,
        &tls_failure_store,
        &filter_failure_store,
        &user_script_store,
        &gm_storage,
        &private_network_access,
        notify_reload.clone(),
        log_handle.clone(),
    );
    let config = match read_configuration(&configuration_save_lock).await {
        Ok(config) => config,
        Err(err) => {
            // Without a configuration there is nothing to bind to. Wait for the
            // next reload rather than returning immediately, which would spin
            // the surrounding loop as fast as it can restart us.
            log::error!("Cannot start the frontend, the configuration could not be read: {err}");
            notify_reload.notified().await;
            return;
        }
    };
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
        let server_config = web_tls_server_config(&tls_cert, &tls_key);
        tokio::spawn(async move {
            serve_frontend(
                frontend,
                web_api_server_addr,
                Some(server_config),
                async move {
                    notify_reload.clone().notified().await;
                },
            )
            .await;
        });
    } else {
        tokio::spawn(async move {
            serve_frontend(frontend, web_api_server_addr, None, async move {
                let _ = notify_reload.clone().notified().await;
            })
            .await;
        });
    }
}

/// Build a rustls `ServerConfig` for the web GUI from the OpenSSL-generated
/// TLS leaf certificate and key. warp 0.4 dropped its built-in `.tls()`
/// support, so the HTTPS web GUI now terminates TLS via `tokio-rustls` and is
/// served through hyper-util (see `serve_frontend_tls`).
fn web_tls_server_config(
    cert: &openssl::x509::X509,
    key: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
) -> rustls::ServerConfig {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let certs = vec![CertificateDer::from(cert.to_der().unwrap())];
    let key = PrivateKeyDer::try_from(key.private_key_to_der().unwrap()).unwrap();
    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("valid web GUI TLS certificate/key")
}

/// Serve the warp frontend filter, optionally over TLS. warp 0.4 dropped both
/// its built-in `.tls()` support and the high-level graceful-shutdown server,
/// so we accept connections ourselves, optionally terminate TLS with
/// `tokio-rustls`, and drive each connection with hyper-util's auto builder
/// (HTTP/1+2, with upgrade support so the WebSocket-based live feeds keep
/// working).
async fn serve_frontend<F, S>(
    frontend: F,
    addr: SocketAddr,
    tls_config: Option<rustls::ServerConfig>,
    shutdown: S,
) where
    F: warp::Filter + Clone + Send + Sync + 'static,
    F::Extract: warp::reply::Reply,
    S: std::future::Future<Output = ()> + Send + 'static,
{
    use tokio_rustls::TlsAcceptor;

    let listener = match TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(err) => {
            log::error!("Unable to bind web GUI to {}: {}", addr, err);
            return;
        }
    };
    let scheme = if tls_config.is_some() {
        "https"
    } else {
        "http"
    };
    log::info!("Web server available at {scheme}://{addr}/");
    log::info!("API server available at {scheme}://{addr}/api");

    let tls_acceptor = tls_config.map(|config| TlsAcceptor::from(Arc::new(config)));
    let warp_service = warp::service(frontend);
    let graceful = GracefulShutdown::new();

    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _peer) = match accepted {
                    Ok(pair) => pair,
                    Err(err) => {
                        log::warn!("Failed to accept web GUI connection: {}", err);
                        continue;
                    }
                };
                let tls_acceptor = tls_acceptor.clone();
                let hyper_service =
                    hyper_util::service::TowerToHyperService::new(warp_service.clone());
                let watcher = graceful.watcher();
                tokio::spawn(async move {
                    let builder = auto::Builder::new(TokioExecutor::new());
                    match tls_acceptor {
                        Some(tls_acceptor) => {
                            let tls_stream = match tls_acceptor.accept(stream).await {
                                Ok(tls_stream) => tls_stream,
                                Err(err) => {
                                    log::debug!("Web GUI TLS handshake failed: {}", err);
                                    return;
                                }
                            };
                            let connection = builder.serve_connection_with_upgrades(
                                TokioIo::new(tls_stream),
                                hyper_service,
                            );
                            let _ = watcher.watch(connection.into_owned()).await;
                        }
                        None => {
                            let connection = builder.serve_connection_with_upgrades(
                                TokioIo::new(stream),
                                hyper_service,
                            );
                            let _ = watcher.watch(connection.into_owned()).await;
                        }
                    }
                });
            }
            _ = &mut shutdown => {
                break;
            }
        }
    }

    graceful.shutdown().await;
}

/// The last configuration that parsed.
///
/// `SIGHUP` tears the server loops down before anything has looked at the new
/// file, so a configuration that fails to parse would otherwise leave both
/// listeners closed until the next signal. Keeping the previous one lets a reload
/// over a broken file degrade to "carry on with the old settings".
static LAST_GOOD_CONFIGURATION: std::sync::Mutex<Option<configuration::Configuration>> =
    std::sync::Mutex::new(None);

/// Read the configuration from disk under the save lock, falling back to the
/// last one that parsed.
///
/// Returns an error rather than unwrapping: a hand-edited configuration with a
/// syntax error (a duplicate TOML key, say) used to panic a worker here, which
/// took both server loops down while the process kept running — ports stopped
/// listening with no way back short of a restart. An error now only surfaces
/// when there is no previous configuration to fall back on, i.e. at startup,
/// where there is genuinely nothing to serve.
async fn read_configuration(
    configuration_save_lock: &Arc<tokio::sync::Mutex<()>>,
) -> configuration::ConfigurationResult<configuration::Configuration> {
    let lock = configuration_save_lock.lock().await;
    let result = configuration::Configuration::read_from_home().await;
    drop(lock);

    match result {
        Ok(config) => {
            *LAST_GOOD_CONFIGURATION.lock().unwrap() = Some(config.clone());
            Ok(config)
        }
        Err(err) => match LAST_GOOD_CONFIGURATION.lock().unwrap().clone() {
            Some(previous) => {
                log::error!(
                    "The configuration file could not be read ({err}); continuing with the last \
                     settings that loaded. Fix the file and reload again to apply it."
                );
                Ok(previous)
            }
            None => Err(err),
        },
    }
}
async fn env_or_config_ip(network_config: &NetworkConfig) -> IpAddr {
    match env::var("PRIVAXY_IP_ADDRESS") {
        Ok(val) => parse_ip_address(&val),
        Err(_) => network_config.parsed_ip_address(),
    }
}

/// Bracket IPv6 addresses so they are usable as the host part of a URL.
fn format_ip_host(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => format!("[{ip}]"),
    }
}

/// Where the web GUI can be reached from a proxied client's point of view.
/// Used to build links back to the GUI (e.g. the "Exclude this host" button on
/// proxy error pages). When the GUI listens on an unspecified address and no
/// FQDN is configured, the host is only known per connection — from the local
/// address the client dialed — hence `base_url` taking it as a parameter.
#[derive(Debug, Clone)]
pub(crate) struct WebGuiUrl {
    /// Operator-declared full base URL, used verbatim when set. This is the
    /// only variant that can express a reverse-proxied GUI (different port,
    /// or a host the server never sees, e.g. behind Docker NAT).
    override_url: Option<String>,
    scheme: &'static str,
    configured_host: Option<String>,
    web_port: u16,
}

impl WebGuiUrl {
    async fn from_network_config(network: &NetworkConfig) -> Self {
        let override_url = network
            .gui_url
            .as_ref()
            .map(|url| url.trim().trim_end_matches('/').to_string())
            .filter(|url| !url.is_empty());
        let scheme = if network.tls { "https" } else { "http" };
        let configured_host = match network.listen_url.clone() {
            // An operator-declared FQDN wins over any bound address.
            Some(listen_url) => Some(listen_url),
            None => {
                let ip = env_or_config_ip(network).await;
                if ip.is_unspecified() {
                    None
                } else {
                    Some(format_ip_host(ip))
                }
            }
        };

        Self {
            override_url,
            scheme,
            configured_host,
            web_port: network.web_port,
        }
    }

    fn base_url(&self, dialed_ip: Option<IpAddr>) -> Option<String> {
        if let Some(url) = &self.override_url {
            return Some(url.clone());
        }
        let host = match &self.configured_host {
            Some(host) => host.clone(),
            None => format_ip_host(dialed_ip?),
        };
        let scheme = self.scheme;
        let web_port = self.web_port;

        Some(format!("{scheme}://{host}:{web_port}"))
    }
}

#[allow(clippy::too_many_arguments)]
async fn privaxy_backend(
    client: reqwest::Client,
    cert_cache: cert::CertCache,
    blocker_requester: AdblockRequester,
    broadcast_tx: broadcast::Sender<Event>,
    statistics: statistics::Statistics,
    local_exclusion_store: LocalExclusionStore,
    tls_failure_store: TlsFailureStore,
    user_script_store: UserScriptStore,
    gm_storage: GmStorageStore,
    private_network_access: PrivateNetworkAccess,
    configuration_save_lock: Arc<tokio::sync::Mutex<()>>,
    notify_reload: Arc<tokio::sync::Notify>,
) {
    // Mirror the reqwest client's connection hardening (see above): without a
    // connect timeout and OS-level keepalive, an upgrade can hang on a pooled
    // keep-alive connection the remote has silently dropped, surfacing as
    // "upgrade expected but not completed".
    let mut http_connector = hyper_util::client::legacy::connect::HttpConnector::new();
    http_connector.enforce_http(false);
    http_connector.set_connect_timeout(Some(Duration::from_secs(10)));
    http_connector.set_keepalive(Some(Duration::from_secs(60)));

    let https_connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()
        .expect("failed to load native root certificates")
        .https_or_http()
        .enable_http1()
        .wrap_connector(http_connector);
    let config = match read_configuration(&configuration_save_lock).await {
        Ok(config) => config,
        Err(err) => {
            // As in the frontend loop: nothing to bind to, and returning at once
            // would spin the caller's restart loop.
            log::error!("Cannot start the proxy, the configuration could not be read: {err}");
            notify_reload.notified().await;
            return;
        }
    };
    let network_config = &config.network;
    let web_gui_url = WebGuiUrl::from_network_config(network_config).await;
    let doh_config = network_config.doh.clone();
    // Read once per (re)start; the backend loop re-runs this on reload, so
    // toggling the setting in the UI takes effect after its notify_reload.
    let scriptlet_debug_logging = config.debug.scriptlet_console_logging;

    // Everything the request path needs for userscripts. The signing key is
    // captured here so minting (at injection) and verification (on the reserved
    // endpoint) always agree, even if the stored key is rotated mid-run: both
    // sides keep using this copy until the next reload.
    let user_scripts = UserScriptContext {
        store: user_script_store,
        gm_storage,
        endpoint_signing_key: config.auth.session_signing_key.clone(),
        allow_private_network_requests: private_network_access,
    };

    // The hyper client is only used to perform upgrades. We don't need to
    // handle compression.
    // Hyper's client don't follow redirects, which is what we want, nothing to
    // disable here.
    // An upgraded connection is consumed by the tunnel anyway, so idle pooling
    // buys nothing and only risks reusing a stale connection under a long-lived
    // WebSocket — disable it.
    let hyper_client: UpgradeClient = Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(0)
        .build(https_connector);

    let ip = env_or_config_ip(network_config).await;
    let proxy_server_addr = SocketAddr::from((ip, network_config.proxy_port));

    // hyper 1.0 removed the high-level `Server`; we accept connections by hand
    // and drive each one with hyper-util's auto (HTTP/1+2) builder. The old
    // `Server::tcp_keepalive`/`http1_*` knobs are reproduced below.
    let listener = match TcpListener::bind(proxy_server_addr).await {
        Ok(listener) => listener,
        Err(err) => {
            log::error!("Unable to bind proxy to {}: {}", proxy_server_addr, err);
            return;
        }
    };
    log::info!("Proxy available at http://{}", proxy_server_addr);

    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .preserve_header_case(true)
        .title_case_headers(true);
    let graceful = GracefulShutdown::new();

    let shutdown = async move {
        let _ = notify_reload.clone().notified().await;
        log::info!("Stopping Privaxy proxy");
    };
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer_addr) = match accepted {
                    Ok(pair) => pair,
                    Err(err) => {
                        log::warn!("Failed to accept proxy connection: {}", err);
                        continue;
                    }
                };

                // Reproduce the old `Server::tcp_keepalive(600s)`: enable
                // OS-level keepalive on each accepted socket.
                let _ = socket2::SockRef::from(&stream).set_tcp_keepalive(
                    &socket2::TcpKeepalive::new().with_time(Duration::from_secs(600)),
                );

                let client_ip_address = peer_addr.ip();
                let client = client.clone();
                let hyper_client = hyper_client.clone();
                let cert_cache = cert_cache.clone();
                let blocker_requester = blocker_requester.clone();
                let broadcast_tx = broadcast_tx.clone();
                let statistics = statistics.clone();
                let local_exclusion_store = local_exclusion_store.clone();
                let tls_failure_store = tls_failure_store.clone();
                let user_scripts = user_scripts.clone();
                let doh_config = doh_config.clone();
                // The address the client dialed to reach the proxy is the best
                // guess for a GUI host when none is configured; it must be read
                // before the stream is consumed by the connection below.
                let gui_base_url =
                    web_gui_url.base_url(stream.local_addr().ok().map(|addr| addr.ip()));

                let service = service_fn(move |req| {
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
                        doh_config.clone(),
                        scriptlet_debug_logging,
                        tls_failure_store.clone(),
                        gui_base_url.clone(),
                        user_scripts.clone(),
                    )
                });

                let connection = builder
                    .serve_connection_with_upgrades(TokioIo::new(stream), service);
                let watched = graceful.watch(connection.into_owned());
                tokio::spawn(async move {
                    let _ = watched.await;
                });
            }
            _ = &mut shutdown => {
                break;
            }
        }
    }

    graceful.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gui_url(configured_host: Option<&str>, tls: bool) -> WebGuiUrl {
        WebGuiUrl {
            override_url: None,
            scheme: if tls { "https" } else { "http" },
            configured_host: configured_host.map(str::to_string),
            web_port: 8200,
        }
    }

    #[test]
    fn base_url_prefers_override_url_over_everything() {
        let mut url = gui_url(Some("privaxy.lan"), false);
        url.override_url = Some("http://proxy.lan".to_string());
        assert_eq!(
            url.base_url(Some("172.17.0.2".parse().unwrap())),
            Some("http://proxy.lan".to_string())
        );
    }

    #[test]
    fn base_url_prefers_configured_host_over_dialed_ip() {
        let url = gui_url(Some("privaxy.lan"), false);
        assert_eq!(
            url.base_url(Some("192.168.1.2".parse().unwrap())),
            Some("http://privaxy.lan:8200".to_string())
        );
    }

    #[test]
    fn base_url_falls_back_to_dialed_ip_and_brackets_ipv6() {
        let url = gui_url(None, false);
        assert_eq!(
            url.base_url(Some("192.168.1.2".parse().unwrap())),
            Some("http://192.168.1.2:8200".to_string())
        );
        assert_eq!(
            url.base_url(Some("fd00::1".parse().unwrap())),
            Some("http://[fd00::1]:8200".to_string())
        );
    }

    #[test]
    fn base_url_is_none_without_any_host() {
        assert_eq!(gui_url(None, false).base_url(None), None);
    }

    #[test]
    fn base_url_uses_https_scheme_when_tls_enabled() {
        let url = gui_url(Some("privaxy.lan"), true);
        assert_eq!(
            url.base_url(None),
            Some("https://privaxy.lan:8200".to_string())
        );
    }
}
