use super::{exclusions::LocalExclusionStore, serve::serve};
use crate::{blocker::AdblockRequester, cert::CertCache, statistics::Statistics, Event};
use http::uri::{Authority, Scheme};
use hyper::{
    client::HttpConnector, http, server::conn::Http, service::service_fn, upgrade::Upgraded, Body,
    Method, Request, Response,
};
use hyper_rustls::HttpsConnector;
use std::{net::IpAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::broadcast,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;
use futures_util::pin_mut;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const BUFFER_SIZE: usize = 64 * 1024; // 64KB buffer

#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve_mitm_session(
    adblock_requester: AdblockRequester,
    hyper_client: hyper::Client<HttpsConnector<HttpConnector>>,
    client: reqwest::Client,
    req: Request<Body>,
    cert_cache: CertCache,
    broadcast_tx: broadcast::Sender<Event>,
    statistics: Statistics,
    client_ip_address: IpAddr,
    local_exclusion_store: LocalExclusionStore,
) -> Result<Response<Body>, hyper::Error> {
    let authority = match req.uri().authority().cloned() {
        Some(authority) => authority,
        None => {
            log::warn!("Received a request without proper authority, sending bad request");
            return Ok(Response::builder()
                .status(http::StatusCode::BAD_REQUEST)
                .body(Body::empty())
                .unwrap());
        }
    };

    if Method::CONNECT == req.method() {
        // Handle HTTPS CONNECT requests
        let server_configuration = Arc::new(cert_cache.get(authority.clone()).await.server_configuration);

        tokio::spawn(async move {
            if let Ok(upgraded) = hyper::upgrade::on(req).await {
                if local_exclusion_store.contains(authority.host()) {
                    if let Err(e) = handle_tunnel(upgraded, &authority).await {
                        log::debug!("Tunnel error for {}: {}", authority, e);
                    }
                    return;
                }

                handle_tls_connection(
                    upgraded,
                    server_configuration,
                    authority.clone(),
                    adblock_requester,
                    hyper_client,
                    client,
                    broadcast_tx,
                    statistics,
                    client_ip_address,
                )
                .await;
            }
        });

        Ok(Response::new(Body::empty()))
    } else {
        // Handle regular HTTP requests
        serve(
            adblock_requester,
            req,
            hyper_client,
            client,
            authority,
            Scheme::HTTP,
            broadcast_tx,
            statistics,
            client_ip_address,
        )
        .await
    }
}

async fn handle_tls_connection(
    upgraded: Upgraded,
    server_configuration: Arc<rustls::ServerConfig>,
    authority: Authority,
    adblock_requester: AdblockRequester,
    hyper_client: hyper::Client<HttpsConnector<HttpConnector>>,
    client: reqwest::Client,
    broadcast_tx: broadcast::Sender<Event>,
    statistics: Statistics,
    client_ip_address: IpAddr,
) {
    let http = Http::new();

    match timeout(
        Duration::from_secs(5),
        TlsAcceptor::from(server_configuration).accept(upgraded),
    )
    .await
    {
        Ok(Ok(tls_stream)) => {
            let _result = http
                .serve_connection(
                    tls_stream,
                    service_fn(move |req| {
                        serve(
                            adblock_requester.clone(),
                            req,
                            hyper_client.clone(),
                            client.clone(),
                            authority.clone(),
                            Scheme::HTTPS,
                            broadcast_tx.clone(),
                            statistics.clone(),
                            client_ip_address,
                        )
                    }),
                )
                .with_upgrades()
                .await;
        }
        Ok(Err(error)) => {
            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                log::warn!(
                    "TLS handshake failed for {}: {}",
                    authority,
                    error
                );
            } else {
                log::error!("TLS error for {}: {}", authority, error);
            }
        }
        Err(_) => {
            log::warn!("TLS handshake timed out for {}", authority);
        }
    }
}

async fn handle_tunnel(upgraded: Upgraded, authority: &Authority) -> std::io::Result<()> {
    // Connect to the target server with timeout
    let addr = format!("{}:{}", authority.host(), authority.port_u16().unwrap_or(443));
    let mut server = match timeout(CONNECT_TIMEOUT, TcpStream::connect(&addr)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            log::warn!("Failed to connect to {}: {}", authority, e);
            return Err(e);
        }
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("Connection to {} timed out", authority),
            ));
        }
    };

    // Set TCP options for better performance
    server.set_nodelay(true)?;

    // Create separate buffers for client->server and server->client
    let (mut client_rx, mut client_tx) = tokio::io::split(upgraded);
    let (mut server_rx, mut server_tx) = server.split();

    // Create the two copy futures
    let client_to_server = async {
        let mut buffer = [0u8; BUFFER_SIZE];
        loop {
            match client_rx.read(&mut buffer).await {
                Ok(0) => break Ok(()), // EOF
                Ok(n) => {
                    if let Err(e) = server_tx.write_all(&buffer[..n]).await {
                        break Err(e);
                    }
                }
                Err(e) => break Err(e),
            }
        }
    };

    let server_to_client = async {
        let mut buffer = [0u8; BUFFER_SIZE];
        loop {
            match server_rx.read(&mut buffer).await {
                Ok(0) => break Ok(()), // EOF
                Ok(n) => {
                    if let Err(e) = client_tx.write_all(&buffer[..n]).await {
                        break Err(e);
                    }
                }
                Err(e) => break Err(e),
            }
        }
    };

    // Run both copies concurrently
    pin_mut!(client_to_server, server_to_client);
    match futures_util::future::try_join(client_to_server, server_to_client).await {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}
