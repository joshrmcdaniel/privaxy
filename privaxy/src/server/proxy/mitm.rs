use super::{exclusions::LocalExclusionStore, serve::serve};
use crate::{
    blocker::AdblockRequester, cert::CertCache, configuration::DohConfig, statistics::Statistics,
    Event,
};
use http::uri::{Authority, Scheme};
use hyper::{
    client::HttpConnector, http, server::conn::Http, service::service_fn, upgrade::Upgraded, Body,
    Method, Request, Response,
};
use hyper_rustls::HttpsConnector;
use std::{net::IpAddr, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::broadcast,
};
use tokio_rustls::TlsAcceptor;

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
    doh_config: DohConfig,
    scriptlet_debug_logging: bool,
) -> Result<Response<Body>, hyper::Error> {
    let authority = match req.uri().authority().cloned() {
        Some(authority) => authority,
        None => {
            let mut response = Response::new(Body::empty());
            *response.status_mut() = http::StatusCode::BAD_REQUEST;

            log::warn!("Received a request without proper authority, sending bad request");

            return Ok(response);
        }
    };

    if Method::CONNECT == req.method() {
        // Received an HTTP request like:
        // ```
        // CONNECT www.domain.com:443 HTTP/1.1
        // Host: www.domain.com:443
        // Proxy-Connection: Keep-Alive
        // ```
        //
        // When HTTP method is CONNECT we should return an empty body
        // then we can eventually upgrade the connection and talk a new protocol.
        let server_configuration =
            Arc::new(cert_cache.get(authority.clone()).await.server_configuration);

        tokio::task::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(mut upgraded) => {
                    let is_host_blacklisted = local_exclusion_store.contains(authority.host());

                    if is_host_blacklisted {
                        let _result = tunnel(&mut upgraded, &authority).await;

                        return;
                    }

                    let http = Http::new();

                    match TlsAcceptor::from(server_configuration)
                        .accept(upgraded)
                        .await
                    {
                        Ok(tls_stream) => {
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
                                            doh_config.clone(),
                                            scriptlet_debug_logging,
                                        )
                                    }),
                                )
                                .with_upgrades()
                                .await;
                        }
                        // Couldn't perform the tls handshake, they may only support TLS features that we don't or
                        // make use of untrusted certificates. Let's add them to a blacklist so we'll be able to
                        // tunnel them instead of trying to perform MITM.
                        // No blocking will be able to be performed.
                        Err(error) => {
                            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                                log::warn!("Unable to perform handshake for host: {}. Consider excluding it from blocking. The service may not tolerate TLS interception.", authority);
                            }
                        }
                    }
                }
                Err(e) => log::error!("upgrade error: {}", e),
            }
        });

        Ok(Response::new(Body::empty()))
    } else if local_exclusion_store.contains(authority.host())
        && req.headers().contains_key(http::header::UPGRADE)
    {
        // An excluded host performing a protocol upgrade over plain HTTP — e.g.
        // WeChat's MMTLS long-link (`http://dns.weixin.qq.com/mmtls/...`), which
        // speaks a proprietary, non-HTTP protocol once upgraded. The hyper-based
        // bridge in `serve` can't carry that (the upstream never returns a clean
        // `101`, so the upgrade "expected but not completed"). Blind-tunnel the
        // bytes at the TCP level instead, the same way excluded CONNECT hosts
        // are tunneled.
        tunnel_http_upgrade(req, authority).await
    } else {
        // The request is not of method `CONNECT`. Therefore,
        // this request is for an HTTP resource.
        //
        // An opaque (non-WebSocket) protocol upgrade to a host that is *not*
        // excluded will be routed through `serve`, whose hyper bridge cannot
        // carry a non-HTTP protocol — it will hang or fail. We can't safely
        // tunnel it (the user hasn't opted the host out of filtering), so warn
        // and let it proceed, pointing the user at the exclusion list.
        if is_opaque_upgrade(req.headers()) {
            log::warn!(
                "Proxying opaque protocol-upgrade traffic (MMTLS?) for {}; \
                 this is unlikely to work through the MITM proxy. Consider adding the host \
                 to your exclusions.",
                authority
            );
        }

        serve(
            adblock_requester,
            req,
            hyper_client.clone(),
            client.clone(),
            authority,
            Scheme::HTTP,
            broadcast_tx,
            statistics,
            client_ip_address,
            doh_config,
            scriptlet_debug_logging,
        )
        .await
    }
}

/// An HTTP `Upgrade` request whose target protocol is something other than
/// WebSocket (or h2c) — e.g. WeChat's MMTLS long-link. The proxy can't do
/// anything useful with such a protocol, and its hyper-based upgrade bridge
/// can't carry it; these are only handled correctly by blind-tunneling, which
/// requires the host to be excluded.
fn is_opaque_upgrade(headers: &http::HeaderMap) -> bool {
    headers
        .get(http::header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            // The Upgrade header may list multiple comma-separated tokens, each
            // optionally `name/version`. Treat it as opaque only if no token is
            // a protocol we can actually bridge.
            value.split(',').all(|token| {
                let name = token.trim().split('/').next().unwrap_or("").trim();
                !name.eq_ignore_ascii_case("websocket") && !name.eq_ignore_ascii_case("h2c")
            })
        })
        .unwrap_or(false)
}

/// Blind-tunnel a plain-HTTP protocol upgrade to an excluded host. The proxied
/// request carries an absolute-form URI; we replay it to the upstream in
/// origin-form over a raw socket, return our own `101` to the client, and pipe
/// the (opaque) post-upgrade bytes both ways. The upstream's own `101` header
/// block is discarded so the client sees exactly one status line.
///
/// thank you, wechat, for making this necessary
async fn tunnel_http_upgrade(
    req: Request<Body>,
    authority: Authority,
) -> Result<Response<Body>, hyper::Error> {
    // Build the origin-form request head before `req` is moved into the task.
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let mut head = format!("{} {} HTTP/1.1\r\n", req.method(), path);
    for (name, value) in req.headers() {
        head.push_str(name.as_str());
        head.push_str(": ");
        // Header values are effectively always ASCII here; lossy conversion just
        // avoids failing the replay on a pathological non-UTF8 value.
        head.push_str(&String::from_utf8_lossy(value.as_bytes()));
        head.push_str("\r\n");
    }
    head.push_str("\r\n");

    let upgrade_value = req.headers().get(http::header::UPGRADE).cloned();

    // The bridge runs detached: `hyper::upgrade::on` only resolves once we have
    // returned the `101` below, so awaiting it here would deadlock.
    tokio::spawn(async move {
        match bridge_http_upgrade(req, head, &authority).await {
            Ok(()) => log::debug!("HTTP-upgrade tunnel closed for {}", authority),
            Err(e) => log::warn!("HTTP-upgrade tunnel for {} failed: {}", authority, e),
        }
    });

    let mut response = Response::new(Body::empty());
    *response.status_mut() = http::StatusCode::SWITCHING_PROTOCOLS;
    response.headers_mut().insert(
        http::header::CONNECTION,
        http::HeaderValue::from_static("upgrade"),
    );
    if let Some(upgrade) = upgrade_value {
        response.headers_mut().insert(http::header::UPGRADE, upgrade);
    }
    Ok(response)
}

/// Upstream half of `tunnel_http_upgrade`: wait for the client upgrade, connect
/// to the origin, replay the request head, strip the origin's `101`, then pipe.
async fn bridge_http_upgrade(
    req: Request<Body>,
    head: String,
    authority: &Authority,
) -> std::io::Result<()> {
    let host = authority.host();
    // Proxied `http://` authorities carry no port; default to 80.
    let port = authority.port_u16().unwrap_or(80);

    let mut client = hyper::upgrade::on(req)
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let mut upstream = TcpStream::connect((host, port)).await?;
    upstream.write_all(head.as_bytes()).await?;

    let leftover = read_past_response_headers(&mut upstream).await?;
    if !leftover.is_empty() {
        client.write_all(&leftover).await?;
    }

    pipe(&mut client, &mut upstream).await
}

/// Read from `stream` until the end of the HTTP response header block
/// (`\r\n\r\n`) and return any bytes that followed it (the start of the tunneled
/// payload). If the upstream closes or never sends a recognizable header block,
/// whatever was read is returned so it can still be forwarded.
async fn read_past_response_headers(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    const HEADER_CAP: usize = 64 * 1024;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];

    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Ok(buf);
        }
        buf.extend_from_slice(&chunk[..n]);

        if let Some(pos) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
            return Ok(buf.split_off(pos + 4));
        }
        if buf.len() > HEADER_CAP {
            // No header terminator in a sane amount of data; treat everything as
            // payload rather than stalling.
            return Ok(buf);
        }
    }
}

async fn tunnel(upgraded: &mut Upgraded, authority: &Authority) -> std::io::Result<()> {
    let mut server = TcpStream::connect(authority.to_string()).await?;

    log::debug!("Started tunneling host: {}", authority);

    pipe(upgraded, &mut server).await
}

/// Pipe two duplex streams in both directions until either side closes.
async fn pipe<A, B>(a: &mut A, b: &mut B) -> std::io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    tokio::io::copy_bidirectional(a, b).await?;
    Ok(())
}
