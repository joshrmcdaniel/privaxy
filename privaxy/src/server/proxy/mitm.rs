use super::serve::UpgradeClient;
use super::tls_failures::TlsFailureStore;
use super::{empty_body, exclusions::LocalExclusionStore, serve::serve, ProxyBody};
use crate::{
    blocker::AdblockRequester, cert::CertCache, configuration::DohConfig, statistics::Statistics,
    Event,
};
use http::uri::{Authority, Scheme};
use http::{Method, Request, Response};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use std::{net::IpAddr, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::broadcast,
};
use tokio_rustls::TlsAcceptor;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve_mitm_session(
    adblock_requester: AdblockRequester,
    hyper_client: UpgradeClient,
    client: reqwest::Client,
    req: Request<Incoming>,
    cert_cache: CertCache,
    broadcast_tx: broadcast::Sender<Event>,
    statistics: Statistics,
    client_ip_address: IpAddr,
    local_exclusion_store: LocalExclusionStore,
    doh_config: DohConfig,
    scriptlet_debug_logging: bool,
    tls_failure_store: TlsFailureStore,
    gui_base_url: Option<String>,
) -> Result<Response<ProxyBody>, hyper::Error> {
    let raw_authority = match req.uri().authority().cloned() {
        Some(authority) => authority,
        None => {
            let mut response = Response::new(empty_body());
            *response.status_mut() = http::StatusCode::BAD_REQUEST;

            log::warn!("Received a request without proper authority, sending bad request");

            return Ok(response);
        }
    };

    // Apple's RCS client tunnels to Google's Jibe backend with a service
    // selector embedded in the CONNECT authority — `CONNECT rbm.goog(smsft):443`.
    // The parenthetical is not part of the DNS name, so everything operational
    // (cert minting, exclusion matching, tunneling, outbound requests) works on
    // the sanitized authority; the raw one is kept for logging and for
    // exclusion entries that match the literal client-sent host.
    let authority = sanitize_authority(&raw_authority);

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
        //
        // Excluded hosts are blind-tunneled and never see our interception
        // cert, so minting one would only delay the CONNECT response (cert
        // signing is expensive on low-powered machines).
        let server_configuration =
            if is_authority_excluded(&local_exclusion_store, &authority, &raw_authority) {
                None
            } else {
                Some(Arc::new(
                    cert_cache.get(authority.clone()).await.server_configuration,
                ))
            };

        tokio::task::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    // hyper 1.0's `Upgraded` exposes hyper's own IO traits;
                    // `TokioIo` bridges it to tokio's `AsyncRead`/`AsyncWrite`
                    // (needed both for blind tunneling and the TLS acceptor).
                    let mut upgraded = TokioIo::new(upgraded);

                    let server_configuration = match server_configuration {
                        Some(server_configuration) => server_configuration,
                        None => {
                            // Connect failures are logged inside `tunnel`;
                            // errors surfaced while piping an established
                            // tunnel are routine (resets, aborts) and stay
                            // quiet.
                            let _result = tunnel(&mut upgraded, &authority, &raw_authority).await;

                            return;
                        }
                    };

                    match TlsAcceptor::from(server_configuration)
                        .accept(upgraded)
                        .await
                    {
                        Ok(tls_stream) => {
                            // hyper 1.0 dropped the all-in-one `Http` server
                            // type; `hyper-util`'s auto builder negotiates
                            // HTTP/1 vs HTTP/2 and carries upgrade support.
                            let _result = auto::Builder::new(TokioExecutor::new())
                                .serve_connection_with_upgrades(
                                    TokioIo::new(tls_stream),
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
                                            gui_base_url.clone(),
                                        )
                                    }),
                                )
                                .await;
                        }
                        // Couldn't perform the tls handshake, they may only support TLS features that we don't or
                        // make use of untrusted certificates. Let's add them to a blacklist so we'll be able to
                        // tunnel them instead of trying to perform MITM.
                        // No blocking will be able to be performed.
                        Err(error) => {
                            // The client never completed a TLS session with
                            // us, so it can never be shown an error page —
                            // record the failure so the web GUI can surface
                            // it instead.
                            tls_failure_store.record(
                                authority.host(),
                                &error.to_string(),
                                error.kind() == std::io::ErrorKind::UnexpectedEof,
                            );
                            // UnexpectedEof is the signature of a client that
                            // saw our interception cert and hung up (pinning),
                            // hence the exclusion hint. Other handshake
                            // failures are surfaced too — a silent death here
                            // makes broken hosts undiagnosable.
                            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                                log::warn!("Unable to perform handshake for host: {}. Consider excluding it from blocking. The service may not tolerate TLS interception.", raw_authority);
                            } else {
                                log::warn!(
                                    "TLS interception handshake failed for host {}: {}",
                                    raw_authority,
                                    error
                                );
                            }
                        }
                    }
                }
                Err(e) => log::error!("upgrade error: {}", e),
            }
        });

        Ok(Response::new(empty_body()))
    } else if is_authority_excluded(&local_exclusion_store, &authority, &raw_authority)
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
            gui_base_url,
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
    req: Request<Incoming>,
    authority: Authority,
) -> Result<Response<ProxyBody>, hyper::Error> {
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

    let mut response = Response::new(empty_body());
    *response.status_mut() = http::StatusCode::SWITCHING_PROTOCOLS;
    response.headers_mut().insert(
        http::header::CONNECTION,
        http::HeaderValue::from_static("upgrade"),
    );
    if let Some(upgrade) = upgrade_value {
        response
            .headers_mut()
            .insert(http::header::UPGRADE, upgrade);
    }
    Ok(response)
}

/// Upstream half of `tunnel_http_upgrade`: wait for the client upgrade, connect
/// to the origin, replay the request head, strip the origin's `101`, then pipe.
async fn bridge_http_upgrade(
    req: Request<Incoming>,
    head: String,
    authority: &Authority,
) -> std::io::Result<()> {
    let host = authority.host();
    // Proxied `http://` authorities carry no port; default to 80.
    let port = authority.port_u16().unwrap_or(80);

    let upgraded = hyper::upgrade::on(req)
        .await
        .map_err(std::io::Error::other)?;
    // `TokioIo` bridges hyper 1.0's `Upgraded` to tokio's IO traits.
    let mut client = TokioIo::new(upgraded);
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

/// Blind-tunnel an excluded CONNECT host: dial the (sanitized) authority and
/// pipe bytes both ways. DNS resolution and TCP connect failures are logged at
/// warn level — the client only ever sees its tunnel close, so without a log
/// line these failures are invisible.
async fn tunnel(
    upgraded: &mut TokioIo<Upgraded>,
    authority: &Authority,
    raw_authority: &Authority,
) -> std::io::Result<()> {
    let mut server = match TcpStream::connect(authority.to_string()).await {
        Ok(server) => server,
        Err(error) => {
            if authority == raw_authority {
                log::warn!("Unable to open tunnel to {}: {}", authority, error);
            } else {
                log::warn!(
                    "Unable to open tunnel to {} (client requested {}): {}",
                    authority,
                    raw_authority,
                    error
                );
            }
            return Err(error);
        }
    };

    log::debug!("Started tunneling host: {}", authority);

    // Byte counts and lifetime make tunnel health diagnosable from logs: a
    // tunnel that closes quickly having received 0 bytes from upstream means
    // the server (or client) rejected the conversation, which is otherwise
    // indistinguishable from a working tunnel.
    let started_at = std::time::Instant::now();
    match tokio::io::copy_bidirectional(upgraded, &mut server).await {
        Ok((bytes_to_server, bytes_to_client)) => {
            log::debug!(
                "Tunnel to {} closed after {:?}: {} bytes sent, {} bytes received",
                authority,
                started_at.elapsed(),
                bytes_to_server,
                bytes_to_client
            );
            Ok(())
        }
        Err(error) => {
            log::debug!(
                "Tunnel to {} ended with error after {:?}: {}",
                authority,
                started_at.elapsed(),
                error
            );
            Err(error)
        }
    }
}

/// Strip a trailing parenthesized service selector from an authority's host.
///
/// Apple's RCS client tunnels to Google's Jibe backend using CONNECT
/// authorities like `rbm.goog(smsft):443` (also seen on other Google RCS
/// hosts, e.g. under `telephony.goog`). The parenthetical selects a service
/// but is not part of the DNS name, so resolving or dialing the authority
/// verbatim fails. Returns the authority with the selector removed, or the
/// original authority when there is no trailing selector or stripping it
/// would not leave a valid authority. Plain `host:port`, bracketed IPv6
/// literals, and hosts with non-trailing parentheses pass through unchanged.
fn sanitize_authority(authority: &Authority) -> Authority {
    let host = authority.host();
    if !host.ends_with(')') {
        return authority.clone();
    }
    let stripped_host = match host.find('(') {
        Some(open_paren) => &host[..open_paren],
        None => return authority.clone(),
    };
    if stripped_host.is_empty() {
        return authority.clone();
    }
    let candidate = match authority.port_u16() {
        Some(port) => format!("{stripped_host}:{port}"),
        None => stripped_host.to_string(),
    };
    candidate.parse().unwrap_or_else(|_| authority.clone())
}

/// An authority is excluded when its sanitized host matches the exclusion
/// list, or — for authorities that carried a service selector — when the raw
/// client-sent host matches a literal exclusion entry.
fn is_authority_excluded(
    exclusions: &LocalExclusionStore,
    authority: &Authority,
    raw_authority: &Authority,
) -> bool {
    exclusions.contains(authority.host())
        || (raw_authority.host() != authority.host() && exclusions.contains(raw_authority.host()))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn upgrade_headers(value: &str) -> http::HeaderMap {
        let mut map = http::HeaderMap::new();
        map.insert(
            http::header::UPGRADE,
            http::HeaderValue::from_str(value).unwrap(),
        );
        map
    }

    #[test]
    fn websocket_and_h2c_are_not_opaque() {
        assert!(!is_opaque_upgrade(&upgrade_headers("websocket")));
        assert!(!is_opaque_upgrade(&upgrade_headers("WebSocket")));
        assert!(!is_opaque_upgrade(&upgrade_headers("h2c")));
        // A bridgeable token among others still counts as non-opaque.
        assert!(!is_opaque_upgrade(&upgrade_headers("foo, websocket")));
    }

    #[test]
    fn unknown_protocols_are_opaque() {
        // e.g. WeChat's MMTLS long-link.
        assert!(is_opaque_upgrade(&upgrade_headers("mmtls")));
        assert!(is_opaque_upgrade(&upgrade_headers("tls/1.2, foo")));
    }

    #[test]
    fn absent_upgrade_header_is_not_opaque() {
        assert!(!is_opaque_upgrade(&http::HeaderMap::new()));
    }

    fn authority(value: &str) -> Authority {
        value.parse().unwrap()
    }

    #[test]
    fn connect_authority_with_service_selector_parses_and_sanitizes() {
        // Apple's RCS client sends e.g. `CONNECT rbm.goog(smsft):443` — the
        // parenthetical must survive http's authority parsing (it does: parens
        // are RFC 3986 sub-delims) and then be stripped by sanitization.
        let raw = authority("rbm.goog(smsft):443");
        assert_eq!(raw.host(), "rbm.goog(smsft)");
        assert_eq!(raw.port_u16(), Some(443));

        // `tunnel` dials `TcpStream::connect(authority.to_string())`, so this
        // rendering is exactly the address the tunnel connects to.
        assert_eq!(sanitize_authority(&raw).to_string(), "rbm.goog:443");
    }

    #[test]
    fn sanitize_authority_strips_selector_generically() {
        assert_eq!(
            sanitize_authority(&authority("eu.telephony.goog(smsft):443")).to_string(),
            "eu.telephony.goog:443"
        );
        // Portless authorities keep working.
        assert_eq!(
            sanitize_authority(&authority("rbm.goog(smsft)")).to_string(),
            "rbm.goog"
        );
    }

    #[test]
    fn sanitize_authority_leaves_normal_authorities_untouched() {
        for value in [
            "example.com:443",
            "example.com",
            "127.0.0.1:8443",
            "[::1]:443",
            // A parenthetical that is not a trailing selector.
            "weird(host).example.com:443",
            // Unbalanced or empty variants stay as-is rather than guessing.
            "rbm.goog):443",
            "(smsft):443",
        ] {
            let raw = authority(value);
            assert_eq!(sanitize_authority(&raw), raw, "{value}");
        }
    }

    #[test]
    fn exclusion_matching_tolerates_service_selector() {
        let raw = authority("rbm.goog(smsft):443");
        let sanitized = sanitize_authority(&raw);

        let exact = LocalExclusionStore::new(vec![String::from("rbm.goog")]);
        assert!(is_authority_excluded(&exact, &sanitized, &raw));

        let wildcard = LocalExclusionStore::new(vec![String::from("*.goog")]);
        assert!(is_authority_excluded(&wildcard, &sanitized, &raw));

        // An entry matching the literal client-sent host keeps working.
        let literal = LocalExclusionStore::new(vec![String::from("rbm.goog(smsft)")]);
        assert!(is_authority_excluded(&literal, &sanitized, &raw));

        let unrelated = LocalExclusionStore::new(vec![String::from("example.com")]);
        assert!(!is_authority_excluded(&unrelated, &sanitized, &raw));
    }
}
