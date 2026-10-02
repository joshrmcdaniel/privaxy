use super::serve::UpgradeClient;
use super::tls_failures::TlsFailureStore;
use super::userscripts::UserScriptContext;
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
    io::{
        AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
        BufReader,
    },
    net::TcpStream,
    sync::broadcast,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::either::Either;

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
    user_scripts: UserScriptContext,
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
        // tun2proxy uses CONNECT for every TCP flow, including plain HTTP.
        // Reply before reading its payload; clients wait for the 200 first.
        let intercept =
            should_intercept_authority(&local_exclusion_store, &authority, &raw_authority);

        tokio::task::spawn(async move {
            let upgraded = match hyper::upgrade::on(req).await {
                Ok(upgraded) => upgraded,
                Err(error) => {
                    log::error!("CONNECT upgrade failed for {raw_authority}: {error}");
                    return;
                }
            };
            let mut upgraded = TokioIo::new(upgraded);
            if !intercept {
                // Bypass before looking at any payload. This also preserves
                // server-first protocols and avoids unnecessary cert minting.
                let _ = tunnel(&mut upgraded, &authority, &raw_authority).await;
                return;
            }

            // Keep both hyper's upgrade read-ahead and our protocol peek. The
            // first HTTP bytes or TLS ClientHello must reach the parser intact.
            let mut upgraded = BufReader::new(upgraded);
            let protocol = match peek_connect_protocol(&mut upgraded).await {
                Ok(Some(protocol)) => protocol,
                Ok(None) => return,
                Err(error) => {
                    log::debug!("Unable to read CONNECT payload for {raw_authority}: {error}");
                    return;
                }
            };
            let (stream, scheme) = match protocol {
                ConnectProtocol::Http => (Either::Left(upgraded), Scheme::HTTP),
                ConnectProtocol::Tls => {
                    // Hostnames come from CONNECT (tun2proxy's virtual DNS
                    // supplies them). Mint only once we know this is TLS.
                    let server_configuration =
                        Arc::new(cert_cache.get(authority.clone()).await.server_configuration);
                    match TlsAcceptor::from(server_configuration)
                        .accept(upgraded)
                        .await
                    {
                        Ok(tls_stream) => (Either::Right(tls_stream), Scheme::HTTPS),
                        Err(error) => {
                            // A failed TLS session cannot display an error
                            // page, so keep it visible in the web GUI.
                            tls_failure_store.record(
                                authority.host(),
                                &error.to_string(),
                                error.kind() == std::io::ErrorKind::UnexpectedEof,
                            );
                            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                                log::warn!("Unable to perform handshake for host: {}. Consider excluding it from blocking. The service may not tolerate TLS interception.", raw_authority);
                            } else {
                                log::warn!(
                                    "TLS interception handshake failed for host {}: {}",
                                    raw_authority,
                                    error
                                );
                            }
                            return;
                        }
                    }
                }
            };

            // Both transports use the same filtering, rewriting and upgrade
            // path. Bind requests to the CONNECT destination, not an inner
            // Host header or absolute URI that could name a different host.
            let session_authority = raw_authority.clone();
            let result = auto::Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(
                    TokioIo::new(stream),
                    service_fn(move |req| {
                        serve(
                            adblock_requester.clone(),
                            req,
                            hyper_client.clone(),
                            client.clone(),
                            authority.clone(),
                            scheme.clone(),
                            broadcast_tx.clone(),
                            statistics.clone(),
                            client_ip_address,
                            doh_config.clone(),
                            scriptlet_debug_logging,
                            gui_base_url.clone(),
                            user_scripts.clone(),
                            should_intercept_authority(
                                &local_exclusion_store,
                                &authority,
                                &raw_authority,
                            ),
                        )
                    }),
                )
                .await;
            if let Err(error) = result {
                log::debug!("HTTP session inside CONNECT to {session_authority} ended: {error}");
            }
        });

        Ok(Response::new(empty_body()))
    } else if !should_intercept_authority(&local_exclusion_store, &authority, &raw_authority)
        && is_opaque_upgrade(req.headers())
    {
        // An excluded host performing a protocol upgrade over plain HTTP — e.g.
        // WeChat's MMTLS long-link (`http://dns.weixin.qq.com/mmtls/...`), which
        // speaks a proprietary, non-HTTP protocol once upgraded. The hyper-based
        // bridge in `serve` can't carry that (the upstream never returns a clean
        // `101`, so the upgrade "expected but not completed"). Blind-tunnel the
        // bytes at the TCP level instead, the same way excluded CONNECT hosts
        // are tunneled. WebSockets need the origin's handshake headers, so they
        // use the ordinary upgrade bridge instead of this fabricated response.
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

        let intercept =
            should_intercept_authority(&local_exclusion_store, &authority, &raw_authority);
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
            user_scripts,
            intercept,
        )
        .await
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ConnectProtocol {
    Http,
    Tls,
}

/// TLS begins with a handshake record (0x16); everything else must parse as
/// HTTP. Unknown protocols are not automatically bypassed. BufReader retains
/// every byte, including a request sent in the same packet as CONNECT.
async fn peek_connect_protocol(
    stream: &mut (impl AsyncBufRead + Unpin),
) -> std::io::Result<Option<ConnectProtocol>> {
    Ok(stream.fill_buf().await?.first().map(|byte| {
        if *byte == 0x16 {
            ConnectProtocol::Tls
        } else {
            ConnectProtocol::Http
        }
    }))
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

/// Apply one interception decision to the sanitized and original hostnames.
fn should_intercept_authority(
    exclusions: &LocalExclusionStore,
    authority: &Authority,
    raw_authority: &Authority,
) -> bool {
    exclusions.should_intercept(authority.host(), raw_authority.host())
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

    #[tokio::test]
    async fn connect_detection_preserves_http_and_tls_read_ahead() {
        for (bytes, expected) in [
            (
                &b"POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\nbody"[..],
                ConnectProtocol::Http,
            ),
            (
                &b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"[..],
                ConnectProtocol::Http,
            ),
            (
                &b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00"[..],
                ConnectProtocol::Tls,
            ),
        ] {
            let mut stream = BufReader::new(bytes);
            assert_eq!(
                peek_connect_protocol(&mut stream).await.unwrap(),
                Some(expected)
            );
            let mut remaining = Vec::new();
            stream.read_to_end(&mut remaining).await.unwrap();
            assert_eq!(remaining, bytes);
        }
    }

    #[tokio::test]
    async fn connect_detection_accepts_fragmented_requests_without_eating_the_first_byte() {
        let (mut writer, reader) = tokio::io::duplex(64);
        let mut reader = BufReader::new(reader);
        writer.write_all(b"G").await.unwrap();
        assert_eq!(
            peek_connect_protocol(&mut reader).await.unwrap(),
            Some(ConnectProtocol::Http)
        );
        writer.write_all(b"ET / HTTP/1.1\r\n\r\n").await.unwrap();
        writer.shutdown().await.unwrap();
        let mut request = String::new();
        reader.read_to_string(&mut request).await.unwrap();
        assert_eq!(request, "GET / HTTP/1.1\r\n\r\n");
    }

    #[tokio::test]
    async fn connect_detection_handles_an_empty_connection() {
        let mut stream = BufReader::new(&b""[..]);
        assert_eq!(peek_connect_protocol(&mut stream).await.unwrap(), None);
    }

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
        assert!(!should_intercept_authority(&exact, &sanitized, &raw));

        let wildcard = LocalExclusionStore::new(vec![String::from("*.goog")]);
        assert!(!should_intercept_authority(&wildcard, &sanitized, &raw));

        // An entry matching the literal client-sent host keeps working.
        let literal = LocalExclusionStore::new(vec![String::from("rbm.goog(smsft)")]);
        assert!(!should_intercept_authority(&literal, &sanitized, &raw));

        let unrelated = LocalExclusionStore::new(vec![String::from("example.com")]);
        assert!(should_intercept_authority(&unrelated, &sanitized, &raw));
    }
}
