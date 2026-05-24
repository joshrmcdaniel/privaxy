use super::html_rewriter::Rewriter;
use crate::blocker::AdblockRequester;
use crate::statistics::Statistics;
use crate::web_gui::events::Event;
use adblock::blocker::BlockerResult;
use base64::Engine;
use http::uri::{Authority, Scheme};
use http::{HeaderMap, HeaderValue, StatusCode, Uri};
use hyper::body::Bytes;
use hyper::client::HttpConnector;
use hyper::{http, Body, Request, Response};
use hyper_rustls::HttpsConnector;
use std::net::IpAddr;
use tokio::sync::broadcast;

const CSP_HEADERS: [&str; 4] = [
    "content-security-policy",
    "content-security-policy-report-only",
    "x-content-security-policy",
    "x-webkit-csp",
];

/// 16 random bytes → 22 chars of url-safe base64. Plenty of entropy and
/// avoids `=` padding that some CSP parsers historically choked on.
fn generate_csp_nonce() -> String {
    let mut bytes = [0u8; 16];
    openssl::rand::rand_bytes(&mut bytes).expect("OS RNG must be available");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// For each CSP header value, append a nonce source to the directive that
/// actually governs script (and style) execution. CSP3 ignores `'unsafe-inline'`
/// when a nonce is present, so this is non-destructive: the page's other
/// allow-listed sources keep working, only our injected tag gains permission.
fn augment_csp_headers(headers: &mut HeaderMap, nonce: &str) {
    for header_name in CSP_HEADERS {
        let values: Vec<HeaderValue> = headers.get_all(header_name).iter().cloned().collect();
        if values.is_empty() {
            continue;
        }
        headers.remove(header_name);
        for value in values {
            let Ok(text) = value.to_str() else {
                // Preserve un-parseable values unchanged so we don't accidentally
                // weaken something we can't read.
                headers.append(header_name, value);
                continue;
            };
            let rewritten = augment_csp_value(text, nonce);
            let _ = match HeaderValue::from_str(&rewritten) {
                Ok(v) => headers.append(header_name, v),
                Err(_) => headers.append(header_name, value),
            };
        }
    }
}

/// `default-src 'self'; script-src 'self'` + nonce `abc` →
/// `default-src 'self'; script-src 'self' 'nonce-abc'`
/// If only `default-src` is set, augment that instead (browsers fall back to
/// default-src for script-src/style-src checks). The nonce keyword is ignored
/// in directives that don't honor it, so this is safe.
fn augment_csp_value(value: &str, nonce: &str) -> String {
    let nonce_source = format!("'nonce-{}'", nonce);
    let mut directives: Vec<String> = value.split(';').map(|d| d.trim().to_string()).collect();

    fn directive_name(d: &str) -> Option<&str> {
        d.split_whitespace().next()
    }

    // Trusted Types blocks plain-string assignment to script-URL sinks
    // (script.src = "…", eval, etc.), which uBO scriptlets routinely do.
    // Drop both directives so the injected scriptlet can run; nonce-based
    // protection still covers inline script execution.
    directives.retain(|d| {
        !matches!(
            directive_name(d).map(|n| n.to_ascii_lowercase()).as_deref(),
            Some("require-trusted-types-for") | Some("trusted-types")
        )
    });
    fn has(directives: &[String], name: &str) -> bool {
        directives
            .iter()
            .any(|d| directive_name(d).map(|t| t.eq_ignore_ascii_case(name)).unwrap_or(false))
    }
    fn find_directive<'a>(directives: &'a [String], name: &str) -> Option<&'a str> {
        directives
            .iter()
            .find(|d| directive_name(d).map(|t| t.eq_ignore_ascii_case(name)).unwrap_or(false))
            .map(|d| d.as_str())
    }
    fn has_unsafe_inline(directive: &str) -> bool {
        directive
            .split_whitespace()
            .any(|t| t.eq_ignore_ascii_case("'unsafe-inline'"))
    }
    fn has_nonce_or_hash(directive: &str) -> bool {
        directive.split_whitespace().any(|t| {
            let lower = t.to_ascii_lowercase();
            lower.starts_with("'nonce-")
                || lower.starts_with("'sha256-")
                || lower.starts_with("'sha384-")
                || lower.starts_with("'sha512-")
        })
    }
    // CSP3: a nonce or hash in script-src causes `'unsafe-inline'` to be
    // ignored. So if a directive currently has `'unsafe-inline'` and no
    // existing nonce/hash, the page is relying on that permissiveness for its
    // own inline scripts — appending our nonce would silently break them. In
    // that case our injected tag is already allowed by `'unsafe-inline'`,
    // and the nonce attribute on it is a harmless no-op, so we skip.
    fn needs_nonce(directive: &str) -> bool {
        !(has_unsafe_inline(directive) && !has_nonce_or_hash(directive))
    }
    fn append_to(directives: &mut [String], name: &str, nonce_source: &str) {
        for d in directives.iter_mut() {
            if directive_name(d).map(|t| t.eq_ignore_ascii_case(name)).unwrap_or(false) {
                d.push(' ');
                d.push_str(nonce_source);
                return;
            }
        }
    }

    let script_target = if has(&directives, "script-src") {
        Some("script-src")
    } else if has(&directives, "default-src") {
        Some("default-src")
    } else {
        None
    };
    let script_needs_nonce = script_target
        .and_then(|n| find_directive(&directives, n))
        .map(needs_nonce)
        .unwrap_or(false);
    if script_needs_nonce {
        if let Some(name) = script_target {
            append_to(&mut directives, name, &nonce_source);
        }
    }

    let style_target = if has(&directives, "style-src") {
        Some("style-src")
    } else if has(&directives, "default-src") {
        Some("default-src")
    } else {
        None
    };
    let style_needs_nonce = style_target
        .and_then(|n| find_directive(&directives, n))
        .map(needs_nonce)
        .unwrap_or(false);
    if style_needs_nonce {
        if let Some(name) = style_target {
            // Don't double-append when both script and style fall back to default-src.
            if !(script_target == Some("default-src")
                && name == "default-src"
                && script_needs_nonce)
            {
                append_to(&mut directives, name, &nonce_source);
            }
        }
    }

    directives
        .into_iter()
        .filter(|d| !d.is_empty())
        .collect::<Vec<_>>()
        .join("; ")
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve(
    adblock_requester: AdblockRequester,
    request: Request<Body>,
    hyper_client: hyper::Client<HttpsConnector<HttpConnector>>,
    client: reqwest::Client,
    authority: Authority,
    scheme: Scheme,
    broadcast_sender: broadcast::Sender<Event>,
    statistics: Statistics,
    client_ip_address: IpAddr,
) -> Result<Response<Body>, hyper::Error> {
    let scheme_string = scheme.to_string();

    let uri = match http::uri::Builder::new()
        .scheme(scheme)
        .authority(authority)
        .path_and_query(match request.uri().path_and_query() {
            Some(path_and_query) => path_and_query.as_str(),
            None => "/",
        })
        .build()
    {
        Ok(uri) => uri,
        Err(_err) => {
            return Ok(get_empty_response(http::StatusCode::BAD_REQUEST));
        }
    };

    if request.headers().contains_key(http::header::UPGRADE) {
        return Ok(perform_two_ends_upgrade(request, uri, hyper_client).await);
    }

    let (mut parts, body) = request.into_parts();
    parts.uri = uri.clone();

    let (sender, new_body) = Body::channel();

    let req = Request::from_parts(parts, body);

    log::debug!("{} {}", req.method(), req.uri());

    statistics.increment_top_clients(client_ip_address);

    let (is_request_blocked, blocker_result) = adblock_requester
        .is_network_url_blocked(
            uri.to_string(),
            match req.headers().get(http::header::REFERER) {
                Some(referer) => referer.to_str().unwrap().to_string(),
                // When no referer, we default to `uri` as we otherwise may get many false
                // positives due to the blocker thinking it's third party requests.
                None => uri.to_string(),
            },
        )
        .await;

    let _result = broadcast_sender.send(Event {
        now: chrono::Utc::now(),
        method: req.method().to_string(),
        url: req.uri().to_string(),
        is_request_blocked,
    });

    if is_request_blocked {
        statistics.increment_blocked_requests();
        statistics.increment_top_blocked_paths(format!(
            "{}://{}{}",
            scheme_string,
            uri.host().unwrap(),
            uri.path()
        ));

        log::debug!("Blocked request: {}", uri);

        return Ok(get_blocked_by_privaxy_response(blocker_result));
    }

    let mut new_response = Response::new(new_body);

    let mut request_headers = req.headers().clone();
    request_headers.remove(http::header::CONNECTION);
    request_headers.remove(http::header::HOST);

    // zstd is causing issues
    if let Some(accept_encoding) = request_headers.get(http::header::ACCEPT_ENCODING) {
        if let Ok(encoding_str) = accept_encoding.to_str() {
            if encoding_str.contains("zstd") {
                let new_encoding = encoding_str
                    .split(',')
                    .filter(|e| !e.trim().eq_ignore_ascii_case("zstd"))
                    .collect::<Vec<&str>>()
                    .join(", ");

                if !new_encoding.is_empty() {
                    request_headers.insert(
                        http::header::ACCEPT_ENCODING,
                        http::HeaderValue::from_str(&new_encoding).unwrap_or_else(|_| {
                            http::HeaderValue::from_static("gzip, deflate, br")
                        }),
                    );
                } else {
                    request_headers.remove(http::header::ACCEPT_ENCODING);
                }
            }
        }
    }
    let mut response = match client
        .request(req.method().clone(), req.uri().to_string())
        .headers(request_headers)
        .body(req.into_body())
        .send()
        .await
    {
        Ok(response) => response,
        Err(err) => {
            log::error!("Failed to send request: {}", err.to_string());
            return Ok(get_informative_error_response(&err.to_string()));
        }
    };

    statistics.increment_proxied_requests();

    *new_response.headers_mut() = response.headers().clone();

    let is_html = response
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("text/html"))
        .unwrap_or(false);

    // When we rewrite HTML we need a CSP nonce so the inline <style>/<script>
    // we append survive the page's Content-Security-Policy without us having
    // to strip CSP entirely.
    let csp_nonce = if is_html { Some(generate_csp_nonce()) } else { None };

    if let Some(nonce) = csp_nonce.as_deref() {
        let headers = new_response.headers_mut();
        // We append bytes to the body, and reqwest has already decoded any
        // gzip/br/deflate, so upstream Content-Length / Content-Encoding no
        // longer describe what we send.
        headers.remove(http::header::CONTENT_LENGTH);
        headers.remove(http::header::CONTENT_ENCODING);
        augment_csp_headers(headers, nonce);
    }

    let (mut parts, new_new_body) = new_response.into_parts();
    parts.status = response.status();

    let new_response = Response::from_parts(parts, new_new_body);

    if is_html {
        let (sender_rewriter, receiver_rewriter) = crossbeam_channel::unbounded::<Bytes>();

        let rewriter = Rewriter::new(
            uri.to_string(),
            adblock_requester,
            receiver_rewriter,
            sender,
            statistics,
            csp_nonce.expect("csp_nonce is Some whenever is_html"),
        );

        tokio::task::spawn_blocking(|| rewriter.rewrite());

        while let Ok(Some(chunk)) = response.chunk().await {
            if let Err(_err) = sender_rewriter.send(chunk) {
                break;
            }
        }

        return Ok(new_response);
    }

    if response.headers().contains_key(http::header::CONTENT_TYPE) {
        tokio::spawn(write_proxied_body(response, sender));

        return Ok(new_response);
    }

    tokio::spawn(write_proxied_body(response, sender));

    Ok(new_response)
}

fn get_informative_error_response(reason: &str) -> Response<Body> {
    let mut response_body = String::from(include_str!("../../resources/head.html"));
    response_body +=
        &include_str!("../../resources/error.html").replace("#{request_error_reason}#", reason);

    let mut response = Response::new(Body::from(response_body));
    *response.status_mut() = http::StatusCode::BAD_GATEWAY;

    response
}

fn get_blocked_by_privaxy_response(blocker_result: BlockerResult) -> Response<Body> {
    // We don't redirect to network urls due to security concerns.
    if let Some(resource) = blocker_result.redirect {
        let response = Response::new(Body::from(resource));

        return response;
    }

    let filter_information = match blocker_result.filter {
        Some(filter) => filter,
        None => "No information".to_string(),
    };

    let mut response_body = String::from(include_str!("../../resources/head.html"));
    response_body += &include_str!("../../resources/blocked_by_privaxy.html")
        .replace("#{matching_filter}#", &filter_information);

    let mut response = Response::new(Body::from(response_body));
    *response.status_mut() = http::StatusCode::FORBIDDEN;

    response
}

fn get_empty_response(status_code: http::StatusCode) -> Response<Body> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status_code;

    response
}

async fn write_proxied_body(mut response: reqwest::Response, mut sender: hyper::body::Sender) {
    while let Ok(Some(chunk)) = response.chunk().await {
        // The other end is broken, let's abort immediately.
        if let Err(_err) = sender.send_data(chunk).await {
            break;
        }
    }
}

/// When we receive a request to perform an upgrade, we need to initiate a bidirectional tunnel.
/// We upgrade the request towards the target server, towards the proxy end and we connect both through a duplex stream.
async fn perform_two_ends_upgrade(
    request: Request<Body>,
    uri: Uri,
    hyper_client: hyper::Client<HttpsConnector<HttpConnector>>,
) -> Response<Body> {
    let (mut duplex_client, mut duplex_server) = tokio::io::duplex(32);

    let mut new_request = Request::new(Body::empty());
    *new_request.headers_mut() = request.headers().clone();
    *new_request.uri_mut() = uri;

    tokio::spawn(async move {
        match hyper::upgrade::on(request).await {
            Ok(mut upgraded_client) => {
                let _result =
                    tokio::io::copy_bidirectional(&mut upgraded_client, &mut duplex_client).await;
            }
            Err(e) => {
                log::debug!("Unable to upgrade: {}", e)
            }
        }
    });

    let response = match hyper_client.request(new_request).await {
        Ok(response) => response,
        Err(_err) => return get_empty_response(http::StatusCode::BAD_REQUEST),
    };

    let mut new_response = get_empty_response(StatusCode::SWITCHING_PROTOCOLS);
    *new_response.headers_mut() = response.headers().clone();

    match hyper::upgrade::on(response).await {
        Ok(mut upgraded_server) => {
            tokio::spawn(async move {
                let _result =
                    tokio::io::copy_bidirectional(&mut upgraded_server, &mut duplex_server).await;
            });
        }
        Err(e) => {
            log::debug!("Unable to upgrade: {}", e)
        }
    }

    new_response
}
