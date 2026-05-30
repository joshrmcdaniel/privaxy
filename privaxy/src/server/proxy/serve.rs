use super::doh::{self, DohAction};
use super::html_rewriter::Rewriter;
use crate::blocker::AdblockRequester;
use crate::configuration::DohConfig;
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

// Only *enforcing* CSP headers are augmented. Report-only headers
// (`content-security-policy-report-only`) are deliberately left untouched:
// they never block our injected script/style, so augmenting them buys nothing,
// and doing so would inject our nonce into the site's own violation telemetry
// and suppress reports the site author relies on (e.g. while testing a strict
// policy before enforcing it).
const CSP_HEADERS: [&str; 3] = [
    "content-security-policy",
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
        directives.iter().any(|d| {
            directive_name(d)
                .map(|t| t.eq_ignore_ascii_case(name))
                .unwrap_or(false)
        })
    }
    fn find_directive<'a>(directives: &'a [String], name: &str) -> Option<&'a str> {
        directives
            .iter()
            .find(|d| {
                directive_name(d)
                    .map(|t| t.eq_ignore_ascii_case(name))
                    .unwrap_or(false)
            })
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
            if directive_name(d)
                .map(|t| t.eq_ignore_ascii_case(name))
                .unwrap_or(false)
            {
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

/// Map an outgoing request's headers to the adblock-rust request-type string
/// the engine expects (the same vocabulary as uBO's `$type` options). Without
/// an accurate type, type-scoped filter and exception rules — e.g. the
/// `$script`/`$xmlhttprequest` exceptions in uBO's unbreak lists that keep
/// sites like DuckDuckGo working — match incorrectly and cause false blocks.
///
/// Modern browsers send `Sec-Fetch-Dest`, which maps cleanly onto these types.
/// When it's absent we fall back to sniffing `Accept`, and finally to `other`.
fn request_type_from_headers(headers: &HeaderMap) -> &'static str {
    if let Some(dest) = headers.get("sec-fetch-dest").and_then(|v| v.to_str().ok()) {
        return match dest {
            "document" => "document",
            "frame" | "iframe" => "sub_frame",
            "script" | "serviceworker" | "sharedworker" | "worker" | "audioworklet"
            | "paintworklet" => "script",
            "style" => "stylesheet",
            "image" => "image",
            "font" => "font",
            "audio" | "video" | "track" => "media",
            "object" | "embed" => "object",
            "report" => "ping",
            // `empty` is what fetch()/XHR report; treat it as xhr.
            "empty" | "" => "xmlhttprequest",
            _ => "other",
        };
    }

    match headers
        .get(http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
    {
        Some(accept) if accept.contains("text/html") => "document",
        Some(accept) if accept.contains("text/css") => "stylesheet",
        Some(accept) if accept.contains("image/") => "image",
        Some(accept) if accept.contains("javascript") || accept.contains("ecmascript") => "script",
        _ => "other",
    }
}

/// adblock-rust matches against the literal URL string, so an explicit default
/// port (`:443` for https, `:80` for http) wedges itself between the host and the
/// path and breaks hostname-anchored rules (`||host/path`) — the path no longer
/// follows the host directly. Browsers and uBO match on the canonical URL with
/// the default port stripped, so we normalise the same way before handing URLs to
/// the blocker/cosmetic engine. Non-default ports are preserved.
fn url_for_matching(uri: &Uri) -> String {
    let scheme = uri.scheme_str().unwrap_or("https");
    let host = uri.host().unwrap_or("");
    let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let default_port = match scheme {
        "https" => Some(443),
        "http" => Some(80),
        _ => None,
    };
    match uri.port_u16() {
        Some(port) if Some(port) != default_port => format!("{scheme}://{host}:{port}{path}"),
        _ => format!("{scheme}://{host}{path}"),
    }
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
    doh_config: DohConfig,
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

    let request_type = request_type_from_headers(req.headers()).to_string();

    // Canonical URL (default port stripped) for all adblock-engine matching —
    // see `url_for_matching`. The raw `uri` (which may carry `:443`) is still
    // used for the actual outbound request below.
    let match_url = url_for_matching(&uri);

    // DNS-over-HTTPS policy is applied before adblock matching: a DoH endpoint
    // rarely matches a network rule, but we still want to refuse or redirect it.
    let doh_action = doh::classify(&doh_config, req.headers(), &uri);
    if let DohAction::Block = &doh_action {
        log::debug!("Refusing DoH request: {}", uri);
        let _result = broadcast_sender.send(Event {
            now: chrono::Utc::now(),
            method: req.method().to_string(),
            url: req.uri().to_string(),
            is_request_blocked: true,
        });
        statistics.increment_blocked_requests();
        return Ok(get_empty_response(StatusCode::BAD_GATEWAY));
    }

    let (is_request_blocked, blocker_result) = adblock_requester
        .is_network_url_blocked(
            match_url.clone(),
            match req.headers().get(http::header::REFERER) {
                Some(referer) => referer.to_str().unwrap().to_string(),
                // When no referer, we default to `uri` as we otherwise may get many false
                // positives due to the blocker thinking it's third party requests.
                None => match_url.clone(),
            },
            request_type.clone(),
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

        // adblock-rust fuses many same-option patterns into one filter and
        // reports the union as the matched filter, which can be enormous; cap
        // it so debug logs stay readable.
        let matched_filter = blocker_result.filter.as_deref().unwrap_or("<none>");
        let matched_filter = match matched_filter.char_indices().nth(200) {
            Some((idx, _)) => format!("{}… (truncated)", &matched_filter[..idx]),
            None => matched_filter.to_string(),
        };
        log::debug!(
            "Blocked request: {} [type={}] matched filter: {}",
            uri,
            request_type,
            matched_filter
        );

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
    // In redirect mode the query is forwarded to the configured upstream
    // resolver instead of the endpoint the client chose; otherwise the original
    // URL is used unchanged.
    let outbound_url = match &doh_action {
        DohAction::Redirect(upstream) => {
            log::debug!("Redirecting DoH request to {}: {}", upstream, uri);
            doh::redirect_url(upstream, req.method(), &uri)
        }
        _ => req.uri().to_string(),
    };

    let mut response = match client
        .request(req.method().clone(), outbound_url)
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
    let csp_nonce = if is_html {
        Some(generate_csp_nonce())
    } else {
        None
    };

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

        // Resolve the URL-scoped payloads up-front so the rewriter can prepend
        // them inside <head> before any page scripts execute: the uBO scriptlet
        // and the procedural cosmetic filters (both URL-specific, not dependent
        // on collected IDs/classes). The end-of-body cosmetic lookup still runs
        // for hide/style selectors, which do depend on collected IDs/classes.
        let head_cosmetics = adblock_requester
            .get_cosmetic_response(match_url.clone(), Vec::new(), Vec::new())
            .await;

        let rewriter = Rewriter::new(
            match_url.clone(),
            adblock_requester,
            receiver_rewriter,
            sender,
            statistics,
            csp_nonce.expect("csp_nonce is Some whenever is_html"),
            head_cosmetics.injected_script,
            head_cosmetics.procedural_filters,
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
