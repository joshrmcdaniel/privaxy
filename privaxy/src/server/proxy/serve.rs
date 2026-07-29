use super::doh::{self, DohAction};
use super::gm::endpoint as gm_endpoint;
use super::html_rewriter::Rewriter;
use super::userscripts::UserScriptContext;
use super::{body_channel, boxed_incoming, empty_body, full_body, BodySender, ProxyBody};
use crate::blocker::AdblockRequester;
use crate::configuration::DohConfig;
use crate::statistics::Statistics;
use crate::web_gui::events::Event;
use adblock::blocker::BlockerResult;
use base64::Engine;
use bytes::Bytes;
use futures::TryStreamExt;
use http::uri::{Authority, Scheme};
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, BodyStream, Limited};
use hyper::body::{Frame, Incoming};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::TokioIo;
use std::net::IpAddr;
use tokio::sync::broadcast;
use url::Url;

/// Type of the hyper client used for upgrade tunneling (websockets, etc.).
pub(crate) type UpgradeClient = HyperClient<HttpsConnector<HttpConnector>, ProxyBody>;

/// Adapt an incoming request body into a `reqwest::Body`, preserving streaming
/// (hyper 1.0 + reqwest 0.13 no longer share a body type, so we bridge via a
/// `Bytes` stream). Trailer frames are dropped — proxied request bodies don't
/// carry meaningful trailers.
fn incoming_to_reqwest_body(incoming: Incoming) -> reqwest::Body {
    let stream =
        BodyStream::new(incoming).try_filter_map(|frame| async move { Ok(frame.into_data().ok()) });
    reqwest::Body::wrap_stream(stream)
}

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

/// Cap on a buffered request body for the reserved endpoints. Generous for a
/// batch of `GM_setValue` writes and far below anything worth buffering.
const MAX_RESERVED_ENDPOINT_BODY_BYTES: usize = 256 * 1024;

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
        !has_unsafe_inline(directive) || has_nonce_or_hash(directive)
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
    request: Request<Incoming>,
    hyper_client: UpgradeClient,
    client: reqwest::Client,
    authority: Authority,
    scheme: Scheme,
    broadcast_sender: broadcast::Sender<Event>,
    statistics: Statistics,
    client_ip_address: IpAddr,
    doh_config: DohConfig,
    scriptlet_debug_logging: bool,
    gui_base_url: Option<String>,
    user_scripts: UserScriptContext,
) -> Result<Response<ProxyBody>, hyper::Error> {
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

    // Requests to the reserved path are answered by the proxy on the page's own
    // origin and never forwarded upstream, which is what lets a userscript
    // running in the page's main world reach Privaxy without CORS. Handled
    // before any statistics counting: these are not proxied traffic.
    if gm_endpoint::is_reserved(uri.path()) {
        let (parts, body) = request.into_parts();
        // Bounded so a hostile page cannot make the proxy buffer an unbounded
        // body; an oversized request simply fails to parse below.
        let collected = Limited::new(body, MAX_RESERVED_ENDPOINT_BODY_BYTES)
            .collect()
            .await
            .map(|collected| collected.to_bytes())
            .unwrap_or_default();

        return Ok(
            gm_endpoint::handle(&uri, &parts.method, &collected, &user_scripts, &client).await,
        );
    }

    let (mut parts, body) = request.into_parts();
    parts.uri = uri.clone();

    let (sender, new_body) = body_channel();

    let req = Request::from_parts(parts, body);

    log::debug!("{} {}", req.method(), req.uri());

    statistics.increment_top_clients(client_ip_address);

    let request_type = request_type_from_headers(req.headers());

    // Canonical URL (default port stripped) for all adblock-engine matching —
    // see `url_for_matching`. The raw `uri` (which may carry `:443`) is still
    // used for the actual outbound request below.
    let match_url = url_for_matching(&uri);

    // DNS-over-HTTPS policy is applied before adblock matching: a DoH endpoint
    // rarely matches a network rule, but we still want to refuse or redirect it.
    let doh_action = doh::classify(&doh_config, req.headers(), &uri);
    if let DohAction::Block = &doh_action {
        log::debug!("Refusing DoH request: {}", uri);
        // Events only feed the live requests view; when nobody is subscribed,
        // building one (two Strings and a timestamp) is wasted work.
        if broadcast_sender.receiver_count() > 0 {
            let _result = broadcast_sender.send(Event {
                now: chrono::Utc::now(),
                method: req.method().to_string(),
                url: req.uri().to_string(),
                is_request_blocked: true,
            });
        }
        statistics.increment_blocked_requests();
        return Ok(get_empty_response(StatusCode::BAD_GATEWAY));
    }

    let (is_request_blocked, blocker_result) = adblock_requester.is_network_url_blocked(
        &match_url,
        match req.headers().get(http::header::REFERER) {
            Some(referer) => referer.to_str().unwrap_or(&match_url),
            // When no referer, we default to `uri` as we otherwise may get many false
            // positives due to the blocker thinking it's third party requests.
            None => &match_url,
        },
        request_type,
    );

    if broadcast_sender.receiver_count() > 0 {
        let _result = broadcast_sender.send(Event {
            now: chrono::Utc::now(),
            method: req.method().to_string(),
            url: req.uri().to_string(),
            is_request_blocked,
        });
    }

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
        .body(incoming_to_reqwest_body(req.into_body()))
        .send()
        .await
    {
        Ok(response) => response,
        Err(err) => {
            log::error!("Failed to send request: {}", err);
            // `authority` was moved into the uri builder above; the host of
            // the rebuilt `uri` is the same portless hostname.
            let failing_host = uri.host();
            let exclude_url = build_exclude_url(failing_host, gui_base_url.as_deref());
            return Ok(get_informative_error_response(
                &err.to_string(),
                failing_host,
                exclude_url.as_deref(),
            ));
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
        // Bounded so the whole backpressure chain holds: client ← response body
        // ← rewriter ← this channel ← upstream. Before, every hop here was
        // unbounded and the entire document buffered in memory.
        let (sender_rewriter, receiver_rewriter) = tokio::sync::mpsc::channel::<Bytes>(32);

        // Resolve the URL-scoped payloads up-front so the rewriter can prepend
        // them inside <head> before any page scripts execute: the uBO scriptlet
        // and the procedural cosmetic filters (both URL-specific, not dependent
        // on collected IDs/classes). This is the single `url_cosmetic_resources`
        // lookup for the page — the end-of-body pass only resolves the generic
        // class/id-indexed selectors on top of it, using the exception set
        // carried in this result.
        let head_cosmetics = adblock_requester
            .get_cosmetic_response(match_url.clone())
            .await;

        // Userscripts are matched against the same canonical URL the adblock
        // engine uses. The store is consulted per request rather than captured
        // once per proxy start, so scripts added or toggled in the web UI apply
        // to the very next page load without a reload.
        let matched_user_scripts = if user_scripts.store.is_empty() {
            Vec::new()
        } else {
            match Url::parse(&match_url) {
                Ok(url) => user_scripts.store.matching(&url),
                Err(err) => {
                    log::debug!("Not matching userscripts against {match_url}: {err}");
                    Vec::new()
                }
            }
        };

        // Minted per page and handed to the in-page runtime so it can persist
        // GM values. Bound to this origin; see `userscript_token`.
        let endpoint_token = gm_endpoint::origin_of(&uri)
            .map(|origin| super::gm::token::mint(&origin, &user_scripts.endpoint_signing_key));

        let rewriter = Rewriter::new(
            adblock_requester,
            receiver_rewriter,
            sender,
            statistics,
            csp_nonce.expect("csp_nonce is Some whenever is_html"),
            head_cosmetics,
            scriptlet_debug_logging,
            matched_user_scripts,
            user_scripts.gm_storage.clone(),
            endpoint_token,
        );

        tokio::task::spawn_blocking(|| rewriter.rewrite());

        // Drain the upstream body on its own task so the response (headers plus
        // the streaming rewritten body) is returned to the client immediately.
        // Holding the response until the whole document had been downloaded
        // meant the browser could not start parsing — or prefetching
        // subresources — until the very last upstream byte had arrived.
        tokio::spawn(async move {
            while let Ok(Some(chunk)) = response.chunk().await {
                if sender_rewriter.send(chunk).await.is_err() {
                    break;
                }
            }
        });

        return Ok(new_response);
    }

    if response.headers().contains_key(http::header::CONTENT_TYPE) {
        tokio::spawn(write_proxied_body(response, sender));

        return Ok(new_response);
    }

    tokio::spawn(write_proxied_body(response, sender));

    Ok(new_response)
}

/// Minimal HTML escaping for text interpolated into the proxy's error page.
/// The failure reason comes from reqwest and can embed attacker-influenced
/// URLs; the failing host is client-controlled.
fn escape_html(s: &str) -> String {
    let mut escaped = String::with_capacity(s.len());
    for character in s.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

/// The web GUI link that pre-fills the exclusion flow for the failing host,
/// when both the host and a reachable GUI base URL are known. The host is
/// percent-encoded into the `host` query parameter.
fn build_exclude_url(failing_host: Option<&str>, gui_base_url: Option<&str>) -> Option<String> {
    match (failing_host, gui_base_url) {
        (Some(host), Some(base)) => Some(format!(
            "{base}/exclude?host={}",
            url::form_urlencoded::byte_serialize(host.as_bytes()).collect::<String>()
        )),
        _ => None,
    }
}

/// Markup substituted for `#{exclude_section}#` in the error page: the failing
/// host, plus an "Exclude this host" link when the GUI is reachable. Empty
/// when the failing host is unknown.
fn build_exclude_section(failing_host: Option<&str>, exclude_url: Option<&str>) -> String {
    let host = match failing_host {
        Some(host) => host,
        None => return String::new(),
    };

    let mut section = format!(
        "<p class=\"mt-1 text-base text-gray-500\">Failing host: \
         <span class=\"font-mono bg-gray-100 rounded-md\">{}</span></p>",
        escape_html(host)
    );
    if let Some(exclude_url) = exclude_url {
        // `exclude_url` is percent-encoded by construction; escaping it again
        // hardens the attribute against any future construction change.
        section.push_str(&format!(
            "<a href=\"{}\" class=\"mt-4 inline-block rounded-md bg-blue-600 px-4 py-2 \
             text-white font-medium\">Exclude this host</a>",
            escape_html(exclude_url)
        ));
    }

    section
}

fn get_informative_error_response(
    reason: &str,
    failing_host: Option<&str>,
    exclude_url: Option<&str>,
) -> Response<ProxyBody> {
    let mut response_body = String::from(include_str!("../../resources/head.html"));
    response_body += &include_str!("../../resources/error.html")
        .replace("#{request_error_reason}#", &escape_html(reason))
        .replace(
            "#{exclude_section}#",
            &build_exclude_section(failing_host, exclude_url),
        );

    let mut response = Response::new(full_body(response_body));
    *response.status_mut() = http::StatusCode::BAD_GATEWAY;

    response
}

fn get_blocked_by_privaxy_response(blocker_result: BlockerResult) -> Response<ProxyBody> {
    // We don't redirect to network urls due to security concerns.
    if let Some(resource) = blocker_result.redirect {
        let response = Response::new(full_body(resource));

        return response;
    }

    let filter_information = match blocker_result.filter {
        Some(filter) => filter,
        None => "No information".to_string(),
    };

    let mut response_body = String::from(include_str!("../../resources/head.html"));
    response_body += &include_str!("../../resources/blocked_by_privaxy.html")
        .replace("#{matching_filter}#", &filter_information);

    let mut response = Response::new(full_body(response_body));
    *response.status_mut() = http::StatusCode::FORBIDDEN;

    response
}

fn get_empty_response(status_code: http::StatusCode) -> Response<ProxyBody> {
    let mut response = Response::new(empty_body());
    *response.status_mut() = status_code;

    response
}

async fn write_proxied_body(mut response: reqwest::Response, sender: BodySender) {
    while let Ok(Some(chunk)) = response.chunk().await {
        // The other end is broken, let's abort immediately.
        if let Err(_err) = sender.send(Ok(Frame::data(chunk))).await {
            break;
        }
    }
}

/// When we receive a request to perform an upgrade, we need to initiate a bidirectional tunnel.
/// We upgrade the request towards the target server, towards the proxy end and we connect both through a duplex stream.
async fn perform_two_ends_upgrade(
    request: Request<Incoming>,
    uri: Uri,
    hyper_client: UpgradeClient,
) -> Response<ProxyBody> {
    // The duplex buffer caps how many bytes can be in flight between the two
    // `copy_bidirectional` tasks bridging client and upstream. A tiny buffer
    // forces the tunnel to ping-pong wakeups every few bytes, throttling
    // WebSocket throughput; 64 KiB matches a typical socket buffer.
    let (mut duplex_client, mut duplex_server) = tokio::io::duplex(64 * 1024);

    // Captured for log context; `uri` is moved into `new_request` below.
    let request_uri = uri.to_string();

    let mut new_request = Request::new(empty_body());
    *new_request.headers_mut() = request.headers().clone();
    *new_request.uri_mut() = uri;

    let client_uri = request_uri.clone();
    tokio::spawn(async move {
        match hyper::upgrade::on(request).await {
            Ok(upgraded_client) => {
                // hyper 1.0's `Upgraded` speaks hyper's own IO traits, so wrap
                // it in `TokioIo` to bridge to tokio's `AsyncRead`/`AsyncWrite`.
                let mut upgraded_client = TokioIo::new(upgraded_client);
                let _result =
                    tokio::io::copy_bidirectional(&mut upgraded_client, &mut duplex_client).await;
            }
            Err(e) => {
                log::warn!(
                    "Unable to upgrade client connection for {}: {}",
                    client_uri,
                    e
                )
            }
        }
    });

    let response = match hyper_client.request(new_request).await {
        Ok(response) => response,
        Err(err) => {
            log::warn!(
                "Upstream upgrade request failed for {}: {}",
                request_uri,
                err
            );
            return get_empty_response(http::StatusCode::BAD_GATEWAY);
        }
    };

    // Only bridge a genuine protocol switch. If the upstream did not return
    // `101 Switching Protocols`, forwarding a fabricated 101 leaves the client
    // believing the upgrade succeeded while no bytes are ever bridged from the
    // server half — the connection then hangs forever. Forward the upstream's
    // actual response instead so the client can fail (or follow it) cleanly.
    if response.status() != StatusCode::SWITCHING_PROTOCOLS {
        log::warn!(
            "Upstream did not upgrade {} (status {}); forwarding response as-is",
            request_uri,
            response.status()
        );
        return response.map(boxed_incoming);
    }

    let mut new_response = get_empty_response(StatusCode::SWITCHING_PROTOCOLS);
    *new_response.headers_mut() = response.headers().clone();

    match hyper::upgrade::on(response).await {
        Ok(upgraded_server) => {
            let mut upgraded_server = TokioIo::new(upgraded_server);
            tokio::spawn(async move {
                let _result =
                    tokio::io::copy_bidirectional(&mut upgraded_server, &mut duplex_server).await;
            });
        }
        Err(e) => {
            log::warn!(
                "Unable to upgrade upstream connection for {}: {}",
                request_uri,
                e
            )
        }
    }

    new_response
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderMap, HeaderValue, Uri};

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            let header_name = http::header::HeaderName::from_bytes(name.as_bytes()).unwrap();
            map.insert(header_name, HeaderValue::from_str(value).unwrap());
        }
        map
    }

    #[test]
    fn request_type_from_sec_fetch_dest() {
        let cases = [
            ("document", "document"),
            ("frame", "sub_frame"),
            ("iframe", "sub_frame"),
            ("script", "script"),
            ("serviceworker", "script"),
            ("worker", "script"),
            ("style", "stylesheet"),
            ("image", "image"),
            ("font", "font"),
            ("audio", "media"),
            ("video", "media"),
            ("object", "object"),
            ("embed", "object"),
            ("report", "ping"),
            ("empty", "xmlhttprequest"),
            ("something-unknown", "other"),
        ];
        for (dest, expected) in cases {
            let h = headers(&[("sec-fetch-dest", dest)]);
            assert_eq!(
                request_type_from_headers(&h),
                expected,
                "sec-fetch-dest: {dest}"
            );
        }
    }

    #[test]
    fn request_type_falls_back_to_accept() {
        assert_eq!(
            request_type_from_headers(&headers(&[("accept", "text/html,*/*")])),
            "document"
        );
        assert_eq!(
            request_type_from_headers(&headers(&[("accept", "text/css")])),
            "stylesheet"
        );
        assert_eq!(
            request_type_from_headers(&headers(&[("accept", "image/png")])),
            "image"
        );
        assert_eq!(
            request_type_from_headers(&headers(&[("accept", "application/javascript")])),
            "script"
        );
        assert_eq!(
            request_type_from_headers(&headers(&[("accept", "application/octet-stream")])),
            "other"
        );
        // No usable headers at all.
        assert_eq!(request_type_from_headers(&HeaderMap::new()), "other");
    }

    #[test]
    fn url_for_matching_strips_default_ports() {
        let strip = |s: &str| url_for_matching(&s.parse::<Uri>().unwrap());
        assert_eq!(
            strip("https://example.com:443/a/b"),
            "https://example.com/a/b"
        );
        assert_eq!(strip("http://example.com:80/a"), "http://example.com/a");
        // Non-default ports are preserved.
        assert_eq!(
            strip("https://example.com:8443/a"),
            "https://example.com:8443/a"
        );
        // Missing path defaults to "/".
        assert_eq!(strip("https://example.com:443"), "https://example.com/");
    }

    #[test]
    fn csp_nonce_has_expected_shape() {
        let nonce = generate_csp_nonce();
        // 16 bytes -> 22 url-safe base64 chars, no padding.
        assert_eq!(nonce.len(), 22);
        assert!(!nonce.contains('='));
        assert!(nonce
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn csp_appends_nonce_to_script_src() {
        // script-src gets the nonce directly; with no style-src present, the
        // style path falls back to default-src and adds the nonce there too.
        let out = augment_csp_value("default-src 'self'; script-src 'self'", "abc");
        assert_eq!(
            out,
            "default-src 'self' 'nonce-abc'; script-src 'self' 'nonce-abc'"
        );
    }

    #[test]
    fn csp_falls_back_to_default_src() {
        let out = augment_csp_value("default-src 'self'", "abc");
        assert_eq!(out, "default-src 'self' 'nonce-abc'");
    }

    #[test]
    fn csp_skips_when_unsafe_inline_without_nonce() {
        // Appending a nonce would silently break the site's own inline scripts,
        // so the value must be left untouched.
        let out = augment_csp_value("script-src 'self' 'unsafe-inline'", "abc");
        assert_eq!(out, "script-src 'self' 'unsafe-inline'");
    }

    #[test]
    fn csp_drops_trusted_types_directives() {
        let out = augment_csp_value(
            "default-src 'self'; require-trusted-types-for 'script'; trusted-types foo",
            "abc",
        );
        assert!(!out.contains("trusted-types"));
        assert!(out.contains("'nonce-abc'"));
    }

    #[test]
    fn exclude_section_escapes_hostile_host() {
        let section = build_exclude_section(Some("<script>alert(1)</script>"), None);
        assert!(section.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(!section.contains("<script>"));
    }

    #[test]
    fn exclude_url_percent_encodes_host() {
        let exclude_url = build_exclude_url(Some("foo/bar?baz&qux"), Some("http://gui.lan:8200"));
        assert_eq!(
            exclude_url.as_deref(),
            Some("http://gui.lan:8200/exclude?host=foo%2Fbar%3Fbaz%26qux")
        );
    }

    #[test]
    fn exclude_section_has_no_link_without_gui_url() {
        assert_eq!(build_exclude_url(Some("example.com"), None), None);

        let section = build_exclude_section(Some("example.com"), None);
        assert!(section.contains("Failing host"));
        assert!(!section.contains("<a "));

        // Without a failing host there is nothing to render at all.
        assert_eq!(build_exclude_section(None, None), "");
    }
}
