//! Detection and policy for DNS-over-HTTPS (DoH) requests flowing through the
//! MITM proxy.
//!
//! Privaxy filters at the HTTP layer, not at DNS-resolution time, so DoH does
//! not bypass blocking the way it bypasses a DNS-level filter. This module
//! instead lets the operator either refuse DoH outright — pushing fallback-mode
//! clients (e.g. default Firefox) back onto the system resolver, whose lookups
//! already traverse the proxy — or transparently redirect DoH queries to a
//! chosen upstream resolver.

use crate::configuration::{DohConfig, DohMode};
use http::{HeaderMap, Method, Uri};

/// Well-known DoH endpoint hostnames. Used as a secondary signal (alongside the
/// RFC 8484 `application/dns-message` content type) to catch JSON DoH and
/// clients that omit the canonical media type.
const KNOWN_DOH_HOSTS: [&str; 12] = [
    "cloudflare-dns.com",
    "mozilla.cloudflare-dns.com",
    "dns.google",
    "dns.google.com",
    "dns.quad9.net",
    "doh.opendns.com",
    "dns.nextdns.io",
    "firefox.dns.nextdns.io",
    "doh.cleanbrowsing.org",
    "dns.adguard-dns.com",
    "doh.dns.sb",
    "dns.controld.com",
];

const DOH_MEDIA_TYPES: [&str; 2] = ["application/dns-message", "application/dns-json"];

/// What to do with a request the proxy has (or has not) identified as DoH.
#[derive(Debug, Clone)]
pub(crate) enum DohAction {
    /// Not DoH, or the feature is disabled: handle the request normally.
    Passthrough,
    /// Refuse the request so the client's DoH attempt fails.
    Block,
    /// Forward the query to this upstream DoH resolver URL instead.
    Redirect(String),
}

fn header_advertises_doh(headers: &HeaderMap, name: http::header::HeaderName) -> bool {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            let value = value.to_ascii_lowercase();
            DOH_MEDIA_TYPES.iter().any(|media| value.contains(media))
        })
        .unwrap_or(false)
}

fn host_is_known_doh(host: &str, extra_hosts: &[String]) -> bool {
    let host = host.to_ascii_lowercase();
    let is_match = |candidate: &str| host == candidate || host.ends_with(&format!(".{candidate}"));
    KNOWN_DOH_HOSTS.iter().any(|h| is_match(h)) || extra_hosts.iter().any(|h| is_match(h))
}

/// A request is treated as DoH when it carries the RFC 8484 media type (the
/// authoritative signal, exclusive to DoH for both `Content-Type` on POST and
/// `Accept` on GET) or when it targets a known DoH endpoint with a query-shaped
/// path (covering JSON DoH that may arrive with a generic `Accept` header).
fn is_doh_request(headers: &HeaderMap, uri: &Uri, extra_hosts: &[String]) -> bool {
    if header_advertises_doh(headers, http::header::CONTENT_TYPE)
        || header_advertises_doh(headers, http::header::ACCEPT)
    {
        return true;
    }

    let host = uri.host().unwrap_or("");
    if !host_is_known_doh(host, extra_hosts) {
        return false;
    }

    uri.path().contains("dns-query")
        || uri
            .query()
            .map(|query| query.contains("dns=") || query.contains("name="))
            .unwrap_or(false)
}

/// Decide how to handle a request given the configured DoH policy.
pub(crate) fn classify(config: &DohConfig, headers: &HeaderMap, uri: &Uri) -> DohAction {
    if matches!(config.mode, DohMode::Off) || !is_doh_request(headers, uri, &config.extra_hosts) {
        return DohAction::Passthrough;
    }

    match config.mode {
        DohMode::Off => DohAction::Passthrough,
        DohMode::Block => DohAction::Block,
        DohMode::Redirect => match &config.upstream {
            Some(upstream) if !upstream.is_empty() => DohAction::Redirect(upstream.clone()),
            // Redirect configured without a usable upstream: fail safe by
            // blocking rather than silently forwarding to the original resolver.
            _ => DohAction::Block,
        },
    }
}

/// Build the outbound URL for a redirected DoH request. GET-style DoH carries
/// the query in the URL (`?dns=` / `?name=`), so it must be preserved; POST DoH
/// carries it in the body and needs only the upstream endpoint.
pub(crate) fn redirect_url(upstream: &str, method: &Method, uri: &Uri) -> String {
    if method == Method::GET {
        if let Some(query) = uri.query() {
            return format!("{upstream}?{query}");
        }
    }
    upstream.to_string()
}
