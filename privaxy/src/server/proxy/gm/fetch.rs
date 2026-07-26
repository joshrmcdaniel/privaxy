//! Server-side `GM_xmlhttpRequest`.
//!
//! This is the one capability a real content script cannot have: the request is
//! made by the proxy, so there is no CORS, no preflight and no opaque response.
//! It is also the most dangerous thing in the userscript engine, because the
//! proxy's network position is not the browser's — it typically sits inside a
//! LAN and can reach routers, admin panels and cloud metadata endpoints that no
//! page could contact.
//!
//! Three independent controls therefore gate every relayed request:
//!
//! 1. The origin-bound token (see [`super::token`]), so only origins
//!    where Privaxy actually injected a script can reach the endpoint at all.
//! 2. The requesting script's own `@connect` declarations. A script may only
//!    reach hosts it declared, which is also what Tampermonkey requires — so
//!    this costs compatibility nothing and bounds a compromised page to the
//!    hosts the operator already accepted when installing the script.
//! 3. Address filtering: every hop must resolve to a public address unless
//!    `userscripts.allow_private_network_requests` is set.
//!
//! Redirects are followed manually so that checks 2 and 3 re-run on every hop;
//! letting the HTTP client follow them would allow an allow-listed host to
//! bounce the request straight to `127.0.0.1`.

use super::super::userscripts::UserScriptStore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;
use url::Url;

/// Cap on a relayed response body. Generous for API responses while bounding
/// what one page can make the proxy buffer.
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Redirect hops to follow before giving up.
const MAX_REDIRECTS: usize = 5;

/// Ceiling on the per-request timeout a script may ask for.
const MAX_TIMEOUT: Duration = Duration::from_secs(60);
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Methods the relay will issue. `CONNECT` and `TRACE` are excluded: neither has
/// a meaningful `GM_xmlhttpRequest` use and both invite proxy abuse.
const ALLOWED_METHODS: [&str; 7] = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

/// Request headers a script may not set.
///
/// Hop-by-hop headers would corrupt the relayed exchange, and `Host` would let a
/// script reach one server while claiming to address another — defeating the
/// `@connect` check, which is applied to the URL.
const FORBIDDEN_REQUEST_HEADERS: [&str; 8] = [
    "host",
    "content-length",
    "connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
    "te",
    "trailer",
];

#[derive(Debug, Deserialize)]
pub(crate) struct FetchRequest {
    pub token: String,
    /// File name of the requesting script, used to look up its `@connect` list.
    pub script: String,
    #[serde(default = "default_method")]
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
    /// Milliseconds, clamped to [`MAX_TIMEOUT`].
    #[serde(default)]
    pub timeout: Option<u64>,
}

fn default_method() -> String {
    "GET".to_string()
}

#[derive(Debug, Serialize)]
pub(crate) struct FetchResponse {
    pub status: u16,
    pub status_text: String,
    pub headers: BTreeMap<String, String>,
    pub body: String,
    /// The URL the response actually came from, after any redirects.
    pub final_url: String,
    /// True when the body was truncated at [`MAX_RESPONSE_BYTES`].
    pub truncated: bool,
}

#[derive(Debug)]
pub(crate) enum FetchError {
    /// The script asked for something it is not allowed to do.
    Forbidden(String),
    /// The request itself was malformed.
    BadRequest(String),
    /// The upstream exchange failed.
    Upstream(String),
}

/// Whether `address` is one the relay refuses by default.
///
/// Covers loopback, RFC1918 and other private ranges, link-local (including the
/// `169.254.169.254` cloud metadata address), unspecified and multicast. IPv6
/// gets the equivalent treatment, plus IPv4-mapped addresses so that
/// `::ffff:127.0.0.1` cannot be used to sneak past the IPv4 checks.
fn is_restricted_address(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                // 100.64.0.0/10, carrier-grade NAT.
                || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]))
                // 192.0.0.0/24, IETF protocol assignments.
                || (v4.octets()[0] == 192 && v4.octets()[1] == 0 && v4.octets()[2] == 0)
                // 198.18.0.0/15, benchmarking.
                || (v4.octets()[0] == 198 && (18..20).contains(&v4.octets()[1]))
                // 240.0.0.0/4, reserved.
                || v4.octets()[0] >= 240
        }
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_restricted_address(&IpAddr::V4(mapped));
            }

            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // fc00::/7 unique local, fe80::/10 link-local.
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Resolve `url`'s host and confirm every address it maps to is permitted.
///
/// Both the check and the subsequent request resolve the name, so a name whose
/// answer changes in between (DNS rebinding) could in principle slip past. That
/// window is narrow and requires control of DNS for a host the script already
/// declared in `@connect`, which is why `@connect` is enforced too rather than
/// relying on address filtering alone.
async fn check_address(url: &Url, allow_private: bool) -> Result<(), FetchError> {
    if allow_private {
        return Ok(());
    }

    // `Url::host()` is used rather than `host_str()` because the latter returns
    // IPv6 literals still wrapped in brackets (`[::1]`), which parse as neither
    // an address nor a resolvable name — a literal loopback would then fall
    // through to DNS and be reported as unresolvable instead of restricted.
    let host = url
        .host()
        .ok_or_else(|| FetchError::BadRequest("the URL has no host".to_string()))?;
    let port = url.port_or_known_default().unwrap_or(443);

    // A literal address needs no resolution — and must not get a free pass by
    // failing to resolve.
    let literal = match host {
        url::Host::Ipv4(address) => Some(IpAddr::V4(address)),
        url::Host::Ipv6(address) => Some(IpAddr::V6(address)),
        url::Host::Domain(_) => None,
    };
    if let Some(address) = literal {
        return if is_restricted_address(&address) {
            Err(FetchError::Forbidden(format!(
                "{address} is a private or loopback address; enable \
                 userscripts.allow_private_network_requests to permit it"
            )))
        } else {
            Ok(())
        };
    }

    let url::Host::Domain(host) = host else {
        unreachable!("literal addresses are handled above");
    };

    let addresses = tokio::net::lookup_host((host, port))
        .await
        .map_err(|err| FetchError::Upstream(format!("unable to resolve {host}: {err}")))?;

    let mut saw_any = false;
    for address in addresses {
        saw_any = true;
        if is_restricted_address(&address.ip()) {
            return Err(FetchError::Forbidden(format!(
                "{host} resolves to the private or loopback address {}; enable \
                 userscripts.allow_private_network_requests to permit it",
                address.ip()
            )));
        }
    }

    if !saw_any {
        return Err(FetchError::Upstream(format!("{host} did not resolve")));
    }

    Ok(())
}

/// Confirm the requesting script declared `@connect` for this URL's host.
fn check_connect(
    url: &Url,
    script_id: &str,
    user_script_store: &UserScriptStore,
) -> Result<(), FetchError> {
    let host = url
        .host_str()
        .ok_or_else(|| FetchError::BadRequest("the URL has no host".to_string()))?;

    // Only a script that is actually loaded may relay: a disabled or
    // uninstalled script is absent from the store and gets nothing.
    let script = user_script_store.find(script_id).ok_or_else(|| {
        FetchError::Forbidden("no such userscript is currently active".to_string())
    })?;

    if script.metadata.permits_connection_to(host) {
        Ok(())
    } else {
        Err(FetchError::Forbidden(format!(
            "'{}' does not declare @connect for {host}",
            script.title
        )))
    }
}

/// Validate and perform a relayed request, following redirects manually so
/// every hop is re-checked.
pub(crate) async fn relay(
    request: FetchRequest,
    http_client: &reqwest::Client,
    user_script_store: &UserScriptStore,
    allow_private: bool,
) -> Result<FetchResponse, FetchError> {
    let method = request.method.to_ascii_uppercase();
    if !ALLOWED_METHODS.contains(&method.as_str()) {
        return Err(FetchError::BadRequest(format!(
            "method {method} is not permitted"
        )));
    }
    let method = reqwest::Method::from_bytes(method.as_bytes())
        .map_err(|_| FetchError::BadRequest("invalid method".to_string()))?;

    let mut url = Url::parse(&request.url)
        .map_err(|err| FetchError::BadRequest(format!("invalid URL: {err}")))?;

    // Only the web schemes; `file:`, `data:` and friends have no business being
    // fetched by the proxy on a page's behalf.
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(FetchError::BadRequest(format!(
            "scheme {} is not permitted",
            url.scheme()
        )));
    }

    let timeout = request
        .timeout
        .map(Duration::from_millis)
        .unwrap_or(DEFAULT_TIMEOUT)
        .min(MAX_TIMEOUT);

    let mut redirects = 0;
    loop {
        check_connect(&url, &request.script, user_script_store)?;
        check_address(&url, allow_private).await?;

        let mut outgoing = http_client
            .request(method.clone(), url.as_str())
            .timeout(timeout);

        for (name, value) in &request.headers {
            if FORBIDDEN_REQUEST_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
                continue;
            }
            outgoing = outgoing.header(name, value);
        }

        if let Some(body) = &request.body {
            outgoing = outgoing.body(body.clone());
        }

        let response = outgoing
            .send()
            .await
            .map_err(|err| FetchError::Upstream(format!("{err}")))?;

        let status = response.status();
        if status.is_redirection() && redirects < MAX_REDIRECTS {
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.to_string());

            if let Some(location) = location {
                url = url.join(&location).map_err(|err| {
                    FetchError::Upstream(format!("invalid redirect target: {err}"))
                })?;
                redirects += 1;
                // Loop back around so `@connect` and address filtering apply to
                // the new target as well.
                continue;
            }
        }

        let headers: BTreeMap<String, String> = response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_string(), value.to_string()))
            })
            .collect();

        let final_url = response.url().to_string();
        let status_text = status.canonical_reason().unwrap_or("").to_string();

        let bytes = response
            .bytes()
            .await
            .map_err(|err| FetchError::Upstream(format!("{err}")))?;
        let truncated = bytes.len() > MAX_RESPONSE_BYTES;
        let bytes = if truncated {
            &bytes[..MAX_RESPONSE_BYTES]
        } else {
            &bytes[..]
        };

        return Ok(FetchResponse {
            status: status.as_u16(),
            status_text,
            headers,
            // Lossy so a binary response still yields something rather than
            // failing the whole call; scripts fetching binary data are outside
            // what this relay supports.
            body: String::from_utf8_lossy(bytes).to_string(),
            final_url,
            truncated,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn loopback_and_private_ranges_are_restricted() {
        for value in [
            "127.0.0.1",
            "127.1.2.3",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "0.0.0.0",
            "255.255.255.255",
            "100.64.0.1",
            "192.0.0.1",
            "198.18.0.1",
            "240.0.0.1",
        ] {
            assert!(
                is_restricted_address(&address(value)),
                "{value} must be restricted"
            );
        }
    }

    /// The cloud metadata endpoint is the classic SSRF target and must be
    /// covered by the link-local check.
    #[test]
    fn cloud_metadata_address_is_restricted() {
        assert!(is_restricted_address(&address("169.254.169.254")));
    }

    #[test]
    fn public_addresses_are_permitted() {
        for value in ["1.1.1.1", "8.8.8.8", "93.184.216.34", "2606:4700::1111"] {
            assert!(
                !is_restricted_address(&address(value)),
                "{value} must be permitted"
            );
        }
    }

    #[test]
    fn ipv6_private_ranges_are_restricted() {
        for value in ["::1", "::", "fc00::1", "fd12:3456::1", "fe80::1", "ff02::1"] {
            assert!(
                is_restricted_address(&address(value)),
                "{value} must be restricted"
            );
        }
    }

    /// `::ffff:127.0.0.1` is loopback wearing an IPv6 hat; without unwrapping
    /// the mapping it would sail past every IPv4 check.
    #[test]
    fn ipv4_mapped_addresses_are_unwrapped() {
        assert!(is_restricted_address(&address("::ffff:127.0.0.1")));
        assert!(is_restricted_address(&address("::ffff:192.168.1.1")));
        assert!(!is_restricted_address(&address("::ffff:8.8.8.8")));
    }

    #[tokio::test]
    async fn literal_private_addresses_are_refused_without_resolving() {
        let url = Url::parse("http://127.0.0.1:8080/admin").unwrap();

        let err = check_address(&url, false).await.expect_err("refused");
        assert!(matches!(err, FetchError::Forbidden(_)), "{err:?}");

        // ...and permitted when the operator has opted in.
        assert!(check_address(&url, true).await.is_ok());
    }

    /// `Url::host_str` renders IPv6 literals bracketed (`[::1]`), which parses
    /// as neither an address nor a name. Such a URL must still be recognized as
    /// loopback rather than falling through to a resolution failure.
    #[tokio::test]
    async fn bracketed_ipv6_literals_are_recognized() {
        for value in [
            "http://[::1]:8891/data.json",
            "http://[fc00::1]/",
            "http://[fe80::1]/",
            "http://[::ffff:127.0.0.1]/",
        ] {
            let url = Url::parse(value).unwrap();
            let err = check_address(&url, false)
                .await
                .unwrap_err_or_else_message();

            assert!(
                err.contains("private or loopback"),
                "{value} should be reported as restricted, got: {err}"
            );
        }
    }

    /// A public IPv6 literal is still allowed through.
    #[tokio::test]
    async fn public_ipv6_literals_are_permitted() {
        let url = Url::parse("http://[2606:4700::1111]/").unwrap();

        assert!(check_address(&url, false).await.is_ok());
    }

    /// Helper making the assertions above read cleanly.
    trait UnwrapErrMessage {
        fn unwrap_err_or_else_message(self) -> String;
    }

    impl UnwrapErrMessage for Result<(), FetchError> {
        fn unwrap_err_or_else_message(self) -> String {
            match self {
                Ok(()) => panic!("expected the address to be refused"),
                Err(FetchError::Forbidden(message)) => message,
                Err(other) => panic!("expected Forbidden, got {other:?}"),
            }
        }
    }

    #[test]
    fn forbidden_headers_cover_host_and_hop_by_hop() {
        assert!(FORBIDDEN_REQUEST_HEADERS.contains(&"host"));
        assert!(FORBIDDEN_REQUEST_HEADERS.contains(&"content-length"));
        assert!(FORBIDDEN_REQUEST_HEADERS.contains(&"transfer-encoding"));
    }
}
