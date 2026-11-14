//! Keep the HTTP/TLS identity separate from an IP CONNECT's TCP destination.
use super::{ProxyBody, MAX_HTTP2_HEADER_LIST_SIZE};
use http::{uri::Authority, Uri};
use hyper_rustls::{ConfigBuilderExt, HttpsConnector};
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use std::{
    net::SocketAddr,
    task::{Context, Poll},
    time::Duration,
};
use tower_service::Service;

/// HTTP/1 client for protocol upgrades and unchanged, unfiltered responses.
pub(crate) type UpgradeClient = Client<HttpsConnector<DestinationConnector>, ProxyBody>;

/// Shared defaults for ordinary requests and clients scoped to an IP CONNECT.
/// Keep redirects disabled: each request must go through proxy policy checks.
pub(crate) fn http_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .use_rustls_tls()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .gzip(true)
        .brotli(true)
        .deflate(true)
        // Bound unreachable peers and retire stale idle connections quickly.
        .connect_timeout(Duration::from_secs(10))
        .pool_idle_timeout(Duration::from_secs(30))
        // Permit long polls/SSE while bounding a stalled response read.
        .read_timeout(Duration::from_secs(300))
        // Avoid a slow response stalling other streams on an HTTP/2 connection.
        .http2_adaptive_window(true)
        // Large CSP and Set-Cookie responses can exceed hyper's 16 KiB
        // default, which h2 reports as a generic stream PROTOCOL_ERROR. Allow
        // 64 KiB of decoded headers (including per-field overhead) while
        // retaining a finite limit for both shared and IP-pinned clients.
        .http2_max_header_list_size(MAX_HTTP2_HEADER_LIST_SIZE)
}

#[derive(Clone)]
pub(crate) struct UpstreamClients {
    // Global clients remain available for policy-directed DoH redirects and
    // GM requests, whose destination checks must not inherit a CONNECT pin.
    pub http: reqwest::Client,
    pub upgrade: UpgradeClient,
    pinned: Option<(reqwest::Client, UpgradeClient)>,
    upgrade_tls: rustls::ClientConfig,
    #[cfg(test)]
    test_roots: Option<Vec<reqwest::Certificate>>,
}

impl UpstreamClients {
    pub fn new(http: reqwest::Client) -> std::io::Result<Self> {
        let tls = rustls::ClientConfig::builder()
            .with_native_roots()?
            .with_no_client_auth();
        Ok(Self::from_config(http, tls))
    }

    fn from_config(http: reqwest::Client, upgrade_tls: rustls::ClientConfig) -> Self {
        Self {
            http,
            upgrade: upgrade_client(&upgrade_tls, None),
            pinned: None,
            upgrade_tls,
            #[cfg(test)]
            test_roots: None,
        }
    }

    /// A separate pool per CONNECT prevents one IP (or hostname) from reusing
    /// another tunnel's connection. The URL remains the TLS identity, so both
    /// clients send its SNI and verify its certificate using their usual roots.
    pub fn for_destination(
        &self,
        identity: &Authority,
        destination: SocketAddr,
    ) -> Result<Self, reqwest::Error> {
        // The URI carries the original port. A zero resolver port lets the
        // HTTP client use that URI port, including explicit default ports.
        let builder =
            http_client_builder().resolve(identity.host(), SocketAddr::new(destination.ip(), 0));
        #[cfg(test)]
        let builder = match &self.test_roots {
            Some(roots) => builder.tls_certs_only(roots.clone()),
            None => builder,
        };
        Ok(Self {
            pinned: Some((
                builder.build()?,
                upgrade_client(&self.upgrade_tls, Some((identity.clone(), destination))),
            )),
            ..self.clone()
        })
    }

    pub fn proxy_clients(&self) -> (reqwest::Client, UpgradeClient) {
        self.pinned
            .clone()
            .unwrap_or_else(|| (self.http.clone(), self.upgrade.clone()))
    }

    #[cfg(test)]
    pub(super) fn with_test_roots(roots: &[rustls::pki_types::CertificateDer<'_>]) -> Self {
        let mut store = rustls::RootCertStore::empty();
        for root in roots {
            store.add(root.clone().into_owned()).unwrap();
        }
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(store)
            .with_no_client_auth();
        let roots: Vec<_> = roots
            .iter()
            .map(|root| reqwest::Certificate::from_der(root).unwrap())
            .collect();
        let http = http_client_builder()
            .tls_certs_only(roots.clone())
            .build()
            .unwrap();
        let mut clients = Self::from_config(http, tls);
        clients.test_roots = Some(roots);
        clients
    }
}

fn upgrade_client(
    tls: &rustls::ClientConfig,
    destination: Option<(Authority, SocketAddr)>,
) -> UpgradeClient {
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    http.set_nodelay(true);
    http.set_connect_timeout(Some(Duration::from_secs(10)));
    http.set_keepalive(Some(Duration::from_secs(60)));
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls.clone())
        .https_or_http()
        .enable_http1()
        .wrap_connector(DestinationConnector { http, destination });
    // Upgraded connections are consumed by their tunnels; do not pool them.
    Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(0)
        .build(https)
}

/// hyper-rustls chooses SNI/verification from the original URI before calling
/// this connector. Only TCP dialing sees the CONNECT IP. Other destinations
/// (e.g. a configured DoH redirect) keep their normal routing and verification.
#[derive(Clone)]
pub(crate) struct DestinationConnector {
    http: HttpConnector,
    destination: Option<(Authority, SocketAddr)>,
}

impl Service<Uri> for DestinationConnector {
    type Response = <HttpConnector as Service<Uri>>::Response;
    type Error = <HttpConnector as Service<Uri>>::Error;
    type Future = <HttpConnector as Service<Uri>>::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.http.poll_ready(cx)
    }

    fn call(&mut self, mut uri: Uri) -> Self::Future {
        if let Some((identity, destination)) = &self.destination {
            if uri.authority() == Some(identity) {
                let mut parts = uri.into_parts();
                parts.authority = Some(destination.to_string().parse().expect("socket authority"));
                uri = Uri::from_parts(parts).expect("valid destination URI");
            }
        }
        self.http.call(uri)
    }
}
