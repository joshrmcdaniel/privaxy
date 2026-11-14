//! Local CONNECT/TLS regressions. All keys and trusted roots are ephemeral;
//! these fixtures never load configuration, production CAs or public services.
use super::*;
use crate::blocker::BlockingDisabledStore;
use crate::proxy::{gm::storage::GmStorageStore, userscripts::UserScriptStore};
use http_body_util::BodyExt;
use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{
        extension::{BasicConstraints, ExtendedKeyUsage, SubjectAlternativeName},
        X509NameBuilder, X509,
    },
};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    ClientConfig, ServerConfig,
};
use std::{
    collections::BTreeMap,
    io,
    sync::{OnceLock, RwLock},
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::mpsc,
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tokio_rustls::{client::TlsStream, LazyConfigAcceptor, TlsConnector};

const TEST_TIMEOUT: Duration = Duration::from_secs(15);

struct Pki {
    proxy: (X509, PKey<Private>),
    upstream: (X509, PKey<Private>),
    untrusted: (X509, PKey<Private>),
    leaf_key: PKey<Private>,
}

fn pki() -> &'static Pki {
    static PKI: OnceLock<Pki> = OnceLock::new();
    PKI.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
        Pki {
            proxy: crate::ca::make_ca_certificate(),
            upstream: crate::ca::make_ca_certificate(),
            untrusted: crate::ca::make_ca_certificate(),
            leaf_key: PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap(),
        }
    })
}

fn der(cert: &X509) -> CertificateDer<'static> {
    cert.to_der().unwrap().into()
}

// Independent origin certificates: don't use Privaxy's leaf generator for
// both sides of a hostname-verification regression.
fn origin_config(host: &str, trusted: bool, expired: bool) -> Arc<ServerConfig> {
    let pki = pki();
    let (ca, key) = if trusted {
        &pki.upstream
    } else {
        &pki.untrusted
    };
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    let mut serial = BigNum::new().unwrap();
    serial.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();
    cert.set_serial_number(&serial.to_asn1_integer().unwrap())
        .unwrap();
    let mut subject = X509NameBuilder::new().unwrap();
    subject.append_entry_by_text("CN", host).unwrap();
    cert.set_subject_name(&subject.build()).unwrap();
    cert.set_issuer_name(ca.subject_name()).unwrap();
    cert.set_pubkey(&pki.leaf_key).unwrap();
    let (start, end) = if expired {
        (
            Asn1Time::from_unix(1).unwrap(),
            Asn1Time::from_unix(2).unwrap(),
        )
    } else {
        (
            Asn1Time::days_from_now(0).unwrap(),
            Asn1Time::days_from_now(1).unwrap(),
        )
    };
    cert.set_not_before(&start).unwrap();
    cert.set_not_after(&end).unwrap();
    cert.append_extension(BasicConstraints::new().build().unwrap())
        .unwrap();
    cert.append_extension(ExtendedKeyUsage::new().server_auth().build().unwrap())
        .unwrap();
    let mut san = SubjectAlternativeName::new();
    if host.parse::<IpAddr>().is_ok() {
        san.ip(host);
    } else {
        san.dns(host);
    }
    cert.append_extension(san.build(&cert.x509v3_context(Some(ca), None)).unwrap())
        .unwrap();
    cert.sign(key, MessageDigest::sha256()).unwrap();
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![der(&cert.build()), der(ca)],
            PrivateKeyDer::try_from(pki.leaf_key.private_key_to_der().unwrap()).unwrap(),
        )
        .unwrap();
    Arc::new(config)
}

fn client_config(proxy: bool, sni: bool) -> Arc<ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(der(if proxy {
            &pki().proxy.0
        } else {
            &pki().upstream.0
        }))
        .unwrap();
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    // Disabling SNI does not disable certificate hostname/IP verification.
    config.enable_sni = sni;
    Arc::new(config)
}

struct Task(JoinHandle<()>);
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Proxy {
    addr: SocketAddr,
    _task: Task,
}

impl Proxy {
    async fn start(policy: LocalExclusionStore) -> Self {
        Self::with_doh(policy, DohConfig::default()).await
    }

    async fn with_doh(policy: LocalExclusionStore, doh_config: DohConfig) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let clients = UpstreamClients::with_test_roots(&[der(&pki().upstream.0)]);
        let cache = CertCache::new(pki().proxy.0.clone(), pki().proxy.1.clone());
        let blocker = AdblockRequester::new(BlockingDisabledStore(Arc::new(RwLock::new(false))));
        let (events, _) = broadcast::channel(4);
        let task = tokio::spawn(async move {
            let mut sessions = JoinSet::new();
            while let Ok((stream, peer)) = listener.accept().await {
                let clients = clients.clone();
                let cache = cache.clone();
                let blocker = blocker.clone();
                let events = events.clone();
                let policy = policy.clone();
                let doh_config = doh_config.clone();
                sessions.spawn(async move {
                    let service = service_fn(move |request| {
                        serve_mitm_session(
                            blocker.clone(),
                            clients.clone(),
                            request,
                            cache.clone(),
                            events.clone(),
                            Statistics::new(),
                            peer.ip(),
                            policy.clone(),
                            doh_config.clone(),
                            false,
                            TlsFailureStore::new(Default::default()),
                            None,
                            UserScriptContext {
                                store: UserScriptStore::default(),
                                gm_storage: GmStorageStore::in_memory(),
                                endpoint_signing_key: "fixture-only".into(),
                                allow_private_network_requests: Default::default(),
                            },
                        )
                    });
                    let _ = auto::Builder::new(TokioExecutor::new())
                        .serve_connection_with_upgrades(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        Self {
            addr,
            _task: Task(task),
        }
    }

    async fn connect(
        &self,
        destination: &str,
        config: Arc<ClientConfig>,
        name: &str,
    ) -> TlsStream<TcpStream> {
        let mut tcp = TcpStream::connect(self.addr).await.unwrap();
        tcp.write_all(
            format!("CONNECT {destination} HTTP/1.1\r\nHost: {destination}\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
        assert!(read_headers(&mut tcp)
            .await
            .unwrap()
            .starts_with(b"HTTP/1.1 200"));
        timeout(
            TEST_TIMEOUT,
            TlsConnector::from(config).connect(ServerName::try_from(name.to_owned()).unwrap(), tcp),
        )
        .await
        .unwrap()
        .unwrap()
    }
}

// Read exactly through the header terminator, retaining TLS/DNS bytes that
// might arrive in the same TCP packet.
async fn read_headers(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        bytes.push(stream.read_u8().await?);
        assert!(bytes.len() < 32 * 1024);
    }
    Ok(bytes)
}

#[derive(Clone, Copy)]
enum Protocol {
    Http,
    HttpKeepAlive,
    HttpWaitForPeer,
    Http2RefuseOnce,
    Http2ResponseHeaders(usize),
    Dns,
    Upgrade,
}

struct Origin {
    addr: SocketAddr,
    requests: mpsc::UnboundedReceiver<(Option<String>, Vec<u8>)>,
    _task: Task,
}

impl Origin {
    async fn start(configs: Vec<(&str, Arc<ServerConfig>)>, protocol: Protocol) -> Self {
        Self::bind("127.0.0.1:0", configs, protocol).await
    }

    async fn bind(
        address: &str,
        configs: Vec<(&str, Arc<ServerConfig>)>,
        protocol: Protocol,
    ) -> Self {
        let listener = TcpListener::bind(address).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let fallback = configs[0].1.clone();
        let configs: BTreeMap<_, _> = configs
            .into_iter()
            .map(|(name, config)| (name.to_owned(), config))
            .collect();
        let (tx, requests) = mpsc::unbounded_channel();
        let response_gate = Arc::new(tokio::sync::Notify::new());
        let task = tokio::spawn(async move {
            let mut sessions = JoinSet::new();
            while let Ok((tcp, _)) = listener.accept().await {
                let configs = configs.clone();
                let fallback = fallback.clone();
                let tx = tx.clone();
                let response_gate = response_gate.clone();
                sessions.spawn(async move {
                    let Ok(hello) = LazyConfigAcceptor::new(Default::default(), tcp).await else { return; };
                    let name = hello.client_hello().server_name().map(str::to_owned);
                    let config = name.as_ref().and_then(|name| configs.get(name)).unwrap_or(&fallback).clone();
                    let Ok(mut tls) = hello.into_stream(config).await else { return; };
                    match protocol {
                        Protocol::Http | Protocol::HttpKeepAlive | Protocol::HttpWaitForPeer => {
                            let keep_alive = matches!(protocol, Protocol::HttpKeepAlive);
                            loop {
                                let Ok(request) = read_headers(&mut tls).await else { return; };
                                let slow = request.starts_with(b"GET /slow ");
                                let fast = request.starts_with(b"GET /fast ");
                                tx.send((name.clone(), request)).unwrap();
                                if matches!(protocol, Protocol::HttpWaitForPeer) {
                                    if slow {
                                        response_gate.notified().await;
                                    } else if fast {
                                        response_gate.notify_one();
                                    }
                                }
                                let body = format!("upstream:{}", name.as_deref().unwrap_or("no-sni"));
                                let connection = if keep_alive { "keep-alive" } else { "close" };
                                tls.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: {connection}\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
                                if !keep_alive { break; }
                            }
                        }
                        Protocol::Dns => {
                            // Two actual DNS-over-TCP frames, including their
                            // length prefixes and binary DNS response headers.
                            for _ in 0..2 {
                                let length = tls.read_u16().await.unwrap();
                                let mut query = vec![0; length as usize];
                                tls.read_exact(&mut query).await.unwrap();
                                tx.send((name.clone(), query.clone())).unwrap();
                                query[2..4].copy_from_slice(&[0x81, 0x83]); // NXDOMAIN
                                tls.write_u16(length).await.unwrap();
                                tls.write_all(&query).await.unwrap();
                            }
                        }
                        Protocol::Http2RefuseOnce => {
                            let mut connection = h2::server::handshake(tls).await.unwrap();
                            let mut refused = false;
                            while let Some(request) = connection.accept().await {
                                let (request, mut respond) = request.unwrap();
                                tx.send((name.clone(), request.method().as_str().as_bytes().to_vec())).unwrap();
                                if !refused {
                                    // The origin explicitly guarantees it did
                                    // not process this request. A bodyless GET
                                    // should be replayed by reqwest's policy.
                                    respond.send_reset(h2::Reason::REFUSED_STREAM);
                                    refused = true;
                                } else {
                                    let response = http::Response::builder()
                                        .header("content-type", "text/plain")
                                        .body(())
                                        .unwrap();
                                    respond.send_response(response, false).unwrap()
                                        .send_data(bytes::Bytes::from_static(b"retried"), true).unwrap();
                                }
                            }
                            return;
                        }
                        Protocol::Http2ResponseHeaders(size) => {
                            let mut connection = h2::server::handshake(tls).await.unwrap();
                            while let Some(request) = connection.accept().await {
                                let (request, mut respond) = request.unwrap();
                                tx.send((name.clone(), request.method().as_str().as_bytes().to_vec())).unwrap();
                                let response = http::Response::builder()
                                    .header("content-type", "text/plain")
                                    .header("content-security-policy", format!("script-src https://{}.test", "a".repeat(size)))
                                    .body(())
                                    .unwrap();
                                respond.send_response(response, false).unwrap()
                                    .send_data(bytes::Bytes::from_static(b"large headers"), true).unwrap();
                            }
                            return;
                        }
                        Protocol::Upgrade => {
                            let request = read_headers(&mut tls).await.unwrap();
                            tx.send((name, request)).unwrap();
                            tls.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n").await.unwrap();
                            let mut payload = [0; 4];
                            tls.read_exact(&mut payload).await.unwrap();
                            tls.write_all(&payload).await.unwrap();
                        }
                    }
                    let _ = tls.shutdown().await;
                });
            }
        });
        Self {
            addr,
            requests,
            _task: Task(task),
        }
    }

    async fn request(&mut self) -> (Option<String>, Vec<u8>) {
        timeout(TEST_TIMEOUT, self.requests.recv())
            .await
            .unwrap()
            .unwrap()
    }
}

async fn http_get(
    stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
) -> (http::StatusCode, String) {
    http_request(stream, "https://unrelated.invalid:1234/test", "text/plain").await
}

async fn http_request(
    stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    uri: &str,
    accept: &str,
) -> (http::StatusCode, String) {
    // Neither an inner Host nor an absolute URL may change the selected peer.
    let request = Request::builder()
        .uri(uri)
        .header("Host", "unrelated.invalid:1234")
        .header("Accept", accept)
        .body(empty_body())
        .unwrap();
    send_http_request(stream, request).await
}

async fn send_http_request(
    stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    request: Request<ProxyBody>,
) -> (http::StatusCode, String) {
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let _task = Task(tokio::spawn(async {
        let _ = connection.await;
    }));
    let response = timeout(TEST_TIMEOUT, sender.send_request(request))
        .await
        .unwrap()
        .unwrap();
    let status = response.status();
    let bytes = timeout(TEST_TIMEOUT, response.into_body().collect())
        .await
        .unwrap()
        .unwrap()
        .to_bytes();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

fn peer_certificate<IO>(tls: &TlsStream<IO>) -> X509 {
    X509::from_der(tls.get_ref().1.peer_certificates().unwrap()[0].as_ref()).unwrap()
}

fn assert_dns_identity(cert: &X509, host: &str) {
    let names = cert.subject_alt_names().unwrap();
    assert_eq!(names.len(), 1);
    assert_eq!(names[0].dnsname(), Some(host));
    assert!(cert.verify(&pki().proxy.0.public_key().unwrap()).unwrap());
}

#[tokio::test]
async fn ip_connect_uses_sni_for_certificates_upstream_tls_and_cache() {
    let mut origin = Origin::start(
        vec![
            ("one.test", origin_config("one.test", true, false)),
            ("two.test", origin_config("two.test", true, false)),
        ],
        Protocol::Http,
    )
    .await;
    let proxy = Proxy::start(LocalExclusionStore::new(vec![])).await;
    let mut first_cert = None;
    for host in ["one.test", "two.test", "one.test"] {
        let tls = proxy
            .connect(&origin.addr.to_string(), client_config(true, true), host)
            .await;
        let cert = peer_certificate(&tls);
        assert_dns_identity(&cert, host);
        if host == "one.test" {
            if let Some(first) = &first_cert {
                assert_eq!(&cert.to_der().unwrap(), first);
            } else {
                first_cert = Some(cert.to_der().unwrap());
            }
        }
        let (status, body) = http_get(tls).await;
        assert_eq!(status, http::StatusCode::OK, "{body}");
        assert_eq!(body, format!("upstream:{host}"));
        let (sni, request) = origin.request().await;
        assert_eq!(sni.as_deref(), Some(host));
        let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
        assert!(request.starts_with("get /test http/1.1"));
        assert!(request.contains(&format!("host: {host}:{}\r\n", origin.addr.port())));
    }
}

#[tokio::test]
async fn same_sni_on_different_connect_destinations_does_not_reuse_the_wrong_pool() {
    let mut first = Origin::start(
        vec![("shared.test", origin_config("shared.test", true, false))],
        Protocol::HttpKeepAlive,
    )
    .await;
    let address = format!("127.0.0.2:{}", first.addr.port());
    let mut second = Origin::bind(
        &address,
        vec![("shared.test", origin_config("shared.test", true, false))],
        Protocol::HttpKeepAlive,
    )
    .await;
    let proxy = Proxy::start(LocalExclusionStore::new(vec![])).await;
    for index in 0..3 {
        let origin = if index == 1 { &mut second } else { &mut first };
        let tls = proxy
            .connect(
                &origin.addr.to_string(),
                client_config(true, true),
                "shared.test",
            )
            .await;
        assert_eq!(http_get(tls).await.0, http::StatusCode::OK);
        assert_eq!(origin.request().await.0.as_deref(), Some("shared.test"));
    }
}

#[tokio::test]
async fn hostname_and_literal_ip_connect_keep_verification_and_missing_sni_behavior() {
    for (connect_host, identity, send_sni) in [
        ("localhost", "localhost", true),
        ("localhost", "localhost", false),
        ("127.0.0.1", "127.0.0.1", false),
        ("[::1]", "::1", false),
        ("[::1]", "one.test", true),
    ] {
        let bind = if connect_host == "[::1]" {
            "[::1]:0"
        } else {
            "127.0.0.1:0"
        };
        let mut origin = Origin::bind(
            bind,
            vec![(identity, origin_config(identity, true, false))],
            Protocol::Http,
        )
        .await;
        let proxy = Proxy::start(LocalExclusionStore::new(vec![])).await;
        let authority = format!("{connect_host}:{}", origin.addr.port());
        let tls = proxy
            .connect(&authority, client_config(true, send_sni), identity)
            .await;
        let cert = peer_certificate(&tls);
        if identity.parse::<IpAddr>().is_err() {
            assert_dns_identity(&cert, identity);
        } else {
            assert!(cert.subject_alt_names().unwrap()[0].ipaddress().is_some());
        }
        let (status, body) = http_get(tls).await;
        assert_eq!(status, http::StatusCode::OK, "{body}");
        let upstream_sni = origin.request().await.0;
        assert_eq!(
            upstream_sni.as_deref(),
            if identity.parse::<IpAddr>().is_err() {
                Some(identity)
            } else {
                None
            }
        );
    }
}

#[tokio::test]
async fn ip_connect_without_sni_does_not_guess_a_dns_identity() {
    let origin = Origin::start(
        vec![("one.test", origin_config("one.test", true, false))],
        Protocol::Http,
    )
    .await;
    let proxy = Proxy::start(LocalExclusionStore::new(vec![])).await;
    let mut tcp = TcpStream::connect(proxy.addr).await.unwrap();
    tcp.write_all(format!("CONNECT {} HTTP/1.1\r\n\r\n", origin.addr).as_bytes())
        .await
        .unwrap();
    read_headers(&mut tcp).await.unwrap();
    let result = timeout(
        TEST_TIMEOUT,
        TlsConnector::from(client_config(true, false))
            .connect(ServerName::try_from("one.test").unwrap(), tcp),
    )
    .await
    .unwrap();
    assert!(
        result.is_err(),
        "a DNS verifier must not accept an IP-only certificate"
    );
}

#[tokio::test]
async fn sni_exclusions_and_ip_exclusions_bypass_interception() {
    for (host, exclusions) in [
        ("excluded.test", vec!["*.test".into()]),
        ("www.apple.com", vec![]), // built-in exclusion from the reported failure
        ("one.test", vec!["127.0.0.1".into()]),
    ] {
        let mut origin = Origin::start(
            vec![(host, origin_config(host, true, false))],
            Protocol::Http,
        )
        .await;
        let proxy = Proxy::start(LocalExclusionStore::new(exclusions)).await;
        // Trust only the origin CA: a minted interception cert must fail here.
        let tls = proxy
            .connect(&origin.addr.to_string(), client_config(false, true), host)
            .await;
        assert!(peer_certificate(&tls)
            .verify(&pki().upstream.0.public_key().unwrap())
            .unwrap());
        assert_eq!(http_get(tls).await.0, http::StatusCode::OK);
        assert_eq!(origin.request().await.0.as_deref(), Some(host));
    }
}

#[tokio::test]
async fn include_only_rules_are_evaluated_after_ip_sni_and_exclusions_win() {
    let origin = Origin::start(
        vec![("included.test", origin_config("included.test", true, false))],
        Protocol::Http,
    )
    .await;
    for (exclusions, intercept) in [
        (vec![], true),
        (vec!["included.test".into()], false),
        (vec!["127.0.0.1".into()], false),
    ] {
        let policy =
            LocalExclusionStore::with_rules(true, vec!["included.test".into()], exclusions);
        let proxy = Proxy::start(policy).await;
        let tls = proxy
            .connect(
                &origin.addr.to_string(),
                client_config(intercept, true),
                "included.test",
            )
            .await;
        if intercept {
            assert_dns_identity(&peer_certificate(&tls), "included.test");
        }
        assert_eq!(http_get(tls).await.0, http::StatusCode::OK);
    }
}

#[tokio::test]
async fn browser_alpn_enables_parallel_http2_requests_and_keeps_http1() {
    let host = "multiplex.test";
    let mut origin = Origin::start(
        vec![(host, origin_config(host, true, false))],
        Protocol::HttpWaitForPeer,
    )
    .await;
    let proxy = Proxy::start(LocalExclusionStore::new(vec![])).await;
    let mut config = (*client_config(true, true)).clone();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let tls = proxy
        .connect(&origin.addr.to_string(), Arc::new(config), host)
        .await;
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .unwrap();
    let _task = Task(tokio::spawn(async {
        let _ = connection.await;
    }));

    // The first origin response is held until the second request arrives.
    // Both requests must share this one browser-side TLS connection.
    let slow = tokio::spawn(
        sender.send_request(
            Request::builder()
                .uri("https://unrelated.invalid/slow")
                .body(empty_body())
                .unwrap(),
        ),
    );
    let (sni, request) = origin.request().await;
    assert_eq!(sni.as_deref(), Some(host));
    assert!(request.starts_with(b"GET /slow "));
    let response = timeout(
        TEST_TIMEOUT,
        sender.send_request(
            Request::builder()
                .uri("https://unrelated.invalid/fast")
                // Cookie-heavy browsers must not hit hyper's 16 KiB default
                // when they start negotiating HTTP/2 with the proxy.
                .header("cookie", format!("padding={}", "a".repeat(24 * 1024)))
                .body(empty_body())
                .unwrap(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let slow_response = timeout(TEST_TIMEOUT, slow).await.unwrap().unwrap().unwrap();
    for response in [response, slow_response] {
        assert_eq!(response.status(), http::StatusCode::OK);
        let body = timeout(TEST_TIMEOUT, response.into_body().collect())
            .await
            .unwrap()
            .unwrap()
            .to_bytes();
        assert_eq!(body, format!("upstream:{host}"));
    }
    let (sni, request) = origin.request().await;
    assert_eq!(sni.as_deref(), Some(host));
    assert!(request.starts_with(b"GET /fast "));
    assert!(String::from_utf8(request)
        .unwrap()
        .contains(&format!("host: {host}:{}", origin.addr.port())));

    let mut config = (*client_config(true, true)).clone();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tls = proxy
        .connect(&origin.addr.to_string(), Arc::new(config), host)
        .await;
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(b"http/1.1".as_slice())
    );
    assert_eq!(http_get(tls).await.0, http::StatusCode::OK);
}

#[tokio::test]
async fn empty_get_retries_a_refused_http2_stream() {
    let mut config = (*origin_config("retry.test", true, false)).clone();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let mut origin = Origin::start(
        vec![("retry.test", Arc::new(config))],
        Protocol::Http2RefuseOnce,
    )
    .await;
    let proxy = Proxy::start(LocalExclusionStore::new(vec![])).await;
    let tls = proxy
        .connect(
            &origin.addr.to_string(),
            client_config(true, true),
            "retry.test",
        )
        .await;

    let (status, body) = http_get(tls).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(body, "retried");
    for _ in 0..2 {
        let (sni, method) = origin.request().await;
        assert_eq!(sni.as_deref(), Some("retry.test"));
        assert_eq!(method, b"GET");
    }
    assert!(origin.requests.try_recv().is_err());
}

#[tokio::test]
async fn nonempty_requests_are_not_replayed_after_http2_refusal() {
    for method in [Method::GET, Method::POST] {
        let mut config = (*origin_config("retry.test", true, false)).clone();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let mut origin = Origin::start(
            vec![("retry.test", Arc::new(config))],
            Protocol::Http2RefuseOnce,
        )
        .await;
        let proxy = Proxy::start(LocalExclusionStore::new(vec![])).await;
        let tls = proxy
            .connect(
                &origin.addr.to_string(),
                client_config(true, true),
                "retry.test",
            )
            .await;
        let request = Request::builder()
            .method(method.clone())
            .uri("/upload")
            .body(crate::proxy::full_body("must not be replayed"))
            .unwrap();
        let (status, _) = send_http_request(tls, request).await;
        assert_eq!(status, http::StatusCode::BAD_GATEWAY);
        assert_eq!(origin.request().await.1, method.as_str().as_bytes());
        assert!(origin.requests.try_recv().is_err());
    }
}

#[tokio::test]
async fn large_http2_response_headers_are_accepted_with_a_bounded_limit() {
    // Exercise the shared client (literal IP) and an SNI-pinned client. The
    // decoded size, including HPACK's per-field overhead, matters here, not
    // the compressed bytes on the wire.
    for host in ["127.0.0.1", "headers.test"] {
        for (size, expected) in [
            (24 * 1024, http::StatusCode::OK),
            (128 * 1024, http::StatusCode::BAD_GATEWAY),
        ] {
            let mut config = (*origin_config(host, true, false)).clone();
            config.alpn_protocols = vec![b"h2".to_vec()];
            let origin = Origin::start(
                vec![(host, Arc::new(config))],
                Protocol::Http2ResponseHeaders(size),
            )
            .await;
            let proxy = Proxy::start(LocalExclusionStore::new(vec![])).await;
            let tls = proxy
                .connect(&origin.addr.to_string(), client_config(true, true), host)
                .await;
            let (status, body) = http_get(tls).await;
            let reason = body
                .lines()
                .find(|line| line.contains("error sending request"))
                .unwrap_or(&body);
            assert_eq!(status, expected, "host={host}, size={size}: {reason}");
            if expected == http::StatusCode::OK {
                assert_eq!(body, "large headers");
            }
        }
    }
}

#[tokio::test]
async fn invalid_upstream_certificates_are_rejected() {
    for (cert_host, trusted, expired) in [
        ("one.test", false, false),
        ("wrong.test", true, false),
        ("one.test", true, true),
    ] {
        let mut origin = Origin::start(
            vec![("one.test", origin_config(cert_host, trusted, expired))],
            Protocol::Http,
        )
        .await;
        let proxy = Proxy::start(LocalExclusionStore::new(vec![])).await;
        let tls = proxy
            .connect(
                &origin.addr.to_string(),
                client_config(true, true),
                "one.test",
            )
            .await;
        let (status, body) = http_get(tls).await;
        assert_eq!(
            status,
            http::StatusCode::BAD_GATEWAY,
            "cert={cert_host}, trusted={trusted}, expired={expired}"
        );
        assert!(body.contains("invalid peer certificate"), "{body}");
        assert!(
            origin.requests.try_recv().is_err(),
            "HTTP must never reach an unverified peer"
        );
        // The separate hyper client used for upgrades must reject it too.
        let mut tls = proxy
            .connect(
                &origin.addr.to_string(),
                client_config(true, true),
                "one.test",
            )
            .await;
        tls.write_all(b"GET /socket HTTP/1.1\r\nHost: one.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n").await.unwrap();
        let response = timeout(TEST_TIMEOUT, read_headers(&mut tls))
            .await
            .unwrap()
            .unwrap();
        assert!(response.starts_with(b"HTTP/1.1 502"));
        assert!(origin.requests.try_recv().is_err());
    }
}

#[tokio::test]
async fn ip_connect_protocol_upgrades_keep_the_destination_and_verify_sni() {
    let mut origin = Origin::start(
        vec![("upgrade.test", origin_config("upgrade.test", true, false))],
        Protocol::Upgrade,
    )
    .await;
    let proxy = Proxy::start(LocalExclusionStore::new(vec![])).await;
    let mut tls = proxy
        .connect(
            &origin.addr.to_string(),
            client_config(true, true),
            "upgrade.test",
        )
        .await;
    tls.write_all(b"GET /socket HTTP/1.1\r\nHost: unrelated.invalid\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n").await.unwrap();
    let response = timeout(TEST_TIMEOUT, read_headers(&mut tls))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 101"));
    tls.write_all(b"ping").await.unwrap();
    let mut echo = [0; 4];
    timeout(TEST_TIMEOUT, tls.read_exact(&mut echo))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&echo, b"ping");
    let (sni, request) = origin.request().await;
    assert_eq!(sni.as_deref(), Some("upgrade.test"));
    assert!(String::from_utf8(request)
        .unwrap()
        .contains(&format!("host: upgrade.test:{}", origin.addr.port())));
}

#[tokio::test]
async fn dns_over_tls_passes_binary_queries_and_responses_unchanged() {
    let mut origin = Origin::start(
        vec![("dns.quad9.net", origin_config("dns.quad9.net", true, false))],
        Protocol::Dns,
    )
    .await;
    // An ephemeral unprivileged port keeps this test runnable without root.
    // Standard port 853's automatic bypass is covered separately below.
    let proxy = Proxy::start(LocalExclusionStore::new(vec!["dns.quad9.net".into()])).await;
    let mut tls = proxy
        .connect(
            &origin.addr.to_string(),
            client_config(false, true),
            "dns.quad9.net",
        )
        .await;
    for id in [0x12, 0x34] {
        let query = [
            id, 0x56, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l',
            b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
        ];
        tls.write_u16(query.len() as u16).await.unwrap();
        tls.write_all(&query).await.unwrap();
        let length = timeout(TEST_TIMEOUT, tls.read_u16())
            .await
            .unwrap()
            .unwrap();
        let mut response = vec![0; length as usize];
        timeout(TEST_TIMEOUT, tls.read_exact(&mut response))
            .await
            .unwrap()
            .unwrap();
        let mut expected = query;
        expected[2..4].copy_from_slice(&[0x81, 0x83]);
        assert_eq!(response, expected);
        let (sni, received) = origin.request().await;
        assert_eq!(sni.as_deref(), Some("dns.quad9.net"));
        assert_eq!(received, query);
    }
}

#[test]
fn standard_dot_port_bypasses_without_consuming_tls_or_entering_http() {
    let policy = LocalExclusionStore::new(vec![]);
    for destination in ["9.9.9.9:853", "[2620:fe::fe]:853", "dns.quad9.net:853"] {
        let authority: Authority = destination.parse().unwrap();
        assert!(bypass_before_client_hello(&policy, &authority, &authority));
    }
    let https: Authority = "9.9.9.9:443".parse().unwrap();
    assert!(!bypass_before_client_hello(&policy, &https, &https));
}

fn initial_client_hello(
    config: Arc<ClientConfig>,
    host: &str,
) -> (rustls::ClientConnection, Vec<u8>) {
    let mut client =
        rustls::ClientConnection::new(config, ServerName::try_from(host.to_owned()).unwrap())
            .unwrap();
    let mut bytes = Vec::new();
    client.write_tls(&mut bytes).unwrap();
    (client, bytes)
}

/// Split the handshake itself across TLS records as well as TCP writes. Just
/// fragmenting TCP would miss implementations that only parse the first record.
fn fragment_records(wire: &[u8]) -> Vec<u8> {
    let mut fragmented = Vec::new();
    let mut offset = 0;
    while offset < wire.len() {
        let header = &wire[offset..offset + 5];
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
        for chunk in wire[offset + 5..offset + 5 + length].chunks(17) {
            fragmented.extend_from_slice(&header[..3]);
            fragmented.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
            fragmented.extend_from_slice(chunk);
        }
        offset += 5 + length;
    }
    fragmented
}

async fn flush_tls(client: &mut rustls::ClientConnection, tcp: &mut TcpStream) {
    while client.wants_write() {
        let mut bytes = Vec::new();
        client.write_tls(&mut bytes).unwrap();
        tcp.write_all(&bytes).await.unwrap();
    }
}

async fn receive_tls(client: &mut rustls::ClientConnection, tcp: &mut TcpStream) {
    let mut bytes = [0; 16 * 1024];
    let length = tcp.read(&mut bytes).await.unwrap();
    assert_ne!(length, 0, "TLS peer closed unexpectedly");
    let mut reader = &bytes[..length];
    while !reader.is_empty() {
        assert_ne!(client.read_tls(&mut reader).unwrap(), 0);
        client.process_new_packets().unwrap();
    }
}

#[tokio::test]
async fn fragmented_client_hello_and_connect_read_ahead_work_for_mitm_and_bypass() {
    for intercept in [true, false] {
        let mut origin = Origin::start(
            vec![("fragment.test", origin_config("fragment.test", true, false))],
            Protocol::Http,
        )
        .await;
        let policy = LocalExclusionStore::new(if intercept {
            vec![]
        } else {
            vec!["fragment.test".into()]
        });
        let proxy = Proxy::start(policy).await;
        timeout(TEST_TIMEOUT, async {
            let (mut client, hello) =
                initial_client_hello(client_config(intercept, true), "fragment.test");
            let hello = fragment_records(&hello);
            let mut tcp = TcpStream::connect(proxy.addr).await.unwrap();
            tcp.set_nodelay(true).unwrap();
            let mut request = format!(
                "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                origin.addr, origin.addr
            )
            .into_bytes();
            // Exercise hyper's upgrade read-ahead with a partial TLS header.
            request.extend_from_slice(&hello[..3]);
            tcp.write_all(&request).await.unwrap();
            assert!(read_headers(&mut tcp)
                .await
                .unwrap()
                .starts_with(b"HTTP/1.1 200"));
            for chunk in hello[3..].chunks(3) {
                tcp.write_all(chunk).await.unwrap();
                tokio::task::yield_now().await;
            }
            while client.is_handshaking() {
                flush_tls(&mut client, &mut tcp).await;
                receive_tls(&mut client, &mut tcp).await;
            }
            if intercept {
                let cert = X509::from_der(client.peer_certificates().unwrap()[0].as_ref()).unwrap();
                assert_dns_identity(&cert, "fragment.test");
            }
            std::io::Write::write_all(
                &mut client.writer(),
                b"GET /fragment HTTP/1.1\r\nHost: fragment.test\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
            flush_tls(&mut client, &mut tcp).await;
            let mut response = Vec::new();
            loop {
                receive_tls(&mut client, &mut tcp).await;
                match std::io::Read::read_to_end(&mut client.reader(), &mut response) {
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => panic!("TLS read: {error}"),
                }
                if response.ends_with(b"upstream:fragment.test") {
                    break;
                }
            }
            assert!(response.starts_with(b"HTTP/1.1 200"));
            assert_eq!(origin.request().await.0.as_deref(), Some("fragment.test"));
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn client_hello_parser_retains_every_byte_at_all_record_and_buffer_boundaries() {
    let (_, hello) = initial_client_hello(client_config(true, true), "fragment.test");
    let mut wire = fragment_records(&hello);
    // Bytes after the ClientHello may already be buffered, including TLS 1.3
    // compatibility CCS or early data. A tunnel must preserve them verbatim.
    wire.extend_from_slice(b"\x14\x03\x03\x00\x01\x01buffered-after-hello");
    for capacity in [1, 2, 5, 19, 8192] {
        let (mut writer, reader) = tokio::io::duplex(wire.len());
        writer.write_all(&wire).await.unwrap();
        writer.shutdown().await.unwrap();
        let (mut hello, mut replay) = read_client_hello(BufReader::with_capacity(capacity, reader))
            .await
            .unwrap();
        assert_eq!(hello.client_hello().server_name(), Some("fragment.test"));
        hello.io.read_to_end(&mut replay).await.unwrap();
        assert_eq!(replay, wire, "buffer capacity {capacity}");
    }
}

#[tokio::test]
async fn malformed_truncated_and_oversized_client_hellos_fail_closed() {
    let mut oversized = vec![0x16, 3, 1, 0, 4, 1, 1, 0, 1];
    for _ in 0..5 {
        oversized.extend_from_slice(&[0x16, 3, 1, 0x40, 0]);
        oversized.extend_from_slice(&[0; 16 * 1024]);
    }
    for bytes in [
        b"\x16\x03\x01\x00\x20\x01".to_vec(), // truncated handshake
        b"\x16\x03\x01\x00\x05\x02\x00\x00\x01\x00".to_vec(), // not ClientHello
        oversized,
    ] {
        let (mut writer, reader) = tokio::io::duplex(bytes.len());
        writer.write_all(&bytes).await.unwrap();
        writer.shutdown().await.unwrap();
        assert!(read_client_hello(BufReader::new(reader)).await.is_err());
    }
}

#[test]
fn tls_identity_only_uses_dns_sni_for_ip_connect_and_keeps_the_port() {
    for (connect, sni, expected) in [
        (
            "192.0.2.1:4443",
            Some("WWW.Example.test"),
            "www.example.test:4443",
        ),
        ("[2001:db8::1]:443", Some("one.test"), "one.test:443"),
        ("192.0.2.1:443", None, "192.0.2.1:443"),
        ("[2001:db8::1]:443", Some("192.0.2.2"), "[2001:db8::1]:443"),
        ("192.0.2.1:443", Some("invalid/host"), "192.0.2.1:443"),
        (
            "original.test:443",
            Some("different.test"),
            "original.test:443",
        ),
    ] {
        assert_eq!(
            tls_identity(&connect.parse().unwrap(), sni).as_str(),
            expected
        );
    }
}

#[tokio::test]
async fn connect_ip_pin_does_not_override_configured_doh_redirect_routing() {
    let mut resolver = Origin::start(
        vec![("localhost", origin_config("localhost", true, false))],
        Protocol::Http,
    )
    .await;
    let mut destination = Origin::bind(
        &format!("127.0.0.2:{}", resolver.addr.port()),
        vec![("localhost", origin_config("localhost", true, false))],
        Protocol::Http,
    )
    .await;
    let doh = DohConfig {
        mode: crate::configuration::DohMode::Redirect,
        upstream: Some(format!(
            "https://localhost:{}/dns-query",
            resolver.addr.port()
        )),
        extra_hosts: vec![],
    };
    let proxy = Proxy::with_doh(LocalExclusionStore::new(vec![]), doh).await;
    let tls = proxy
        .connect(
            &destination.addr.to_string(),
            client_config(true, true),
            "localhost",
        )
        .await;
    let (status, body) = http_request(tls, "/dns-query?dns=AA", "application/dns-message").await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    let (sni, request) = resolver.request().await;
    assert_eq!(sni.as_deref(), Some("localhost"));
    assert!(request.starts_with(b"GET /dns-query?dns=AA HTTP/1.1"));
    assert!(
        destination.requests.try_recv().is_err(),
        "redirect must resolve its own destination"
    );
}
