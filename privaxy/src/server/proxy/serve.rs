use super::html_rewriter::Rewriter;
use crate::blocker::AdblockRequester;
use crate::statistics::Statistics;
use crate::web_gui::events::Event;
use adblock::blocker::BlockerResult;
use http::uri::{Authority, Scheme};
use http::{StatusCode, Uri};
use hyper::body::Bytes;
use hyper::client::HttpConnector;
use hyper::{http, Body, Request, Response};
use hyper_rustls::HttpsConnector;
use std::net::IpAddr;
use tokio::sync::broadcast;

const BUFFER_SIZE: usize = 64 * 1024; // 64KB buffer

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

    // Check blocking status early to avoid unnecessary work
    let (is_request_blocked, blocker_result) = adblock_requester
        .is_network_url_blocked(
            uri.to_string(),
            req.headers()
                .get(http::header::REFERER)
                .and_then(|r| r.to_str().ok())
                .unwrap_or(&uri.to_string())
                .to_string(),
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

    // Clean up headers
    let mut request_headers = req.headers().clone();
    request_headers.remove(http::header::CONNECTION);
    request_headers.remove(http::header::HOST);

    // Send request with optimized client
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

    // Copy response headers
    *new_response.headers_mut() = response.headers().clone();

    let (mut parts, new_new_body) = new_response.into_parts();
    parts.status = response.status();

    let new_response = Response::from_parts(parts, new_new_body);

    // Handle HTML content specially
    if let Some(content_type) = response.headers().get(http::header::CONTENT_TYPE) {
        if let Ok(value) = content_type.to_str() {
            if value.contains("text/html") {
                let (sender_rewriter, receiver_rewriter) = crossbeam_channel::unbounded::<Bytes>();

                let rewriter = Rewriter::new(
                    uri.to_string(),
                    adblock_requester,
                    receiver_rewriter,
                    sender,
                    statistics,
                );

                tokio::task::spawn_blocking(|| rewriter.rewrite());

                // Stream HTML content with buffering
                let mut buffer = Vec::with_capacity(BUFFER_SIZE);
                while let Ok(Some(chunk)) = response.chunk().await {
                    buffer.extend_from_slice(&chunk);
                    if buffer.len() >= BUFFER_SIZE {
                        if let Err(_) = sender_rewriter.send(Bytes::from(buffer.clone())) {
                            break;
                        }
                        buffer.clear();
                    }
                }
                if !buffer.is_empty() {
                    let _ = sender_rewriter.send(Bytes::from(buffer));
                }

                return Ok(new_response);
            }
        }

        // Handle non-HTML content with efficient streaming
        tokio::spawn(write_proxied_body_buffered(response, sender));
        return Ok(new_response);
    }

    tokio::spawn(write_proxied_body_buffered(response, sender));
    Ok(new_response)
}

fn get_informative_error_response(reason: &str) -> Response<Body> {
    let mut response_body = String::with_capacity(1024);
    response_body.push_str(include_str!("../../resources/head.html"));
    response_body.push_str(
        &include_str!("../../resources/error.html").replace("#{request_error_reson}#", reason),
    );

    let mut response = Response::new(Body::from(response_body));
    *response.status_mut() = http::StatusCode::BAD_GATEWAY;
    response
}

fn get_blocked_by_privaxy_response(blocker_result: BlockerResult) -> Response<Body> {
    if let Some(resource) = blocker_result.redirect {
        return Response::new(Body::from(resource));
    }

    let filter_information = blocker_result
        .filter
        .unwrap_or_else(|| "No information".to_string());

    let mut response_body = String::with_capacity(1024);
    response_body.push_str(include_str!("../../resources/head.html"));
    response_body.push_str(
        &include_str!("../../resources/blocked_by_privaxy.html")
            .replace("#{matching_filter}#", &filter_information),
    );

    let mut response = Response::new(Body::from(response_body));
    *response.status_mut() = http::StatusCode::FORBIDDEN;
    response
}

fn get_empty_response(status_code: http::StatusCode) -> Response<Body> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status_code;
    response
}

async fn write_proxied_body_buffered(mut response: reqwest::Response, mut sender: hyper::body::Sender) {
    let mut buffer = Vec::with_capacity(BUFFER_SIZE);
    
    while let Ok(Some(chunk)) = response.chunk().await {
        buffer.extend_from_slice(&chunk);
        if buffer.len() >= BUFFER_SIZE {
            if sender.send_data(Bytes::from(buffer.clone())).await.is_err() {
                break;
            }
            buffer.clear();
        }
    }
    
    if !buffer.is_empty() {
        let _ = sender.send_data(Bytes::from(buffer)).await;
    }
}

async fn perform_two_ends_upgrade(
    request: Request<Body>,
    uri: Uri,
    hyper_client: hyper::Client<HttpsConnector<HttpConnector>>,
) -> Response<Body> {
    let (mut duplex_client, mut duplex_server) = tokio::io::duplex(64 * 1024); // Increased buffer size

    let mut new_request = Request::new(Body::empty());
    *new_request.headers_mut() = request.headers().clone();
    *new_request.uri_mut() = uri;

    tokio::spawn(async move {
        if let Ok(mut upgraded_client) = hyper::upgrade::on(request).await {
            let _result = tokio::io::copy_bidirectional(&mut upgraded_client, &mut duplex_client).await;
        }
    });

    let response = match hyper_client.request(new_request).await {
        Ok(response) => response,
        Err(_) => return get_empty_response(http::StatusCode::BAD_REQUEST),
    };

    let mut new_response = get_empty_response(StatusCode::SWITCHING_PROTOCOLS);
    *new_response.headers_mut() = response.headers().clone();

    if let Ok(mut upgraded_server) = hyper::upgrade::on(response).await {
        tokio::spawn(async move {
            let _result = tokio::io::copy_bidirectional(&mut upgraded_server, &mut duplex_server).await;
        });
    }

    new_response
}
