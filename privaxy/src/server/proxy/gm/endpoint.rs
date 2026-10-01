//! The reserved `/__privaxy__/gm/*` endpoints, answered by the proxy on the
//! page's own origin instead of being forwarded upstream.
//!
//! Serving these on the page origin is what makes them reachable from a
//! userscript at all: the script runs in the page's main world, so a request to
//! the Privaxy origin would be cross-origin and this codebase does not enable
//! CORS on `/api`. See [`super::token`] for what authorizes them and,
//! importantly, what that authorization does not guarantee.

use super::super::userscripts::UserScriptContext;
use super::super::{full_body, ProxyBody};
use super::fetch::{self, FetchError, FetchRequest};
use super::token;
use crate::configuration::CompiledUserScript;
use http::{Response, StatusCode, Uri};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Path prefix the proxy answers itself. Deliberately unlikely to collide with
/// a real site route; a site that does use it loses that route while Privaxy is
/// in the path.
pub(crate) const RESERVED_PATH_PREFIX: &str = "/__privaxy__/";

/// Body of `POST /__privaxy__/gm/values`.
#[derive(Debug, Deserialize)]
struct ValuesRequest {
    /// Capability minted for this script on its matching page.
    token: String,
    /// File name of the script whose values are being written.
    script: String,
    /// Keys to set, or to delete when the value is `null`.
    values: BTreeMap<String, Option<Value>>,
}

/// Whether `path` is one of the reserved endpoints.
pub(crate) fn is_reserved(path: &str) -> bool {
    path.starts_with(RESERVED_PATH_PREFIX)
}

/// The origin a page at `uri` sees, used as the token binding.
///
/// Built from the canonical request URI rather than a client-supplied `Origin`
/// header, which a hostile page could set to anything. The default port for the
/// scheme is dropped so that minting (from the page request, whose authority may
/// carry an explicit `:443` inherited from CONNECT) and verification (from the
/// script's later fetch) cannot disagree over the same origin.
pub(crate) fn origin_of(uri: &Uri) -> Option<String> {
    let url = url::Url::parse(&uri.to_string()).ok()?;
    matches!(url.scheme(), "http" | "https").then(|| url.origin().ascii_serialization())
}

fn json_response(status: StatusCode, body: &str) -> Response<ProxyBody> {
    let mut response = Response::new(full_body(body.to_string()));
    *response.status_mut() = status;
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/json"),
    );
    // These are private to the page and must never be reused from cache.
    response.headers_mut().insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );

    response
}

fn error_response(status: StatusCode, message: &str) -> Response<ProxyBody> {
    json_response(status, &serde_json::json!({ "error": message }).to_string())
}

/// Handle a request to the reserved path.
///
/// Returns a response for every reserved path, including unknown ones: once the
/// prefix matches, the request is ours and must not reach the origin server.
pub(crate) async fn handle(
    uri: &Uri,
    method: &http::Method,
    body: &[u8],
    user_scripts: &UserScriptContext,
    http_client: &reqwest::Client,
) -> Response<ProxyBody> {
    let Some(origin) = origin_of(uri) else {
        return error_response(StatusCode::BAD_REQUEST, "unable to determine the origin");
    };

    // The path is matched before the method so an unknown endpoint answers 404
    // whatever verb it was asked for, rather than a misleading 405.
    //
    // `@resource` is the one GET: a script hands its URL to an <img> or a
    // stylesheet, so it has to be fetchable without setting headers. Everything
    // else mutates and is POST.
    match uri.path() {
        "/__privaxy__/gm/resource" => match require_method(method, http::Method::GET) {
            Some(response) => response,
            None => serve_resource(uri, &origin, user_scripts),
        },
        "/__privaxy__/gm/values" => match require_method(method, http::Method::POST) {
            Some(response) => response,
            None => handle_values(body, &origin, user_scripts),
        },
        "/__privaxy__/gm/read" => match require_method(method, http::Method::POST) {
            Some(response) => response,
            None => handle_read(body, &origin, user_scripts),
        },
        "/__privaxy__/gm/fetch" => match require_method(method, http::Method::POST) {
            Some(response) => response,
            None => handle_fetch(body, &origin, user_scripts, http_client).await,
        },
        _ => error_response(StatusCode::NOT_FOUND, "unknown Privaxy endpoint"),
    }
}

/// Refuse a request whose method the matched endpoint does not accept.
fn require_method(method: &http::Method, expected: http::Method) -> Option<Response<ProxyBody>> {
    if method == expected {
        return None;
    }

    Some(error_response(
        StatusCode::METHOD_NOT_ALLOWED,
        &format!("expected {expected}"),
    ))
}

/// Percent-decoded query parameters of `GET /__privaxy__/gm/resource`.
///
/// Parsed via the `url` crate, which is already a direct dependency and handles
/// the decoding, rather than reaching for `form_urlencoded` transitively.
fn query_parameters(uri: &Uri) -> BTreeMap<String, String> {
    let Ok(url) = url::Url::parse(&uri.to_string()) else {
        return BTreeMap::new();
    };

    url.query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect()
}

/// Every endpoint uses the same capability checks. Matching applies to the
/// authenticated page URL, so path-scoped scripts can use the reserved routes
/// while disabling a script or changing its matching rules revokes access.
fn authorize_script(
    token: &str,
    script_id: &str,
    origin: &str,
    user_scripts: &UserScriptContext,
) -> Result<Arc<CompiledUserScript>, (StatusCode, &'static str)> {
    let Some(page_url) =
        token::verify(token, origin, script_id, &user_scripts.endpoint_signing_key)
    else {
        log::warn!("Rejected a userscript request for {origin} with an invalid token");
        return Err((StatusCode::FORBIDDEN, "invalid token"));
    };
    let Some(script) = user_scripts.store.find(script_id) else {
        return Err((StatusCode::NOT_FOUND, "no such active userscript"));
    };
    if !script.matches(&page_url) {
        return Err((
            StatusCode::FORBIDDEN,
            "this script no longer matches the authorized page",
        ));
    }
    Ok(script)
}

/// Serve one `@resource` payload as its original bytes and content type.
///
/// The token travels in the query string here rather than a header, because the
/// whole point is a URL a script can assign to `img.src`, where headers cannot
/// be set. It is the same script-bound token used elsewhere and grants no more
/// than the descriptor already contains for a matching page.
fn serve_resource(
    uri: &Uri,
    origin: &str,
    user_scripts: &UserScriptContext,
) -> Response<ProxyBody> {
    let parameters = query_parameters(uri);
    let token = parameters.get("token").map(String::as_str).unwrap_or("");

    let Some(script_id) = parameters.get("script") else {
        return error_response(StatusCode::BAD_REQUEST, "missing script");
    };
    let Some(name) = parameters.get("name") else {
        return error_response(StatusCode::BAD_REQUEST, "missing name");
    };

    let script = match authorize_script(token, script_id, origin, user_scripts) {
        Ok(script) => script,
        Err((status, message)) => return error_response(status, message),
    };

    let Some(asset) = script.resource(name) else {
        return error_response(StatusCode::NOT_FOUND, "no such @resource");
    };

    let mut response = Response::new(full_body(asset.bytes.clone()));
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_str(&asset.content_type)
            .unwrap_or_else(|_| http::HeaderValue::from_static("application/octet-stream")),
    );
    // The bytes are stable for the life of the cached asset, but they are
    // per-script and must not be shared between origins by an intermediary.
    response.headers_mut().insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("private, max-age=3600"),
    );
    // A resource is data, never markup to be sniffed into script.
    response.headers_mut().insert(
        "x-content-type-options",
        http::HeaderValue::from_static("nosniff"),
    );

    response
}

fn handle_values(
    body: &[u8],
    origin: &str,
    user_scripts: &UserScriptContext,
) -> Response<ProxyBody> {
    let request: ValuesRequest = match serde_json::from_slice(body) {
        Ok(request) => request,
        Err(err) => {
            return error_response(StatusCode::BAD_REQUEST, &format!("malformed body: {err}"))
        }
    };

    if let Err((status, message)) =
        authorize_script(&request.token, &request.script, origin, user_scripts)
    {
        return error_response(status, message);
    }

    match user_scripts
        .gm_storage
        .apply(&request.script, request.values)
    {
        Ok(()) => json_response(StatusCode::OK, r#"{"ok":true}"#),
        Err(message) => error_response(StatusCode::UNPROCESSABLE_ENTITY, &message),
    }
}

/// Read one script's stored values, used only to service
/// `GM_addValueChangeListener` polling for changes made on another origin or
/// another device. Same-origin tabs are covered by `BroadcastChannel` and never
/// reach this.
///
/// The capability proves which script matched the page. The reserved endpoint
/// path itself need not match that script's `@match`/`@include` patterns.
fn handle_read(body: &[u8], origin: &str, user_scripts: &UserScriptContext) -> Response<ProxyBody> {
    #[derive(Deserialize)]
    struct ReadRequest {
        token: String,
        script: String,
    }

    let request: ReadRequest = match serde_json::from_slice(body) {
        Ok(request) => request,
        Err(err) => {
            return error_response(StatusCode::BAD_REQUEST, &format!("malformed body: {err}"))
        }
    };

    if let Err((status, message)) =
        authorize_script(&request.token, &request.script, origin, user_scripts)
    {
        return error_response(status, message);
    }

    let values = user_scripts.gm_storage.snapshot(&request.script);
    match serde_json::to_string(&serde_json::json!({ "values": values })) {
        Ok(body) => json_response(StatusCode::OK, &body),
        Err(err) => {
            log::error!("Unable to serialize userscript values: {err}");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "unable to encode values")
        }
    }
}

/// `GM_xmlhttpRequest`. Every rejection is logged: this endpoint can reach the
/// network the proxy sits on, so a refused attempt is worth seeing.
async fn handle_fetch(
    body: &[u8],
    origin: &str,
    user_scripts: &UserScriptContext,
    http_client: &reqwest::Client,
) -> Response<ProxyBody> {
    let request: FetchRequest = match serde_json::from_slice(body) {
        Ok(request) => request,
        Err(err) => {
            return error_response(StatusCode::BAD_REQUEST, &format!("malformed body: {err}"))
        }
    };

    if let Err((status, message)) =
        authorize_script(&request.token, &request.script, origin, user_scripts)
    {
        return error_response(status, message);
    }

    let target = request.url.clone();
    match fetch::relay(
        request,
        http_client,
        &user_scripts.store,
        user_scripts.allow_private_network_requests.is_allowed(),
    )
    .await
    {
        Ok(response) => match serde_json::to_string(&response) {
            Ok(body) => json_response(StatusCode::OK, &body),
            Err(err) => {
                log::error!("Unable to serialize a relayed response: {err}");
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "unable to encode the response",
                )
            }
        },
        Err(FetchError::Forbidden(message)) => {
            log::warn!("Refused a userscript fetch from {origin} to {target}: {message}");
            error_response(StatusCode::FORBIDDEN, &message)
        }
        Err(FetchError::BadRequest(message)) => error_response(StatusCode::BAD_REQUEST, &message),
        Err(FetchError::Upstream(message)) => {
            log::debug!("Relayed fetch to {target} failed: {message}");
            error_response(StatusCode::BAD_GATEWAY, &message)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::{UserScript, UserScriptAsset};
    use crate::proxy::gm::storage::GmStorageStore;
    use crate::proxy::userscripts::{PrivateNetworkAccess, UserScriptStore};
    use http_body_util::BodyExt;

    const KEY: &str = "endpoint-regression-test-key";
    const SCRIPT: &str = "scoped.user.js";

    fn compiled(file_name: &str, pattern: &str) -> CompiledUserScript {
        let script = UserScript {
            enabled: true,
            title: file_name.to_string(),
            file_name: file_name.to_string(),
            url: None,
        };
        let body = format!(
            "// ==UserScript==\n// @name Fixture\n// @match {pattern}\n// @connect *\n// ==/UserScript==\nvoid 0;"
        );
        let mut compiled = CompiledUserScript::new(&script, body).unwrap();
        compiled.resources.push((
            "icon".to_string(),
            UserScriptAsset {
                bytes: vec![0, 255, 1],
                content_type: "image/png".to_string(),
            },
        ));
        compiled
    }

    fn context() -> UserScriptContext {
        UserScriptContext {
            store: UserScriptStore::new(vec![
                compiled(SCRIPT, "https://example.com/watch*"),
                compiled("other.user.js", "https://other.test/*"),
            ]),
            gm_storage: GmStorageStore::in_memory(),
            endpoint_signing_key: KEY.to_string(),
            allow_private_network_requests: PrivateNetworkAccess::default(),
        }
    }

    fn client() -> reqwest::Client {
        let _ = rustls::crypto::ring::default_provider().install_default();
        reqwest::Client::builder().no_proxy().build().unwrap()
    }

    #[tokio::test]
    async fn every_endpoint_rejects_another_scripts_capability() {
        let context = context();
        let client = client();
        let page = url::Url::parse("https://example.com/watch?id=1").unwrap();
        let capability = token::mint(&page, SCRIPT, KEY);
        let payload = serde_json::to_vec(&serde_json::json!({
            "token": capability,
            "script": "other.user.js",
            "values": {"injected": true},
            "url": "http://127.0.0.1/",
        }))
        .unwrap();

        for endpoint in ["values", "read", "fetch"] {
            let uri = format!("https://example.com/__privaxy__/gm/{endpoint}")
                .parse()
                .unwrap();
            let response = handle(&uri, &http::Method::POST, &payload, &context, &client).await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{endpoint}");
        }
        let uri = format!(
            "https://example.com/__privaxy__/gm/resource?script=other.user.js&name=icon&token={capability}"
        ).parse().unwrap();
        let response = handle(&uri, &http::Method::GET, &[], &context, &client).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(context.gm_storage.snapshot("other.user.js").is_empty());
    }

    #[tokio::test]
    async fn path_scoped_scripts_can_write_poll_and_read_resources() {
        let context = context();
        let client = client();
        let page = url::Url::parse("https://example.com/watch?id=1").unwrap();
        let capability = token::mint(&page, SCRIPT, KEY);
        let payload = serde_json::to_vec(&serde_json::json!({
            "token": capability,
            "script": SCRIPT,
            "values": {"theme": "dark"},
        }))
        .unwrap();
        for endpoint in ["values", "read"] {
            let uri = format!("https://example.com/__privaxy__/gm/{endpoint}")
                .parse()
                .unwrap();
            let response = handle(&uri, &http::Method::POST, &payload, &context, &client).await;
            assert_eq!(response.status(), StatusCode::OK, "{endpoint}");
            if endpoint == "read" {
                let body = response.into_body().collect().await.unwrap().to_bytes();
                let values: Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(values["values"]["theme"], "dark");
            }
        }
        let uri = format!(
            "https://example.com/__privaxy__/gm/resource?script={SCRIPT}&name=icon&token={capability}"
        ).parse().unwrap();
        let response = handle(&uri, &http::Method::GET, &[], &context, &client).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[http::header::CONTENT_TYPE], "image/png");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), &[0, 255, 1]);
    }

    #[test]
    fn disabling_or_changing_matches_revokes_existing_capabilities() {
        let context = context();
        let page = url::Url::parse("https://example.com/watch?id=1").unwrap();
        let capability = token::mint(&page, SCRIPT, KEY);
        assert!(authorize_script(&capability, SCRIPT, "https://example.com", &context).is_ok());

        context
            .store
            .replace(vec![compiled(SCRIPT, "https://example.com/elsewhere*")]);
        let response =
            authorize_script(&capability, SCRIPT, "https://example.com", &context).unwrap_err();
        assert_eq!(response.0, StatusCode::FORBIDDEN);

        context.store.replace(Vec::new());
        let response =
            authorize_script(&capability, SCRIPT, "https://example.com", &context).unwrap_err();
        assert_eq!(response.0, StatusCode::NOT_FOUND);
    }

    #[test]
    fn reserved_prefix_matching() {
        assert!(is_reserved("/__privaxy__/gm/values"));
        assert!(is_reserved("/__privaxy__/anything"));
        assert!(!is_reserved("/"));
        assert!(!is_reserved("/api/userscripts"));
        // Must anchor at the start: a site path merely containing the prefix is
        // still the site's own route.
        assert!(!is_reserved("/foo/__privaxy__/gm/values"));
    }

    #[test]
    fn origin_is_built_from_the_request_uri() {
        let uri: Uri = "https://example.com/__privaxy__/gm/values".parse().unwrap();
        assert_eq!(origin_of(&uri).as_deref(), Some("https://example.com"));

        // A non-default port is part of the origin, so a token minted for
        // :8443 cannot be replayed against :443.
        let uri: Uri = "https://example.com:8443/x".parse().unwrap();
        assert_eq!(origin_of(&uri).as_deref(), Some("https://example.com:8443"));
    }

    #[test]
    fn query_parameters_are_percent_decoded() {
        let uri: Uri = "https://example.com/__privaxy__/gm/resource\
            ?script=abc.user.js&name=my%20sheet&token=a-b_c"
            .parse()
            .unwrap();

        let parameters = query_parameters(&uri);

        assert_eq!(
            parameters.get("script").map(String::as_str),
            Some("abc.user.js")
        );
        // Percent-encoding must be decoded, or a resource name with a space
        // would never match the name the script declared.
        assert_eq!(parameters.get("name").map(String::as_str), Some("my sheet"));
        assert_eq!(parameters.get("token").map(String::as_str), Some("a-b_c"));
    }

    #[test]
    fn query_parameters_tolerate_a_missing_query() {
        let uri: Uri = "https://example.com/__privaxy__/gm/resource"
            .parse()
            .unwrap();

        assert!(query_parameters(&uri).is_empty());
    }

    /// Proxied HTTPS URIs inherit an explicit `:443` from the CONNECT
    /// authority, while the browser's own view of the origin has no port. Both
    /// must produce the same string or every token would fail to verify.
    #[test]
    fn default_ports_do_not_change_the_origin() {
        for (with_port, without_port) in [
            ("https://example.com:443/x", "https://example.com/x"),
            ("http://example.com:80/x", "http://example.com/x"),
        ] {
            let with_port: Uri = with_port.parse().unwrap();
            let without_port: Uri = without_port.parse().unwrap();

            assert_eq!(origin_of(&with_port), origin_of(&without_port));
        }
    }
}
