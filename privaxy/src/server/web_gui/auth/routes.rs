use crate::configuration::{generate_random_hex, hash_password, Configuration};
use crate::web_gui::auth::session::{
    build_logout_cookie, build_session_cookie, extract_session_cookie, issue_token, verify,
};
use crate::web_gui::with_configuration_save_lock;
use crate::web_gui::with_configuration_updater_sender;
use crate::web_gui::ApiError;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;
use warp::filters::BoxedFilter;
use warp::http::{Response, StatusCode};
use warp::{Filter, Reply};

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct SetupRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthStatusResponse {
    pub authenticated: bool,
    pub setup_required: bool,
    pub username: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ApiKeyResponse {
    pub api_key: String,
}

pub fn create_routes(
    configuration_updater_sender: Sender<Configuration>,
    configuration_save_lock: Arc<Mutex<()>>,
) -> BoxedFilter<(impl Reply,)> {
    let status_route = warp::path("status")
        .and(warp::path::end())
        .and(warp::get())
        .and(warp::header::optional::<String>("cookie"))
        .and(warp::header::optional::<String>("x-api-key"))
        .and(with_configuration_save_lock(
            configuration_save_lock.clone(),
        ))
        .and_then(get_status);

    let setup_route = warp::path("setup")
        .and(warp::path::end())
        .and(warp::post())
        .and(warp::body::json())
        .and(with_configuration_save_lock(
            configuration_save_lock.clone(),
        ))
        .and(with_configuration_updater_sender(
            configuration_updater_sender.clone(),
        ))
        .and_then(post_setup);

    let login_route = warp::path("login")
        .and(warp::path::end())
        .and(warp::post())
        .and(warp::body::json())
        .and(with_configuration_save_lock(
            configuration_save_lock.clone(),
        ))
        .and_then(post_login);

    let logout_route = warp::path("logout")
        .and(warp::path::end())
        .and(warp::post())
        .and(with_configuration_save_lock(
            configuration_save_lock.clone(),
        ))
        .and_then(post_logout);

    // Routes below require auth. The auth filter is invoked inside each
    // handler (rather than wrapping the routes here) so that the response
    // payload can include detailed error messages instead of a bare 401.
    let change_password_route = warp::path("change-password")
        .and(warp::path::end())
        .and(warp::post())
        .and(warp::header::optional::<String>("cookie"))
        .and(warp::header::optional::<String>("x-api-key"))
        .and(warp::body::json())
        .and(with_configuration_save_lock(
            configuration_save_lock.clone(),
        ))
        .and(with_configuration_updater_sender(
            configuration_updater_sender.clone(),
        ))
        .and_then(post_change_password);

    let rotate_api_key_route = warp::path("rotate-api-key")
        .and(warp::path::end())
        .and(warp::post())
        .and(warp::header::optional::<String>("cookie"))
        .and(warp::header::optional::<String>("x-api-key"))
        .and(with_configuration_save_lock(
            configuration_save_lock.clone(),
        ))
        .and(with_configuration_updater_sender(
            configuration_updater_sender.clone(),
        ))
        .and_then(post_rotate_api_key);

    let get_api_key_route = warp::path("api-key")
        .and(warp::path::end())
        .and(warp::get())
        .and(warp::header::optional::<String>("cookie"))
        .and(warp::header::optional::<String>("x-api-key"))
        .and(with_configuration_save_lock(
            configuration_save_lock.clone(),
        ))
        .and_then(get_api_key);

    status_route
        .or(setup_route)
        .or(login_route)
        .or(logout_route)
        .or(change_password_route)
        .or(rotate_api_key_route)
        .or(get_api_key_route)
        .boxed()
}

async fn get_status(
    cookie: Option<String>,
    api_key: Option<String>,
    configuration_save_lock: Arc<Mutex<()>>,
) -> Result<Box<dyn Reply>, Infallible> {
    let configuration = match read_configuration(&configuration_save_lock).await {
        Ok(cfg) => cfg,
        Err(reply) => return Ok(reply),
    };

    let setup_required = !configuration.auth.is_set_up();
    let (authenticated, username) = if setup_required {
        (false, None)
    } else if let Some(user) = authenticated_username(&configuration, &cookie, &api_key) {
        (true, Some(user))
    } else {
        (false, None)
    };

    let body = serde_json::to_string(&AuthStatusResponse {
        authenticated,
        setup_required,
        username,
    })
    .unwrap();
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json");

    // If the caller presented a session cookie that did not authenticate them
    // (expired, signed with a rotated key, or otherwise stale), clear it from
    // the browser.
    if !authenticated && has_invalid_session_cookie(&configuration, &cookie) {
        response = response.header("Set-Cookie", build_logout_cookie(configuration.network.tls));
    }

    Ok(Box::new(response.body(body).unwrap()))
}

/// Returns true when a `privaxy_session` cookie is present but fails
/// verification against the current signing key.
fn has_invalid_session_cookie(configuration: &Configuration, cookie: &Option<String>) -> bool {
    match cookie.as_deref().and_then(extract_session_cookie) {
        Some(token) => verify(&token, &configuration.auth.session_signing_key).is_err(),
        None => false,
    }
}

async fn post_setup(
    body: SetupRequest,
    configuration_save_lock: Arc<Mutex<()>>,
    configuration_updater_sender: Sender<Configuration>,
) -> Result<Box<dyn Reply>, Infallible> {
    if body.username.trim().is_empty() {
        return Ok(json_error(StatusCode::BAD_REQUEST, "Username is required"));
    }
    if body.password.len() < 8 {
        return Ok(json_error(
            StatusCode::BAD_REQUEST,
            "Password must be at least 8 characters",
        ));
    }

    let guard = configuration_save_lock.lock().await;
    let mut configuration = match Configuration::read_from_home().await {
        Ok(cfg) => cfg,
        Err(err) => {
            log::error!("Setup failed to read configuration: {err}");
            return Ok(internal_error());
        }
    };

    if configuration.auth.is_set_up() {
        drop(guard);
        return Ok(json_error(
            StatusCode::CONFLICT,
            "Account is already set up",
        ));
    }

    let hash = match hash_password(&body.password) {
        Ok(h) => h,
        Err(err) => {
            log::error!("Failed to hash password: {err}");
            drop(guard);
            return Ok(internal_error());
        }
    };

    configuration.auth.username = Some(body.username.trim().to_string());
    configuration.auth.password_hash = Some(hash);
    if configuration.auth.api_key.is_empty() {
        configuration.auth.api_key = generate_random_hex(32);
    }
    if configuration.auth.session_signing_key.is_empty() {
        configuration.auth.session_signing_key = generate_random_hex(64);
    }

    if let Err(err) = configuration.save().await {
        log::error!("Setup failed to save configuration: {err}");
        drop(guard);
        return Ok(internal_error());
    }

    if let Err(err) = configuration_updater_sender
        .send(configuration.clone())
        .await
    {
        log::error!("Setup failed to broadcast configuration: {err}");
    }
    drop(guard);

    let username = configuration.auth.username.clone().unwrap_or_default();
    issue_session_response(&username, &configuration, StatusCode::CREATED)
}

async fn post_login(
    body: LoginRequest,
    configuration_save_lock: Arc<Mutex<()>>,
) -> Result<Box<dyn Reply>, Infallible> {
    let configuration = match read_configuration(&configuration_save_lock).await {
        Ok(cfg) => cfg,
        Err(reply) => return Ok(reply),
    };

    if !configuration.auth.is_set_up() {
        return Ok(json_error(
            StatusCode::CONFLICT,
            "Account is not yet set up",
        ));
    }

    if !configuration
        .auth
        .verify_credentials(&body.username, &body.password)
    {
        return Ok(json_error(StatusCode::UNAUTHORIZED, "Invalid credentials"));
    }

    issue_session_response(&body.username, &configuration, StatusCode::OK)
}

async fn post_logout(
    configuration_save_lock: Arc<Mutex<()>>,
) -> Result<Box<dyn Reply>, Infallible> {
    let secure = match read_configuration(&configuration_save_lock).await {
        Ok(cfg) => cfg.network.tls,
        Err(_) => false,
    };
    let response = Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header("Set-Cookie", build_logout_cookie(secure))
        .body(String::new())
        .unwrap();
    Ok(Box::new(response))
}

async fn post_change_password(
    cookie: Option<String>,
    api_key: Option<String>,
    body: ChangePasswordRequest,
    configuration_save_lock: Arc<Mutex<()>>,
    configuration_updater_sender: Sender<Configuration>,
) -> Result<Box<dyn Reply>, Infallible> {
    let guard = configuration_save_lock.lock().await;
    let mut configuration = match Configuration::read_from_home().await {
        Ok(cfg) => cfg,
        Err(err) => {
            log::error!("Change password failed to read configuration: {err}");
            drop(guard);
            return Ok(internal_error());
        }
    };

    let username = match authenticated_username(&configuration, &cookie, &api_key) {
        Some(u) => u,
        None => {
            drop(guard);
            return Ok(json_error(StatusCode::UNAUTHORIZED, "Unauthenticated"));
        }
    };

    if !configuration
        .auth
        .verify_credentials(&username, &body.current_password)
    {
        drop(guard);
        return Ok(json_error(
            StatusCode::UNAUTHORIZED,
            "Current password is incorrect",
        ));
    }

    if body.new_password.len() < 8 {
        drop(guard);
        return Ok(json_error(
            StatusCode::BAD_REQUEST,
            "New password must be at least 8 characters",
        ));
    }

    let hash = match hash_password(&body.new_password) {
        Ok(h) => h,
        Err(err) => {
            log::error!("Failed to hash password: {err}");
            drop(guard);
            return Ok(internal_error());
        }
    };
    configuration.auth.password_hash = Some(hash);

    if let Err(err) = configuration.save().await {
        log::error!("Change password failed to save configuration: {err}");
        drop(guard);
        return Ok(internal_error());
    }
    if let Err(err) = configuration_updater_sender
        .send(configuration.clone())
        .await
    {
        log::error!("Change password failed to broadcast configuration: {err}");
    }
    drop(guard);

    issue_session_response(&username, &configuration, StatusCode::OK)
}

async fn post_rotate_api_key(
    cookie: Option<String>,
    api_key: Option<String>,
    configuration_save_lock: Arc<Mutex<()>>,
    configuration_updater_sender: Sender<Configuration>,
) -> Result<Box<dyn Reply>, Infallible> {
    let guard = configuration_save_lock.lock().await;
    let mut configuration = match Configuration::read_from_home().await {
        Ok(cfg) => cfg,
        Err(err) => {
            log::error!("Rotate API key failed to read configuration: {err}");
            drop(guard);
            return Ok(internal_error());
        }
    };

    if authenticated_username(&configuration, &cookie, &api_key).is_none() {
        drop(guard);
        return Ok(json_error(StatusCode::UNAUTHORIZED, "Unauthenticated"));
    }

    let new_key = generate_random_hex(32);
    configuration.auth.api_key = new_key.clone();

    if let Err(err) = configuration.save().await {
        log::error!("Rotate API key failed to save configuration: {err}");
        drop(guard);
        return Ok(internal_error());
    }
    if let Err(err) = configuration_updater_sender
        .send(configuration.clone())
        .await
    {
        log::error!("Rotate API key failed to broadcast configuration: {err}");
    }
    drop(guard);

    Ok(Box::new(warp::reply::json(&ApiKeyResponse {
        api_key: new_key,
    })))
}

async fn get_api_key(
    cookie: Option<String>,
    api_key: Option<String>,
    configuration_save_lock: Arc<Mutex<()>>,
) -> Result<Box<dyn Reply>, Infallible> {
    let configuration = match read_configuration(&configuration_save_lock).await {
        Ok(cfg) => cfg,
        Err(reply) => return Ok(reply),
    };

    if authenticated_username(&configuration, &cookie, &api_key).is_none() {
        return Ok(json_error(StatusCode::UNAUTHORIZED, "Unauthenticated"));
    }

    Ok(Box::new(warp::reply::json(&ApiKeyResponse {
        api_key: configuration.auth.api_key.clone(),
    })))
}

fn authenticated_username(
    configuration: &Configuration,
    cookie: &Option<String>,
    api_key: &Option<String>,
) -> Option<String> {
    if !configuration.auth.is_set_up() {
        return None;
    }
    if let Some(provided) = api_key.as_deref() {
        if !configuration.auth.api_key.is_empty()
            && constant_time_eq(provided.as_bytes(), configuration.auth.api_key.as_bytes())
        {
            return configuration.auth.username.clone();
        }
    }
    if let Some(cookie_header) = cookie.as_deref() {
        if let Some(token) = extract_session_cookie(cookie_header) {
            if let Ok(claims) = verify(&token, &configuration.auth.session_signing_key) {
                return Some(claims.u);
            }
        }
    }
    None
}

fn issue_session_response(
    username: &str,
    configuration: &Configuration,
    status: StatusCode,
) -> Result<Box<dyn Reply>, Infallible> {
    let token = issue_token(username, &configuration.auth.session_signing_key);
    let cookie = build_session_cookie(&token, configuration.network.tls);
    let body = serde_json::to_string(&AuthStatusResponse {
        authenticated: true,
        setup_required: false,
        username: Some(username.to_string()),
    })
    .unwrap();
    let response = Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .header("Set-Cookie", cookie)
        .body(body)
        .unwrap();
    Ok(Box::new(response))
}

async fn read_configuration(
    configuration_save_lock: &Arc<Mutex<()>>,
) -> Result<Configuration, Box<dyn Reply>> {
    let _guard = configuration_save_lock.lock().await;
    match Configuration::read_from_home().await {
        Ok(cfg) => Ok(cfg),
        Err(err) => {
            log::error!("Auth route failed to read configuration: {err}");
            Err(internal_error())
        }
    }
}

fn json_error(status: StatusCode, message: &str) -> Box<dyn Reply> {
    let body = serde_json::to_string(&ApiError {
        error: message.to_string(),
    })
    .unwrap();
    let response = Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(body)
        .unwrap();
    Box::new(response)
}

fn internal_error() -> Box<dyn Reply> {
    json_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
