use crate::configuration::Configuration;
use crate::web_gui::with_configuration_save_lock;
use std::sync::Arc;
use tokio::sync::Mutex;
use warp::reject::Reject;
use warp::Filter;

pub mod routes;
pub mod session;

#[derive(Debug)]
pub struct Unauthorized;
impl Reject for Unauthorized {}

#[derive(Debug)]
pub struct ConfigUnavailable;
impl Reject for ConfigUnavailable {}

/// Returns a warp filter that allows the request through if the caller has
/// either a valid signed session cookie or a matching `X-Api-Key` header.
/// Rejects with `Unauthorized` otherwise.
pub fn require_auth(
    configuration_save_lock: Arc<Mutex<()>>,
) -> impl Filter<Extract = (), Error = warp::Rejection> + Clone {
    warp::any()
        .and(warp::header::optional::<String>("cookie"))
        .and(warp::header::optional::<String>("x-api-key"))
        .and(with_configuration_save_lock(configuration_save_lock))
        .and_then(check_auth)
        .untuple_one()
}

async fn check_auth(
    cookie: Option<String>,
    api_key: Option<String>,
    configuration_save_lock: Arc<Mutex<()>>,
) -> Result<(), warp::Rejection> {
    let configuration = {
        let _guard = configuration_save_lock.lock().await;
        match Configuration::read_from_home().await {
            Ok(cfg) => cfg,
            Err(err) => {
                log::error!("Auth filter could not read configuration: {err}");
                return Err(warp::reject::custom(ConfigUnavailable));
            }
        }
    };

    // Until the user has set up an account, there is no auth to enforce.
    // (The /api/auth/setup endpoint itself is exempt from this filter, so
    // this branch only applies to other API routes hit before setup —
    // we keep them blocked so the frontend is forced through setup first.)
    if !configuration.auth.is_set_up() {
        return Err(warp::reject::custom(Unauthorized));
    }

    if let Some(provided_key) = api_key.as_deref() {
        if !configuration.auth.api_key.is_empty()
            && constant_time_eq(
                provided_key.as_bytes(),
                configuration.auth.api_key.as_bytes(),
            )
        {
            return Ok(());
        }
    }

    if let Some(cookie_header) = cookie.as_deref() {
        if let Some(token) = session::extract_session_cookie(cookie_header) {
            if session::verify(&token, &configuration.auth.session_signing_key).is_ok() {
                return Ok(());
            }
        }
    }

    Err(warp::reject::custom(Unauthorized))
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
