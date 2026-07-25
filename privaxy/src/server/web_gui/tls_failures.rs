use super::{get_error_response, get_unprocessable_response};
use crate::configuration::Configuration;
use crate::proxy::exclusions::LocalExclusionStore;
use crate::proxy::tls_failures::{normalize_ignored_host, TlsFailureEntry, TlsFailureStore};
use std::{convert::Infallible, sync::Arc};
use warp::filters::BoxedFilter;
use warp::http::StatusCode;
use warp::Filter as RouteFilter;

/// Ceiling on the persisted ignore list — it lives in the TOML configuration,
/// which is rewritten wholesale on every save, so it must not grow unbounded.
const MAX_IGNORED_TLS_FAILURES: usize = 1_000;

/// The body is a single JSON-encoded hostname; anything bigger is junk.
const IGNORE_BODY_LIMIT_BYTES: u64 = 4 * 1024;

async fn get_tls_failures(
    tls_failure_store: TlsFailureStore,
    local_exclusions_store: LocalExclusionStore,
) -> Result<Box<dyn warp::Reply>, Infallible> {
    // The store already omits ignored hosts; additionally omit hosts the
    // exclusion list now covers (their failures predate the exclusion, or the
    // client re-dialed before the exclusion took effect).
    let entries: Vec<TlsFailureEntry> = tls_failure_store
        .entries()
        .into_iter()
        .filter(|entry| !local_exclusions_store.contains(&entry.host))
        .collect();

    Ok(Box::new(warp::reply::json(&entries)))
}

async fn post_ignore_tls_failure(
    host: String,
    tls_failure_store: TlsFailureStore,
    configuration_save_lock: Arc<tokio::sync::Mutex<()>>,
) -> Result<Box<dyn warp::Reply>, Infallible> {
    // Normalize to the portless lowercase shape the store records; reject
    // anything that is not host-shaped instead of persisting a dead entry
    // that could never match.
    let host = match normalize_ignored_host(&host) {
        Some(host) => host,
        None => {
            return Ok(Box::new(get_unprocessable_response("not a valid hostname")));
        }
    };

    let _guard = configuration_save_lock.lock().await;

    let mut configuration = match Configuration::read_from_home().await {
        Ok(configuration) => configuration,
        Err(err) => {
            log::error!("Failed to ignore TLS failure: {err}");
            return Ok(Box::new(get_error_response(err)));
        }
    };

    if configuration.ignored_tls_failures.len() >= MAX_IGNORED_TLS_FAILURES
        && !configuration.ignored_tls_failures.contains(&host)
    {
        return Ok(Box::new(get_unprocessable_response(
            "ignore list is full; prune ignored_tls_failures in the configuration",
        )));
    }

    if let Err(err) = configuration
        .ignore_tls_failure(&host, tls_failure_store)
        .await
    {
        return Ok(Box::new(get_error_response(err)));
    }

    // Deliberately no `configuration_updater_sender` send here: nothing
    // downstream (blocker, proxy loops) consumes the ignore list, and the
    // in-memory store was already updated by `ignore_tls_failure`, so a
    // reload notification would be pure churn.

    Ok(Box::new(StatusCode::ACCEPTED))
}

pub(super) fn create_routes(
    tls_failure_store: TlsFailureStore,
    local_exclusions_store: LocalExclusionStore,
    configuration_save_lock: Arc<tokio::sync::Mutex<()>>,
) -> BoxedFilter<(impl warp::Reply,)> {
    let root_get = warp::path::end()
        .and(warp::get())
        .and(super::with_arc(tls_failure_store.clone()))
        .and(super::with_arc(local_exclusions_store))
        .and_then(self::get_tls_failures);

    let ignore_post = warp::path("ignore")
        .and(warp::path::end())
        .and(warp::post())
        .and(warp::body::content_length_limit(IGNORE_BODY_LIMIT_BYTES))
        .and(warp::body::json::<String>())
        .and(super::with_arc(tls_failure_store))
        .and(super::with_arc(configuration_save_lock))
        .and_then(self::post_ignore_tls_failure);

    root_get.or(ignore_post).boxed()
}
