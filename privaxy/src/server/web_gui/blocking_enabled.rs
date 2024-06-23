use crate::blocker::BlockingDisabledStore;
use serde::Deserialize;
use std::convert::Infallible;
use warp::filters::BoxedFilter;
use warp::http::StatusCode;
use warp::Filter as RouteFilter;

#[derive(Deserialize)]
pub struct BlockingEnabled(bool);

pub async fn get_blocking_enabled(
    blocking_disabled_store: BlockingDisabledStore,
) -> Result<impl warp::Reply, Infallible> {
    Ok(warp::reply::json(&blocking_disabled_store.is_enabled()))
}

pub async fn put_blocking_enabled(
    blocking_enabled: BlockingEnabled,
    blocking_disabled_store: BlockingDisabledStore,
) -> Result<impl warp::Reply, Infallible> {
    blocking_disabled_store.set(!blocking_enabled.0);

    Ok(StatusCode::NO_CONTENT)
}

pub(super) fn create_routes(
    blocking_disabled_store: BlockingDisabledStore,
) -> BoxedFilter<(impl warp::Reply,)> {
    let block_store = super::with_blocking_disabled_store(blocking_disabled_store);
    warp::get()
        .and(block_store.clone())
        .and_then(self::get_blocking_enabled)
        .or(warp::put()
            .and(warp::body::json())
            .and(block_store)
            .and_then(self::put_blocking_enabled))
        .boxed()
}
