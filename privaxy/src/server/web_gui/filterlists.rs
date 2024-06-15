use filterlists_api;
use warp::Filter as RouteFilter;

use std::convert::Infallible;
use warp::filters::BoxedFilter;

async fn get_filters() -> Result<Box<dyn warp::Reply>, Infallible> {
    match filterlists_api::get_filters().await {
        Ok(filters) => Ok(Box::new(warp::reply::json(&filters))),
        Err(err) => Ok(Box::new(super::get_error_response(err))),
    }
}

async fn get_filter(id: u64) -> Result<Box<dyn warp::Reply>, Infallible> {
    match filterlists_api::get_filter_information(filterlists_api::FilterArgs::U64(id)).await {
        Ok(filter) => Ok(Box::new(warp::reply::json(&filter))),
        Err(err) => Ok(Box::new(super::get_error_response(err))),
    }
}

async fn get_syntaxes() -> Result<Box<dyn warp::Reply>, Infallible> {
    match filterlists_api::get_syntaxes().await {
        Ok(syntaxes) => Ok(Box::new(warp::reply::json(&syntaxes))),
        Err(err) => Ok(Box::new(super::get_error_response(err))),
    }
}

async fn get_languages() -> Result<Box<dyn warp::Reply>, Infallible> {
    match filterlists_api::get_languages().await {
        Ok(languages) => Ok(Box::new(warp::reply::json(&languages))),
        Err(err) => Ok(Box::new(super::get_error_response(err))),
    }
}

async fn get_tags() -> Result<Box<dyn warp::Reply>, Infallible> {
    match filterlists_api::get_tags().await {
        Ok(tags) => Ok(Box::new(warp::reply::json(&tags))),
        Err(err) => Ok(Box::new(super::get_error_response(err))),
    }
}

async fn get_licenses() -> Result<Box<dyn warp::Reply>, Infallible> {
    match filterlists_api::get_licenses().await {
        Ok(licenses) => Ok(Box::new(warp::reply::json(&licenses))),
        Err(err) => Ok(Box::new(super::get_error_response(err))),
    }
}

pub(super) fn create_routes() -> BoxedFilter<(impl warp::Reply,)> {
    warp::path("list")
        .and(warp::get())
        .and_then(self::get_filters)
        .or(warp::path!("list" / u64)
            .and(warp::get())
            .and_then(self::get_filter))
        .or(warp::path("syntaxes")
            .and(warp::get())
            .and_then(self::get_syntaxes))
        .or(warp::path("languages")
            .and(warp::get())
            .and_then(self::get_languages))
        .or(warp::path("tags").and(warp::get()).and_then(self::get_tags))
        .or(warp::path("licenses")
            .and(warp::get())
            .and_then(self::get_licenses))
        .boxed()
}
