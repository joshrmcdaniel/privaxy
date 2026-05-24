use crate::configuration::Configuration;
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Arc;
use tera::{Context, Tera};
use tokio::sync::Mutex;
use warp::filters::BoxedFilter;
use warp::http::Response;
use warp::{http, Filter, Reply};

const PAC_TEMPLATE: &str = include_str!("../../resources/proxy.pac.tera");
const PAC_MIME: &str = "application/x-ns-proxy-autoconfig";

#[derive(Serialize)]
struct PacContext<'a> {
    proxy_host: &'a str,
    ips: &'a [String],
    cidrs: &'a BTreeMap<String, String>,
    fqdns: &'a [String],
}

pub(crate) fn create_routes(
    configuration_save_lock: Arc<Mutex<()>>,
) -> BoxedFilter<(impl Reply,)> {
    let mut tera = Tera::default();
    tera.add_raw_template("proxy.pac", PAC_TEMPLATE)
        .expect("proxy.pac template failed to parse");
    let tera = Arc::new(tera);

    warp::path!("proxy.pac")
        .and(warp::get())
        .and(super::with_arc(tera))
        .and(super::with_configuration_save_lock(configuration_save_lock))
        .and_then(render_pac)
        .boxed()
}

async fn render_pac(
    tera: Arc<Tera>,
    configuration_save_lock: Arc<Mutex<()>>,
) -> Result<Response<String>, warp::Rejection> {
    let cfg = {
        let _lock = configuration_save_lock.lock().await;
        Configuration::read_from_home().await.map_err(|err| {
            log::error!("PAC: failed to read configuration: {err:?}");
            warp::reject()
        })?
    };

    if !cfg.network.pac_enabled {
        return Ok(not_found_response());
    }

    let proxy_host = cfg.network.pac_proxy_host.clone().unwrap_or_else(|| {
        format!("{}:{}", cfg.network.bind_addr, cfg.network.proxy_port)
    });

    let ctx_data = PacContext {
        proxy_host: &proxy_host,
        ips: &cfg.network.pac_direct_ips,
        cidrs: &cfg.network.pac_direct_cidrs,
        fqdns: &cfg.network.pac_direct_fqdns,
    };

    let ctx = Context::from_serialize(&ctx_data).map_err(|err| {
        log::error!("PAC: context build failed: {err:?}");
        warp::reject()
    })?;
    let body = tera.render("proxy.pac", &ctx).map_err(|err| {
        log::error!("PAC: render failed: {err:?}");
        warp::reject()
    })?;

    Ok(Response::builder()
        .header(http::header::CONTENT_TYPE, PAC_MIME)
        .header(http::header::CACHE_CONTROL, "no-cache")
        .body(body)
        .unwrap())
}

fn not_found_response() -> Response<String> {
    Response::builder()
        .status(http::StatusCode::NOT_FOUND)
        .header(http::header::CONTENT_TYPE, "text/plain")
        .body(String::new())
        .unwrap()
}
