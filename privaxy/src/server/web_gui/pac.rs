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

pub(crate) fn create_routes(configuration_save_lock: Arc<Mutex<()>>) -> BoxedFilter<(impl Reply,)> {
    let mut tera = Tera::default();
    tera.add_raw_template("proxy.pac", PAC_TEMPLATE)
        .expect("proxy.pac template failed to parse");
    let tera = Arc::new(tera);

    warp::path!("proxy.pac")
        .or(warp::path!("wpad.dat"))
        .unify()
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

    let proxy_host = cfg
        .network
        .pac_proxy_host
        .clone()
        .unwrap_or_else(|| format!("{}:{}", cfg.network.bind_addr, cfg.network.proxy_port));

    let cidrs = cfg
        .network
        .pac_direct_cidrs
        .iter()
        .map(|(subnet, netmask)| (subnet.clone(), normalize_netmask(netmask)))
        .collect();

    let ctx_data = PacContext {
        proxy_host: &proxy_host,
        ips: &cfg.network.pac_direct_ips,
        cidrs: &cidrs,
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

/// `isInNet` only understands dotted-decimal masks, but the GUI accepts
/// `subnet/22`-style CIDR input and stores the bare prefix length, so a
/// prefix length is converted here at render time. Anything that is not a
/// prefix length (already-dotted masks in particular) passes through as-is.
fn normalize_netmask(netmask: &str) -> String {
    match netmask.parse::<u8>() {
        Ok(prefix) if prefix <= 32 => {
            let bits = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix))
            };
            std::net::Ipv4Addr::from(bits).to_string()
        }
        _ => netmask.to_string(),
    }
}

fn not_found_response() -> Response<String> {
    Response::builder()
        .status(http::StatusCode::NOT_FOUND)
        .header(http::header::CONTENT_TYPE, "text/plain")
        .body(String::new())
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::normalize_netmask;

    #[test]
    fn prefix_lengths_become_dotted_masks() {
        assert_eq!(normalize_netmask("0"), "0.0.0.0");
        assert_eq!(normalize_netmask("8"), "255.0.0.0");
        assert_eq!(normalize_netmask("12"), "255.240.0.0");
        assert_eq!(normalize_netmask("20"), "255.255.240.0");
        assert_eq!(normalize_netmask("22"), "255.255.252.0");
        assert_eq!(normalize_netmask("26"), "255.255.255.192");
        assert_eq!(normalize_netmask("28"), "255.255.255.240");
        assert_eq!(normalize_netmask("32"), "255.255.255.255");
    }

    #[test]
    fn dotted_masks_and_junk_pass_through() {
        assert_eq!(normalize_netmask("255.255.252.0"), "255.255.252.0");
        assert_eq!(normalize_netmask("33"), "33");
        assert_eq!(normalize_netmask(""), "");
        assert_eq!(normalize_netmask("garbage"), "garbage");
    }
}
