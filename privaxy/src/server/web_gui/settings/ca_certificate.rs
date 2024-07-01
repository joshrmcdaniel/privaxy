use super::get_error_response;
use crate::configuration::Ca;
use crate::configuration::Configuration;
use crate::web_gui::with_configuration_save_lock;
use crate::web_gui::with_configuration_updater_sender;
use crate::web_gui::with_notify_reload;
use crate::web_gui::ApiError;
use std::convert::Infallible;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use tokio::sync::Notify;
use warp::filters::BoxedFilter;
use warp::http::Response;
use warp::Filter as RouteFilter;

async fn get_ca_certificates() -> Result<Box<dyn warp::Reply>, Infallible> {
    log::debug!("Getting CA certificates");
    let configuration = match Configuration::read_from_home().await {
        Ok(configuration) => configuration,
        Err(err) => {
            log::error!("Failed to load config: {err}");
            return Ok(Box::new(get_error_response(err)));
        }
    };
    let ca_cert = match configuration.ca.get_ca_certificate().await {
        Ok(ca_cert) => ca_cert,
        Err(err) => {
            log::error!("Failed to get CA certificates: {err}");
            return Ok(Box::new(get_error_response(err)));
        }
    };

    Ok(Box::new(
        Response::builder()
            .header(
                http::header::CONTENT_DISPOSITION,
                "attachment; filename=privaxy-ca-certificate.pem;",
            )
            .header(http::header::CONTENT_TYPE, "application/x-pem-file")
            .body(ca_cert.to_pem().unwrap()),
    ))
}

async fn validate_ca_certificates(body: Ca) -> Result<Box<dyn warp::Reply>, Infallible> {
    match body.validate().await {
        Ok(_) => Ok(Box::new(
            Response::builder()
                .status(http::StatusCode::NO_CONTENT)
                .body(""),
        )),
        Err(err) => {
            log::error!("Invalid CA certificates: {err}");
            return Ok(Box::new(
                Response::builder()
                    .status(http::StatusCode::BAD_REQUEST)
                    .body(
                        serde_json::to_string(&ApiError {
                            error: err.to_string(),
                        })
                        .unwrap(),
                    ),
            ));
        }
    }
}

async fn put_ca_certificates(
    ca_cert_struct: Ca,
    configuration_updater_sender: Sender<Configuration>,
    configuration_save_lock: Arc<tokio::sync::Mutex<()>>,
    notify_reload: Arc<Notify>,
) -> Result<Box<dyn warp::Reply>, Infallible> {
    let _guard = configuration_save_lock.lock().await;

    let mut configuration = match Configuration::read_from_home().await {
        Ok(configuration) => configuration,
        Err(err) => {
            log::error!("Failed to load config: {err}");
            return Ok(Box::new(get_error_response(err)));
        }
    };

    if let Err(err) = configuration.set_ca_settings(&ca_cert_struct).await {
        log::error!("Failed to set CA certificate: {err}");
        return Ok(Box::new(get_error_response(err)));
    }

    configuration_updater_sender
        .send(configuration.clone())
        .await
        .unwrap();

    Ok(Box::new(
        Response::builder()
            .status(http::StatusCode::NO_CONTENT)
            .body("".to_string()),
    ))
}

pub(super) fn create_routes(
    configuration_updater_sender: Sender<Configuration>,
    configuration_save_lock: Arc<tokio::sync::Mutex<()>>,
    notify_reload: Arc<Notify>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path::end()
        .and(
            warp::get()
                .and_then(self::get_ca_certificates)
                .or(warp::put()
                    .and(warp::body::json())
                    .and(with_configuration_updater_sender(
                        configuration_updater_sender.clone(),
                    ))
                    .and(with_configuration_save_lock(
                        configuration_save_lock.clone(),
                    ))
                    .and(with_notify_reload(notify_reload.clone()))
                    .and_then(self::put_ca_certificates)),
        )
        .or(warp::path("validate").and(
            warp::path::end()
                .and(warp::post())
                .and(warp::body::json())
                .and_then(self::validate_ca_certificates),
        ))
        .boxed()
}
