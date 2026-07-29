//! `/api/userscripts` — install, edit, toggle and remove userscripts at
//! runtime.
//!
//! Every mutation persists the configuration and then replaces the contents of
//! the [`UserScriptStore`], so a change made in the web UI applies to the next
//! page load without a proxy reload.
//!
//! Unlike the filter routes, these deliberately do *not* push through
//! `configuration_updater_sender`: that channel makes the updater re-read every
//! filter list from disk and rebuild the adblock engine, which a userscript
//! change has no reason to trigger. The updater's own configuration copy only
//! ever touches filters, so leaving it untouched is safe.

use super::{get_error_response, get_unprocessable_response};
use crate::configuration::{
    calc_local_userscript_filename, calc_userscript_filename, fetch_userscript, Configuration,
    ConfigurationError, RefreshOutcome, UserScript, UserScriptMetadata, UserScriptRefresh,
    UserScriptUpdate,
};
use crate::proxy::gm::storage::GmStorageStore;
use crate::proxy::userscripts::{reload_userscripts, PrivateNetworkAccess, UserScriptStore};
use serde::{Deserialize, Serialize};
use std::{convert::Infallible, sync::Arc};
use url::Url;
use warp::filters::BoxedFilter;
use warp::http::Response;
use warp::Filter;

/// The userscript section as served to the web UI: the master switch plus every
/// installed script.
#[derive(Debug, Serialize)]
struct UserScriptsResponse {
    enabled: bool,
    allow_private_network_requests: bool,
    scripts: Vec<UserScriptResponse>,
}

/// An installed script, annotated with what its metadata block declares so the
/// UI can show where it runs without parsing JavaScript itself.
#[derive(Debug, Serialize)]
struct UserScriptResponse {
    enabled: bool,
    title: String,
    file_name: String,
    url: Option<String>,
    version: Option<String>,
    description: Option<String>,
    run_at: Option<String>,
    matches: Vec<String>,
    grants: Vec<String>,
    no_frames: bool,
    /// Set when the stored body could not be read or no longer parses. Such a
    /// script is skipped at injection time, so the UI must be able to say so.
    error: Option<String>,
    /// Non-fatal compile problems, e.g. a `@require` library that could not be
    /// fetched. The script still runs, degraded.
    warnings: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct UserScriptStatusChangeRequest {
    file_name: String,
    enabled: bool,
}

/// `PUT /api/userscripts/enabled` — the engine-level switches. Both fields are
/// optional so a client may change one without knowing the other's value.
#[derive(Debug, Deserialize)]
pub struct EngineSettingsRequest {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    allow_private_network_requests: Option<bool>,
}

/// Install a script, either from pasted source or by fetching a URL.
#[derive(Debug, Deserialize)]
pub struct AddUserScriptRequest {
    /// Script source, pasted directly into the UI.
    #[serde(default)]
    body: Option<String>,
    /// URL to fetch the script from, for installing from e.g. Greasyfork.
    #[serde(default)]
    url: Option<String>,
    #[serde(default = "enabled_by_default")]
    enabled: bool,
}

fn enabled_by_default() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct UpdateUserScriptRequest {
    file_name: String,
    body: String,
}

#[derive(Debug, Deserialize)]
pub struct DeleteUserScriptRequest {
    file_name: String,
}

/// `POST /api/userscripts/update` — refresh from upstream on demand rather than
/// waiting out the 24h timer.
#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    /// One script, or every URL-installed script when absent.
    #[serde(default)]
    file_name: Option<String>,
}

/// Turn a stored script plus its on-disk body into the UI representation,
/// reporting rather than hiding a body that cannot be read or parsed.
///
/// Compile warnings (an unreachable `@require`, say) are read from the live
/// store rather than recomputed, so the UI reports exactly what the injection
/// path is actually working with. A disabled script is absent from the store and
/// therefore has no warnings — it isn't being injected at all.
async fn describe_script(
    script: &UserScript,
    user_script_store: &UserScriptStore,
) -> UserScriptResponse {
    let mut response = UserScriptResponse {
        enabled: script.enabled,
        title: script.title.clone(),
        file_name: script.file_name.clone(),
        url: script.url.as_ref().map(|url| url.to_string()),
        version: None,
        description: None,
        run_at: None,
        matches: Vec::new(),
        grants: Vec::new(),
        no_frames: false,
        error: None,
        warnings: user_script_store
            .find(&script.file_name)
            .map(|compiled| compiled.warnings.clone())
            .unwrap_or_default(),
    };

    let body = match script.read_body().await {
        Ok(body) => body,
        Err(err) => {
            response.error = Some(format!("Unable to read the script body: {err}"));
            return response;
        }
    };

    match UserScriptMetadata::parse(&body) {
        Ok(metadata) => {
            response.version = metadata.version.clone();
            response.description = metadata.description.clone();
            response.run_at = Some(metadata.run_at.as_token().to_string());
            response.no_frames = metadata.no_frames;
            response.grants = metadata.grants.clone();
            response.matches = metadata
                .matches
                .iter()
                .map(|pattern| pattern.as_str().to_string())
                .chain(
                    metadata
                        .includes
                        .iter()
                        .map(|pattern| pattern.as_str().to_string()),
                )
                .collect();
        }
        Err(err) => response.error = Some(err.to_string()),
    }

    response
}

async fn get_userscripts(
    user_script_store: UserScriptStore,
) -> Result<impl warp::Reply, Infallible> {
    let configuration = match Configuration::read_from_home().await {
        Ok(configuration) => configuration,
        Err(err) => {
            log::error!("Failed to read configuration: {err}");
            return Ok(get_error_response(err));
        }
    };

    let mut scripts = Vec::with_capacity(configuration.userscripts.scripts.len());
    for script in &configuration.userscripts.scripts {
        scripts.push(describe_script(script, &user_script_store).await);
    }

    let response = UserScriptsResponse {
        enabled: configuration.userscripts.enabled,
        allow_private_network_requests: configuration.userscripts.allow_private_network_requests,
        scripts,
    };

    Ok(Response::builder()
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(serde_json::to_string(&response).unwrap())
        .unwrap())
}

async fn get_userscript_body(
    file_name: String,
    _user_script_store: UserScriptStore,
) -> Result<impl warp::Reply, Infallible> {
    let configuration = match Configuration::read_from_home().await {
        Ok(configuration) => configuration,
        Err(err) => {
            log::error!("Failed to read configuration: {err}");
            return Ok(get_error_response(err));
        }
    };

    let Some(script) = configuration.userscripts.find(&file_name) else {
        return Ok(super::get_unprocessable_response("No such userscript"));
    };

    match script.read_body().await {
        Ok(body) => Ok(Response::builder()
            .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(body)
            .unwrap()),
        Err(err) => {
            log::error!("Failed to read userscript body: {err}");
            Ok(get_error_response(err))
        }
    }
}

/// Map a configuration error to the right status: a rejected script is the
/// caller's problem (422), anything else is ours (500).
fn userscript_error_response(err: ConfigurationError) -> Response<String> {
    match err {
        ConfigurationError::UserScript(err) => get_unprocessable_response(&err.to_string()),
        ConfigurationError::UserScriptFetchError(message) => get_unprocessable_response(&message),
        ConfigurationError::UserScriptNotFound(_) => {
            get_unprocessable_response("No such userscript")
        }
        err => {
            log::error!("Userscript operation failed: {err}");
            get_error_response(err)
        }
    }
}

async fn set_engine_settings(
    request: EngineSettingsRequest,
    http_client: reqwest::Client,
    configuration_save_lock: Arc<tokio::sync::Mutex<()>>,
    user_script_store: UserScriptStore,
    private_network_access: PrivateNetworkAccess,
) -> Result<impl warp::Reply, Infallible> {
    // The lock is held across read-modify-write so a concurrent mutation cannot
    // be lost by writing back a configuration read before it landed.
    let _guard = configuration_save_lock.lock().await;

    let mut configuration = match Configuration::read_from_home().await {
        Ok(configuration) => configuration,
        Err(err) => return Ok(get_error_response(err)),
    };

    if let Some(enabled) = request.enabled {
        configuration.userscripts.enabled = enabled;
    }
    if let Some(allowed) = request.allow_private_network_requests {
        configuration.userscripts.allow_private_network_requests = allowed;
    }

    if let Err(err) = configuration.save().await {
        return Ok(userscript_error_response(err));
    }

    // Applied to the live relay switch immediately, so this behaves like every
    // other userscript setting rather than waiting for a reload.
    private_network_access.set(configuration.userscripts.allow_private_network_requests);

    reload_userscripts(&user_script_store, &configuration, &http_client).await;

    Ok(Response::builder()
        .status(http::StatusCode::ACCEPTED)
        .body(String::new())
        .unwrap())
}

async fn change_userscript_status(
    requests: Vec<UserScriptStatusChangeRequest>,
    http_client: reqwest::Client,
    configuration_save_lock: Arc<tokio::sync::Mutex<()>>,
    user_script_store: UserScriptStore,
) -> Result<impl warp::Reply, Infallible> {
    let _guard = configuration_save_lock.lock().await;

    let mut configuration = match Configuration::read_from_home().await {
        Ok(configuration) => configuration,
        Err(err) => return Ok(get_error_response(err)),
    };

    for request in requests {
        if let Err(err) = configuration
            .set_userscript_enabled_status(&request.file_name, request.enabled)
            .await
        {
            return Ok(userscript_error_response(err));
        }
    }

    reload_userscripts(&user_script_store, &configuration, &http_client).await;

    Ok(Response::builder()
        .status(http::StatusCode::ACCEPTED)
        .body(String::new())
        .unwrap())
}

async fn add_userscript(
    request: AddUserScriptRequest,
    http_client: reqwest::Client,
    configuration_save_lock: Arc<tokio::sync::Mutex<()>>,
    user_script_store: UserScriptStore,
) -> Result<impl warp::Reply, Infallible> {
    // Resolve the source before taking the lock: fetching a remote script can
    // be slow and must not serialize other configuration writers.
    let (body, url) = match (request.body, request.url) {
        (_, Some(url)) => {
            let Ok(url) = Url::parse(url.trim()) else {
                return Ok(get_unprocessable_response("The script URL is not valid"));
            };
            match fetch_userscript(&url, &http_client).await {
                Ok(body) => (body, Some(url)),
                Err(err) => return Ok(userscript_error_response(err)),
            }
        }
        (Some(body), None) => (body, None),
        (None, None) => {
            return Ok(get_unprocessable_response(
                "Provide either a script body or a URL to install from",
            ))
        }
    };

    let file_name = match &url {
        // Keyed by URL so re-installing the same script reuses its body file.
        Some(url) => calc_userscript_filename(url.as_str()),
        None => calc_local_userscript_filename(),
    };

    let _guard = configuration_save_lock.lock().await;

    let mut configuration = match Configuration::read_from_home().await {
        Ok(configuration) => configuration,
        Err(err) => return Ok(get_error_response(err)),
    };

    if configuration.userscripts.find(&file_name).is_some() {
        return Ok(Response::builder()
            .status(http::StatusCode::CONFLICT)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(
                serde_json::to_string(&super::ApiError {
                    error: "This userscript is already installed".to_string(),
                })
                .unwrap(),
            )
            .unwrap());
    }

    let script = UserScript {
        enabled: request.enabled,
        // Replaced with the parsed `@name` by `add_userscript`.
        title: String::new(),
        file_name,
        url,
    };

    if let Err(err) = configuration.add_userscript(script, &body).await {
        return Ok(userscript_error_response(err));
    }

    reload_userscripts(&user_script_store, &configuration, &http_client).await;

    Ok(Response::builder()
        .status(http::StatusCode::CREATED)
        .body(String::new())
        .unwrap())
}

/// Refresh one script or all of them from upstream.
///
/// Unlike the periodic refresh in `ConfigurationUpdater`, this holds the save
/// lock, so a `@name` or `@version` that changed upstream is persisted rather
/// than being recomputed on every read.
async fn refresh_userscripts(
    request: RefreshRequest,
    http_client: reqwest::Client,
    configuration_save_lock: Arc<tokio::sync::Mutex<()>>,
    user_script_store: UserScriptStore,
) -> Result<impl warp::Reply, Infallible> {
    let _guard = configuration_save_lock.lock().await;

    let mut configuration = match Configuration::read_from_home().await {
        Ok(configuration) => configuration,
        Err(err) => return Ok(get_error_response(err)),
    };

    let outcomes = match request.file_name {
        Some(file_name) => {
            let Some(script) = configuration
                .userscripts
                .scripts
                .iter_mut()
                .find(|script| script.file_name == file_name)
            else {
                return Ok(get_unprocessable_response("No such userscript"));
            };

            if script.url.is_none() {
                return Ok(get_unprocessable_response(
                    "This userscript was pasted rather than installed from a URL, so there is \
                     nothing to refresh.",
                ));
            }

            let outcome = match script.update(&http_client).await {
                Ok(UserScriptUpdate::Updated { version }) => RefreshOutcome::Updated { version },
                Ok(UserScriptUpdate::AlreadyCurrent) => RefreshOutcome::AlreadyCurrent,
                Err(err) => RefreshOutcome::Failed {
                    error: err.to_string(),
                },
            };

            vec![UserScriptRefresh {
                file_name: script.file_name.clone(),
                title: script.title.clone(),
                outcome,
            }]
        }
        None => configuration.update_userscripts(&http_client).await,
    };

    // Titles and versions may have moved on; persist them while we hold the lock.
    if let Err(err) = configuration.save().await {
        return Ok(userscript_error_response(err));
    }

    reload_userscripts(&user_script_store, &configuration, &http_client).await;

    Ok(Response::builder()
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(serde_json::to_string(&outcomes).unwrap())
        .unwrap())
}

async fn update_userscript(
    request: UpdateUserScriptRequest,
    http_client: reqwest::Client,
    configuration_save_lock: Arc<tokio::sync::Mutex<()>>,
    user_script_store: UserScriptStore,
) -> Result<impl warp::Reply, Infallible> {
    let _guard = configuration_save_lock.lock().await;

    let mut configuration = match Configuration::read_from_home().await {
        Ok(configuration) => configuration,
        Err(err) => return Ok(get_error_response(err)),
    };

    if let Err(err) = configuration
        .replace_userscript_body(&request.file_name, &request.body)
        .await
    {
        return Ok(userscript_error_response(err));
    }

    reload_userscripts(&user_script_store, &configuration, &http_client).await;

    Ok(Response::builder()
        .status(http::StatusCode::OK)
        .body(String::new())
        .unwrap())
}

async fn delete_userscript(
    request: DeleteUserScriptRequest,
    http_client: reqwest::Client,
    configuration_save_lock: Arc<tokio::sync::Mutex<()>>,
    user_script_store: UserScriptStore,
    gm_storage: GmStorageStore,
) -> Result<impl warp::Reply, Infallible> {
    let _guard = configuration_save_lock.lock().await;

    let mut configuration = match Configuration::read_from_home().await {
        Ok(configuration) => configuration,
        Err(err) => return Ok(get_error_response(err)),
    };

    if let Err(err) = configuration.remove_userscript(&request.file_name).await {
        return Ok(userscript_error_response(err));
    }

    // An uninstalled script must not leave its stored values behind to be
    // silently inherited if a script with the same file name is installed later.
    gm_storage.forget(&request.file_name);

    reload_userscripts(&user_script_store, &configuration, &http_client).await;

    Ok(Response::builder()
        .status(http::StatusCode::NO_CONTENT)
        .body(String::new())
        .unwrap())
}

pub(super) fn create_routes(
    configuration_save_lock: Arc<tokio::sync::Mutex<()>>,
    http_client: reqwest::Client,
    user_script_store: UserScriptStore,
    gm_storage: GmStorageStore,
    private_network_access: PrivateNetworkAccess,
) -> BoxedFilter<(impl warp::Reply,)> {
    // The master switch lives on a fixed sub-path, so it must be matched before
    // the `<file_name>` parameter route below would swallow it.
    let engine_enabled_route = warp::path("enabled")
        .and(warp::path::end())
        .and(warp::put())
        .and(warp::body::json())
        .and(super::with_http_client(http_client.clone()))
        .and(super::with_configuration_save_lock(
            configuration_save_lock.clone(),
        ))
        .and(super::with_arc(user_script_store.clone()))
        .and(super::with_arc(private_network_access))
        .and_then(self::set_engine_settings);

    let refresh_route = warp::path("update")
        .and(warp::path::end())
        .and(warp::post())
        .and(warp::body::json())
        .and(super::with_http_client(http_client.clone()))
        .and(super::with_configuration_save_lock(
            configuration_save_lock.clone(),
        ))
        .and(super::with_arc(user_script_store.clone()))
        .and_then(self::refresh_userscripts);

    let body_route = warp::path::param::<String>()
        .and(warp::path("body"))
        .and(warp::path::end())
        .and(warp::get())
        .and(super::with_arc(user_script_store.clone()))
        .and_then(self::get_userscript_body);

    engine_enabled_route
        .or(refresh_route)
        .or(body_route)
        .or(warp::path::end()
            .and(warp::get())
            .and(super::with_arc(user_script_store.clone()))
            .and_then(self::get_userscripts))
        .or(warp::path::end()
            .and(warp::put())
            .and(warp::body::json())
            .and(super::with_http_client(http_client.clone()))
            .and(super::with_configuration_save_lock(
                configuration_save_lock.clone(),
            ))
            .and(super::with_arc(user_script_store.clone()))
            .and_then(self::change_userscript_status))
        .or(warp::path::end()
            .and(warp::post())
            .and(warp::body::json())
            .and(super::with_http_client(http_client.clone()))
            .and(super::with_configuration_save_lock(
                configuration_save_lock.clone(),
            ))
            .and(super::with_arc(user_script_store.clone()))
            .and_then(self::add_userscript))
        .or(warp::path::end()
            .and(warp::patch())
            .and(warp::body::json())
            .and(super::with_http_client(http_client.clone()))
            .and(super::with_configuration_save_lock(
                configuration_save_lock.clone(),
            ))
            .and(super::with_arc(user_script_store.clone()))
            .and_then(self::update_userscript))
        .or(warp::path::end()
            .and(warp::delete())
            .and(warp::body::json())
            .and(super::with_http_client(http_client))
            .and(super::with_configuration_save_lock(configuration_save_lock))
            .and(super::with_arc(user_script_store))
            .and(super::with_arc(gm_storage))
            .and_then(self::delete_userscript))
        .boxed()
}
