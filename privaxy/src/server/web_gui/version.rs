use super::{json_status, with_arc};
use reqwest::Client;
use semver::Version;
use serde::{Deserialize, Serialize};
use std::{
    convert::Infallible,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use warp::{filters::BoxedFilter, http::StatusCode, Filter, Reply};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const PROJECT_URL: &str = env!("CARGO_PKG_REPOSITORY");
const RELEASE_API: &str = "https://api.github.com/repos/joshrmcdaniel/privaxy/releases/latest";
const CACHE_DURATION: Duration = Duration::from_secs(3600);
const ERROR_CACHE_DURATION: Duration = Duration::from_secs(60);

#[derive(Serialize)]
struct VersionInfo {
    version: &'static str,
    project_url: &'static str,
}

#[derive(Clone, Serialize)]
struct ReleaseInfo {
    version: String,
    url: String,
}

#[derive(Clone, Serialize)]
struct UpdateCheck {
    current_version: &'static str,
    latest_release: Option<ReleaseInfo>,
    update_available: bool,
    checked_at: i64,
}

#[derive(Deserialize)]
struct GitHubRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
}

struct CachedCheck {
    result: Result<UpdateCheck, String>,
    fetched_at: Instant,
}

#[derive(Clone)]
struct UpdateChecker {
    client: Client,
    cache: Arc<Mutex<Option<CachedCheck>>>,
}

impl UpdateChecker {
    async fn check(&self) -> Result<UpdateCheck, String> {
        // Share both successful and failed checks across tabs. Holding this
        // lock also combines simultaneous requests into one bounded fetch.
        let mut cache = self.cache.lock().await;
        if let Some(cached) = cache.as_ref() {
            let ttl = if cached.result.is_ok() {
                CACHE_DURATION
            } else {
                ERROR_CACHE_DURATION
            };
            if cached.fetched_at.elapsed() < ttl {
                return cached.result.clone();
            }
        }
        let result = self.fetch().await;
        *cache = Some(CachedCheck {
            result: result.clone(),
            fetched_at: Instant::now(),
        });
        result
    }

    async fn fetch(&self) -> Result<UpdateCheck, String> {
        let response = self
            .client
            .get(RELEASE_API)
            .header(
                reqwest::header::USER_AGENT,
                concat!("Privaxy/", env!("CARGO_PKG_VERSION")),
            )
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2026-03-10")
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|error| {
                if error.is_timeout() {
                    "Update check timed out. Try again in a minute."
                } else {
                    "Could not reach GitHub. Try again in a minute."
                }
                .to_string()
            })?;
        let release = match response.status() {
            StatusCode::NOT_FOUND => None,
            StatusCode::OK => Some(response.json::<GitHubRelease>().await.map_err(|_| {
                "GitHub returned invalid release information. Try again in a minute.".to_string()
            })?),
            status => return Err(format!("GitHub returned HTTP {status}. Try again later.")),
        };
        let (latest_release, update_available) = match release {
            Some(release) => {
                let (info, newer) = compare_release(VERSION, release)?;
                (Some(info), newer)
            }
            None => (None, false),
        };
        Ok(UpdateCheck {
            current_version: VERSION,
            latest_release,
            update_available,
            checked_at: chrono::Utc::now().timestamp(),
        })
    }
}

fn compare_release(current: &str, release: GitHubRelease) -> Result<(ReleaseInfo, bool), String> {
    let version = Version::parse(
        release
            .tag_name
            .strip_prefix('v')
            .unwrap_or(&release.tag_name),
    )
    .map_err(|_| "The latest release has an unrecognized version tag.".to_string())?;
    if release.draft || release.prerelease || !version.pre.is_empty() {
        return Err("GitHub did not return a stable release.".to_string());
    }
    let current = Version::parse(current)
        .map_err(|_| "The running version could not be compared.".to_string())?;
    let newer = version.cmp_precedence(&current).is_gt();
    // Construct the link from the fixed project URL and validated version tag;
    // the remote response cannot supply an arbitrary link to the frontend.
    Ok((
        ReleaseInfo {
            version: version.to_string(),
            url: format!("{PROJECT_URL}/releases/tag/{}", release.tag_name),
        },
        newer,
    ))
}

async fn check_update(checker: UpdateChecker) -> Result<Box<dyn Reply>, Infallible> {
    Ok(match checker.check().await {
        Ok(result) => Box::new(warp::reply::json(&result)),
        Err(error) => json_status(StatusCode::BAD_GATEWAY, &error),
    })
}

pub(super) fn version() -> impl Reply {
    warp::reply::with_header(
        warp::reply::json(&VersionInfo {
            version: VERSION,
            project_url: PROJECT_URL,
        }),
        "cache-control",
        "no-store",
    )
}

pub(super) fn updates(client: Client) -> BoxedFilter<(impl Reply,)> {
    warp::path::end()
        .and(warp::get())
        .and(with_arc(UpdateChecker {
            client,
            cache: Arc::new(Mutex::new(None)),
        }))
        .and_then(check_update)
        .with(warp::reply::with::header("cache-control", "no-store"))
        .boxed()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(tag: &str) -> GitHubRelease {
        GitHubRelease {
            tag_name: tag.into(),
            draft: false,
            prerelease: false,
        }
    }

    #[test]
    fn updates_use_semantic_precedence_and_preserve_release_links() {
        for (current, tag, expected) in [
            ("0.8.0", "v0.8.1", true),
            ("0.9.0", "v0.10.0", true),
            ("0.8.0", "0.8.0", false),
            ("0.9.0", "v0.8.0", false),
            ("0.8.0-rc.1", "v0.8.0", true),
            ("0.8.0+local", "v0.8.0+release", false),
        ] {
            let (info, newer) = compare_release(current, release(tag)).unwrap();
            assert_eq!(newer, expected, "{current} -> {tag}");
            assert_eq!(info.url, format!("{PROJECT_URL}/releases/tag/{tag}"));
        }
    }

    #[test]
    fn invalid_and_unstable_releases_cannot_be_reported_as_updates() {
        for tag in [
            "latest",
            "dev",
            "v1.0.0-beta.1",
            "https://example.test/",
            "v1.0.0/extra",
        ] {
            assert!(compare_release("0.8.0", release(tag)).is_err());
        }
        for (draft, prerelease) in [(true, false), (false, true)] {
            assert!(compare_release(
                "0.8.0",
                GitHubRelease {
                    draft,
                    prerelease,
                    ..release("v1.0.0")
                }
            )
            .is_err());
        }
    }
}
