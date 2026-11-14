//! Expand uBO includes before a subscription replaces its on-disk cache.
use std::time::Duration;

use url::Url;

use super::super::{ConfigurationError, ConfigurationResult};
use super::{validate_filter_content_type, validate_filter_rules, Filter};
use crate::filter_list::{is_trusted_source, preprocess_for_download};

const MAX_FILES: usize = 64;
const MAX_DEPTH: usize = 16;
const MAX_BYTES: usize = 64 * 1024 * 1024;

/// uBO includes must stay in the parent's directory or one of its descendants.
/// Reject URL/encoding tricks before joining, including encoded path traversal.
fn include_url(parent: &Url, path: &str) -> Result<Url, &'static str> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains("..")
        || path.contains(['\\', ':', '%', '?', '#'])
        || path.chars().any(char::is_whitespace)
    {
        return Err("!#include must name a relative file in the same directory or a subdirectory");
    }
    let child = parent.join(path).map_err(|_| "invalid !#include path")?;
    if !within_directory(parent, &child) {
        return Err("!#include cannot leave its parent's directory or origin");
    }
    Ok(child)
}

fn within_directory(parent: &Url, child: &Url) -> bool {
    let directory_end = parent.path().rfind('/').map_or(0, |index| index + 1);
    matches!(parent.scheme(), "http" | "https")
        && parent.origin() == child.origin()
        && child.path().starts_with(&parent.path()[..directory_end])
}

struct Download<'a> {
    filter: &'a Filter,
    client: &'a reqwest::Client,
    ancestors: Vec<Url>,
    files: usize,
    bytes: usize,
}

impl Download<'_> {
    fn invalid(&self, message: impl std::fmt::Display) -> ConfigurationError {
        ConfigurationError::FilterValidationError(format!("{}: {message}", self.filter.title))
    }

    async fn load(&mut self, url: &Url) -> ConfigurationResult<String> {
        if self.ancestors.contains(url) {
            return Err(self.invalid("cyclic !#include"));
        }
        if self.ancestors.len() > MAX_DEPTH {
            return Err(self.invalid("!#include nesting exceeds 16 levels"));
        }
        self.files += 1;
        if self.files > MAX_FILES {
            return Err(self.invalid("subscription exceeds 64 files"));
        }
        if is_trusted_source(&self.filter.url) && !is_trusted_source(url) {
            return Err(self.invalid("!#include cannot leave the trusted filter source"));
        }

        let mut response = self
            .client
            .get(url.clone())
            .timeout(Duration::from_secs(60))
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(ConfigurationError::FilterError(format!(
                "Failed to fetch filter content for {}: {}",
                self.filter.title,
                response.status()
            )));
        }
        // The shared client disables redirects. Also check the final URL when
        // called with another client, so fetched content cannot gain trust by
        // redirecting out of the permitted source.
        if (is_trusted_source(&self.filter.url) && !is_trusted_source(response.url()))
            || self
                .ancestors
                .last()
                .is_some_and(|parent| !within_directory(parent, response.url()))
        {
            return Err(self.invalid("filter redirect leaves the permitted source"));
        }
        validate_filter_content_type(self.filter, &response)?;
        let headers = response.headers().clone();
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            self.bytes = self.bytes.saturating_add(chunk.len());
            if self.bytes > MAX_BYTES {
                return Err(self.invalid("combined subscription exceeds 64 MiB"));
            }
            bytes.extend_from_slice(&chunk);
        }
        // Preserve reqwest's charset decoding after reading a bounded body.
        let mut response = reqwest::Response::from(http::Response::new(bytes));
        *response.headers_mut() = headers;
        let content = response.text().await?;
        let parsed = preprocess_for_download(&content).map_err(|error| self.invalid(error))?;
        if parsed.includes.is_empty() {
            return Ok(content);
        }

        self.ancestors.push(url.clone());
        let mut expanded = String::new();
        let mut includes = parsed.includes.into_iter().peekable();
        for (index, line) in content.lines().enumerate() {
            if let Some(&(include_index, path)) = includes.peek() {
                if index == include_index {
                    includes.next();
                    let child = include_url(url, path).map_err(|error| self.invalid(error))?;
                    let fragment = Box::pin(self.load(&child))
                        .await
                        .map_err(|error| self.invalid(format!("!#include {path}: {error}")))?;
                    self.append(&mut expanded, &format!("! Included: {path}\n"))?;
                    self.append(&mut expanded, &fragment)?;
                    self.append(&mut expanded, "\n! End include\n")?;
                    continue;
                }
            }
            self.append(&mut expanded, line)?;
            self.append(&mut expanded, "\n")?;
        }
        self.ancestors.pop();
        Ok(expanded)
    }

    fn append(&self, output: &mut String, text: &str) -> ConfigurationResult<()> {
        if output.len().saturating_add(text.len()) > MAX_BYTES {
            return Err(self.invalid("expanded subscription exceeds 64 MiB"));
        }
        output.push_str(text);
        Ok(())
    }
}

pub(super) async fn get_filter(
    filter: &Filter,
    client: &reqwest::Client,
) -> ConfigurationResult<String> {
    let mut download = Download {
        filter,
        client,
        ancestors: Vec::new(),
        files: 0,
        bytes: 0,
    };
    let content = download.load(&filter.url).await?;
    validate_filter_rules(filter, &content)?;
    Ok(content)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    use super::*;
    use crate::configuration::filter::tests::{subscription, test_client, TestCache};
    use crate::filter_list::preprocess;

    struct Server {
        url: Url,
        requests: Arc<Mutex<Vec<String>>>,
        task: JoinHandle<()>,
    }

    impl Server {
        async fn new(routes: &[(&str, &str)]) -> Self {
            let routes: HashMap<_, _> = routes
                .iter()
                .map(|(path, body)| (path.to_string(), body.to_string()))
                .collect();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
            let requests = Arc::new(Mutex::new(Vec::new()));
            let recorded = Arc::clone(&requests);
            let task = tokio::spawn(async move {
                loop {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut request = Vec::new();
                    let mut chunk = [0; 1024];
                    while !request.ends_with(b"\r\n\r\n") {
                        let len = stream.read(&mut chunk).await.unwrap();
                        if len == 0 {
                            break;
                        }
                        request.extend_from_slice(&chunk[..len]);
                    }
                    let request = String::from_utf8(request).unwrap();
                    let path = request.split_whitespace().nth(1).unwrap();
                    recorded.lock().unwrap().push(path.to_owned());
                    let (status, body) = match routes.get(path) {
                        Some(body) => ("200 OK", body.as_str()),
                        None => ("404 Not Found", "missing"),
                    };
                    let mime = if body.starts_with("<html>") {
                        "text/html"
                    } else {
                        "text/plain; charset=utf-8"
                    };
                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    stream.write_all(response.as_bytes()).await.unwrap();
                }
            });
            Self {
                url,
                requests,
                task,
            }
        }

        fn filter(&self) -> Filter {
            subscription(self.url.join("lists/main.txt").unwrap().as_str(), true)
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    #[test]
    fn include_paths_cannot_leave_the_subscription_directory() {
        let base = Url::parse("https://example.com/lists/main.txt").unwrap();
        for path in ["child.txt", "nested/child.txt", "./child.txt"] {
            assert!(include_url(&base, path).is_ok(), "{path}");
        }
        for path in [
            "",
            "../child.txt",
            "/child.txt",
            "//other.example/child.txt",
            "https://other.example/child.txt",
            "file:///etc/passwd",
            "sub/../../child.txt",
            "%2e%2e/child.txt",
            "sub%2fchild.txt",
            "sub\\child.txt",
            "child.txt?url=other",
            "child.txt#fragment",
        ] {
            assert!(include_url(&base, path).is_err(), "{path}");
        }
        assert!(!within_directory(
            &base,
            &Url::parse("https://example.com/lists-other/child.txt").unwrap()
        ));
    }

    #[tokio::test]
    async fn nested_includes_upgrade_old_caches_and_survive_offline_reload() {
        let main = "!#if ext_ublock\n!#include child.txt\n!#else\n!#include missing.txt\n!#endif\n||after.example^";
        let server = Server::new(&[
            ("/lists/main.txt", main),
            (
                "/lists/child.txt",
                "||child.example^\n!#include nested/leaf.txt",
            ),
            (
                "/lists/nested/leaf.txt",
                "!#if cap_html_filtering\n||unused.example^\n!#else\n||leaf.example^\n!#endif",
            ),
        ])
        .await;
        let cache = TestCache::new();
        let mut filter = server.filter();
        let path = cache.0.join(&filter.file_name);
        // Old versions cached unresolved include directives as comments.
        tokio::fs::write(&path, main).await.unwrap();
        let client = test_client();
        let expanded = filter
            .get_contents_in_directory(&client, &cache.0)
            .await
            .unwrap();
        let active = preprocess(&expanded).unwrap();
        let rules: Vec<_> = active
            .lines
            .into_iter()
            .filter(|line| line.starts_with("||"))
            .collect();
        assert_eq!(
            rules,
            ["||child.example^", "||leaf.example^", "||after.example^"]
        );
        assert_eq!(
            *server.requests.lock().unwrap(),
            [
                "/lists/main.txt",
                "/lists/child.txt",
                "/lists/nested/leaf.txt"
            ]
        );
        assert_eq!(tokio::fs::read_to_string(path).await.unwrap(), expanded);
        drop(server);
        assert_eq!(
            filter
                .get_contents_in_directory(&client, &cache.0)
                .await
                .unwrap(),
            expanded
        );
    }

    #[tokio::test]
    async fn failed_includes_preserve_the_last_complete_cache() {
        for (fragment, expected_error) in [
            (None, "404"),
            (Some("<html>not a list</html>"), "text/html"),
            (Some("!#endif\n||bad.example^"), "unmatched !#endif"),
            (Some("!#include main.txt"), "cyclic !#include"),
            (Some("!#include ../outside.txt"), "relative file"),
        ] {
            let mut routes = vec![("/lists/main.txt", "||new.example^\n!#include child.txt")];
            if let Some(fragment) = fragment {
                routes.push(("/lists/child.txt", fragment));
            }
            let server = Server::new(&routes).await;
            let mut filter = server.filter();
            let client = test_client();
            let cache = TestCache::new();
            let path = cache.0.join(&filter.file_name);
            let previous = "||previous.example^\n";
            tokio::fs::write(&path, previous).await.unwrap();
            let error = filter
                .update_in_directory(&client, &cache.0)
                .await
                .unwrap_err()
                .to_string();
            assert!(error.contains(expected_error), "{error}");
            assert_eq!(tokio::fs::read_to_string(path).await.unwrap(), previous);
            assert_eq!(
                filter
                    .get_contents_in_directory(&client, &cache.0)
                    .await
                    .unwrap(),
                previous
            );
        }
    }

    #[tokio::test]
    async fn subscriptions_can_consist_only_of_includes() {
        let server = Server::new(&[
            ("/lists/main.txt", "!#include child.txt"),
            ("/lists/child.txt", "||ads.example^"),
        ])
        .await;
        let result = get_filter(&server.filter(), &test_client()).await.unwrap();
        assert!(result.contains("||ads.example^"));
    }

    #[tokio::test]
    async fn download_limits_and_trust_are_enforced() {
        let server = Server::new(&[("/lists/main.txt", "||ads.example^")]).await;
        let filter = server.filter();
        let client = test_client();
        let mut download = Download {
            filter: &filter,
            client: &client,
            ancestors: Vec::new(),
            files: MAX_FILES,
            bytes: 0,
        };
        let error = download.load(&filter.url).await.unwrap_err().to_string();
        assert!(error.contains("64 files"));
        download.files = 0;
        download.ancestors = vec![server.url.clone(); MAX_DEPTH + 1];
        let error = download.load(&filter.url).await.unwrap_err().to_string();
        assert!(error.contains("nesting exceeds"));
        download.ancestors.clear();
        download.bytes = MAX_BYTES;
        let error = download.load(&filter.url).await.unwrap_err().to_string();
        assert!(error.contains("64 MiB"));
        assert_eq!(server.requests.lock().unwrap().len(), 1);

        let trusted = subscription(
            "https://raw.githubusercontent.com/uBlockOrigin/uAssetsCDN/main/filters/filters.min.txt",
            true,
        );
        download.filter = &trusted;
        download.bytes = 0;
        let error = download.load(&filter.url).await.unwrap_err().to_string();
        assert!(error.contains("trusted filter source"));
        assert_eq!(server.requests.lock().unwrap().len(), 1);
    }
}
