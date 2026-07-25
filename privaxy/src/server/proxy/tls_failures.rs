//! Bounded in-memory record of TLS interception handshake failures.
//!
//! Certificate-pinning clients abort our MITM handshake before any HTTP
//! exchange happens, so they can never be shown an error page. The proxy
//! records those failures here instead; the web GUI surfaces them via
//! `GET /api/tls-failures` so the operator can exclude (or ignore) the hosts.

use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

/// Maximum number of distinct failing hosts kept in memory. Older hosts are
/// evicted first once the bound is reached.
const MAX_TRACKED_FAILURES: usize = 100;

/// A single failing host, most recent failure details included.
#[derive(Debug, Clone, Serialize)]
pub struct TlsFailureEntry {
    /// Sanitized, portless hostname the client tried to CONNECT to.
    pub host: String,
    /// When the host last failed a handshake (RFC 3339 via chrono's serde).
    pub last_seen: DateTime<Utc>,
    /// How many handshake failures have been observed for this host.
    pub count: u64,
    /// Whether the last failure looked like certificate pinning (the client
    /// saw our interception certificate and hung up).
    pub likely_pinning: bool,
    /// The last handshake error, verbatim.
    pub last_error: String,
}

#[derive(Debug)]
struct Inner {
    /// Most-recent-first list of failing hosts, bounded by
    /// `MAX_TRACKED_FAILURES`.
    entries: Vec<TlsFailureEntry>,
    /// Hosts the operator chose to hide from the report; persisted in the
    /// configuration as `ignored_tls_failures`.
    ignored: BTreeSet<String>,
}

/// Cheaply-cloneable shared store of TLS interception failures. Lock scopes
/// are short and never held across an await point.
#[derive(Debug, Clone)]
pub struct TlsFailureStore(Arc<Mutex<Inner>>);

impl TlsFailureStore {
    pub fn new(ignored: BTreeSet<String>) -> Self {
        Self(Arc::new(Mutex::new(Inner {
            entries: Vec::new(),
            ignored,
        })))
    }

    /// Record a handshake failure for `host`, deduplicating by host: a host
    /// already present is bumped to the front with its counter incremented
    /// and failure details refreshed. Ignored hosts are not recorded. Hosts
    /// are lowercased on the way in — DNS names are case-insensitive and the
    /// exclusion store matches lowercased hosts, so the store must too.
    pub fn record(&self, host: &str, error: &str, likely_pinning: bool) {
        let host = host.to_lowercase();
        let mut inner = self.0.lock().unwrap();

        if inner.ignored.contains(&host) {
            return;
        }

        let last_seen = Utc::now();
        match inner.entries.iter().position(|entry| entry.host == host) {
            Some(index) => {
                let mut entry = inner.entries.remove(index);
                entry.count += 1;
                entry.last_seen = last_seen;
                entry.last_error = error.to_string();
                entry.likely_pinning = likely_pinning;
                inner.entries.insert(0, entry);
            }
            None => {
                inner.entries.insert(
                    0,
                    TlsFailureEntry {
                        host,
                        last_seen,
                        count: 1,
                        likely_pinning,
                        last_error: error.to_string(),
                    },
                );
                inner.entries.truncate(MAX_TRACKED_FAILURES);
            }
        }
    }

    /// Snapshot of the tracked failures, most recent first.
    pub fn entries(&self) -> Vec<TlsFailureEntry> {
        self.0.lock().unwrap().entries.clone()
    }

    /// Hide `host` from the report: drop any tracked entry and suppress
    /// future `record` calls for it. Lowercased like `record`.
    pub fn ignore(&self, host: &str) {
        let host = host.to_lowercase();
        let mut inner = self.0.lock().unwrap();
        inner.entries.retain(|entry| entry.host != host);
        inner.ignored.insert(host);
    }

    /// Replace the ignore set wholesale (used when configuration is reloaded
    /// on SIGHUP), pruning entries the new set covers. Values are lowercased
    /// so hand-edited configuration entries match regardless of case.
    pub fn set_ignored(&self, ignored: BTreeSet<String>) {
        let ignored: BTreeSet<String> = ignored
            .into_iter()
            .map(|host| host.trim().to_lowercase())
            .collect();
        let mut inner = self.0.lock().unwrap();
        inner.entries.retain(|entry| !ignored.contains(&entry.host));
        inner.ignored = ignored;
    }
}

/// Normalize an operator-supplied host for the ignore list: trim, lowercase,
/// and strip a trailing `:port` (both `host:1234` and `[v6]:1234` forms) so
/// the value matches the portless hosts the store records. Returns `None`
/// when nothing host-shaped remains (empty input, internal whitespace, or a
/// bare `:port`).
pub fn normalize_ignored_host(raw: &str) -> Option<String> {
    let trimmed = raw.trim().to_lowercase();
    if trimmed.is_empty() || trimmed.chars().any(char::is_whitespace) {
        return None;
    }

    let host = match trimmed.rsplit_once(':') {
        Some((head, port))
            if !port.is_empty()
                && port.chars().all(|c| c.is_ascii_digit())
                // Only strip when what precedes the colon is not itself a
                // bare IPv6 address: bracketed literals end with `]`, and a
                // hostname/IPv4 head contains no further colon.
                && (head.ends_with(']') || !head.contains(':')) =>
        {
            head.to_string()
        }
        _ => trimmed,
    };

    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_dedupes_by_host_and_bumps_count() {
        let store = TlsFailureStore::new(BTreeSet::new());
        store.record("pinned.example.com", "first error", false);
        store.record("pinned.example.com", "second error", true);

        let entries = store.entries();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.host, "pinned.example.com");
        assert_eq!(entry.count, 2);
        assert!(entry.likely_pinning);
        assert_eq!(entry.last_error, "second error");
    }

    #[test]
    fn record_moves_repeated_host_to_front() {
        let store = TlsFailureStore::new(BTreeSet::new());
        store.record("a.example.com", "error", false);
        store.record("b.example.com", "error", false);
        store.record("a.example.com", "error", false);

        let hosts: Vec<String> = store
            .entries()
            .into_iter()
            .map(|entry| entry.host)
            .collect();
        assert_eq!(hosts, vec!["a.example.com", "b.example.com"]);
    }

    #[test]
    fn store_is_bounded_and_evicts_oldest() {
        let store = TlsFailureStore::new(BTreeSet::new());
        for index in 0..=MAX_TRACKED_FAILURES {
            store.record(&format!("host-{index}.example.com"), "error", false);
        }

        let entries = store.entries();
        assert_eq!(entries.len(), MAX_TRACKED_FAILURES);
        assert_eq!(
            entries[0].host,
            format!("host-{MAX_TRACKED_FAILURES}.example.com")
        );
        // The very first (oldest) host was evicted.
        assert!(entries
            .iter()
            .all(|entry| entry.host != "host-0.example.com"));
    }

    #[test]
    fn ignore_drops_existing_entry_and_suppresses_future_records() {
        let store = TlsFailureStore::new(BTreeSet::new());
        store.record("pinned.example.com", "error", true);

        store.ignore("pinned.example.com");
        assert!(store.entries().is_empty());

        store.record("pinned.example.com", "error", true);
        assert!(store.entries().is_empty());
    }

    #[test]
    fn record_and_ignore_are_case_insensitive() {
        let store = TlsFailureStore::new(BTreeSet::new());
        store.record("PINNED.Example.com", "error", true);
        store.record("pinned.example.com", "error", true);

        let entries = store.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].host, "pinned.example.com");
        assert_eq!(entries[0].count, 2);

        store.ignore("Pinned.EXAMPLE.com");
        assert!(store.entries().is_empty());
        store.record("pinned.example.com", "error", true);
        assert!(store.entries().is_empty());
    }

    #[test]
    fn normalize_ignored_host_shapes() {
        assert_eq!(
            normalize_ignored_host("  Pinned.Example.com  "),
            Some("pinned.example.com".to_string())
        );
        assert_eq!(
            normalize_ignored_host("pinned.example.com:443"),
            Some("pinned.example.com".to_string())
        );
        assert_eq!(
            normalize_ignored_host("[::1]:443"),
            Some("[::1]".to_string())
        );
        // A bare IPv6 address must not have its last group eaten as a port.
        assert_eq!(normalize_ignored_host("::1"), Some("::1".to_string()));
        // Non-numeric suffixes are not ports.
        assert_eq!(
            normalize_ignored_host("svc:name"),
            Some("svc:name".to_string())
        );
        assert_eq!(normalize_ignored_host(""), None);
        assert_eq!(normalize_ignored_host("   "), None);
        assert_eq!(normalize_ignored_host(":443"), None);
        assert_eq!(normalize_ignored_host("two words"), None);
    }

    #[test]
    fn set_ignored_prunes_newly_ignored_entries() {
        let store = TlsFailureStore::new(BTreeSet::new());
        store.record("a.example.com", "error", false);
        store.record("b.example.com", "error", false);

        store.set_ignored(BTreeSet::from(["a.example.com".to_string()]));

        let hosts: Vec<String> = store
            .entries()
            .into_iter()
            .map(|entry| entry.host)
            .collect();
        assert_eq!(hosts, vec!["b.example.com"]);

        // The replaced set also suppresses future records.
        store.record("a.example.com", "error", false);
        let hosts: Vec<String> = store
            .entries()
            .into_iter()
            .map(|entry| entry.host)
            .collect();
        assert_eq!(hosts, vec!["b.example.com"]);
    }
}
