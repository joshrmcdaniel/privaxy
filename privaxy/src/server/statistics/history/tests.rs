use super::*;
use crate::statistics::Statistics;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "privaxy-stats-test-{}",
            crate::configuration::generate_random_hex(12)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn database(&self) -> PathBuf {
        self.0.join("statistics.redb")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn enabled(privacy: StatisticsPrivacy) -> StatisticsConfig {
    StatisticsConfig {
        enabled: true,
        privacy,
        ..Default::default()
    }
}
fn client() -> IpAddr {
    "192.0.2.10".parse().unwrap()
}
async fn snapshot(store: &HistoryStore) -> HistorySnapshot {
    store.query(HistoryQuery::default()).await.unwrap()
}

#[tokio::test]
async fn disabled_and_anonymous_do_not_create_databases_or_retroactively_collect() {
    for config in [
        StatisticsConfig::default(),
        enabled(StatisticsPrivacy::Anonymous),
    ] {
        let fixture = Fixture::new();
        let store = HistoryStore::start(fixture.database(), config).await;
        store.request(Some("private.example.test"), client(), true);
        store.modified();
        assert!(snapshot(&store).await.requests.is_empty());
        assert!(!fixture.database().exists());
        store
            .configure(enabled(StatisticsPrivacy::Full))
            .await
            .unwrap();
        assert!(snapshot(&store).await.requests.is_empty());
        store.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn requests_and_modified_counts_survive_restart_without_url_details() {
    let fixture = Fixture::new();
    let config = enabled(StatisticsPrivacy::Full);
    let store = HistoryStore::start(fixture.database(), config.clone()).await;
    let uri: http::Uri = "https://EXAMPLE.test:443/private-account?secret=do-not-store"
        .parse()
        .unwrap();
    store.request(uri.host(), client(), true);
    store.request(Some("allowed.example.test"), client(), false);
    store.modified();
    store.shutdown().await.unwrap();
    let store = HistoryStore::start(fixture.database(), config).await;
    let data = snapshot(&store).await;
    assert_eq!(data.totals.blocked_requests, 1);
    assert_eq!(data.totals.proxied_requests, 1);
    assert_eq!(data.totals.modified_responses, 1);
    assert_eq!(data.requests[1].domain.as_deref(), Some("example.test"));
    assert_eq!(data.requests[1].client.as_deref(), Some("192.0.2.10"));
    assert_eq!(data.top_blocked_domains, vec![("example.test".into(), 1)]);
    store.shutdown().await.unwrap();
    let bytes = std::fs::read(fixture.database()).unwrap();
    let text = String::from_utf8_lossy(&bytes);
    assert!(!text.contains("private-account"));
    assert!(!text.contains("do-not-store"));
    assert!(!text.contains(":443"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(fixture.database())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[tokio::test]
async fn identifiers_are_redacted_before_queueing_and_cannot_be_recovered() {
    for privacy in [
        StatisticsPrivacy::HideDomains,
        StatisticsPrivacy::HideDomainsAndClients,
    ] {
        let fixture = Fixture::new();
        let store = HistoryStore::start(fixture.database(), enabled(privacy)).await;
        store.request(Some("private.example.test"), client(), true);
        store
            .configure(enabled(StatisticsPrivacy::Full))
            .await
            .unwrap();
        let data = snapshot(&store).await;
        assert_eq!(data.requests.len(), 1);
        assert!(data.requests[0].domain.is_none());
        assert_eq!(
            data.requests[0].client.is_none(),
            privacy == StatisticsPrivacy::HideDomainsAndClients
        );
        store.shutdown().await.unwrap();
        let bytes = std::fs::read(fixture.database()).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("private.example.test"));
        if privacy == StatisticsPrivacy::HideDomainsAndClients {
            assert!(!text.contains("192.0.2.10"));
        }
    }
}

#[tokio::test]
async fn increasing_privacy_redacts_old_rows_including_before_anonymous_mode() {
    for privacy in [
        StatisticsPrivacy::HideDomains,
        StatisticsPrivacy::HideDomainsAndClients,
        StatisticsPrivacy::Anonymous,
    ] {
        let fixture = Fixture::new();
        let store = HistoryStore::start(fixture.database(), enabled(StatisticsPrivacy::Full)).await;
        store.request(Some("private.example.test"), client(), true);
        // The pending record must also be covered by this transition.
        store.configure(enabled(privacy)).await.unwrap();
        store
            .configure(enabled(StatisticsPrivacy::Full))
            .await
            .unwrap();
        let data = snapshot(&store).await;
        assert_eq!(data.requests.len(), 1);
        assert!(data.requests[0].domain.is_none());
        assert_eq!(
            data.requests[0].client.is_none(),
            privacy >= StatisticsPrivacy::HideDomainsAndClients
        );
        store.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn retention_entry_cap_and_cursor_pagination_are_enforced() {
    let fixture = Fixture::new();
    let mut config = enabled(StatisticsPrivacy::Full);
    config.max_entries = 100;
    let store = HistoryStore::start(fixture.database(), config.clone()).await;
    for i in 0..150 {
        store.request(
            Some(&format!("host-{i}.example.test")),
            client(),
            i % 2 == 0,
        );
    }
    let query = || HistoryQuery {
        limit: Some(10),
        blocked: Some(true),
        ..Default::default()
    };
    let first = store.query(query()).await.unwrap();
    assert_eq!(first.status.stored_requests, 100);
    assert_eq!(first.totals.blocked_requests, 50);
    assert_eq!(first.totals.proxied_requests, 50);
    assert!(first.requests.iter().all(|r| r.blocked));
    assert_eq!(first.requests.len(), 10);
    let second = store
        .query(HistoryQuery {
            before: first.next_before,
            ..query()
        })
        .await
        .unwrap();
    assert_eq!(second.requests.len(), 10);
    assert!(second
        .requests
        .iter()
        .all(|r| r.id < first.requests.last().unwrap().id));
    assert_eq!(second.totals.blocked_requests, 50);
    let generation = store.policy.read().unwrap().generation;
    store
        .sender
        .send(Command::Event(
            generation,
            Event::Request(RequestRecord {
                id: 0,
                timestamp: now_ms() - 2 * DAY_MS,
                domain: Some("old.example.test".into()),
                client: None,
                blocked: true,
            }),
        ))
        .unwrap();
    config.retention_days = 1;
    store.configure(config).await.unwrap();
    let data = snapshot(&store).await;
    // Old timestamp with a newer ID is pruned too (clock corrections).
    assert_eq!(data.status.stored_requests, 99);
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn clear_and_disable_do_not_replay_queued_records() {
    let fixture = Fixture::new();
    let config = enabled(StatisticsPrivacy::Full);
    let store = HistoryStore::start(fixture.database(), config.clone()).await;
    for _ in 0..100 {
        store.request(Some("old.example.test"), client(), true);
    }
    store.clear().await.unwrap();
    assert!(snapshot(&store).await.requests.is_empty());
    store.configure(StatisticsConfig::default()).await.unwrap();
    store.request(Some("disabled.example.test"), client(), false);
    store.clear().await.unwrap();
    assert!(!fixture.database().exists());
    store.configure(config).await.unwrap();
    assert!(snapshot(&store).await.requests.is_empty());
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn corrupt_storage_is_reported_without_truncation_or_breaking_session_counts() {
    let fixture = Fixture::new();
    std::fs::write(fixture.database(), b"corrupt-fixture-do-not-truncate").unwrap();
    let history = HistoryStore::start(fixture.database(), enabled(StatisticsPrivacy::Full)).await;
    assert!(history.status().error.is_some());
    assert_eq!(
        std::fs::read(fixture.database()).unwrap(),
        b"corrupt-fixture-do-not-truncate"
    );
    let stats = Statistics {
        history: Some(history.clone()),
        ..Statistics::new()
    };
    stats.record_request(Some("example.test"), client(), true);
    assert_eq!(stats.get_serialized().blocked_requests, 1);
    history.clear().await.unwrap();
    assert!(history.status().error.is_none());
    stats.record_request(Some("example.test"), client(), true);
    assert_eq!(snapshot(&history).await.totals.blocked_requests, 1);
    history.shutdown().await.unwrap();
}

#[tokio::test]
async fn excluded_domains_skip_counters_history_and_the_live_log_even_when_disabled() {
    for persistent in [false, true] {
        let fixture = Fixture::new();
        let config = StatisticsConfig {
            enabled: persistent,
            privacy: StatisticsPrivacy::Full,
            excluded_domains: vec!["EXAMPLE.test".into(), "*.private.test".into()],
            ..Default::default()
        };
        let history = HistoryStore::start(fixture.database(), config).await;
        let stats = Statistics {
            history: Some(history.clone()),
            ..Statistics::new()
        };
        for authority in ["example.test:443", "Sub.Private.Test.:8443"] {
            let uri: http::Uri = format!("https://{authority}/secret").parse().unwrap();
            let request_stats = stats.for_domain(uri.host());
            assert!(!request_stats.should_collect());
            request_stats.record_request(uri.host(), client(), true);
            request_stats.increment_modified_responses();
            // The history collector independently enforces the same policy.
            history.request(uri.host(), client(), true);
        }
        let data = stats.get_serialized();
        assert_eq!(data.blocked_requests, 0);
        assert_eq!(data.modified_responses, 0);
        assert!(data.top_clients.is_empty());
        assert!(snapshot(&history).await.requests.is_empty());
        for domain in ["private.test", "sub.example.test", "example.test.evil.test"] {
            assert!(stats.for_domain(Some(domain)).should_collect());
        }
        history.shutdown().await.unwrap();
    }
}

#[test]
fn rejects_unbounded_settings_and_urls_in_domain_exclusions() {
    for pattern in [
        "https://example.test",
        "example.test:443",
        "example.test/path",
        " ",
    ] {
        let config = StatisticsConfig {
            excluded_domains: vec![pattern.into()],
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }
    for days in [0, 366] {
        assert!(StatisticsConfig {
            retention_days: days,
            ..Default::default()
        }
        .validate()
        .is_err());
    }
    for limit in [0, 99, 1_000_001] {
        assert!(StatisticsConfig {
            max_entries: limit,
            ..Default::default()
        }
        .validate()
        .is_err());
    }
    assert!(HistoryQuery {
        limit: Some(201),
        ..Default::default()
    }
    .validate()
    .is_err());
}

#[test]
fn a_full_queue_drops_events_without_blocking_requests() {
    let (sender, receiver) = mpsc::sync_channel(1);
    let store = HistoryStore {
        sender,
        policy: Arc::new(RwLock::new(Policy {
            config: enabled(StatisticsPrivacy::HideDomainsAndClients),
            ..Default::default()
        })),
        status: Arc::new(Mutex::new(HistoryStatus::default())),
        dropped: Arc::new(AtomicU64::new(0)),
        operations: Arc::new(tokio::sync::Mutex::new(())),
    };
    store.request(Some("private.example.test"), client(), true);
    store.request(Some("private.example.test"), client(), true);
    assert_eq!(store.status().dropped_events, 1);
    let Command::Event(_, Event::Request(record)) = receiver.try_recv().unwrap() else {
        panic!("expected a request");
    };
    assert!(record.domain.is_none());
    assert!(record.client.is_none());
}

#[derive(Debug)]
struct FailingDisk {
    inner: redb::backends::FileBackend,
    full: Arc<std::sync::atomic::AtomicBool>,
}
impl redb::StorageBackend for FailingDisk {
    fn len(&self) -> std::io::Result<u64> {
        self.inner.len()
    }
    fn read(&self, offset: u64, out: &mut [u8]) -> std::io::Result<()> {
        self.inner.read(offset, out)
    }
    fn set_len(&self, len: u64) -> std::io::Result<()> {
        if self.full.load(Ordering::Relaxed) {
            return Err(std::io::ErrorKind::StorageFull.into());
        }
        self.inner.set_len(len)
    }
    fn sync_data(&self) -> std::io::Result<()> {
        if self.full.load(Ordering::Relaxed) {
            return Err(std::io::ErrorKind::StorageFull.into());
        }
        self.inner.sync_data()
    }
    fn write(&self, offset: u64, bytes: &[u8]) -> std::io::Result<()> {
        if self.full.load(Ordering::Relaxed) {
            return Err(std::io::ErrorKind::StorageFull.into());
        }
        self.inner.write(offset, bytes)
    }
    fn close(&self) -> std::io::Result<()> {
        self.inner.close()
    }
}

#[test]
fn disk_full_pauses_recording_and_preserves_committed_history() {
    let fixture = Fixture::new();
    let mut worker = Worker {
        path: fixture.database(),
        database: None,
        config: enabled(StatisticsPrivacy::Full),
        generation: 0,
        pending: Vec::new(),
        status: Arc::new(Mutex::new(HistoryStatus::default())),
        dropped: Arc::new(AtomicU64::new(0)),
        last_id: 0,
        last_flush: Instant::now(),
        last_compaction: Instant::now(),
        last_prune: Instant::now(),
    };
    worker.open().unwrap();
    let event = || {
        Event::Request(RequestRecord {
            id: 0,
            timestamp: now_ms(),
            domain: Some("example.test".into()),
            client: None,
            blocked: true,
        })
    };
    worker.pending.push(event());
    worker.flush().unwrap();
    worker.database = None;
    let full = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(fixture.database())
        .unwrap();
    let backend = FailingDisk {
        inner: redb::backends::FileBackend::new(file).unwrap(),
        full: full.clone(),
    };
    worker.database = Some(Database::builder().create_with_backend(backend).unwrap());
    full.store(true, Ordering::Relaxed);
    worker.pending.push(event());
    let error = worker.flush().unwrap_err();
    worker.fail(error.to_string());
    assert!(!worker.status.lock().unwrap().active);
    assert!(worker.status.lock().unwrap().error.is_some());
    assert!(worker.pending.is_empty());
    assert_eq!(worker.dropped.load(Ordering::Relaxed), 1);
    worker.database = None;
    full.store(false, Ordering::Relaxed);
    worker
        .configure(enabled(StatisticsPrivacy::Full), 1)
        .unwrap();
    assert_eq!(
        worker
            .query(HistoryQuery::default())
            .unwrap()
            .totals
            .blocked_requests,
        1
    );
}
