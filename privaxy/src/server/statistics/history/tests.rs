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
fn request_uri(domain: &str) -> http::Uri {
    format!("https://{domain}/private-path?secret=do-not-store")
        .parse()
        .unwrap()
}
async fn snapshot(store: &HistoryStore) -> HistorySnapshot {
    store.query(HistoryQuery::default()).await.unwrap()
}

fn assert_dictionaries(tx: &redb::ReadTransaction, sizes: [u64; 3]) {
    use sha2::{Digest, Sha256};
    let rows = tx.open_table(REQUESTS).unwrap();
    for (column, (definition, index_name)) in [
        (storage::DOMAINS, "domain_index_v3"),
        (storage::ENDPOINTS, "endpoint_index_v3"),
        (storage::CLIENTS, "client_index_v3"),
    ]
    .into_iter()
    .enumerate()
    {
        let mut counts = HashMap::new();
        for entry in rows.iter().unwrap() {
            let row = entry.unwrap().1.value();
            let id = [row.1, row.2, row.3][column];
            if id != 0 {
                *counts.entry(id).or_insert(0_u64) += 1;
            }
        }
        let values = tx.open_table(definition).unwrap();
        let index = tx
            .open_table(TableDefinition::<&[u8], u64>::new(index_name))
            .unwrap();
        assert_eq!(values.len().unwrap(), sizes[column]);
        assert_eq!(index.len().unwrap(), sizes[column]);
        assert_eq!(counts.len() as u64, sizes[column]);
        for entry in values.iter().unwrap() {
            let (id, value) = entry.unwrap();
            let (references, value) = value.value();
            assert_eq!(counts[&id.value()], references);
            assert_eq!(
                index
                    .get(Sha256::digest(value.as_bytes()).as_slice())
                    .unwrap()
                    .unwrap()
                    .value(),
                id.value()
            );
        }
    }
}

#[tokio::test]
async fn repeated_identifiers_share_ids_including_paths_on_different_domains() {
    let fixture = Fixture::new();
    let store = HistoryStore::start(fixture.database(), enabled(StatisticsPrivacy::Full)).await;
    for (uri, ip) in [
        ("https://one.test/204?first=1", "192.0.2.10"),
        ("https://one.test/204?second=2", "192.0.2.10"),
        ("https://two.test/204", "2001:db8::1"),
        ("https://one.test/", "192.0.2.10"),
        ("https://two.test/", "2001:db8::1"),
    ] {
        store.request(&uri.parse().unwrap(), ip.parse().unwrap(), false);
    }
    assert_eq!(snapshot(&store).await.totals.proxied_requests, 5);
    store.shutdown().await.unwrap();
    let database = Database::open(fixture.database()).unwrap();
    let tx = database.begin_read().unwrap();
    assert_dictionaries(&tx, [2, 2, 2]);
    let rows: Vec<_> = tx
        .open_table(REQUESTS)
        .unwrap()
        .iter()
        .unwrap()
        .map(|entry| entry.unwrap().1.value())
        .collect();
    assert_eq!(rows[0].1, rows[1].1);
    assert_eq!(rows[0].2, rows[2].2);
    assert_eq!(rows[0].3, rows[1].3);
    assert_ne!(rows[0].1, rows[2].1);
    assert_ne!(rows[0].3, rows[2].3);
    assert_eq!(rows[3].2, rows[4].2);
    assert_ne!(rows[3].2, 0, "Root paths must not become missing endpoints");
}

#[test]
fn endpoints_store_only_paths_without_the_first_slash() {
    for (input, expected) in [
        (
            "https://username:password@EXAMPLE.test:8443/Some%20Path?q=secret",
            Some("Some%20Path"),
        ),
        (
            "http://[2001:db8::1]:8080/path%3Fpart?token=secret",
            Some("path%3Fpart"),
        ),
        ("https://example.test?token=secret", Some("")),
        ("https://example.test//kept///path", Some("/kept///path")),
        ("/relative/path?token=secret", None),
    ] {
        let uri: http::Uri = input.parse().unwrap();
        assert_eq!(request_endpoint(&uri).as_deref(), expected, "{input}");
    }
    let path = format!("/{}", "segment/".repeat(500));
    let uri = format!("https://example.test{path}?token=secret")
        .parse()
        .unwrap();
    assert_eq!(
        request_endpoint(&uri).unwrap(),
        path.strip_prefix('/').unwrap()
    );
}

#[tokio::test]
async fn existing_history_without_endpoints_still_loads_and_accepts_new_requests() {
    let fixture = Fixture::new();
    let timestamp = now_ms();
    let id = timestamp * 1000;
    // Match the old on-disk JSON schema: no endpoint key, not even a null value.
    let old_record = serde_json::to_vec(&serde_json::json!({
        "id": id,
        "timestamp": timestamp,
        "domain": "old.example.test",
        "client": "192.0.2.10",
        "blocked": true,
    }))
    .unwrap();
    {
        let database = Database::create(fixture.database()).unwrap();
        let tx = database.begin_write().unwrap();
        tx.open_table(META).unwrap().insert("version", 1).unwrap();
        tx.open_table(META).unwrap().insert("privacy", 0).unwrap();
        tx.open_table(LEGACY_REQUESTS)
            .unwrap()
            .insert(id, old_record.as_slice())
            .unwrap();
        tx.commit().unwrap();
    }
    let store = HistoryStore::start(fixture.database(), enabled(StatisticsPrivacy::Full)).await;
    let data = snapshot(&store).await;
    assert_eq!(data.requests.len(), 1);
    assert_eq!(data.requests[0].domain.as_deref(), Some("old.example.test"));
    assert!(data.requests[0].endpoint.is_none());
    store.request(&request_uri("new.example.test"), client(), false);
    let data = snapshot(&store).await;
    assert_eq!(data.requests.len(), 2);
    assert_eq!(data.requests[0].endpoint.as_deref(), Some("private-path"));
    assert_eq!(data.totals.blocked_requests, 1);
    assert_eq!(data.totals.proxied_requests, 1);
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn legacy_endpoints_migrate_once_without_losing_paths_or_privacy() {
    for (version, privacy) in [1, 2].into_iter().flat_map(|version| {
        [StatisticsPrivacy::Full, StatisticsPrivacy::HideDomains].map(|privacy| (version, privacy))
    }) {
        let fixture = Fixture::new();
        let timestamp = now_ms();
        let first_id = timestamp * 1000;
        let examples = [
            ("google.com", "google.com/204", "204"),
            ("google.com", "google.com/", ""),
            ("google.com", "google.com//kept///path", "/kept///path"),
            ("google.com", "google.com/google.com/204", "google.com/204"),
            ("[2001:db8::1]", "[2001:db8::1]:8443/a%2Fb", "a%2Fb"),
        ];
        {
            let database = Database::create(fixture.database()).unwrap();
            let tx = database.begin_write().unwrap();
            tx.open_table(META)
                .unwrap()
                .insert("version", version)
                .unwrap();
            tx.open_table(META).unwrap().insert("privacy", 0).unwrap();
            for (index, (domain, endpoint, path)) in examples.iter().enumerate() {
                let id = first_id + index as u64;
                let record = serde_json::to_vec(&serde_json::json!({
                    "id": id,
                    "timestamp": timestamp,
                    "domain": domain,
                    "endpoint": if version == 1 { endpoint } else { path },
                    "client": "192.0.2.10",
                    "blocked": index % 2 == 0,
                }))
                .unwrap();
                tx.open_table(LEGACY_REQUESTS)
                    .unwrap()
                    .insert(id, record.as_slice())
                    .unwrap();
            }
            tx.commit().unwrap();
        }
        let config = enabled(privacy);
        let store = HistoryStore::start(fixture.database(), config.clone()).await;
        assert!(store.status().error.is_none());
        let data = snapshot(&store).await;
        assert_eq!(data.totals.blocked_requests, 3);
        assert_eq!(data.totals.proxied_requests, 2);
        for (index, (domain, _, path)) in examples.iter().enumerate() {
            let record = data
                .requests
                .iter()
                .find(|record| record.id == first_id + index as u64)
                .unwrap();
            assert_eq!(record.timestamp, timestamp);
            assert_eq!(
                record.domain.as_deref(),
                (privacy == StatisticsPrivacy::Full).then_some(*domain)
            );
            assert_eq!(
                record.endpoint.as_deref(),
                (privacy == StatisticsPrivacy::Full).then_some(*path)
            );
        }
        let new_uri = "https://google.com/google.com/new".parse().unwrap();
        store.request(&new_uri, client(), false);
        store.shutdown().await.unwrap();
        {
            let database = Database::open(fixture.database()).unwrap();
            let tx = database.begin_read().unwrap();
            assert!(matches!(
                tx.open_table(LEGACY_REQUESTS),
                Err(redb::TableError::TableDoesNotExist(_))
            ));
            assert_eq!(
                tx.open_table(META)
                    .unwrap()
                    .get("version")
                    .unwrap()
                    .unwrap()
                    .value(),
                DATABASE_VERSION
            );
            let table = tx.open_table(REQUESTS).unwrap();
            let stored = table.get(first_id).unwrap().unwrap().value();
            let record = DictionaryReader::open(&tx)
                .unwrap()
                .record(first_id, stored)
                .unwrap();
            assert_eq!(
                record.endpoint.as_deref(),
                (privacy == StatisticsPrivacy::Full).then_some("204")
            );
        }
        // A valid path can itself start with a hostname. Reopening must not
        // mistake it for another legacy authority and strip it a second time.
        let store = HistoryStore::start(fixture.database(), config).await;
        let data = snapshot(&store).await;
        assert_eq!(
            data.requests[0].endpoint.as_deref(),
            (privacy == StatisticsPrivacy::Full).then_some("google.com/new")
        );
        let record = data
            .requests
            .iter()
            .find(|record| record.id == first_id + 3)
            .unwrap();
        assert_eq!(
            record.endpoint.as_deref(),
            (privacy == StatisticsPrivacy::Full).then_some("google.com/204")
        );
        store.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn live_subscribers_receive_committed_batches_without_polling() {
    let fixture = Fixture::new();
    let store = HistoryStore::start(fixture.database(), enabled(StatisticsPrivacy::Full)).await;
    let mut updates = store.subscribe();
    updates.borrow_and_update();
    store.request(&request_uri("allowed.example.test"), client(), false);
    store.request(&request_uri("blocked.example.test"), client(), true);
    store.modified();

    // No query is used to force a flush: the normal batching timer wakes viewers.
    tokio::time::timeout(Duration::from_secs(10), updates.changed())
        .await
        .unwrap()
        .unwrap();
    let data = store
        .query_committed(HistoryQuery::default())
        .await
        .unwrap();
    assert_eq!(data.totals.proxied_requests, 1);
    assert_eq!(data.totals.blocked_requests, 1);
    assert_eq!(data.totals.modified_responses, 1);
    assert_eq!(data.requests.len(), 2);
    // Reading a snapshot must not trigger another update loop.
    assert!(!updates.has_changed().unwrap());
    store.shutdown().await.unwrap();
    assert!(updates.changed().await.is_err());
}

#[tokio::test]
async fn live_subscribers_see_privacy_changes_clears_and_disabled_history() {
    let fixture = Fixture::new();
    let store = HistoryStore::start(fixture.database(), enabled(StatisticsPrivacy::Full)).await;
    store.request(&request_uri("private.example.test"), client(), true);
    snapshot(&store).await;
    let mut updates = store.subscribe();
    updates.borrow_and_update();

    store
        .configure(enabled(StatisticsPrivacy::HideDomainsAndClients))
        .await
        .unwrap();
    assert!(updates.has_changed().unwrap());
    updates.borrow_and_update();
    let data = store
        .query_committed(HistoryQuery::default())
        .await
        .unwrap();
    assert!(data.requests[0].domain.is_none());
    assert!(data.requests[0].endpoint.is_none());
    assert!(data.requests[0].client.is_none());
    assert!(data.top_domains.is_empty());
    assert!(data.top_clients.is_empty());

    store.clear().await.unwrap();
    assert!(updates.has_changed().unwrap());
    updates.borrow_and_update();
    let data = store
        .query_committed(HistoryQuery::default())
        .await
        .unwrap();
    assert_eq!(data.totals.blocked_requests, 0);
    assert!(data.requests.is_empty());

    store.configure(StatisticsConfig::default()).await.unwrap();
    assert!(updates.has_changed().unwrap());
    assert!(
        !store
            .query_committed(HistoryQuery::default())
            .await
            .unwrap()
            .status
            .active
    );
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn disabled_and_anonymous_do_not_create_databases_or_retroactively_collect() {
    for config in [
        StatisticsConfig::default(),
        enabled(StatisticsPrivacy::Anonymous),
    ] {
        let fixture = Fixture::new();
        let store = HistoryStore::start(fixture.database(), config).await;
        store.request(&request_uri("private.example.test"), client(), true);
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
async fn requests_survive_restart_with_endpoints_but_without_queries_or_credentials() {
    let fixture = Fixture::new();
    let config = enabled(StatisticsPrivacy::Full);
    let store = HistoryStore::start(fixture.database(), config.clone()).await;
    let uri: http::Uri =
        "https://user:password@EXAMPLE.test:443/private-account?secret=do-not-store"
            .parse()
            .unwrap();
    store.request(&uri, client(), true);
    store.request(&request_uri("allowed.example.test"), client(), false);
    store.modified();
    store.shutdown().await.unwrap();
    let store = HistoryStore::start(fixture.database(), config).await;
    let data = snapshot(&store).await;
    assert_eq!(data.totals.blocked_requests, 1);
    assert_eq!(data.totals.proxied_requests, 1);
    assert_eq!(data.totals.modified_responses, 1);
    assert_eq!(data.requests[1].domain.as_deref(), Some("example.test"));
    assert_eq!(
        data.requests[1].endpoint.as_deref(),
        Some("private-account")
    );
    assert_eq!(data.requests[1].client.as_deref(), Some("192.0.2.10"));
    assert_eq!(data.top_blocked_domains, vec![("example.test".into(), 1)]);
    store.shutdown().await.unwrap();
    let bytes = std::fs::read(fixture.database()).unwrap();
    let text = String::from_utf8_lossy(&bytes);
    assert!(text.contains("private-account"));
    assert!(!text.contains("example.test:443/private-account"));
    assert!(!text.contains("do-not-store"));
    assert!(!text.contains("user:password"));
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
        store.request(&request_uri("private.example.test"), client(), true);
        store
            .configure(enabled(StatisticsPrivacy::Full))
            .await
            .unwrap();
        let data = snapshot(&store).await;
        assert_eq!(data.requests.len(), 1);
        assert!(data.requests[0].domain.is_none());
        assert!(data.requests[0].endpoint.is_none());
        assert_eq!(
            data.requests[0].client.is_none(),
            privacy == StatisticsPrivacy::HideDomainsAndClients
        );
        store.shutdown().await.unwrap();
        let bytes = std::fs::read(fixture.database()).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("private.example.test"));
        assert!(!text.contains("private-path"));
        assert!(!text.contains("do-not-store"));
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
        store.request(&request_uri("private.example.test"), client(), true);
        // The pending record must also be covered by this transition.
        store.configure(enabled(privacy)).await.unwrap();
        store
            .configure(enabled(StatisticsPrivacy::Full))
            .await
            .unwrap();
        let data = snapshot(&store).await;
        assert_eq!(data.requests.len(), 1);
        assert!(data.requests[0].domain.is_none());
        assert!(data.requests[0].endpoint.is_none());
        assert_eq!(
            data.requests[0].client.is_none(),
            privacy >= StatisticsPrivacy::HideDomainsAndClients
        );
        store.shutdown().await.unwrap();
        let database = Database::open(fixture.database()).unwrap();
        let tx = database.begin_read().unwrap();
        assert_dictionaries(
            &tx,
            [0, 0, u64::from(privacy == StatisticsPrivacy::HideDomains)],
        );
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
            &request_uri(&format!("host-{i}.example.test")),
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
                endpoint: None,
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
    let database = Database::open(fixture.database()).unwrap();
    let tx = database.begin_read().unwrap();
    assert_dictionaries(&tx, [99, 1, 1]);
}

#[tokio::test]
async fn expiring_last_references_removes_values_and_indexes() {
    let fixture = Fixture::new();
    let mut config = enabled(StatisticsPrivacy::Full);
    config.retention_days = 3;
    let store = HistoryStore::start(fixture.database(), config.clone()).await;
    let generation = store.policy.read().unwrap().generation;
    for domain in ["first.test", "second.test"] {
        store
            .sender
            .send(Command::Event(
                generation,
                Event::Request(RequestRecord {
                    id: 0,
                    timestamp: now_ms() - 2 * DAY_MS,
                    domain: Some(domain.into()),
                    endpoint: Some("same-path".into()),
                    client: Some(client().to_string()),
                    blocked: false,
                }),
            ))
            .unwrap();
    }
    assert_eq!(snapshot(&store).await.status.stored_requests, 2);
    config.retention_days = 1;
    store.configure(config.clone()).await.unwrap();
    assert_eq!(snapshot(&store).await.status.stored_requests, 0);
    store.shutdown().await.unwrap();
    {
        let database = Database::open(fixture.database()).unwrap();
        assert_dictionaries(&database.begin_read().unwrap(), [0, 0, 0]);
    }
    // Reusing identifiers after they expire must create valid references again.
    let store = HistoryStore::start(fixture.database(), config).await;
    let uri = "https://first.test/same-path".parse().unwrap();
    store.request(&uri, client(), true);
    assert_eq!(snapshot(&store).await.totals.blocked_requests, 1);
    store.shutdown().await.unwrap();
    let database = Database::open(fixture.database()).unwrap();
    assert_dictionaries(&database.begin_read().unwrap(), [1, 1, 1]);
}

#[tokio::test]
async fn invalid_legacy_rows_leave_the_original_database_version_and_records_intact() {
    let fixture = Fixture::new();
    {
        let database = Database::create(fixture.database()).unwrap();
        let tx = database.begin_write().unwrap();
        tx.open_table(META).unwrap().insert("version", 1).unwrap();
        tx.open_table(LEGACY_REQUESTS)
            .unwrap()
            .insert(1, b"invalid JSON".as_slice())
            .unwrap();
        tx.commit().unwrap();
    }
    let store = HistoryStore::start(fixture.database(), enabled(StatisticsPrivacy::Full)).await;
    assert!(store.status().error.is_some());
    store.shutdown().await.unwrap();
    let database = Database::open(fixture.database()).unwrap();
    let tx = database.begin_read().unwrap();
    assert_eq!(
        tx.open_table(META)
            .unwrap()
            .get("version")
            .unwrap()
            .unwrap()
            .value(),
        1
    );
    assert_eq!(
        tx.open_table(LEGACY_REQUESTS)
            .unwrap()
            .get(1)
            .unwrap()
            .unwrap()
            .value(),
        b"invalid JSON"
    );
    assert!(matches!(
        tx.open_table(REQUESTS),
        Err(redb::TableError::TableDoesNotExist(_))
    ));
}

#[tokio::test]
async fn clear_and_disable_do_not_replay_queued_records() {
    let fixture = Fixture::new();
    let config = enabled(StatisticsPrivacy::Full);
    let store = HistoryStore::start(fixture.database(), config.clone()).await;
    for _ in 0..100 {
        store.request(&request_uri("old.example.test"), client(), true);
    }
    store.clear().await.unwrap();
    assert!(snapshot(&store).await.requests.is_empty());
    store.configure(StatisticsConfig::default()).await.unwrap();
    store.request(&request_uri("disabled.example.test"), client(), false);
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
    stats.record_request(&request_uri("example.test"), client(), true);
    assert_eq!(stats.get_serialized().blocked_requests, 1);
    history.clear().await.unwrap();
    assert!(history.status().error.is_none());
    stats.record_request(&request_uri("example.test"), client(), true);
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
            let request_stats = stats.for_request(uri.host(), client());
            assert!(!request_stats.should_collect());
            request_stats.record_request(&uri, client(), true);
            request_stats.increment_modified_responses();
            // The history collector independently enforces the same policy.
            history.request(&uri, client(), true);
        }
        let data = stats.get_serialized();
        assert_eq!(data.blocked_requests, 0);
        assert_eq!(data.modified_responses, 0);
        assert!(data.top_clients.is_empty());
        assert!(snapshot(&history).await.requests.is_empty());
        for domain in ["private.test", "sub.example.test", "example.test.evil.test"] {
            assert!(stats.for_request(Some(domain), client()).should_collect());
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

#[tokio::test]
async fn excluded_clients_skip_all_collection_with_or_without_persistence() {
    let ipv6: IpAddr = "2001:db8::10".parse().unwrap();
    for persistent in [false, true] {
        let fixture = Fixture::new();
        let config = StatisticsConfig {
            enabled: persistent,
            privacy: StatisticsPrivacy::Full,
            excluded_clients: vec![client(), ipv6],
            ..Default::default()
        };
        let history = HistoryStore::start(fixture.database(), config).await;
        let stats = Statistics {
            history: Some(history.clone()),
            ..Statistics::new()
        };
        let uri = request_uri("example.test");
        for address in [client(), ipv6] {
            let request_stats = stats.for_request(uri.host(), address);
            assert!(!request_stats.should_collect());
            request_stats.record_request(&uri, address, true);
            request_stats.increment_modified_responses();
            // Also enforce exclusions when callers use the collectors directly.
            stats.record_request(&uri, address, false);
            history.request(&uri, address, true);
        }
        let data = stats.get_serialized();
        assert_eq!(data.blocked_requests, 0);
        assert_eq!(data.proxied_requests, 0);
        assert_eq!(data.modified_responses, 0);
        assert!(data.top_clients.is_empty());
        assert!(snapshot(&history).await.requests.is_empty());
        let allowed: IpAddr = "192.0.2.11".parse().unwrap();
        let request_stats = stats.for_request(uri.host(), allowed);
        assert!(request_stats.should_collect());
        request_stats.record_request(&uri, allowed, true);
        request_stats.increment_modified_responses();
        assert_eq!(stats.get_serialized().blocked_requests, 1);
        assert_eq!(stats.get_serialized().modified_responses, 1);
        assert_eq!(
            snapshot(&history).await.requests.len(),
            usize::from(persistent)
        );
        history.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn client_names_update_existing_history_and_live_counts_without_merging_clients() {
    let other: IpAddr = "2001:db8::11".parse().unwrap();
    for persistent in [false, true] {
        let fixture = Fixture::new();
        let mut config = StatisticsConfig {
            enabled: persistent,
            privacy: StatisticsPrivacy::Full,
            client_names: BTreeMap::from([(client(), " Living room ".into())]),
            ..Default::default()
        };
        let history = HistoryStore::start(fixture.database(), config.clone()).await;
        let stats = Statistics {
            history: Some(history.clone()),
            ..Statistics::new()
        };
        stats.record_request(&request_uri("example.test"), client(), true);
        stats.record_request(&request_uri("example.test"), other, false);
        assert_eq!(
            stats.get_serialized().client_names[&client().to_string()],
            "Living room"
        );
        config.client_names.insert(client(), "TV".into());
        config.client_names.insert(other, "TV".into());
        stats.configure_history(config.clone()).await.unwrap();
        let live = stats.get_serialized();
        assert_eq!(live.proxied_requests, 1);
        assert_eq!(live.blocked_requests, 1);
        assert_eq!(live.top_clients.len(), 2);
        assert_eq!(live.client_names.len(), 2);
        assert!(live.client_names.values().all(|name| name == "TV"));
        if persistent {
            let data = snapshot(&history).await;
            assert_eq!(data.requests.len(), 2);
            assert_eq!(data.client_names, live.client_names);
            assert_eq!(data.top_clients.len(), 2);
            config.privacy = StatisticsPrivacy::HideDomainsAndClients;
            stats.configure_history(config.clone()).await.unwrap();
            assert!(stats.get_serialized().client_names.is_empty());
            assert!(snapshot(&history).await.client_names.is_empty());
            config.privacy = StatisticsPrivacy::Full;
            stats.configure_history(config.clone()).await.unwrap();
            assert!(snapshot(&history).await.client_names.is_empty());
            assert!(stats.get_serialized().client_names.is_empty());
        }
        history.clear().await.unwrap();
        assert_eq!(history.config().client_names, config.client_names);
        stats.record_request(&request_uri("new.test"), client(), false);
        assert_eq!(
            stats.get_serialized().client_names[&client().to_string()],
            "TV"
        );
        history.shutdown().await.unwrap();
    }
}

#[test]
fn client_settings_round_trip_and_reject_invalid_addresses_or_names() {
    let config = StatisticsConfig {
        excluded_clients: vec![client(), "2001:db8::10".parse().unwrap()],
        client_names: BTreeMap::from([(client(), "Living room TV".into())]),
        ..Default::default()
    };
    config.validate().unwrap();
    let text = toml::to_string(&config).unwrap();
    assert_eq!(toml::from_str::<StatisticsConfig>(&text).unwrap(), config);
    let json = serde_json::to_string(&config).unwrap();
    assert_eq!(
        serde_json::from_str::<StatisticsConfig>(&json).unwrap(),
        config
    );
    for json in [
        r#"{"excluded_clients":["not-an-ip"]}"#,
        r#"{"excluded_clients":["192.0.2.0/24"]}"#,
        r#"{"client_names":{"example.com":"TV"}}"#,
    ] {
        assert!(serde_json::from_str::<StatisticsConfig>(json).is_err());
    }
    for name in [" ".into(), "a".repeat(65), "TV\nsecond line".into()] {
        assert!(StatisticsConfig {
            client_names: BTreeMap::from([(client(), name)]),
            ..Default::default()
        }
        .validate()
        .is_err());
    }
    assert!(StatisticsConfig {
        excluded_clients: vec![client(); 1001],
        ..Default::default()
    }
    .validate()
    .is_err());
}

#[tokio::test]
async fn migration_reduces_storage_for_repeated_identifiers() {
    let fixture = Fixture::new();
    let timestamp = now_ms();
    let count = 10_000_u64;
    let original_bytes;
    {
        let mut database = Database::create(fixture.database()).unwrap();
        let tx = database.begin_write().unwrap();
        tx.open_table(META).unwrap().insert("version", 2).unwrap();
        {
            let mut requests = tx.open_table(LEGACY_REQUESTS).unwrap();
            for offset in 0..count {
                let id = timestamp * 1000 + offset;
                let record = RequestRecord {
                    id,
                    timestamp,
                    domain: Some(format!("host-{}.example.test", offset % 100)),
                    endpoint: Some(format!("api/v1/resources/{}/status", offset % 20)),
                    client: Some(format!("192.0.2.{}", offset % 10 + 1)),
                    blocked: offset % 2 == 0,
                };
                requests
                    .insert(id, serde_json::to_vec(&record).unwrap().as_slice())
                    .unwrap();
            }
        }
        tx.commit().unwrap();
        database.compact().unwrap();
        original_bytes = std::fs::metadata(fixture.database()).unwrap().len();
    }
    let store = HistoryStore::start(fixture.database(), enabled(StatisticsPrivacy::Full)).await;
    let data = snapshot(&store).await;
    assert_eq!(data.totals.blocked_requests, count / 2);
    assert_eq!(data.totals.proxied_requests, count / 2);
    let mut expected: Vec<_> = (0..100)
        .map(|i| (format!("host-{i}.example.test"), 100))
        .collect();
    expected.sort_unstable();
    expected.truncate(50);
    assert_eq!(data.top_domains, expected);
    store.shutdown().await.unwrap();
    let mut database = Database::open(fixture.database()).unwrap();
    database.compact().unwrap();
    assert_dictionaries(&database.begin_read().unwrap(), [100, 20, 10]);
    let compact_bytes = std::fs::metadata(fixture.database()).unwrap().len();
    eprintln!("10,000 requests: JSON {original_bytes} bytes; dictionaries {compact_bytes} bytes");
    assert!(compact_bytes < original_bytes);
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
        updates: watch::channel(()).1,
    };
    store.request(&request_uri("private.example.test"), client(), true);
    store.request(&request_uri("private.example.test"), client(), true);
    assert_eq!(store.status().dropped_events, 1);
    let Command::Event(_, Event::Request(record)) = receiver.try_recv().unwrap() else {
        panic!("expected a request");
    };
    assert!(record.domain.is_none());
    assert!(record.endpoint.is_none());
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
        updates: watch::channel(()).0,
    };
    worker.open().unwrap();
    let event = || {
        Event::Request(RequestRecord {
            id: 0,
            timestamp: now_ms(),
            domain: Some("example.test".into()),
            endpoint: Some("".into()),
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
