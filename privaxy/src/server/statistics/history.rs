//! Opt-in, bounded request history. Only the worker thread touches redb.
//! Request tasks redact identifiers before trying a non-blocking channel send.
use crate::configuration::{StatisticsConfig, StatisticsPrivacy};
use portable_atomic::{AtomicU64, Ordering};
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs::OpenOptions,
    net::IpAddr,
    path::PathBuf,
    sync::{mpsc, Arc, Mutex, RwLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{oneshot, watch};

mod storage;
use storage::{Dictionaries, DictionaryReader, LEGACY_REQUESTS, REQUESTS};
const MODIFIED: TableDefinition<u64, u64> = TableDefinition::new("modified_hours_v1");
const META: TableDefinition<&str, u64> = TableDefinition::new("metadata");
// v1: JSON with full endpoints; v2: JSON with compact paths; v3: ID references.
const DATABASE_VERSION: u64 = 3;
const FLUSH_INTERVAL: Duration = Duration::from_secs(5);
const QUEUE_CAPACITY: usize = 4096;
const BATCH_SIZE: usize = 512;
const HOUR_MS: u64 = 3_600_000;
const DAY_MS: u64 = 24 * HOUR_MS;
type StoreResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Debug, Clone, Default, Serialize)]
pub struct HistoryStatus {
    pub active: bool,
    pub error: Option<String>,
    pub dropped_events: u64,
    pub stored_requests: u64,
    pub database_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestRecord {
    pub id: u64,
    pub timestamp: u64,
    pub domain: Option<String>,
    /// Path without its first slash; absent in older saved records.
    #[serde(default)]
    pub endpoint: Option<String>,
    pub client: Option<String>,
    pub blocked: bool,
}

impl RequestRecord {
    fn migrate_endpoint(&mut self) -> bool {
        let Some(endpoint) = &mut self.endpoint else {
            return false;
        };
        *endpoint = endpoint
            .split_once('/')
            .map(|(_, path)| path)
            .unwrap_or_default()
            .to_owned();
        true
    }

    fn redact(&mut self, privacy: StatisticsPrivacy) {
        if privacy >= StatisticsPrivacy::HideDomains {
            self.domain = None;
            self.endpoint = None;
        }
        if privacy >= StatisticsPrivacy::HideDomainsAndClients {
            self.client = None;
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct Counts {
    pub proxied_requests: u64,
    pub blocked_requests: u64,
    pub modified_responses: u64,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HistoryQuery {
    pub hours: Option<u16>,
    pub before: Option<u64>,
    pub blocked: Option<bool>,
    pub limit: Option<usize>,
}

impl HistoryQuery {
    pub fn validate(&self) -> Result<(), String> {
        if self.hours.is_some_and(|v| v == 0 || v > 365 * 24) {
            return Err("History window must be between 1 and 8760 hours".into());
        }
        if self.limit.is_some_and(|v| v == 0 || v > 200) {
            return Err("History page size must be between 1 and 200".into());
        }
        Ok(())
    }
}

#[derive(Debug, Default, Serialize)]
pub struct HistorySnapshot {
    pub status: HistoryStatus,
    pub totals: Counts,
    pub hourly: Vec<(u64, Counts)>,
    pub top_domains: Vec<(String, u64)>,
    pub top_blocked_domains: Vec<(String, u64)>,
    pub top_clients: Vec<(String, u64)>,
    pub client_names: BTreeMap<String, String>,
    pub requests: Vec<RequestRecord>,
    pub next_before: Option<u64>,
}

#[derive(Debug, Default)]
struct Policy {
    config: StatisticsConfig,
    generation: u64,
    stopped: bool,
    exclusions: Vec<wildmatch::WildMatch>,
    excluded_clients: HashSet<IpAddr>,
}

enum Event {
    Request(RequestRecord),
    Modified(u64),
}

enum Command {
    Event(u64, Event),
    Configure(StatisticsConfig, u64, oneshot::Sender<Result<(), String>>),
    Query {
        query: HistoryQuery,
        flush: bool,
        reply: oneshot::Sender<Result<HistorySnapshot, String>>,
    },
    Clear(u64, oneshot::Sender<Result<(), String>>),
    Shutdown(oneshot::Sender<Result<(), String>>),
}

#[derive(Debug, Clone)]
pub struct HistoryStore {
    sender: mpsc::SyncSender<Command>,
    policy: Arc<RwLock<Policy>>,
    status: Arc<Mutex<HistoryStatus>>,
    dropped: Arc<AtomicU64>,
    operations: Arc<tokio::sync::Mutex<()>>,
    updates: watch::Receiver<()>,
}

impl HistoryStore {
    pub async fn start(path: PathBuf, config: StatisticsConfig) -> Self {
        let (sender, receiver) = mpsc::sync_channel(QUEUE_CAPACITY);
        let (updates, subscriber) = watch::channel(());
        let status = Arc::new(Mutex::new(HistoryStatus::default()));
        let dropped = Arc::new(AtomicU64::new(0));
        let store = Self {
            sender,
            policy: Arc::new(RwLock::new(Policy::default())),
            status: status.clone(),
            dropped: dropped.clone(),
            operations: Arc::new(tokio::sync::Mutex::new(())),
            updates: subscriber,
        };
        let worker = Worker {
            path,
            database: None,
            config: StatisticsConfig::default(),
            generation: 0,
            pending: Vec::new(),
            status,
            dropped,
            last_id: 0,
            last_flush: Instant::now(),
            last_compaction: Instant::now(),
            last_prune: Instant::now() - Duration::from_secs(60),
            updates,
        };
        match std::thread::Builder::new()
            .name("statistics".into())
            .spawn(move || worker.run(receiver))
        {
            Ok(_) => {
                if let Err(error) = store.configure(config).await {
                    log::error!("Persistent statistics unavailable: {error}");
                    store.status.lock().unwrap().error = Some(error);
                }
            }
            Err(error) => store.status.lock().unwrap().error = Some(error.to_string()),
        }
        store
    }

    pub fn config(&self) -> StatisticsConfig {
        self.policy.read().unwrap().config.clone()
    }

    pub fn session_privacy(&self) -> StatisticsPrivacy {
        let policy = self.policy.read().unwrap();
        if policy.config.enabled {
            policy.config.privacy
        } else {
            StatisticsPrivacy::Full
        }
    }

    pub fn status(&self) -> HistoryStatus {
        let mut status = self.status.lock().unwrap().clone();
        status.dropped_events = self.dropped.load(Ordering::Relaxed);
        status
    }

    pub fn is_excluded(&self, domain: Option<&str>, client: IpAddr) -> bool {
        let policy = self.policy.read().unwrap();
        policy.excluded_clients.contains(&client)
            || domain.is_some_and(|domain| matches_exclusion(&policy, domain))
    }

    pub(crate) fn client_names<'a>(
        &self,
        clients: impl Iterator<Item = &'a str>,
    ) -> BTreeMap<String, String> {
        client_names(&self.policy.read().unwrap().config, clients)
    }

    pub fn request(&self, uri: &http::Uri, client: IpAddr, blocked: bool) {
        let domain = uri.host();
        let policy = self.policy.read().unwrap();
        if policy.stopped
            || !policy.config.persists()
            || policy.excluded_clients.contains(&client)
            || domain.is_some_and(|domain| matches_exclusion(&policy, domain))
        {
            return;
        }
        // Strip query strings and credentials before queueing. Endpoint paths
        // follow domain privacy; hidden values cannot be restored by changing
        // settings. Headers and bodies never enter the statistics queue.
        let record = RequestRecord {
            id: 0,
            timestamp: now_ms(),
            domain: if policy.config.privacy == StatisticsPrivacy::Full {
                domain
                    .filter(|v| v.len() <= 253)
                    .map(|v| v.trim_end_matches('.').to_ascii_lowercase())
            } else {
                None
            },
            endpoint: (policy.config.privacy == StatisticsPrivacy::Full)
                .then(|| request_endpoint(uri))
                .flatten(),
            client: (policy.config.privacy < StatisticsPrivacy::HideDomainsAndClients)
                .then(|| client.to_string()),
            blocked,
        };
        self.enqueue(&policy, Event::Request(record));
    }

    pub fn modified(&self) {
        let policy = self.policy.read().unwrap();
        if !policy.stopped && policy.config.persists() {
            self.enqueue(&policy, Event::Modified(now_ms()));
        }
    }

    fn enqueue(&self, policy: &Policy, event: Event) {
        if self
            .sender
            .try_send(Command::Event(policy.generation, event))
            .is_err()
        {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    async fn send<T>(
        &self,
        command: Command,
        reply: oneshot::Receiver<Result<T, String>>,
    ) -> Result<T, String> {
        let sender = self.sender.clone();
        tokio::task::spawn_blocking(move || sender.send(command))
            .await
            .map_err(|e| e.to_string())?
            .map_err(|_| "Statistics worker has stopped".to_string())?;
        reply
            .await
            .map_err(|_| "Statistics worker has stopped".to_string())?
    }

    pub async fn configure(&self, config: StatisticsConfig) -> Result<(), String> {
        config.validate()?;
        let _operation = self.operations.lock().await;
        // Pause collection across the command boundary. An old queued event
        // cannot reintroduce identifiers after a privacy change or clear.
        let generation = {
            let mut policy = self.policy.write().unwrap();
            policy.stopped = true;
            policy.generation += 1;
            policy.generation
        };
        let (tx, rx) = oneshot::channel();
        let result = self
            .send(Command::Configure(config.clone(), generation, tx), rx)
            .await;
        let mut policy = self.policy.write().unwrap();
        policy.exclusions = config
            .excluded_domains
            .iter()
            .map(|pattern| {
                wildmatch::WildMatch::new(
                    &pattern.trim().trim_end_matches('.').to_ascii_lowercase(),
                )
            })
            .collect();
        policy.excluded_clients = config.excluded_clients.iter().copied().collect();
        policy.config = config;
        policy.stopped = result.is_err();
        result
    }

    pub async fn query(&self, query: HistoryQuery) -> Result<HistorySnapshot, String> {
        self.read(query, true).await
    }

    /// Live subscribers read committed batches without forcing extra disk writes.
    pub(crate) async fn query_committed(
        &self,
        query: HistoryQuery,
    ) -> Result<HistorySnapshot, String> {
        self.read(query, false).await
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<()> {
        self.updates.clone()
    }

    async fn read(&self, query: HistoryQuery, flush: bool) -> Result<HistorySnapshot, String> {
        query.validate()?;
        let (tx, rx) = oneshot::channel();
        self.send(
            Command::Query {
                query,
                flush,
                reply: tx,
            },
            rx,
        )
        .await
    }

    pub async fn clear(&self) -> Result<(), String> {
        let _operation = self.operations.lock().await;
        let generation = {
            let mut policy = self.policy.write().unwrap();
            policy.stopped = true;
            policy.generation += 1;
            policy.generation
        };
        let (tx, rx) = oneshot::channel();
        let result = self.send(Command::Clear(generation, tx), rx).await;
        self.policy.write().unwrap().stopped = result.is_err();
        result
    }

    pub async fn shutdown(&self) -> Result<(), String> {
        let _operation = self.operations.lock().await;
        self.policy.write().unwrap().stopped = true;
        let (tx, rx) = oneshot::channel();
        self.send(Command::Shutdown(tx), rx).await
    }
}

struct Worker {
    path: PathBuf,
    database: Option<Database>,
    config: StatisticsConfig,
    generation: u64,
    pending: Vec<Event>,
    status: Arc<Mutex<HistoryStatus>>,
    dropped: Arc<AtomicU64>,
    last_id: u64,
    last_flush: Instant,
    last_compaction: Instant,
    last_prune: Instant,
    updates: watch::Sender<()>,
}

impl Worker {
    fn run(mut self, receiver: mpsc::Receiver<Command>) {
        loop {
            match receiver.recv_timeout(Duration::from_secs(1)) {
                Ok(Command::Event(generation, event)) => {
                    if generation == self.generation
                        && self.database.is_some()
                        && self.status.lock().unwrap().error.is_none()
                    {
                        self.pending.push(event);
                    } else {
                        self.dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Ok(Command::Configure(config, generation, reply)) => {
                    let result = self
                        .configure(config, generation)
                        .map_err(|e| e.to_string());
                    self.report(&result);
                    self.updates.send_replace(());
                    let _ = reply.send(result);
                }
                Ok(Command::Query {
                    query,
                    flush,
                    reply,
                }) => {
                    let result = (if flush { self.flush() } else { Ok(()) })
                        .and_then(|()| self.query(query))
                        .map_err(|e| e.to_string());
                    if let Err(ref error) = result {
                        self.fail(error.clone());
                    }
                    let _ = reply.send(result);
                }
                Ok(Command::Clear(generation, reply)) => {
                    self.generation = generation;
                    self.pending.clear();
                    self.database = None;
                    let result = self.clear().map_err(|e| e.to_string());
                    self.report(&result);
                    self.updates.send_replace(());
                    let _ = reply.send(result);
                }
                Ok(Command::Shutdown(reply)) => {
                    let result = self.flush().map_err(|e| e.to_string());
                    self.database = None;
                    let _ = reply.send(result);
                    break;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    if let Err(error) = self.flush() {
                        self.fail(error.to_string());
                    }
                    break;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
            if self.pending.len() >= BATCH_SIZE || self.last_flush.elapsed() >= FLUSH_INTERVAL {
                if let Err(error) = self.flush() {
                    self.fail(error.to_string());
                }
                self.last_flush = Instant::now();
            }
        }
    }

    fn fail(&mut self, error: String) {
        let mut status = self.status.lock().unwrap();
        let changed = status.active || status.error.as_ref() != Some(&error);
        if status.error.as_ref() != Some(&error) {
            log::error!("Persistent statistics paused: {error}");
        }
        status.active = false;
        status.error = Some(error);
        self.dropped
            .fetch_add(self.pending.len() as u64, Ordering::Relaxed);
        self.pending.clear();
        if changed {
            self.updates.send_replace(());
        }
    }

    fn report(&mut self, result: &Result<(), String>) {
        if let Err(error) = result {
            self.fail(error.clone());
        }
    }

    fn configure(&mut self, config: StatisticsConfig, generation: u64) -> StoreResult<()> {
        // Previously accepted events still have the previous privacy policy.
        // Flush them before redacting the database with the new policy.
        let flush_result = self.flush();
        if let Err(ref error) = flush_result {
            self.fail(error.to_string());
        }
        self.pending.clear();
        self.database = None;
        self.config = config;
        self.generation = generation;
        *self.status.lock().unwrap() = HistoryStatus::default();
        if !self.config.persists() {
            // Disabled stores are never opened. Anonymous mode may redact a
            // database from an earlier opt-in, but never creates one or records
            // new events. Switching back cannot recover old identifiers.
            if self.config.enabled && self.path.exists() {
                self.open()?;
                self.database = None;
                self.status.lock().unwrap().active = false;
            }
            return flush_result;
        }
        self.open()?;
        self.last_prune = Instant::now() - Duration::from_secs(60);
        self.flush()?;
        Ok(())
    }

    fn open(&mut self) -> StoreResult<()> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&self.path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        let mut database = Database::builder()
            .set_cache_size(8 * 1024 * 1024)
            .create_file(file)?;
        let tx = database.begin_write()?;
        let (version, redact) = {
            let mut meta = tx.open_table(META)?;
            let version = meta
                .get("version")?
                .map(|v| v.value())
                .unwrap_or(DATABASE_VERSION);
            if !(1..=DATABASE_VERSION).contains(&version) {
                return Err("Unsupported statistics database version".into());
            }
            let previous = meta.get("privacy")?.map(|v| v.value()).unwrap_or(0);
            meta.insert("version", DATABASE_VERSION)?;
            meta.insert("privacy", self.config.privacy as u64)?;
            (version, (self.config.privacy as u64) > previous)
        };
        {
            let mut dictionaries = Dictionaries::open(&tx)?;
            let mut requests = tx.open_table(REQUESTS)?;
            if version < DATABASE_VERSION {
                let legacy = tx.open_table(LEGACY_REQUESTS)?;
                for entry in legacy.iter()? {
                    let (id, bytes) = entry?;
                    let mut record: RequestRecord = serde_json::from_slice(bytes.value())?;
                    if version == 1 {
                        record.migrate_endpoint();
                    }
                    record.redact(self.config.privacy);
                    requests.insert(id.value(), dictionaries.intern(&record)?)?;
                }
            } else if redact {
                let ids = requests
                    .iter()?
                    .map(|r| r.map(|(id, _)| id.value()))
                    .collect::<Result<Vec<_>, _>>()?;
                for id in ids {
                    let mut record = requests.get(id)?.unwrap().value();
                    if self.config.privacy >= StatisticsPrivacy::HideDomains {
                        record.1 = 0;
                        record.2 = 0;
                    }
                    if self.config.privacy >= StatisticsPrivacy::HideDomainsAndClients {
                        record.3 = 0;
                    }
                    requests.insert(id, record)?;
                }
                dictionaries.redact(self.config.privacy)?;
            }
            self.last_id = requests.last()?.map(|(id, _)| id.value()).unwrap_or(0);
        }
        if version < DATABASE_VERSION {
            tx.delete_table(LEGACY_REQUESTS)?;
        }
        tx.open_table(MODIFIED)?;
        tx.commit()?;
        if redact || version < DATABASE_VERSION {
            database.compact()?;
        }
        self.database = Some(database);
        self.status.lock().unwrap().active = true;
        Ok(())
    }

    fn clear(&mut self) -> StoreResult<()> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        self.last_id = 0;
        self.dropped.store(0, Ordering::Relaxed);
        *self.status.lock().unwrap() = HistoryStatus::default();
        if self.config.persists() {
            self.open()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> StoreResult<()> {
        if self.status.lock().unwrap().error.is_some() {
            return Ok(());
        }
        let Some(database) = self.database.as_ref() else {
            return Ok(());
        };
        let prune = self.last_prune.elapsed() >= Duration::from_secs(60);
        if self.pending.is_empty() && !prune {
            return Ok(());
        }
        let now = now_ms();
        let cutoff = now.saturating_sub(u64::from(self.config.retention_days) * DAY_MS);
        let tx = database.begin_write()?;
        let stored;
        {
            let mut requests = tx.open_table(REQUESTS)?;
            let mut modified = tx.open_table(MODIFIED)?;
            let mut dictionaries = Dictionaries::open(&tx)?;
            for event in &self.pending {
                match event {
                    Event::Request(record) => {
                        // Microsecond-sized IDs remain ordered and fit exactly in
                        // JavaScript numbers for centuries. The clock may step back.
                        self.last_id = (record.timestamp * 1000).max(self.last_id + 1);
                        requests.insert(self.last_id, dictionaries.intern(record)?)?;
                    }
                    Event::Modified(timestamp) => {
                        let hour = timestamp / HOUR_MS * HOUR_MS;
                        let count = modified.get(hour)?.map(|v| v.value()).unwrap_or(0) + 1;
                        modified.insert(hour, count)?;
                    }
                }
            }
            // Also inspect stored timestamps: an NTP clock adjustment must not
            // make old rows immortal merely because their IDs are monotonic.
            if prune {
                for entry in requests.extract_if(|_, record| record.0 < cutoff)? {
                    let (_, record) = entry?;
                    dictionaries.release(record.value())?;
                }
            }
            while requests.len()? > u64::from(self.config.max_entries) {
                let first = requests.first()?.unwrap().0.value();
                let record = requests.remove(first)?.unwrap().value();
                dictionaries.release(record)?;
            }
            modified.retain(|hour, _| hour + HOUR_MS > cutoff)?;
            stored = requests.len()?;
        }
        tx.commit()?;
        self.pending.clear();
        if prune {
            self.last_prune = Instant::now();
        }
        if self.last_compaction.elapsed() >= Duration::from_secs(3600) {
            self.database.as_mut().unwrap().compact()?;
            self.last_compaction = Instant::now();
        }
        let mut status = self.status.lock().unwrap();
        status.stored_requests = stored;
        status.database_bytes = std::fs::metadata(&self.path)?.len();
        self.updates.send_replace(());
        Ok(())
    }

    fn query(&self, query: HistoryQuery) -> StoreResult<HistorySnapshot> {
        let mut snapshot = HistorySnapshot {
            status: self.status.lock().unwrap().clone(),
            ..Default::default()
        };
        snapshot.status.dropped_events = self.dropped.load(Ordering::Relaxed);
        let Some(database) = &self.database else {
            return Ok(snapshot);
        };
        // A failed privacy transition must never reveal previously collected data.
        if snapshot.status.error.is_some() {
            return Ok(snapshot);
        }
        let hours = query
            .hours
            .unwrap_or(24)
            .min(self.config.retention_days * 24);
        let cutoff = (now_ms() / HOUR_MS * HOUR_MS).saturating_sub(u64::from(hours - 1) * HOUR_MS);
        let limit = query.limit.unwrap_or(50);
        let tx = database.begin_read()?;
        let table = tx.open_table(REQUESTS)?;
        let dictionaries = DictionaryReader::open(&tx)?;
        let mut hourly: BTreeMap<u64, Counts> = BTreeMap::new();
        let mut domains = HashMap::new();
        let mut blocked_domains = HashMap::new();
        let mut clients = HashMap::new();
        // IDs are at least timestamp * 1000, even after a clock correction,
        // so this range skips older pages without losing in-window records.
        for entry in table.range(cutoff.saturating_mul(1000)..)?.rev() {
            let (id, record) = entry?;
            let id = id.value();
            let record = record.value();
            if record.0 < cutoff {
                continue;
            }
            let counts = hourly.entry(record.0 / HOUR_MS * HOUR_MS).or_default();
            if record.4 {
                snapshot.totals.blocked_requests += 1;
                counts.blocked_requests += 1;
            } else {
                snapshot.totals.proxied_requests += 1;
                counts.proxied_requests += 1;
            }
            if record.1 != 0 {
                *domains.entry(record.1).or_insert(0) += 1;
                if record.4 {
                    *blocked_domains.entry(record.1).or_insert(0) += 1;
                }
            }
            if record.3 != 0 {
                *clients.entry(record.3).or_insert(0) += 1;
            }
            if query.before.is_none_or(|before| id < before)
                && query.blocked.is_none_or(|v| record.4 == v)
            {
                if snapshot.requests.len() < limit {
                    snapshot.requests.push(dictionaries.record(id, record)?);
                } else if snapshot.next_before.is_none() {
                    snapshot.next_before = snapshot.requests.last().map(|r| r.id);
                }
            }
        }
        for entry in tx
            .open_table(MODIFIED)?
            .range(cutoff / HOUR_MS * HOUR_MS..)?
        {
            let (hour, value) = entry?;
            let count = value.value();
            snapshot.totals.modified_responses += count;
            hourly.entry(hour.value()).or_default().modified_responses = count;
        }
        snapshot.hourly = hourly.into_iter().collect();
        snapshot.top_domains = storage::top_entries(&dictionaries.domains, domains)?;
        snapshot.top_blocked_domains =
            storage::top_entries(&dictionaries.domains, blocked_domains)?;
        snapshot.top_clients = storage::top_entries(&dictionaries.clients, clients)?;
        snapshot.client_names = client_names(
            &self.config,
            snapshot
                .top_clients
                .iter()
                .map(|(client, _)| client.as_str())
                .chain(
                    snapshot
                        .requests
                        .iter()
                        .filter_map(|record| record.client.as_deref()),
                ),
        );
        Ok(snapshot)
    }
}

fn client_names<'a>(
    config: &StatisticsConfig,
    clients: impl Iterator<Item = &'a str>,
) -> BTreeMap<String, String> {
    clients
        .filter_map(|client| {
            let address = client.parse::<IpAddr>().ok()?;
            config
                .client_names
                .get(&address)
                .map(|name| (client.to_owned(), name.trim().to_owned()))
        })
        .collect()
}

fn request_endpoint(uri: &http::Uri) -> Option<String> {
    uri.authority()?;
    // Remove exactly one separator so //path still renders as //path. Query
    // strings, credentials, and the authority never enter this field.
    Some(
        uri.path()
            .strip_prefix('/')
            .unwrap_or(uri.path())
            .to_owned(),
    )
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn matches_exclusion(policy: &Policy, domain: &str) -> bool {
    if policy.exclusions.is_empty() {
        return false;
    }
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    policy
        .exclusions
        .iter()
        .any(|pattern| pattern.matches(&domain))
}

#[cfg(test)]
mod tests;
