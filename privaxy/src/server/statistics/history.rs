//! Opt-in, bounded request history. Only the worker thread touches redb.
//! Request tasks redact identifiers before trying a non-blocking channel send.
use crate::configuration::{StatisticsConfig, StatisticsPrivacy};
use portable_atomic::{AtomicU64, Ordering};
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    fs::OpenOptions,
    net::IpAddr,
    path::PathBuf,
    sync::{mpsc, Arc, Mutex, RwLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::oneshot;

const REQUESTS: TableDefinition<u64, &[u8]> = TableDefinition::new("requests_v1");
const MODIFIED: TableDefinition<u64, u64> = TableDefinition::new("modified_hours_v1");
const META: TableDefinition<&str, u64> = TableDefinition::new("metadata");
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
    pub client: Option<String>,
    pub blocked: bool,
}

impl RequestRecord {
    fn redact(&mut self, privacy: StatisticsPrivacy) {
        if privacy >= StatisticsPrivacy::HideDomains {
            self.domain = None;
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

#[derive(Debug, Default, Deserialize)]
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
    pub requests: Vec<RequestRecord>,
    pub next_before: Option<u64>,
}

#[derive(Debug, Default)]
struct Policy {
    config: StatisticsConfig,
    generation: u64,
    stopped: bool,
    exclusions: Vec<wildmatch::WildMatch>,
}

enum Event {
    Request(RequestRecord),
    Modified(u64),
}

enum Command {
    Event(u64, Event),
    Configure(StatisticsConfig, u64, oneshot::Sender<Result<(), String>>),
    Query(
        HistoryQuery,
        oneshot::Sender<Result<HistorySnapshot, String>>,
    ),
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
}

impl HistoryStore {
    pub async fn start(path: PathBuf, config: StatisticsConfig) -> Self {
        let (sender, receiver) = mpsc::sync_channel(QUEUE_CAPACITY);
        let status = Arc::new(Mutex::new(HistoryStatus::default()));
        let dropped = Arc::new(AtomicU64::new(0));
        let store = Self {
            sender,
            policy: Arc::new(RwLock::new(Policy::default())),
            status: status.clone(),
            dropped: dropped.clone(),
            operations: Arc::new(tokio::sync::Mutex::new(())),
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

    pub fn is_excluded(&self, domain: Option<&str>) -> bool {
        let policy = self.policy.read().unwrap();
        domain.is_some_and(|domain| matches_exclusion(&policy, domain))
    }

    pub fn request(&self, domain: Option<&str>, client: IpAddr, blocked: bool) {
        let policy = self.policy.read().unwrap();
        if policy.stopped
            || !policy.config.persists()
            || domain.is_some_and(|domain| matches_exclusion(&policy, domain))
        {
            return;
        }
        // No URL, path, query string, headers, request body, or client/domain hash
        // is ever queued. Hidden values cannot be restored by changing settings.
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
        policy.config = config;
        policy.stopped = result.is_err();
        result
    }

    pub async fn query(&self, query: HistoryQuery) -> Result<HistorySnapshot, String> {
        query.validate()?;
        let (tx, rx) = oneshot::channel();
        self.send(Command::Query(query, tx), rx).await
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
                    let _ = reply.send(result);
                }
                Ok(Command::Query(query, reply)) => {
                    let result = self
                        .flush()
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
        if status.error.as_ref() != Some(&error) {
            log::error!("Persistent statistics paused: {error}");
        }
        status.active = false;
        status.error = Some(error);
        self.dropped
            .fetch_add(self.pending.len() as u64, Ordering::Relaxed);
        self.pending.clear();
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
        let redact;
        {
            let mut meta = tx.open_table(META)?;
            if meta.get("version")?.is_some_and(|v| v.value() != 1) {
                return Err("Unsupported statistics database version".into());
            }
            meta.insert("version", 1)?;
            let previous = meta.get("privacy")?.map(|v| v.value()).unwrap_or(0);
            redact = (self.config.privacy as u64) > previous;
            meta.insert("privacy", self.config.privacy as u64)?;
        }
        {
            let mut table = tx.open_table(REQUESTS)?;
            self.last_id = table.last()?.map(|(id, _)| id.value()).unwrap_or(0);
            if redact {
                let ids = table
                    .iter()?
                    .map(|r| r.map(|(k, _)| k.value()))
                    .collect::<Result<Vec<_>, _>>()?;
                for id in ids {
                    let mut record: RequestRecord =
                        serde_json::from_slice(table.get(id)?.unwrap().value())?;
                    record.redact(self.config.privacy);
                    table.insert(id, serde_json::to_vec(&record)?.as_slice())?;
                }
            }
        }
        tx.open_table(MODIFIED)?;
        tx.commit()?;
        if redact {
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
            for event in &self.pending {
                match event {
                    Event::Request(record) => {
                        let mut record = record.clone();
                        // Microsecond-sized IDs remain ordered and fit exactly in
                        // JavaScript numbers for centuries. The clock may step back.
                        self.last_id = (record.timestamp * 1000).max(self.last_id + 1);
                        record.id = self.last_id;
                        requests.insert(record.id, serde_json::to_vec(&record)?.as_slice())?;
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
                let mut invalid_row = false;
                requests.retain(|_, bytes| {
                    match serde_json::from_slice::<RequestRecord>(bytes) {
                        Ok(record) => record.timestamp >= cutoff,
                        Err(_) => {
                            invalid_row = true;
                            true
                        }
                    }
                })?;
                if invalid_row {
                    return Err("Invalid record in statistics database; recording paused".into());
                }
            }
            while requests.len()? > u64::from(self.config.max_entries) {
                let first = requests.first()?.unwrap().0.value();
                requests.remove(first)?;
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
        let mut hourly: BTreeMap<u64, Counts> = BTreeMap::new();
        let mut domains = HashMap::new();
        let mut blocked_domains = HashMap::new();
        let mut clients = HashMap::new();
        // IDs are at least timestamp * 1000, even after a clock correction,
        // so this range skips older pages without losing in-window records.
        for entry in table.range(cutoff.saturating_mul(1000)..)?.rev() {
            let (_, bytes) = entry?;
            let record: RequestRecord = serde_json::from_slice(bytes.value())?;
            if record.timestamp < cutoff {
                continue;
            }
            let counts = hourly
                .entry(record.timestamp / HOUR_MS * HOUR_MS)
                .or_default();
            if record.blocked {
                snapshot.totals.blocked_requests += 1;
                counts.blocked_requests += 1;
            } else {
                snapshot.totals.proxied_requests += 1;
                counts.proxied_requests += 1;
            }
            if let Some(ref domain) = record.domain {
                *domains.entry(domain.clone()).or_insert(0) += 1;
                if record.blocked {
                    *blocked_domains.entry(domain.clone()).or_insert(0) += 1;
                }
            }
            if let Some(ref client) = record.client {
                *clients.entry(client.clone()).or_insert(0) += 1;
            }
            if query.before.is_none_or(|id| record.id < id)
                && query.blocked.is_none_or(|v| record.blocked == v)
            {
                if snapshot.requests.len() < limit {
                    snapshot.requests.push(record);
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
        snapshot.top_domains = top_entries(domains);
        snapshot.top_blocked_domains = top_entries(blocked_domains);
        snapshot.top_clients = top_entries(clients);
        Ok(snapshot)
    }
}

fn top_entries(entries: HashMap<String, u64>) -> Vec<(String, u64)> {
    let mut entries: Vec<_> = entries.into_iter().collect();
    entries.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    entries.truncate(50);
    entries
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
