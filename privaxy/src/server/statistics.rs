use crate::configuration::{StatisticsConfig, StatisticsPrivacy};
use portable_atomic::{AtomicU64, Ordering};
use serde::Serialize;
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{atomic::AtomicBool, Arc, Mutex},
};
use uluru::LRUCache;

pub mod history;

const ENTRIES_PER_STATISTICS_TABLE: usize = 50;

#[derive(Debug, Serialize)]
pub struct SerializableStatistics {
    pub proxied_requests: u64,
    pub blocked_requests: u64,
    pub modified_responses: u64,
    #[serde(with = "tuple_vec_map")]
    pub top_blocked_paths: Vec<(String, u64)>,
    #[serde(with = "tuple_vec_map")]
    pub top_clients: Vec<(String, u64)>,
}

#[derive(Debug, Clone)]
pub struct Statistics {
    pub proxied_requests: Arc<AtomicU64>,
    pub blocked_requests: Arc<AtomicU64>,
    pub modified_responses: Arc<AtomicU64>,
    pub top_blocked_paths: Arc<Mutex<LRUCache<(String, u64), 1_000>>>,
    pub top_clients: Arc<Mutex<HashMap<IpAddr, u64>>>,
    pub history: Option<history::HistoryStore>,
    collect: bool,
    response_modified: Option<Arc<AtomicBool>>,
}

impl Default for Statistics {
    fn default() -> Self {
        Self::new()
    }
}

impl Statistics {
    pub fn new() -> Self {
        Self {
            proxied_requests: Arc::new(AtomicU64::new(0)),
            blocked_requests: Arc::new(AtomicU64::new(0)),
            modified_responses: Arc::new(AtomicU64::new(0)),
            top_blocked_paths: Arc::new(Mutex::new(LRUCache::default())),
            top_clients: Arc::new(Mutex::new(HashMap::new())),
            history: None,
            collect: true,
            response_modified: None,
        }
    }

    pub async fn with_history(config: StatisticsConfig) -> Self {
        let path = crate::configuration::get_config_file().with_file_name("statistics.redb");
        Self {
            history: Some(history::HistoryStore::start(path, config).await),
            ..Self::new()
        }
    }

    pub async fn configure_history(&self, config: StatisticsConfig) -> Result<(), String> {
        let Some(history) = &self.history else {
            return Ok(());
        };
        if config == history.config() && history.status().error.is_none() {
            return Ok(());
        }
        let result = history.configure(config).await;
        // Discard session identifiers too. Lowering privacy later must not
        // resurrect identifiers from before the change.
        self.top_blocked_paths.lock().unwrap().clear();
        self.top_clients.lock().unwrap().clear();
        result
    }

    /// Carry one domain's collection decision through response rewriting too.
    /// Statistics exclusions never change interception or blocking decisions.
    pub fn for_domain(&self, domain: Option<&str>) -> Self {
        Self {
            collect: self.collect && !self.history.as_ref().is_some_and(|h| h.is_excluded(domain)),
            ..self.clone()
        }
    }

    pub fn should_collect(&self) -> bool {
        self.collect
    }

    pub(crate) fn for_response(&self) -> Self {
        Self {
            response_modified: Some(Arc::new(AtomicBool::new(false))),
            ..self.clone()
        }
    }

    pub fn record_request(&self, domain: Option<&str>, client: IpAddr, blocked: bool) {
        if !self.collect || self.history.as_ref().is_some_and(|h| h.is_excluded(domain)) {
            return;
        }
        let privacy = self
            .history
            .as_ref()
            .map(|h| h.session_privacy())
            .unwrap_or(StatisticsPrivacy::Full);
        if privacy < StatisticsPrivacy::HideDomainsAndClients {
            self.increment_top_clients(client);
        }
        if blocked {
            self.increment_blocked_requests();
            if privacy == StatisticsPrivacy::Full {
                if let Some(domain) = domain {
                    self.increment_top_blocked_paths(domain.to_ascii_lowercase());
                }
            }
        } else {
            self.increment_proxied_requests();
        }
        if let Some(history) = &self.history {
            history.request(domain, client, blocked);
        }
    }

    pub fn increment_top_blocked_paths(&self, path_: String) {
        let mut top_blocked_paths = self.top_blocked_paths.lock().unwrap();

        match top_blocked_paths.find(|(path, _count)| path == &path_) {
            Some((_path, count)) => {
                *count += 1;
            }
            None => {
                top_blocked_paths.insert((path_, 1));
            }
        }
    }

    pub fn increment_top_clients(&self, client: IpAddr) {
        let mut clients = self.top_clients.lock().unwrap();
        if clients.len() < 1000 || clients.contains_key(&client) {
            *clients.entry(client).or_insert(0) += 1;
        }
    }

    pub fn increment_proxied_requests(&self) -> u64 {
        self.proxied_requests.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn increment_blocked_requests(&self) -> u64 {
        self.blocked_requests.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn increment_modified_responses(&self) -> u64 {
        if !self.collect
            || self
                .response_modified
                .as_ref()
                .is_some_and(|modified| modified.swap(true, Ordering::Relaxed))
        {
            return self.modified_responses.load(Ordering::Relaxed);
        }
        if let Some(history) = &self.history {
            history.modified();
        }
        self.modified_responses.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn get_serialized(&self) -> SerializableStatistics {
        let mut serialized = SerializableStatistics {
            proxied_requests: self.proxied_requests.load(Ordering::Relaxed),
            blocked_requests: self.blocked_requests.load(Ordering::Relaxed),
            modified_responses: self.modified_responses.load(Ordering::Relaxed),
            top_blocked_paths: {
                let top_blocked_paths = self.top_blocked_paths.lock().unwrap();
                let mut top_blocked_paths = top_blocked_paths.iter().cloned().collect::<Vec<_>>();
                top_blocked_paths
                    .sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                top_blocked_paths.truncate(ENTRIES_PER_STATISTICS_TABLE);

                top_blocked_paths
            },
            top_clients: {
                let top_clients = self.top_clients.lock().unwrap();
                let mut top_clients = top_clients
                    .iter()
                    .map(|(ip, count)| (ip.to_string(), *count))
                    .collect::<Vec<_>>();
                top_clients.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                top_clients.truncate(ENTRIES_PER_STATISTICS_TABLE);

                top_clients
            },
        };
        if let Some(history) = &self.history {
            let privacy = history.session_privacy();
            if privacy >= StatisticsPrivacy::HideDomains {
                serialized.top_blocked_paths.clear();
            }
            if privacy >= StatisticsPrivacy::HideDomainsAndClients {
                serialized.top_clients.clear();
            }
        }
        serialized
    }
}
