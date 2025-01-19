use serde::Serialize;
use std::{
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use dashmap::DashMap;

const ENTRIES_PER_STATISTICS_TABLE: u8 = 50;
const METRICS_CLEANUP_INTERVAL: Duration = Duration::from_secs(300); // 5 minutes

#[derive(Debug, Serialize)]
pub struct SerializableStatistics {
    // Core statistics
    pub proxied_requests: u64,
    pub blocked_requests: u64,
    pub modified_responses: u64,
    #[serde(with = "tuple_vec_map")]
    pub top_blocked_paths: Vec<(String, u64)>,
    #[serde(with = "tuple_vec_map")]
    pub top_clients: Vec<(String, u64)>,
    
    // Performance metrics
    pub performance: PerformanceMetrics,
    pub filter_stats: FilterMetrics,
    pub memory_stats: MemoryMetrics,
}

#[derive(Debug, Serialize, Default)]
pub struct PerformanceMetrics {
    pub avg_request_time_ms: f64,
    pub avg_network_time_ms: f64,
    pub avg_cosmetic_time_ms: f64,
    pub avg_update_time_ms: f64,
    pub requests_per_second: f64,
}

#[derive(Debug, Serialize, Default)]
pub struct FilterMetrics {
    pub active_filters: u64,
    pub filter_updates: u64,
    pub failed_updates: u64,
    pub last_update_time_ms: u64,
}

#[derive(Debug, Serialize, Default)]
pub struct MemoryMetrics {
    pub current_usage_mb: u64,
    pub peak_usage_mb: u64,
    pub filter_memory_mb: u64,
}

#[derive(Debug, Clone)]
pub struct Statistics {
    // Core metrics using atomic counters for better performance
    pub proxied_requests: Arc<std::sync::atomic::AtomicU64>,
    pub blocked_requests: Arc<std::sync::atomic::AtomicU64>,
    pub modified_responses: Arc<std::sync::atomic::AtomicU64>,
    
    // Use DashMap for concurrent access without locks
    pub top_blocked_paths: Arc<DashMap<String, u64>>,
    pub top_clients: Arc<DashMap<IpAddr, u64>>,
    
    // Performance tracking
    start_time: Arc<Instant>,
    last_cleanup: Arc<std::sync::atomic::AtomicU64>,
    
    // Additional metrics from blocker
    blocker_metrics: Option<Arc<std::sync::atomic::AtomicU64>>,
}

impl Default for Statistics {
    fn default() -> Self {
        Self::new()
    }
}

impl Statistics {
    pub fn new() -> Self {
        let stats = Self {
            proxied_requests: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            blocked_requests: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            modified_responses: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            top_blocked_paths: Arc::new(DashMap::new()),
            top_clients: Arc::new(DashMap::new()),
            start_time: Arc::new(Instant::now()),
            last_cleanup: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            blocker_metrics: None,
        };

        // Start cleanup task
        let stats_clone = stats.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(METRICS_CLEANUP_INTERVAL).await;
                stats_clone.cleanup_old_metrics();
            }
        });

        stats
    }

    pub fn increment_top_blocked_paths(&self, path_: String) {
        self.top_blocked_paths
            .entry(path_)
            .and_modify(|count| *count += 1)
            .or_insert(1);
    }

    pub fn increment_top_clients(&self, client: IpAddr) {
        self.top_clients
            .entry(client)
            .and_modify(|count| *count += 1)
            .or_insert(1);
    }

    pub fn increment_proxied_requests(&self) -> u64 {
        self.proxied_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1
    }

    pub fn increment_blocked_requests(&self) -> u64 {
        self.blocked_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1
    }

    pub fn increment_modified_responses(&self) -> u64 {
        self.modified_responses.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1
    }

    fn cleanup_old_metrics(&self) {
        // Keep only top entries for paths and clients
        let mut paths: Vec<_> = self.top_blocked_paths
            .iter()
            .map(|r| (r.key().clone(), *r.value()))
            .collect();
        paths.sort_by(|a, b| b.1.cmp(&a.1));
        paths.truncate(ENTRIES_PER_STATISTICS_TABLE as usize);
        
        self.top_blocked_paths.clear();
        for (path, count) in paths {
            self.top_blocked_paths.insert(path, count);
        }

        let mut clients: Vec<_> = self.top_clients
            .iter()
            .map(|r| (*r.key(), *r.value()))
            .collect();
        clients.sort_by(|a, b| b.1.cmp(&a.1));
        clients.truncate(ENTRIES_PER_STATISTICS_TABLE as usize);
        
        self.top_clients.clear();
        for (client, count) in clients {
            self.top_clients.insert(client, count);
        }

        // Update last cleanup time
        self.last_cleanup.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    pub fn get_serialized(&self) -> SerializableStatistics {
        let uptime = self.start_time.elapsed();
        let total_requests = self.proxied_requests.load(std::sync::atomic::Ordering::Relaxed);
        let requests_per_second = if uptime.as_secs() > 0 {
            total_requests as f64 / uptime.as_secs() as f64
        } else {
            0.0
        };

        // Get blocker metrics if available
        let (perf_metrics, filter_metrics, memory_metrics) = if let Some(metrics) = &self.blocker_metrics {
            let value = metrics.load(std::sync::atomic::Ordering::Relaxed);
            (
                PerformanceMetrics {
                    avg_request_time_ms: value as f64,
                    avg_network_time_ms: value as f64,
                    avg_cosmetic_time_ms: value as f64,
                    avg_update_time_ms: value as f64,
                    requests_per_second,
                },
                FilterMetrics {
                    active_filters: value,
                    filter_updates: value,
                    failed_updates: 0,
                    last_update_time_ms: self.last_cleanup.load(std::sync::atomic::Ordering::Relaxed),
                },
                MemoryMetrics {
                    current_usage_mb: value,
                    peak_usage_mb: value,
                    filter_memory_mb: value,
                },
            )
        } else {
            (
                PerformanceMetrics {
                    avg_request_time_ms: 0.0,
                    avg_network_time_ms: 0.0,
                    avg_cosmetic_time_ms: 0.0,
                    avg_update_time_ms: 0.0,
                    requests_per_second,
                },
                FilterMetrics {
                    active_filters: 0,
                    filter_updates: 0,
                    failed_updates: 0,
                    last_update_time_ms: self.last_cleanup.load(std::sync::atomic::Ordering::Relaxed),
                },
                MemoryMetrics {
                    current_usage_mb: 0,
                    peak_usage_mb: 0,
                    filter_memory_mb: 0,
                },
            )
        };

        SerializableStatistics {
            proxied_requests: self.proxied_requests.load(std::sync::atomic::Ordering::Relaxed),
            blocked_requests: self.blocked_requests.load(std::sync::atomic::Ordering::Relaxed),
            modified_responses: self.modified_responses.load(std::sync::atomic::Ordering::Relaxed),
            top_blocked_paths: {
                let mut paths: Vec<_> = self.top_blocked_paths
                    .iter()
                    .map(|r| (r.key().clone(), *r.value()))
                    .collect();
                paths.sort_by(|a, b| b.1.cmp(&a.1));
                paths.truncate(ENTRIES_PER_STATISTICS_TABLE as usize);
                paths
            },
            top_clients: {
                let mut clients: Vec<_> = self.top_clients
                    .iter()
                    .map(|r| (r.key().to_string(), *r.value()))
                    .collect();
                clients.sort_by(|a, b| b.1.cmp(&a.1));
                clients.truncate(ENTRIES_PER_STATISTICS_TABLE as usize);
                clients
            },
            performance: perf_metrics,
            filter_stats: filter_metrics,
            memory_stats: memory_metrics,
        }
    }

    pub fn set_blocker_metrics(&mut self, metrics: Arc<std::sync::atomic::AtomicU64>) {
        self.blocker_metrics = Some(metrics);
    }
}
