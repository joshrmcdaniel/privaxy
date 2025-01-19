use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use sysinfo::{System, Pid};
use tokio::time::{sleep, Duration};

/// Collects and manages various metrics about the application's performance and resource usage.
/// All metrics are collected and stored atomically to ensure thread safety.
#[derive(Debug, Clone)]
pub struct MetricsCollector {
    // Request metrics
    /// Total number of network requests processed
    pub network_requests: Arc<AtomicU64>,
    /// Total number of cosmetic filter requests processed
    pub cosmetic_requests: Arc<AtomicU64>,
    /// Total number of requests that were blocked
    pub blocked_requests: Arc<AtomicU64>,
    /// Exponential moving average of requests per second
    pub requests_per_second: Arc<AtomicU64>,
    
    // Processing time metrics (in nanoseconds)
    /// Total time spent processing network requests
    pub network_processing_time: Arc<AtomicU64>,
    /// Total time spent processing cosmetic filters
    pub cosmetic_processing_time: Arc<AtomicU64>,
    /// Total time spent updating the filter engine
    pub engine_update_time: Arc<AtomicU64>,
    /// Time taken by the last filter engine update
    pub last_update_time: Arc<AtomicU64>,
    
    // Filter metrics
    /// Number of active filters (updated when engine is updated)
    pub active_filters: Arc<AtomicU64>,
    /// Number of times the filter engine has been updated
    pub filter_updates: Arc<AtomicU64>,
    
    // Memory metrics (all values in KB)
    /// Peak memory usage of the process
    pub peak_memory_usage: Arc<AtomicU64>,
    /// Current memory usage of the process
    pub current_memory_usage: Arc<AtomicU64>,
    
    // Error metrics
    /// Number of failed request processing attempts
    pub failed_requests: Arc<AtomicU64>,
    /// Number of failed filter engine updates
    pub failed_updates: Arc<AtomicU64>,
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsCollector {
    /// Creates a new MetricsCollector and starts a background task to poll system metrics.
    /// The background task updates memory usage and calculates request rates using an
    /// exponential moving average for smoother values.
    pub fn new() -> Self {
        let collector = Self {
            network_requests: Arc::new(AtomicU64::new(0)),
            cosmetic_requests: Arc::new(AtomicU64::new(0)),
            blocked_requests: Arc::new(AtomicU64::new(0)),
            requests_per_second: Arc::new(AtomicU64::new(0)),
            network_processing_time: Arc::new(AtomicU64::new(0)),
            cosmetic_processing_time: Arc::new(AtomicU64::new(0)),
            engine_update_time: Arc::new(AtomicU64::new(0)),
            last_update_time: Arc::new(AtomicU64::new(0)),
            active_filters: Arc::new(AtomicU64::new(0)),
            filter_updates: Arc::new(AtomicU64::new(0)),
            peak_memory_usage: Arc::new(AtomicU64::new(0)),
            current_memory_usage: Arc::new(AtomicU64::new(0)),
            failed_requests: Arc::new(AtomicU64::new(0)),
            failed_updates: Arc::new(AtomicU64::new(0)),
        };

        // poll metrics in background
        let collector_clone = collector.clone();
        tokio::spawn(async move {
            let mut sys = System::new();
            let pid = Pid::from(std::process::id() as usize);

            loop {
                // update memory metrics
                sys.refresh_all();
                if let Some(process) = sys.process(pid) {
                    let used_mem = process.memory() / 1024; // send kbs
                    collector_clone.current_memory_usage.store(used_mem, Ordering::Relaxed);
                    
                    let peak = collector_clone.peak_memory_usage.load(Ordering::Relaxed);
                    if used_mem > peak {
                        collector_clone.peak_memory_usage.store(used_mem, Ordering::Relaxed);
                    }
                }

                let prev_network = collector_clone.network_requests.load(Ordering::Relaxed);
                let prev_cosmetic = collector_clone.cosmetic_requests.load(Ordering::Relaxed);
                
                sleep(Duration::from_secs(1)).await;
                
                let curr_network = collector_clone.network_requests.load(Ordering::Relaxed);
                let curr_cosmetic = collector_clone.cosmetic_requests.load(Ordering::Relaxed);
                
                let network_delta = curr_network.saturating_sub(prev_network);
                let cosmetic_delta = curr_cosmetic.saturating_sub(prev_cosmetic);
                let total_delta = network_delta + cosmetic_delta;
                
                // use exponential moving average for smoother rate
                let prev_rate = collector_clone.requests_per_second.load(Ordering::Relaxed);
                let alpha = 0.3;
                let new_rate = (alpha * total_delta as f64 + (1.0 - alpha) * prev_rate as f64) as u64;
                
                collector_clone.requests_per_second.store(new_rate, Ordering::Relaxed);
            }
        });

        collector
    }

    /// Gets performance metrics including average processing times and request rates.
    /// All time values are converted from nanoseconds to milliseconds.
    pub fn get_performance_metrics(&self) -> PerformanceMetrics {
        let network_requests = self.network_requests.load(Ordering::Relaxed);
        let cosmetic_requests = self.cosmetic_requests.load(Ordering::Relaxed);
        let total_requests = network_requests + cosmetic_requests;
        
        let network_time = self.network_processing_time.load(Ordering::Relaxed);
        let cosmetic_time = self.cosmetic_processing_time.load(Ordering::Relaxed);
        let update_time = self.engine_update_time.load(Ordering::Relaxed);

        let avg_network_time = if network_requests > 0 {
            (network_time as f64) / (network_requests as f64) / 1_000_000.0 // Convert ns to ms
        } else {
            0.0
        };

        let avg_cosmetic_time = if cosmetic_requests > 0 {
            (cosmetic_time as f64) / (cosmetic_requests as f64) / 1_000_000.0
        } else {
            0.0
        };

        let avg_update_time = if self.filter_updates.load(Ordering::Relaxed) > 0 {
            (update_time as f64) / (self.filter_updates.load(Ordering::Relaxed) as f64) / 1_000_000.0
        } else {
            0.0
        };

        let avg_request_time = if total_requests > 0 {
            ((network_time + cosmetic_time) as f64) / (total_requests as f64) / 1_000_000.0
        } else {
            0.0
        };
        
        // Get requests per second from the stored value
        let requests_per_second = self.requests_per_second.load(Ordering::Relaxed) as f64;

        PerformanceMetrics {
            avg_request_time_ms: avg_request_time,
            avg_network_time_ms: avg_network_time,
            avg_cosmetic_time_ms: avg_cosmetic_time,
            avg_update_time_ms: avg_update_time,
            requests_per_second,
        }
    }

    /// Gets filter metrics including counts of active filters and updates.
    pub fn get_filter_metrics(&self) -> FilterMetrics {
        FilterMetrics {
            active_filters: self.active_filters.load(Ordering::Relaxed),
            filter_updates: self.filter_updates.load(Ordering::Relaxed),
            failed_updates: self.failed_updates.load(Ordering::Relaxed),
            last_update_time_ms: (self.last_update_time.load(Ordering::Relaxed) as f64 / 1_000_000.0) as u64,
        }
    }

    /// Gets memory metrics in kilobytes (KB).
    pub fn get_memory_metrics(&self) -> MemoryMetrics {
        // Load all values atomically to ensure consistency
        let current = self.current_memory_usage.load(Ordering::SeqCst);
        let peak = self.peak_memory_usage.load(Ordering::SeqCst);
        let active_filters = self.active_filters.load(Ordering::SeqCst);

        // Values are already in KB
        MemoryMetrics {
            current_usage_kb: current,
            peak_usage_kb: peak,
            filter_memory_kb: active_filters,
        }
    }
}

/// Performance metrics for request processing and filter updates.
/// All time values are in milliseconds (ms).
#[derive(Debug, Serialize, Default)]
pub struct PerformanceMetrics {
    /// Average time to process a request (network + cosmetic)
    pub avg_request_time_ms: f64,
    /// Average time to process network requests
    pub avg_network_time_ms: f64,
    /// Average time to process cosmetic filters
    pub avg_cosmetic_time_ms: f64,
    /// Average time to update the filter engine
    pub avg_update_time_ms: f64,
    /// Exponential moving average of requests per second
    pub requests_per_second: f64,
}

/// Filter metrics tracking active filters and update statistics.
#[derive(Debug, Serialize, Default)]
pub struct FilterMetrics {
    /// Number of currently active filters
    pub active_filters: u64,
    /// Number of successful filter updates
    pub filter_updates: u64,
    /// Number of failed filter updates
    pub failed_updates: u64,
    /// Time taken for the last update in milliseconds
    pub last_update_time_ms: u64,
}

/// Memory usage metrics for the application.
/// All values are in kilobytes (KB).
#[derive(Debug, Serialize, Default)]
pub struct MemoryMetrics {
    /// Current memory usage of the process in KB
    pub current_usage_kb: u64,
    /// Peak memory usage of the process in KB
    pub peak_usage_kb: u64,
    /// Memory used by filter strings in KB
    pub filter_memory_kb: u64,
}
