use crate::blocker_utils::{
    build_resource_from_file_contents, read_redirectable_resource_mapping, read_template_resources,
};
use adblock::blocker::BlockerResult as AdblockerBlockerResult;
use adblock::lists::FilterSet;
use adblock::request::Request;
use adblock::resources::Resource;
use adblock::Engine;
use crossbeam_channel::{Receiver, Sender};
use include_dir::{include_dir, Dir};
use lazy_static::lazy_static;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;
use tokio::sync::oneshot;
use crate::metrics::MetricsCollector;

pub type AdblockRequestChannel = Sender<BlockerRequest>;

#[derive(Debug)]
pub struct BlockerStatistics {
    pub requests: RequestStats,
    pub performance: PerformanceStats,
    pub filters: FilterStats,
    pub memory: MemoryStats,
}

#[derive(Debug)]
pub struct RequestStats {
    pub network_total: u64,
    pub cosmetic_total: u64,
    pub blocked_total: u64,
    pub failed_total: u64,
}

#[derive(Debug)]
pub struct PerformanceStats {
    pub avg_network_time_ms: f64,
    pub avg_cosmetic_time_ms: f64,
    pub avg_update_time_ms: f64,
}

#[derive(Debug)]
pub struct FilterStats {
    pub active_count: u64,
    pub update_count: u64,
    pub failed_updates: u64,
}

#[derive(Debug)]
pub struct MemoryStats {
    pub current_usage_mb: u64,
    pub peak_usage_mb: u64,
}

#[derive(Debug, Clone)]
pub struct BlockingDisabledStore(pub Arc<RwLock<bool>>);

impl BlockingDisabledStore {
    pub fn is_enabled(&self) -> bool {
        !*self.0.read()
    }

    pub fn set(&self, enabled: bool) {
        *self.0.write() = !enabled
    }
}

#[derive(Debug)]
pub struct CosmeticRequest {
    pub(crate) url: String,
    pub(crate) ids: Vec<String>,
    pub(crate) classes: Vec<String>,
}

#[derive(Debug)]
pub struct NetworkUrl {
    url: String,
    referer: String,
}

#[derive(Debug)]
pub enum RequestKind {
    Url(NetworkUrl),
    Cosmetic(CosmeticRequest),
    ReplaceEngine(Vec<String>),
}

#[derive(Debug)]
pub enum BlockerResult {
    Network(adblock::blocker::BlockerResult),
    Cosmetic(CosmeticBlockerResult),
}

#[derive(Debug)]
pub struct CosmeticBlockerResult {
    pub hidden_selectors: Vec<String>,
    pub style_selectors: HashMap<String, Vec<String>>,
    pub injected_script: Option<String>,
}

pub struct BlockerRequest {
    pub(crate) kind: RequestKind,
    pub(crate) respond_to: oneshot::Sender<BlockerResult>,
}

lazy_static! {
    static ref ADBLOCKING_RESOURCES: Vec<Resource> = {
        let mut resources =
            read_template_resources(include_str!("../resources/vendor/ublock/scriptlets.js"));

        static WEB_ACCESSIBLE_RESOURCES: Dir = include_dir!(
            "$CARGO_MANIFEST_DIR/src/resources/vendor/ublock/web_accessible_resources/"
        );

        let resource_properties = read_redirectable_resource_mapping(include_str!(
            "../resources/vendor/ublock/redirect-resources.js"
        ));

        resources.extend(resource_properties.iter().filter_map(|resource_info| {
            WEB_ACCESSIBLE_RESOURCES
                .get_file(&resource_info.name)
                .map(|resource| build_resource_from_file_contents(resource.contents(), resource_info))
        }));

        resources
    };
}

pub struct Blocker {
    pub sender: Sender<BlockerRequest>,
    receiver: Receiver<BlockerRequest>,
    engine: Arc<RwLock<Engine>>,
    blocking_disabled: BlockingDisabledStore,
    metrics: Arc<MetricsCollector>,
}

impl Blocker {
    pub fn new(
        sender: Sender<BlockerRequest>,
        receiver: Receiver<BlockerRequest>,
        blocking_disabled: BlockingDisabledStore,
        metrics: Arc<MetricsCollector>,
    ) -> Self {
        Self {
            sender,
            receiver,
            engine: Arc::new(RwLock::new(Engine::new(true))),
            blocking_disabled,
            metrics,
        }
    }

    fn handle_cosmetic_request(&self, request: CosmeticRequest) -> CosmeticBlockerResult {
        let start = Instant::now();

        //  start cosmetic request time
        self.metrics.cosmetic_requests.fetch_add(1, Ordering::Relaxed);

        if !self.blocking_disabled.is_enabled() {
            self.metrics.cosmetic_processing_time.fetch_add(start.elapsed().as_nanos() as u64, Ordering::Relaxed);
            return CosmeticBlockerResult {
                hidden_selectors: Vec::new(),
                style_selectors: HashMap::new(),
                injected_script: None,
            };
        }

        let engine = self.engine.read();
        let url_specific_resources = engine.url_cosmetic_resources(&request.url);

        let mut hidden_selectors = Vec::new();
        if !url_specific_resources.generichide {
            let generic_selectors = engine.hidden_class_id_selectors(
                &request.classes,
                &request.ids,
                &url_specific_resources.exceptions,
            );
            hidden_selectors.extend(generic_selectors);
        }

        hidden_selectors.extend(url_specific_resources.hide_selectors);

        let result = CosmeticBlockerResult {
            hidden_selectors,
            style_selectors: {
                let mut map = HashMap::new();
                for selector in url_specific_resources.procedural_actions {
                    map.insert(selector, Vec::new());
                }
                map
            },
            injected_script: if !url_specific_resources.injected_script.is_empty() {
                Some(url_specific_resources.injected_script)
            } else {
                None
            },
        };

        self.metrics.cosmetic_processing_time.fetch_add(start.elapsed().as_nanos() as u64, Ordering::Relaxed);
        result
    }

    fn handle_network_request(&self, network_url: NetworkUrl) -> adblock::blocker::BlockerResult {
        let start = Instant::now();

        // start network request time
        self.metrics.network_requests.fetch_add(1, Ordering::Relaxed);
        
        if !self.blocking_disabled.is_enabled() {
            self.metrics.network_processing_time.fetch_add(start.elapsed().as_nanos() as u64, Ordering::Relaxed);
            return AdblockerBlockerResult {
                matched: false,
                important: false,
                redirect: None,
                exception: None,
                filter: None,
                rewritten_url: None,
            };
        }

        let engine = self.engine.read();
        let req = match Request::new(
            network_url.url.as_str(),
            network_url.referer.as_str(),
            "other",
        ) {
            Ok(req) => req,
            Err(_) => {
                self.metrics.network_processing_time.fetch_add(start.elapsed().as_nanos() as u64, Ordering::Relaxed);
                self.metrics.failed_requests.fetch_add(1, Ordering::Relaxed);
                return AdblockerBlockerResult {
                    matched: false,
                    important: false,
                    redirect: None,
                    exception: None,
                    filter: None,
                    rewritten_url: None,
                };
            }
        };

        let result = engine.check_network_request(&req);
        if result.matched {
            self.metrics.blocked_requests.fetch_add(1, Ordering::Relaxed);
        }

        self.metrics.network_processing_time.fetch_add(start.elapsed().as_nanos() as u64, Ordering::Relaxed);
        result
    }

    fn update_engine(&self, filters: Vec<String>) {
        let start = Instant::now();
        
        // Create new engine
        let mut filter_set = FilterSet::new(true);
        let mut total_size = 0;
        for filter in &filters {
            filter_set.add_filter_list(filter, adblock::lists::ParseOptions::default());
            total_size += filter.as_bytes().len();
        }

        let mut new_engine = Engine::from_filter_set(filter_set, true);
        new_engine.use_resources(ADBLOCKING_RESOURCES.clone());

        //drop old engine before replacing, and take ownership of old engine and drop it
        {
            let mut engine_write = self.engine.write();
            let old_engine = std::mem::replace(&mut *engine_write, new_engine);
            drop(old_engine);
        }

        drop(filters);

        self.metrics.filter_updates.fetch_add(1, Ordering::Relaxed);
        let elapsed = start.elapsed().as_nanos() as u64;
        self.metrics.engine_update_time.fetch_add(elapsed, Ordering::Relaxed);
        self.metrics.last_update_time.store(elapsed, Ordering::Relaxed);
        
        self.metrics.active_filters.store((total_size / 1024) as u64, Ordering::Relaxed);
    }

    pub fn handle_requests(self) {
        while let Ok(request) = self.receiver.recv() {
            match request.kind {
                RequestKind::Cosmetic(cosmetic_request) => {
                    let result = self.handle_cosmetic_request(cosmetic_request);
                    let _ = request.respond_to.send(BlockerResult::Cosmetic(result));
                }
                RequestKind::Url(network_url) => {
                    let result = self.handle_network_request(network_url);
                    let _ = request.respond_to.send(BlockerResult::Network(result));
                }
                RequestKind::ReplaceEngine(filters) => {
                    self.update_engine(filters);
                    let _ = request.respond_to.send(BlockerResult::Network(AdblockerBlockerResult {
                        matched: false,
                        important: false,
                        redirect: None,
                        exception: None,
                        filter: None,
                        rewritten_url: None,
                    }));
                }
            }
        }
    }

}

#[derive(Debug, Clone)]
pub(crate) struct AdblockRequester {
    adblock_request_channel: AdblockRequestChannel,
}

impl AdblockRequester {
    pub(crate) fn new(adblock_request_channel: AdblockRequestChannel) -> Self {
        Self {
            adblock_request_channel,
        }
    }

    pub(crate) async fn replace_engine(&self, filters: Vec<String>) {
        let (sender, _receiver) = oneshot::channel();
        self.adblock_request_channel
            .send(BlockerRequest {
                respond_to: sender,
                kind: RequestKind::ReplaceEngine(filters),
            })
            .unwrap();
    }

    pub(crate) async fn get_cosmetic_response(
        &self,
        url: String,
        ids: Vec<String>,
        classes: Vec<String>,
    ) -> CosmeticBlockerResult {
        let (sender, receiver) = oneshot::channel();

        self.adblock_request_channel
            .send(BlockerRequest {
                respond_to: sender,
                kind: RequestKind::Cosmetic(CosmeticRequest { url, ids, classes }),
            })
            .unwrap();

        match receiver.await {
            Ok(blocker_result) => match blocker_result {
                BlockerResult::Cosmetic(blocker_result) => blocker_result,
                BlockerResult::Network(_) => unreachable!(),
            },
            Err(_err) => unreachable!(),
        }
    }

    pub(crate) async fn is_network_url_blocked(
        &self,
        network_url: String,
        referer: String,
    ) -> (bool, adblock::blocker::BlockerResult) {
        let (sender, receiver) = oneshot::channel();

        self.adblock_request_channel
            .send(BlockerRequest {
                respond_to: sender,
                kind: RequestKind::Url(NetworkUrl {
                    url: network_url,
                    referer,
                }),
            })
            .unwrap();

        match receiver.await {
            Ok(blocker_result) => match blocker_result {
                BlockerResult::Network(blocker_result) => (blocker_result.matched, blocker_result),
                BlockerResult::Cosmetic(_) => unreachable!(),
            },
            Err(_err) => unreachable!(),
        }
    }
}
