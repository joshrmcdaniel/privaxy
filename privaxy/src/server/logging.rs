//! Global logging setup that mirrors `env_logger`'s stderr output while also
//! fanning every emitted record out to in-process subscribers.
//!
//! The standard `log` facade only permits a single global logger, and
//! `env_logger` writes exclusively to stderr with no hook to observe records.
//! [`init`] therefore builds `env_logger::Logger`s for stderr formatting, then
//! wraps them so each record is additionally pushed into a bounded ring buffer
//! (for backlog replay) and broadcast to live WebSocket subscribers (see
//! `web_gui::logs`).
//!
//! Verbosity of the application's own (`privaxy`-targeted) records is governed
//! by a [`LogHandle`]'s atomic level, which the web UI can change on the fly
//! via the Debug settings — no restart or `RUST_LOG` change required. Records
//! from dependencies keep their `RUST_LOG`-derived filtering so the stream
//! isn't drowned in third-party noise.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use log::{LevelFilter, Log, Metadata, Record};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

/// Crate name used both as the logging target prefix for the application's own
/// records and to decide which records the dynamic level applies to.
const APP_TARGET: &str = "privaxy";

/// Number of recent records retained for replay to clients that connect after
/// the records were emitted.
const BACKLOG_CAPACITY: usize = 1000;

/// Bound on the broadcast channel. Slow subscribers that fall further behind
/// than this are signalled with `Lagged` and skip the dropped records rather
/// than stalling the logger.
const CHANNEL_CAPACITY: usize = 512;

/// Default level for dependency (non-`privaxy`) records when `RUST_LOG` doesn't
/// say otherwise. Keeps third-party crates quiet so the stream stays readable.
const DEPENDENCY_DEFAULT_LEVEL: LevelFilter = LevelFilter::Warn;

/// A configurable log verbosity, persisted in the configuration and selectable
/// from the web UI. Mirrors `log::LevelFilter` but owns its serialized form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum LogLevel {
    Off,
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    pub fn to_level_filter(self) -> LevelFilter {
        match self {
            Self::Off => LevelFilter::Off,
            Self::Error => LevelFilter::Error,
            Self::Warn => LevelFilter::Warn,
            Self::Info => LevelFilter::Info,
            Self::Debug => LevelFilter::Debug,
            Self::Trace => LevelFilter::Trace,
        }
    }
}

/// A single formatted log record, serialized to WebSocket clients.
#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    pub now: DateTime<Utc>,
    pub level: String,
    pub target: String,
    pub message: String,
}

/// Cheap-to-clone handle giving access to the live log broadcast, the retained
/// backlog, and the runtime-adjustable application log level. Shared with the
/// API layer so a new subscriber can be primed with recent history and the
/// Debug settings route can change verbosity live.
#[derive(Clone)]
pub struct LogHandle {
    pub sender: broadcast::Sender<LogEntry>,
    pub backlog: Arc<Mutex<VecDeque<LogEntry>>>,
    level: Arc<AtomicUsize>,
}

impl LogHandle {
    /// Snapshot of the currently retained records, oldest first.
    pub fn backlog_snapshot(&self) -> Vec<LogEntry> {
        match self.backlog.lock() {
            Ok(backlog) => backlog.iter().cloned().collect(),
            Err(poisoned) => poisoned.get_ref().iter().cloned().collect(),
        }
    }

    /// Changes the verbosity applied to the application's own records,
    /// effective immediately for subsequent records.
    pub fn set_level(&self, level: LevelFilter) {
        self.level.store(level as usize, Ordering::Relaxed);
    }

    fn app_level(&self) -> LevelFilter {
        level_filter_from_usize(self.level.load(Ordering::Relaxed))
    }

    fn record(&self, entry: LogEntry) {
        if let Ok(mut backlog) = self.backlog.lock() {
            if backlog.len() == BACKLOG_CAPACITY {
                backlog.pop_front();
            }
            backlog.push_back(entry.clone());
        }
        // A send error only means there are no live subscribers; the backlog
        // still captured the record, so the error is intentionally ignored.
        let _ = self.sender.send(entry);
    }
}

fn level_filter_from_usize(value: usize) -> LevelFilter {
    match value {
        0 => LevelFilter::Off,
        1 => LevelFilter::Error,
        2 => LevelFilter::Warn,
        3 => LevelFilter::Info,
        4 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    }
}

fn is_app_target(target: &str) -> bool {
    target == APP_TARGET || target.starts_with(concat!("privaxy", "::"))
}

struct BroadcastLogger {
    /// Pass-through formatter/writer for the application's own records; its own
    /// filter is wide open so the dynamic level is the sole gate.
    app_writer: env_logger::Logger,
    /// `RUST_LOG`-derived formatter/filter for dependency records.
    dependency_logger: env_logger::Logger,
    handle: LogHandle,
}

impl BroadcastLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        if is_app_target(metadata.target()) {
            metadata.level() <= self.handle.app_level()
        } else {
            self.dependency_logger.enabled(metadata)
        }
    }
}

impl Log for BroadcastLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        self.enabled(metadata)
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        if is_app_target(record.target()) {
            self.app_writer.log(record);
        } else {
            self.dependency_logger.log(record);
        }

        self.handle.record(LogEntry {
            now: Utc::now(),
            level: record.level().to_string(),
            target: record.target().to_string(),
            message: record.args().to_string(),
        });
    }

    fn flush(&self) {
        self.app_writer.flush();
        self.dependency_logger.flush();
    }
}

/// Installs the global logger and returns a [`LogHandle`] for streaming records
/// to clients and adjusting verbosity at runtime.
///
/// `initial_level` seeds the application log level (typically from
/// configuration). Dependency records are filtered via `RUST_LOG`, defaulting
/// to [`DEPENDENCY_DEFAULT_LEVEL`].
///
/// Must be called exactly once, before any logging occurs.
pub fn init(initial_level: LevelFilter) -> LogHandle {
    // Wide-open writer: every application record we hand it is already gated by
    // the dynamic level, so its own filter must not drop anything.
    let app_writer = env_logger::Builder::new()
        .filter_level(LevelFilter::Trace)
        .build();

    // Dependency records keep RUST_LOG behaviour on top of a quiet default.
    let dependency_logger = env_logger::Builder::new()
        .filter_level(DEPENDENCY_DEFAULT_LEVEL)
        .parse_default_env()
        .build();

    let (sender, _receiver) = broadcast::channel(CHANNEL_CAPACITY);
    let handle = LogHandle {
        sender,
        backlog: Arc::new(Mutex::new(VecDeque::with_capacity(BACKLOG_CAPACITY))),
        level: Arc::new(AtomicUsize::new(initial_level as usize)),
    };

    let logger = BroadcastLogger {
        app_writer,
        dependency_logger,
        handle: handle.clone(),
    };

    log::set_boxed_logger(Box::new(logger)).expect("failed to install global logger");
    // Keep the facade permissive so the dynamic level can be raised to Trace at
    // runtime; the wrapper performs the actual per-record gating.
    log::set_max_level(LevelFilter::Trace);

    handle
}
