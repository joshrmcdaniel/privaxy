//! Persistent backing for `GM_setValue` / `GM_getValue`.
//!
//! `GM_getValue` is synchronous in the Greasemonkey API, so it cannot be backed
//! by a request. Values are instead preloaded into each script's descriptor at
//! injection time (see `super::super::html_rewriter::build_userscript_info`) and read from
//! that snapshot in-page; only writes travel back to the proxy. This is
//! effectively what userscript managers do, and it means there is no read
//! endpoint to attack.
//!
//! Writes are coalesced: a mutation updates memory immediately and schedules a
//! flush, so a script calling `GM_setValue` on every scroll event costs one file
//! write rather than hundreds. The configuration file is deliberately *not* used
//! — persisting there would re-serialize the whole `Configuration` and take the
//! save lock on every write.

use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Notify;

/// How long to wait after a write before flushing, so bursts coalesce.
const FLUSH_DEBOUNCE: Duration = Duration::from_millis(500);

/// Cap on the number of keys one script may store, so a runaway script cannot
/// grow the file without bound.
const MAX_KEYS_PER_SCRIPT: usize = 1_000;

/// Cap on a single serialized value.
const MAX_VALUE_BYTES: usize = 64 * 1024;

/// Values for every script, keyed by script file name and then by key.
type StoredValues = BTreeMap<String, BTreeMap<String, Value>>;

#[derive(Debug, Default)]
struct Inner {
    values: StoredValues,
    dirty: bool,
}

/// Cheaply-cloneable handle to the userscript value store. Lock scopes are
/// short and never held across an await point.
#[derive(Debug, Clone)]
pub struct GmStorageStore {
    inner: Arc<Mutex<Inner>>,
    flush_requested: Arc<Notify>,
    /// Where to persist, or `None` when no configuration directory is
    /// available — in which case values live for the process lifetime only.
    path: Option<PathBuf>,
}

impl GmStorageStore {
    /// Load the store from disk, falling back to empty when the file is absent
    /// or unreadable. A corrupt file is logged and ignored rather than fatal:
    /// losing script settings must not stop the proxy from starting.
    pub async fn load() -> Self {
        let path = crate::configuration::userscript_storage_path();

        let values = match &path {
            Some(path) => match tokio::fs::read(path).await {
                Ok(bytes) => match serde_json::from_slice::<StoredValues>(&bytes) {
                    Ok(values) => values,
                    Err(err) => {
                        log::warn!(
                            "Ignoring unreadable userscript value store at {}: {err}",
                            path.display()
                        );
                        StoredValues::new()
                    }
                },
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => StoredValues::new(),
                Err(err) => {
                    log::warn!("Unable to read the userscript value store: {err}");
                    StoredValues::new()
                }
            },
            None => StoredValues::new(),
        };

        let store = Self {
            inner: Arc::new(Mutex::new(Inner {
                values,
                dirty: false,
            })),
            flush_requested: Arc::new(Notify::new()),
            path,
        };

        store.spawn_flusher();

        store
    }

    /// Every stored key/value for one script, for preloading into its
    /// descriptor.
    pub fn snapshot(&self, script_id: &str) -> BTreeMap<String, Value> {
        self.inner
            .lock()
            .unwrap()
            .values
            .get(script_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Apply a batch of writes and deletions for one script. A `None` value
    /// deletes the key. Returns an error message when the batch is refused.
    pub fn apply(
        &self,
        script_id: &str,
        changes: BTreeMap<String, Option<Value>>,
    ) -> Result<(), String> {
        for (key, value) in &changes {
            if let Some(value) = value {
                let size = serde_json::to_string(value).map(|s| s.len()).unwrap_or(0);
                if size > MAX_VALUE_BYTES {
                    return Err(format!(
                        "value for '{key}' exceeds the {MAX_VALUE_BYTES} byte limit"
                    ));
                }
            }
        }

        let mut guard = self.inner.lock().unwrap();
        let script_values = guard.values.entry(script_id.to_string()).or_default();

        for (key, value) in changes {
            match value {
                Some(value) => {
                    if !script_values.contains_key(&key)
                        && script_values.len() >= MAX_KEYS_PER_SCRIPT
                    {
                        return Err(format!(
                            "this script already stores the maximum of {MAX_KEYS_PER_SCRIPT} keys"
                        ));
                    }
                    script_values.insert(key, value);
                }
                None => {
                    script_values.remove(&key);
                }
            }
        }

        // An emptied script leaves no entry behind, so uninstalling a script
        // that cleared its own values does not leave a stub in the file.
        if script_values.is_empty() {
            guard.values.remove(script_id);
        }

        guard.dirty = true;
        drop(guard);

        self.flush_requested.notify_one();

        Ok(())
    }

    /// Drop everything stored for a script. Called when a script is
    /// uninstalled so its values do not linger.
    pub fn forget(&self, script_id: &str) {
        let mut guard = self.inner.lock().unwrap();
        if guard.values.remove(script_id).is_some() {
            guard.dirty = true;
            drop(guard);
            self.flush_requested.notify_one();
        }
    }

    /// Debounced writer: wakes on the first write of a burst, waits out the
    /// burst, then persists once.
    fn spawn_flusher(&self) {
        let store = self.clone();

        tokio::spawn(async move {
            loop {
                store.flush_requested.notified().await;
                tokio::time::sleep(FLUSH_DEBOUNCE).await;
                store.flush().await;
            }
        });
    }

    async fn flush(&self) {
        let Some(path) = &self.path else {
            return;
        };

        let serialized = {
            let mut guard = self.inner.lock().unwrap();
            if !guard.dirty {
                return;
            }
            guard.dirty = false;
            serde_json::to_vec(&guard.values)
        };

        let serialized = match serialized {
            Ok(serialized) => serialized,
            Err(err) => {
                log::error!("Unable to serialize the userscript value store: {err}");
                return;
            }
        };

        if let Some(directory) = path.parent() {
            if let Err(err) = tokio::fs::create_dir_all(directory).await {
                log::warn!("Unable to create the userscript value store directory: {err}");
                return;
            }
        }

        // Write-and-rename so a crash mid-write cannot leave a truncated file
        // that would be discarded on the next start, matching how the
        // configuration file is saved.
        let temporary_path = path.with_extension("json.tmp");
        if let Err(err) = tokio::fs::write(&temporary_path, &serialized).await {
            log::warn!("Unable to write the userscript value store: {err}");
            let _ = tokio::fs::remove_file(&temporary_path).await;
            return;
        }
        if let Err(err) = tokio::fs::rename(&temporary_path, path).await {
            log::warn!("Unable to replace the userscript value store: {err}");
            let _ = tokio::fs::remove_file(&temporary_path).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A store with no configuration directory still works in memory, which is
    /// also what makes this testable without touching disk.
    fn in_memory_store() -> GmStorageStore {
        GmStorageStore {
            inner: Arc::new(Mutex::new(Inner::default())),
            flush_requested: Arc::new(Notify::new()),
            path: None,
        }
    }

    fn changes(pairs: Vec<(&str, Option<Value>)>) -> BTreeMap<String, Option<Value>> {
        pairs
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect()
    }

    #[test]
    fn set_and_read_back_per_script() {
        let store = in_memory_store();

        store
            .apply(
                "a.user.js",
                changes(vec![("theme", Some(Value::from("dark")))]),
            )
            .expect("applies");
        store
            .apply(
                "b.user.js",
                changes(vec![("theme", Some(Value::from("light")))]),
            )
            .expect("applies");

        assert_eq!(
            store.snapshot("a.user.js").get("theme"),
            Some(&Value::from("dark"))
        );
        // Storage is scoped per script, as in every userscript manager.
        assert_eq!(
            store.snapshot("b.user.js").get("theme"),
            Some(&Value::from("light"))
        );
        assert!(store.snapshot("unknown.user.js").is_empty());
    }

    #[test]
    fn none_deletes_a_key() {
        let store = in_memory_store();
        store
            .apply(
                "a.user.js",
                changes(vec![
                    ("keep", Some(Value::from(1))),
                    ("drop", Some(Value::from(2))),
                ]),
            )
            .expect("applies");

        store
            .apply("a.user.js", changes(vec![("drop", None)]))
            .expect("applies");

        let snapshot = store.snapshot("a.user.js");
        assert!(snapshot.contains_key("keep"));
        assert!(!snapshot.contains_key("drop"));
    }

    #[test]
    fn forget_drops_everything_for_one_script() {
        let store = in_memory_store();
        store
            .apply("a.user.js", changes(vec![("k", Some(Value::from(1)))]))
            .expect("applies");
        store
            .apply("b.user.js", changes(vec![("k", Some(Value::from(1)))]))
            .expect("applies");

        store.forget("a.user.js");

        assert!(store.snapshot("a.user.js").is_empty());
        assert!(!store.snapshot("b.user.js").is_empty());
    }

    #[test]
    fn oversized_values_are_refused() {
        let store = in_memory_store();
        let huge = Value::from("x".repeat(MAX_VALUE_BYTES + 1));

        let err = store
            .apply("a.user.js", changes(vec![("big", Some(huge))]))
            .expect_err("should be refused");

        assert!(err.contains("exceeds"), "{err}");
        // Nothing is written when the batch is refused.
        assert!(store.snapshot("a.user.js").is_empty());
    }

    #[test]
    fn key_count_is_capped() {
        let store = in_memory_store();
        let full = changes(
            (0..MAX_KEYS_PER_SCRIPT)
                .map(|index| (format!("k{index}"), Some(Value::from(index))))
                .map(|(key, value)| (Box::leak(key.into_boxed_str()) as &str, value))
                .collect(),
        );
        store.apply("a.user.js", full).expect("applies");

        let err = store
            .apply(
                "a.user.js",
                changes(vec![("one-too-many", Some(Value::from(1)))]),
            )
            .expect_err("should be refused");
        assert!(err.contains("maximum"), "{err}");

        // Overwriting an existing key stays allowed at the cap.
        store
            .apply(
                "a.user.js",
                changes(vec![("k0", Some(Value::from("replaced")))]),
            )
            .expect("overwrite at cap is allowed");
        assert_eq!(
            store.snapshot("a.user.js").get("k0"),
            Some(&Value::from("replaced"))
        );
    }
}
