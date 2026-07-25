//! In-memory record of filter lists that failed to download or validate.
//!
//! Filter lists are refreshed in the background (periodically and on
//! configuration changes), so a list whose URL went stale fails silently from
//! the operator's point of view. The updater records those failures here; the
//! web GUI surfaces them via `GET /api/filters/failures` so the operator can
//! edit the entry's URL or remove it.

use super::filter::{Filter, FilterGroup};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::sync::{Arc, Mutex};

/// A single failing filter list, most recent failure details included.
#[derive(Debug, Clone, Serialize)]
pub struct FilterFailureEntry {
    /// Local file name of the filter; stable identifier tying the entry to
    /// the configuration entry it describes.
    pub file_name: String,
    /// Title of the filter, for display.
    pub title: String,
    /// Remote URL the download failed for.
    pub url: String,
    /// Group of the filter.
    pub group: FilterGroup,
    /// The last download/validation error, verbatim.
    pub last_error: String,
    /// When the filter last failed to update (RFC 3339 via chrono's serde).
    pub last_seen: DateTime<Utc>,
    /// How many consecutive failed update attempts have been observed.
    pub count: u64,
}

/// Cheaply-cloneable shared store of filter update failures. Lock scopes are
/// short and never held across an await point. The store is inherently
/// bounded: entries only exist for filters present in the configuration.
#[derive(Debug, Clone, Default)]
pub struct FilterFailureStore(Arc<Mutex<Vec<FilterFailureEntry>>>);

impl FilterFailureStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a failed update attempt for `filter`, deduplicating by file
    /// name: an already-failing filter is bumped to the front with its
    /// counter incremented and failure details refreshed.
    pub fn record(&self, filter: &Filter, error: &str) {
        let mut entries = self.0.lock().unwrap();

        let last_seen = Utc::now();
        let count = match entries
            .iter()
            .position(|entry| entry.file_name == filter.file_name)
        {
            Some(index) => entries.remove(index).count + 1,
            None => 1,
        };

        entries.insert(
            0,
            FilterFailureEntry {
                file_name: filter.file_name.clone(),
                title: filter.title.clone(),
                url: filter.url.to_string(),
                group: filter.group,
                last_error: error.to_string(),
                last_seen,
                count,
            },
        );
    }

    /// Drop the entry for `file_name`, if any. Called after a successful
    /// update and after the operator edits or removes the filter.
    pub fn clear(&self, file_name: &str) {
        self.0
            .lock()
            .unwrap()
            .retain(|entry| entry.file_name != file_name);
    }

    /// Snapshot of the tracked failures, most recently failed first.
    pub fn entries(&self) -> Vec<FilterFailureEntry> {
        self.0.lock().unwrap().clone()
    }

    /// Reconcile the store with a freshly-applied configuration: drop entries
    /// whose filter no longer exists or was disabled, and refresh the display
    /// metadata of the ones that remain (a title or group edit keeps the same
    /// file name).
    pub fn sync_with_filters(&self, filters: &[Filter]) {
        let mut entries = self.0.lock().unwrap();
        entries.retain_mut(|entry| {
            match filters
                .iter()
                .find(|filter| filter.enabled && filter.file_name == entry.file_name)
            {
                Some(filter) => {
                    entry.title = filter.title.clone();
                    entry.url = filter.url.to_string();
                    entry.group = filter.group;
                    true
                }
                None => false,
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    fn make_filter(file_name: &str, title: &str, enabled: bool) -> Filter {
        Filter {
            enabled,
            title: title.to_string(),
            group: FilterGroup::Ads,
            file_name: file_name.to_string(),
            url: Url::parse("https://example.com/list.txt").unwrap(),
        }
    }

    #[test]
    fn record_dedupes_by_file_name_and_bumps_count() {
        let store = FilterFailureStore::new();
        let filter = make_filter("abc.txt", "Some list", true);

        store.record(&filter, "first error");
        store.record(&filter, "second error");

        let entries = store.entries();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.file_name, "abc.txt");
        assert_eq!(entry.count, 2);
        assert_eq!(entry.last_error, "second error");
    }

    #[test]
    fn record_moves_repeated_filter_to_front() {
        let store = FilterFailureStore::new();
        store.record(&make_filter("a.txt", "A", true), "error");
        store.record(&make_filter("b.txt", "B", true), "error");
        store.record(&make_filter("a.txt", "A", true), "error");

        let file_names: Vec<String> = store
            .entries()
            .into_iter()
            .map(|entry| entry.file_name)
            .collect();
        assert_eq!(file_names, vec!["a.txt", "b.txt"]);
    }

    #[test]
    fn clear_drops_entry() {
        let store = FilterFailureStore::new();
        store.record(&make_filter("a.txt", "A", true), "error");

        store.clear("a.txt");
        assert!(store.entries().is_empty());
    }

    #[test]
    fn sync_with_filters_prunes_removed_and_disabled_filters() {
        let store = FilterFailureStore::new();
        store.record(&make_filter("removed.txt", "Removed", true), "error");
        store.record(&make_filter("disabled.txt", "Disabled", true), "error");
        store.record(&make_filter("kept.txt", "Old title", true), "error");

        store.sync_with_filters(&[
            make_filter("disabled.txt", "Disabled", false),
            make_filter("kept.txt", "New title", true),
        ]);

        let entries = store.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].file_name, "kept.txt");
        // Metadata is refreshed from the configuration entry.
        assert_eq!(entries[0].title, "New title");
    }
}
