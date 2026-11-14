//! Compact request rows and reference-counted identifier dictionaries.
use super::{RequestRecord, StoreResult};
use redb::{
    ReadOnlyTable, ReadTransaction, ReadableTable, Table, TableDefinition, WriteTransaction,
};
use sha2::{Digest, Sha256};
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};

// Timestamp, domain ID, endpoint ID, client ID, blocked. Zero means absent;
// the empty root path is a real dictionary value with a nonzero ID.
pub(super) type StoredRequest = (u64, u64, u64, u64, bool);
pub(super) const REQUESTS: TableDefinition<u64, StoredRequest> =
    TableDefinition::new("requests_v3");
pub(super) const LEGACY_REQUESTS: TableDefinition<u64, &[u8]> = TableDefinition::new("requests_v1");
pub(super) const DOMAINS: TableDefinition<u64, (u64, &str)> = TableDefinition::new("domains_v3");
pub(super) const ENDPOINTS: TableDefinition<u64, (u64, &str)> =
    TableDefinition::new("endpoints_v3");
pub(super) const CLIENTS: TableDefinition<u64, (u64, &str)> = TableDefinition::new("clients_v3");
const DOMAIN_INDEX: TableDefinition<&[u8], u64> = TableDefinition::new("domain_index_v3");
const ENDPOINT_INDEX: TableDefinition<&[u8], u64> = TableDefinition::new("endpoint_index_v3");
const CLIENT_INDEX: TableDefinition<&[u8], u64> = TableDefinition::new("client_index_v3");

struct Dictionary<'a> {
    values: Table<'a, u64, (u64, &'static str)>,
    index: Table<'a, &'static [u8], u64>,
}

impl Dictionary<'_> {
    fn intern(&mut self, value: Option<&str>) -> StoreResult<u64> {
        let Some(value) = value else { return Ok(0) };
        // A fixed-size index avoids storing each string twice, especially for
        // long paths. Verify the string too: collisions must never alias values.
        let hash = Sha256::digest(value.as_bytes());
        let existing = self.index.get(hash.as_slice())?.map(|v| v.value());
        if let Some(id) = existing {
            let references = {
                let saved = self
                    .values
                    .get(id)?
                    .ok_or("Missing statistics identifier")?;
                let (references, saved) = saved.value();
                if saved != value {
                    return Err("Statistics identifier hash collision".into());
                }
                references
                    .checked_add(1)
                    .ok_or("Statistics reference count overflow")?
            };
            self.values.insert(id, (references, value))?;
            return Ok(id);
        }
        let id = self
            .values
            .last()?
            .map(|(id, _)| id.value())
            .unwrap_or(0)
            .checked_add(1)
            .ok_or("Statistics identifier overflow")?;
        self.values.insert(id, (1, value))?;
        self.index.insert(hash.as_slice(), id)?;
        Ok(id)
    }

    fn release(&mut self, id: u64) -> StoreResult<()> {
        if id == 0 {
            return Ok(());
        }
        let (references, value) = {
            let saved = self
                .values
                .get(id)?
                .ok_or("Missing statistics identifier")?;
            let (references, value) = saved.value();
            (references, value.to_owned())
        };
        if references == 1 {
            self.values.remove(id)?;
            self.index
                .remove(Sha256::digest(value.as_bytes()).as_slice())?;
        } else {
            let references = references
                .checked_sub(1)
                .ok_or("Invalid statistics reference count")?;
            self.values.insert(id, (references, value.as_str()))?;
        }
        Ok(())
    }

    fn clear(&mut self) -> StoreResult<()> {
        self.values.retain(|_, _| false)?;
        self.index.retain(|_, _| false)?;
        Ok(())
    }
}

pub(super) struct Dictionaries<'a> {
    domains: Dictionary<'a>,
    endpoints: Dictionary<'a>,
    clients: Dictionary<'a>,
}

impl<'a> Dictionaries<'a> {
    pub(super) fn open(tx: &'a WriteTransaction) -> StoreResult<Self> {
        Ok(Self {
            domains: Dictionary {
                values: tx.open_table(DOMAINS)?,
                index: tx.open_table(DOMAIN_INDEX)?,
            },
            endpoints: Dictionary {
                values: tx.open_table(ENDPOINTS)?,
                index: tx.open_table(ENDPOINT_INDEX)?,
            },
            clients: Dictionary {
                values: tx.open_table(CLIENTS)?,
                index: tx.open_table(CLIENT_INDEX)?,
            },
        })
    }

    pub(super) fn intern(&mut self, record: &RequestRecord) -> StoreResult<StoredRequest> {
        Ok((
            record.timestamp,
            self.domains.intern(record.domain.as_deref())?,
            self.endpoints.intern(record.endpoint.as_deref())?,
            self.clients.intern(record.client.as_deref())?,
            record.blocked,
        ))
    }

    pub(super) fn release(&mut self, record: StoredRequest) -> StoreResult<()> {
        self.domains.release(record.1)?;
        self.endpoints.release(record.2)?;
        self.clients.release(record.3)?;
        Ok(())
    }

    pub(super) fn redact(
        &mut self,
        privacy: crate::configuration::StatisticsPrivacy,
    ) -> StoreResult<()> {
        use crate::configuration::StatisticsPrivacy;
        if privacy >= StatisticsPrivacy::HideDomains {
            self.domains.clear()?;
            self.endpoints.clear()?;
        }
        if privacy >= StatisticsPrivacy::HideDomainsAndClients {
            self.clients.clear()?;
        }
        Ok(())
    }
}

pub(super) struct DictionaryReader {
    pub domains: ReadOnlyTable<u64, (u64, &'static str)>,
    endpoints: ReadOnlyTable<u64, (u64, &'static str)>,
    pub clients: ReadOnlyTable<u64, (u64, &'static str)>,
}

impl DictionaryReader {
    pub(super) fn open(tx: &ReadTransaction) -> StoreResult<Self> {
        Ok(Self {
            domains: tx.open_table(DOMAINS)?,
            endpoints: tx.open_table(ENDPOINTS)?,
            clients: tx.open_table(CLIENTS)?,
        })
    }

    pub(super) fn record(&self, id: u64, record: StoredRequest) -> StoreResult<RequestRecord> {
        Ok(RequestRecord {
            id,
            timestamp: record.0,
            domain: value(&self.domains, record.1)?,
            endpoint: value(&self.endpoints, record.2)?,
            client: value(&self.clients, record.3)?,
            blocked: record.4,
        })
    }
}

fn value(table: &ReadOnlyTable<u64, (u64, &'static str)>, id: u64) -> StoreResult<Option<String>> {
    if id == 0 {
        return Ok(None);
    }
    Ok(Some(
        table
            .get(id)?
            .ok_or("Missing statistics identifier")?
            .value()
            .1
            .to_owned(),
    ))
}

pub(super) fn top_entries(
    table: &ReadOnlyTable<u64, (u64, &'static str)>,
    counts: HashMap<u64, u64>,
) -> StoreResult<Vec<(String, u64)>> {
    // Keep at most 50 strings while resolving IDs, with the same alphabetical
    // tie-breaking as the original dashboard.
    let mut best = BinaryHeap::new();
    for (id, count) in counts {
        if let Some(name) = value(table, id)? {
            best.push((Reverse(count), name));
            if best.len() > 50 {
                best.pop();
            }
        }
    }
    let mut entries: Vec<_> = best
        .into_iter()
        .map(|(Reverse(count), name)| (name, count))
        .collect();
    entries.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    Ok(entries)
}
