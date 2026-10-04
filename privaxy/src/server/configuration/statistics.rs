use serde::{Deserialize, Serialize};

/// These levels describe collected data, not just what the UI displays.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum StatisticsPrivacy {
    Full,
    HideDomains,
    #[default]
    HideDomainsAndClients,
    Anonymous,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct StatisticsConfig {
    pub enabled: bool,
    pub privacy: StatisticsPrivacy,
    pub retention_days: u16,
    pub max_entries: u32,
    pub excluded_domains: Vec<String>,
}

impl Default for StatisticsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            privacy: StatisticsPrivacy::default(),
            retention_days: 7,
            max_entries: 100_000,
            excluded_domains: Vec::new(),
        }
    }
}

impl StatisticsConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.excluded_domains.len() > 1000
            || self.excluded_domains.iter().any(|pattern| {
                let pattern = pattern.trim();
                pattern.is_empty()
                    || pattern.len() > 253
                    || !pattern
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b".-*?".contains(&b))
            })
        {
            return Err("Use at most 1,000 domain patterns, without schemes, ports, or paths (for example example.com or *.example.com)".into());
        }
        if !(1..=365).contains(&self.retention_days) {
            return Err("Statistics retention must be between 1 and 365 days".into());
        }
        if !(100..=1_000_000).contains(&self.max_entries) {
            return Err("Request history limit must be between 100 and 1,000,000 entries".into());
        }
        Ok(())
    }

    pub fn persists(&self) -> bool {
        self.enabled && self.privacy != StatisticsPrivacy::Anonymous
    }
}
