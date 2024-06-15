use readonly;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
#[serde(rename_all = "camelCase")]
#[readonly::make]
pub struct Filter {
    pub id: u64,
    pub name: String,
    #[serde(default = "default_description")]
    pub description: Option<String>,
    pub license_id: u64,
    pub syntax_ids: Vec<u64>,
    pub language_ids: Vec<u64>,
    pub tag_ids: Vec<u64>,
    #[serde(default = "default_view_url")]
    pub primary_view_url: Option<String>,
    pub maintainer_ids: Vec<u64>,
}

fn default_description() -> Option<String> {
    Some("No description".to_string())
}

fn default_view_url() -> Option<String> {
    None
}
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
#[serde(rename_all = "camelCase")]
#[readonly::make]
pub struct FilterViewURL {
    pub segment_number: u32,
    pub primariness: u32,
    pub url: String,
}

#[derive(Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
#[readonly::make]
pub struct FilterLanguage {
    pub id: u64,
    pub iso6391: String,
    pub name: String,
    pub filter_list_ids: Vec<u64>,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
#[serde(rename_all = "camelCase")]
#[readonly::make]
pub struct FilterDetails {
    pub id: u64,
    pub name: String,
    pub description: String,
    pub license_id: u64,
    pub syntax_ids: Vec<u64>,
    pub language_ids: Vec<u64>,
    pub tag_ids: Vec<u64>,
    pub primary_view_url: String,
    pub maintainer_ids: Vec<u64>,
    pub view_urls: Vec<FilterViewURL>,
    pub home_url: String,
    pub onion_url: String,
    pub policy_url: String,
    pub submission_url: String,
    pub issues_url: String,
    pub forum_url: String,
    pub chat_url: String,
    pub email_address: String,
    pub donate_url: String,
    pub upstream_filter_list_ids: Vec<u64>,
    pub include_in_filter_list_ids: Vec<u64>,
    pub includes_filter_list_ids: Vec<u64>,
    pub dependency_filter_list_ids: Vec<u64>,
    pub dependent_filter_list_ids: Vec<u64>,
}

#[derive(Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
#[readonly::make]
pub struct FilterSoftware {
    pub id: u64,
    pub name: String,
    #[serde(default)]
    pub home_url: Option<String>,
    #[serde(default)]
    pub download_url: Option<String>,
    pub supports_abp_url_scheme: bool,
    pub syntax_ids: Vec<u64>,
}

#[derive(Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
#[readonly::make]
pub struct FilterListSyntax {
    pub id: u64,
    pub name: String,
    pub url: String,
    pub filter_list_ids: Vec<u64>,
    pub software_ids: Vec<u64>,
}

#[derive(Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
#[readonly::make]
pub struct FilterLicense {
    pub id: u64,
    pub name: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub permit_modifications: Option<bool>,
    #[serde(default)]
    pub permit_distribution: Option<bool>,
    #[serde(default)]
    pub permit_commercial_use: Option<bool>,
    pub filter_list_ids: Vec<u64>,
}

#[derive(Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
#[readonly::make]
pub struct FilterTag {
    pub id: u64,
    pub name: String,
    pub filter_list_ids: Vec<u64>,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Error)]
#[error("{r#type} error ({status}): {title} {trace_id}")]
#[serde(rename_all = "camelCase")]
#[readonly::make]
pub struct FilterListAPIError {
    pub r#type: String,
    pub title: String,
    pub status: u16,
    pub trace_id: String,
}

#[derive(Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
#[readonly::make]
pub struct FilterMaintainer {
    pub id: u64,
    pub name: String,
    pub url: String,
    pub filter_list_ids: Vec<u64>,
}

pub enum FilterArgs {
    U64(u64),
    Filter(Filter),
}

#[derive(Debug, Error)]
pub enum FilterListError {
    #[error("API error: {0}")]
    APIError(#[from] FilterListAPIError),
    #[cfg(feature = "reqwest")]
    #[error("Reqwest error: {0}")]
    RequestError(#[from] reqwest::Error),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("Unknown error: {0}")]
    GenericError(#[from] Box<dyn std::error::Error + Send + Sync>),
}
