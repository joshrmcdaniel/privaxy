use readonly;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
#[serde(rename_all = "camelCase")]
#[readonly::make]
/// A FilterList.
pub struct Filter {
    /// The identifier of the filter in FilterLists
    pub id: u32,
    /// The unique name in title case
    pub name: String,
    #[serde(default = "default_description")]
    /// The brief description in English (preferably quoted from the project).
    pub description: Option<String>,
    /// The identifier of the License under which this FilterList is released
    pub license_id: u32,
    /// The identifiers of the Syntaxes implemented by this FilterList.
    pub syntax_ids: Vec<u32>,
    /// The identifiers of the Languages targeted by this FilterList.
    pub language_ids: Vec<u32>,
    /// The identifiers of the Tags applied to this FilterList.
    pub tag_ids: Vec<u32>,
    #[serde(default = "default_view_url")]
    /// The primary view URL.
    pub primary_view_url: Option<String>,
    /// The identifiers of the Maintainers of this FilterList.
    pub maintainer_ids: Vec<u32>,
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
/// The URLs to view a FilterList.
pub struct FilterViewURL {
    /// The segment number of the URL for the FilterList (for multi-part lists).
    pub segment_number: u32,
    /// How primary the URL is for the FilterList segment (1 is original, 2+ is a mirror; unique per SegmentNumber)
    pub primariness: u32,
    /// The view URL.
    pub url: String,
}

#[derive(Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
#[readonly::make]
pub struct FilterLanguage {
    /// ID of the language in FilterLists
    pub id: u32,
    /// The unique ISO 639-1 code
    pub iso6391: String,
    /// The unique ISO name
    pub name: String,
    /// The identifiers of the FilterLists targeted by this Language
    pub filter_list_ids: Vec<u32>,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
#[serde(rename_all = "camelCase")]
#[readonly::make]
/// Detailed information about a FilterList.
pub struct FilterDetails {
    /// The identifier of the filter in FilterLists
    pub id: u32,
    /// The unique name in title case
    pub name: String,
    /// The brief description in English (preferably quoted from the project).
    pub description: String,
    /// The identifier of the License under which this FilterList is released
    pub license_id: u32,
    /// The identifiers of the Syntaxes implemented by this FilterList.
    pub syntax_ids: Vec<u32>,
    /// The identifiers of the Languages targeted by this FilterList.
    pub language_ids: Vec<u32>,
    /// The identifiers of the Tags applied to this FilterList.
    pub tag_ids: Vec<u32>,
    /// The view URLs.
    pub view_urls: Vec<FilterViewURL>,
    /// The URL of the homepage
    pub home_url: String,
    /// The URL of the Tor / Onion page.
    pub onion_url: String,
    /// The URL of the policy/guidelines for the types of rules this FilterList includes.
    pub policy_url: String,
    /// The URL of the submission/contact form for adding rules to this FilterList.
    pub submission_url: String,
    /// The URL of the GitHub Issues page.
    pub issues_url: String,
    /// The URL of the forum page.
    pub forum_url: String,
    /// The URL of the chat room.
    pub chat_url: String,
    /// The email address at which the project can be contacted.
    pub email_address: String,
    /// The URL at which donations to the project can be made.
    pub donate_url: String,
    /// The identifiers of the Maintainers of this FilterList.
    pub maintainer_ids: Vec<u32>,
    /// The identifiers of the FilterLists from which this FilterList was forked.
    pub upstream_filter_list_ids: Vec<u32>,
    /// The identifiers of the FilterLists that have been forked from this FilterList.
    pub fork_filter_list_ids: Vec<u32>,
    /// The identifiers of the FilterLists that include this FilterList.
    pub included_in_filter_list_ids: Vec<u32>,
    /// The identifiers of the FilterLists that this FilterList includes.
    pub includes_filter_list_ids: Vec<u32>,
    /// The identifiers of the FilterLists that this FilterList depends upon.
    pub dependency_filter_list_ids: Vec<u32>,
    /// The identifiers of the FilterLists dependent upon this FilterList.
    pub dependent_filter_list_ids: Vec<u32>,
}

#[derive(Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
#[readonly::make]
pub struct FilterSoftware {
    pub id: u32,
    pub name: String,
    #[serde(default)]
    pub home_url: Option<String>,
    #[serde(default)]
    pub download_url: Option<String>,
    pub supports_abp_url_scheme: bool,
    pub syntax_ids: Vec<u32>,
}

#[derive(Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
#[readonly::make]
pub struct FilterListSyntax {
    pub id: u32,
    pub name: String,
    pub url: String,
    pub filter_list_ids: Vec<u32>,
    pub software_ids: Vec<u32>,
}

#[derive(Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
#[readonly::make]
pub struct FilterLicense {
    /// The identifier of the license in FilterLists
    pub id: u32,
    /// The name of the license
    pub name: String,
    #[serde(default)]
    /// The URL of the license
    pub url: Option<String>,
    #[serde(default)]
    /// If the license permits modification
    pub permit_modifications: Option<bool>,
    #[serde(default)]
    /// If the license permits distribution
    pub permit_distribution: Option<bool>,
    #[serde(default)]
    /// If the license permits commercial use
    pub permit_commercial_use: Option<bool>,
    /// The identifiers of the FilterLists released under this License.
    pub filter_list_ids: Vec<u32>,
}

#[derive(Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
#[readonly::make]
pub struct FilterTag {
    pub id: u32,
    pub name: String,
    pub filter_list_ids: Vec<u32>,
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
    pub id: u32,
    pub name: String,
    pub url: String,
    pub filter_list_ids: Vec<u32>,
}

pub enum FilterArgs {
    U32(u32),
    Filter(Filter),
}

#[derive(Debug, Error)]
pub enum FilterListError {
    #[error("API error: {0}")]
    APIError(#[from] FilterListAPIError),
    #[cfg(feature = "reqwest")]
    #[error("Reqwest error: {0}")]
    RequestError(#[from] reqwest_impersonate::Error),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("Unknown error: {0}")]
    GenericError(#[from] Box<dyn std::error::Error + Send + Sync>),
}
