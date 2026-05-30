#[cfg(all(feature = "reqwasm", feature = "reqwest"))]
compile_error!("feature \"reqwasm\" and \"reqwest\" cannot be enabled at the same time");

pub mod dtypes;
pub use self::dtypes::*;
#[cfg(any(feature = "reqwasm", feature = "reqwest"))]
mod get;
#[cfg(any(feature = "reqwasm", feature = "reqwest"))]
use crate::get::_get;

pub const FILTERLISTS_API_URL: &str = "https://api.filterlists.com";

#[cfg(any(feature = "reqwasm", feature = "reqwest"))]
pub async fn get_filters() -> Result<Vec<Filter>, FilterListError> {
    _get::<Vec<Filter>>(&format!("{FILTERLISTS_API_URL}/lists")).await
}

#[cfg(any(feature = "reqwasm", feature = "reqwest"))]
/// Gets the details of the FilterList.
pub async fn get_filter_information(filter: FilterArgs) -> Result<FilterDetails, FilterListError> {
    let id = match filter {
        FilterArgs::U32(id) => id,
        FilterArgs::Filter(filter) => filter.id,
    };
    _get::<FilterDetails>(&format!("{FILTERLISTS_API_URL}/lists/{id}")).await
}

#[cfg(any(feature = "reqwasm", feature = "reqwest"))]
/// Gets the syntaxes of the FilterLists.
pub async fn get_syntaxes() -> Result<Vec<FilterListSyntax>, FilterListError> {
    _get::<Vec<FilterListSyntax>>(&format!("{FILTERLISTS_API_URL}/syntaxes")).await
}

#[cfg(any(feature = "reqwasm", feature = "reqwest"))]
/// Gets the licenses applied to the FilterLists.
pub async fn get_licenses() -> Result<Vec<FilterLicense>, FilterListError> {
    _get::<Vec<FilterLicense>>(&format!("{FILTERLISTS_API_URL}/licenses")).await
}

#[cfg(any(feature = "reqwasm", feature = "reqwest"))]
/// Gets the software that subscribes to the FilterLists.
pub async fn get_software_list() -> Result<Vec<FilterSoftware>, FilterListError> {
    _get::<Vec<FilterSoftware>>(&format!("{FILTERLISTS_API_URL}/software")).await
}

#[cfg(any(feature = "reqwasm", feature = "reqwest"))]
/// Gets the languages targeted by the FilterLists.
pub async fn get_languages() -> Result<Vec<FilterLanguage>, FilterListError> {
    _get::<Vec<FilterLanguage>>(&format!("{FILTERLISTS_API_URL}/languages")).await
}

#[cfg(any(feature = "reqwasm", feature = "reqwest"))]
/// Gets the tags of the FilterLists.
pub async fn get_tags() -> Result<Vec<FilterTag>, FilterListError> {
    _get::<Vec<FilterTag>>(&format!("{FILTERLISTS_API_URL}/tags")).await
}

#[cfg(any(feature = "reqwasm", feature = "reqwest"))]
/// Gets the maintainers of the FilterLists.
pub async fn get_maintainers() -> Result<Vec<FilterMaintainer>, FilterListError> {
    _get::<Vec<FilterMaintainer>>(&format!("{FILTERLISTS_API_URL}/maintainers")).await
}
