#[cfg(all(feature = "reqwasm", feature = "reqwest"))]
compile_error!("feature \"reqwasm\" and \"reqwest\" cannot be enabled at the same time");

use crate::{FilterListAPIError, FilterListError};
macro_rules! if_wasm {
    ($($item:item)*) => {
        $(
            #[cfg(feature = "reqwasm")]
            $item
        )*
    };
}

macro_rules! if_reqwest {
    ($($item:item)*) => {
        $(
            #[cfg(feature = "reqwest")]
            $item
        )*
    };
}
if_wasm! {
    use reqwasm::http::Request;
    use serde::de::DeserializeOwned;

    pub(crate) async fn _get<T>(url: &str) -> Result<T, FilterListError>
    where
        T: DeserializeOwned,
    {
        let response = Request::get(url).send().await.map_err(|e| FilterListError::RequestError(e))?;
        let status = response.status();
        let body = response.text().await.map_err(|e| FilterListError::RequestError(e))?;

        if status == 200 {
            let data: T = serde_json::from_str(&body)?;
            Ok(data)
        } else {
            let error: FilterListAPIError = serde_json::from_str(&body)?;
            Err(FilterListError::APIError(error))
        }
    }
}

if_reqwest! {
    use reqwest_impersonate as reqwest;
    use serde::de::DeserializeOwned;

    pub(crate) async fn _get<T>(url: &str) -> Result<T, FilterListError>
    where
        T: DeserializeOwned,
    {
        let response = reqwest::get(url).await?;
        let status = response.status();
        let body = response.text().await?;

        if status.is_success() {
            let data: T = serde_json::from_str(&body)?;
            Ok(data)
        } else {
            let error: FilterListAPIError = serde_json::from_str(&body)?;
            Err(FilterListError::APIError(error))
        }
    }
}
