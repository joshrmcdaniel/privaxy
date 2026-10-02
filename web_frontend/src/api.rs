use gloo_net::http::{Request, RequestBuilder, Response};
use serde::{de::DeserializeOwned, Serialize};

pub async fn response_error(response: Response) -> String {
    let status = response.status();
    response
        .json::<crate::ApiError>()
        .await
        .map(|error| error.error)
        .unwrap_or_else(|_| format!("HTTP {status}"))
}

pub async fn get_json<T: DeserializeOwned>(url: &str) -> Result<T, String> {
    let response = Request::get(url).send().await.map_err(|e| e.to_string())?;
    if !response.ok() {
        return Err(response_error(response).await);
    }
    response.json().await.map_err(|e| e.to_string())
}

pub async fn send_json<T: Serialize>(request: RequestBuilder, body: &T) -> Result<(), String> {
    let response = request
        .json(body)
        .map_err(|e| e.to_string())?
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !response.ok() {
        return Err(response_error(response).await);
    }
    Ok(())
}
