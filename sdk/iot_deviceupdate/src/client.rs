use azure_core::{
    auth::{AccessToken, TokenCredential},
    error::{Error, ErrorKind, ResultExt},
    from_json, Url,
};
use const_format::formatcp;
use reqwest::{RequestBuilder, StatusCode};
use serde::de::DeserializeOwned;
use std::sync::Arc;

pub(crate) const API_VERSION: &str = "2022-10-01";
pub(crate) const API_VERSION_PARAM: &str = formatcp!("api-version={}", API_VERSION);

/// Client for Device Update operations - import, list and delete updates
///
/// # Example
///
/// ```no_run
/// use azure_iot_deviceupdate::DeviceUpdateClient;
/// let credential = azure_identity::create_credential().unwrap();
/// let client = DeviceUpdateClient::new("contoso.api.adu.microsoft.com", credential).unwrap();
/// ```

#[derive(Clone)]
pub struct DeviceUpdateClient {
    pub(crate) device_update_url: Url,
    pub(crate) token_credential: Arc<dyn TokenCredential>,
}

impl DeviceUpdateClient {
    /// Creates a new `DeviceUpdateClient`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use azure_iot_deviceupdate::DeviceUpdateClient;
    /// let credential = azure_identity::create_credential().unwrap();
    /// let client = DeviceUpdateClient::new("contoso.api.adu.microsoft.com", credential).unwrap();
    /// ```
    pub fn new(
        device_update_url: &str,
        token_credential: Arc<dyn TokenCredential>,
    ) -> azure_core::Result<Self> {
        let device_update_url = Url::parse(device_update_url)
            .with_context(ErrorKind::DataConversion, || {
                format!("failed to parse update url: {device_update_url}")
            })?;

        let client = DeviceUpdateClient {
            device_update_url,
            token_credential,
        };
        Ok(client)
    }

    async fn get_token(&self) -> azure_core::Result<AccessToken> {
        self.token_credential
            .get_token(&["https://api.adu.microsoft.com/.default"])
            .await
            .context(ErrorKind::Credential, "get token failed")
    }

    async fn request_with_operation_location(
        &self,
        req: RequestBuilder,
        uri: &Url,
    ) -> azure_core::Result<String> {
        let resp = req.send().await.with_context(ErrorKind::Io, || {
            format!("failed to send request. uri: {uri}")
        })?;

        if resp.status() == StatusCode::ACCEPTED {
            let headers = resp.headers();
            return match headers.get("operation-location") {
                Some(location) => location.to_str().map(ToString::to_string).context(
                    ErrorKind::Other,
                    "invalid characters in operation-location path",
                ),
                None => Err(Error::message(
                    ErrorKind::Other,
                    "successful (202 status) but no operation-location header found",
                )),
            };
        }

        Err(Error::with_message(ErrorKind::Other, || {
            format!("unsuccessful, status: {}", resp.status())
        }))
    }

    pub(crate) async fn get<R>(&self, uri: String) -> azure_core::Result<R>
    where
        R: DeserializeOwned,
    {
        let resp = reqwest::Client::new()
            .get(&uri)
            .bearer_auth(self.get_token().await?.token.secret())
            .send()
            .await
            .with_context(ErrorKind::Io, || {
                format!("failed to send request. uri: {uri}")
            })?;

        let body = resp.bytes().await.with_context(ErrorKind::Io, || {
            format!("failed to read response body text. uri: {uri}")
        })?;
        from_json(&body)
    }

    pub(crate) async fn post(
        &self,
        uri: &Url,
        json_body: Option<String>,
    ) -> azure_core::Result<String> {
        let mut req = reqwest::Client::new()
            .post(uri.as_str())
            .bearer_auth(self.get_token().await?.token.secret());

        if let Some(body) = json_body {
            req = req.header("content-type", "application/json").body(body);
        } else {
            req = req.header("content-length", 0);
        }

        self.request_with_operation_location(req, uri).await
    }

    pub(crate) async fn delete(&self, uri: &Url) -> azure_core::Result<String> {
        let req = reqwest::Client::new()
            .delete(uri.as_str())
            .bearer_auth(self.get_token().await?.token.secret())
            .header("content-type", "application/json");

        self.request_with_operation_location(req, uri).await
    }
}
