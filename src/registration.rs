//! Dynamic client registration (RFC 7591).

use crate::types::{AppInfo, ClientRegistration, OAuthError, OAuthMetadata};

/// Register a public client with the authorization server.
///
/// `scope` is the OAuth scope to request (e.g. `"urn:ietf:params:oauth:scope:mail"`).
pub async fn register_client(
    metadata: &OAuthMetadata,
    app_info: &AppInfo,
    scope: &str,
) -> Result<ClientRegistration, OAuthError> {
    let payload = serde_json::json!({
        "redirect_uris": [&app_info.redirect_uri],
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "scope": scope,
        "client_name": &app_info.client_name,
        "client_uri": &app_info.client_uri,
        "software_id": &app_info.software_id,
        "software_version": &app_info.software_version,
    });

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    let resp = http
        .post(&metadata.registration_endpoint)
        .json(&payload)
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(OAuthError::Registration(format!(
            "HTTP {status}: {body}"
        )));
    }

    let body: serde_json::Value = resp.json().await.map_err(|e| {
        OAuthError::Registration(format!("Failed to parse registration response: {e}"))
    })?;

    let client_id = body
        .get("client_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            OAuthError::Registration("Missing client_id in registration response".into())
        })?
        .to_string();

    Ok(ClientRegistration { client_id })
}
