//! Authorization code exchange and token refresh (RFC 6749).

use crate::types::{OAuthError, TokenSet};

/// Exchange an authorization code for tokens.
pub async fn exchange_code(
    token_endpoint: &str,
    client_id: &str,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
) -> Result<TokenSet, OAuthError> {
    let params = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("code_verifier", code_verifier),
    ];

    send_token_request(token_endpoint, &params).await
}

/// Refresh an access token using a refresh token.
///
/// `scope` is the OAuth scope to request (e.g. `"urn:ietf:params:oauth:scope:mail"`).
/// `resource` must match the resource used during the original authorization
/// (RFC 8707 — required by servers that use resource indicators).
pub async fn refresh_access_token(
    token_endpoint: &str,
    client_id: &str,
    refresh_token: &str,
    scope: &str,
    resource: &str,
) -> Result<TokenSet, OAuthError> {
    let params = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
        ("scope", scope),
        ("resource", resource),
    ];

    send_token_request(token_endpoint, &params).await
}

async fn send_token_request(
    token_endpoint: &str,
    params: &[(&str, &str)],
) -> Result<TokenSet, OAuthError> {
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let resp = http
        .post(token_endpoint)
        .form(params)
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(OAuthError::Exchange(format!("HTTP {status}: {body}")));
    }

    let body: serde_json::Value = resp.json().await.map_err(|e| {
        OAuthError::Exchange(format!("Failed to parse token response: {e}"))
    })?;

    let access_token = body
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| OAuthError::Exchange("Missing access_token".into()))?
        .to_string();

    let refresh_token = body
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| OAuthError::Exchange("Missing refresh_token".into()))?
        .to_string();

    let expires_in = body
        .get("expires_in")
        .and_then(|v| v.as_u64())
        .unwrap_or(3600);

    let scope = body
        .get("scope")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Ok(TokenSet {
        access_token,
        refresh_token,
        expires_in,
        scope,
    })
}
