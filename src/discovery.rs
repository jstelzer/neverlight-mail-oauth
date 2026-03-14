//! OAuth metadata discovery per RFC 9728 (protected resource metadata)
//! and RFC 8414 (authorization server metadata).

use crate::types::{OAuthError, OAuthMetadata};

/// Discover OAuth authorization server metadata from a protected resource URL.
///
/// Discovery chain:
/// 1. GET `resource_url` without auth -> expect 401 with `WWW-Authenticate`
///    containing a `resource_metadata` URL
/// 2. GET that resource metadata URL -> extract `authorization_servers[0]`
/// 3. GET `{issuer}/.well-known/oauth-authorization-server` -> `OAuthMetadata`
pub async fn discover_oauth_metadata(resource_url: &str) -> Result<OAuthMetadata, OAuthError> {
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    // Step 1: Unauthenticated GET to discover resource metadata URL
    let resource_metadata_url = discover_resource_metadata_url(&http, resource_url).await?;

    // Step 2: Fetch protected resource metadata
    let issuer = fetch_resource_metadata(&http, &resource_metadata_url).await?;

    // Step 3: Fetch authorization server metadata
    fetch_as_metadata(&http, &issuer).await
}

/// Step 1: GET the resource URL without auth, parse `WWW-Authenticate` for resource metadata.
async fn discover_resource_metadata_url(
    http: &reqwest::Client,
    resource_url: &str,
) -> Result<String, OAuthError> {
    let resp = http
        .get(resource_url)
        .send()
        .await?;

    // We expect 401 Unauthorized with WWW-Authenticate header
    if resp.status() != reqwest::StatusCode::UNAUTHORIZED {
        return Err(OAuthError::Discovery(format!(
            "Expected 401 from unauthenticated resource request, got {}",
            resp.status()
        )));
    }

    let www_auth = resp
        .headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            OAuthError::Discovery("No WWW-Authenticate header in 401 response".into())
        })?;

    // Parse: Bearer resource_metadata="https://..."
    parse_resource_metadata_url(www_auth)
}

/// Parse `resource_metadata` from a `WWW-Authenticate: Bearer` header value.
fn parse_resource_metadata_url(www_auth: &str) -> Result<String, OAuthError> {
    // Look for resource_metadata="<url>" in the header value
    let needle = "resource_metadata=\"";
    let start = www_auth.find(needle).ok_or_else(|| {
        OAuthError::Discovery(format!(
            "WWW-Authenticate header missing resource_metadata: {www_auth}"
        ))
    })? + needle.len();

    let rest = &www_auth[start..];
    let end = rest.find('"').ok_or_else(|| {
        OAuthError::Discovery("Unterminated resource_metadata value".into())
    })?;

    Ok(rest[..end].to_string())
}

/// Step 2: Fetch protected resource metadata (RFC 9728), extract issuer.
async fn fetch_resource_metadata(
    http: &reqwest::Client,
    url: &str,
) -> Result<String, OAuthError> {
    let resp = http
        .get(url)
        .send()
        .await?;

    if !resp.status().is_success() {
        return Err(OAuthError::Discovery(format!(
            "Resource metadata HTTP {}",
            resp.status()
        )));
    }

    let body: serde_json::Value = resp.json().await?;

    let servers = body
        .get("authorization_servers")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            OAuthError::Discovery("Missing authorization_servers in resource metadata".into())
        })?;

    servers
        .first()
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            OAuthError::Discovery("Empty authorization_servers array".into())
        })
}

/// Step 3: Fetch authorization server metadata (RFC 8414).
///
/// Per RFC 8414 §3, the well-known URI is constructed by inserting
/// `/.well-known/oauth-authorization-server` after the host (and port),
/// followed by the issuer path. For example:
///   `https://example.com/oauth2/default` →
///   `https://example.com/.well-known/oauth-authorization-server/oauth2/default`
async fn fetch_as_metadata(
    http: &reqwest::Client,
    issuer: &str,
) -> Result<OAuthMetadata, OAuthError> {
    let url = build_as_metadata_url(issuer)?;

    let resp = http
        .get(&url)
        .send()
        .await?;

    if !resp.status().is_success() {
        return Err(OAuthError::Discovery(format!(
            "AS metadata HTTP {} from {url}",
            resp.status()
        )));
    }

    let metadata: OAuthMetadata = resp.json().await.map_err(|e| {
        OAuthError::Discovery(format!("Failed to parse AS metadata: {e}"))
    })?;

    // Validate issuer matches
    if metadata.issuer.trim_end_matches('/') != issuer.trim_end_matches('/') {
        return Err(OAuthError::IssuerMismatch {
            expected: issuer.to_string(),
            actual: metadata.issuer.clone(),
        });
    }

    Ok(metadata)
}

/// Build the RFC 8414 well-known URL for an issuer.
///
/// The well-known suffix is inserted between the authority and the issuer path:
///   `https://host/path` → `https://host/.well-known/oauth-authorization-server/path`
fn build_as_metadata_url(issuer: &str) -> Result<String, OAuthError> {
    let parsed = reqwest::Url::parse(issuer).map_err(|e| {
        OAuthError::Discovery(format!("Invalid issuer URL '{issuer}': {e}"))
    })?;

    let scheme = parsed.scheme();
    let host = parsed.host_str().ok_or_else(|| {
        OAuthError::Discovery(format!("Issuer URL has no host: {issuer}"))
    })?;
    let origin = match parsed.port() {
        Some(port) => format!("{scheme}://{host}:{port}"),
        None => format!("{scheme}://{host}"),
    };
    let path = parsed.path().trim_matches('/');

    if path.is_empty() {
        Ok(format!("{origin}/.well-known/oauth-authorization-server"))
    } else {
        Ok(format!("{origin}/.well-known/oauth-authorization-server/{path}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_resource_metadata_url_from_www_authenticate() {
        let header = r#"Bearer resource_metadata="https://api.fastmail.com/.well-known/oauth-protected-resource""#;
        let url = parse_resource_metadata_url(header).unwrap();
        assert_eq!(
            url,
            "https://api.fastmail.com/.well-known/oauth-protected-resource"
        );
    }

    #[test]
    fn parses_resource_metadata_with_extra_params() {
        let header = r#"Bearer realm="jmap", resource_metadata="https://example.com/meta", scope="mail""#;
        let url = parse_resource_metadata_url(header).unwrap();
        assert_eq!(url, "https://example.com/meta");
    }

    #[test]
    fn rejects_missing_resource_metadata() {
        let header = "Bearer realm=\"jmap\"";
        assert!(parse_resource_metadata_url(header).is_err());
    }

    #[test]
    fn builds_as_metadata_url_no_path() {
        let url = build_as_metadata_url("https://auth.example.com").unwrap();
        assert_eq!(url, "https://auth.example.com/.well-known/oauth-authorization-server");
    }

    #[test]
    fn builds_as_metadata_url_with_trailing_slash() {
        let url = build_as_metadata_url("https://auth.example.com/").unwrap();
        assert_eq!(url, "https://auth.example.com/.well-known/oauth-authorization-server");
    }

    #[test]
    fn builds_as_metadata_url_with_path() {
        let url = build_as_metadata_url("https://example.com/oauth2/default").unwrap();
        assert_eq!(
            url,
            "https://example.com/.well-known/oauth-authorization-server/oauth2/default"
        );
    }

    #[test]
    fn builds_as_metadata_url_with_port_and_path() {
        let url = build_as_metadata_url("https://example.com:8443/tenant/v2").unwrap();
        assert_eq!(
            url,
            "https://example.com:8443/.well-known/oauth-authorization-server/tenant/v2"
        );
    }
}
