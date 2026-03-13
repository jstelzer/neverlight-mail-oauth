//! OAuth type definitions.

use serde::{Deserialize, Serialize};

/// OAuth authorization server metadata (RFC 8414).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthMetadata {
    pub issuer: String,
    pub registration_endpoint: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub scopes_supported: Vec<String>,
    #[serde(default)]
    pub revocation_endpoint: Option<String>,
}

/// Result of dynamic client registration (RFC 7591).
#[derive(Debug, Clone)]
pub struct ClientRegistration {
    pub client_id: String,
}

/// Token set returned from authorization code exchange or refresh.
#[derive(Debug, Clone)]
pub struct TokenSet {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
    pub scope: String,
}

/// Application identity for dynamic client registration.
pub struct AppInfo {
    pub client_name: String,
    pub client_uri: String,
    pub software_id: String,
    pub software_version: String,
    pub redirect_uri: String,
}

/// Errors from the OAuth flow.
#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Discovery failed: {0}")]
    Discovery(String),
    #[error("Registration failed: {0}")]
    Registration(String),
    #[error("Token exchange failed: {0}")]
    Exchange(String),
    #[error("Redirect error: {0}")]
    Redirect(String),
    #[error("State mismatch: expected {expected}, got {actual}")]
    StateMismatch { expected: String, actual: String },
    #[error("Issuer mismatch: expected {expected}, got {actual}")]
    IssuerMismatch { expected: String, actual: String },
}
