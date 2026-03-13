//! OAuthFlow state machine — orchestrates discovery, registration, auth, and token exchange.

use crate::discovery::discover_oauth_metadata;
use crate::exchange::exchange_code;
use crate::pkce::{generate_code_verifier, pkce_challenge_s256};
use crate::redirect::OAuthRedirectHandler;
use crate::registration::register_client;
use crate::types::{AppInfo, OAuthError, OAuthMetadata, TokenSet};

/// Orchestrates the full OAuth authorization flow.
pub struct OAuthFlow {
    metadata: OAuthMetadata,
    client_id: String,
    pkce_verifier: String,
    state: String,
    redirect_uri: String,
    resource: String,
    scope: String,
}

impl OAuthFlow {
    /// Discover OAuth metadata and register a client.
    ///
    /// `resource_url` is the protected resource endpoint (e.g. a JMAP session URL).
    /// `scope` is the OAuth scope to request (e.g. `"urn:ietf:params:oauth:scope:mail"`).
    pub async fn discover_and_register(
        resource_url: &str,
        app_info: &AppInfo,
        scope: &str,
    ) -> Result<Self, OAuthError> {
        log::info!("Starting OAuth discovery for {resource_url}");
        let metadata = discover_oauth_metadata(resource_url).await?;
        log::info!("Discovered OAuth issuer: {}", metadata.issuer);

        let registration = register_client(&metadata, app_info, scope).await?;
        log::info!("Registered client: {}", registration.client_id);

        let pkce_verifier = generate_code_verifier();
        let state = generate_code_verifier(); // reuse verifier generation for state param

        Ok(Self {
            client_id: registration.client_id,
            resource: resource_url.to_string(),
            redirect_uri: app_info.redirect_uri.clone(),
            pkce_verifier,
            state,
            metadata,
            scope: scope.to_string(),
        })
    }

    /// Build the authorization URL to open in the user's browser.
    pub fn authorization_url(&self) -> String {
        let challenge = pkce_challenge_s256(&self.pkce_verifier);
        format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&state={}&code_challenge={}&code_challenge_method=S256&scope={}&resource={}",
            self.metadata.authorization_endpoint,
            urlencod(&self.client_id),
            urlencod(&self.redirect_uri),
            urlencod(&self.state),
            urlencod(&challenge),
            urlencod(&self.scope),
            urlencod(&self.resource),
        )
    }

    /// Complete the flow: open browser, wait for redirect, exchange code.
    pub async fn authorize(
        &self,
        handler: &impl OAuthRedirectHandler,
    ) -> Result<TokenSet, OAuthError> {
        let url = self.authorization_url();
        handler.open_browser(&url)?;

        log::debug!("OAuth: waiting for browser redirect...");
        let (code, state) = handler.wait_for_redirect().await?;
        log::debug!("OAuth: received code ({} chars), verifying state", code.len());

        if state != self.state {
            log::error!("OAuth: state mismatch");
            return Err(OAuthError::StateMismatch {
                expected: self.state.clone(),
                actual: state,
            });
        }

        log::info!("OAuth: exchanging authorization code for tokens");
        let token_set = exchange_code(
            &self.metadata.token_endpoint,
            &self.client_id,
            &code,
            &self.redirect_uri,
            &self.pkce_verifier,
        )
        .await?;

        log::info!("OAuth: token exchange successful");
        Ok(token_set)
    }

    /// Accessors for storing OAuth config after successful auth.
    pub fn issuer(&self) -> &str {
        &self.metadata.issuer
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn resource(&self) -> &str {
        &self.resource
    }

    pub fn token_endpoint(&self) -> &str {
        &self.metadata.token_endpoint
    }

    pub fn state(&self) -> &str {
        &self.state
    }

    pub fn pkce_verifier(&self) -> &str {
        &self.pkce_verifier
    }

    pub fn scope(&self) -> &str {
        &self.scope
    }
}

/// Minimal percent-encoding for URL query parameters.
fn urlencod(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(b as char);
            }
            _ => {
                result.push('%');
                result.push(char::from(HEX[(b >> 4) as usize]));
                result.push(char::from(HEX[(b & 0x0f) as usize]));
            }
        }
    }
    result
}

const HEX: [u8; 16] = *b"0123456789ABCDEF";
