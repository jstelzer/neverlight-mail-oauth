//! OAuth 2.0 for public mail clients (draft-ietf-mailmaint-oauth-public-02).
//!
//! Provider-agnostic implementation — no opinions about JMAP, IMAP, or any
//! specific mail protocol. Consumers supply their own scope, app identity,
//! and protected-resource URL.
//!
//! Implements:
//! - Protected resource metadata discovery (RFC 9728)
//! - Authorization server metadata discovery (RFC 8414)
//! - Dynamic client registration (RFC 7591)
//! - PKCE S256 (RFC 7636)
//! - Authorization code exchange + token refresh (RFC 6749)

mod discovery;
mod exchange;
mod flow;
mod pkce;
mod redirect;
mod registration;
mod types;

pub use discovery::discover_oauth_metadata;
pub use exchange::{exchange_code, refresh_access_token};
pub use flow::OAuthFlow;
pub use pkce::{generate_code_verifier, pkce_challenge_s256};
pub use redirect::{LocalServerRedirect, OAuthRedirectHandler};
pub use types::{AppInfo, ClientRegistration, OAuthError, OAuthMetadata, TokenSet};
