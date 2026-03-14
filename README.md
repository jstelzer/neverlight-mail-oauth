# neverlight-mail-oauth

Provider-agnostic OAuth 2.0 library for public mail clients, implementing the [OAuth Profile for Open Public Clients](https://www.ietf.org/archive/id/draft-ietf-mailmaint-oauth-public-02.html) (draft-ietf-mailmaint-oauth-public).

Zero GUI dependencies. Built on [reqwest](https://crates.io/crates/reqwest) for HTTP transport.

## Standards

- RFC 9728 — Protected resource metadata discovery
- RFC 8414 — Authorization server metadata discovery
- RFC 7591 — Dynamic client registration
- RFC 7636 — PKCE S256
- RFC 6749 — Authorization code exchange + token refresh

## Usage

```toml
[dependencies]
neverlight-mail-oauth = { git = "https://github.com/jstelzer/neverlight-mail-oauth" }
```

## Re-exports

Core types are re-exported from the crate root:

```rust
use neverlight_mail_oauth::{
    OAuthFlow, OAuthError, OAuthMetadata,
    AppInfo, ClientRegistration, TokenSet,
    LocalServerRedirect, OAuthRedirectHandler,
    discover_oauth_metadata, exchange_code, refresh_access_token,
    generate_code_verifier, pkce_challenge_s256,
};
```

## Example

```rust
use neverlight_mail_oauth::{AppInfo, OAuthFlow, LocalServerRedirect};

let app_info = AppInfo {
    client_name: "My Mail Client".into(),
    client_uri: "https://example.com".into(),
    software_id: "com.example.mail".into(),
    software_version: "0.1.0".into(),
    redirect_uri: handler.redirect_uri(),
};

// Full flow: discover metadata, register client, authorize
let handler = LocalServerRedirect::bind("My Mail Client").await?;
let flow = OAuthFlow::discover_and_register(
    "https://api.fastmail.com/jmap/session",
    &app_info,
    "urn:ietf:params:oauth:scope:mail",
).await?;
let tokens = flow.authorize(&handler).await?;

// Later: refresh an expired access token.
// The server may omit a new refresh token (RFC 6749 §6) —
// fall back to the one you already have.
let current_refresh = tokens.refresh_token.as_deref()
    .expect("initial grant should include a refresh token");
let refreshed = neverlight_mail_oauth::refresh_access_token(
    flow.token_endpoint(),
    flow.client_id(),
    current_refresh,
    "urn:ietf:params:oauth:scope:mail",
    flow.resource(),
).await?;
let next_refresh = refreshed.refresh_token.as_deref()
    .unwrap_or(current_refresh);

```

## Modules

| Module | Purpose |
|---|---|
| `discovery` | RFC 9728 + RFC 8414 metadata discovery chain |
| `registration` | RFC 7591 dynamic client registration |
| `pkce` | RFC 7636 S256 code challenge generation |
| `exchange` | RFC 6749 authorization code exchange + token refresh |
| `redirect` | Local HTTP server for desktop/TUI OAuth callbacks |
| `flow` | `OAuthFlow` state machine orchestrating the full flow |
| `types` | `AppInfo`, `OAuthMetadata`, `TokenSet`, `OAuthError`, etc. |

## Consumers

- [neverlight-mail-core](https://github.com/jstelzer/neverlight-mail-core) — JMAP-native headless email engine

## License

MIT OR Apache-2.0
