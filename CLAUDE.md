# Claude Context: neverlight-mail-oauth

**Last Updated:** 2026-03-13

## What This Is

Provider-agnostic OAuth 2.0 library for public mail clients. Implements draft-ietf-mailmaint-oauth-public (RFC 9728, 8414, 7591, 7636, 6749).

No opinions about JMAP, IMAP, or any specific mail protocol. Consumers supply their own scope, app identity, and protected-resource URL.

Licensed MIT/Apache-2.0.

## Read First

- `docs/code-conventions.md` — Code style, state modeling, error handling. **Follow this.**
- The Rust Book: https://doc.rust-lang.org/book/

## Crate Structure

```
neverlight-mail-oauth/
├── Cargo.toml
├── CLAUDE.md              — This file
├── README.md              — Usage docs and examples
├── docs/
│   └── code-conventions.md
└── src/
    ├── lib.rs             — Crate root, module declarations + re-exports
    ├── types.rs           — AppInfo, OAuthMetadata, TokenSet, OAuthError, ClientRegistration
    ├── discovery.rs       — RFC 9728 + RFC 8414 metadata discovery chain
    ├── registration.rs    — RFC 7591 dynamic client registration
    ├── pkce.rs            — RFC 7636 S256 code verifier + challenge
    ├── exchange.rs        — RFC 6749 authorization code exchange + token refresh
    ├── redirect.rs        — Local HTTP server for desktop/TUI OAuth callbacks
    └── flow.rs            — OAuthFlow state machine orchestrating the full flow
```

## Key Design Decisions

### Provider-agnostic, no protocol opinions

This crate knows nothing about JMAP, IMAP, or any mail protocol. The `resource_url` parameter is just a protected resource endpoint — consumers decide what it points to.

### Scope is a parameter, not a constant

The OAuth scope (e.g. `"urn:ietf:params:oauth:scope:mail"`) is passed by the consumer to `OAuthFlow::discover_and_register()`, `register_client()`, and `refresh_access_token()`. The library never hardcodes a scope.

### No Default for AppInfo

`AppInfo` has no `Default` impl. Consumers must provide all fields explicitly — client name, URI, software ID, version, and redirect URI. This prevents accidental use of another project's branding.

### No GUI dependencies

This crate must never depend on `libcosmic`, `iced`, or any GUI framework.

### No config knowledge

This crate does not read config files or environment variables. It accepts parameters and returns tokens. Config resolution is the consumer's responsibility.

## Dependencies

| Crate            | Purpose                                    |
|------------------|--------------------------------------------|
| reqwest          | HTTP transport (metadata, registration, token exchange) |
| serde/serde_json | JSON serialization for OAuth payloads      |
| sha2             | PKCE S256 code challenge                   |
| base64           | PKCE base64url encoding                    |
| rand             | Code verifier + state generation           |
| tokio            | Async runtime (TCP listener for redirects) |
| open             | Open authorization URL in system browser   |
| log              | Logging                                    |
| thiserror        | Error type derivation                      |

## Testing

```bash
cargo test -p neverlight-mail-oauth
```

Tests are unit tests only — PKCE vectors, URL parsing, redirect callback parsing, HTML escaping. No network access required.

## What to Avoid

- Adding any GUI dependency
- Hardcoding scopes, app names, or provider-specific behavior
- Adding config file or keyring logic — that belongs in consumers
- Nested `if let` trees — see `docs/code-conventions.md`
- Boolean flags to represent states — use enums with context
