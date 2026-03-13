# Code Conventions

When in doubt, the Rust Book is canon: https://doc.rust-lang.org/book/

---

## State as Nouns, Not Adjective Combos

The single most important convention in this codebase. Model states as **named enum variants with embedded context**, not as combinations of boolean flags and Option fields.

### The problem

```rust
// BAD: state is spread across multiple fields
struct Connection {
    session: Option<Session>,
    is_connected: bool,
    is_syncing: bool,
    last_error: Option<String>,
    retry_count: u32,
}

// BAD: every call site interrogates the same booleans
if self.is_connected {
    if let Some(session) = &self.session {
        if !self.is_syncing {
            // finally do something
        }
    }
}
```

This creates impossible states (`is_connected = true` but `session = None`), duplicates decision logic across call sites, and buries the actual state machine in scattered `if let` trees.

### The fix

```rust
// GOOD: each state is a noun that carries its own context
enum ConnectionState {
    Disconnected,
    Connecting { domain: String },
    Connected(Session),
    Syncing { session: Session, since: State },
    Error { message: String, retries: u32 },
}
```

**Each variant is a named thing.** You can't be `Connected` without a `Session`. You can't be `Syncing` without a sync cursor. Invalid states are unrepresentable.

### Transitions are functions, not mutations

```rust
impl ConnectionState {
    fn on_event(self, event: Event) -> Self {
        match (self, event) {
            (Self::Connected(session), Event::SyncRequested) => {
                Self::Syncing {
                    since: session.last_state(),
                    session,
                }
            }
            (Self::Syncing { session, .. }, Event::SyncComplete(new_state)) => {
                Self::Connected(session.with_state(new_state))
            }
            (_, Event::Disconnected(reason)) => {
                Self::Error { message: reason, retries: 0 }
            }
            (state, _) => state,
        }
    }
}
```

Takes `self` by value, returns the next state. No mutation of Option fields. No boolean toggling. The compiler enforces that you handle every combination.

---

## `let-else` Over Nested `if let`

For linear "bail if this isn't what I expect" flows, use `let-else` (RFC 3137). This keeps the happy path at the left margin.

```rust
// BAD: nesting obscures the happy path
fn process(input: Option<&str>) -> Result<Output, Error> {
    if let Some(value) = input {
        if let Ok(parsed) = value.parse::<u64>() {
            if parsed > 0 {
                Ok(do_work(parsed))
            } else {
                Err(Error::InvalidInput("must be positive"))
            }
        } else {
            Err(Error::ParseFailed)
        }
    } else {
        Err(Error::MissingInput)
    }
}

// GOOD: flat, early returns, happy path is obvious
fn process(input: Option<&str>) -> Result<Output, Error> {
    let Some(value) = input else {
        return Err(Error::MissingInput);
    };
    let Ok(parsed) = value.parse::<u64>() else {
        return Err(Error::ParseFailed);
    };
    if parsed == 0 {
        return Err(Error::InvalidInput("must be positive"));
    }
    Ok(do_work(parsed))
}
```

---

## Match Once at the Boundary

When you receive an enum, match it **once** at the entry point and dispatch to typed functions. Don't re-match or re-interrogate deeper in the call stack.

---

## Error Types

Use `thiserror` for error enums. Keep variants specific — not `Generic(String)` catch-alls.

At module boundaries where you cross from library errors to application errors, convert explicitly. Don't propagate `reqwest::Error` to consumers — wrap it in a domain error.

---

## Naming

Follow Rust standard conventions (https://rust-lang.github.io/api-guidelines/naming.html):

- Types: `PascalCase` — `OAuthFlow`, `TokenSet`, `AppInfo`
- Functions/methods: `snake_case` — `discover_oauth_metadata`, `refresh_access_token`
- Constants: `SCREAMING_SNAKE_CASE` — `HEX`
- Modules: `snake_case` — `discovery`, `exchange`, `redirect`

---

## Module Organization

Each module has a single responsibility. This crate is small enough that each module is a single file. If a module grows past ~400 lines, promote it to a directory module.

---

## Warnings Are Errors

Treat compiler warnings and clippy lints as defects. Fix them, don't suppress them.

- Do not add `#[allow(...)]` to silence warnings without discussion.
- Run `cargo clippy` before considering work done.
- Delete dead code. Git has history.

---

## Tests

Tests are not optional. New logic gets tests. Changed logic gets updated tests.

- Unit tests live in `#[cfg(test)] mod tests` at the bottom of each module.
- Each test function tests one behavior. Name it after what it asserts.
- Run `cargo test` before considering any change done.

---

## What Not to Do

- **No nested `if let` trees.** Use `let-else`, `match`, or early returns.
- **No boolean flags for state.** Use enums with context.
- **No `unwrap()` in library code.** Use `?`, `let-else`, or explicit error handling.
- **No `#[allow(...)]` without discussion.** Fix the warning or explain why.
- **No dead code.** Delete it. Git has history.
- **No duplicated logic.** Extract a pure function.
- **No speculative abstraction.** Don't add traits, generics, or configurability until there's a second consumer.
- **No `Clone` on large types just to avoid lifetime issues.** Rethink the data flow.
- **No untested code.** If it's worth writing, it's worth testing.
