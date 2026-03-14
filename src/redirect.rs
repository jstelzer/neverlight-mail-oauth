//! OAuth redirect handling — local HTTP server for desktop/TUI clients.

use crate::types::OAuthError;

/// Platform-specific OAuth redirect handling.
pub trait OAuthRedirectHandler: Send + Sync {
    /// The redirect URI to register with the OAuth server.
    fn redirect_uri(&self) -> String;

    /// Open the authorization URL in the system browser.
    fn open_browser(&self, url: &str) -> Result<(), OAuthError>;

    /// Wait for the authorization code from the redirect.
    /// Returns the `code` and `state` parameters.
    fn wait_for_redirect(
        &self,
    ) -> impl std::future::Future<Output = Result<(String, String), OAuthError>> + Send;
}

/// Local HTTP server redirect handler for desktop and TUI clients.
///
/// Binds to `127.0.0.1:0` (OS-assigned port), serves the redirect callback,
/// and extracts the authorization code from the query string.
pub struct LocalServerRedirect {
    listener: tokio::net::TcpListener,
    port: u16,
    app_name: String,
}

impl LocalServerRedirect {
    /// Create a new redirect handler, binding to an OS-assigned port.
    ///
    /// `app_name` is shown in the browser success page (e.g. "Neverlight Mail").
    pub async fn bind(app_name: &str) -> Result<Self, OAuthError> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| OAuthError::Redirect(format!("Failed to bind redirect listener: {e}")))?;

        let port = listener
            .local_addr()
            .map_err(|e| OAuthError::Redirect(format!("Failed to get local addr: {e}")))?
            .port();

        log::info!("OAuth redirect listener bound to 127.0.0.1:{port}");
        Ok(Self { listener, port, app_name: app_name.to_string() })
    }
}

impl OAuthRedirectHandler for LocalServerRedirect {
    fn redirect_uri(&self) -> String {
        format!("http://127.0.0.1:{}/callback", self.port)
    }

    fn open_browser(&self, url: &str) -> Result<(), OAuthError> {
        open::that(url).map_err(|e| OAuthError::Redirect(format!("Failed to open browser: {e}")))
    }

    async fn wait_for_redirect(&self) -> Result<(String, String), OAuthError> {
        let timeout = std::time::Duration::from_secs(120);

        tokio::time::timeout(timeout, async {
            loop {
                let (mut stream, addr) = self
                    .listener
                    .accept()
                    .await
                    .map_err(|e| OAuthError::Redirect(format!("Accept failed: {e}")))?;

                log::debug!("OAuth redirect: accepted connection from {addr}");

                let mut buf = vec![0u8; 4096];
                let n = tokio::io::AsyncReadExt::read(&mut stream, &mut buf)
                    .await
                    .map_err(|e| OAuthError::Redirect(format!("Read failed: {e}")))?;

                if n == 0 {
                    log::debug!("OAuth redirect: empty request, waiting for next connection");
                    continue;
                }

                let request = String::from_utf8_lossy(&buf[..n]);
                let first_line = request.lines().next().unwrap_or("");
                log::debug!("OAuth redirect: {first_line}");

                // Skip non-callback requests (favicon.ico, preflight, etc.)
                match parse_callback_query(&request) {
                    Ok((code, state)) => {
                        log::info!("OAuth redirect: received authorization code");

                        let response = format!(
                            "HTTP/1.1 200 OK\r\n\
                             Content-Type: text/html\r\n\
                             Connection: close\r\n\
                             \r\n\
                             <!DOCTYPE html><html><body>\
                             <h2>Authorization successful</h2>\
                             <p>You can close this tab and return to {}.</p>\
                             </body></html>",
                            html_escape(&self.app_name),
                        );
                        let _ = tokio::io::AsyncWriteExt::write_all(
                            &mut stream,
                            response.as_bytes(),
                        )
                        .await;
                        let _ = tokio::io::AsyncWriteExt::shutdown(&mut stream).await;

                        return Ok((code, state));
                    }
                    Err(_) => {
                        // Send 404 for non-callback requests and keep listening
                        let response = "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n";
                        let _ = tokio::io::AsyncWriteExt::write_all(
                            &mut stream,
                            response.as_bytes(),
                        )
                        .await;
                        let _ = tokio::io::AsyncWriteExt::shutdown(&mut stream).await;
                        log::debug!("OAuth redirect: non-callback request, waiting for next");
                        continue;
                    }
                }
            }
        })
        .await
        .map_err(|_| OAuthError::Redirect("Timed out waiting for browser authorization (120s)".into()))?
    }
}

/// Parse `code` and `state` from an HTTP GET request line's query string.
fn parse_callback_query(request: &str) -> Result<(String, String), OAuthError> {
    let first_line = request
        .lines()
        .next()
        .ok_or_else(|| OAuthError::Redirect("Empty request".into()))?;

    // "GET /callback?code=abc&state=xyz HTTP/1.1"
    let path = first_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| OAuthError::Redirect("Malformed request line".into()))?;

    let (path_part, query) = path
        .split_once('?')
        .ok_or_else(|| OAuthError::Redirect("No query string in callback".into()))?;

    if path_part != "/callback" {
        return Err(OAuthError::Redirect(format!(
            "Unexpected callback path: {path_part}"
        )));
    }

    let mut code = None;
    let mut state = None;

    for pair in query.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        match key {
            "code" => code = Some(url_decode(value)),
            "state" => state = Some(url_decode(value)),
            _ => {}
        }
    }

    let code = code.ok_or_else(|| OAuthError::Redirect("Missing 'code' parameter".into()))?;
    let state = state.ok_or_else(|| OAuthError::Redirect("Missing 'state' parameter".into()))?;

    Ok((code, state))
}

/// Decode percent-encoded URL query parameter values.
fn url_decode(s: &str) -> String {
    let mut result = Vec::with_capacity(s.len());
    let mut bytes = s.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let hi = bytes.next().and_then(hex_val);
            let lo = bytes.next().and_then(hex_val);
            if let (Some(h), Some(l)) = (hi, lo) {
                result.push(h << 4 | l);
            }
        } else if b == b'+' {
            result.push(b' ');
        } else {
            result.push(b);
        }
    }
    String::from_utf8(result).unwrap_or_else(|e| String::from_utf8_lossy(&e.into_bytes()).into_owned())
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Escape HTML special characters for safe interpolation into HTML content.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_callback_query() {
        let request = "GET /callback?code=abc123&state=xyz789&iss=https%3A%2F%2Fexample.com HTTP/1.1\r\nHost: 127.0.0.1:49152\r\n";
        let (code, state) = parse_callback_query(request).unwrap();
        assert_eq!(code, "abc123");
        assert_eq!(state, "xyz789");
    }

    #[test]
    fn decodes_percent_encoded_code() {
        let request = "GET /callback?code=a3da6f9f%3A4c264053%3ABUWSjR&state=xyz789 HTTP/1.1\r\n";
        let (code, state) = parse_callback_query(request).unwrap();
        assert_eq!(code, "a3da6f9f:4c264053:BUWSjR");
        assert_eq!(state, "xyz789");
    }

    #[test]
    fn rejects_missing_code() {
        let request = "GET /callback?state=xyz HTTP/1.1\r\n";
        assert!(parse_callback_query(request).is_err());
    }

    #[test]
    fn rejects_missing_query_string() {
        let request = "GET /callback HTTP/1.1\r\n";
        assert!(parse_callback_query(request).is_err());
    }

    #[test]
    fn rejects_wrong_path() {
        let request = "GET /other?code=abc&state=xyz HTTP/1.1\r\n";
        assert!(parse_callback_query(request).is_err());
    }

    #[test]
    fn html_escape_prevents_injection() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("A & B"), "A &amp; B");
    }
}
