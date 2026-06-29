//! A minimal, hand-rolled HTTP/1.1 client over an arbitrary async byte stream.
//!
//! The Arti `DataStream` is `AsyncRead + AsyncWrite`; we speak HTTP/1.1 directly
//! over it rather than pulling `hyper`. The body is a known
//! Sentry-envelope blob and we only need the response **status code**, so the
//! full HTTP machinery is unnecessary — and hand-rolling lets us control every
//! request byte (the fixed-minimal-header hygiene requirement).
//!
//! The functions are generic over `AsyncRead + AsyncWrite + Unpin`, so they are
//! exercised in tests against an in-memory [`tokio::io::duplex`] pipe (no live
//! `.onion` needed).

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::hygiene::build_request_headers;

/// Outcome of an HTTP exchange, reduced to what the transport needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpOutcome {
    /// A 2xx status — the report was accepted.
    Accepted,
    /// A non-2xx status. Carries the code only (non-identifying).
    Rejected(u16),
}

/// HTTP-layer error (non-identifying messages only — never a URL or host).
#[derive(Debug)]
pub enum HttpError {
    /// Writing the request to the stream failed.
    Write(String),
    /// Reading/parsing the response failed.
    Read(String),
    /// The response status line was malformed.
    BadStatusLine,
}

impl std::fmt::Display for HttpError {
    // Plain copy with a retry expectation; no protocol jargon and no inner
    // stream-error detail. The inner reason stays on the variant for a host-side
    // log toggle.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpError::Write(_) => {
                f.write_str("The report could not be sent right now; it will be retried later.")
            }
            HttpError::Read(_) => f.write_str(
                "The report could not be delivered right now; it will be retried later.",
            ),
            HttpError::BadStatusLine => f.write_str(
                "The server gave an invalid response; the report will be retried later.",
            ),
        }
    }
}

impl std::error::Error for HttpError {}

/// Maximum response bytes we will read before giving up (the server reply is a
/// tiny ack; this caps a misbehaving/hostile peer).
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// POST `body` to `path` on `host` over the given async stream and return the
/// reduced [`HttpOutcome`]. Writes a fixed-minimal header set (no `User-Agent`,
/// no `Accept-*`), then reads the response and extracts the status code.
pub async fn post_envelope<S>(
    stream: &mut S,
    host: &str,
    path: &str,
    body: &[u8],
) -> Result<HttpOutcome, HttpError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let headers = build_request_headers(host, path, body.len());

    stream
        .write_all(&headers)
        .await
        .map_err(|e| HttpError::Write(e.kind().to_string()))?;
    stream
        .write_all(body)
        .await
        .map_err(|e| HttpError::Write(e.kind().to_string()))?;
    stream
        .flush()
        .await
        .map_err(|e| HttpError::Write(e.kind().to_string()))?;

    // Read up to the end of the status line (the first CRLF) — that's all we
    // need. We read in bounded chunks and stop at the first newline or the cap.
    let mut buf = Vec::with_capacity(256);
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| HttpError::Read(e.kind().to_string()))?;
        if n == 0 {
            break; // EOF
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(2).any(|w| w == b"\r\n") || buf.len() >= MAX_RESPONSE_BYTES {
            break;
        }
    }

    let code = parse_status_code(&buf)?;
    if (200..300).contains(&code) {
        Ok(HttpOutcome::Accepted)
    } else {
        Ok(HttpOutcome::Rejected(code))
    }
}

/// Parse the numeric status code from an HTTP/1.x status line
/// (`HTTP/1.1 200 OK`). Only the first line is inspected.
pub fn parse_status_code(response: &[u8]) -> Result<u16, HttpError> {
    let line_end = response
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(response.len());
    let line = &response[..line_end];
    let text = std::str::from_utf8(line).map_err(|_| HttpError::BadStatusLine)?;
    let mut parts = text.split_whitespace();
    let version = parts.next().ok_or(HttpError::BadStatusLine)?;
    if !version.starts_with("HTTP/") {
        return Err(HttpError::BadStatusLine);
    }
    let code_str = parts.next().ok_or(HttpError::BadStatusLine)?;
    code_str
        .parse::<u16>()
        .map_err(|_| HttpError::BadStatusLine)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    /// WS-036/037/038: `HttpError` Display carries plain copy with a retry
    /// expectation, no protocol jargon, and no inner stream-error detail.
    #[test]
    fn http_error_display_is_plain_and_jargon_free() {
        let write = HttpError::Write("connection reset (os error 104)".to_string());
        let read = HttpError::Read("broken pipe at /tmp/sock".to_string());
        let bad = HttpError::BadStatusLine;
        assert_eq!(
            format!("{write}"),
            "The report could not be sent right now; it will be retried later."
        );
        assert_eq!(
            format!("{read}"),
            "The report could not be delivered right now; it will be retried later."
        );
        assert_eq!(
            format!("{bad}"),
            "The server gave an invalid response; the report will be retried later."
        );
        for err in [&write, &read] {
            let shown = format!("{err}");
            assert!(!shown.contains("os error"), "errno leaked: {shown}");
            assert!(!shown.contains('/'), "path separator leaked: {shown}");
            assert!(!shown.contains("http "), "protocol jargon leaked: {shown}");
        }
    }

    #[test]
    fn parses_2xx_status() {
        assert_eq!(parse_status_code(b"HTTP/1.1 200 OK\r\n").unwrap(), 200);
        assert_eq!(
            parse_status_code(b"HTTP/1.1 204 No Content\r\n").unwrap(),
            204
        );
    }

    #[test]
    fn parses_non_2xx_status() {
        assert_eq!(
            parse_status_code(b"HTTP/1.1 413 Too Large\r\n").unwrap(),
            413
        );
        assert_eq!(parse_status_code(b"HTTP/1.0 500 Err\r\n").unwrap(), 500);
    }

    #[test]
    fn rejects_malformed_status_line() {
        assert!(matches!(
            parse_status_code(b"GARBAGE\r\n"),
            Err(HttpError::BadStatusLine)
        ));
        assert!(matches!(
            parse_status_code(b"HTTP/1.1 notanumber OK\r\n"),
            Err(HttpError::BadStatusLine)
        ));
    }

    #[tokio::test]
    async fn post_writes_exact_request_bytes_and_reads_status() {
        // A loopback duplex pipe stands in for the Arti DataStream.
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);

        let body = b"{ENVELOPE-BYTES}";
        let host = "abcd1234.onion";
        let path = "/api/1/envelope/";

        // Server task: read the full request, assert the framing, reply 200.
        let server_task = tokio::spawn(async move {
            let mut got = Vec::new();
            let mut chunk = [0u8; 1024];
            // Read until we have headers + body (body length known = 16).
            loop {
                let n = server.read(&mut chunk).await.unwrap();
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&chunk[..n]);
                if got.windows(4).any(|w| w == b"\r\n\r\n") && got.ends_with(b"{ENVELOPE-BYTES}") {
                    break;
                }
            }
            // Reply.
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            server.flush().await.unwrap();
            got
        });

        let outcome = post_envelope(&mut client, host, path, body).await.unwrap();
        assert_eq!(outcome, HttpOutcome::Accepted);

        let request = server_task.await.unwrap();
        let req_str = String::from_utf8(request).unwrap();
        // Exact framing assertions (the hygiene contract on the wire).
        assert!(req_str.starts_with("POST /api/1/envelope/ HTTP/1.1\r\n"));
        assert!(req_str.contains("Host: abcd1234.onion\r\n"));
        assert!(req_str.contains("Content-Type: application/x-sentry-envelope\r\n"));
        assert!(req_str.contains("Content-Length: 16\r\n"));
        assert!(req_str.ends_with("{ENVELOPE-BYTES}"));
        // No fingerprint headers on the wire.
        let lower = req_str.to_lowercase();
        assert!(!lower.contains("user-agent"));
        assert!(!lower.contains("accept-encoding"));
    }

    #[tokio::test]
    async fn post_maps_non_2xx_to_rejected() {
        let (mut client, mut server) = tokio::io::duplex(8 * 1024);
        let server_task = tokio::spawn(async move {
            let mut chunk = [0u8; 1024];
            // Drain a bit of the request, then reply 413.
            let _ = server.read(&mut chunk).await.unwrap();
            server
                .write_all(b"HTTP/1.1 413 Payload Too Large\r\n\r\n")
                .await
                .unwrap();
            server.flush().await.unwrap();
        });
        let outcome = post_envelope(&mut client, "x.onion", "/p", b"data")
            .await
            .unwrap();
        assert_eq!(outcome, HttpOutcome::Rejected(413));
        server_task.await.unwrap();
    }
}
