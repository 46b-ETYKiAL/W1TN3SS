//! The onion-connection seam — the **abstraction** every send path goes through.
//!
//! [`TorOnionTransport`](crate::TorOnionTransport) does not dial Arti directly;
//! it holds an [`OnionConnector`] and asks it for a duplex byte stream to the
//! onion endpoint. This module is the **port**: the connector trait, the stream
//! currency, and the non-identifying error helper — all pure and
//! in-process-testable. The production **adapter** that touches live Tor,
//! [`ArtiConnector`], lives in the sibling [`crate::arti_connector`] file so the
//! coverage gate can exclude exactly that one structurally-uncoverable surface
//! (ADR-0002). A test injects an in-memory connector backed by a
//! [`tokio::io::duplex`] pipe, so the entire spool-drain orchestration is
//! exercised offline, with no live `.onion`.
//!
//! Everything downstream of the stream is already transport-agnostic:
//! [`crate::http::post_envelope`] is generic over `AsyncRead + AsyncWrite` and
//! is duplex-tested in its own module. This seam closes the last gap.
//!
//! [`ArtiConnector`]: crate::arti_connector::ArtiConnector

use std::future::Future;
use std::pin::Pin;

use tokio::io::{AsyncRead, AsyncWrite};

use itasha_report_core::backend::SendError;

/// A bidirectional byte stream to the onion service.
///
/// The blanket impl below means **any** `AsyncRead + AsyncWrite + Unpin + Send`
/// type is already an `OnionStream` with no extra code: Arti's `DataStream`, a
/// `tokio::io::DuplexStream`, a TLS stream, … This is the object-safe currency
/// the [`OnionConnector`] hands back.
pub trait OnionStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + ?Sized> OnionStream for T {}

/// A boxed, owned [`OnionStream`] — what a connector yields on success.
pub type BoxedOnionStream = Box<dyn OnionStream>;

/// The boxed future an [`OnionConnector::connect`] returns. Hand-rolled (rather
/// than pulling the `async-trait` proc-macro) to keep the dependency/`cargo-vet`
/// surface minimal — the same rationale that hand-rolls the HTTP client.
pub type ConnectFuture<'a> =
    Pin<Box<dyn Future<Output = Result<BoxedOnionStream, SendError>> + Send + 'a>>;

/// The connection seam: open a duplex byte stream to `onion_address:onion_port`.
///
/// Implementors MUST surface only non-identifying errors (no onion address, no
/// circuit details) via [`SendError::Transport`] — the connector is the layer
/// that touches the endpoint, so it is the layer that must not leak it. Use
/// [`non_identifying`] to reduce an adapter error to its class.
pub trait OnionConnector: Send + Sync {
    /// Connect to the onion service and return a ready duplex stream.
    fn connect(&self, onion_address: &str, onion_port: u16) -> ConnectFuture<'_>;
}

/// Reduce an arbitrary error to a non-identifying single-line string (no URLs,
/// no host, no onion address). Keeps the error *class* for diagnostics without
/// leaking the endpoint.
pub(crate) fn non_identifying<E: std::fmt::Display>(_e: &E) -> &'static str {
    // We deliberately do NOT format the error: Arti errors can embed the onion
    // address / circuit details. The transport surfaces a class only.
    "tor transport error"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_identifying_never_leaks_input() {
        let s = non_identifying(&"connect to abcd1234.onion failed");
        assert_eq!(s, "tor transport error");
        assert!(!s.contains("onion"));
    }

    #[test]
    fn any_async_duplex_is_an_onion_stream() {
        // The blanket impl makes a plain in-memory duplex a `BoxedOnionStream`
        // with no glue — this is exactly what the test connector relies on.
        fn assert_boxable<T: OnionStream + 'static>(t: T) -> BoxedOnionStream {
            Box::new(t)
        }
        let (a, _b) = tokio::io::duplex(16);
        let boxed = assert_boxable(a);
        // `Box<dyn OnionStream>` must itself satisfy AsyncRead+AsyncWrite+Unpin
        // (so `post_envelope` can take `&mut` of it).
        fn requires_stream<S: AsyncRead + AsyncWrite + Unpin>(_s: &S) {}
        requires_stream(&boxed);
    }
}
