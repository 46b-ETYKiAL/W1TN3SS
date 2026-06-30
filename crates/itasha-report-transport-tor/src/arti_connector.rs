//! [`ArtiConnector`] — the production [`OnionConnector`] backed by embedded Arti.
//!
//! This file is the **adapter** half of the connector seam: it is the one place
//! that touches the live Tor network (bootstrap the embedded Arti client, dial a
//! v3 `.onion`). It is the only structurally-uncoverable surface in the crate —
//! `tor_client` and `connect` need a real Tor directory consensus + a live onion
//! rendezvous that no in-process, network-free test can drive — so it is the
//! file the coverage gate excludes (ADR-0002). The seam abstraction it
//! implements, and everything downstream of the returned stream, stays in the
//! measured surface ([`crate::connector`], [`crate::http`], [`crate::transport`]).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use itasha_report_core::backend::SendError;

use crate::connector::{non_identifying, BoxedOnionStream, ConnectFuture, OnionConnector};

/// Opaque handle to the embedded Arti client (kept behind an alias so the
/// public API never leaks Arti types).
type ArtiHandle = arti_client::TorClient<tor_rtcompat::PreferredRuntime>;

/// The production [`OnionConnector`]: an embedded, in-process Arti (pure-Rust
/// Tor) client dialing a v3 `.onion`.
///
/// The client is bootstrapped lazily (`OnDemand`) on the first connect and
/// cached behind an `Arc<Mutex<…>>` so subsequent drains reuse the warm
/// directory consensus. `TorClient` is not `Clone`, hence the shared `Arc`.
#[derive(Clone)]
pub struct ArtiConnector {
    state_dir: PathBuf,
    cache_dir: PathBuf,
    tor: Arc<tokio::sync::Mutex<Option<Arc<ArtiHandle>>>>,
}

impl std::fmt::Debug for ArtiConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArtiConnector")
            .field("state_dir", &self.state_dir)
            .field("cache_dir", &self.cache_dir)
            .finish_non_exhaustive()
    }
}

impl ArtiConnector {
    /// Construct the connector rooted at the app's Arti `state`/`cache` dirs.
    /// Persisting these speeds warm bootstraps; they hold the Tor consensus
    /// cache only — never a client identifier.
    #[must_use]
    pub fn new(state_dir: impl Into<PathBuf>, cache_dir: impl Into<PathBuf>) -> Self {
        Self {
            state_dir: state_dir.into(),
            cache_dir: cache_dir.into(),
            tor: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    /// Lazily bootstrap (or reuse) the embedded Arti client. The first call
    /// builds it with `OnDemand` bootstrap behaviour; subsequent calls reuse the
    /// cached handle.
    async fn tor_client(&self) -> Result<Arc<ArtiHandle>, SendError> {
        let mut guard = self.tor.lock().await;
        if let Some(client) = guard.as_ref() {
            return Ok(Arc::clone(client));
        }
        let cfg = build_arti_config(&self.state_dir, &self.cache_dir)?;
        let client = arti_client::TorClient::builder()
            .config(cfg)
            .bootstrap_behavior(arti_client::BootstrapBehavior::OnDemand)
            .create_unbootstrapped()
            .map_err(|e| SendError::Transport(format!("arti init: {}", non_identifying(&e))))?;
        // `create_unbootstrapped` already yields an `Arc<TorClient>`.
        *guard = Some(Arc::clone(&client));
        Ok(client)
    }
}

impl OnionConnector for ArtiConnector {
    fn connect(&self, onion_address: &str, onion_port: u16) -> ConnectFuture<'_> {
        // The address is owned into the future so its lifetime is independent of
        // the caller's borrow once `connect` returns.
        let addr = onion_address.to_string();
        Box::pin(async move {
            let client = self.tor_client().await?;
            let stream = client
                .connect((addr.as_str(), onion_port))
                .await
                .map_err(|e| {
                    SendError::Transport(format!("onion connect: {}", non_identifying(&e)))
                })?;
            Ok(Box::new(stream) as BoxedOnionStream)
        })
    }
}

/// Build the Arti `TorClientConfig` pointing storage at the app's state/cache
/// dirs. Persisting the consensus cache makes warm bootstraps fast.
fn build_arti_config(
    state_dir: &Path,
    cache_dir: &Path,
) -> Result<arti_client::TorClientConfig, SendError> {
    arti_client::config::TorClientConfigBuilder::from_directories(state_dir, cache_dir)
        .build()
        .map_err(|e| SendError::Transport(format!("arti config: {}", non_identifying(&e))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_does_not_leak_an_endpoint() {
        let c = ArtiConnector::new("/tmp/state", "/tmp/cache");
        let dbg = format!("{c:?}");
        assert!(dbg.contains("ArtiConnector"));
        // The connector holds no onion address — it is supplied per-connect, so
        // a debug print of a long-lived connector can never leak the endpoint.
        assert!(!dbg.contains(".onion"));
    }

    #[test]
    fn build_arti_config_accepts_dirs() {
        let dir = std::env::temp_dir().join("w1tn3ss-arti-cfg-test");
        let cfg = build_arti_config(&dir.join("state"), &dir.join("cache"));
        assert!(cfg.is_ok());
    }
}
