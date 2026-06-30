//! Configuration for the Tor onion transport.
//!
//! Everything network-facing is **injected by the host** — the `.onion`
//! address and port are configuration, never hardcoded, so a mis-build cannot
//! phone home to an attacker endpoint (mirroring `report-core`'s
//! "no default endpoint" rule).

use std::path::PathBuf;
use std::time::Duration;

/// The size buckets the envelope body is padded up to (bytes), ascending.
///
/// Padding to a fixed bucket hides the true report size from an on-path size
/// observer — a near-unique stack-trace/minidump size can otherwise be matched
/// to a known crash (research §5, "Request size correlation"). A report larger
/// than the top bucket is sent un-padded (its size is already its own bucket).
pub const DEFAULT_PADDING_BUCKETS: &[usize] = &[
    4 * 1024,         // 4 KiB
    16 * 1024,        // 16 KiB
    64 * 1024,        // 64 KiB
    256 * 1024,       // 256 KiB
    1024 * 1024,      // 1 MiB
    4 * 1024 * 1024,  // 4 MiB
    16 * 1024 * 1024, // 16 MiB
];

/// Bounds for the randomized send-time jitter that decouples crash-time from
/// send-time (research §5, "Timing correlation").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JitterBounds {
    /// Minimum delay before a send attempt.
    pub min: Duration,
    /// Maximum delay before a send attempt. Must be `>= min`.
    pub max: Duration,
}

impl JitterBounds {
    /// Construct jitter bounds, clamping `max` up to `min` if mis-ordered so the
    /// range is always valid.
    #[must_use]
    pub fn new(min: Duration, max: Duration) -> Self {
        let max = if max < min { min } else { max };
        Self { min, max }
    }

    /// Jitter disabled — always an immediate send (used in deterministic tests
    /// and by hosts that spool+batch elsewhere).
    #[must_use]
    pub fn none() -> Self {
        Self {
            min: Duration::ZERO,
            max: Duration::ZERO,
        }
    }
}

impl Default for JitterBounds {
    /// Default: a uniform random delay in `[0, 60s]`. Fire-and-forget + the
    /// spool make this invisible to the user.
    fn default() -> Self {
        Self {
            min: Duration::ZERO,
            max: Duration::from_secs(60),
        }
    }
}

/// Retry policy for the background spool drain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Maximum attempts per report before it is left for a later drain pass.
    pub max_attempts: u32,
    /// Base backoff; attempt `n` waits `base * 2^(n-1)` (capped at `max_backoff`).
    pub base_backoff: Duration,
    /// Cap on the exponential backoff.
    pub max_backoff: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            base_backoff: Duration::from_secs(2),
            max_backoff: Duration::from_secs(300),
        }
    }
}

impl RetryPolicy {
    /// The backoff for a given (1-based) attempt number, capped at `max_backoff`.
    #[must_use]
    pub fn backoff_for(&self, attempt: u32) -> Duration {
        if attempt <= 1 {
            return self.base_backoff.min(self.max_backoff);
        }
        // base * 2^(attempt-1), saturating, capped.
        let shift = (attempt - 1).min(32);
        let factor = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
        let millis = self
            .base_backoff
            .as_millis()
            .saturating_mul(u128::from(factor));
        let capped = millis.min(self.max_backoff.as_millis());
        Duration::from_millis(capped.min(u128::from(u64::MAX)) as u64)
    }
}

/// Configuration for [`crate::TorOnionTransport`].
#[derive(Debug, Clone)]
pub struct TorTransportConfig {
    /// The v3 `.onion` hostname of the ingest service (host only, e.g.
    /// `"abcd…wxyz.onion"`). **No default** — the host must supply it.
    pub onion_address: String,
    /// The virtual port the onion service listens on (commonly `80`).
    pub onion_port: u16,
    /// The HTTP request path the envelope is POSTed to (e.g.
    /// `"/api/1/envelope/"`).
    pub request_path: String,
    /// Directory for Arti's persistent state (keystore, etc.). Persisting it
    /// speeds warm bootstraps. Holds the Tor consensus cache only — **not** a
    /// client identifier.
    pub state_dir: PathBuf,
    /// Directory for Arti's directory/consensus cache.
    pub cache_dir: PathBuf,
    /// Per-attempt connect/IO timeout.
    pub timeout: Duration,
    /// Maximum envelope size (before padding). Oversize is rejected.
    pub max_payload_bytes: usize,
    /// Send-time jitter bounds.
    pub jitter: JitterBounds,
    /// Body padding buckets (ascending). Empty disables padding.
    pub padding_buckets: Vec<usize>,
    /// Spool-drain retry policy.
    pub retry: RetryPolicy,
    /// Optional wall-clock budget for a SINGLE [`crate::TorOnionTransport::drain_spool`]
    /// pass. `None` (default) = unbounded: the pass processes every spooled
    /// report. `Some(d)` = the drain stops *starting* new reports once the pass
    /// has run for `d`, leaving the remainder spooled for the next pass. This
    /// bounds a pass against an unreachable onion (where each report can burn the
    /// full retry+timeout budget) so a large spool cannot turn one pass into a
    /// multi-hour run. The in-flight report always completes; the budget gates
    /// only whether the NEXT one starts.
    pub max_pass_duration: Option<Duration>,
}

impl TorTransportConfig {
    /// Construct a config for a config-injected onion endpoint with safe
    /// defaults. `state_dir`/`cache_dir` should live under the app's data dir.
    pub fn new(
        onion_address: impl Into<String>,
        onion_port: u16,
        state_dir: impl Into<PathBuf>,
        cache_dir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            onion_address: onion_address.into(),
            onion_port,
            request_path: "/api/1/envelope/".to_string(),
            state_dir: state_dir.into(),
            cache_dir: cache_dir.into(),
            timeout: Duration::from_secs(120),
            max_payload_bytes: 8 * 1024 * 1024,
            jitter: JitterBounds::default(),
            padding_buckets: DEFAULT_PADDING_BUCKETS.to_vec(),
            retry: RetryPolicy::default(),
            max_pass_duration: None,
        }
    }

    /// Override the request path.
    #[must_use]
    pub fn with_request_path(mut self, path: impl Into<String>) -> Self {
        self.request_path = path.into();
        self
    }

    /// Override the per-attempt timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Override the send-time jitter bounds.
    #[must_use]
    pub fn with_jitter(mut self, jitter: JitterBounds) -> Self {
        self.jitter = jitter;
        self
    }

    /// Override the body padding buckets (ascending; empty disables padding).
    #[must_use]
    pub fn with_padding_buckets(mut self, buckets: Vec<usize>) -> Self {
        self.padding_buckets = buckets;
        self
    }

    /// Override the max payload size (pre-padding).
    #[must_use]
    pub fn with_max_payload_bytes(mut self, cap: usize) -> Self {
        self.max_payload_bytes = cap;
        self
    }

    /// Override the retry policy.
    #[must_use]
    pub fn with_retry(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    /// Set a wall-clock budget for a single drain pass (see
    /// [`max_pass_duration`](Self::max_pass_duration)). `None` restores the
    /// unbounded default.
    #[must_use]
    pub fn with_max_pass_duration(mut self, budget: Option<Duration>) -> Self {
        self.max_pass_duration = budget;
        self
    }

    /// Validate that the onion address is structurally a v3 `.onion` host (56
    /// base32 chars + `.onion`). Cheap structural check — the real
    /// authentication is the onion key, enforced by Arti at connect time.
    #[must_use]
    pub fn is_valid_onion(&self) -> bool {
        let host = self.onion_address.trim();
        let Some(label) = host.strip_suffix(".onion") else {
            return false;
        };
        // v3 onion = 56 chars of lowercase base32 (a-z, 2-7).
        label.len() == 56
            && label
                .chars()
                .all(|c| c.is_ascii_lowercase() && c != '0' && c != '1' && c != '8' && c != '9')
            && label.chars().all(|c| matches!(c, 'a'..='z' | '2'..='7'))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_onion() -> String {
        // 56 lowercase base32 chars.
        "a".repeat(56) + ".onion"
    }

    #[test]
    fn config_has_no_default_endpoint() {
        let c = TorTransportConfig::new(valid_onion(), 80, "/state", "/cache");
        assert!(c.onion_address.ends_with(".onion"));
        assert_eq!(c.onion_port, 80);
        // Defaults are sane.
        assert_eq!(c.max_payload_bytes, 8 * 1024 * 1024);
        assert!(!c.padding_buckets.is_empty());
    }

    #[test]
    fn v3_onion_validation() {
        let good = TorTransportConfig::new(valid_onion(), 80, "/s", "/c");
        assert!(good.is_valid_onion());

        // Too short.
        let short = TorTransportConfig::new("abc.onion", 80, "/s", "/c");
        assert!(!short.is_valid_onion());

        // Not .onion.
        let clear = TorTransportConfig::new("evil.example.com", 80, "/s", "/c");
        assert!(!clear.is_valid_onion());

        // Uppercase / invalid base32 char.
        let bad = TorTransportConfig::new("A".repeat(56) + ".onion", 80, "/s", "/c");
        assert!(!bad.is_valid_onion());

        // base32 excludes 0/1/8/9.
        let with_digit = TorTransportConfig::new("0".repeat(56) + ".onion", 80, "/s", "/c");
        assert!(!with_digit.is_valid_onion());
    }

    #[test]
    fn jitter_clamps_misordered_bounds() {
        let j = JitterBounds::new(Duration::from_secs(10), Duration::from_secs(2));
        assert_eq!(j.min, Duration::from_secs(10));
        assert_eq!(j.max, Duration::from_secs(10)); // clamped up to min
    }

    #[test]
    fn jitter_none_is_zero() {
        let j = JitterBounds::none();
        assert_eq!(j.min, Duration::ZERO);
        assert_eq!(j.max, Duration::ZERO);
    }

    #[test]
    fn retry_backoff_is_exponential_and_capped() {
        let r = RetryPolicy {
            max_attempts: 10,
            base_backoff: Duration::from_secs(2),
            max_backoff: Duration::from_secs(60),
        };
        assert_eq!(r.backoff_for(1), Duration::from_secs(2));
        assert_eq!(r.backoff_for(2), Duration::from_secs(4));
        assert_eq!(r.backoff_for(3), Duration::from_secs(8));
        // Eventually capped at max_backoff.
        assert_eq!(r.backoff_for(20), Duration::from_secs(60));
    }
}
