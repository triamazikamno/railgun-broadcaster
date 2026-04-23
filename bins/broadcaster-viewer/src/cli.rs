use std::path::PathBuf;
use std::time::Duration;

use structopt::StructOpt;

pub(crate) const DEFAULT_CHAINS: &[u64] = &[1, 56, 137, 42161];

#[derive(Debug, Clone, StructOpt)]
#[structopt(
    name = "broadcaster-viewer",
    about = "Read-only GUI for monitoring Railgun broadcaster Waku traffic."
)]
#[allow(dead_code)] // trusted_signers / debug_log are parsed today; UI hooks land in a follow-up.
pub(crate) struct Options {
    /// Monitor fees for this chain ID. Repeat to monitor several chains.
    /// When omitted, the viewer monitors the default chain set
    /// (`1`, `56`, `137`, `42161`). Any explicit `--chain-id` replaces the
    /// defaults entirely.
    #[structopt(long = "chain-id")]
    pub(crate) chain_ids: Vec<u64>,

    /// Waku cluster ID.
    #[structopt(long = "cluster-id")]
    pub(crate) cluster_id: Option<u32>,

    /// DNS-over-HTTPS endpoint used for ENR discovery.
    #[structopt(long = "doh-endpoint")]
    pub(crate) doh_endpoint: Option<String>,

    /// Maximum number of Waku peers to connect to.
    #[structopt(long = "max-peers")]
    pub(crate) max_peers: Option<usize>,

    /// Peer connection / request timeout (e.g. `10s`, `500ms`).
    #[structopt(long = "peer-connection-timeout", parse(try_from_str = parse_duration))]
    pub(crate) peer_connection_timeout: Option<Duration>,

    /// Optional nwaku HTTP REST endpoint to poll alongside the internal Waku client.
    #[structopt(long = "nwaku-url")]
    pub(crate) nwaku_url: Option<String>,

    /// Annotate fees messages signed by this Railgun address as trusted.
    /// May be repeated. Trusted signers do NOT hide untrusted rows by default.
    #[structopt(long = "trusted-signer")]
    pub(crate) trusted_signers: Vec<String>,

    /// Enable debug-level logging for the viewer.
    #[structopt(long = "debug")]
    pub(crate) debug: bool,

    /// Optional explicit tracing filter directive (e.g.
    /// `info,waku=debug,broadcaster_viewer=trace`). Overrides `--debug`.
    #[structopt(long = "debug-level")]
    pub(crate) debug_level: Option<String>,

    /// Optional file to tee structured log output to.
    #[structopt(long = "debug-log", parse(from_os_str))]
    pub(crate) debug_log: Option<PathBuf>,

    /// Optional: bind a diagnostic HTTP server exposing `/debug/pprof/profile`
    /// for CPU flamegraph / pprof captures (e.g. `127.0.0.1:6060`). Off by
    /// default; pass the flag to enable when investigating render-loop cost.
    #[structopt(long = "pprof-listen")]
    pub(crate) pprof_listen: Option<String>,
}

impl Options {
    /// Parse CLI arguments using `StructOpt::from_args`.
    #[must_use]
    pub(crate) fn from_args() -> Self {
        <Self as StructOpt>::from_args()
    }

    /// Effective monitored chain set: explicit flags override the defaults
    /// entirely; the empty case falls back to [`DEFAULT_CHAINS`].
    #[must_use]
    pub(crate) fn effective_chain_ids(&self) -> Vec<u64> {
        if self.chain_ids.is_empty() {
            DEFAULT_CHAINS.to_vec()
        } else {
            self.chain_ids.clone()
        }
    }

    /// Effective tracing filter directive, given `--debug-level` / `--debug`.
    #[must_use]
    pub(crate) fn effective_debug_level(&self) -> String {
        if let Some(level) = &self.debug_level {
            return level.clone();
        }
        if self.debug {
            "debug,broadcaster_viewer=trace".to_string()
        } else {
            "info,broadcaster_viewer=debug,waku=info,waku_relay=info".to_string()
        }
    }
}

fn parse_duration(raw: &str) -> Result<Duration, humantime::DurationError> {
    humantime::parse_duration(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use structopt::StructOpt;

    #[test]
    fn default_chain_set_when_no_chain_id_flag() {
        let opts = Options::from_iter_safe(["broadcaster-viewer"]).unwrap();
        assert_eq!(opts.effective_chain_ids(), DEFAULT_CHAINS.to_vec());
    }

    #[test]
    fn explicit_single_chain_replaces_defaults() {
        let opts = Options::from_iter_safe(["broadcaster-viewer", "--chain-id", "10"]).unwrap();
        assert_eq!(opts.effective_chain_ids(), vec![10]);
    }

    #[test]
    fn explicit_multi_chain_replaces_defaults() {
        let opts = Options::from_iter_safe([
            "broadcaster-viewer",
            "--chain-id",
            "10",
            "--chain-id",
            "8453",
        ])
        .unwrap();
        assert_eq!(opts.effective_chain_ids(), vec![10, 8453]);
        assert!(!opts.effective_chain_ids().contains(&1));
    }

    #[test]
    fn peer_connection_timeout_parses_humantime() {
        let opts =
            Options::from_iter_safe(["broadcaster-viewer", "--peer-connection-timeout", "250ms"])
                .unwrap();
        assert_eq!(
            opts.peer_connection_timeout,
            Some(Duration::from_millis(250))
        );
    }

    #[test]
    fn debug_level_overrides_debug_flag() {
        let opts =
            Options::from_iter_safe(["broadcaster-viewer", "--debug", "--debug-level", "trace"])
                .unwrap();
        assert_eq!(opts.effective_debug_level(), "trace");
    }
}
