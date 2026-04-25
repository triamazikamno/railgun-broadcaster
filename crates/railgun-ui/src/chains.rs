use std::path::PathBuf;
use std::sync::LazyLock;

static CHAIN_ICON_DIR: LazyLock<PathBuf> =
    LazyLock::new(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets/chains"));

pub const DEFAULT_CHAINS: &[u64] = &[1, 56, 137, 42161];

const fn chain_icon_file(chain_id: u64) -> Option<&'static str> {
    match chain_id {
        1 => Some("ethereum.svg"),
        56 => Some("bsc.svg"),
        137 => Some("polygon.svg"),
        42161 => Some("arbitrum.svg"),
        _ => None,
    }
}

/// Human-readable name for a chain id. Returns `None` for any chain outside
/// the default app set so callers can decide whether to fall back to the
/// numeric id.
#[must_use]
pub const fn chain_name(chain_id: u64) -> Option<&'static str> {
    match chain_id {
        1 => Some("Ethereum"),
        56 => Some("BSC"),
        137 => Some("Polygon"),
        42161 => Some("Arbitrum"),
        _ => None,
    }
}

#[must_use]
pub fn chain_icon_path(chain_id: u64) -> Option<PathBuf> {
    chain_icon_file(chain_id).map(|file| CHAIN_ICON_DIR.join(file))
}
