use std::path::PathBuf;

use eyre::{Result, eyre};
use railgun_ui::DEFAULT_CHAINS;
use reqwest::Url;
use structopt::StructOpt;

const DEFAULT_DB_PATH: &str = "db";
const DEFAULT_INITIAL_CHAIN_ID: u64 = 1;

#[derive(Clone, StructOpt)]
#[structopt(name = "wallet", about = "Railgun wallet desktop GUI.")]
pub(crate) struct Options {
    #[structopt(long)]
    pub(crate) mnemonic: String,

    /// Initial selected wallet chain. All default chains remain available in the UI.
    #[structopt(long = "chain-id", default_value = "1")]
    pub(crate) chain_id: u64,

    #[structopt(long, default_value = DEFAULT_DB_PATH, parse(from_os_str))]
    pub(crate) db_path: PathBuf,

    #[structopt(long)]
    pub(crate) init_block_number: Option<u64>,

    /// Override the default RPC URL for the initially selected chain.
    #[structopt(long)]
    pub(crate) rpc_url: Option<Url>,

    /// Route wallet operation HTTP traffic through a proxy.
    #[structopt(long)]
    pub(crate) proxy: Option<Url>,
}

impl Options {
    pub(crate) fn from_args() -> Result<Self> {
        let opts = <Self as StructOpt>::from_args();
        if !is_default_chain(opts.chain_id) {
            return Err(eyre!(
                "unsupported initial chain id {}; supported chain ids: {:?}",
                opts.chain_id,
                DEFAULT_CHAINS
            ));
        }
        Ok(opts)
    }
}

#[must_use]
pub(crate) fn is_default_chain(chain_id: u64) -> bool {
    DEFAULT_CHAINS.contains(&chain_id)
}

#[allow(dead_code)]
pub(crate) const fn default_initial_chain_id() -> u64 {
    DEFAULT_INITIAL_CHAIN_ID
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_chain_set_accepts_supported_chains() {
        for chain_id in DEFAULT_CHAINS {
            assert!(is_default_chain(*chain_id));
        }
    }

    #[test]
    fn default_chain_set_rejects_unknown_chain() {
        assert!(!is_default_chain(10));
    }
}
