use std::path::PathBuf;

use reqwest::Url;
use structopt::StructOpt;
use wallet_ops::WalletNetworkMode;

const DEFAULT_DB_PATH: &str = "db";

#[derive(Clone, StructOpt)]
#[structopt(name = "wallet", about = "Railgun wallet desktop GUI.")]
pub(crate) struct Options {
    #[structopt(long, default_value = DEFAULT_DB_PATH, parse(from_os_str))]
    pub(crate) db_path: PathBuf,

    /// Route wallet operation HTTP traffic through a proxy.
    #[structopt(long)]
    pub(crate) proxy: Option<Url>,

    /// Wallet network mode: tor (default), proxy, or direct.
    #[structopt(long, possible_values = &["tor", "proxy", "direct"])]
    pub(crate) network_mode: Option<WalletNetworkMode>,
}

impl Options {
    pub(crate) fn from_args() -> Self {
        <Self as StructOpt>::from_args()
    }
}
