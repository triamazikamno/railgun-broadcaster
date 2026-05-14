use std::path::PathBuf;

use directories::BaseDirs;
use reqwest::Url;
use structopt::StructOpt;
use wallet_ops::WalletNetworkMode;

const DEFAULT_DB_PATH: &str = "db";
const APP_DATA_DIR: &str = "RailOxide";

#[derive(Clone, StructOpt)]
#[structopt(name = "wallet", about = "Railgun wallet desktop GUI.")]
pub(crate) struct Options {
    #[structopt(long, parse(from_os_str))]
    pub(crate) db_path: Option<PathBuf>,

    /// Route wallet operation HTTP traffic through a proxy.
    #[structopt(long)]
    pub(crate) proxy: Option<Url>,

    /// Wallet network mode: tor (default), proxy, or direct.
    #[structopt(long, possible_values = &["tor", "proxy", "direct"])]
    pub(crate) network_mode: Option<WalletNetworkMode>,
}

pub(crate) fn default_db_path() -> PathBuf {
    BaseDirs::new().map_or_else(
        || PathBuf::from(DEFAULT_DB_PATH),
        |dirs| dirs.data_local_dir().join(APP_DATA_DIR),
    )
}

impl Options {
    pub(crate) fn from_args() -> Self {
        <Self as StructOpt>::from_args()
    }
}
