use std::path::PathBuf;

use reqwest::Url;
use structopt::StructOpt;

const DEFAULT_DB_PATH: &str = "db";

#[derive(Clone, StructOpt)]
#[structopt(name = "wallet", about = "Railgun wallet desktop GUI.")]
pub(crate) struct Options {
    #[structopt(long, default_value = DEFAULT_DB_PATH, parse(from_os_str))]
    pub(crate) db_path: PathBuf,

    /// Route wallet operation HTTP traffic through a proxy.
    #[structopt(long)]
    pub(crate) proxy: Option<Url>,
}

impl Options {
    pub(crate) fn from_args() -> Self {
        <Self as StructOpt>::from_args()
    }
}
