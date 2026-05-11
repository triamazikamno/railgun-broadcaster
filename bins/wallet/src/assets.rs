use std::borrow::Cow;

use gpui::{AssetSource, Result, SharedString};
use gpui_component::IconNamed;

pub(crate) const LOGO_ICON_PATH: &str = "railgun/icons/logo.svg";
const ARROW_BIG_RIGHT_DASH_ICON_PATH: &str = "railgun/icons/arrow-big-right-dash.svg";
const WALLET_ICON_PATH: &str = "railgun/icons/wallet.svg";
const BROADCASTER_ICON_PATH: &str = "railgun/icons/robot.svg";
const LOGS_ICON_PATH: &str = "railgun/icons/logs.svg";

const RAILGUN_ICON_PATHS: &[&str] = &[
    LOGO_ICON_PATH,
    ARROW_BIG_RIGHT_DASH_ICON_PATH,
    WALLET_ICON_PATH,
    BROADCASTER_ICON_PATH,
    LOGS_ICON_PATH,
];

const LOGO_ICON_BYTES: &[u8] = include_bytes!("../assets/icons/logo.svg");
const ARROW_BIG_RIGHT_DASH_ICON_BYTES: &[u8] =
    include_bytes!("../assets/icons/arrow-big-right-dash.svg");
const WALLET_ICON_BYTES: &[u8] = include_bytes!("../../../crates/ui/assets/icons/wallet.svg");
const BROADCASTER_ICON_BYTES: &[u8] = include_bytes!("../../../crates/ui/assets/icons/robot.svg");
const LOGS_ICON_BYTES: &[u8] = include_bytes!("../../../crates/ui/assets/icons/logs.svg");

pub(crate) struct WalletAssets;

impl AssetSource for WalletAssets {
    fn load(&self, path: &str) -> Result<Option<Cow<'static, [u8]>>> {
        if let Some(bytes) = railgun_asset(path) {
            return Ok(Some(Cow::Borrowed(bytes)));
        }

        gpui_component_assets::Assets.load(path)
    }

    fn list(&self, path: &str) -> Result<Vec<SharedString>> {
        let mut assets = gpui_component_assets::Assets.list(path)?;
        assets.extend(
            RAILGUN_ICON_PATHS
                .iter()
                .filter(|asset| asset.starts_with(path))
                .map(|asset| SharedString::from(*asset)),
        );
        Ok(assets)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RailgunActionIcon {
    Send,
}

impl IconNamed for RailgunActionIcon {
    fn path(self) -> SharedString {
        match self {
            Self::Send => ARROW_BIG_RIGHT_DASH_ICON_PATH,
        }
        .into()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RailgunSidebarIcon {
    Wallet,
    Broadcaster,
    Logs,
}

impl IconNamed for RailgunSidebarIcon {
    fn path(self) -> SharedString {
        match self {
            Self::Wallet => WALLET_ICON_PATH,
            Self::Broadcaster => BROADCASTER_ICON_PATH,
            Self::Logs => LOGS_ICON_PATH,
        }
        .into()
    }
}

fn railgun_asset(path: &str) -> Option<&'static [u8]> {
    match path {
        LOGO_ICON_PATH => Some(LOGO_ICON_BYTES),
        ARROW_BIG_RIGHT_DASH_ICON_PATH => Some(ARROW_BIG_RIGHT_DASH_ICON_BYTES),
        WALLET_ICON_PATH => Some(WALLET_ICON_BYTES),
        BROADCASTER_ICON_PATH => Some(BROADCASTER_ICON_BYTES),
        LOGS_ICON_PATH => Some(LOGS_ICON_BYTES),
        _ => None,
    }
}
