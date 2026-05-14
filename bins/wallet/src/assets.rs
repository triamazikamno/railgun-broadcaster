use std::borrow::Cow;

use gpui::{AssetSource, Result, SharedString};
use gpui_component::IconNamed;

pub(crate) const LOGO_ICON_PATH: &str = "railgun/icons/logo.svg";
pub(crate) const SIDEBAR_WORDMARK_PATH: &str = "railgun/icons/wordmark.svg";
pub(crate) const HERO_WORDMARK_PATH: &str = "railgun/icons/hero-wordmark.svg";
pub(crate) const HEMATITE_HERO_PATH: &str = "railgun/backgrounds/hematite-hero.svg";
pub(crate) const WARM_GLOW_PATH: &str = "railgun/backgrounds/warm-glow.svg";
const ARROW_BIG_RIGHT_DASH_ICON_PATH: &str = "railgun/icons/arrow-big-right-dash.svg";
const SHIELD_ICON_PATH: &str = "railgun/icons/shield.svg";
const WALLET_ICON_PATH: &str = "railgun/icons/wallet.svg";
const BROADCASTER_ICON_PATH: &str = "railgun/icons/robot.svg";
const LOGS_ICON_PATH: &str = "railgun/icons/logs.svg";
const PENCIL_ICON_PATH: &str = "railgun/icons/pencil.svg";
const QR_CODE_ICON_PATH: &str = "railgun/icons/qr-code.svg";
const TRASH_2_ICON_PATH: &str = "railgun/icons/trash-2.svg";
const KEY_ROUND_ICON_PATH: &str = "railgun/icons/key-round.svg";
const NETWORK_ICON_PATH: &str = "railgun/icons/network.svg";
const PIN_ICON_PATH: &str = "railgun/icons/pin.svg";
const TOR_STATUS_ICON_PATH: &str = "railgun/icons/tor-status.svg";

const RAILGUN_ASSET_PATHS: &[&str] = &[
    LOGO_ICON_PATH,
    SIDEBAR_WORDMARK_PATH,
    HERO_WORDMARK_PATH,
    HEMATITE_HERO_PATH,
    WARM_GLOW_PATH,
    ARROW_BIG_RIGHT_DASH_ICON_PATH,
    SHIELD_ICON_PATH,
    WALLET_ICON_PATH,
    BROADCASTER_ICON_PATH,
    LOGS_ICON_PATH,
    PENCIL_ICON_PATH,
    QR_CODE_ICON_PATH,
    TRASH_2_ICON_PATH,
    KEY_ROUND_ICON_PATH,
    NETWORK_ICON_PATH,
    PIN_ICON_PATH,
    TOR_STATUS_ICON_PATH,
];

const LOGO_ICON_BYTES: &[u8] = include_bytes!("../assets/icons/logo.svg");
const SIDEBAR_WORDMARK_BYTES: &[u8] = include_bytes!("../assets/icons/wordmark.svg");
const HERO_WORDMARK_BYTES: &[u8] = include_bytes!("../assets/icons/hero-wordmark.svg");
const HEMATITE_HERO_BYTES: &[u8] = include_bytes!("../assets/backgrounds/hematite-hero.svg");
const WARM_GLOW_BYTES: &[u8] = include_bytes!("../assets/backgrounds/warm-glow.svg");
const ARROW_BIG_RIGHT_DASH_ICON_BYTES: &[u8] =
    include_bytes!("../assets/icons/arrow-big-right-dash.svg");
const SHIELD_ICON_BYTES: &[u8] = include_bytes!("../assets/icons/shield.svg");
const WALLET_ICON_BYTES: &[u8] = include_bytes!("../../../crates/ui/assets/icons/wallet.svg");
const BROADCASTER_ICON_BYTES: &[u8] = include_bytes!("../../../crates/ui/assets/icons/robot.svg");
const LOGS_ICON_BYTES: &[u8] = include_bytes!("../../../crates/ui/assets/icons/logs.svg");
const PENCIL_ICON_BYTES: &[u8] = include_bytes!("../assets/icons/pencil.svg");
const QR_CODE_ICON_BYTES: &[u8] = include_bytes!("../assets/icons/qr-code.svg");
const TRASH_2_ICON_BYTES: &[u8] = include_bytes!("../assets/icons/trash-2.svg");
const KEY_ROUND_ICON_BYTES: &[u8] = include_bytes!("../assets/icons/key-round.svg");
const NETWORK_ICON_BYTES: &[u8] = include_bytes!("../assets/icons/network.svg");
const PIN_ICON_BYTES: &[u8] = include_bytes!("../assets/icons/pin.svg");
const TOR_STATUS_ICON_BYTES: &[u8] = include_bytes!("../assets/icons/tor-status.svg");

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
            RAILGUN_ASSET_PATHS
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
    Shield,
    Pencil,
    QrCode,
    Trash2,
}

impl IconNamed for RailgunActionIcon {
    fn path(self) -> SharedString {
        match self {
            Self::Send => ARROW_BIG_RIGHT_DASH_ICON_PATH,
            Self::Shield => SHIELD_ICON_PATH,
            Self::Pencil => PENCIL_ICON_PATH,
            Self::QrCode => QR_CODE_ICON_PATH,
            Self::Trash2 => TRASH_2_ICON_PATH,
        }
        .into()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RailgunPublicAccountIcon {
    Derived,
    Global,
    Imported,
}

impl IconNamed for RailgunPublicAccountIcon {
    fn path(self) -> SharedString {
        match self {
            Self::Derived => NETWORK_ICON_PATH,
            Self::Global => PIN_ICON_PATH,
            Self::Imported => KEY_ROUND_ICON_PATH,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RailgunNetworkStatusIcon {
    Tor,
}

impl IconNamed for RailgunNetworkStatusIcon {
    fn path(self) -> SharedString {
        match self {
            Self::Tor => TOR_STATUS_ICON_PATH,
        }
        .into()
    }
}

fn railgun_asset(path: &str) -> Option<&'static [u8]> {
    match path {
        LOGO_ICON_PATH => Some(LOGO_ICON_BYTES),
        SIDEBAR_WORDMARK_PATH => Some(SIDEBAR_WORDMARK_BYTES),
        HERO_WORDMARK_PATH => Some(HERO_WORDMARK_BYTES),
        HEMATITE_HERO_PATH => Some(HEMATITE_HERO_BYTES),
        WARM_GLOW_PATH => Some(WARM_GLOW_BYTES),
        ARROW_BIG_RIGHT_DASH_ICON_PATH => Some(ARROW_BIG_RIGHT_DASH_ICON_BYTES),
        SHIELD_ICON_PATH => Some(SHIELD_ICON_BYTES),
        WALLET_ICON_PATH => Some(WALLET_ICON_BYTES),
        BROADCASTER_ICON_PATH => Some(BROADCASTER_ICON_BYTES),
        LOGS_ICON_PATH => Some(LOGS_ICON_BYTES),
        PENCIL_ICON_PATH => Some(PENCIL_ICON_BYTES),
        QR_CODE_ICON_PATH => Some(QR_CODE_ICON_BYTES),
        TRASH_2_ICON_PATH => Some(TRASH_2_ICON_BYTES),
        KEY_ROUND_ICON_PATH => Some(KEY_ROUND_ICON_BYTES),
        NETWORK_ICON_PATH => Some(NETWORK_ICON_BYTES),
        PIN_ICON_PATH => Some(PIN_ICON_BYTES),
        TOR_STATUS_ICON_PATH => Some(TOR_STATUS_ICON_BYTES),
        _ => None,
    }
}
