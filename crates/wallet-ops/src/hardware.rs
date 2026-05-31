use std::collections::VecDeque;
use std::fmt;

use async_trait::async_trait;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

pub const DEFAULT_HARDWARE_DERIVATION_PATH: &str = "m/44'/60'/0'/0/0";

const HARDWARE_DERIVED_KDF_VERSION_V1: u16 = 1;
const HARDWARE_DERIVED_KDF_SALT_V1: &[u8] = b"railgun:hardware-derived-wallet:kdf:v1";
const HARDWARE_DERIVED_KDF_INFO_PREFIX_V1: &[u8] = b"railgun:hardware-derived-wallet:entropy:v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum HardwareDeviceKind {
    Ledger,
    Trezor,
}

impl HardwareDeviceKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ledger => "ledger",
            Self::Trezor => "trezor",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum HardwareDerivationMethod {
    LedgerEip1024V1,
    TrezorCipherKeyValueV1,
}

impl HardwareDerivationMethod {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LedgerEip1024V1 => "ledger_eip1024_v1",
            Self::TrezorCipherKeyValueV1 => "trezor_cipher_key_value_v1",
        }
    }

    #[must_use]
    pub const fn device_kind(self) -> HardwareDeviceKind {
        match self {
            Self::LedgerEip1024V1 => HardwareDeviceKind::Ledger,
            Self::TrezorCipherKeyValueV1 => HardwareDeviceKind::Trezor,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HardwareWalletSyncIntent {
    CreateNew,
    RecoverExisting,
}

impl HardwareWalletSyncIntent {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CreateNew => "create_new",
            Self::RecoverExisting => "recover_existing",
        }
    }
}

pub const HARDENED_BIP32_INDEX: u32 = 0x8000_0000;

const fn hardened_bip32_index(index: u32) -> u32 {
    index | HARDENED_BIP32_INDEX
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HardwarePublicAccountPathKind {
    LedgerLive,
    TrezorSuite,
    LedgerBip44,
    TrezorBip44,
}

impl HardwarePublicAccountPathKind {
    #[must_use]
    pub const fn device_kind(self) -> HardwareDeviceKind {
        match self {
            Self::LedgerLive | Self::LedgerBip44 => HardwareDeviceKind::Ledger,
            Self::TrezorSuite | Self::TrezorBip44 => HardwareDeviceKind::Trezor,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HardwarePublicAccountDescriptor {
    pub device_kind: HardwareDeviceKind,
    pub path_kind: HardwarePublicAccountPathKind,
    pub path: Vec<u32>,
    #[serde(default)]
    pub wallet_account_index: u32,
    #[serde(default, alias = "account_index")]
    pub public_account_index: u32,
}

impl HardwarePublicAccountDescriptor {
    pub fn for_wallet_public_index(
        device_kind: HardwareDeviceKind,
        wallet_account_index: u32,
        public_account_index: u32,
    ) -> Result<Self, HardwareDerivationError> {
        if wallet_account_index >= HARDENED_BIP32_INDEX {
            return Err(HardwareDerivationError::InvalidDescriptor(
                "hardware public wallet account index is too large",
            ));
        }
        if public_account_index >= HARDENED_BIP32_INDEX {
            return Err(HardwareDerivationError::InvalidDescriptor(
                "hardware public account index is too large",
            ));
        }
        let descriptor = Self::for_wallet_public_index_unchecked(
            device_kind,
            wallet_account_index,
            public_account_index,
        );
        descriptor.validate()?;
        Ok(descriptor)
    }

    pub fn for_device_index(
        device_kind: HardwareDeviceKind,
        account_index: u32,
    ) -> Result<Self, HardwareDerivationError> {
        Self::for_wallet_public_index(device_kind, 0, account_index)
    }

    pub fn validate(&self) -> Result<(), HardwareDerivationError> {
        if self.wallet_account_index >= HARDENED_BIP32_INDEX {
            return Err(HardwareDerivationError::InvalidDescriptor(
                "hardware public wallet account index is too large",
            ));
        }
        if self.public_account_index >= HARDENED_BIP32_INDEX {
            return Err(HardwareDerivationError::InvalidDescriptor(
                "hardware public account index is too large",
            ));
        }
        if self.path_kind.device_kind() != self.device_kind {
            return Err(HardwareDerivationError::InvalidDescriptor(
                "hardware public account path kind does not match device kind",
            ));
        }
        if self.path.len() != 5 {
            return Err(HardwareDerivationError::InvalidDescriptor(
                "hardware public account path must contain 5 segments",
            ));
        }
        let expected = Self::for_wallet_public_index_unchecked(
            self.device_kind,
            self.wallet_account_index,
            self.public_account_index,
        );
        let legacy =
            Self::legacy_for_device_index_unchecked(self.device_kind, self.public_account_index);
        if (self.path_kind != expected.path_kind || self.path != expected.path)
            && (self.path_kind != legacy.path_kind || self.path != legacy.path)
        {
            return Err(HardwareDerivationError::InvalidDescriptor(
                "hardware public account path does not match account index",
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn path_display(&self) -> String {
        format_bip32_path(&self.path)
    }

    fn for_wallet_public_index_unchecked(
        device_kind: HardwareDeviceKind,
        wallet_account_index: u32,
        public_account_index: u32,
    ) -> Self {
        match device_kind {
            HardwareDeviceKind::Ledger => Self {
                device_kind,
                path_kind: HardwarePublicAccountPathKind::LedgerBip44,
                path: vec![
                    hardened_bip32_index(44),
                    hardened_bip32_index(60),
                    hardened_bip32_index(wallet_account_index),
                    0,
                    public_account_index,
                ],
                wallet_account_index,
                public_account_index,
            },
            HardwareDeviceKind::Trezor => Self {
                device_kind,
                path_kind: HardwarePublicAccountPathKind::TrezorBip44,
                path: vec![
                    hardened_bip32_index(44),
                    hardened_bip32_index(60),
                    hardened_bip32_index(wallet_account_index),
                    0,
                    public_account_index,
                ],
                wallet_account_index,
                public_account_index,
            },
        }
    }

    fn legacy_for_device_index_unchecked(
        device_kind: HardwareDeviceKind,
        account_index: u32,
    ) -> Self {
        match device_kind {
            HardwareDeviceKind::Ledger => Self {
                device_kind,
                path_kind: HardwarePublicAccountPathKind::LedgerLive,
                path: vec![
                    hardened_bip32_index(44),
                    hardened_bip32_index(60),
                    hardened_bip32_index(account_index),
                    0,
                    0,
                ],
                wallet_account_index: 0,
                public_account_index: account_index,
            },
            HardwareDeviceKind::Trezor => Self {
                device_kind,
                path_kind: HardwarePublicAccountPathKind::TrezorSuite,
                path: vec![
                    hardened_bip32_index(44),
                    hardened_bip32_index(60),
                    hardened_bip32_index(0),
                    0,
                    account_index,
                ],
                wallet_account_index: 0,
                public_account_index: account_index,
            },
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HardwareDerivationDescriptor {
    pub device_kind: HardwareDeviceKind,
    pub method: HardwareDerivationMethod,
    pub path: Vec<u32>,
    pub account_index: u32,
    pub profile_fingerprint: String,
    pub kdf_version: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passphrase_hint: Option<String>,
    pub sync_intent: HardwareWalletSyncIntent,
}

impl fmt::Debug for HardwareDerivationDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HardwareDerivationDescriptor")
            .field("device_kind", &self.device_kind)
            .field("method", &self.method)
            .field("path", &format_bip32_path(&self.path))
            .field("account_index", &self.account_index)
            .field("profile_fingerprint", &"<redacted>")
            .field("kdf_version", &self.kdf_version)
            .field(
                "passphrase_hint",
                &self.passphrase_hint.as_ref().map(|_| "<present>"),
            )
            .field("sync_intent", &self.sync_intent)
            .finish()
    }
}

impl HardwareDerivationDescriptor {
    #[must_use]
    pub const fn ledger_eip1024_v1(
        path: Vec<u32>,
        account_index: u32,
        profile_fingerprint: String,
        passphrase_hint: Option<String>,
        sync_intent: HardwareWalletSyncIntent,
    ) -> Self {
        Self {
            device_kind: HardwareDeviceKind::Ledger,
            method: HardwareDerivationMethod::LedgerEip1024V1,
            path,
            account_index,
            profile_fingerprint,
            kdf_version: HARDWARE_DERIVED_KDF_VERSION_V1,
            passphrase_hint,
            sync_intent,
        }
    }

    #[must_use]
    pub const fn trezor_cipher_key_value_v1(
        path: Vec<u32>,
        account_index: u32,
        profile_fingerprint: String,
        passphrase_hint: Option<String>,
        sync_intent: HardwareWalletSyncIntent,
    ) -> Self {
        Self {
            device_kind: HardwareDeviceKind::Trezor,
            method: HardwareDerivationMethod::TrezorCipherKeyValueV1,
            path,
            account_index,
            profile_fingerprint,
            kdf_version: HARDWARE_DERIVED_KDF_VERSION_V1,
            passphrase_hint,
            sync_intent,
        }
    }

    pub fn validate(&self) -> Result<(), HardwareDerivationError> {
        if self.method.device_kind() != self.device_kind {
            return Err(HardwareDerivationError::InvalidDescriptor(
                "device kind does not match derivation method",
            ));
        }
        if self.account_index >= HARDENED_BIP32_INDEX {
            return Err(HardwareDerivationError::InvalidDescriptor(
                "hardware wallet account index is too large",
            ));
        }
        if self.path.is_empty() {
            return Err(HardwareDerivationError::InvalidDescriptor(
                "derivation path must not be empty",
            ));
        }
        if self.path.len() > 10 {
            return Err(HardwareDerivationError::InvalidDescriptor(
                "derivation path must contain at most 10 segments",
            ));
        }
        if self.profile_fingerprint.trim().is_empty() {
            return Err(HardwareDerivationError::InvalidDescriptor(
                "profile fingerprint must not be empty",
            ));
        }
        if self.kdf_version != HARDWARE_DERIVED_KDF_VERSION_V1 {
            return Err(HardwareDerivationError::UnsupportedKdfVersion(
                self.kdf_version,
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn kdf_info(&self) -> Vec<u8> {
        let mut info = Vec::with_capacity(
            HARDWARE_DERIVED_KDF_INFO_PREFIX_V1.len()
                + self.path.len() * 4
                + self.profile_fingerprint.len()
                + 64,
        );
        info.extend_from_slice(HARDWARE_DERIVED_KDF_INFO_PREFIX_V1);
        push_kdf_field(&mut info, self.device_kind.as_str().as_bytes());
        push_kdf_field(&mut info, self.method.as_str().as_bytes());
        info.extend_from_slice(&self.kdf_version.to_be_bytes());
        info.extend_from_slice(&self.account_index.to_be_bytes());
        push_kdf_field(&mut info, self.profile_fingerprint.as_bytes());
        let path_len = u8::try_from(self.path.len()).unwrap_or(u8::MAX);
        info.push(path_len);
        for index in &self.path {
            info.extend_from_slice(&index.to_be_bytes());
        }
        info
    }
}

fn push_kdf_field(info: &mut Vec<u8>, field: &[u8]) {
    let len = u16::try_from(field.len()).expect("hardware KDF field length fits in u16");
    info.extend_from_slice(&len.to_be_bytes());
    info.extend_from_slice(field);
}

pub struct HardwareOperationOutput(Zeroizing<[u8; 32]>);

impl HardwareOperationOutput {
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    #[must_use]
    pub fn expose_secret(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub fn into_zeroizing(self) -> Zeroizing<[u8; 32]> {
        self.0
    }
}

impl fmt::Debug for HardwareOperationOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HardwareOperationOutput(<redacted>)")
    }
}

pub struct SyntheticRailgunEntropy(Zeroizing<[u8; 32]>);

impl SyntheticRailgunEntropy {
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub fn into_zeroizing(self) -> Zeroizing<[u8; 32]> {
        self.0
    }
}

impl fmt::Debug for SyntheticRailgunEntropy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SyntheticRailgunEntropy(<redacted>)")
    }
}

pub fn synthetic_entropy_from_hardware_output(
    descriptor: &HardwareDerivationDescriptor,
    output: HardwareOperationOutput,
) -> Result<SyntheticRailgunEntropy, HardwareDerivationError> {
    descriptor.validate()?;
    let output = output.into_zeroizing();
    let hkdf = Hkdf::<Sha256>::new(Some(HARDWARE_DERIVED_KDF_SALT_V1), output.as_ref());
    let mut entropy = [0u8; 32];
    hkdf.expand(&descriptor.kdf_info(), &mut entropy)
        .map_err(|_| HardwareDerivationError::KdfExpand)?;
    Ok(SyntheticRailgunEntropy(Zeroizing::new(entropy)))
}

pub fn parse_bip32_path(path: &str) -> Result<Vec<u32>, HardwareDerivationError> {
    let path = path.trim();
    let path = path.strip_prefix("m/").unwrap_or(path);
    if path.is_empty() || path == "m" {
        return Err(HardwareDerivationError::InvalidPath(path.to_owned()));
    }
    path.split('/')
        .map(|segment| {
            let hardened =
                segment.ends_with('\'') || segment.ends_with('h') || segment.ends_with('H');
            let number = if hardened {
                &segment[..segment.len().saturating_sub(1)]
            } else {
                segment
            };
            let mut index = number
                .parse::<u32>()
                .map_err(|_| HardwareDerivationError::InvalidPath(segment.to_owned()))?;
            if hardened {
                index |= 0x8000_0000;
            }
            Ok(index)
        })
        .collect()
}

#[must_use]
pub fn format_bip32_path(path: &[u32]) -> String {
    let mut formatted = String::from("m");
    for index in path {
        formatted.push('/');
        if index & 0x8000_0000 != 0 {
            formatted.push_str(&(index & 0x7fff_ffff).to_string());
            formatted.push('\'');
        } else {
            formatted.push_str(&index.to_string());
        }
    }
    formatted
}

#[must_use]
pub fn hardware_profile_fingerprint(
    device_kind: HardwareDeviceKind,
    evm_address: impl AsRef<str>,
) -> String {
    format!(
        "{}:evm:{}",
        device_kind.as_str(),
        evm_address.as_ref().to_ascii_lowercase()
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct HardwareAppVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl HardwareAppVersion {
    #[must_use]
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

impl fmt::Display for HardwareAppVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Debug, Error)]
pub enum HardwareDerivationError {
    #[error("invalid hardware derivation descriptor: {0}")]
    InvalidDescriptor(&'static str),
    #[error("invalid BIP32 derivation path segment: {0}")]
    InvalidPath(String),
    #[error("unsupported hardware KDF version: {0}")]
    UnsupportedKdfVersion(u16),
    #[error("hardware KDF expansion failed")]
    KdfExpand,
    #[error("hardware derivation client has no queued mock output")]
    MissingMockOutput,
    #[error("unexpected hardware response length: got {got}, expected {expected}")]
    UnexpectedResponseLength { got: usize, expected: usize },
    #[error("unexpected hardware response: {0}")]
    UnexpectedHardwareResponse(&'static str),
    #[error("unsupported Ledger Ethereum app version {actual}; requires {required} or newer")]
    UnsupportedLedgerEthereumAppVersion {
        actual: HardwareAppVersion,
        required: HardwareAppVersion,
    },
    #[cfg(feature = "hardware")]
    #[error("Ledger {operation} failed ({status:#06x}): {message}")]
    LedgerStatus {
        operation: &'static str,
        status: u16,
        message: &'static str,
    },
    #[cfg(feature = "hardware")]
    #[error("{0}")]
    LedgerUnavailable(&'static str),
    #[cfg(feature = "hardware")]
    #[error(transparent)]
    Ledger(#[from] coins_ledger::LedgerError),
    #[cfg(feature = "hardware")]
    #[error(transparent)]
    Trezor(#[from] trezor_client::Error),
    #[cfg(feature = "hardware")]
    #[error("Trezor Bridge transport failed: {0}")]
    TrezorBridge(String),
}

impl HardwareDerivationError {
    #[must_use]
    pub const fn is_early_device_readiness_error(&self) -> bool {
        match self {
            #[cfg(feature = "hardware")]
            Self::LedgerUnavailable(_) | Self::TrezorBridge(_) => true,
            #[cfg(feature = "hardware")]
            Self::LedgerStatus { status, .. } => {
                matches!(*status, 0x6511 | 0x6a15 | 0x6d00 | 0x6e00 | 0x6804 | 0x6b0c)
            }
            #[cfg(feature = "hardware")]
            Self::Trezor(trezor_client::Error::NoDeviceFound) => true,
            #[cfg(feature = "hardware")]
            Self::Trezor(trezor_client::Error::TransportConnect(
                trezor_client::transport::error::Error::DeviceNotFound,
            )) => true,
            _ => false,
        }
    }
}

#[async_trait(?Send)]
pub trait HardwareDerivationClient {
    async fn derive_hardware_output(
        &mut self,
        descriptor: &HardwareDerivationDescriptor,
    ) -> Result<HardwareOperationOutput, HardwareDerivationError>;

    async fn derive_synthetic_entropy(
        &mut self,
        descriptor: &HardwareDerivationDescriptor,
    ) -> Result<SyntheticRailgunEntropy, HardwareDerivationError> {
        let output = self.derive_hardware_output(descriptor).await?;
        synthetic_entropy_from_hardware_output(descriptor, output)
    }
}

pub struct MockHardwareDerivationClient {
    outputs: VecDeque<HardwareOperationOutput>,
}

impl MockHardwareDerivationClient {
    #[must_use]
    pub fn new(outputs: impl IntoIterator<Item = [u8; 32]>) -> Self {
        Self {
            outputs: outputs
                .into_iter()
                .map(HardwareOperationOutput::new)
                .collect(),
        }
    }
}

#[async_trait(?Send)]
impl HardwareDerivationClient for MockHardwareDerivationClient {
    async fn derive_hardware_output(
        &mut self,
        descriptor: &HardwareDerivationDescriptor,
    ) -> Result<HardwareOperationOutput, HardwareDerivationError> {
        descriptor.validate()?;
        self.outputs
            .pop_front()
            .ok_or(HardwareDerivationError::MissingMockOutput)
    }
}

#[cfg(feature = "hardware")]
pub mod ledger {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::{
        HardwareAppVersion, HardwareDerivationClient, HardwareDerivationDescriptor,
        HardwareDerivationError, HardwareDerivationMethod, HardwareDeviceKind,
        HardwareOperationOutput, HardwarePublicAccountDescriptor, hardware_profile_fingerprint,
    };
    use alloy::hex;
    use alloy::primitives::{Address, Signature, normalize_v};
    use async_trait::async_trait;
    use coins_ledger::{
        LedgerError,
        common::{APDUAnswer, APDUCommand, APDUData},
        transports::{Ledger, LedgerAsync, native::NativeTransportError},
    };
    use hidapi_rusb::HidApi;
    use tokio::sync::Mutex as AsyncMutex;

    pub const LEDGER_ETHEREUM_EIP1024_MIN_APP_VERSION: HardwareAppVersion =
        HardwareAppVersion::new(1, 9, 17);

    const LEDGER_READY_MESSAGE: &str =
        "Connect and unlock your Ledger, open the Ethereum app, then retry.";
    const LEDGER_VID: u16 = 0x2c97;
    #[cfg(not(target_os = "linux"))]
    const LEDGER_USAGE_PAGE: u16 = 0xffa0;
    static LEDGER_CONNECT_LOCK: AsyncMutex<()> = AsyncMutex::const_new(());
    static LEDGER_COINS_HIDAPI_TOUCHED: AtomicBool = AtomicBool::new(false);

    pub const RAILGUN_LEDGER_EIP1024_REMOTE_PUBLIC_KEY_V1: [u8; 32] = [
        0xeb, 0x88, 0xd6, 0xa7, 0xb6, 0x92, 0x83, 0xd0, 0x58, 0x22, 0x98, 0xe6, 0x04, 0xe1, 0x3e,
        0x4d, 0x86, 0xa2, 0x98, 0xe5, 0x96, 0xe5, 0x82, 0x93, 0xee, 0x6a, 0x8d, 0xbb, 0x07, 0x61,
        0x0f, 0x51,
    ];

    pub struct LedgerHardwareDerivationClient {
        ledger: Ledger,
    }

    impl LedgerHardwareDerivationClient {
        pub async fn connect() -> Result<Self, HardwareDerivationError> {
            let _guard = LEDGER_CONNECT_LOCK.lock().await;
            if !LEDGER_COINS_HIDAPI_TOUCHED.load(Ordering::SeqCst) {
                ledger_hid_preflight()?;
            }

            let ledger = Ledger::init().await.map_err(ledger_connect_error);
            LEDGER_COINS_HIDAPI_TOUCHED.store(true, Ordering::SeqCst);
            Ok(Self { ledger: ledger? })
        }

        pub async fn ethereum_app_version(
            &self,
        ) -> Result<HardwareAppVersion, HardwareDerivationError> {
            let command = APDUCommand {
                cla: 0xe0,
                ins: 0x06,
                p1: 0x00,
                p2: 0x00,
                data: APDUData::new(&[]),
                response_len: Some(0),
            };
            let answer = self
                .ledger
                .exchange(&command)
                .await
                .map_err(|error| ledger_exchange_error(error, "get Ethereum app version"))?;
            let data = ledger_response_data(&answer, "get Ethereum app version")?;
            if data.len() != 4 {
                return Err(HardwareDerivationError::UnexpectedResponseLength {
                    got: data.len(),
                    expected: 4,
                });
            }
            Ok(HardwareAppVersion::new(
                u16::from(data[1]),
                u16::from(data[2]),
                u16::from(data[3]),
            ))
        }

        pub async fn ethereum_address(
            &self,
            path: &[u32],
        ) -> Result<String, HardwareDerivationError> {
            self.ethereum_address_with_confirmation(path, false).await
        }

        async fn ethereum_address_with_confirmation(
            &self,
            path: &[u32],
            display_and_confirm: bool,
        ) -> Result<String, HardwareDerivationError> {
            let data = ledger_path_payload(path)?;
            let command = APDUCommand {
                cla: 0xe0,
                ins: 0x02,
                p1: ledger_address_display_p1(display_and_confirm),
                p2: 0x00,
                data: APDUData::new(&data),
                response_len: None,
            };
            let answer = self
                .ledger
                .exchange(&command)
                .await
                .map_err(|error| ledger_exchange_error(error, "get Ethereum address"))?;
            let data = ledger_response_data(&answer, "get Ethereum address")?;
            let address = ledger_address_from_response(data)?;
            Ok(format!("0x{}", address.to_ascii_lowercase()))
        }

        pub async fn public_ethereum_address(
            &self,
            descriptor: &HardwarePublicAccountDescriptor,
        ) -> Result<Address, HardwareDerivationError> {
            self.public_ethereum_address_with_confirmation(descriptor, false)
                .await
        }

        pub async fn confirmed_public_ethereum_address(
            &self,
            descriptor: &HardwarePublicAccountDescriptor,
        ) -> Result<Address, HardwareDerivationError> {
            self.public_ethereum_address_with_confirmation(descriptor, true)
                .await
        }

        async fn public_ethereum_address_with_confirmation(
            &self,
            descriptor: &HardwarePublicAccountDescriptor,
            display_and_confirm: bool,
        ) -> Result<Address, HardwareDerivationError> {
            descriptor.validate()?;
            if descriptor.device_kind != HardwareDeviceKind::Ledger {
                return Err(HardwareDerivationError::InvalidDescriptor(
                    "Ledger public account requires a Ledger descriptor",
                ));
            }
            self.ethereum_address_with_confirmation(&descriptor.path, display_and_confirm)
                .await?
                .parse()
                .map_err(|_| {
                    HardwareDerivationError::UnexpectedHardwareResponse(
                        "Ledger address response is not an EVM address",
                    )
                })
        }

        pub async fn sign_transaction_rlp(
            &self,
            descriptor: &HardwarePublicAccountDescriptor,
            encoded_for_signing: &[u8],
        ) -> Result<Signature, HardwareDerivationError> {
            descriptor.validate()?;
            if descriptor.device_kind != HardwareDeviceKind::Ledger {
                return Err(HardwareDerivationError::InvalidDescriptor(
                    "Ledger transaction signing requires a Ledger descriptor",
                ));
            }
            let mut payload = ledger_path_payload(&descriptor.path)?;
            payload.extend_from_slice(encoded_for_signing);
            self.sign_payload(0x04, &payload).await
        }

        pub async fn sign_message(
            &self,
            descriptor: &HardwarePublicAccountDescriptor,
            message: &[u8],
        ) -> Result<Signature, HardwareDerivationError> {
            descriptor.validate()?;
            if descriptor.device_kind != HardwareDeviceKind::Ledger {
                return Err(HardwareDerivationError::InvalidDescriptor(
                    "Ledger message signing requires a Ledger descriptor",
                ));
            }
            let message_len = u32::try_from(message.len()).map_err(|_| {
                HardwareDerivationError::InvalidDescriptor("Ledger message is too large")
            })?;
            let mut payload = ledger_path_payload(&descriptor.path)?;
            payload.extend_from_slice(&message_len.to_be_bytes());
            payload.extend_from_slice(message);
            self.sign_payload(0x08, &payload).await
        }

        async fn sign_payload(
            &self,
            ins: u8,
            payload: &[u8],
        ) -> Result<Signature, HardwareDerivationError> {
            let operation = ledger_signing_operation(ins);
            let mut command = APDUCommand {
                cla: 0xe0,
                ins,
                p1: 0x00,
                p2: 0x00,
                data: APDUData::new(&[]),
                response_len: None,
            };
            let chunk_size = (0..=255)
                .rev()
                .find(|size| payload.len() % size != 3)
                .expect("nonzero Ledger chunk size exists");
            let mut answer = None;
            for chunk in payload.chunks(chunk_size) {
                command.data = APDUData::new(chunk);
                let response = self
                    .ledger
                    .exchange(&command)
                    .await
                    .map_err(|error| ledger_exchange_error(error, operation))?;
                ledger_ensure_success(&response, operation)?;
                answer = Some(response);
                command.p1 = 0x80;
            }
            let answer = answer.ok_or(HardwareDerivationError::UnexpectedHardwareResponse(
                "Ledger signing payload is empty",
            ))?;
            let data = ledger_response_data(&answer, operation)?;
            if data.len() != 65 {
                return Err(HardwareDerivationError::UnexpectedResponseLength {
                    got: data.len(),
                    expected: 65,
                });
            }
            let parity = normalize_v(u64::from(data[0])).ok_or(
                HardwareDerivationError::UnexpectedHardwareResponse(
                    "Ledger signature has invalid recovery id",
                ),
            )?;
            Ok(Signature::from_bytes_and_parity(&data[1..], parity))
        }

        pub async fn profile_fingerprint(
            &self,
            path: &[u32],
        ) -> Result<String, HardwareDerivationError> {
            let address = self.ethereum_address(path).await?;
            Ok(hardware_profile_fingerprint(
                HardwareDeviceKind::Ledger,
                address,
            ))
        }

        pub async fn eip1024_shared_secret(
            &self,
            path: &[u32],
            display_and_confirm: bool,
        ) -> Result<HardwareOperationOutput, HardwareDerivationError> {
            let version = self.ethereum_app_version().await?;
            if version < LEDGER_ETHEREUM_EIP1024_MIN_APP_VERSION {
                return Err(
                    HardwareDerivationError::UnsupportedLedgerEthereumAppVersion {
                        actual: version,
                        required: LEDGER_ETHEREUM_EIP1024_MIN_APP_VERSION,
                    },
                );
            }

            let mut data = ledger_path_payload(path)?;
            data.extend_from_slice(&RAILGUN_LEDGER_EIP1024_REMOTE_PUBLIC_KEY_V1);

            let command = APDUCommand {
                cla: 0xe0,
                ins: 0x18,
                p1: u8::from(display_and_confirm),
                p2: 0x01,
                data: APDUData::new(&data),
                response_len: None,
            };
            let answer = self
                .ledger
                .exchange(&command)
                .await
                .map_err(|error| ledger_exchange_error(error, "derive Railgun secret"))?;
            let data = ledger_response_data(&answer, "derive Railgun secret")?;
            if data.len() != 32 {
                return Err(HardwareDerivationError::UnexpectedResponseLength {
                    got: data.len(),
                    expected: 32,
                });
            }
            let mut output = [0u8; 32];
            output.copy_from_slice(data);
            Ok(HardwareOperationOutput::new(output))
        }
    }

    fn ledger_hid_preflight() -> Result<(), HardwareDerivationError> {
        let api = HidApi::new().map_err(|error| {
            tracing::debug!(%error, "Ledger HID preflight failed to initialize HID API");
            HardwareDerivationError::LedgerUnavailable(LEDGER_READY_MESSAGE)
        })?;
        if api
            .device_list()
            .any(|device| ledger_hid_device_matches(device.vendor_id(), device.usage_page()))
        {
            Ok(())
        } else {
            Err(HardwareDerivationError::LedgerUnavailable(
                LEDGER_READY_MESSAGE,
            ))
        }
    }

    const fn ledger_hid_device_matches(vendor_id: u16, usage_page: u16) -> bool {
        if vendor_id != LEDGER_VID {
            return false;
        }
        #[cfg(target_os = "linux")]
        {
            let _ = usage_page;
            true
        }
        #[cfg(not(target_os = "linux"))]
        {
            usage_page == LEDGER_USAGE_PAGE
        }
    }

    fn ledger_connect_error(error: LedgerError) -> HardwareDerivationError {
        match error {
            LedgerError::NativeTransportError(NativeTransportError::DeviceNotFound) => {
                HardwareDerivationError::LedgerUnavailable(LEDGER_READY_MESSAGE)
            }
            error => HardwareDerivationError::Ledger(error),
        }
    }

    fn ledger_exchange_error(
        error: LedgerError,
        operation: &'static str,
    ) -> HardwareDerivationError {
        match error {
            LedgerError::BadRetcode(status) => ledger_status_error(operation, status as u16),
            error => HardwareDerivationError::Ledger(error),
        }
    }

    fn ledger_ensure_success(
        answer: &APDUAnswer,
        operation: &'static str,
    ) -> Result<(), HardwareDerivationError> {
        if answer.is_success() {
            Ok(())
        } else {
            Err(ledger_status_error(operation, answer.retcode()))
        }
    }

    fn ledger_response_data<'a>(
        answer: &'a APDUAnswer,
        operation: &'static str,
    ) -> Result<&'a [u8], HardwareDerivationError> {
        ledger_ensure_success(answer, operation)?;
        answer
            .data()
            .ok_or(HardwareDerivationError::UnexpectedHardwareResponse(
                "Ledger success response has no data",
            ))
    }

    const fn ledger_status_error(operation: &'static str, status: u16) -> HardwareDerivationError {
        HardwareDerivationError::LedgerStatus {
            operation,
            status,
            message: ledger_status_message(status),
        }
    }

    const fn ledger_status_message(status: u16) -> &'static str {
        match status {
            0x6511 | 0x6a15 | 0x6d00 | 0x6e00 => {
                "Open the Ethereum app on your Ledger, then retry."
            }
            0x6804 | 0x6b0c => "Unlock your Ledger, then retry.",
            0x6982 => "The request was rejected on your Ledger.",
            0x6985 => {
                "The request was rejected or the Ledger is not ready. Approve on device or retry."
            }
            0x6a80 | 0x6b00 => {
                "The Ledger rejected the request data. Confirm the account path and retry."
            }
            _ => {
                "Ledger returned an unexpected status. Open the Ethereum app on your Ledger and retry."
            }
        }
    }

    const fn ledger_signing_operation(ins: u8) -> &'static str {
        match ins {
            0x04 => "sign transaction",
            0x08 => "sign message",
            _ => "sign payload",
        }
    }

    const fn ledger_address_display_p1(display_and_confirm: bool) -> u8 {
        if display_and_confirm { 0x01 } else { 0x00 }
    }

    fn ledger_path_payload(path: &[u32]) -> Result<Vec<u8>, HardwareDerivationError> {
        let mut data = Vec::with_capacity(1 + path.len() * 4);
        data.push(u8::try_from(path.len()).map_err(|_| {
            HardwareDerivationError::InvalidDescriptor(
                "Ledger EIP-1024 path contains too many segments",
            )
        })?);
        for index in path {
            data.extend_from_slice(&index.to_be_bytes());
        }
        Ok(data)
    }

    fn ledger_address_from_response(data: &[u8]) -> Result<String, HardwareDerivationError> {
        let Some((&public_key_len, rest)) = data.split_first() else {
            return Err(HardwareDerivationError::UnexpectedHardwareResponse(
                "Ledger address response is missing public key length",
            ));
        };
        let address_len_offset = usize::from(public_key_len);
        if rest.len() <= address_len_offset {
            return Err(HardwareDerivationError::UnexpectedHardwareResponse(
                "Ledger address response is missing address length",
            ));
        }
        let address_len = usize::from(rest[address_len_offset]);
        let address_start = address_len_offset + 1;
        let address_end = address_start + address_len;
        if rest.len() < address_end {
            return Err(HardwareDerivationError::UnexpectedHardwareResponse(
                "Ledger address response is truncated",
            ));
        }
        let address = std::str::from_utf8(&rest[address_start..address_end]).map_err(|_| {
            HardwareDerivationError::UnexpectedHardwareResponse(
                "Ledger address response is not UTF-8",
            )
        })?;
        if hex::decode(address).map_or(true, |bytes| bytes.len() != 20) {
            return Err(HardwareDerivationError::UnexpectedHardwareResponse(
                "Ledger address response is not an EVM address",
            ));
        }
        Ok(address.to_owned())
    }

    #[async_trait(?Send)]
    impl HardwareDerivationClient for LedgerHardwareDerivationClient {
        async fn derive_hardware_output(
            &mut self,
            descriptor: &HardwareDerivationDescriptor,
        ) -> Result<HardwareOperationOutput, HardwareDerivationError> {
            descriptor.validate()?;
            if descriptor.method != HardwareDerivationMethod::LedgerEip1024V1 {
                return Err(HardwareDerivationError::InvalidDescriptor(
                    "Ledger client requires a Ledger EIP-1024 descriptor",
                ));
            }
            self.eip1024_shared_secret(&descriptor.path, true).await
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn answer_with_status(status: u16) -> APDUAnswer {
            APDUAnswer::from_answer(status.to_be_bytes().to_vec()).expect("status answer")
        }

        #[test]
        fn ledger_hid_preflight_filter_matches_coins_ledger_filter() {
            #[cfg(not(target_os = "linux"))]
            {
                assert!(ledger_hid_device_matches(0x2c97, 0xffa0));
                assert!(!ledger_hid_device_matches(0x2c97, 0x0001));
            }
            #[cfg(target_os = "linux")]
            {
                assert!(ledger_hid_device_matches(0x2c97, 0x0001));
            }
            assert!(!ledger_hid_device_matches(0x1234, 0xffa0));
        }

        #[test]
        fn ledger_connect_device_not_found_preserves_retry_guidance() {
            let error = ledger_connect_error(LedgerError::NativeTransportError(
                NativeTransportError::DeviceNotFound,
            ));

            assert!(matches!(
                error,
                HardwareDerivationError::LedgerUnavailable(LEDGER_READY_MESSAGE)
            ));
            assert!(error.to_string().contains("unlock your Ledger"));
            assert!(error.to_string().contains("open the Ethereum app"));
        }

        #[test]
        fn ledger_app_closed_status_points_to_ethereum_app() {
            let error = ledger_response_data(&answer_with_status(0x6511), "get Ethereum address")
                .expect_err("app closed status should fail");

            assert!(matches!(
                error,
                HardwareDerivationError::LedgerStatus {
                    operation: "get Ethereum address",
                    status: 0x6511,
                    ..
                }
            ));
            let message = error.to_string();
            assert!(message.contains("0x6511"));
            assert!(message.contains("Open the Ethereum app on your Ledger"));
        }

        #[test]
        fn ledger_known_bad_retcode_points_to_ethereum_app() {
            let error = ledger_exchange_error(
                LedgerError::BadRetcode(coins_ledger::common::APDUResponseCodes::InsNotSupported),
                "get Ethereum app version",
            );

            assert!(matches!(
                error,
                HardwareDerivationError::LedgerStatus {
                    operation: "get Ethereum app version",
                    status: 0x6d00,
                    ..
                }
            ));
            assert!(
                error
                    .to_string()
                    .contains("Open the Ethereum app on your Ledger")
            );
        }

        #[test]
        fn ledger_locked_status_points_to_unlock() {
            let error = ledger_response_data(&answer_with_status(0x6b0c), "get Ethereum address")
                .expect_err("locked status should fail");

            assert!(matches!(
                error,
                HardwareDerivationError::LedgerStatus { status: 0x6b0c, .. }
            ));
            assert!(error.to_string().contains("Unlock your Ledger"));
        }

        #[test]
        fn ledger_address_confirmation_sets_display_flag() {
            assert_eq!(ledger_address_display_p1(false), 0x00);
            assert_eq!(ledger_address_display_p1(true), 0x01);
        }
    }
}

#[cfg(feature = "hardware")]
pub mod trezor {
    use std::fmt;
    use std::io::{Read as _, Write as _};
    use std::net::{SocketAddr, TcpStream};
    use std::time::Duration;

    use super::{
        HardwareAppVersion, HardwareDerivationClient, HardwareDerivationDescriptor,
        HardwareDerivationError, HardwareDerivationMethod, HardwareDeviceKind,
        HardwareOperationOutput, HardwarePublicAccountDescriptor, hardware_profile_fingerprint,
    };
    use alloy::consensus::SignableTransaction;
    use alloy::hex;
    use alloy::primitives::{Address, Signature, TxKind, U256, normalize_v};
    use async_trait::async_trait;
    use protobuf::Enum as _;
    use serde::Deserialize;
    use trezor_client::TrezorMessage;
    use trezor_client::client::handle_interaction;
    use trezor_client::transport::{ProtoMessage, Transport, error::Error as TrezorTransportError};
    use zeroize::Zeroize;

    const TREZOR_CIPHER_INPUT_V1: [u8; 32] = [0u8; 32];
    const TREZOR_BRIDGE_ADDR: &str = "127.0.0.1:21325";
    const TREZOR_BRIDGE_HOST: &str = "127.0.0.1";
    const TREZOR_BRIDGE_ORIGIN: &str = "http://localhost:8000";
    const TREZOR_BRIDGE_CONNECT_TIMEOUT: Duration = Duration::from_millis(750);
    const TREZOR_BRIDGE_READ_TIMEOUT: Duration = Duration::from_mins(5);
    const TREZOR_BRIDGE_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
    const TREZOR_ETHEREUM_TX_CHUNK_SIZE: usize = 1024;

    #[derive(Debug, Clone, Deserialize)]
    pub(super) struct BridgeDevice {
        pub(super) path: String,
        pub(super) session: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct BridgeAcquireResponse {
        session: String,
    }

    #[derive(Debug)]
    pub(super) enum BridgeConnectError {
        Unavailable(String),
        NoDevice,
        DeviceBusy,
        DeviceNotUnique(usize),
        Transport(String),
    }

    impl BridgeConnectError {
        const fn should_fallback(&self) -> bool {
            matches!(self, Self::Unavailable(_) | Self::NoDevice)
        }

        fn into_hardware_error(self) -> HardwareDerivationError {
            HardwareDerivationError::TrezorBridge(self.to_string())
        }
    }

    impl fmt::Display for BridgeConnectError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Unavailable(error) => write!(f, "Trezor Bridge is unavailable: {error}"),
                Self::NoDevice => f.write_str("Trezor Bridge did not report a connected device"),
                Self::DeviceBusy => f.write_str(trezor_bridge_busy_message()),
                Self::DeviceNotUnique(count) => {
                    write!(
                        f,
                        "Trezor Bridge reported {count} devices; connect exactly one Trezor"
                    )
                }
                Self::Transport(error) => write!(f, "{error}"),
            }
        }
    }

    #[must_use]
    pub const fn trezor_bridge_busy_message() -> &'static str {
        "Trezor Bridge reports that the device is already in use. Close Trezor Suite, browser wallet tabs, or other Trezor applications, then reconnect the device and retry."
    }

    struct BridgeHttpResponse {
        status: u16,
        body: Vec<u8>,
    }

    struct BridgeTransport {
        session: String,
        pending_message: Option<ProtoMessage>,
        released: bool,
    }

    impl BridgeTransport {
        fn connect_unique() -> Result<Self, BridgeConnectError> {
            let response = bridge_http_post(
                &bridge_path(&["enumerate"]),
                None,
                BridgeHttpErrorMode::Unavailable,
            )?;
            ensure_success(response.status, &response.body)
                .map_err(BridgeConnectError::Transport)?;
            let devices: Vec<BridgeDevice> = serde_json::from_slice(&response.body)
                .map_err(|error| BridgeConnectError::Transport(error.to_string()))?;
            let device = select_bridge_device(&devices)?;
            let response = bridge_http_post(
                &bridge_path(&["acquire", &device.path, "null"]),
                None,
                BridgeHttpErrorMode::Transport,
            )?;
            ensure_success(response.status, &response.body)
                .map_err(BridgeConnectError::Transport)?;
            let response: BridgeAcquireResponse = serde_json::from_slice(&response.body)
                .map_err(|error| BridgeConnectError::Transport(error.to_string()))?;
            Ok(Self {
                session: response.session,
                pending_message: None,
                released: false,
            })
        }

        fn release(&mut self) -> Result<(), TrezorTransportError> {
            if self.released {
                return Ok(());
            }
            let response = bridge_http_post(
                &bridge_path(&["release", &self.session]),
                None,
                BridgeHttpErrorMode::Transport,
            )
            .map_err(|error| transport_io_error(error.to_string()))?;
            ensure_success(response.status, &response.body).map_err(transport_io_error)?;
            self.released = true;
            Ok(())
        }

        fn call(&self, message: ProtoMessage) -> Result<ProtoMessage, TrezorTransportError> {
            let body = encode_bridge_message(message);
            let response = bridge_http_post(
                &bridge_path(&["call", &self.session]),
                Some(&body),
                BridgeHttpErrorMode::Transport,
            )
            .map_err(|error| transport_io_error(error.to_string()))?;
            ensure_success(response.status, &response.body).map_err(transport_io_error)?;
            let body = std::str::from_utf8(&response.body)
                .map_err(|error| transport_io_error(error.to_string()))?
                .trim();
            let data = hex::decode(body).map_err(|error| transport_io_error(error.to_string()))?;
            decode_bridge_message(&data)
        }
    }

    impl Drop for BridgeTransport {
        fn drop(&mut self) {
            let _ = self.release();
        }
    }

    impl Transport for BridgeTransport {
        fn session_begin(&mut self) -> Result<(), TrezorTransportError> {
            Ok(())
        }

        fn session_end(&mut self) -> Result<(), TrezorTransportError> {
            self.release()
        }

        fn write_message(&mut self, message: ProtoMessage) -> Result<(), TrezorTransportError> {
            self.pending_message = Some(message);
            Ok(())
        }

        fn read_message(&mut self) -> Result<ProtoMessage, TrezorTransportError> {
            let message = self
                .pending_message
                .take()
                .ok_or_else(|| transport_io_error("Trezor Bridge read requested before write"))?;
            self.call(message)
        }
    }

    #[derive(Clone, Copy)]
    enum BridgeHttpErrorMode {
        Unavailable,
        Transport,
    }

    fn bridge_http_post(
        path: &str,
        body: Option<&str>,
        error_mode: BridgeHttpErrorMode,
    ) -> Result<BridgeHttpResponse, BridgeConnectError> {
        let addr: SocketAddr = TREZOR_BRIDGE_ADDR
            .parse()
            .expect("Trezor Bridge socket address is valid");
        let mut stream = TcpStream::connect_timeout(&addr, TREZOR_BRIDGE_CONNECT_TIMEOUT)
            .map_err(|error| bridge_io_error(error_mode, &error))?;
        stream
            .set_read_timeout(Some(TREZOR_BRIDGE_READ_TIMEOUT))
            .map_err(|error| bridge_io_error(error_mode, &error))?;
        stream
            .set_write_timeout(Some(TREZOR_BRIDGE_WRITE_TIMEOUT))
            .map_err(|error| bridge_io_error(error_mode, &error))?;

        let body = body.unwrap_or("");
        let request = format!(
            "POST {path} HTTP/1.0\r\nHost: {TREZOR_BRIDGE_HOST}\r\nOrigin: {TREZOR_BRIDGE_ORIGIN}\r\nUser-Agent: railgun-wallet\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|error| bridge_io_error(error_mode, &error))?;
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .map_err(|error| bridge_io_error(error_mode, &error))?;
        parse_http_response(&response).map_err(BridgeConnectError::Transport)
    }

    fn bridge_io_error(
        error_mode: BridgeHttpErrorMode,
        error: &std::io::Error,
    ) -> BridgeConnectError {
        match error_mode {
            BridgeHttpErrorMode::Unavailable => BridgeConnectError::Unavailable(error.to_string()),
            BridgeHttpErrorMode::Transport => BridgeConnectError::Transport(error.to_string()),
        }
    }

    fn parse_http_response(response: &[u8]) -> Result<BridgeHttpResponse, String> {
        let Some(header_end) = response.windows(4).position(|window| window == b"\r\n\r\n") else {
            return Err("Trezor Bridge returned an invalid HTTP response".to_owned());
        };
        let headers = std::str::from_utf8(&response[..header_end])
            .map_err(|error| format!("Trezor Bridge returned non-UTF-8 headers: {error}"))?;
        let status = headers
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|status| status.parse::<u16>().ok())
            .ok_or_else(|| "Trezor Bridge returned an invalid HTTP status".to_owned())?;
        Ok(BridgeHttpResponse {
            status,
            body: response[header_end + 4..].to_vec(),
        })
    }

    fn ensure_success(status: u16, body: &[u8]) -> Result<(), String> {
        if (200..300).contains(&status) {
            return Ok(());
        }
        let body = String::from_utf8_lossy(body);
        Err(format!("Trezor Bridge HTTP {status}: {body}"))
    }

    pub(super) fn select_bridge_device(
        devices: &[BridgeDevice],
    ) -> Result<BridgeDevice, BridgeConnectError> {
        match devices {
            [] => Err(BridgeConnectError::NoDevice),
            [device] if device.session.is_some() => Err(BridgeConnectError::DeviceBusy),
            [device] => Ok(device.clone()),
            _ => Err(BridgeConnectError::DeviceNotUnique(devices.len())),
        }
    }

    fn bridge_path(segments: &[&str]) -> String {
        let mut path = String::new();
        for segment in segments {
            path.push('/');
            percent_encode_path_segment(segment, &mut path);
        }
        path
    }

    fn percent_encode_path_segment(segment: &str, output: &mut String) {
        for byte in segment.bytes() {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                output.push(char::from(byte));
            } else {
                output.push('%');
                output.push(char::from(hex_digit(byte >> 4)));
                output.push(char::from(hex_digit(byte & 0x0f)));
            }
        }
    }

    const fn hex_digit(value: u8) -> u8 {
        match value {
            0..=9 => b'0' + value,
            10..=15 => b'A' + (value - 10),
            _ => b'0',
        }
    }

    pub(super) fn encode_bridge_message(message: ProtoMessage) -> String {
        let message_type = message.message_type() as u16;
        let payload = message.into_payload();
        let mut data = Vec::with_capacity(6 + payload.len());
        data.extend_from_slice(&message_type.to_be_bytes());
        data.extend_from_slice(
            &u32::try_from(payload.len())
                .expect("Trezor protobuf payload length fits in u32")
                .to_be_bytes(),
        );
        data.extend_from_slice(&payload);
        hex::encode(data)
    }

    pub(super) fn decode_bridge_message(data: &[u8]) -> Result<ProtoMessage, TrezorTransportError> {
        if data.len() < 6 {
            return Err(TrezorTransportError::UnexpectedChunkSizeFromDevice(
                data.len(),
            ));
        }
        let message_type_id = u16::from_be_bytes([data[0], data[1]]);
        let data_len = u32::from_be_bytes([data[2], data[3], data[4], data[5]]) as usize;
        if data.len() != 6 + data_len {
            return Err(TrezorTransportError::UnexpectedChunkSizeFromDevice(
                data.len(),
            ));
        }
        let message_type = trezor_client::protos::MessageType::from_i32(i32::from(message_type_id))
            .ok_or_else(|| TrezorTransportError::InvalidMessageType(u32::from(message_type_id)))?;
        Ok(ProtoMessage::new(message_type, data[6..].to_vec()))
    }

    fn transport_io_error(message: impl Into<String>) -> TrezorTransportError {
        TrezorTransportError::IO(std::io::Error::other(message.into()))
    }

    pub struct TrezorHardwareDerivationClient {
        client: trezor_client::Trezor,
    }

    #[derive(Debug, Clone)]
    pub struct TrezorDeviceInfo {
        pub model: String,
        pub vendor: String,
        pub version: HardwareAppVersion,
        pub initialized: bool,
        pub passphrase_protection: bool,
        pub bootloader_mode: bool,
    }

    impl TrezorHardwareDerivationClient {
        pub fn connect() -> Result<Self, HardwareDerivationError> {
            match BridgeTransport::connect_unique() {
                Ok(transport) => {
                    let mut client = trezor_client::client::trezor_with_transport(
                        trezor_client::Model::Trezor,
                        Box::new(transport),
                    );
                    client.init_device(None)?;
                    Ok(Self { client })
                }
                Err(error) if error.should_fallback() => {
                    tracing::debug!(%error, "Trezor Bridge unavailable; falling back to direct WebUSB transport");
                    Self::connect_direct()
                }
                Err(error) => Err(error.into_hardware_error()),
            }
        }

        fn connect_direct() -> Result<Self, HardwareDerivationError> {
            let mut client = trezor_client::unique(false)?;
            client.init_device(None)?;
            Ok(Self { client })
        }

        pub fn device_info(&self) -> Result<TrezorDeviceInfo, HardwareDerivationError> {
            let features =
                self.client
                    .features()
                    .ok_or(HardwareDerivationError::InvalidDescriptor(
                        "Trezor features were not loaded",
                    ))?;
            Ok(TrezorDeviceInfo {
                model: features.model().to_owned(),
                vendor: features.vendor().to_owned(),
                version: HardwareAppVersion::new(
                    u16::try_from(features.major_version()).unwrap_or(u16::MAX),
                    u16::try_from(features.minor_version()).unwrap_or(u16::MAX),
                    u16::try_from(features.patch_version()).unwrap_or(u16::MAX),
                ),
                initialized: features.initialized(),
                passphrase_protection: features.passphrase_protection(),
                bootloader_mode: features.bootloader_mode(),
            })
        }

        pub fn ethereum_address(
            &mut self,
            path: &[u32],
        ) -> Result<String, HardwareDerivationError> {
            self.ethereum_address_with_confirmation(path, false)
        }

        fn ethereum_address_with_confirmation(
            &mut self,
            path: &[u32],
            display_and_confirm: bool,
        ) -> Result<String, HardwareDerivationError> {
            let request = trezor_ethereum_get_address_request(path, display_and_confirm);
            let address = handle_interaction(self.client.call(
                request,
                Box::new(|_, message: trezor_client::protos::EthereumAddress| {
                    Ok(message.address().to_owned())
                }),
            )?)?;
            Ok(address.to_ascii_lowercase())
        }

        pub fn public_ethereum_address(
            &mut self,
            descriptor: &HardwarePublicAccountDescriptor,
        ) -> Result<Address, HardwareDerivationError> {
            self.public_ethereum_address_with_confirmation(descriptor, false)
        }

        pub fn confirmed_public_ethereum_address(
            &mut self,
            descriptor: &HardwarePublicAccountDescriptor,
        ) -> Result<Address, HardwareDerivationError> {
            self.public_ethereum_address_with_confirmation(descriptor, true)
        }

        fn public_ethereum_address_with_confirmation(
            &mut self,
            descriptor: &HardwarePublicAccountDescriptor,
            display_and_confirm: bool,
        ) -> Result<Address, HardwareDerivationError> {
            descriptor.validate()?;
            if descriptor.device_kind != HardwareDeviceKind::Trezor {
                return Err(HardwareDerivationError::InvalidDescriptor(
                    "Trezor public account requires a Trezor descriptor",
                ));
            }
            self.ethereum_address_with_confirmation(&descriptor.path, display_and_confirm)?
                .parse()
                .map_err(|_| {
                    HardwareDerivationError::UnexpectedHardwareResponse(
                        "Trezor address response is not an EVM address",
                    )
                })
        }

        pub fn sign_transaction(
            &mut self,
            descriptor: &HardwarePublicAccountDescriptor,
            tx: &dyn SignableTransaction<Signature>,
        ) -> Result<Signature, HardwareDerivationError> {
            descriptor.validate()?;
            if descriptor.device_kind != HardwareDeviceKind::Trezor {
                return Err(HardwareDerivationError::InvalidDescriptor(
                    "Trezor transaction signing requires a Trezor descriptor",
                ));
            }
            let request = trezor_sign_request(tx)?;
            let signature = match request {
                TrezorSignRequest::Legacy(request) => {
                    self.sign_legacy_transaction(&descriptor.path, request)?
                }
                TrezorSignRequest::Eip1559(request) => {
                    self.sign_eip1559_transaction(&descriptor.path, request)?
                }
            };
            Ok(signature)
        }

        fn sign_legacy_transaction(
            &mut self,
            path: &[u32],
            mut request: TrezorLegacySignRequest,
        ) -> Result<Signature, HardwareDerivationError> {
            let chain_id = request.chain_id;
            let mut message = trezor_client::protos::EthereumSignTx::new();
            message.address_n = path.to_vec();
            message.set_nonce(request.nonce);
            message.set_gas_price(request.gas_price);
            message.set_gas_limit(request.gas_limit);
            message.set_value(request.value);
            if let Some(chain_id) = chain_id {
                message.set_chain_id(chain_id);
            }
            message.set_to(request.to);
            message.set_data_length(request.data.len() as u32);
            message.set_data_initial_chunk(trezor_ethereum_next_data_chunk(&mut request.data));

            let response = self.trezor_ethereum_signing_response(message, &mut request.data)?;
            trezor_signature_to_alloy(trezor_ethereum_signature_from_response(
                &response, chain_id,
            )?)
        }

        fn sign_eip1559_transaction(
            &mut self,
            path: &[u32],
            mut request: TrezorEip1559SignRequest,
        ) -> Result<Signature, HardwareDerivationError> {
            let chain_id = request.chain_id;
            let mut message = trezor_client::protos::EthereumSignTxEIP1559::new();
            message.address_n = path.to_vec();
            message.set_nonce(request.nonce);
            message.set_max_gas_fee(request.max_gas_fee);
            message.set_max_priority_fee(request.max_priority_fee);
            message.set_gas_limit(request.gas_limit);
            message.set_value(request.value);
            if let Some(chain_id) = chain_id {
                message.set_chain_id(chain_id);
            }
            message.set_to(request.to);
            if !request.access_list.is_empty() {
                message.access_list = request
                    .access_list
                    .into_iter()
                    .map(|item| {
                        trezor_client::protos::ethereum_sign_tx_eip1559::EthereumAccessList {
                            address: Some(item.address),
                            storage_keys: item.storage_keys,
                            ..Default::default()
                        }
                    })
                    .collect();
            }
            message.set_data_length(request.data.len() as u32);
            message.set_data_initial_chunk(trezor_ethereum_next_data_chunk(&mut request.data));

            let response = self.trezor_ethereum_signing_response(message, &mut request.data)?;
            trezor_signature_to_alloy(trezor_ethereum_signature_from_response(
                &response, chain_id,
            )?)
        }

        fn trezor_ethereum_signing_response<S: TrezorMessage>(
            &mut self,
            message: S,
            data: &mut Vec<u8>,
        ) -> Result<trezor_client::protos::EthereumTxRequest, HardwareDerivationError> {
            let mut response = handle_interaction(self.client.call(
                message,
                Box::new(|_, message: trezor_client::protos::EthereumTxRequest| Ok(message)),
            )?)?;
            while response.data_length() > 0 {
                let mut ack = trezor_client::protos::EthereumTxAck::new();
                ack.set_data_chunk(trezor_ethereum_next_data_chunk(data));
                response = handle_interaction(self.client.call(
                    ack,
                    Box::new(|_, message: trezor_client::protos::EthereumTxRequest| Ok(message)),
                )?)?;
            }
            Ok(response)
        }

        pub fn sign_message(
            &mut self,
            descriptor: &HardwarePublicAccountDescriptor,
            message: &[u8],
        ) -> Result<Signature, HardwareDerivationError> {
            descriptor.validate()?;
            if descriptor.device_kind != HardwareDeviceKind::Trezor {
                return Err(HardwareDerivationError::InvalidDescriptor(
                    "Trezor message signing requires a Trezor descriptor",
                ));
            }
            let signature = self
                .client
                .ethereum_sign_message(message.to_vec(), descriptor.path.clone())?;
            trezor_signature_to_alloy(signature)
        }

        pub fn profile_fingerprint(
            &mut self,
            path: &[u32],
        ) -> Result<String, HardwareDerivationError> {
            let address = self.ethereum_address(path)?;
            Ok(hardware_profile_fingerprint(
                HardwareDeviceKind::Trezor,
                address,
            ))
        }

        pub fn cipher_key_value(
            &mut self,
            descriptor: &HardwareDerivationDescriptor,
        ) -> Result<HardwareOperationOutput, HardwareDerivationError> {
            let mut request = trezor_client::protos::CipherKeyValue::new();
            request.address_n.clone_from(&descriptor.path);
            request.set_key(trezor_cipher_label(descriptor));
            request.set_value(TREZOR_CIPHER_INPUT_V1.to_vec());
            request.set_encrypt(true);
            request.set_ask_on_encrypt(true);
            request.set_ask_on_decrypt(true);

            let response = self.client.call(
                request,
                Box::new(|_, mut message: trezor_client::protos::CipheredKeyValue| {
                    Ok(message.take_value())
                }),
            )?;
            let mut data = handle_interaction(response)?;
            if data.len() != 32 {
                return Err(HardwareDerivationError::UnexpectedResponseLength {
                    got: data.len(),
                    expected: 32,
                });
            }
            let mut output = [0u8; 32];
            output.copy_from_slice(&data);
            data.zeroize();
            Ok(HardwareOperationOutput::new(output))
        }
    }

    fn trezor_cipher_label(descriptor: &HardwareDerivationDescriptor) -> String {
        format!("Railgun wallet v1 account {}", descriptor.account_index)
    }

    fn trezor_ethereum_get_address_request(
        path: &[u32],
        display_and_confirm: bool,
    ) -> trezor_client::protos::EthereumGetAddress {
        let mut request = trezor_client::protos::EthereumGetAddress::new();
        request.address_n = path.to_vec();
        request.set_show_display(display_and_confirm);
        request
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TrezorLegacySignRequest {
        nonce: Vec<u8>,
        gas_price: Vec<u8>,
        gas_limit: Vec<u8>,
        to: String,
        value: Vec<u8>,
        data: Vec<u8>,
        chain_id: Option<u64>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TrezorEip1559SignRequest {
        nonce: Vec<u8>,
        gas_limit: Vec<u8>,
        to: String,
        value: Vec<u8>,
        data: Vec<u8>,
        chain_id: Option<u64>,
        max_gas_fee: Vec<u8>,
        max_priority_fee: Vec<u8>,
        access_list: Vec<trezor_client::client::AccessListItem>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum TrezorSignRequest {
        Legacy(TrezorLegacySignRequest),
        Eip1559(TrezorEip1559SignRequest),
    }

    fn trezor_sign_request(
        tx: &dyn SignableTransaction<Signature>,
    ) -> Result<TrezorSignRequest, HardwareDerivationError> {
        let nonce = u64_to_trezor(tx.nonce());
        let gas_limit = u64_to_trezor(tx.gas_limit());
        let to = match tx.kind() {
            TxKind::Call(to) => to.to_checksum(None),
            TxKind::Create => String::new(),
        };
        let value = u256_to_trezor(tx.value());
        let data = tx.input().to_vec();
        let chain_id = tx.chain_id();

        if tx.is_eip1559() {
            let access_list = tx
                .access_list()
                .map(|access_list| {
                    access_list
                        .0
                        .iter()
                        .map(|item| trezor_client::client::AccessListItem {
                            address: item.address.to_checksum(None),
                            storage_keys: item
                                .storage_keys
                                .iter()
                                .map(|key| key.to_vec())
                                .collect(),
                        })
                        .collect()
                })
                .unwrap_or_default();
            Ok(TrezorSignRequest::Eip1559(TrezorEip1559SignRequest {
                nonce,
                gas_limit,
                to,
                value,
                data,
                chain_id,
                max_gas_fee: u128_to_trezor(tx.max_fee_per_gas()),
                max_priority_fee: u128_to_trezor(tx.max_priority_fee_per_gas().unwrap_or_default()),
                access_list,
            }))
        } else if tx.is_legacy() {
            Ok(TrezorSignRequest::Legacy(TrezorLegacySignRequest {
                nonce,
                gas_price: u128_to_trezor(tx.max_fee_per_gas()),
                gas_limit,
                to,
                value,
                data,
                chain_id,
            }))
        } else {
            Err(HardwareDerivationError::UnexpectedHardwareResponse(
                "Trezor only supports legacy and EIP-1559 transaction signing",
            ))
        }
    }

    fn trezor_ethereum_next_data_chunk(data: &mut Vec<u8>) -> Vec<u8> {
        let chunk_len = TREZOR_ETHEREUM_TX_CHUNK_SIZE.min(data.len());
        data.drain(..chunk_len).collect()
    }

    fn trezor_ethereum_signature_from_response(
        response: &trezor_client::protos::EthereumTxRequest,
        chain_id: Option<u64>,
    ) -> Result<trezor_client::client::Signature, HardwareDerivationError> {
        let mut v = u64::from(response.signature_v());
        if let Some(chain_id) = chain_id
            && v <= 1
        {
            v += 2 * chain_id + 35;
        }
        let r = response.signature_r().try_into().map_err(|_| {
            HardwareDerivationError::UnexpectedResponseLength {
                got: response.signature_r().len(),
                expected: 32,
            }
        })?;
        let s = response.signature_s().try_into().map_err(|_| {
            HardwareDerivationError::UnexpectedResponseLength {
                got: response.signature_s().len(),
                expected: 32,
            }
        })?;
        Ok(trezor_client::client::Signature { r, s, v })
    }

    fn u64_to_trezor(value: u64) -> Vec<u8> {
        let bytes = value.to_be_bytes();
        bytes[value.leading_zeros() as usize / 8..].to_vec()
    }

    fn u128_to_trezor(value: u128) -> Vec<u8> {
        let bytes = value.to_be_bytes();
        bytes[value.leading_zeros() as usize / 8..].to_vec()
    }

    fn u256_to_trezor(value: U256) -> Vec<u8> {
        let bytes = value.to_be_bytes::<32>();
        bytes[value.leading_zeros() / 8..].to_vec()
    }

    fn trezor_signature_to_alloy(
        signature: trezor_client::client::Signature,
    ) -> Result<Signature, HardwareDerivationError> {
        let parity =
            normalize_v(signature.v).ok_or(HardwareDerivationError::UnexpectedHardwareResponse(
                "Trezor signature has invalid recovery id",
            ))?;
        Ok(Signature::new(
            U256::from_be_bytes(signature.r),
            U256::from_be_bytes(signature.s),
            parity,
        ))
    }

    #[async_trait(?Send)]
    impl HardwareDerivationClient for TrezorHardwareDerivationClient {
        async fn derive_hardware_output(
            &mut self,
            descriptor: &HardwareDerivationDescriptor,
        ) -> Result<HardwareOperationOutput, HardwareDerivationError> {
            descriptor.validate()?;
            if descriptor.method != HardwareDerivationMethod::TrezorCipherKeyValueV1 {
                return Err(HardwareDerivationError::InvalidDescriptor(
                    "Trezor client requires a Trezor CipherKeyValue descriptor",
                ));
            }
            self.cipher_key_value(descriptor)
        }
    }

    #[cfg(test)]
    mod tests {
        use std::collections::VecDeque;
        use std::sync::{Arc, Mutex};

        use trezor_client::protos::MessageType;

        use super::*;

        struct QueuedTransport {
            responses: VecDeque<ProtoMessage>,
            writes: Arc<Mutex<Vec<MessageType>>>,
        }

        impl Transport for QueuedTransport {
            fn session_begin(&mut self) -> Result<(), TrezorTransportError> {
                Ok(())
            }

            fn session_end(&mut self) -> Result<(), TrezorTransportError> {
                Ok(())
            }

            fn write_message(&mut self, message: ProtoMessage) -> Result<(), TrezorTransportError> {
                self.writes
                    .lock()
                    .expect("writes lock")
                    .push(message.message_type());
                Ok(())
            }

            fn read_message(&mut self) -> Result<ProtoMessage, TrezorTransportError> {
                self.responses.pop_front().ok_or_else(|| {
                    TrezorTransportError::IO(std::io::Error::other("no queued response"))
                })
            }
        }

        fn queued_message<M: TrezorMessage>(message: &M) -> ProtoMessage {
            ProtoMessage(
                M::MESSAGE_TYPE,
                message.write_to_bytes().expect("encode test message"),
            )
        }

        #[test]
        fn ethereum_signing_flow_handles_button_request_after_data_ack() {
            let mut chunk_request = trezor_client::protos::EthereumTxRequest::new();
            chunk_request.set_data_length(1);
            let button_request = trezor_client::protos::ButtonRequest::new();
            let mut final_request = trezor_client::protos::EthereumTxRequest::new();
            final_request.set_signature_v(1);
            final_request.set_signature_r(vec![1; 32]);
            final_request.set_signature_s(vec![2; 32]);

            let writes = Arc::new(Mutex::new(Vec::new()));
            let transport = QueuedTransport {
                responses: VecDeque::from([
                    queued_message(&chunk_request),
                    queued_message(&button_request),
                    queued_message(&final_request),
                ]),
                writes: Arc::clone(&writes),
            };
            let client = trezor_client::client::trezor_with_transport(
                trezor_client::Model::Trezor,
                Box::new(transport),
            );
            let mut client = TrezorHardwareDerivationClient { client };
            let signature = client
                .sign_legacy_transaction(
                    &[0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0],
                    TrezorLegacySignRequest {
                        nonce: vec![1],
                        gas_price: vec![1],
                        gas_limit: vec![0x52, 0x08],
                        to: "0x1111111111111111111111111111111111111111".to_owned(),
                        value: Vec::new(),
                        data: vec![0xaa; TREZOR_ETHEREUM_TX_CHUNK_SIZE + 1],
                        chain_id: Some(1),
                    },
                )
                .expect("signing flow handles button request after ack");

            assert_eq!(signature.r(), U256::from_be_slice(&[1; 32]));
            assert_eq!(signature.s(), U256::from_be_slice(&[2; 32]));
            assert_eq!(
                writes.lock().expect("writes lock").as_slice(),
                &[
                    MessageType::MessageType_EthereumSignTx,
                    MessageType::MessageType_EthereumTxAck,
                    MessageType::MessageType_ButtonAck,
                ]
            );
        }

        #[test]
        fn trezor_address_confirmation_sets_display_flag() {
            let path = [0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0];

            let silent = trezor_ethereum_get_address_request(&path, false);
            assert_eq!(silent.address_n, path.to_vec());
            assert!(!silent.show_display());

            let confirmed = trezor_ethereum_get_address_request(&path, true);
            assert_eq!(confirmed.address_n, path.to_vec());
            assert!(confirmed.show_display());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_descriptor() -> HardwareDerivationDescriptor {
        HardwareDerivationDescriptor::ledger_eip1024_v1(
            parse_bip32_path("m/44'/60'/0'/0/0").expect("valid path"),
            0,
            "0x0123456789abcdef".to_owned(),
            None,
            HardwareWalletSyncIntent::CreateNew,
        )
    }

    #[test]
    fn path_roundtrip() {
        let path = parse_bip32_path("m/44'/60'/0'/0/0").expect("valid path");
        assert_eq!(format_bip32_path(&path), "m/44'/60'/0'/0/0");
    }

    #[test]
    fn hardware_public_account_paths_partition_by_wallet_account() {
        let trezor_zero = HardwarePublicAccountDescriptor::for_wallet_public_index(
            HardwareDeviceKind::Trezor,
            0,
            0,
        )
        .expect("trezor wallet 0 public 0 path");
        let trezor_one = HardwarePublicAccountDescriptor::for_wallet_public_index(
            HardwareDeviceKind::Trezor,
            1,
            2,
        )
        .expect("trezor wallet 1 public 2 path");
        let ledger_zero = HardwarePublicAccountDescriptor::for_wallet_public_index(
            HardwareDeviceKind::Ledger,
            0,
            0,
        )
        .expect("ledger wallet 0 public 0 path");
        let ledger_one = HardwarePublicAccountDescriptor::for_wallet_public_index(
            HardwareDeviceKind::Ledger,
            1,
            2,
        )
        .expect("ledger wallet 1 public 2 path");

        assert_eq!(trezor_zero.path_display(), "m/44'/60'/0'/0/0");
        assert_eq!(trezor_one.path_display(), "m/44'/60'/1'/0/2");
        assert_eq!(ledger_zero.path_display(), "m/44'/60'/0'/0/0");
        assert_eq!(ledger_one.path_display(), "m/44'/60'/1'/0/2");
    }

    #[test]
    fn hardware_derivation_descriptor_rejects_hardened_account_index() {
        let mut descriptor = test_descriptor();
        descriptor.account_index = HARDENED_BIP32_INDEX;

        assert!(matches!(
            descriptor.validate(),
            Err(HardwareDerivationError::InvalidDescriptor(
                "hardware wallet account index is too large"
            ))
        ));
    }

    #[test]
    fn legacy_hardware_public_account_descriptor_still_validates() {
        let descriptor: HardwarePublicAccountDescriptor = serde_json::from_str(
            r#"{
                "device_kind":"ledger",
                "path_kind":"ledger_live",
                "path":[2147483692,2147483708,2147483649,0,0],
                "account_index":1
            }"#,
        )
        .expect("legacy descriptor");

        assert_eq!(descriptor.wallet_account_index, 0);
        assert_eq!(descriptor.public_account_index, 1);
        descriptor.validate().expect("legacy descriptor validates");
    }

    #[cfg(feature = "hardware")]
    #[test]
    fn early_device_readiness_error_includes_trezor_no_device() {
        assert!(
            HardwareDerivationError::Trezor(trezor_client::Error::NoDeviceFound)
                .is_early_device_readiness_error()
        );
        assert!(
            HardwareDerivationError::Trezor(trezor_client::Error::TransportConnect(
                trezor_client::transport::error::Error::DeviceNotFound,
            ))
            .is_early_device_readiness_error()
        );
        assert!(
            !HardwareDerivationError::Trezor(trezor_client::Error::UnexpectedInteractionRequest(
                trezor_client::client::InteractionType::Button,
            ))
            .is_early_device_readiness_error()
        );
    }

    #[test]
    fn descriptor_debug_redacts_fingerprint_and_passphrase_hint() {
        let mut descriptor = test_descriptor();
        descriptor.passphrase_hint = Some("passphrase wallet".to_owned());
        let debug = format!("{descriptor:?}");
        assert!(!debug.contains("0123456789abcdef"));
        assert!(!debug.contains("passphrase wallet"));
        assert!(debug.contains("<redacted>"));
        assert!(debug.contains("<present>"));
    }

    #[test]
    fn synthetic_entropy_is_deterministic_for_pure_vector() {
        let descriptor = test_descriptor();
        let mut hardware_output = [0u8; 32];
        for (index, byte) in hardware_output.iter_mut().enumerate() {
            *byte = u8::try_from(index).expect("index fits in u8");
        }
        let first = synthetic_entropy_from_hardware_output(
            &descriptor,
            HardwareOperationOutput::new(hardware_output),
        )
        .expect("derive entropy");
        let second = synthetic_entropy_from_hardware_output(
            &descriptor,
            HardwareOperationOutput::new(hardware_output),
        )
        .expect("derive entropy");
        assert_eq!(first.expose_secret(), second.expose_secret());
        assert_eq!(
            first.expose_secret(),
            &[
                0xf6, 0x87, 0x45, 0x84, 0x46, 0xa8, 0x16, 0x9e, 0xfb, 0x58, 0x6c, 0x3c, 0x75, 0xe6,
                0x9b, 0x0e, 0xeb, 0xde, 0xec, 0xb9, 0x6d, 0xf9, 0x9d, 0x17, 0xfc, 0xcf, 0xe3, 0xe9,
                0xf5, 0x80, 0x9f, 0x26,
            ],
        );
    }

    #[tokio::test]
    async fn mock_client_derives_synthetic_entropy() {
        let descriptor = test_descriptor();
        let mut mock = MockHardwareDerivationClient::new([[7u8; 32]]);
        let entropy = mock
            .derive_synthetic_entropy(&descriptor)
            .await
            .expect("derive entropy");
        assert_ne!(entropy.expose_secret(), &[0u8; 32]);
    }

    #[cfg(feature = "hardware")]
    #[test]
    fn trezor_bridge_message_framing_roundtrip() {
        let encoded = trezor::encode_bridge_message(trezor_client::transport::ProtoMessage::new(
            trezor_client::protos::MessageType::MessageType_Initialize,
            vec![1, 2, 3],
        ));
        assert_eq!(encoded, "000000000003010203");

        let bytes = alloy::hex::decode(encoded).expect("hex bridge frame");
        let decoded = trezor::decode_bridge_message(&bytes).expect("decode bridge frame");
        assert_eq!(
            decoded.message_type(),
            trezor_client::protos::MessageType::MessageType_Initialize,
        );
        assert_eq!(decoded.payload(), &[1, 2, 3]);
    }

    #[cfg(feature = "hardware")]
    #[test]
    fn trezor_bridge_selection_rejects_busy_or_ambiguous_devices() {
        let free = trezor::BridgeDevice {
            path: "device-1".to_owned(),
            session: None,
        };
        let busy = trezor::BridgeDevice {
            path: "device-1".to_owned(),
            session: Some("session".to_owned()),
        };

        assert!(matches!(
            trezor::select_bridge_device(&[]),
            Err(trezor::BridgeConnectError::NoDevice)
        ));
        assert!(matches!(
            trezor::select_bridge_device(std::slice::from_ref(&busy)),
            Err(trezor::BridgeConnectError::DeviceBusy)
        ));
        assert!(matches!(
            trezor::select_bridge_device(&[free.clone(), busy]),
            Err(trezor::BridgeConnectError::DeviceNotUnique(2))
        ));
        let selected = trezor::select_bridge_device(&[free]).expect("select one free device");
        assert_eq!(selected.path, "device-1");
    }

    #[cfg(feature = "hardware")]
    #[test]
    fn trezor_bridge_busy_message_points_to_competing_apps() {
        let message = trezor::trezor_bridge_busy_message();

        assert!(message.contains("Trezor Suite"));
        assert!(message.contains("browser wallet tabs"));
        assert!(message.contains("other Trezor applications"));
    }
}
