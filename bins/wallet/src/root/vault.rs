use std::sync::Arc;
#[cfg(feature = "hardware")]
use std::time::Duration;

#[cfg(feature = "hardware")]
use alloy::primitives::Address;
#[cfg(feature = "hardware")]
use gpui::div;
use gpui::{Context, Entity, Focusable, ParentElement, Styled, Window, px};
#[cfg(feature = "hardware")]
use gpui_component::scroll::ScrollableElement;
use gpui_component::{WindowExt, input::InputState, select::SearchableVec};
#[cfg(feature = "hardware")]
use tokio::{sync::mpsc, time::sleep};
use ui::controls::app_strong_text;
#[cfg(any(feature = "hardware", test))]
use wallet_ops::hardware::HARDENED_BIP32_INDEX;
#[cfg(feature = "hardware")]
use wallet_ops::hardware::{
    DEFAULT_HARDWARE_DERIVATION_PATH, HardwareDerivationDescriptor, HardwareDerivationError,
    HardwareDerivationMethod, HardwareViewAccessKey, SyntheticRailgunEntropy,
    hardware_view_access_key_from_hardware_output,
    ledger::LedgerHardwareDerivationClient,
    parse_bip32_path, synthetic_entropy_from_hardware_output,
    trezor::{
        TrezorHardwareDerivationClient, TrezorPinMatrixProvider, TrezorPinMatrixRequestKind,
        trezor_cipher_key_label,
    },
};
use wallet_ops::hardware::{HardwareDeviceKind, HardwareWalletSyncIntent};
#[cfg(any(feature = "hardware", test))]
use wallet_ops::vault::TrezorPassphraseMode;
#[cfg(feature = "hardware")]
use wallet_ops::vault::{
    DesktopVaultStore, HardwareProfileBindingKind, HardwareProfileSession, HardwareWalletProfile,
};
use wallet_ops::vault::{
    DesktopViewSession, HardwareProfileMetadata, HardwareRailgunAccountMetadata,
    PRIMARY_WALLET_LABEL, VaultError, ViewUnlock, WalletMetadataBundle, WalletSource,
    default_wallet_label_for_metadata, generate_opaque_id, generate_seed_material,
    sort_wallet_metadata,
};
#[cfg(feature = "hardware")]
use zeroize::Zeroize;
use zeroize::Zeroizing;

use super::wallet_header::WalletSelectItem;
use super::{
    BroadcasterActivityTab, ChainUtxoState, WalletRoot, WalletTab, dialog_content_max_height,
    dialog_max_height, scrollable_dialog_content, secondary_dialog_content_width,
};

pub(super) enum VaultState {
    CreateVault,
    UnlockVault,
    SetupWallet,
    ViewUnlocked,
    Error(Arc<str>),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum WalletSetupMode {
    Choose,
    GeneratedReview,
    Import,
    #[allow(dead_code)]
    Hardware(HardwareDeviceKind),
}

#[derive(Clone)]
pub(super) struct WalletOption {
    pub(super) wallet_id: Arc<str>,
    pub(super) source: WalletSource,
}

#[cfg(feature = "hardware")]
const TREZOR_APP_PASSPHRASE_REQUIRED_ERROR_TEXT: &str =
    "Trezor requested an app-entered passphrase but none was provided";

#[cfg(feature = "hardware")]
enum HardwareWalletCreationError {
    Hardware {
        error: HardwareDerivationError,
        awaiting_approval: bool,
    },
    Vault(VaultError),
}

#[cfg(feature = "hardware")]
type HardwareWalletCreationResult = (DesktopViewSession, Vec<WalletMetadataBundle>);

#[cfg(feature = "hardware")]
const HARDWARE_PROFILE_READINESS_RETRY_INTERVAL: Duration = Duration::from_secs(1);

#[cfg(feature = "hardware")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HardwareProfileStep {
    UnlockDevice,
    OpenEthereumApp,
    ApproveRailgunRequest,
}

#[cfg(feature = "hardware")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HardwareProfileStepStatus {
    NotStarted,
    Pending,
    Done,
    Error,
}

#[cfg(feature = "hardware")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HardwareProfilePickerView {
    Summary,
    ChooseDefaultSyncIntent,
}

#[cfg(feature = "hardware")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::root) enum HardwareProfileUnlockPurpose {
    OpenWallet,
    AddWallet,
}

#[cfg(feature = "hardware")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct HardwareProfileStepState {
    pub(super) step: HardwareProfileStep,
    pub(super) status: HardwareProfileStepStatus,
    pub(super) message: Option<Arc<str>>,
}

#[cfg(feature = "hardware")]
struct HardwareProfileProgressUpdate {
    step: HardwareProfileStep,
    status: HardwareProfileStepStatus,
    message: Option<String>,
    apply_step: bool,
    trezor_passphrase_always_on_device: Option<bool>,
    approval_prompt: Option<HardwareProfileApprovalPrompt>,
    trezor_pin_matrix_request: Option<HardwareProfilePinMatrixRequest>,
    clear_trezor_pin_matrix_request: bool,
}

#[cfg(feature = "hardware")]
struct HardwareProfilePinMatrixRequest {
    kind: TrezorPinMatrixRequestKind,
    response_tx: std::sync::mpsc::Sender<Zeroizing<String>>,
}

#[cfg(feature = "hardware")]
pub(super) struct TrezorPinMatrixPromptState {
    pub(super) kind: TrezorPinMatrixRequestKind,
    pub(super) positions: String,
    response_tx: Option<std::sync::mpsc::Sender<Zeroizing<String>>>,
}

#[cfg(feature = "hardware")]
impl TrezorPinMatrixPromptState {
    fn clear_sensitive(&mut self) {
        self.positions.zeroize();
    }
}

#[cfg(feature = "hardware")]
#[derive(Clone)]
pub(super) struct HardwareAccountPickerRow {
    pub(super) wallet_id: Arc<str>,
    pub(super) label: Arc<str>,
    pub(super) account_index: u32,
    pub(super) account: HardwareRailgunAccountMetadata,
    pub(super) supported: bool,
    pub(super) active: bool,
}

#[cfg(feature = "hardware")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum HardwareProfileApprovalPrompt {
    EvmAddress(Arc<str>),
    TrezorCipherKeyValue(Arc<str>),
}

#[cfg(feature = "hardware")]
pub(super) struct HardwareProfileUnlockState {
    pub(super) target_wallet_id: Option<Arc<str>>,
    pub(in crate::root) purpose: HardwareProfileUnlockPurpose,
    pub(super) device_kind: Option<HardwareDeviceKind>,
    pub(super) session: Option<HardwareProfileSession>,
    pub(super) profile: Option<HardwareProfileMetadata>,
    pub(super) accounts: Vec<HardwareAccountPickerRow>,
    pub(super) locked_accounts: Vec<HardwareAccountPickerRow>,
    pub(super) vault_view_unlock: Option<Arc<ViewUnlock>>,
    pub(super) in_progress: bool,
    pub(super) action_label: Option<Arc<str>>,
    pub(super) approval_prompt: Option<HardwareProfileApprovalPrompt>,
    pub(super) error: Option<Arc<str>>,
    pub(super) trezor_passphrase_mode: TrezorPassphraseMode,
    pub(super) trezor_passphrase_always_on_device: Option<bool>,
    pub(super) trezor_pin_matrix_prompt: Option<TrezorPinMatrixPromptState>,
    pub(super) progress_steps: Vec<HardwareProfileStepState>,
    pub(super) picker_view: HardwareProfilePickerView,
    pub(super) advanced_open: bool,
    pub(super) editing_label: bool,
    reconnect_notice: Option<Arc<str>>,
}

#[cfg(feature = "hardware")]
impl Default for HardwareProfileUnlockState {
    fn default() -> Self {
        Self {
            target_wallet_id: None,
            purpose: HardwareProfileUnlockPurpose::OpenWallet,
            device_kind: None,
            session: None,
            profile: None,
            accounts: Vec::new(),
            locked_accounts: Vec::new(),
            vault_view_unlock: None,
            in_progress: false,
            action_label: None,
            approval_prompt: None,
            error: None,
            trezor_passphrase_mode: TrezorPassphraseMode::NoPassphrase,
            trezor_passphrase_always_on_device: None,
            trezor_pin_matrix_prompt: None,
            progress_steps: default_hardware_profile_steps(),
            picker_view: HardwareProfilePickerView::Summary,
            advanced_open: false,
            editing_label: false,
            reconnect_notice: None,
        }
    }
}

#[cfg(feature = "hardware")]
impl HardwareProfileUnlockState {
    fn clear_sensitive(&mut self) {
        self.vault_view_unlock = None;
        self.clear_trezor_pin_matrix_prompt();
    }

    fn clear_trezor_pin_matrix_prompt(&mut self) {
        if let Some(mut prompt) = self.trezor_pin_matrix_prompt.take() {
            prompt.clear_sensitive();
        }
    }

    fn reset_for_device(
        &mut self,
        device_kind: HardwareDeviceKind,
        target_wallet_id: Option<Arc<str>>,
        purpose: HardwareProfileUnlockPurpose,
    ) {
        self.clear_sensitive();
        self.target_wallet_id = target_wallet_id;
        self.purpose = purpose;
        self.device_kind = Some(device_kind);
        self.session = None;
        self.profile = None;
        self.accounts.clear();
        self.locked_accounts.clear();
        self.in_progress = false;
        self.action_label = None;
        self.approval_prompt = None;
        self.error = None;
        self.trezor_passphrase_mode = TrezorPassphraseMode::NoPassphrase;
        self.trezor_passphrase_always_on_device = None;
        self.clear_trezor_pin_matrix_prompt();
        self.progress_steps = default_hardware_profile_steps();
        self.picker_view = HardwareProfilePickerView::Summary;
        self.advanced_open = false;
        self.editing_label = false;
        self.reconnect_notice = None;
    }

    fn set_progress_step(
        &mut self,
        step: HardwareProfileStep,
        status: HardwareProfileStepStatus,
        message: Option<impl Into<Arc<str>>>,
    ) {
        if let Some(existing) = self
            .progress_steps
            .iter_mut()
            .find(|existing| existing.step == step)
        {
            existing.status = status;
            existing.message = message.map(Into::into);
        }
    }

    fn mark_first_pending_progress_step_error(&mut self, message: impl Into<Arc<str>>) {
        let message = Some(message.into());
        if let Some(step) = self
            .progress_steps
            .iter_mut()
            .find(|step| step.status == HardwareProfileStepStatus::Pending)
        {
            step.status = HardwareProfileStepStatus::Error;
            step.message = message;
        }
    }

    #[must_use]
    fn awaiting_approval(&self) -> bool {
        self.progress_steps.iter().any(|step| {
            step.step == HardwareProfileStep::ApproveRailgunRequest
                && step.status == HardwareProfileStepStatus::Pending
        })
    }
}

#[cfg(feature = "hardware")]
fn default_hardware_profile_steps() -> Vec<HardwareProfileStepState> {
    [
        HardwareProfileStep::UnlockDevice,
        HardwareProfileStep::OpenEthereumApp,
        HardwareProfileStep::ApproveRailgunRequest,
    ]
    .into_iter()
    .map(|step| HardwareProfileStepState {
        step,
        status: HardwareProfileStepStatus::NotStarted,
        message: None,
    })
    .collect()
}

#[cfg(feature = "hardware")]
impl From<HardwareDerivationError> for HardwareWalletCreationError {
    fn from(error: HardwareDerivationError) -> Self {
        Self::Hardware {
            error,
            awaiting_approval: false,
        }
    }
}

#[cfg(feature = "hardware")]
const fn hardware_approval_error(error: HardwareDerivationError) -> HardwareWalletCreationError {
    HardwareWalletCreationError::Hardware {
        error,
        awaiting_approval: true,
    }
}

#[cfg(feature = "hardware")]
impl From<VaultError> for HardwareWalletCreationError {
    fn from(error: VaultError) -> Self {
        Self::Vault(error)
    }
}

pub(super) fn wallet_options_from_metadata(
    mut metadata: Vec<WalletMetadataBundle>,
) -> Vec<WalletOption> {
    metadata.retain(|metadata| metadata.status == wallet_ops::vault::WalletStatus::Active);
    sort_wallet_metadata(&mut metadata);
    metadata
        .into_iter()
        .map(|metadata| WalletOption {
            wallet_id: Arc::from(metadata.wallet_uuid),
            source: metadata.source,
        })
        .collect()
}

pub(in crate::root) const fn hardware_device_wallet_select_value(
    device_kind: HardwareDeviceKind,
) -> &'static str {
    match device_kind {
        HardwareDeviceKind::Ledger => "hardware-device:ledger",
        HardwareDeviceKind::Trezor => "hardware-device:trezor",
    }
}

pub(in crate::root) const fn hardware_device_wallet_select_label(
    device_kind: HardwareDeviceKind,
) -> &'static str {
    match device_kind {
        HardwareDeviceKind::Ledger => "Ledger",
        HardwareDeviceKind::Trezor => "Trezor",
    }
}

pub(in crate::root) fn hardware_device_kind_from_wallet_select_value(
    value: &str,
) -> Option<HardwareDeviceKind> {
    match value {
        "hardware-device:ledger" => Some(HardwareDeviceKind::Ledger),
        "hardware-device:trezor" => Some(HardwareDeviceKind::Trezor),
        _ => None,
    }
}

pub(in crate::root) fn wallet_select_items_from_metadata(
    metadata: &[WalletMetadataBundle],
) -> Vec<WalletSelectItem> {
    let mut metadata = metadata.to_vec();
    metadata.retain(|metadata| metadata.status == wallet_ops::vault::WalletStatus::Active);
    sort_wallet_metadata(&mut metadata);

    let mut items = Vec::new();
    let mut ledger_added = false;
    let mut trezor_added = false;

    for metadata in metadata {
        let Some(device_kind) = hardware_device_kind_from_source(metadata.source) else {
            items.push(WalletSelectItem {
                wallet_id: Arc::from(metadata.wallet_uuid),
                label: Arc::from(metadata.label),
            });
            continue;
        };
        if metadata.hardware_account.is_none() {
            continue;
        }

        let added = match device_kind {
            HardwareDeviceKind::Ledger => &mut ledger_added,
            HardwareDeviceKind::Trezor => &mut trezor_added,
        };
        if *added {
            continue;
        }
        *added = true;
        items.push(WalletSelectItem {
            wallet_id: Arc::from(hardware_device_wallet_select_value(device_kind)),
            label: Arc::from(hardware_device_wallet_select_label(device_kind)),
        });
    }

    items
}

#[cfg(any(feature = "hardware", test))]
pub(in crate::root) const fn hardware_session_needs_trezor_app_passphrase(
    session: &wallet_ops::vault::HardwareProfileSession,
) -> bool {
    session.uses_trezor_app_passphrase() && session.trezor_session_id.is_none()
}

#[cfg(feature = "hardware")]
fn trezor_app_passphrase_required_error_message(message: &str) -> bool {
    message.contains(TREZOR_APP_PASSPHRASE_REQUIRED_ERROR_TEXT)
}

#[cfg(feature = "hardware")]
pub(in crate::root) fn trezor_session_stale_error_message(message: &str) -> bool {
    trezor_app_passphrase_required_error_message(message)
        || message.contains("derived hardware wallet key does not match the stored wallet")
        || message.contains("Hardware wallet identity mismatch")
        || message.contains("hardware wallet identity mismatch")
        || message.contains("hardware public signer profile mismatch")
        || message.contains("hardware public account identity mismatch")
        || message.contains("wrong hardware device or passphrase context is active")
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::root) struct HardwareWalletDisplayInfo {
    pub(in crate::root) chip_label: String,
    pub(in crate::root) detail_label: String,
}

pub(in crate::root) fn hardware_wallet_display_info(
    wallet: &WalletMetadataBundle,
    active_profile: Option<&HardwareProfileMetadata>,
) -> Option<HardwareWalletDisplayInfo> {
    let account = wallet.hardware_account.as_ref()?;
    let device_kind = hardware_device_kind_from_source(wallet.source)?;
    let profile_label = hardware_wallet_profile_label(
        wallet,
        &account.profile_id,
        account.account_index,
        active_profile,
    );
    let compact_profile_label = compact_hardware_profile_label(&profile_label, device_kind);
    let renamed_account_label = renamed_hardware_account_label(wallet, account);
    let account_label = renamed_account_label
        .clone()
        .unwrap_or_else(|| hardware_account_index_label(account.account_index));
    let chip_label = format!("{compact_profile_label} / {account_label}");
    let detail_label = if let Some(renamed_account_label) = renamed_account_label {
        format!(
            "{}: {profile_label} / {renamed_account_label} account {}",
            hardware_device_wallet_select_label(device_kind),
            account.account_index
        )
    } else {
        format!(
            "{}: {profile_label} account {}",
            hardware_device_wallet_select_label(device_kind),
            account.account_index
        )
    };

    Some(HardwareWalletDisplayInfo {
        chip_label,
        detail_label,
    })
}

#[cfg(feature = "hardware")]
pub(super) fn hardware_profile_approval_prompt_for_account(
    account: &HardwareRailgunAccountMetadata,
) -> Option<HardwareProfileApprovalPrompt> {
    hardware_profile_approval_prompt_for_descriptor(&account.descriptor)
}

#[cfg(feature = "hardware")]
fn hardware_profile_approval_prompt_for_descriptor(
    descriptor: &HardwareDerivationDescriptor,
) -> Option<HardwareProfileApprovalPrompt> {
    match descriptor.method {
        HardwareDerivationMethod::LedgerEip1024V1 => None,
        HardwareDerivationMethod::TrezorCipherKeyValueV1 => {
            Some(HardwareProfileApprovalPrompt::TrezorCipherKeyValue(
                Arc::from(trezor_cipher_key_label(descriptor.account_index)),
            ))
        }
    }
}

#[cfg(feature = "hardware")]
fn hardware_profile_approval_prompt_for_account_index(
    device_kind: HardwareDeviceKind,
    account_index: u32,
) -> Option<HardwareProfileApprovalPrompt> {
    match device_kind {
        HardwareDeviceKind::Ledger => None,
        HardwareDeviceKind::Trezor => Some(HardwareProfileApprovalPrompt::TrezorCipherKeyValue(
            Arc::from(trezor_cipher_key_label(account_index)),
        )),
    }
}

fn hardware_wallet_profile_label(
    wallet: &WalletMetadataBundle,
    profile_id: &str,
    account_index: u32,
    active_profile: Option<&HardwareProfileMetadata>,
) -> String {
    if let Some(profile) = active_profile.filter(|profile| profile.profile_id == profile_id) {
        return profile.label.clone();
    }

    let label = wallet
        .hardware_account
        .as_ref()
        .map_or(wallet.label.as_str(), |account| account.label.as_str());
    strip_hardware_account_suffix(label, account_index).to_owned()
}

fn renamed_hardware_account_label(
    wallet: &WalletMetadataBundle,
    account: &HardwareRailgunAccountMetadata,
) -> Option<String> {
    (wallet.label != account.label)
        .then(|| strip_hardware_account_suffix(&wallet.label, account.account_index).to_owned())
}

fn hardware_account_index_label(account_index: u32) -> String {
    format!("Account {account_index}")
}

fn strip_hardware_account_suffix(label: &str, account_index: u32) -> &str {
    let recovery_suffix = format!(" account {account_index} recovery");
    if let Some(profile_label) = label.strip_suffix(&recovery_suffix)
        && !profile_label.trim().is_empty()
    {
        return profile_label.trim();
    }

    let suffix = format!(" account {account_index}");
    if let Some(profile_label) = label.strip_suffix(&suffix)
        && !profile_label.trim().is_empty()
    {
        return profile_label.trim();
    }

    label
}

fn compact_hardware_profile_label(profile_label: &str, device_kind: HardwareDeviceKind) -> String {
    let default_profile_prefix = match device_kind {
        HardwareDeviceKind::Ledger => "Ledger hardware profile",
        HardwareDeviceKind::Trezor => "Trezor hardware profile",
    };

    if let Some(suffix) = profile_label.strip_prefix(default_profile_prefix) {
        let suffix = suffix.trim();
        return if suffix.is_empty() {
            "Profile".to_owned()
        } else {
            format!("Profile {suffix}")
        };
    }

    profile_label.to_owned()
}

pub(in crate::root) fn wallet_select_value_for_selected_wallet(
    wallet_id: &Arc<str>,
    metadata: &[WalletMetadataBundle],
) -> Arc<str> {
    metadata
        .iter()
        .find(|metadata| {
            metadata.status == wallet_ops::vault::WalletStatus::Active
                && metadata.wallet_uuid == wallet_id.as_ref()
        })
        .and_then(|metadata| {
            if metadata.hardware_account.is_some() {
                hardware_device_kind_from_source(metadata.source)
                    .map(hardware_device_wallet_select_value)
                    .map(Arc::from)
            } else {
                None
            }
        })
        .unwrap_or_else(|| Arc::clone(wallet_id))
}

pub(super) const fn vault_error_kind(error: &VaultError) -> &'static str {
    match error {
        VaultError::Random => "random",
        VaultError::InvalidKdfParams => "invalid_kdf_params",
        VaultError::Kdf => "kdf",
        VaultError::KeySeparation => "key_separation",
        VaultError::Encrypt => "encrypt",
        VaultError::Decrypt => "decrypt",
        VaultError::Encode(_) => "encode",
        VaultError::Decode(_) => "decode",
        VaultError::Db(_) => "db",
        VaultError::Io(_) => "io",
        VaultError::Key(_) => "key",
        VaultError::UnsupportedVersion(_) => "unsupported_version",
        VaultError::VaultAlreadyExists => "vault_already_exists",
        VaultError::VaultNotFound => "vault_not_found",
        VaultError::UnlockFailed => "unlock_failed",
        VaultError::InvalidSpendGrant => "invalid_spend_grant",
        VaultError::WalletNotFound => "wallet_not_found",
        VaultError::InvalidWalletLabel => "invalid_wallet_label",
        VaultError::DuplicateWalletLabel => "duplicate_wallet_label",
        VaultError::InvalidWalletOrder => "invalid_wallet_order",
        VaultError::LastActiveWallet => "last_active_wallet",
        VaultError::WalletDisplayOrderOverflow => "wallet_display_order_overflow",
        VaultError::PublicAccountNotFound => "public_account_not_found",
        VaultError::DuplicatePublicAccountAddress => "duplicate_public_account_address",
        VaultError::InvalidPublicAccountOperation => "invalid_public_account_operation",
        VaultError::PublicAccountDisplayOrderOverflow => "public_account_display_order_overflow",
        VaultError::InvalidPublicEvmPrivateKey => "invalid_public_evm_private_key",
        VaultError::PublicEvmKeyDerivation => "public_evm_key_derivation",
        VaultError::InvalidAddressBookLabel => "invalid_address_book_label",
        VaultError::InvalidPrivateAddressBookAddress => "invalid_private_address_book_address",
        VaultError::DuplicatePrivateAddressBookAddress => "duplicate_private_address_book_address",
        VaultError::PrivateAddressBookEntryNotFound => "private_address_book_entry_not_found",
        VaultError::PrivateAddressBookDisplayOrderOverflow => {
            "private_address_book_display_order_overflow"
        }
        VaultError::InvalidPublicAddressBookAddress => "invalid_public_address_book_address",
        VaultError::DuplicatePublicAddressBookAddress => "duplicate_public_address_book_address",
        VaultError::PublicAddressBookEntryNotFound => "public_address_book_entry_not_found",
        VaultError::PublicAddressBookDisplayOrderOverflow => {
            "public_address_book_display_order_overflow"
        }
        VaultError::InvalidBroadcasterPreferenceAddress => "invalid_broadcaster_preference_address",
        VaultError::InvalidHardwareWalletDescriptor => "invalid_hardware_wallet_descriptor",
        VaultError::HardwareWalletAccountIndexOverflow => "hardware_wallet_account_index_overflow",
        VaultError::DuplicateHardwareWalletAccountIndex => {
            "duplicate_hardware_wallet_account_index"
        }
        VaultError::HardwareWalletIdentityMismatch => "hardware_wallet_identity_mismatch",
        VaultError::HardwareWalletViewRequiresDevice => "hardware_wallet_view_requires_device",
        VaultError::UnsupportedHardwareCustodyBackend(_) => "unsupported_hardware_custody_backend",
        VaultError::InvalidHardwareAccountRecoveryRange => {
            "invalid_hardware_account_recovery_range"
        }
        VaultError::HardwareWalletReceiveAddress => "hardware_wallet_receive_address",
    }
}

#[cfg(feature = "hardware")]
pub(in crate::root) const fn hardware_setup_error_preserves_password(
    error: &HardwareDerivationError,
) -> bool {
    error.is_early_device_readiness_error()
}

#[cfg(feature = "hardware")]
pub(in crate::root) fn hardware_profile_evm_address_for_session(
    session: Option<&HardwareProfileSession>,
) -> Option<String> {
    let session = session?;
    if session.binding.kind != HardwareProfileBindingKind::EvmAddressFingerprint {
        return None;
    }
    let prefix = format!("{}:evm:", session.device_kind.as_str());
    let address = session.binding.fingerprint.strip_prefix(&prefix)?;
    let parsed: Address = address.parse().ok()?;
    Some(format!("{parsed:#x}"))
}

#[cfg(feature = "hardware")]
pub(in crate::root) fn hardware_profile_hardware_error_message(
    operation: &str,
    error: &HardwareDerivationError,
    awaiting_approval: bool,
) -> Arc<str> {
    let awaiting_approval = awaiting_approval
        || matches!(
            error,
            HardwareDerivationError::LedgerStatus {
                operation: "derive Railgun secret",
                ..
            }
        );
    if error.is_ledger_busy_error() {
        return "Ledger connection is busy. Make sure no other wallet app is using it, keep the Ethereum app open, then try again. If this keeps happening, unplug and reconnect your Ledger."
            .into();
    }
    if awaiting_approval {
        match error {
            HardwareDerivationError::LedgerStatus { status: 0x6982, .. } => {
                return "Request rejected on Ledger. Try again when you are ready to approve it."
                    .into();
            }
            HardwareDerivationError::LedgerStatus { status: 0x6985, .. } => {
                return "Ledger did not approve the request. If it locked or timed out, unlock your Ledger, open the Ethereum app, then try again."
                    .into();
            }
            HardwareDerivationError::LedgerStatus {
                status: 0x6804 | 0x6b0c,
                ..
            } => {
                return "Ledger locked before the request was approved. Unlock your Ledger, open the Ethereum app, then try again."
                    .into();
            }
            HardwareDerivationError::LedgerStatus {
                status: 0x6511 | 0x6a15 | 0x6d00 | 0x6e00,
                ..
            } => {
                return "The Ethereum app closed before the request was approved. Unlock your Ledger, open the Ethereum app, then try again."
                    .into();
            }
            HardwareDerivationError::LedgerUnavailable(_) | HardwareDerivationError::Ledger(_) => {
                return "Ledger locked or disconnected before the request was approved. Unlock your Ledger, open the Ethereum app, then try again."
                    .into();
            }
            HardwareDerivationError::TrezorLocked
            | HardwareDerivationError::UnsupportedTrezorPinMatrix => {
                return "Trezor locked before the request was approved. Unlock your Trezor, then try again."
                    .into();
            }
            HardwareDerivationError::TrezorBridge(_) | HardwareDerivationError::Trezor(_) => {
                return "Trezor locked or disconnected before the request was approved. Unlock your Trezor, then try again."
                    .into();
            }
            _ => {}
        }
    }

    match error {
        HardwareDerivationError::LedgerUnavailable(_) => {
            "Connect and unlock your Ledger, open the Ethereum app, then try again.".into()
        }
        HardwareDerivationError::LedgerStatus { message, .. } => (*message).into(),
        HardwareDerivationError::Ledger(_) => {
            "Ledger communication failed. Keep the Ethereum app open, then try again. If this keeps happening, unplug and reconnect your Ledger."
                .into()
        }
        HardwareDerivationError::TrezorBridge(_) | HardwareDerivationError::Trezor(_) => {
            "Connect and unlock your Trezor, then try again.".into()
        }
        HardwareDerivationError::TrezorLocked
        | HardwareDerivationError::UnsupportedTrezorPinMatrix => {
            "Unlock your Trezor, then try again.".into()
        }
        _ => format!("{operation}: {error}").into(),
    }
}

#[cfg(feature = "hardware")]
pub(in crate::root) const fn hardware_profile_should_reconnect_after_error(
    error: &HardwareDerivationError,
    awaiting_approval: bool,
) -> bool {
    if awaiting_approval || error.is_ledger_busy_error() {
        return false;
    }
    match error {
        HardwareDerivationError::LedgerUnavailable(_) | HardwareDerivationError::Ledger(_) => true,
        HardwareDerivationError::LedgerStatus { status, .. } => {
            ledger_locked_status(*status) || ledger_ethereum_app_status(*status)
        }
        _ => false,
    }
}

#[cfg(feature = "hardware")]
pub(in crate::root) fn hardware_profile_detection_should_retry(
    error: &HardwareDerivationError,
) -> bool {
    if error.is_early_device_readiness_error() {
        return true;
    }
    matches!(
        error,
        HardwareDerivationError::LedgerStatus {
            operation: "get Ethereum app version" | "get Ethereum address",
            ..
        }
    )
}

#[cfg(feature = "hardware")]
pub(in crate::root) const fn hardware_profile_detection_should_suppress_initial_trezor_progress(
    error: &HardwareDerivationError,
) -> bool {
    matches!(
        error,
        HardwareDerivationError::TrezorLocked | HardwareDerivationError::UnsupportedTrezorPinMatrix
    )
}

#[cfg(all(test, feature = "hardware"))]
pub(in crate::root) fn hardware_profile_detection_ledger_is_unlocked(
    error: &HardwareDerivationError,
) -> bool {
    matches!(
        error,
        HardwareDerivationError::LedgerStatus {
            operation: "get Ethereum app version" | "get Ethereum address",
            status,
            ..
        } if ledger_ethereum_app_status(*status)
    )
}

#[cfg(feature = "hardware")]
pub(in crate::root) const fn hardware_profile_detection_should_suppress_initial_ledger_progress(
    error: &HardwareDerivationError,
) -> bool {
    matches!(
        error,
        HardwareDerivationError::LedgerStatus { .. } | HardwareDerivationError::Ledger(_)
    )
}

#[cfg(feature = "hardware")]
#[derive(Clone, Copy)]
enum HardwareSetupErrorFocus {
    WalletName,
    VaultPassword,
}

pub(in crate::root) fn vault_error_message(error: &VaultError) -> Arc<str> {
    match error {
        VaultError::UnlockFailed => "Unlock failed. Check the password and try again.".into(),
        VaultError::Key(_) => "Invalid recovery phrase. Paste it again to retry.".into(),
        VaultError::VaultNotFound => {
            "Wallet vault not found. Create a new vault to continue.".into()
        }
        VaultError::InvalidWalletLabel => "Enter a wallet name before continuing.".into(),
        VaultError::DuplicateWalletLabel => {
            "A wallet with that name already exists. Choose a different wallet name.".into()
        }
        VaultError::DuplicateHardwareWalletAccountIndex => {
            "A hardware-derived wallet with that account index already exists. Choose a different restore index or unhide the existing wallet.".into()
        }
        VaultError::HardwareWalletIdentityMismatch => {
            "Hardware wallet identity mismatch. Check that the correct device, passphrase wallet, path, and account index are active, then try again.".into()
        }
        VaultError::HardwareWalletViewRequiresDevice => {
            "Connect the matching hardware wallet to view this account.".into()
        }
        VaultError::UnsupportedHardwareCustodyBackend(_) => {
            "This hardware wallet custody backend is not supported by this app version.".into()
        }
        VaultError::InvalidHardwareAccountRecoveryRange => {
            "Enter a valid bounded hardware account recovery range.".into()
        }
        _ => "Wallet vault operation failed. See logs for non-sensitive diagnostics.".into(),
    }
}

#[cfg(any(feature = "hardware", test))]
pub(in crate::root) fn hardware_setup_vault_error_message(
    error: &VaultError,
    label: &str,
) -> Arc<str> {
    match error {
        VaultError::DuplicateWalletLabel => format!(
            "A wallet named {:?} already exists. Choose a different wallet name.",
            label.trim()
        )
        .into(),
        VaultError::InvalidWalletLabel => "Enter a wallet name before continuing.".into(),
        _ => vault_error_message(error),
    }
}

pub(in crate::root) const fn default_hardware_wallet_setup_intent(
    retry_intent: Option<HardwareWalletSyncIntent>,
    restore_account_index_set: bool,
) -> HardwareWalletSyncIntent {
    if restore_account_index_set {
        return HardwareWalletSyncIntent::RecoverExisting;
    }
    match retry_intent {
        Some(intent) => intent,
        None => HardwareWalletSyncIntent::CreateNew,
    }
}

#[cfg(any(feature = "hardware", test))]
pub(in crate::root) const fn hardware_wallet_creation_result_is_current(
    current_generation: u64,
    result_generation: u64,
) -> bool {
    current_generation == result_generation
}

#[cfg(any(feature = "hardware", test))]
pub(in crate::root) fn parse_hardware_wallet_restore_account_index(
    value: &str,
) -> Result<Option<u32>, &'static str> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let index = value.parse::<u32>().map_err(
        |_| "Enter a valid Railgun account index to restore, or leave the restore index blank.",
    )?;
    if index >= HARDENED_BIP32_INDEX {
        return Err(
            "Enter a Railgun account index below 2147483648 to restore, or leave the restore index blank.",
        );
    }
    Ok(Some(index))
}

#[cfg(any(feature = "hardware", test))]
pub(in crate::root) const fn hardware_profile_label_warning() -> &'static str {
    "Profile labels are saved as non-secret metadata. Do not put your hardware passphrase or passphrase fragments in the label."
}

#[cfg(any(feature = "hardware", test))]
pub(in crate::root) const HARDWARE_PROFILE_ADD_SUBACCOUNT_BUTTON_ID: &str =
    "hardware-profile-add-subaccount";
#[cfg(any(feature = "hardware", test))]
pub(in crate::root) const HARDWARE_PROFILE_RECOVER_EXACT_BUTTON_ID: &str =
    "hardware-profile-recover-exact";
#[cfg(any(feature = "hardware", test))]
pub(in crate::root) const HARDWARE_PROFILE_RECOVER_RANGE_BUTTON_ID: &str =
    "hardware-profile-recover-range";

#[cfg(any(feature = "hardware", test))]
pub(in crate::root) const fn trezor_passphrase_mode_copy(
    mode: wallet_ops::vault::TrezorPassphraseMode,
) -> &'static str {
    match mode {
        wallet_ops::vault::TrezorPassphraseMode::NoPassphrase => {
            "Use the standard Trezor wallet. If your Trezor asks on-device, leave the passphrase blank."
        }
        wallet_ops::vault::TrezorPassphraseMode::EnterOnTrezor => {
            "Use a hidden wallet passphrase entered on your Trezor. The app stores only the live Trezor session id."
        }
        wallet_ops::vault::TrezorPassphraseMode::EnterInApp => {
            "Enter in app sends the passphrase to this Trezor request once, then clears it immediately. It is never saved."
        }
    }
}

#[cfg(any(feature = "hardware", test))]
pub(in crate::root) const fn effective_trezor_passphrase_mode(
    mode: TrezorPassphraseMode,
    passphrase_always_on_device: bool,
) -> TrezorPassphraseMode {
    if passphrase_always_on_device && matches!(mode, TrezorPassphraseMode::EnterInApp) {
        TrezorPassphraseMode::NoPassphrase
    } else {
        mode
    }
}

#[cfg(any(feature = "hardware", test))]
pub(in crate::root) fn parse_hardware_recovery_range(
    start_value: &str,
    count_value: &str,
) -> Result<Vec<u32>, &'static str> {
    let start = parse_hardware_recovery_index(start_value, "Enter a valid start account index.")?;
    let count = count_value
        .trim()
        .parse::<u32>()
        .map_err(|_| "Enter a valid recovery count.")?;
    if count == 0 {
        return Err("Enter a recovery count above zero.");
    }
    if count > wallet_ops::vault::MAX_HARDWARE_RECOVERY_RANGE_COUNT {
        return Err("Enter a recovery count no greater than 255.");
    }
    let end = start
        .checked_add(count)
        .ok_or("Enter a bounded recovery range below 2147483648.")?;
    if end > HARDENED_BIP32_INDEX {
        return Err("Enter a bounded recovery range below 2147483648.");
    }
    Ok((start..end).collect())
}

#[cfg(any(feature = "hardware", test))]
pub(in crate::root) fn parse_hardware_exact_recovery_index(
    value: &str,
) -> Result<u32, &'static str> {
    parse_hardware_recovery_index(value, "Enter a valid account index to recover.")
}

#[cfg(any(feature = "hardware", test))]
fn parse_hardware_recovery_index(value: &str, error: &'static str) -> Result<u32, &'static str> {
    let index = value.trim().parse::<u32>().map_err(|_| error)?;
    if index >= HARDENED_BIP32_INDEX {
        return Err("Enter a Railgun account index below 2147483648.");
    }
    Ok(index)
}

const fn hardware_device_kind_from_source(source: WalletSource) -> Option<HardwareDeviceKind> {
    match source {
        WalletSource::LedgerDerived => Some(HardwareDeviceKind::Ledger),
        WalletSource::TrezorDerived => Some(HardwareDeviceKind::Trezor),
        WalletSource::Generated | WalletSource::Imported => None,
    }
}

#[cfg(feature = "hardware")]
const fn default_hardware_profile_label(device_kind: HardwareDeviceKind) -> &'static str {
    match device_kind {
        HardwareDeviceKind::Ledger => "Ledger hardware profile",
        HardwareDeviceKind::Trezor => "Trezor hardware profile",
    }
}

#[cfg(feature = "hardware")]
pub(in crate::root) fn hardware_account_picker_rows(
    metadata: &[WalletMetadataBundle],
    profile_id: &str,
    active_wallet_id: Option<&str>,
) -> (Vec<HardwareAccountPickerRow>, Vec<HardwareAccountPickerRow>) {
    let mut matching = Vec::new();
    let mut locked = Vec::new();
    for wallet in metadata
        .iter()
        .filter(|wallet| wallet.status == wallet_ops::vault::WalletStatus::Active)
    {
        let Some(account) = wallet.hardware_account.clone() else {
            continue;
        };
        let row = HardwareAccountPickerRow {
            wallet_id: Arc::from(wallet.wallet_uuid.clone()),
            label: Arc::from(wallet.label.clone()),
            account_index: account.account_index,
            supported: account.custody_backend.is_supported(),
            active: active_wallet_id == Some(wallet.wallet_uuid.as_str()),
            account,
        };
        if row.account.profile_id == profile_id {
            matching.push(row);
        } else {
            locked.push(row);
        }
    }
    matching.sort_by(|left, right| {
        left.account_index
            .cmp(&right.account_index)
            .then_with(|| left.label.cmp(&right.label))
    });
    locked.sort_by(|left, right| {
        left.account
            .profile_id
            .cmp(&right.account.profile_id)
            .then_with(|| left.account_index.cmp(&right.account_index))
            .then_with(|| left.label.cmp(&right.label))
    });
    (matching, locked)
}

#[cfg(feature = "hardware")]
pub(in crate::root) fn hardware_profile_auto_open_wallet_id(
    state: &HardwareProfileUnlockState,
) -> Result<Option<Arc<str>>, Arc<str>> {
    if let Some(target_wallet_id) = state.target_wallet_id.as_ref() {
        let Some(row) = state
            .accounts
            .iter()
            .find(|row| row.wallet_id.as_ref() == target_wallet_id.as_ref())
        else {
            return Err(Arc::from(
                "Connected hardware profile does not match the selected wallet. Check that the correct device and passphrase wallet are active, then try again.",
            ));
        };
        if !row.supported {
            return Err(Arc::from(
                "This hardware account custody backend is not supported by this app version.",
            ));
        }
        return Ok(Some(Arc::clone(&row.wallet_id)));
    }

    if state.purpose == HardwareProfileUnlockPurpose::AddWallet {
        return Ok(None);
    }

    let mut supported = state.accounts.iter().filter(|row| row.supported);
    let Some(row) = supported.next() else {
        return Ok(None);
    };
    if supported.next().is_some() {
        return Ok(None);
    }
    Ok(Some(Arc::clone(&row.wallet_id)))
}

#[cfg(feature = "hardware")]
const fn hardware_setup_vault_error_preserves_password(error: &VaultError) -> bool {
    matches!(
        error,
        VaultError::InvalidWalletLabel | VaultError::DuplicateWalletLabel
    )
}

#[cfg(feature = "hardware")]
const fn hardware_setup_vault_error_focus(error: &VaultError) -> HardwareSetupErrorFocus {
    match error {
        VaultError::InvalidWalletLabel | VaultError::DuplicateWalletLabel => {
            HardwareSetupErrorFocus::WalletName
        }
        _ => HardwareSetupErrorFocus::VaultPassword,
    }
}

impl WalletRoot {
    pub(super) fn set_wallet_name_input(
        &self,
        value: &str,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let value = value.to_owned();
        self.wallet_name_input
            .update(cx, |input, cx| input.set_value(&value, window, cx));
    }

    fn set_default_wallet_name_from_password(
        &self,
        password: &str,
        window: &Window,
        cx: &mut Context<'_, Self>,
    ) {
        let label = self
            .vault_store
            .as_ref()
            .and_then(|store| store.default_wallet_label(password).ok())
            .unwrap_or_else(|| PRIMARY_WALLET_LABEL.to_owned());
        Self::defer_wallet_name_input(label, window, cx);
    }

    fn defer_wallet_name_input(value: String, window: &Window, cx: &mut Context<'_, Self>) {
        cx.defer_in(window, move |root, window, cx| {
            root.set_wallet_name_input(&value, window, cx);
        });
    }

    fn clear_hardware_wallet_restore_account_index(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        self.hardware_wallet_restore_account_index_input
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.hardware_wallet_restore_account_index_set = false;
    }

    #[cfg(feature = "hardware")]
    fn clear_hardware_profile_sensitive_inputs(
        &self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        self.hardware_profile_password_input
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.clear_trezor_app_passphrase_input(window, cx);
    }

    #[cfg(feature = "hardware")]
    pub(super) const fn hardware_profile_unlock_requires_password(&self) -> bool {
        self.hardware_profile_unlock.vault_view_unlock.is_none()
            && self.vault_view_unlock.is_none()
            && self.view_session.is_none()
            && self.setup_password.is_none()
    }

    #[cfg(feature = "hardware")]
    fn hardware_profile_vault_view_unlock(
        &mut self,
        store: &DesktopVaultStore,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) -> Option<Arc<ViewUnlock>> {
        if let Some(vault_view_unlock) = self.hardware_profile_unlock.vault_view_unlock.clone() {
            return Some(vault_view_unlock);
        }
        if let Some(vault_view_unlock) = self.vault_view_unlock.clone() {
            self.hardware_profile_unlock.vault_view_unlock = Some(Arc::clone(&vault_view_unlock));
            return Some(vault_view_unlock);
        }
        if let Some(session) = self.view_session.as_ref() {
            let vault_view_unlock = Arc::new(session.clone_vault_view_unlock());
            self.vault_view_unlock = Some(Arc::clone(&vault_view_unlock));
            self.hardware_profile_unlock.vault_view_unlock = Some(Arc::clone(&vault_view_unlock));
            return Some(vault_view_unlock);
        }
        if let Some(password) = self.setup_password.as_ref() {
            match store.unlock_view(password.as_str()) {
                Ok(view) => {
                    let vault_view_unlock = Arc::new(view);
                    self.vault_view_unlock = Some(Arc::clone(&vault_view_unlock));
                    self.hardware_profile_unlock.vault_view_unlock =
                        Some(Arc::clone(&vault_view_unlock));
                    return Some(vault_view_unlock);
                }
                Err(error) => {
                    self.handle_hardware_profile_vault_error(&error);
                    cx.notify();
                    return None;
                }
            }
        }

        let password =
            Self::read_and_clear_input(&self.hardware_profile_password_input, window, cx);
        if password.trim().is_empty() {
            self.hardware_profile_unlock.error =
                Some(Arc::from("Enter the vault password to continue"));
            cx.notify();
            return None;
        }
        match store.unlock_view(password.as_str()) {
            Ok(view) => {
                let vault_view_unlock = Arc::new(view);
                self.vault_view_unlock = Some(Arc::clone(&vault_view_unlock));
                self.hardware_profile_unlock.vault_view_unlock =
                    Some(Arc::clone(&vault_view_unlock));
                Some(vault_view_unlock)
            }
            Err(error) => {
                self.handle_hardware_profile_vault_error(&error);
                cx.notify();
                None
            }
        }
    }

    #[cfg(feature = "hardware")]
    pub(super) fn clear_trezor_app_passphrase_input(
        &self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        self.trezor_app_passphrase_input
            .update(cx, |input, cx| input.set_value("", window, cx));
    }

    #[cfg(not(feature = "hardware"))]
    pub(super) fn clear_trezor_app_passphrase_input(
        &self,
        _window: &mut Window,
        _cx: &mut Context<'_, Self>,
    ) {
    }

    #[cfg(feature = "hardware")]
    fn dismiss_hardware_profile_unlock_dialog(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        self.next_hardware_profile_action_generation();
        self.hardware_profile_unlock = HardwareProfileUnlockState::default();
        self.clear_hardware_profile_sensitive_inputs(window, cx);
        cx.notify();
    }

    #[cfg(feature = "hardware")]
    const fn next_hardware_profile_action_generation(&mut self) -> u64 {
        self.hardware_wallet_creation_generation =
            self.hardware_wallet_creation_generation.wrapping_add(1);
        self.hardware_wallet_creation_generation
    }

    #[cfg(feature = "hardware")]
    const fn hardware_profile_action_is_current(&self, generation: u64) -> bool {
        hardware_wallet_creation_result_is_current(
            self.hardware_wallet_creation_generation,
            generation,
        )
    }

    #[cfg(feature = "hardware")]
    pub(super) const fn hardware_profile_unlock_auto_starts(&self) -> bool {
        matches!(
            self.hardware_profile_unlock.device_kind,
            Some(HardwareDeviceKind::Ledger)
        ) && !self.hardware_profile_unlock_requires_password()
    }

    #[cfg(feature = "hardware")]
    fn begin_hardware_profile_detection_progress(&mut self, device_kind: HardwareDeviceKind) {
        self.hardware_profile_unlock.progress_steps = default_hardware_profile_steps();
        let message = self
            .hardware_profile_unlock
            .reconnect_notice
            .take()
            .unwrap_or_else(|| {
                format!(
                    "Connect and unlock your {}.",
                    crate::root::vault_ui::hardware_device_label(device_kind)
                )
                .into()
            });
        self.hardware_profile_unlock.set_progress_step(
            HardwareProfileStep::UnlockDevice,
            HardwareProfileStepStatus::Pending,
            Some(message),
        );
    }

    #[cfg(feature = "hardware")]
    fn apply_hardware_profile_progress_update(
        &mut self,
        update: HardwareProfileProgressUpdate,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        if let Some(always_on_device) = update.trezor_passphrase_always_on_device {
            self.hardware_profile_unlock
                .trezor_passphrase_always_on_device = Some(always_on_device);
            if always_on_device
                && self.hardware_profile_unlock.trezor_passphrase_mode
                    == TrezorPassphraseMode::EnterInApp
            {
                self.hardware_profile_unlock.trezor_passphrase_mode =
                    TrezorPassphraseMode::NoPassphrase;
                self.trezor_app_passphrase_input
                    .update(cx, |input, cx| input.set_value("", window, cx));
            }
        }
        if let Some(approval_prompt) = update.approval_prompt {
            self.hardware_profile_unlock.approval_prompt = Some(approval_prompt);
        }
        if update.clear_trezor_pin_matrix_request {
            self.hardware_profile_unlock
                .clear_trezor_pin_matrix_prompt();
        }
        if let Some(request) = update.trezor_pin_matrix_request {
            self.hardware_profile_unlock
                .clear_trezor_pin_matrix_prompt();
            self.hardware_profile_unlock.trezor_pin_matrix_prompt =
                Some(TrezorPinMatrixPromptState {
                    kind: request.kind,
                    positions: String::new(),
                    response_tx: Some(request.response_tx),
                });
        }
        if update.apply_step {
            self.hardware_profile_unlock.set_progress_step(
                update.step,
                update.status,
                update.message.map(Arc::<str>::from),
            );
        }
        cx.notify();
    }

    #[cfg(feature = "hardware")]
    fn spawn_hardware_profile_progress_listener(
        generation: u64,
        mut progress_rx: mpsc::UnboundedReceiver<HardwareProfileProgressUpdate>,
        window: &Window,
        cx: &Context<'_, Self>,
    ) {
        cx.spawn_in(window, async move |this, cx| {
            while let Some(update) = progress_rx.recv().await {
                let Ok(current) = this.update_in(cx, |root, window, cx| {
                    if !root.hardware_profile_action_is_current(generation) {
                        return false;
                    }
                    root.apply_hardware_profile_progress_update(update, window, cx);
                    true
                }) else {
                    break;
                };
                if !current {
                    break;
                }
            }
        })
        .detach();
    }

    #[cfg(feature = "hardware")]
    pub(super) fn trezor_pin_matrix_provider_for_operation(
        &mut self,
        window: &Window,
        cx: &Context<'_, Self>,
    ) -> TrezorPinMatrixProvider {
        self.hardware_profile_unlock
            .clear_trezor_pin_matrix_prompt();
        let generation = self.next_hardware_profile_action_generation();
        let (progress_tx, progress_rx) = mpsc::unbounded_channel();
        Self::spawn_hardware_profile_progress_listener(generation, progress_rx, window, cx);
        trezor_pin_matrix_provider(progress_tx)
    }

    #[cfg(feature = "hardware")]
    pub(super) fn drop_trezor_pin_matrix_prompt(&mut self) {
        self.hardware_profile_unlock
            .clear_trezor_pin_matrix_prompt();
    }

    #[cfg(not(feature = "hardware"))]
    pub(super) fn drop_trezor_pin_matrix_prompt(&mut self) {}

    #[cfg(feature = "hardware")]
    pub(super) fn clear_trezor_pin_matrix_prompt(&mut self, cx: &mut Context<'_, Self>) {
        self.drop_trezor_pin_matrix_prompt();
        cx.notify();
    }

    #[cfg(not(feature = "hardware"))]
    pub(super) fn clear_trezor_pin_matrix_prompt(&mut self, _cx: &mut Context<'_, Self>) {}

    #[cfg(feature = "hardware")]
    fn read_trezor_app_passphrase_for_profile_operation(
        &self,
        device_kind: HardwareDeviceKind,
        trezor_mode: TrezorPassphraseMode,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) -> Option<Zeroizing<String>> {
        if device_kind != HardwareDeviceKind::Trezor
            || trezor_mode != TrezorPassphraseMode::EnterInApp
            || self
                .hardware_profile_unlock
                .trezor_passphrase_always_on_device
                .unwrap_or(false)
        {
            self.trezor_app_passphrase_input
                .update(cx, |input, cx| input.set_value("", window, cx));
            return None;
        }
        let passphrase = Self::read_and_clear_input(&self.trezor_app_passphrase_input, window, cx);
        (!passphrase.is_empty()).then_some(passphrase)
    }

    #[cfg(feature = "hardware")]
    pub(super) fn current_session_needs_trezor_app_passphrase(&self) -> bool {
        self.view_session
            .as_ref()
            .and_then(|session| session.hardware_profile_session())
            .is_some_and(hardware_session_needs_trezor_app_passphrase)
    }

    #[cfg(feature = "hardware")]
    pub(super) fn discard_active_trezor_session_if_stale(
        &mut self,
        message: &str,
        cx: &mut Context<'_, Self>,
    ) {
        if !trezor_session_stale_error_message(message) {
            return;
        }
        let Some(view_session) = self.view_session.as_ref() else {
            return;
        };
        let Some(mut hardware_session) = view_session.hardware_profile_session().cloned() else {
            return;
        };
        if !hardware_session.uses_trezor_app_passphrase()
            || hardware_session.trezor_session_id.is_none()
        {
            return;
        }
        hardware_session.discard_trezor_session();
        self.view_session = Some(Arc::new(
            view_session.clone_with_hardware_profile_session(hardware_session),
        ));
        cx.notify();
    }

    #[cfg(feature = "hardware")]
    pub(super) fn push_trezor_pin_matrix_position(
        &mut self,
        position: char,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(prompt) = self
            .hardware_profile_unlock
            .trezor_pin_matrix_prompt
            .as_mut()
        else {
            return;
        };
        if ('1'..='9').contains(&position) {
            prompt.positions.push(position);
            cx.notify();
        }
    }

    #[cfg(feature = "hardware")]
    pub(super) fn backspace_trezor_pin_matrix_position(&mut self, cx: &mut Context<'_, Self>) {
        let Some(prompt) = self
            .hardware_profile_unlock
            .trezor_pin_matrix_prompt
            .as_mut()
        else {
            return;
        };
        prompt.positions.pop();
        cx.notify();
    }

    #[cfg(feature = "hardware")]
    pub(super) fn clear_trezor_pin_matrix_positions(&mut self, cx: &mut Context<'_, Self>) {
        let Some(prompt) = self
            .hardware_profile_unlock
            .trezor_pin_matrix_prompt
            .as_mut()
        else {
            return;
        };
        prompt.positions.zeroize();
        cx.notify();
    }

    #[cfg(feature = "hardware")]
    pub(super) fn submit_trezor_pin_matrix_positions(&mut self, cx: &mut Context<'_, Self>) {
        let Some(mut prompt) = self.hardware_profile_unlock.trezor_pin_matrix_prompt.take() else {
            return;
        };
        if prompt.positions.is_empty() {
            self.hardware_profile_unlock.trezor_pin_matrix_prompt = Some(prompt);
            return;
        }
        let positions = std::mem::take(&mut prompt.positions);
        if let Some(response_tx) = prompt.response_tx.take()
            && response_tx.send(Zeroizing::new(positions)).is_err()
        {
            self.hardware_profile_unlock.error = Some(Arc::from(
                "Trezor PIN request expired. Unlock your Trezor, then try again.",
            ));
        }
        prompt.clear_sensitive();
        cx.notify();
    }

    #[cfg(feature = "hardware")]
    pub(super) fn read_trezor_app_passphrase_for_hardware_session(
        &self,
        session: &HardwareProfileSession,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) -> Option<Zeroizing<String>> {
        if !session.uses_trezor_app_passphrase() {
            self.trezor_app_passphrase_input
                .update(cx, |input, cx| input.set_value("", window, cx));
            return None;
        }
        let passphrase = Self::read_and_clear_input(&self.trezor_app_passphrase_input, window, cx);
        (!passphrase.is_empty()).then_some(passphrase)
    }

    #[cfg(not(feature = "hardware"))]
    pub(super) const fn current_session_needs_trezor_app_passphrase(&self) -> bool {
        false
    }

    #[cfg(not(feature = "hardware"))]
    pub(super) fn discard_active_trezor_session_if_stale(
        &mut self,
        _message: &str,
        _cx: &mut Context<'_, Self>,
    ) {
    }

    #[cfg(feature = "hardware")]
    fn handle_hardware_profile_hardware_error(
        &mut self,
        operation: &str,
        error: &HardwareDerivationError,
        awaiting_approval: bool,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let awaiting_approval =
            awaiting_approval || self.hardware_profile_unlock.awaiting_approval();
        tracing::warn!(
            %error,
            operation,
            awaiting_approval,
            "hardware profile operation failed"
        );
        if self.hardware_profile_unlock.session.is_some()
            && hardware_profile_should_reconnect_after_error(error, awaiting_approval)
        {
            self.reconnect_hardware_profile_after_interruption(window, cx);
            return;
        }
        if matches!(error, HardwareDerivationError::MissingTrezorAppPassphrase) {
            if let Some(session) = self.hardware_profile_unlock.session.as_mut() {
                session.discard_trezor_session();
            }
            let message = Arc::from(
                "Trezor session expired or requires the app-entered passphrase again. Re-enter the passphrase in the profile picker, then retry.",
            );
            self.hardware_profile_unlock
                .mark_first_pending_progress_step_error(Arc::clone(&message));
            self.hardware_profile_unlock.error = Some(message);
            return;
        }
        let message = hardware_profile_hardware_error_message(operation, error, awaiting_approval);
        self.hardware_profile_unlock
            .mark_first_pending_progress_step_error(Arc::clone(&message));
        self.hardware_profile_unlock.error = Some(message);
    }

    #[cfg(feature = "hardware")]
    #[allow(clippy::needless_pass_by_ref_mut)]
    fn reconnect_hardware_profile_after_interruption(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(device_kind) = self.hardware_profile_unlock.device_kind else {
            self.hardware_profile_unlock.error = Some(Arc::from(
                "Hardware wallet connection was interrupted. Reconnect your device, then try again.",
            ));
            return;
        };
        self.hardware_profile_unlock.session = None;
        self.hardware_profile_unlock.profile = None;
        self.hardware_profile_unlock.accounts.clear();
        self.hardware_profile_unlock.locked_accounts.clear();
        self.hardware_profile_unlock.approval_prompt = None;
        self.hardware_profile_unlock.picker_view = HardwareProfilePickerView::Summary;
        self.hardware_profile_unlock.advanced_open = false;
        self.hardware_profile_unlock.editing_label = false;
        self.hardware_profile_unlock.error = None;
        self.hardware_profile_unlock.progress_steps = default_hardware_profile_steps();
        self.hardware_profile_unlock.reconnect_notice = Some(Arc::from(
            "Ledger connection was interrupted. Unlock your Ledger and open the Ethereum app to reconnect.",
        ));

        cx.defer_in(window, move |root, window, cx| {
            if root.hardware_profile_unlock.device_kind == Some(device_kind)
                && root.hardware_profile_unlock.session.is_none()
                && !root.hardware_profile_unlock.in_progress
            {
                root.unlock_hardware_profile_from_dialog(window, cx);
            }
        });
    }

    #[cfg(feature = "hardware")]
    fn handle_hardware_profile_vault_error(&mut self, error: &VaultError) {
        if matches!(error, VaultError::HardwareWalletIdentityMismatch)
            && let Some(session) = self.hardware_profile_unlock.session.as_mut()
        {
            session.discard_trezor_session();
        }
        let message = vault_error_message(error);
        self.hardware_profile_unlock
            .mark_first_pending_progress_step_error(Arc::clone(&message));
        self.hardware_profile_unlock.error = Some(message);
    }

    pub(super) fn select_wallet(
        &mut self,
        wallet_id: &str,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        if let Some(device_kind) = hardware_device_kind_from_wallet_select_value(wallet_id) {
            #[cfg(feature = "hardware")]
            {
                self.open_hardware_profile_unlock_dialog_for_device(
                    device_kind,
                    HardwareProfileUnlockPurpose::OpenWallet,
                    window,
                    cx,
                );
                self.sync_wallet_select(window, cx);
            }
            #[cfg(not(feature = "hardware"))]
            {
                self.set_vault_error(
                    format!(
                        "{} support is not enabled in this build.",
                        hardware_device_wallet_select_label(device_kind)
                    ),
                    cx,
                );
                self.sync_wallet_select(window, cx);
            }
            return;
        }
        if self.selected_wallet_id.as_deref() == Some(wallet_id) {
            return;
        }
        window.close_all_dialogs(cx);
        self.switch_active_wallet(wallet_id, window, cx);
    }

    pub(super) fn open_add_wallet_dialog(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        self.open_add_wallet_dialog_with_mode(WalletSetupMode::Choose, window, cx);
    }

    #[cfg(feature = "hardware")]
    pub(super) fn open_hardware_profile_unlock_dialog_for_wallet(
        &mut self,
        wallet_id: Arc<str>,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(wallet) = self
            .wallet_metadata
            .iter()
            .find(|metadata| metadata.wallet_uuid == wallet_id.as_ref())
        else {
            self.set_vault_error("Wallet metadata is unavailable", cx);
            return;
        };
        let Some(device_kind) = hardware_device_kind_from_source(wallet.source) else {
            self.set_vault_error("Selected wallet is not hardware-derived", cx);
            return;
        };
        self.open_hardware_profile_unlock_dialog(
            Some(wallet_id),
            device_kind,
            HardwareProfileUnlockPurpose::OpenWallet,
            window,
            cx,
        );
    }

    #[cfg(feature = "hardware")]
    fn open_hardware_profile_unlock_dialog(
        &mut self,
        wallet_id: Option<Arc<str>>,
        device_kind: HardwareDeviceKind,
        purpose: HardwareProfileUnlockPurpose,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        window.close_all_dialogs(cx);
        self.next_hardware_profile_action_generation();
        self.hardware_profile_unlock
            .reset_for_device(device_kind, wallet_id, purpose);
        self.clear_hardware_profile_sensitive_inputs(window, cx);
        self.hardware_profile_label_input.update(cx, |input, cx| {
            input.set_value(default_hardware_profile_label(device_kind), window, cx);
        });
        self.hardware_profile_recovery_start_input
            .update(cx, |input, cx| input.set_value("0", window, cx));
        self.hardware_profile_recovery_count_input
            .update(cx, |input, cx| input.set_value("1", window, cx));
        self.hardware_profile_exact_index_input
            .update(cx, |input, cx| input.set_value("0", window, cx));
        let root = cx.entity();
        let device_label = crate::root::vault_ui::hardware_device_label(device_kind);
        let viewport_size = window.viewport_size();
        let dialog_width = (viewport_size.width * 0.92).min(px(620.0));
        let dialog_max_height = viewport_size.height * 0.84;
        let dialog_content_max_height = viewport_size.height * 0.74;
        let content_width = secondary_dialog_content_width(dialog_width);
        window.open_dialog(cx, move |dialog, _window, cx| {
            let close_root = root.clone();
            let content_root = root.clone();
            dialog
                .w(dialog_width)
                .max_h(dialog_max_height)
                .title(app_strong_text(format!("{device_label} wallet")))
                .on_close(move |_event, window, cx| {
                    close_root.update(cx, |root, cx| {
                        root.dismiss_hardware_profile_unlock_dialog(window, cx);
                    });
                })
                .child(
                    div()
                        .max_h(dialog_content_max_height)
                        .min_h(px(0.0))
                        .overflow_y_scrollbar()
                        .child(
                            content_root
                                .read(cx)
                                .render_hardware_profile_unlock_dialog_content(
                                    &content_root,
                                    content_width,
                                ),
                        ),
                )
        });
        if self.hardware_profile_unlock_requires_password() {
            self.hardware_profile_password_input
                .read(cx)
                .focus_handle(cx)
                .focus(window);
        } else if self.hardware_profile_unlock_auto_starts() {
            cx.defer_in(window, move |root, window, cx| {
                if root.hardware_profile_unlock_auto_starts()
                    && root.hardware_profile_unlock.device_kind == Some(device_kind)
                    && root.hardware_profile_unlock.session.is_none()
                    && !root.hardware_profile_unlock.in_progress
                {
                    root.unlock_hardware_profile_from_dialog(window, cx);
                }
            });
        }
        cx.notify();
    }

    #[cfg(feature = "hardware")]
    fn open_hardware_profile_unlock_dialog_for_device(
        &mut self,
        device_kind: HardwareDeviceKind,
        purpose: HardwareProfileUnlockPurpose,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        self.open_hardware_profile_unlock_dialog(None, device_kind, purpose, window, cx);
    }

    fn open_add_wallet_dialog_with_mode(
        &mut self,
        initial_mode: WalletSetupMode,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        window.close_all_dialogs(cx);
        self.generated_seed = None;
        self.vault_error = None;
        self.wallet_setup_mode = initial_mode;
        let label = default_wallet_label_for_metadata(&self.wallet_metadata);
        let root = cx.entity();
        let dialog_width = (window.viewport_size().width * 0.92).min(px(520.0));
        let dialog_max_height = dialog_max_height(window);
        let content_max_height = dialog_content_max_height(window);
        let content_width = secondary_dialog_content_width(dialog_width);
        window.open_dialog(cx, move |dialog, _window, cx| {
            let content_root = root.clone();
            dialog
                .w(dialog_width)
                .max_h(dialog_max_height)
                .title(app_strong_text("Add wallet"))
                .child(scrollable_dialog_content(
                    content_max_height,
                    content_root
                        .read(cx)
                        .render_add_wallet_dialog_content(content_root.clone(), content_width),
                ))
        });
        cx.defer_in(window, move |root, window, cx| {
            root.set_wallet_name_input(&label, window, cx);
            root.add_wallet_password_input
                .update(cx, |input, cx| input.set_value("", window, cx));
        });
    }

    #[cfg_attr(not(feature = "hardware"), allow(clippy::needless_pass_by_ref_mut))]
    fn switch_active_wallet(
        &mut self,
        wallet_id: &str,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        #[cfg(feature = "hardware")]
        if self.wallet_metadata.iter().any(|metadata| {
            metadata.wallet_uuid == wallet_id
                && hardware_device_kind_from_source(metadata.source).is_some()
        }) {
            self.open_hardware_profile_unlock_dialog_for_wallet(
                Arc::from(wallet_id.to_owned()),
                window,
                cx,
            );
            return;
        }
        let Some(store) = self.vault_store.clone() else {
            self.set_vault_error("Wallet vault storage is unavailable", cx);
            return;
        };
        let Some(current_session) = self.view_session.clone() else {
            self.set_vault_error("Wallet vault is locked", cx);
            return;
        };

        let current_wallet_id: Arc<str> = Arc::from(current_session.wallet_id().to_owned());
        let active_wallet_generation = self.active_wallet_generation;
        self.wallet_switch_generation = self.wallet_switch_generation.wrapping_add(1);
        let switch_generation = self.wallet_switch_generation;
        self.vault_error = None;
        let wallet_id_string = wallet_id.to_owned();
        let metadata = self.wallet_metadata.clone();
        let join = self.runtime.spawn_blocking(move || {
            store.load_view_session_with_view_session(current_session.as_ref(), &wallet_id_string)
        });
        cx.spawn_in(window, async move |this, cx| {
            let result = join.await;
            let _ = this.update_in(cx, |root, window, cx| {
                if root.wallet_switch_generation != switch_generation
                    || !root.is_active_wallet_generation(
                        current_wallet_id.as_ref(),
                        active_wallet_generation,
                    )
                {
                    return;
                }
                match result {
                    Ok(Ok(session)) => root.install_view_session(session, metadata, window, cx),
                    Ok(Err(error)) => {
                        root.handle_vault_error(&error, cx);
                        root.sync_wallet_select(window, cx);
                    }
                    Err(error) => {
                        root.set_vault_error(
                            format!("Failed to switch wallet: {error}").as_str(),
                            cx,
                        );
                        root.sync_wallet_select(window, cx);
                    }
                }
            });
        })
        .detach();
        cx.notify();
    }

    #[allow(dead_code)]
    fn deactivate_wallet_and_switch(
        &mut self,
        wallet_id: &str,
        password: &str,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(store) = self.vault_store.clone() else {
            self.set_vault_error("Wallet vault storage is unavailable", cx);
            return;
        };
        if let Err(error) = store.deactivate_wallet(password, wallet_id) {
            self.handle_vault_error(&error, cx);
            return;
        }
        let metadata = match store.list_wallet_metadata(password) {
            Ok(metadata) => metadata,
            Err(error) => {
                self.handle_vault_error(&error, cx);
                return;
            }
        };
        self.wallet_metadata.clone_from(&metadata);
        self.wallet_options = wallet_options_from_metadata(metadata.clone());

        if self.selected_wallet_id.as_deref() != Some(wallet_id) {
            self.sync_wallet_select(window, cx);
            cx.notify();
            return;
        }

        let Some(next_wallet_id) = self
            .wallet_options
            .first()
            .map(|option| Arc::clone(&option.wallet_id))
        else {
            self.set_vault_error("No active wallet remains after deactivation", cx);
            return;
        };
        match store.load_view_session(password, next_wallet_id.as_ref()) {
            Ok(session) => self.install_view_session(session, metadata, window, cx),
            Err(error) => self.handle_vault_error(&error, cx),
        }
    }

    pub(super) fn focus_vault_input_if_requested(
        &mut self,
        window: &mut Window,
        cx: &Context<'_, Self>,
    ) {
        if !self.focus_vault_input_on_render {
            return;
        }

        match self.vault_state {
            VaultState::CreateVault => self
                .new_password_input
                .read(cx)
                .focus_handle(cx)
                .focus(window),
            VaultState::UnlockVault => self
                .unlock_password_input
                .read(cx)
                .focus_handle(cx)
                .focus(window),
            VaultState::SetupWallet if self.wallet_setup_mode == WalletSetupMode::Import => self
                .import_mnemonic_input
                .read(cx)
                .focus_handle(cx)
                .focus(window),
            VaultState::SetupWallet | VaultState::ViewUnlocked | VaultState::Error(_) => {}
        }
        self.focus_vault_input_on_render = false;
    }

    pub(super) fn create_vault_from_inputs(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(store) = self.vault_store.as_ref() else {
            self.set_vault_error("Wallet vault storage is unavailable", cx);
            return;
        };
        let password = Self::read_and_clear_input(&self.new_password_input, window, cx);
        let confirm = Self::read_and_clear_input(&self.confirm_password_input, window, cx);

        if password.trim().is_empty() {
            self.set_vault_error("Enter a vault password to continue", cx);
            return;
        }
        if password.as_str() != confirm.as_str() {
            self.set_vault_error("Vault passwords do not match", cx);
            return;
        }

        match store.create_vault(password.as_str()) {
            Ok(created) => {
                Self::defer_wallet_name_input(PRIMARY_WALLET_LABEL.to_owned(), window, cx);
                self.vault_view_unlock = Some(Arc::new(created.view));
                self.setup_password = Some(password);
                self.vault_error = None;
                self.vault_state = VaultState::SetupWallet;
                self.wallet_setup_mode = WalletSetupMode::Choose;
                cx.notify();
            }
            Err(VaultError::VaultAlreadyExists) => {
                self.vault_state = VaultState::UnlockVault;
                self.focus_vault_input_on_render = true;
                self.set_vault_error("A wallet vault already exists. Unlock it to continue.", cx);
            }
            Err(error) => self.handle_vault_error(&error, cx),
        }
    }

    pub(super) fn unlock_vault_from_input(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        if self.unlock_in_progress {
            return;
        }
        let Some(store) = self.vault_store.as_ref() else {
            self.set_vault_error("Wallet vault storage is unavailable", cx);
            return;
        };
        let password = Self::read_and_clear_input(&self.unlock_password_input, window, cx);
        if password.trim().is_empty() {
            self.set_vault_error("Enter the vault password to continue", cx);
            return;
        }

        let store = Arc::clone(store);
        self.unlock_in_progress = true;
        self.vault_error = None;
        cx.notify();

        let join = self.runtime.spawn_blocking(move || {
            let view = store.unlock_view(password.as_str())?;
            let metadata = store.list_wallet_metadata_with_view_unlock(&view, true)?;
            let active = wallet_options_from_metadata(metadata.clone());
            let vault_view_unlock = Arc::new(view);
            if active.is_empty() {
                return Ok((None, metadata, vault_view_unlock, Some(password)));
            }
            for wallet in &active {
                match store.load_view_session_with_view_unlock(
                    &vault_view_unlock,
                    wallet.wallet_id.as_ref(),
                ) {
                    Ok(session) => return Ok((Some(session), metadata, vault_view_unlock, None)),
                    Err(
                        VaultError::HardwareWalletViewRequiresDevice
                        | VaultError::UnsupportedHardwareCustodyBackend(_),
                    ) => {}
                    Err(error) => return Err(error),
                }
            }
            Ok((None, metadata, vault_view_unlock, None))
        });
        cx.spawn_in(window, async move |this, cx| {
            let result = join.await;
            let _ = this.update_in(cx, |root, window, cx| {
                root.unlock_in_progress = false;
                match result {
                    Ok(Ok((Some(session), metadata, vault_view_unlock, _setup_password))) => {
                        root.vault_view_unlock = Some(vault_view_unlock);
                        root.enter_view_unlocked(session, metadata, window, cx);
                    }
                    Ok(Ok((None, metadata, vault_view_unlock, setup_password))) => {
                        root.enter_password_metadata_unlocked(
                            metadata,
                            vault_view_unlock,
                            setup_password,
                            window,
                            cx,
                        );
                    }
                    Ok(Err(error)) => {
                        root.focus_vault_input_on_render = true;
                        root.handle_vault_error(&error, cx);
                    }
                    Err(error) => {
                        tracing::warn!(%error, "desktop wallet vault unlock task failed");
                        root.focus_vault_input_on_render = true;
                        root.set_vault_error(
                            "Unlock failed. Check the password and try again.",
                            cx,
                        );
                    }
                }
            });
        })
        .detach();
    }

    pub(super) fn choose_generated_wallet(&mut self, cx: &mut Context<'_, Self>) {
        match generate_seed_material() {
            Ok(seed) => {
                self.generated_seed = Some(seed);
                self.vault_error = None;
                self.wallet_setup_mode = WalletSetupMode::GeneratedReview;
                cx.notify();
            }
            Err(error) => self.handle_vault_error(&error, cx),
        }
    }

    pub(super) fn choose_import_wallet(&mut self, window: &Window, cx: &mut Context<'_, Self>) {
        self.generated_seed = None;
        self.vault_error = None;
        self.wallet_setup_mode = WalletSetupMode::Import;
        cx.notify();
        cx.defer_in(window, move |root, window, cx| {
            if root.wallet_setup_mode == WalletSetupMode::Import {
                root.import_mnemonic_input
                    .read(cx)
                    .focus_handle(cx)
                    .focus(window);
            }
        });
    }

    #[cfg(feature = "hardware")]
    pub(super) fn choose_hardware_wallet(
        &mut self,
        device_kind: HardwareDeviceKind,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        self.open_hardware_profile_unlock_dialog_for_device(
            device_kind,
            HardwareProfileUnlockPurpose::AddWallet,
            window,
            cx,
        );
    }

    #[cfg(not(feature = "hardware"))]
    pub(super) fn choose_hardware_wallet(
        &mut self,
        device_kind: HardwareDeviceKind,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        self.generated_seed = None;
        self.vault_error = None;
        self.wallet_setup_mode = WalletSetupMode::Hardware(device_kind);
        self.hardware_wallet_creation_intent = None;
        self.clear_hardware_wallet_restore_account_index(window, cx);
        cx.notify();
        cx.defer_in(window, move |root, window, cx| {
            if matches!(root.vault_state, VaultState::ViewUnlocked)
                && root.wallet_setup_mode == WalletSetupMode::Hardware(device_kind)
            {
                root.add_wallet_password_input
                    .read(cx)
                    .focus_handle(cx)
                    .focus(window);
            }
        });
    }

    pub(super) fn submit_default_hardware_wallet_setup(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let WalletSetupMode::Hardware(device_kind) = self.wallet_setup_mode else {
            return;
        };
        self.store_hardware_derived_wallet(
            device_kind,
            default_hardware_wallet_setup_intent(
                self.hardware_wallet_creation_intent,
                self.hardware_wallet_restore_account_index_set,
            ),
            window,
            cx,
        );
    }

    pub(super) fn back_to_wallet_setup_choice(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        self.generated_seed = None;
        self.import_mnemonic_input
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.vault_error = None;
        self.wallet_setup_mode = WalletSetupMode::Choose;
        self.hardware_wallet_creation_intent = None;
        self.clear_hardware_wallet_restore_account_index(window, cx);
        cx.notify();
    }

    fn wallet_creation_password(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) -> Option<Zeroizing<String>> {
        if matches!(self.vault_state, VaultState::ViewUnlocked) {
            let password = Self::read_and_clear_input(&self.add_wallet_password_input, window, cx);
            if password.trim().is_empty() {
                self.set_vault_error("Enter the vault password to add a wallet", cx);
                return None;
            }
            return Some(password);
        }
        let Some(password) = self.setup_password.as_ref() else {
            self.set_vault_error("Unlock the wallet vault before adding a wallet", cx);
            return None;
        };
        Some(Zeroizing::new(password.to_string()))
    }

    #[cfg(feature = "hardware")]
    fn hardware_wallet_creation_password(
        &mut self,
        cx: &mut Context<'_, Self>,
    ) -> Option<Zeroizing<String>> {
        if matches!(self.vault_state, VaultState::ViewUnlocked) {
            let password =
                Zeroizing::new(self.add_wallet_password_input.read(cx).value().to_string());
            if password.trim().is_empty() {
                self.set_vault_error("Enter the vault password to add a wallet", cx);
                return None;
            }
            return Some(password);
        }
        let Some(password) = self.setup_password.as_ref() else {
            self.set_vault_error("Unlock the wallet vault before adding a wallet", cx);
            return None;
        };
        Some(Zeroizing::new(password.to_string()))
    }

    #[cfg(feature = "hardware")]
    #[allow(clippy::option_option)]
    fn hardware_wallet_restore_account_index(
        &mut self,
        cx: &mut Context<'_, Self>,
    ) -> Option<Option<u32>> {
        let value = self
            .hardware_wallet_restore_account_index_input
            .read(cx)
            .value()
            .to_string();
        match parse_hardware_wallet_restore_account_index(&value) {
            Ok(index) => Some(index),
            Err(message) => {
                self.set_vault_error(message, cx);
                None
            }
        }
    }

    fn wallet_name_from_input(&self, cx: &Context<'_, Self>) -> String {
        self.wallet_name_input.read(cx).value().to_string()
    }

    pub(super) fn store_generated_wallet(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let wallet_id = match generate_opaque_id() {
            Ok(wallet_id) => wallet_id,
            Err(error) => {
                self.handle_vault_error(&error, cx);
                return;
            }
        };
        let label = self.wallet_name_from_input(cx);
        let Some(password) = self.wallet_creation_password(window, cx) else {
            return;
        };
        let result = {
            let Some(store) = self.vault_store.as_ref() else {
                self.set_vault_error("Wallet vault storage is unavailable", cx);
                return;
            };
            let Some(seed) = self.generated_seed.as_ref() else {
                self.set_vault_error("Generate a recovery phrase before creating the wallet", cx);
                return;
            };
            let metadata = store.new_wallet_metadata(
                password.as_str(),
                &wallet_id,
                0,
                WalletSource::Generated,
                &label,
            );
            let metadata = match metadata {
                Ok(metadata) => metadata,
                Err(error) => return self.handle_vault_error(&error, cx),
            };
            store
                .store_generated_wallet_with_metadata(
                    password.as_str(),
                    &wallet_id,
                    0,
                    "english",
                    seed,
                    &metadata,
                )
                .and_then(|_| {
                    let metadata = store.list_wallet_metadata(password.as_str())?;
                    let session = store.load_view_session(password.as_str(), &wallet_id)?;
                    Ok((session, metadata))
                })
        };

        match result {
            Ok((session, metadata)) => self.enter_view_unlocked(session, metadata, window, cx),
            Err(error) => self.handle_vault_error(&error, cx),
        }
    }

    pub(super) fn store_imported_wallet(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let mnemonic = Self::read_and_clear_input(&self.import_mnemonic_input, window, cx);
        if mnemonic.trim().is_empty() {
            self.set_vault_error("Paste a recovery phrase to import", cx);
            return;
        }
        let wallet_id = match generate_opaque_id() {
            Ok(wallet_id) => wallet_id,
            Err(error) => {
                self.handle_vault_error(&error, cx);
                return;
            }
        };
        let label = self.wallet_name_from_input(cx);
        let Some(password) = self.wallet_creation_password(window, cx) else {
            return;
        };

        let result = {
            let Some(store) = self.vault_store.as_ref() else {
                self.set_vault_error("Wallet vault storage is unavailable", cx);
                return;
            };
            let metadata = store.new_wallet_metadata(
                password.as_str(),
                &wallet_id,
                0,
                WalletSource::Imported,
                &label,
            );
            let metadata = match metadata {
                Ok(metadata) => metadata,
                Err(error) => return self.handle_vault_error(&error, cx),
            };
            store
                .import_wallet_mnemonic_with_metadata(
                    password.as_str(),
                    &wallet_id,
                    0,
                    "english",
                    mnemonic.as_str(),
                    &metadata,
                )
                .and_then(|_| {
                    let metadata = store.list_wallet_metadata(password.as_str())?;
                    let session = store.load_view_session(password.as_str(), &wallet_id)?;
                    Ok((session, metadata))
                })
        };

        match result {
            Ok((session, metadata)) => self.enter_view_unlocked(session, metadata, window, cx),
            Err(error) => self.handle_vault_error(&error, cx),
        }
    }

    #[cfg(not(feature = "hardware"))]
    pub(super) fn store_hardware_derived_wallet(
        &mut self,
        _device_kind: HardwareDeviceKind,
        sync_intent: HardwareWalletSyncIntent,
        _window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        self.hardware_wallet_creation_intent = Some(sync_intent);
        self.set_vault_error(
            "Hardware wallet support is not enabled in this build. Rebuild the wallet with the hardware feature to use Ledger-derived or Trezor-derived wallets.",
            cx,
        );
    }

    #[cfg(feature = "hardware")]
    pub(super) fn store_hardware_derived_wallet(
        &mut self,
        device_kind: HardwareDeviceKind,
        sync_intent: HardwareWalletSyncIntent,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        if self.hardware_wallet_creation_in_progress {
            return;
        }
        self.hardware_wallet_creation_intent = Some(sync_intent);
        let Some(explicit_account_index) = self.hardware_wallet_restore_account_index(cx) else {
            return;
        };
        if sync_intent == HardwareWalletSyncIntent::CreateNew && explicit_account_index.is_some() {
            self.set_vault_error(
                "Clear the restore account index before creating a new hardware-derived wallet.",
                cx,
            );
            return;
        }
        let wallet_id = match generate_opaque_id() {
            Ok(wallet_id) => wallet_id,
            Err(error) => {
                self.handle_vault_error(&error, cx);
                return;
            }
        };
        let label = self.wallet_name_from_input(cx);
        let Some(password) = self.hardware_wallet_creation_password(cx) else {
            return;
        };
        let Some(store) = self.vault_store.clone() else {
            self.set_vault_error("Wallet vault storage is unavailable", cx);
            return;
        };
        let label = match store.preflight_new_wallet_metadata(password.as_str(), &label) {
            Ok(label) => label,
            Err(error) => {
                self.handle_hardware_wallet_setup_vault_error(&error, &label, window, cx);
                return;
            }
        };

        window.blur();
        self.focus_vault_input_on_render = false;
        self.hardware_wallet_creation_in_progress = true;
        self.hardware_wallet_creation_generation =
            self.hardware_wallet_creation_generation.wrapping_add(1);
        let creation_generation = self.hardware_wallet_creation_generation;
        self.vault_error = None;
        cx.notify();

        let join = self.runtime.spawn(create_hardware_derived_wallet(
            store,
            password,
            wallet_id,
            label,
            device_kind,
            sync_intent,
            explicit_account_index,
        ));
        cx.spawn_in(window, async move |this, cx| {
            let result = join.await;
            let _ = this.update_in(cx, |root, window, cx| {
                if !hardware_wallet_creation_result_is_current(
                    root.hardware_wallet_creation_generation,
                    creation_generation,
                ) {
                    return;
                }
                root.hardware_wallet_creation_in_progress = false;
                match result {
                    Ok(Ok((session, metadata))) => {
                        root.enter_view_unlocked(session, metadata, window, cx);
                    }
                    Ok(Err(HardwareWalletCreationError::Vault(error))) => {
                        root.handle_hardware_wallet_setup_vault_error(&error, "", window, cx);
                    }
                    Ok(Err(HardwareWalletCreationError::Hardware { error, .. })) => {
                        let clear_password = !hardware_setup_error_preserves_password(&error);
                        root.set_vault_error(
                            format!("Hardware wallet derivation failed: {error}"),
                            cx,
                        );
                        root.finish_hardware_wallet_setup_error(
                            window,
                            cx,
                            clear_password,
                            HardwareSetupErrorFocus::VaultPassword,
                        );
                    }
                    Err(error) => {
                        tracing::warn!(%error, "desktop hardware wallet setup task failed");
                        root.set_vault_error(
                            "Hardware wallet setup failed. See logs for non-sensitive diagnostics.",
                            cx,
                        );
                        root.finish_hardware_wallet_setup_error(
                            window,
                            cx,
                            true,
                            HardwareSetupErrorFocus::VaultPassword,
                        );
                    }
                }
            });
        })
        .detach();
    }

    #[cfg(feature = "hardware")]
    pub(super) fn set_trezor_profile_passphrase_mode(
        &mut self,
        mode: TrezorPassphraseMode,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let mode = if mode == TrezorPassphraseMode::EnterInApp
            && self
                .hardware_profile_unlock
                .trezor_passphrase_always_on_device
                .unwrap_or(false)
        {
            TrezorPassphraseMode::NoPassphrase
        } else {
            mode
        };
        self.hardware_profile_unlock.trezor_passphrase_mode = mode;
        self.hardware_profile_unlock.error = None;
        if mode != TrezorPassphraseMode::EnterInApp {
            self.trezor_app_passphrase_input
                .update(cx, |input, cx| input.set_value("", window, cx));
        }
        cx.notify();
        if mode == TrezorPassphraseMode::EnterInApp {
            cx.defer_in(window, |root, window, cx| {
                if root.hardware_profile_unlock.device_kind == Some(HardwareDeviceKind::Trezor)
                    && root.hardware_profile_unlock.trezor_passphrase_mode
                        == TrezorPassphraseMode::EnterInApp
                    && root.hardware_profile_unlock.session.is_none()
                    && !root.hardware_profile_unlock.in_progress
                {
                    root.trezor_app_passphrase_input
                        .read(cx)
                        .focus_handle(cx)
                        .focus(window);
                }
            });
        }
    }

    #[cfg(feature = "hardware")]
    pub(super) fn submit_trezor_profile_passphrase_input(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        if self.hardware_profile_unlock.device_kind != Some(HardwareDeviceKind::Trezor)
            || self.hardware_profile_unlock.trezor_passphrase_mode
                != TrezorPassphraseMode::EnterInApp
            || self.hardware_profile_unlock.session.is_some()
            || self.hardware_profile_unlock.in_progress
        {
            return;
        }

        self.unlock_hardware_profile_from_dialog(window, cx);
    }

    #[cfg(feature = "hardware")]
    pub(super) fn begin_hardware_profile_label_edit(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        self.hardware_profile_unlock.editing_label = true;
        self.hardware_profile_label_input
            .read(cx)
            .focus_handle(cx)
            .focus(window);
        cx.notify();
    }

    #[cfg(feature = "hardware")]
    pub(super) fn cancel_hardware_profile_label_edit(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        if let Some(profile) = self.hardware_profile_unlock.profile.as_ref() {
            self.hardware_profile_label_input.update(cx, |input, cx| {
                input.set_value(profile.label.clone(), window, cx);
            });
        }
        self.hardware_profile_unlock.editing_label = false;
        self.hardware_profile_unlock.error = None;
        cx.notify();
    }

    #[cfg(feature = "hardware")]
    pub(super) fn save_hardware_profile_label_edit(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(device_kind) = self.hardware_profile_unlock.device_kind else {
            self.hardware_profile_unlock.error = Some(Arc::from("Choose a hardware wallet first"));
            cx.notify();
            return;
        };
        let Some(profile) = self.hardware_profile_unlock.profile.as_mut() else {
            self.hardware_profile_unlock.error = Some(Arc::from("Unlock a hardware profile first"));
            cx.notify();
            return;
        };
        let label = self
            .hardware_profile_label_input
            .read(cx)
            .value()
            .trim()
            .to_owned();
        let label = if label.is_empty() {
            default_hardware_profile_label(device_kind).to_owned()
        } else {
            label
        };
        profile.label.clone_from(&label);
        self.hardware_profile_label_input.update(cx, |input, cx| {
            input.set_value(label.clone(), window, cx);
        });

        if let (Some(store), Some(vault_view_unlock)) = (
            self.vault_store.as_ref(),
            self.hardware_profile_unlock.vault_view_unlock.as_ref(),
        ) && let Err(error) =
            store.store_hardware_profile_metadata_with_view_unlock(vault_view_unlock, profile)
        {
            self.handle_hardware_profile_vault_error(&error);
            cx.notify();
            return;
        }

        self.active_hardware_profile = self.hardware_profile_unlock.profile.clone();
        self.hardware_profile_unlock.editing_label = false;
        self.hardware_profile_unlock.error = None;
        cx.notify();
    }

    #[cfg(feature = "hardware")]
    pub(super) fn show_hardware_profile_default_sync_choice(&mut self, cx: &mut Context<'_, Self>) {
        self.hardware_profile_unlock.picker_view =
            HardwareProfilePickerView::ChooseDefaultSyncIntent;
        self.hardware_profile_unlock.error = None;
        cx.notify();
    }

    #[cfg(feature = "hardware")]
    pub(super) fn show_hardware_profile_summary(&mut self, cx: &mut Context<'_, Self>) {
        self.hardware_profile_unlock.picker_view = HardwareProfilePickerView::Summary;
        self.hardware_profile_unlock.error = None;
        cx.notify();
    }

    #[cfg(feature = "hardware")]
    pub(super) fn toggle_hardware_profile_advanced(&mut self, cx: &mut Context<'_, Self>) {
        self.hardware_profile_unlock.advanced_open = !self.hardware_profile_unlock.advanced_open;
        cx.notify();
    }

    #[cfg(feature = "hardware")]
    pub(super) fn setup_default_hardware_account_from_profile_picker(
        &mut self,
        sync_intent: HardwareWalletSyncIntent,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        if sync_intent == HardwareWalletSyncIntent::RecoverExisting {
            self.recover_hardware_account_zero_from_profile_picker(window, cx);
            return;
        }
        self.create_hardware_accounts_from_profile_picker(
            vec![DesktopVaultStore::default_hardware_recovery_account_index()],
            sync_intent,
            window,
            cx,
        );
    }

    #[cfg(feature = "hardware")]
    pub(super) fn unlock_hardware_profile_from_dialog(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        if self.hardware_profile_unlock.in_progress {
            return;
        }
        let Some(store) = self.vault_store.clone() else {
            self.hardware_profile_unlock.error =
                Some(Arc::from("Wallet vault storage is unavailable"));
            cx.notify();
            return;
        };
        let Some(device_kind) = self.hardware_profile_unlock.device_kind else {
            self.hardware_profile_unlock.error = Some(Arc::from("Choose a hardware wallet first"));
            cx.notify();
            return;
        };
        let Some(vault_view_unlock) =
            self.hardware_profile_vault_view_unlock(store.as_ref(), window, cx)
        else {
            return;
        };
        let trezor_mode = self.hardware_profile_unlock.trezor_passphrase_mode;
        let trezor_app_passphrase = if device_kind == HardwareDeviceKind::Trezor
            && trezor_mode == TrezorPassphraseMode::EnterInApp
        {
            Some(Self::read_and_clear_input(
                &self.trezor_app_passphrase_input,
                window,
                cx,
            ))
        } else {
            self.trezor_app_passphrase_input
                .update(cx, |input, cx| input.set_value("", window, cx));
            None
        };

        self.begin_hardware_profile_detection_progress(device_kind);
        self.hardware_profile_unlock
            .clear_trezor_pin_matrix_prompt();
        self.hardware_profile_unlock.in_progress = true;
        self.hardware_profile_unlock.action_label = None;
        self.hardware_profile_unlock.approval_prompt = None;
        self.hardware_profile_unlock.error = None;
        let profile_generation = self.next_hardware_profile_action_generation();
        let (progress_tx, progress_rx) = mpsc::unbounded_channel();
        Self::spawn_hardware_profile_progress_listener(profile_generation, progress_rx, window, cx);
        cx.notify();

        let join = self.runtime.spawn(unlock_hardware_profile(
            store,
            vault_view_unlock,
            device_kind,
            trezor_mode,
            trezor_app_passphrase,
            progress_tx,
        ));
        cx.spawn_in(window, async move |this, cx| {
            let result = join.await;
            let _ = this.update_in(cx, |root, window, cx| {
                if !root.hardware_profile_action_is_current(profile_generation) {
                    return;
                }
                root.hardware_profile_unlock.in_progress = false;
                root.hardware_profile_unlock.action_label = None;
                match result {
                    Ok(Ok((vault_view_unlock, session, profile, metadata))) => {
                        root.install_hardware_profile_picker(
                            vault_view_unlock,
                            session,
                            profile,
                            &metadata,
                            window,
                            cx,
                        );
                    }
                    Ok(Err(HardwareWalletCreationError::Vault(error))) => {
                        root.handle_hardware_profile_vault_error(&error);
                    }
                    Ok(Err(HardwareWalletCreationError::Hardware {
                        error,
                        awaiting_approval,
                    })) => {
                        root.handle_hardware_profile_hardware_error(
                            "Hardware profile unlock failed",
                            &error,
                            awaiting_approval,
                            window,
                            cx,
                        );
                    }
                    Err(error) => {
                        tracing::warn!(%error, "hardware profile unlock task failed");
                        root.hardware_profile_unlock.error = Some(Arc::from(
                            "Hardware profile unlock failed. See logs for non-sensitive diagnostics.",
                        ));
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    #[cfg(feature = "hardware")]
    fn install_hardware_profile_picker(
        &mut self,
        vault_view_unlock: Arc<ViewUnlock>,
        session: HardwareProfileSession,
        profile: HardwareProfileMetadata,
        metadata: &[WalletMetadataBundle],
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        self.wallet_metadata = metadata.to_vec();
        self.wallet_options = wallet_options_from_metadata(self.wallet_metadata.clone());
        self.wallet_switch_generation = self.wallet_switch_generation.wrapping_add(1);
        self.clear_hardware_profile_sensitive_inputs(window, cx);
        self.sync_wallet_select(window, cx);
        let (accounts, locked_accounts) = hardware_account_picker_rows(
            metadata,
            &profile.profile_id,
            self.selected_wallet_id.as_deref(),
        );
        self.hardware_profile_label_input.update(cx, |input, cx| {
            input.set_value(profile.label.clone(), window, cx);
        });
        self.active_hardware_profile = Some(profile.clone());
        self.hardware_profile_unlock.vault_view_unlock = Some(vault_view_unlock);
        self.hardware_profile_unlock.session = Some(session);
        self.hardware_profile_unlock.profile = Some(profile);
        self.hardware_profile_unlock.accounts = accounts;
        self.hardware_profile_unlock.locked_accounts = locked_accounts;
        self.hardware_profile_unlock.picker_view = HardwareProfilePickerView::Summary;
        self.hardware_profile_unlock.advanced_open = false;
        self.hardware_profile_unlock.editing_label = false;
        self.hardware_profile_unlock.set_progress_step(
            HardwareProfileStep::UnlockDevice,
            HardwareProfileStepStatus::Done,
            None::<Arc<str>>,
        );
        self.hardware_profile_unlock.set_progress_step(
            HardwareProfileStep::OpenEthereumApp,
            HardwareProfileStepStatus::Done,
            None::<Arc<str>>,
        );
        self.hardware_profile_unlock.set_progress_step(
            HardwareProfileStep::ApproveRailgunRequest,
            HardwareProfileStepStatus::NotStarted,
            None::<Arc<str>>,
        );
        self.hardware_profile_unlock.error = None;
        let auto_open_wallet_id =
            match hardware_profile_auto_open_wallet_id(&self.hardware_profile_unlock) {
                Ok(wallet_id) => wallet_id,
                Err(message) => {
                    self.hardware_profile_unlock.error = Some(message);
                    None
                }
            };
        cx.notify();
        if let Some(wallet_id) = auto_open_wallet_id {
            self.open_hardware_account_from_profile_picker(wallet_id.as_ref(), window, cx);
        }
    }

    #[cfg(feature = "hardware")]
    pub(super) fn open_hardware_account_from_profile_picker(
        &mut self,
        wallet_id: &str,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        if self.hardware_profile_unlock.in_progress {
            return;
        }
        let Some(store) = self.vault_store.clone() else {
            self.hardware_profile_unlock.error =
                Some(Arc::from("Wallet vault storage is unavailable"));
            cx.notify();
            return;
        };
        let Some(session) = self.hardware_profile_unlock.session.clone() else {
            self.hardware_profile_unlock.error =
                Some(Arc::from("Unlock the hardware profile first"));
            cx.notify();
            return;
        };
        let Some(vault_view_unlock) = self.hardware_profile_unlock.vault_view_unlock.clone() else {
            self.hardware_profile_unlock.error =
                Some(Arc::from("Unlock the hardware profile first"));
            cx.notify();
            return;
        };
        let Some(row) = self
            .hardware_profile_unlock
            .accounts
            .iter()
            .find(|row| row.wallet_id.as_ref() == wallet_id)
            .cloned()
        else {
            self.hardware_profile_unlock.error = Some(Arc::from(
                "Selected account is not in the unlocked hardware profile",
            ));
            cx.notify();
            return;
        };
        if !row.supported {
            self.hardware_profile_unlock.error = Some(Arc::from(
                "This hardware account custody backend is not supported by this app version.",
            ));
            cx.notify();
            return;
        }
        let trezor_mode = self.hardware_profile_unlock.trezor_passphrase_mode;
        let trezor_app_passphrase = self.read_trezor_app_passphrase_for_profile_operation(
            row.account.descriptor.device_kind,
            trezor_mode,
            window,
            cx,
        );
        self.hardware_profile_unlock.in_progress = true;
        self.hardware_profile_unlock.action_label = None;
        self.hardware_profile_unlock.approval_prompt =
            hardware_profile_approval_prompt_for_account(&row.account);
        self.hardware_profile_unlock.error = None;
        let profile_generation = self.next_hardware_profile_action_generation();
        let (progress_tx, progress_rx) = mpsc::unbounded_channel();
        Self::spawn_hardware_profile_progress_listener(profile_generation, progress_rx, window, cx);
        cx.notify();

        let join = self.runtime.spawn(open_hardware_account(
            store,
            vault_view_unlock,
            session,
            wallet_id.to_owned(),
            row.account,
            trezor_mode,
            trezor_app_passphrase,
            progress_tx,
        ));
        cx.spawn_in(window, async move |this, cx| {
            let result = join.await;
            let _ = this.update_in(cx, |root, window, cx| {
                if !root.hardware_profile_action_is_current(profile_generation) {
                    return;
                }
                root.hardware_profile_unlock.in_progress = false;
                root.hardware_profile_unlock.action_label = None;
                match result {
                    Ok(Ok((session, metadata))) => {
                        root.install_view_session(session, metadata, window, cx);
                    }
                    Ok(Err(HardwareWalletCreationError::Vault(error))) => {
                        root.handle_hardware_profile_vault_error(&error);
                    }
                    Ok(Err(HardwareWalletCreationError::Hardware {
                        error,
                        awaiting_approval,
                    })) => {
                        root.handle_hardware_profile_hardware_error(
                            "Hardware account unlock failed",
                            &error,
                            awaiting_approval,
                            window,
                            cx,
                        );
                    }
                    Err(error) => {
                        tracing::warn!(%error, "hardware account unlock task failed");
                        root.hardware_profile_unlock.error = Some(Arc::from(
                            "Hardware account unlock failed. See logs for non-sensitive diagnostics.",
                        ));
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    #[cfg(feature = "hardware")]
    pub(super) fn add_hardware_subaccount_from_profile_picker(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(store) = self.vault_store.clone() else {
            self.hardware_profile_unlock.error =
                Some(Arc::from("Wallet vault storage is unavailable"));
            cx.notify();
            return;
        };
        let Some(vault_view_unlock) = self.hardware_profile_unlock.vault_view_unlock.clone() else {
            self.hardware_profile_unlock.error =
                Some(Arc::from("Unlock the hardware profile first"));
            cx.notify();
            return;
        };
        let Some(profile) = self
            .hardware_profile_unlock
            .session
            .as_ref()
            .and_then(HardwareProfileSession::wallet_profile)
        else {
            self.hardware_profile_unlock.error = Some(Arc::from(
                "This hardware profile is not stored yet. Create or recover account 0 first.",
            ));
            cx.notify();
            return;
        };
        match store
            .next_hardware_account_index_for_profile_with_view_unlock(&vault_view_unlock, &profile)
        {
            Ok(account_index) => self.create_hardware_accounts_from_profile_picker(
                vec![account_index],
                HardwareWalletSyncIntent::CreateNew,
                window,
                cx,
            ),
            Err(error) => {
                self.hardware_profile_unlock.error = Some(vault_error_message(&error));
                cx.notify();
            }
        }
    }

    #[cfg(feature = "hardware")]
    pub(super) fn recover_hardware_account_zero_from_profile_picker(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        self.create_hardware_accounts_from_profile_picker(
            vec![DesktopVaultStore::default_hardware_recovery_account_index()],
            HardwareWalletSyncIntent::RecoverExisting,
            window,
            cx,
        );
    }

    #[cfg(feature = "hardware")]
    pub(super) fn recover_hardware_exact_account_from_profile_picker(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let value = self
            .hardware_profile_exact_index_input
            .read(cx)
            .value()
            .to_string();
        match parse_hardware_exact_recovery_index(&value) {
            Ok(account_index) => self.create_hardware_accounts_from_profile_picker(
                vec![account_index],
                HardwareWalletSyncIntent::RecoverExisting,
                window,
                cx,
            ),
            Err(message) => {
                self.hardware_profile_unlock.error = Some(Arc::from(message));
                cx.notify();
            }
        }
    }

    #[cfg(feature = "hardware")]
    pub(super) fn recover_hardware_range_from_profile_picker(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let start = self
            .hardware_profile_recovery_start_input
            .read(cx)
            .value()
            .to_string();
        let count = self
            .hardware_profile_recovery_count_input
            .read(cx)
            .value()
            .to_string();
        match parse_hardware_recovery_range(&start, &count) {
            Ok(indices) => self.create_hardware_accounts_from_profile_picker(
                indices,
                HardwareWalletSyncIntent::RecoverExisting,
                window,
                cx,
            ),
            Err(message) => {
                self.hardware_profile_unlock.error = Some(Arc::from(message));
                cx.notify();
            }
        }
    }

    #[cfg(feature = "hardware")]
    fn create_hardware_accounts_from_profile_picker(
        &mut self,
        account_indices: Vec<u32>,
        sync_intent: HardwareWalletSyncIntent,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        if self.hardware_profile_unlock.in_progress {
            return;
        }
        let Some(store) = self.vault_store.clone() else {
            self.hardware_profile_unlock.error =
                Some(Arc::from("Wallet vault storage is unavailable"));
            cx.notify();
            return;
        };
        let Some(device_kind) = self.hardware_profile_unlock.device_kind else {
            self.hardware_profile_unlock.error = Some(Arc::from("Unlock a hardware profile first"));
            cx.notify();
            return;
        };
        let Some(session) = self.hardware_profile_unlock.session.clone() else {
            self.hardware_profile_unlock.error = Some(Arc::from("Unlock a hardware profile first"));
            cx.notify();
            return;
        };
        let Some(vault_view_unlock) = self.hardware_profile_unlock.vault_view_unlock.clone() else {
            self.hardware_profile_unlock.error =
                Some(Arc::from("Unlock the hardware profile first"));
            cx.notify();
            return;
        };
        if account_indices.is_empty() {
            self.hardware_profile_unlock.error = Some(Arc::from(
                "Enter at least one hardware account index to recover",
            ));
            cx.notify();
            return;
        }
        let label_prefix = self
            .hardware_profile_label_input
            .read(cx)
            .value()
            .to_string();
        let label_prefix = if label_prefix.trim().is_empty() {
            default_hardware_profile_label(device_kind).to_owned()
        } else {
            label_prefix.trim().to_owned()
        };
        let trezor_mode = self.hardware_profile_unlock.trezor_passphrase_mode;
        let trezor_app_passphrase = self.read_trezor_app_passphrase_for_profile_operation(
            device_kind,
            trezor_mode,
            window,
            cx,
        );
        self.hardware_profile_unlock.in_progress = true;
        self.hardware_profile_unlock.action_label = None;
        self.hardware_profile_unlock.approval_prompt =
            account_indices.first().and_then(|account_index| {
                hardware_profile_approval_prompt_for_account_index(device_kind, *account_index)
            });
        self.hardware_profile_unlock.error = None;
        let profile_generation = self.next_hardware_profile_action_generation();
        let (progress_tx, progress_rx) = mpsc::unbounded_channel();
        Self::spawn_hardware_profile_progress_listener(profile_generation, progress_rx, window, cx);
        cx.notify();

        let join = self.runtime.spawn(create_hardware_profile_accounts(
            store,
            vault_view_unlock,
            label_prefix,
            device_kind,
            session,
            account_indices,
            sync_intent,
            trezor_mode,
            trezor_app_passphrase,
            progress_tx,
        ));
        cx.spawn_in(window, async move |this, cx| {
            let result = join.await;
            let _ = this.update_in(cx, |root, window, cx| {
                if !root.hardware_profile_action_is_current(profile_generation) {
                    return;
                }
                root.hardware_profile_unlock.in_progress = false;
                root.hardware_profile_unlock.action_label = None;
                match result {
                    Ok(Ok((session, metadata))) => {
                        root.install_view_session(session, metadata, window, cx);
                    }
                    Ok(Err(HardwareWalletCreationError::Vault(error))) => {
                        root.handle_hardware_profile_vault_error(&error);
                    }
                    Ok(Err(HardwareWalletCreationError::Hardware {
                        error,
                        awaiting_approval,
                    })) => {
                        root.handle_hardware_profile_hardware_error(
                            "Hardware account creation failed",
                            &error,
                            awaiting_approval,
                            window,
                            cx,
                        );
                    }
                    Err(error) => {
                        tracing::warn!(%error, "hardware profile account creation task failed");
                        root.hardware_profile_unlock.error = Some(Arc::from(
                            "Hardware account creation failed. See logs for non-sensitive diagnostics.",
                        ));
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    #[cfg(feature = "hardware")]
    fn handle_hardware_wallet_setup_vault_error(
        &mut self,
        error: &VaultError,
        label: &str,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        tracing::warn!(
            error_kind = vault_error_kind(error),
            "desktop wallet vault operation failed"
        );
        self.set_vault_error(hardware_setup_vault_error_message(error, label), cx);
        self.finish_hardware_wallet_setup_error(
            window,
            cx,
            !hardware_setup_vault_error_preserves_password(error),
            hardware_setup_vault_error_focus(error),
        );
    }

    #[cfg(feature = "hardware")]
    fn finish_hardware_wallet_setup_error(
        &self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
        clear_password: bool,
        focus: HardwareSetupErrorFocus,
    ) {
        if !matches!(self.vault_state, VaultState::ViewUnlocked) {
            return;
        }
        if clear_password {
            self.add_wallet_password_input
                .update(cx, |input, cx| input.set_value("", window, cx));
        }
        cx.defer_in(window, move |root, window, cx| {
            if matches!(root.vault_state, VaultState::ViewUnlocked)
                && matches!(root.wallet_setup_mode, WalletSetupMode::Hardware(_))
                && !root.hardware_wallet_creation_in_progress
            {
                match focus {
                    HardwareSetupErrorFocus::WalletName => root
                        .wallet_name_input
                        .read(cx)
                        .focus_handle(cx)
                        .focus(window),
                    HardwareSetupErrorFocus::VaultPassword => root
                        .add_wallet_password_input
                        .read(cx)
                        .focus_handle(cx)
                        .focus(window),
                }
            }
        });
    }

    fn install_view_session(
        &mut self,
        session: DesktopViewSession,
        metadata: Vec<WalletMetadataBundle>,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        self.install_view_session_with_dialog_policy(session, metadata, true, window, cx);
    }

    pub(super) fn install_view_session_after_management(
        &mut self,
        session: DesktopViewSession,
        metadata: Vec<WalletMetadataBundle>,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        self.install_view_session_with_dialog_policy(session, metadata, false, window, cx);
    }

    #[cfg(feature = "hardware")]
    fn active_hardware_profile_for_wallet(&self) -> Option<HardwareProfileMetadata> {
        let selected_wallet_id = self.selected_wallet_id.as_deref()?;
        let account = self
            .wallet_metadata
            .iter()
            .find(|wallet| wallet.wallet_uuid == selected_wallet_id)
            .and_then(|wallet| wallet.hardware_account.as_ref())?;

        self.hardware_profile_unlock
            .profile
            .as_ref()
            .filter(|profile| profile.profile_id == account.profile_id)
            .cloned()
            .or_else(|| {
                self.active_hardware_profile
                    .as_ref()
                    .filter(|profile| profile.profile_id == account.profile_id)
                    .cloned()
            })
    }

    fn install_view_session_with_dialog_policy(
        &mut self,
        session: DesktopViewSession,
        metadata: Vec<WalletMetadataBundle>,
        close_dialogs: bool,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let vault_view_unlock = Arc::new(session.clone_vault_view_unlock());
        let session = Arc::new(session);
        let wallet_id: Arc<str> = Arc::from(session.wallet_id().to_owned());
        if close_dialogs {
            window.close_all_dialogs(cx);
        }
        self.active_wallet_generation = self.active_wallet_generation.wrapping_add(1);
        self.view_session = Some(session);
        self.vault_view_unlock = Some(vault_view_unlock);
        self.wallet_metadata = metadata;
        self.wallet_options = wallet_options_from_metadata(self.wallet_metadata.clone());
        self.selected_wallet_id = Some(wallet_id);
        #[cfg(feature = "hardware")]
        {
            self.active_hardware_profile = self.active_hardware_profile_for_wallet();
        }
        self.sync_wallet_select(window, cx);
        self.reset_wallet_scoped_state(cx);
        self.reload_address_books(cx);
        self.reload_broadcaster_preferences(cx);
        self.reload_public_accounts(window, cx);
        self.setup_password = None;
        self.generated_seed = None;
        #[cfg(feature = "hardware")]
        {
            self.hardware_profile_unlock = HardwareProfileUnlockState::default();
            self.clear_hardware_profile_sensitive_inputs(window, cx);
        }
        self.hardware_wallet_creation_in_progress = false;
        self.hardware_wallet_creation_generation =
            self.hardware_wallet_creation_generation.wrapping_add(1);
        self.hardware_wallet_creation_intent = None;
        self.clear_hardware_wallet_restore_account_index(window, cx);
        self.add_wallet_password_input
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.import_mnemonic_input
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.vault_error = None;
        self.vault_state = VaultState::ViewUnlocked;
        self.wallet_setup_mode = WalletSetupMode::Choose;
        self.ensure_chain_load(self.selected_chain, cx);
        cx.notify();
    }

    #[allow(clippy::needless_pass_by_ref_mut)]
    pub(super) fn sync_wallet_select(&mut self, window: &mut Window, cx: &mut Context<'_, Self>) {
        let items = wallet_select_items_from_metadata(&self.wallet_metadata);
        let selected_value = self.selected_wallet_id.as_ref().map(|wallet_id| {
            wallet_select_value_for_selected_wallet(wallet_id, &self.wallet_metadata)
        });
        self.wallet_select.update(cx, |select, cx| {
            select.set_items(SearchableVec::new(items), window, cx);
            if let Some(value) = selected_value.as_ref() {
                select.set_selected_value(value, window, cx);
            } else {
                select.set_selected_index(None, window, cx);
            }
        });
    }

    fn enter_view_unlocked(
        &mut self,
        session: DesktopViewSession,
        metadata: Vec<WalletMetadataBundle>,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        self.install_view_session(session, metadata, window, cx);
    }

    pub(super) fn enter_password_metadata_unlocked(
        &mut self,
        metadata: Vec<WalletMetadataBundle>,
        vault_view_unlock: Arc<ViewUnlock>,
        setup_password: Option<Zeroizing<String>>,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let active = wallet_options_from_metadata(metadata.clone());
        if active.is_empty() {
            if let Some(password) = setup_password {
                self.set_default_wallet_name_from_password(password.as_str(), window, cx);
                self.setup_password = Some(password);
            }
            self.vault_view_unlock = Some(vault_view_unlock);
            self.vault_error = None;
            self.vault_state = VaultState::SetupWallet;
            self.wallet_setup_mode = WalletSetupMode::Choose;
            cx.notify();
            return;
        }

        window.close_all_dialogs(cx);
        self.active_wallet_generation = self.active_wallet_generation.wrapping_add(1);
        self.view_session = None;
        self.vault_view_unlock = Some(vault_view_unlock);
        self.wallet_metadata = metadata;
        self.wallet_options = active;
        self.selected_wallet_id = None;
        self.sync_wallet_select(window, cx);
        self.reset_wallet_scoped_state(cx);
        self.setup_password = None;
        self.generated_seed = None;
        #[cfg(feature = "hardware")]
        {
            self.active_hardware_profile = None;
            self.hardware_profile_unlock = HardwareProfileUnlockState::default();
            self.clear_hardware_profile_sensitive_inputs(window, cx);
        }
        self.hardware_wallet_creation_in_progress = false;
        self.hardware_wallet_creation_generation =
            self.hardware_wallet_creation_generation.wrapping_add(1);
        self.hardware_wallet_creation_intent = None;
        self.clear_hardware_wallet_restore_account_index(window, cx);
        self.vault_error = Some(Arc::from(
            "Hardware-derived private data is locked. Select a hardware wallet and unlock its matching device profile.",
        ));
        self.vault_state = VaultState::ViewUnlocked;
        self.wallet_setup_mode = WalletSetupMode::Choose;
        cx.notify();
    }

    pub(super) fn lock_vault(&mut self, window: &mut Window, cx: &mut Context<'_, Self>) {
        if let Some(store) = self.session_store.get().cloned() {
            self.runtime.spawn(async move {
                store.shutdown().await;
            });
        }
        window.close_all_dialogs(cx);
        self.clear_spend_authorization(cx);
        self.view_session = None;
        self.wallet_metadata.clear();
        self.wallet_options.clear();
        self.private_address_book.clear();
        self.public_address_book.clear();
        self.set_broadcaster_preferences(wallet_ops::vault::BroadcasterPreferences::default(), cx);
        self.broadcaster_preference_error = None;
        self.address_book.search_query = Arc::from("");
        self.address_book
            .search_input
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.address_book.clear_dialog_state(window, cx);
        self.favorite_broadcaster_input
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.banned_broadcaster_input
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.active_broadcaster_tab = BroadcasterActivityTab::default();
        self.address_book_save_error = None;
        self.selected_wallet_id = None;
        self.active_wallet_generation = self.active_wallet_generation.wrapping_add(1);
        self.sync_wallet_select(window, cx);
        self.send_forms.clear();
        self.unshield_forms.clear();
        self.reset_public_wallet_state(window, cx);
        self.private_action_form = None;
        self.clear_private_broadcaster_progress_state();
        self.broadcaster_picker = None;
        self.active_wallet_tab = WalletTab::default();
        self.setup_password = None;
        self.vault_view_unlock = None;
        self.generated_seed = None;
        #[cfg(feature = "hardware")]
        {
            self.active_hardware_profile = None;
            self.hardware_profile_unlock = HardwareProfileUnlockState::default();
            self.clear_hardware_profile_sensitive_inputs(window, cx);
        }
        self.hardware_wallet_creation_in_progress = false;
        self.hardware_wallet_creation_generation =
            self.hardware_wallet_creation_generation.wrapping_add(1);
        self.hardware_wallet_creation_intent = None;
        self.clear_hardware_wallet_restore_account_index(window, cx);
        self.vault_error = None;
        self.repair_cache_error = None;
        self.vault_state = VaultState::UnlockVault;
        self.wallet_setup_mode = WalletSetupMode::Choose;
        self.session_store = Arc::new(tokio::sync::OnceCell::new());
        self.focus_vault_input_on_render = true;
        for state in self.chain_states.values_mut() {
            *state = ChainUtxoState::Idle;
        }
        self.sync_utxo_table(cx);
        cx.notify();
    }

    pub(super) fn read_and_clear_input(
        input: &Entity<InputState>,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) -> Zeroizing<String> {
        let value = Zeroizing::new(input.read(cx).value().to_string());
        input.update(cx, |input, cx| input.set_value("", window, cx));
        value
    }

    pub(super) fn handle_vault_error(&mut self, error: &VaultError, cx: &mut Context<'_, Self>) {
        tracing::warn!(
            error_kind = vault_error_kind(error),
            "desktop wallet vault operation failed"
        );
        self.set_vault_error(vault_error_message(error), cx);
    }

    pub(super) fn set_vault_error(
        &mut self,
        message: impl Into<Arc<str>>,
        cx: &mut Context<'_, Self>,
    ) {
        self.vault_error = Some(message.into());
        cx.notify();
    }
}

#[cfg(feature = "hardware")]
async fn unlock_hardware_profile(
    store: Arc<DesktopVaultStore>,
    vault_view_unlock: Arc<ViewUnlock>,
    device_kind: HardwareDeviceKind,
    trezor_mode: TrezorPassphraseMode,
    trezor_app_passphrase: Option<Zeroizing<String>>,
    progress_tx: mpsc::UnboundedSender<HardwareProfileProgressUpdate>,
) -> Result<
    (
        Arc<ViewUnlock>,
        HardwareProfileSession,
        HardwareProfileMetadata,
        Vec<WalletMetadataBundle>,
    ),
    HardwareWalletCreationError,
> {
    let path = parse_bip32_path(DEFAULT_HARDWARE_DERIVATION_PATH)?;
    let mut suppress_initial_ledger_progress = false;
    let mut suppress_initial_trezor_progress = false;
    loop {
        let detection = detect_hardware_profile_once(
            store.as_ref(),
            &vault_view_unlock,
            device_kind,
            trezor_mode,
            trezor_app_passphrase.as_ref(),
            &path,
            suppress_initial_ledger_progress,
            suppress_initial_trezor_progress,
            &progress_tx,
        )
        .await;
        match detection {
            Ok((session, profile, metadata)) => {
                let _ = send_hardware_profile_progress(
                    &progress_tx,
                    HardwareProfileStep::UnlockDevice,
                    HardwareProfileStepStatus::Done,
                    None,
                );
                let _ = send_hardware_profile_progress(
                    &progress_tx,
                    HardwareProfileStep::OpenEthereumApp,
                    HardwareProfileStepStatus::Done,
                    None,
                );
                return Ok((vault_view_unlock, session, profile, metadata));
            }
            Err(HardwareWalletCreationError::Hardware {
                error,
                awaiting_approval,
            }) if !awaiting_approval && hardware_profile_detection_should_retry(&error) => {
                if !send_hardware_profile_readiness_progress(device_kind, &error, &progress_tx) {
                    return Err(HardwareWalletCreationError::Hardware {
                        error,
                        awaiting_approval,
                    });
                }
                suppress_initial_ledger_progress = device_kind == HardwareDeviceKind::Ledger
                    && hardware_profile_detection_should_suppress_initial_ledger_progress(&error);
                suppress_initial_trezor_progress = device_kind == HardwareDeviceKind::Trezor
                    && hardware_profile_detection_should_suppress_initial_trezor_progress(&error);
                sleep(HARDWARE_PROFILE_READINESS_RETRY_INTERVAL).await;
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(feature = "hardware")]
async fn detect_hardware_profile_once(
    store: &DesktopVaultStore,
    vault_view_unlock: &ViewUnlock,
    device_kind: HardwareDeviceKind,
    trezor_mode: TrezorPassphraseMode,
    trezor_app_passphrase: Option<&Zeroizing<String>>,
    path: &[u32],
    suppress_initial_ledger_progress: bool,
    suppress_initial_trezor_progress: bool,
    progress_tx: &mpsc::UnboundedSender<HardwareProfileProgressUpdate>,
) -> Result<
    (
        HardwareProfileSession,
        HardwareProfileMetadata,
        Vec<WalletMetadataBundle>,
    ),
    HardwareWalletCreationError,
> {
    let (profile_fingerprint, trezor_session_id, effective_trezor_mode) = match device_kind {
        HardwareDeviceKind::Ledger => {
            if !suppress_initial_ledger_progress {
                let _ = send_hardware_profile_progress(
                    progress_tx,
                    HardwareProfileStep::UnlockDevice,
                    HardwareProfileStepStatus::Pending,
                    Some("Connect and unlock your Ledger."),
                );
            }
            let client = LedgerHardwareDerivationClient::connect().await?;
            let fingerprint = client.profile_fingerprint(path).await?;
            let _ = send_hardware_profile_progress(
                progress_tx,
                HardwareProfileStep::UnlockDevice,
                HardwareProfileStepStatus::Done,
                None,
            );
            let _ = send_hardware_profile_progress(
                progress_tx,
                HardwareProfileStep::OpenEthereumApp,
                HardwareProfileStepStatus::Pending,
                Some("Open the Ethereum app on your Ledger."),
            );
            (fingerprint, None, trezor_mode)
        }
        HardwareDeviceKind::Trezor => {
            if !suppress_initial_trezor_progress {
                let _ = send_hardware_profile_progress(
                    progress_tx,
                    HardwareProfileStep::UnlockDevice,
                    HardwareProfileStepStatus::Pending,
                    Some("Connect and unlock your Trezor."),
                );
            }
            let mut client = TrezorHardwareDerivationClient::connect()?;
            client.set_pin_matrix_provider(trezor_pin_matrix_provider(progress_tx.clone()));
            let info = client.device_info()?;
            let _ = send_trezor_passphrase_policy_progress(
                progress_tx,
                info.passphrase_always_on_device,
            );
            let effective_mode =
                effective_trezor_passphrase_mode(trezor_mode, info.passphrase_always_on_device);
            client.set_passphrase_mode(effective_mode);
            if effective_mode == TrezorPassphraseMode::EnterInApp
                && let Some(passphrase) = trezor_app_passphrase.cloned()
            {
                client.set_app_passphrase_zeroizing(passphrase);
            }
            if info.unlocked != Some(false) {
                let _ = send_hardware_profile_progress(
                    progress_tx,
                    HardwareProfileStep::UnlockDevice,
                    HardwareProfileStepStatus::Done,
                    None,
                );
                let _ = send_hardware_profile_progress(
                    progress_tx,
                    HardwareProfileStep::OpenEthereumApp,
                    HardwareProfileStepStatus::Pending,
                    Some("Confirm the active Trezor wallet context."),
                );
            }
            let fingerprint = client.profile_fingerprint(path)?;
            (fingerprint, client.session_id(), effective_mode)
        }
    };
    let mut session = store.hardware_profile_session_for_fingerprint_with_view_unlock(
        vault_view_unlock,
        device_kind,
        &profile_fingerprint,
        trezor_session_id.as_deref(),
    )?;
    if device_kind == HardwareDeviceKind::Trezor {
        session.set_trezor_passphrase_mode(effective_trezor_mode);
    }
    let profiles = store.list_hardware_profile_metadata_with_view_unlock(vault_view_unlock)?;
    let profile = session.profile_id.as_ref().map_or_else(
        || {
            HardwareProfileMetadata::from_binding(
                device_kind,
                default_hardware_profile_label(device_kind),
                session.binding.clone(),
            )
        },
        |profile_id| {
            profiles
                .iter()
                .find(|profile| profile.profile_id == *profile_id)
                .cloned()
                .unwrap_or_else(|| {
                    HardwareProfileMetadata::from_binding(
                        device_kind,
                        default_hardware_profile_label(device_kind),
                        session.binding.clone(),
                    )
                })
        },
    );
    let metadata = store.list_wallet_metadata_with_view_unlock(vault_view_unlock, true)?;
    Ok((session, profile, metadata))
}

#[cfg(feature = "hardware")]
fn send_hardware_profile_progress(
    progress_tx: &mpsc::UnboundedSender<HardwareProfileProgressUpdate>,
    step: HardwareProfileStep,
    status: HardwareProfileStepStatus,
    message: Option<&str>,
) -> bool {
    progress_tx
        .send(HardwareProfileProgressUpdate {
            step,
            status,
            message: message.map(ToOwned::to_owned),
            apply_step: true,
            trezor_passphrase_always_on_device: None,
            approval_prompt: None,
            trezor_pin_matrix_request: None,
            clear_trezor_pin_matrix_request: false,
        })
        .is_ok()
}

#[cfg(feature = "hardware")]
fn send_trezor_passphrase_policy_progress(
    progress_tx: &mpsc::UnboundedSender<HardwareProfileProgressUpdate>,
    passphrase_always_on_device: bool,
) -> bool {
    progress_tx
        .send(HardwareProfileProgressUpdate {
            step: HardwareProfileStep::UnlockDevice,
            status: HardwareProfileStepStatus::Pending,
            message: None,
            apply_step: false,
            trezor_passphrase_always_on_device: Some(passphrase_always_on_device),
            approval_prompt: None,
            trezor_pin_matrix_request: None,
            clear_trezor_pin_matrix_request: false,
        })
        .is_ok()
}

#[cfg(feature = "hardware")]
fn send_trezor_pin_matrix_prompt_progress(
    progress_tx: &mpsc::UnboundedSender<HardwareProfileProgressUpdate>,
    kind: TrezorPinMatrixRequestKind,
    response_tx: std::sync::mpsc::Sender<Zeroizing<String>>,
) -> bool {
    progress_tx
        .send(HardwareProfileProgressUpdate {
            step: HardwareProfileStep::UnlockDevice,
            status: HardwareProfileStepStatus::Pending,
            message: Some("Enter your Trezor PIN using the matrix below.".to_owned()),
            apply_step: true,
            trezor_passphrase_always_on_device: None,
            approval_prompt: None,
            trezor_pin_matrix_request: Some(HardwareProfilePinMatrixRequest { kind, response_tx }),
            clear_trezor_pin_matrix_request: false,
        })
        .is_ok()
}

#[cfg(feature = "hardware")]
fn send_trezor_pin_matrix_clear_progress(
    progress_tx: &mpsc::UnboundedSender<HardwareProfileProgressUpdate>,
) -> bool {
    progress_tx
        .send(HardwareProfileProgressUpdate {
            step: HardwareProfileStep::UnlockDevice,
            status: HardwareProfileStepStatus::Pending,
            message: None,
            apply_step: false,
            trezor_passphrase_always_on_device: None,
            approval_prompt: None,
            trezor_pin_matrix_request: None,
            clear_trezor_pin_matrix_request: true,
        })
        .is_ok()
}

#[cfg(feature = "hardware")]
fn trezor_pin_matrix_provider(
    progress_tx: mpsc::UnboundedSender<HardwareProfileProgressUpdate>,
) -> TrezorPinMatrixProvider {
    Arc::new(move |kind| {
        let (response_tx, response_rx) = std::sync::mpsc::channel();
        if !send_trezor_pin_matrix_prompt_progress(&progress_tx, kind, response_tx) {
            return Err(HardwareDerivationError::TrezorPinEntryCancelled);
        }
        let pin = response_rx
            .recv()
            .map_err(|_| HardwareDerivationError::TrezorPinEntryCancelled)?;
        let _ = send_trezor_pin_matrix_clear_progress(&progress_tx);
        let _ = send_hardware_profile_progress(
            &progress_tx,
            HardwareProfileStep::UnlockDevice,
            HardwareProfileStepStatus::Done,
            None,
        );
        let _ = send_hardware_profile_progress(
            &progress_tx,
            HardwareProfileStep::OpenEthereumApp,
            HardwareProfileStepStatus::Pending,
            Some("Confirm the active Trezor wallet context."),
        );
        Ok(pin)
    })
}

#[cfg(feature = "hardware")]
fn send_hardware_profile_approval_progress(
    device_kind: HardwareDeviceKind,
    approval_prompt: Option<HardwareProfileApprovalPrompt>,
    progress_tx: &mpsc::UnboundedSender<HardwareProfileProgressUpdate>,
) -> bool {
    let device_label = crate::root::vault_ui::hardware_device_label(device_kind);
    let message = format!("Approve the Railgun request on your {device_label}.");
    send_hardware_profile_progress(
        progress_tx,
        HardwareProfileStep::UnlockDevice,
        HardwareProfileStepStatus::Done,
        None,
    ) && send_hardware_profile_progress(
        progress_tx,
        HardwareProfileStep::OpenEthereumApp,
        HardwareProfileStepStatus::Done,
        None,
    ) && progress_tx
        .send(HardwareProfileProgressUpdate {
            step: HardwareProfileStep::ApproveRailgunRequest,
            status: HardwareProfileStepStatus::Pending,
            message: Some(message),
            apply_step: true,
            trezor_passphrase_always_on_device: None,
            approval_prompt,
            trezor_pin_matrix_request: None,
            clear_trezor_pin_matrix_request: false,
        })
        .is_ok()
}

#[cfg(feature = "hardware")]
fn send_hardware_profile_readiness_progress(
    device_kind: HardwareDeviceKind,
    error: &HardwareDerivationError,
    progress_tx: &mpsc::UnboundedSender<HardwareProfileProgressUpdate>,
) -> bool {
    match device_kind {
        HardwareDeviceKind::Ledger => match error {
            HardwareDerivationError::LedgerStatus { status, .. }
                if ledger_locked_status(*status) =>
            {
                send_hardware_profile_progress(
                    progress_tx,
                    HardwareProfileStep::UnlockDevice,
                    HardwareProfileStepStatus::Pending,
                    Some("Unlock your Ledger."),
                ) && send_hardware_profile_progress(
                    progress_tx,
                    HardwareProfileStep::OpenEthereumApp,
                    HardwareProfileStepStatus::NotStarted,
                    None,
                )
            }
            HardwareDerivationError::LedgerStatus { status, .. }
                if ledger_ethereum_app_status(*status) =>
            {
                send_hardware_profile_progress(
                    progress_tx,
                    HardwareProfileStep::UnlockDevice,
                    HardwareProfileStepStatus::Done,
                    None,
                ) && send_hardware_profile_progress(
                    progress_tx,
                    HardwareProfileStep::OpenEthereumApp,
                    HardwareProfileStepStatus::Pending,
                    Some("Open the Ethereum app on your Ledger."),
                )
            }
            HardwareDerivationError::LedgerUnavailable(_) => {
                send_hardware_profile_progress(
                    progress_tx,
                    HardwareProfileStep::UnlockDevice,
                    HardwareProfileStepStatus::Pending,
                    Some("Connect and unlock your Ledger."),
                ) && send_hardware_profile_progress(
                    progress_tx,
                    HardwareProfileStep::OpenEthereumApp,
                    HardwareProfileStepStatus::NotStarted,
                    None,
                ) && send_hardware_profile_progress(
                    progress_tx,
                    HardwareProfileStep::ApproveRailgunRequest,
                    HardwareProfileStepStatus::NotStarted,
                    None,
                )
            }
            _ => {
                send_hardware_profile_progress(
                    progress_tx,
                    HardwareProfileStep::UnlockDevice,
                    HardwareProfileStepStatus::Pending,
                    Some("Unlock your Ledger, then open the Ethereum app."),
                ) && send_hardware_profile_progress(
                    progress_tx,
                    HardwareProfileStep::OpenEthereumApp,
                    HardwareProfileStepStatus::NotStarted,
                    None,
                )
            }
        },
        HardwareDeviceKind::Trezor => {
            let unlock_message = if matches!(
                error,
                HardwareDerivationError::TrezorLocked
                    | HardwareDerivationError::UnsupportedTrezorPinMatrix
            ) {
                "Unlock your Trezor."
            } else {
                "Connect and unlock your Trezor."
            };
            send_hardware_profile_progress(
                progress_tx,
                HardwareProfileStep::UnlockDevice,
                HardwareProfileStepStatus::Pending,
                Some(unlock_message),
            ) && send_hardware_profile_progress(
                progress_tx,
                HardwareProfileStep::OpenEthereumApp,
                HardwareProfileStepStatus::NotStarted,
                None,
            ) && send_hardware_profile_progress(
                progress_tx,
                HardwareProfileStep::ApproveRailgunRequest,
                HardwareProfileStepStatus::NotStarted,
                None,
            )
        }
    }
}

#[cfg(feature = "hardware")]
const fn ledger_locked_status(status: u16) -> bool {
    matches!(status, 0x6804 | 0x6b0c)
}

#[cfg(feature = "hardware")]
const fn ledger_ethereum_app_status(status: u16) -> bool {
    matches!(status, 0x6511 | 0x6a15 | 0x6d00 | 0x6e00)
}

#[cfg(all(test, feature = "hardware"))]
mod hardware_profile_detection_tests {
    use super::*;

    #[test]
    fn generic_ledger_detection_status_keeps_unlock_pending() {
        let (progress_tx, mut progress_rx) = mpsc::unbounded_channel();
        let error = HardwareDerivationError::LedgerStatus {
            operation: "get Ethereum address",
            status: 0x5515,
            message: "Ledger returned an unexpected status. Open the Ethereum app on your Ledger and retry.",
        };

        assert!(send_hardware_profile_readiness_progress(
            HardwareDeviceKind::Ledger,
            &error,
            &progress_tx,
        ));

        let unlock = progress_rx.try_recv().expect("unlock progress update");
        assert_eq!(unlock.step, HardwareProfileStep::UnlockDevice);
        assert_eq!(unlock.status, HardwareProfileStepStatus::Pending);
        assert_eq!(
            unlock.message.as_deref(),
            Some("Unlock your Ledger, then open the Ethereum app.")
        );

        let ethereum = progress_rx
            .try_recv()
            .expect("ethereum app progress update");
        assert_eq!(ethereum.step, HardwareProfileStep::OpenEthereumApp);
        assert_eq!(ethereum.status, HardwareProfileStepStatus::NotStarted);
        assert_eq!(ethereum.message, None);
        assert!(progress_rx.try_recv().is_err());
    }

    #[test]
    fn ethereum_app_ledger_detection_status_keeps_open_ethereum_pending() {
        let (progress_tx, mut progress_rx) = mpsc::unbounded_channel();
        let error = HardwareDerivationError::LedgerStatus {
            operation: "get Ethereum address",
            status: 0x6511,
            message: "Open the Ethereum app on your Ledger, then retry.",
        };

        assert!(send_hardware_profile_readiness_progress(
            HardwareDeviceKind::Ledger,
            &error,
            &progress_tx,
        ));

        let unlock = progress_rx.try_recv().expect("unlock progress update");
        assert_eq!(unlock.step, HardwareProfileStep::UnlockDevice);
        assert_eq!(unlock.status, HardwareProfileStepStatus::Done);
        assert_eq!(unlock.message, None);

        let ethereum = progress_rx
            .try_recv()
            .expect("ethereum app progress update");
        assert_eq!(ethereum.step, HardwareProfileStep::OpenEthereumApp);
        assert_eq!(ethereum.status, HardwareProfileStepStatus::Pending);
        assert_eq!(
            ethereum.message.as_deref(),
            Some("Open the Ethereum app on your Ledger.")
        );
        assert!(progress_rx.try_recv().is_err());
    }

    #[test]
    fn ledger_unavailable_resets_downstream_progress() {
        let (progress_tx, mut progress_rx) = mpsc::unbounded_channel();
        let ethereum_app_error = HardwareDerivationError::LedgerStatus {
            operation: "get Ethereum address",
            status: 0x6511,
            message: "Open the Ethereum app on your Ledger, then retry.",
        };
        assert!(send_hardware_profile_readiness_progress(
            HardwareDeviceKind::Ledger,
            &ethereum_app_error,
            &progress_tx,
        ));
        progress_rx.try_recv().expect("unlock done update");
        let ethereum = progress_rx.try_recv().expect("ethereum app pending update");
        assert_eq!(ethereum.step, HardwareProfileStep::OpenEthereumApp);
        assert_eq!(ethereum.status, HardwareProfileStepStatus::Pending);

        let unavailable = HardwareDerivationError::LedgerUnavailable("Ledger is not connected");
        assert!(send_hardware_profile_readiness_progress(
            HardwareDeviceKind::Ledger,
            &unavailable,
            &progress_tx,
        ));

        let unlock = progress_rx.try_recv().expect("unlock pending update");
        assert_eq!(unlock.step, HardwareProfileStep::UnlockDevice);
        assert_eq!(unlock.status, HardwareProfileStepStatus::Pending);

        let ethereum = progress_rx.try_recv().expect("ethereum app reset update");
        assert_eq!(ethereum.step, HardwareProfileStep::OpenEthereumApp);
        assert_eq!(ethereum.status, HardwareProfileStepStatus::NotStarted);
        assert_eq!(ethereum.message, None);

        let approval = progress_rx.try_recv().expect("approval reset update");
        assert_eq!(approval.step, HardwareProfileStep::ApproveRailgunRequest);
        assert_eq!(approval.status, HardwareProfileStepStatus::NotStarted);
        assert_eq!(approval.message, None);
        assert!(progress_rx.try_recv().is_err());
    }

    #[test]
    fn trezor_locked_resets_downstream_progress() {
        let (progress_tx, mut progress_rx) = mpsc::unbounded_channel();
        let error = HardwareDerivationError::TrezorLocked;

        assert!(send_hardware_profile_readiness_progress(
            HardwareDeviceKind::Trezor,
            &error,
            &progress_tx,
        ));

        let unlock = progress_rx.try_recv().expect("unlock pending update");
        assert_eq!(unlock.step, HardwareProfileStep::UnlockDevice);
        assert_eq!(unlock.status, HardwareProfileStepStatus::Pending);
        assert_eq!(unlock.message.as_deref(), Some("Unlock your Trezor."));

        let context = progress_rx.try_recv().expect("context reset update");
        assert_eq!(context.step, HardwareProfileStep::OpenEthereumApp);
        assert_eq!(context.status, HardwareProfileStepStatus::NotStarted);
        assert_eq!(context.message, None);

        let approval = progress_rx.try_recv().expect("approval reset update");
        assert_eq!(approval.step, HardwareProfileStep::ApproveRailgunRequest);
        assert_eq!(approval.status, HardwareProfileStepStatus::NotStarted);
        assert_eq!(approval.message, None);
        assert!(progress_rx.try_recv().is_err());
    }
}

#[cfg(feature = "hardware")]
async fn open_hardware_account(
    store: Arc<DesktopVaultStore>,
    vault_view_unlock: Arc<ViewUnlock>,
    mut hardware_session: HardwareProfileSession,
    wallet_id: String,
    account: HardwareRailgunAccountMetadata,
    trezor_mode: TrezorPassphraseMode,
    trezor_app_passphrase: Option<Zeroizing<String>>,
    progress_tx: mpsc::UnboundedSender<HardwareProfileProgressUpdate>,
) -> Result<HardwareWalletCreationResult, HardwareWalletCreationError> {
    hardware_session.verify_account(&account)?;
    let descriptor = account.descriptor.clone();
    let output = match descriptor.device_kind {
        HardwareDeviceKind::Ledger => {
            let client = LedgerHardwareDerivationClient::connect().await?;
            let active = client.active_profile_session(&descriptor.path).await?;
            active.verify_descriptor(&descriptor)?;
            let _ = send_hardware_profile_approval_progress(
                HardwareDeviceKind::Ledger,
                hardware_profile_approval_prompt_for_descriptor(&descriptor),
                &progress_tx,
            );
            client
                .eip1024_shared_secret(&descriptor.path, true)
                .await
                .map_err(hardware_approval_error)?
        }
        HardwareDeviceKind::Trezor => {
            let mut client = TrezorHardwareDerivationClient::connect_with_session(
                hardware_session.trezor_session_id.clone(),
            )?;
            client.set_pin_matrix_provider(trezor_pin_matrix_provider(progress_tx.clone()));
            let info = client.device_info()?;
            let _ = send_trezor_passphrase_policy_progress(
                &progress_tx,
                info.passphrase_always_on_device,
            );
            let effective_mode =
                effective_trezor_passphrase_mode(trezor_mode, info.passphrase_always_on_device);
            client.set_passphrase_mode(effective_mode);
            if effective_mode == TrezorPassphraseMode::EnterInApp
                && let Some(passphrase) = trezor_app_passphrase
            {
                client.set_app_passphrase_zeroizing(passphrase);
            }
            let active = client.active_profile_session(&descriptor.path)?;
            active.verify_descriptor(&descriptor)?;
            hardware_session.trezor_session_id = active.trezor_session_id;
            hardware_session.set_trezor_passphrase_mode(effective_mode);
            let _ = send_hardware_profile_approval_progress(
                HardwareDeviceKind::Trezor,
                hardware_profile_approval_prompt_for_descriptor(&descriptor),
                &progress_tx,
            );
            client
                .cipher_key_value(&descriptor)
                .map_err(hardware_approval_error)?
        }
    };
    let view_access_key = hardware_view_access_key_from_hardware_output(&descriptor, &output)?;
    let session = store.load_hardware_view_session_with_view_unlock(
        &vault_view_unlock,
        &hardware_session,
        &wallet_id,
        &view_access_key,
    )?;
    let metadata = store.list_wallet_metadata_with_view_unlock(&vault_view_unlock, true)?;
    Ok((session, metadata))
}

#[cfg(feature = "hardware")]
async fn create_hardware_profile_accounts(
    store: Arc<DesktopVaultStore>,
    vault_view_unlock: Arc<ViewUnlock>,
    label_prefix: String,
    device_kind: HardwareDeviceKind,
    mut hardware_session: HardwareProfileSession,
    account_indices: Vec<u32>,
    sync_intent: HardwareWalletSyncIntent,
    trezor_mode: TrezorPassphraseMode,
    trezor_app_passphrase: Option<Zeroizing<String>>,
    progress_tx: mpsc::UnboundedSender<HardwareProfileProgressUpdate>,
) -> Result<HardwareWalletCreationResult, HardwareWalletCreationError> {
    let path = parse_bip32_path(DEFAULT_HARDWARE_DERIVATION_PATH)?;
    let profile_fingerprint = hardware_session.binding.fingerprint.clone();
    let mut profile_metadata = store
        .list_hardware_profile_metadata_with_view_unlock(&vault_view_unlock)?
        .into_iter()
        .find(|profile| hardware_session.matches_profile(profile))
        .unwrap_or_else(|| {
            HardwareProfileMetadata::from_binding(
                device_kind,
                label_prefix.clone(),
                hardware_session.binding.clone(),
            )
        });
    profile_metadata.label.clone_from(&label_prefix);
    hardware_session.profile_id = Some(profile_metadata.profile_id.clone());

    let mut last_result: Option<HardwareWalletCreationResult> = None;
    let total = account_indices.len();
    match device_kind {
        HardwareDeviceKind::Ledger => {
            let client = LedgerHardwareDerivationClient::connect().await?;
            let active = client.active_profile_session(&path).await?;
            for account_index in account_indices {
                let descriptor = HardwareDerivationDescriptor::ledger_eip1024_v1(
                    path.clone(),
                    account_index,
                    profile_fingerprint.clone(),
                    sync_intent,
                );
                active.verify_descriptor(&descriptor)?;
                let _ = send_hardware_profile_approval_progress(
                    HardwareDeviceKind::Ledger,
                    hardware_profile_approval_prompt_for_descriptor(&descriptor),
                    &progress_tx,
                );
                let output = client
                    .eip1024_shared_secret(&descriptor.path, true)
                    .await
                    .map_err(hardware_approval_error)?;
                let view_access_key =
                    hardware_view_access_key_from_hardware_output(&descriptor, &output)?;
                let entropy = synthetic_entropy_from_hardware_output(&descriptor, output)?;
                last_result = Some(store_hardware_profile_account(
                    store.as_ref(),
                    &vault_view_unlock,
                    &label_prefix,
                    total,
                    account_index,
                    descriptor,
                    &entropy,
                    &view_access_key,
                    &hardware_session,
                    &profile_metadata,
                )?);
            }
        }
        HardwareDeviceKind::Trezor => {
            let mut client = TrezorHardwareDerivationClient::connect_with_session(
                hardware_session.trezor_session_id.clone(),
            )?;
            client.set_pin_matrix_provider(trezor_pin_matrix_provider(progress_tx.clone()));
            let info = client.device_info()?;
            let _ = send_trezor_passphrase_policy_progress(
                &progress_tx,
                info.passphrase_always_on_device,
            );
            let effective_mode =
                effective_trezor_passphrase_mode(trezor_mode, info.passphrase_always_on_device);
            profile_metadata.preferred_trezor_passphrase_mode = Some(effective_mode);
            client.set_passphrase_mode(effective_mode);
            if effective_mode == TrezorPassphraseMode::EnterInApp
                && let Some(passphrase) = trezor_app_passphrase
            {
                client.set_app_passphrase_zeroizing(passphrase);
            }
            let active = client.active_profile_session(&path)?;
            hardware_session
                .trezor_session_id
                .clone_from(&active.trezor_session_id);
            hardware_session.set_trezor_passphrase_mode(effective_mode);
            for account_index in account_indices {
                let descriptor = HardwareDerivationDescriptor::trezor_cipher_key_value_v1(
                    path.clone(),
                    account_index,
                    profile_fingerprint.clone(),
                    sync_intent,
                );
                active.verify_descriptor(&descriptor)?;
                let _ = send_hardware_profile_approval_progress(
                    HardwareDeviceKind::Trezor,
                    hardware_profile_approval_prompt_for_descriptor(&descriptor),
                    &progress_tx,
                );
                let output = client
                    .cipher_key_value(&descriptor)
                    .map_err(hardware_approval_error)?;
                let view_access_key =
                    hardware_view_access_key_from_hardware_output(&descriptor, &output)?;
                let entropy = synthetic_entropy_from_hardware_output(&descriptor, output)?;
                last_result = Some(store_hardware_profile_account(
                    store.as_ref(),
                    &vault_view_unlock,
                    &label_prefix,
                    total,
                    account_index,
                    descriptor,
                    &entropy,
                    &view_access_key,
                    &hardware_session,
                    &profile_metadata,
                )?);
            }
        }
    }
    last_result.ok_or(HardwareWalletCreationError::Vault(
        VaultError::InvalidHardwareAccountRecoveryRange,
    ))
}

#[cfg(feature = "hardware")]
fn store_hardware_profile_account(
    store: &DesktopVaultStore,
    vault_view_unlock: &ViewUnlock,
    label_prefix: &str,
    total: usize,
    account_index: u32,
    descriptor: HardwareDerivationDescriptor,
    entropy: &SyntheticRailgunEntropy,
    view_access_key: &HardwareViewAccessKey,
    hardware_session: &HardwareProfileSession,
    profile_metadata: &HardwareProfileMetadata,
) -> Result<HardwareWalletCreationResult, HardwareWalletCreationError> {
    let wallet_id = generate_opaque_id()?;
    let label = if total == 1 {
        format!("{label_prefix} account {account_index}")
    } else {
        format!("{label_prefix} account {account_index} recovery")
    };
    let metadata = store.new_hardware_wallet_metadata_with_view_unlock(
        vault_view_unlock,
        &wallet_id,
        &label,
        descriptor,
    )?;
    store.store_hardware_derived_wallet_from_entropy_with_metadata_for_view(
        vault_view_unlock,
        &wallet_id,
        account_index,
        entropy.expose_secret(),
        &metadata,
        view_access_key,
    )?;
    store.store_hardware_profile_metadata_with_view_unlock(vault_view_unlock, profile_metadata)?;
    let session = store.load_hardware_view_session_with_view_unlock(
        vault_view_unlock,
        hardware_session,
        &wallet_id,
        view_access_key,
    )?;
    let metadata = store.list_wallet_metadata_with_view_unlock(vault_view_unlock, true)?;
    Ok((session, metadata))
}

#[cfg(feature = "hardware")]
async fn create_hardware_derived_wallet(
    store: Arc<DesktopVaultStore>,
    password: Zeroizing<String>,
    wallet_id: String,
    label: String,
    device_kind: HardwareDeviceKind,
    sync_intent: HardwareWalletSyncIntent,
    explicit_account_index: Option<u32>,
) -> Result<HardwareWalletCreationResult, HardwareWalletCreationError> {
    let path = parse_bip32_path(DEFAULT_HARDWARE_DERIVATION_PATH)?;
    let (descriptor, entropy, view_access_key) = match device_kind {
        HardwareDeviceKind::Ledger => {
            let client = LedgerHardwareDerivationClient::connect().await?;
            let profile_fingerprint = client.profile_fingerprint(&path).await?;
            let account_index = match explicit_account_index {
                Some(index) => index,
                None => next_hardware_account_index(
                    store.as_ref(),
                    password.as_str(),
                    device_kind,
                    &profile_fingerprint,
                )?,
            };
            let descriptor = HardwareDerivationDescriptor::ledger_eip1024_v1(
                path,
                account_index,
                profile_fingerprint,
                sync_intent,
            );
            let output = client.eip1024_shared_secret(&descriptor.path, true).await?;
            let view_access_key =
                hardware_view_access_key_from_hardware_output(&descriptor, &output)?;
            let entropy = synthetic_entropy_from_hardware_output(&descriptor, output)?;
            (descriptor, entropy, view_access_key)
        }
        HardwareDeviceKind::Trezor => {
            let mut client = TrezorHardwareDerivationClient::connect()?;
            let profile_fingerprint = client.profile_fingerprint(&path)?;
            let account_index = match explicit_account_index {
                Some(index) => index,
                None => next_hardware_account_index(
                    store.as_ref(),
                    password.as_str(),
                    device_kind,
                    &profile_fingerprint,
                )?,
            };
            let descriptor = HardwareDerivationDescriptor::trezor_cipher_key_value_v1(
                path,
                account_index,
                profile_fingerprint,
                sync_intent,
            );
            let output = client.cipher_key_value(&descriptor)?;
            let view_access_key =
                hardware_view_access_key_from_hardware_output(&descriptor, &output)?;
            let entropy = synthetic_entropy_from_hardware_output(&descriptor, output)?;
            (descriptor, entropy, view_access_key)
        }
    };
    let (session, metadata) = store_hardware_wallet(
        store.as_ref(),
        password.as_str(),
        &wallet_id,
        &label,
        descriptor,
        &entropy,
        &view_access_key,
    )?;
    Ok((session, metadata))
}

#[cfg(feature = "hardware")]
fn next_hardware_account_index(
    store: &DesktopVaultStore,
    password: &str,
    device_kind: HardwareDeviceKind,
    profile_fingerprint: &str,
) -> Result<u32, VaultError> {
    let profile = HardwareWalletProfile {
        device_kind,
        profile_fingerprint: profile_fingerprint.to_owned(),
    };
    store.next_hardware_account_index_for_profile(password, &profile)
}

#[cfg(feature = "hardware")]
fn store_hardware_wallet(
    store: &DesktopVaultStore,
    password: &str,
    wallet_id: &str,
    label: &str,
    descriptor: HardwareDerivationDescriptor,
    entropy: &SyntheticRailgunEntropy,
    view_access_key: &HardwareViewAccessKey,
) -> Result<(DesktopViewSession, Vec<WalletMetadataBundle>), HardwareWalletCreationError> {
    let account_index = descriptor.account_index;
    let device_kind = descriptor.device_kind;
    let profile_fingerprint = descriptor.profile_fingerprint.clone();
    let metadata = store.new_hardware_wallet_metadata(password, wallet_id, label, descriptor)?;
    store.store_hardware_derived_wallet_from_entropy_with_metadata(
        password,
        wallet_id,
        account_index,
        entropy.expose_secret(),
        &metadata,
        view_access_key,
    )?;
    let metadata = store.list_wallet_metadata(password)?;
    let hardware_session = store.hardware_profile_session_for_fingerprint(
        password,
        device_kind,
        &profile_fingerprint,
        None,
    )?;
    let session = store.load_hardware_view_session(
        password,
        &hardware_session,
        wallet_id,
        view_access_key,
    )?;
    Ok((session, metadata))
}
