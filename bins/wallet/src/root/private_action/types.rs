use super::{
    Address, App, Arc, BroadcasterChoice, BroadcasterFeePolicy, DesktopSelfBroadcastResult,
    DesktopVaultStore, DesktopViewSession, Eip1559GasFeeEditorState, Entity, FeeRow, InputState,
    IntoElement, PreparedSendCall, PreparedUnshieldCall, PublicBroadcasterCostEstimate,
    PublicBroadcasterFeeMode, PublicBroadcasterResultKind, PublicBroadcasterSubmissionResult,
    SearchableVec, SelectItem, SelectState, SelfBroadcastGasFeeSelection, SharedString,
    SpendAuthorizationSummary, SpendAuthorizationSummaryRow, TransactionGenerationStage, U256,
    WalletIconSource, WalletSession, Window, format_send_amount_input,
    format_unshield_amount_input, private_action_asset_select_row,
    self_broadcast_gas_payer_fields_match, self_broadcast_gas_payer_select_menu_row,
    self_broadcast_gas_payer_select_trigger_row, short_address,
};

#[cfg(test)]
pub(in crate::root) const SEND_AUTHORIZATION_FAILED_ERROR: &str =
    "authorize public broadcaster send spend: unlock failed";
#[cfg(test)]
pub(in crate::root) const UNSHIELD_AUTHORIZATION_FAILED_ERROR: &str =
    "authorize public broadcaster unshield spend: unlock failed";
pub(in crate::root) const SELF_BROADCAST_PRIVACY_WARNING: &str = "Self-broadcast links the selected Public account, RPC metadata, and transaction timing to this private action.";
pub(in crate::root) const SELF_BROADCAST_ZERO_GAS_PAYER_WARNING: &str = "Selected gas payer has 0 native balance on this chain. Choose another Public account or fund this account before self-broadcasting.";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(in crate::root) enum DeliveryMode {
    ManualCalldata,
    #[default]
    PublicBroadcaster,
    SelfBroadcast,
}

impl DeliveryMode {
    const fn label(self) -> &'static str {
        match self {
            Self::ManualCalldata => "External wallet",
            Self::PublicBroadcaster => "Public broadcaster",
            Self::SelfBroadcast => "Self-broadcast",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::root) enum DeliveryFormKind {
    Send,
    Unshield,
}

pub(in crate::root) struct PrivateActionFormState {
    pub(in crate::root) kind: DeliveryFormKind,
    pub(in crate::root) key: UnshieldAssetKey,
}

#[derive(Clone)]
pub(in crate::root) struct SelfBroadcastGasPayerSelectItem {
    pub(in crate::root) public_account_uuid: Arc<str>,
    pub(in crate::root) label: Arc<str>,
    pub(in crate::root) address: Address,
    pub(in crate::root) chain_id: u64,
    pub(in crate::root) balance_label: Arc<str>,
}

impl SelectItem for SelfBroadcastGasPayerSelectItem {
    type Value = Arc<str>;

    fn title(&self) -> SharedString {
        SharedString::from(format!("{} · {}", self.label, short_address(&self.address)))
    }

    fn display_title(&self) -> Option<gpui::AnyElement> {
        Some(
            self_broadcast_gas_payer_select_trigger_row(&self.label, &self.address)
                .into_any_element(),
        )
    }

    fn render(&self, _: &mut Window, _: &mut App) -> impl IntoElement {
        self_broadcast_gas_payer_select_menu_row(
            &self.label,
            &self.address,
            self.chain_id,
            &self.balance_label,
        )
    }

    fn value(&self) -> &Self::Value {
        &self.public_account_uuid
    }

    fn matches(&self, query: &str) -> bool {
        self_broadcast_gas_payer_fields_match(Some(&self.label), &self.address, query)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(in crate::root) struct PrivateActionAssetSelectItem {
    pub(in crate::root) token: Address,
    pub(in crate::root) label: Arc<str>,
    pub(in crate::root) icon_path: Option<WalletIconSource>,
}

impl SelectItem for PrivateActionAssetSelectItem {
    type Value = Address;

    fn title(&self) -> SharedString {
        SharedString::from(self.label.to_string())
    }

    fn display_title(&self) -> Option<gpui::AnyElement> {
        Some(
            private_action_asset_select_row(&self.label, self.icon_path.clone()).into_any_element(),
        )
    }

    fn render(&self, _: &mut Window, _: &mut App) -> impl IntoElement {
        private_action_asset_select_row(&self.label, self.icon_path.clone())
    }

    fn value(&self) -> &Self::Value {
        &self.token
    }

    fn matches(&self, query: &str) -> bool {
        let query = query.trim().to_ascii_lowercase();
        query.is_empty()
            || self.label.to_ascii_lowercase().contains(&query)
            || self
                .token
                .to_checksum(None)
                .to_ascii_lowercase()
                .contains(&query)
    }
}

pub(in crate::root) enum SendResult {
    Manual(PreparedSendCall),
    PublicBroadcaster(Box<PublicBroadcasterSubmissionResult>),
    SelfBroadcast(Box<DesktopSelfBroadcastResult>),
}

pub(in crate::root) enum UnshieldResult {
    Manual(PreparedUnshieldCall),
    PublicBroadcaster(Box<PublicBroadcasterSubmissionResult>),
    SelfBroadcast(Box<DesktopSelfBroadcastResult>),
}

pub(in crate::root) fn send_form_submitted(form: &SendFormState) -> bool {
    matches!(
        form.result.as_ref(),
        Some(SendResult::PublicBroadcaster(result))
            if matches!(result.result, PublicBroadcasterResultKind::Submitted { .. })
    ) || matches!(form.result.as_ref(), Some(SendResult::SelfBroadcast(_)))
}

pub(in crate::root) fn unshield_form_submitted(form: &UnshieldFormState) -> bool {
    matches!(
        form.result.as_ref(),
        Some(UnshieldResult::PublicBroadcaster(result))
            if matches!(result.result, PublicBroadcasterResultKind::Submitted { .. })
    ) || matches!(form.result.as_ref(), Some(UnshieldResult::SelfBroadcast(_)))
}

#[derive(Clone, Eq, PartialEq)]
pub(in crate::root) struct UnshieldAsset {
    pub(in crate::root) chain_id: u64,
    pub(in crate::root) token: Address,
    pub(in crate::root) label: String,
    pub(in crate::root) decimals: Option<u8>,
    pub(in crate::root) total: U256,
    pub(in crate::root) poi_verified_total: U256,
    pub(in crate::root) max_batched: U256,
    pub(in crate::root) icon_path: Option<WalletIconSource>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(in crate::root) struct UnshieldAssetKey {
    pub(in crate::root) chain_id: u64,
    pub(in crate::root) token: Address,
}

impl UnshieldAssetKey {
    pub(in crate::root) const fn new(chain_id: u64, token: Address) -> Self {
        Self { chain_id, token }
    }

    pub(in crate::root) const fn from_asset(asset: &UnshieldAsset) -> Self {
        Self::new(asset.chain_id, asset.token)
    }
}

pub(in crate::root) struct SendSpendDraft {
    pub(in crate::root) asset: UnshieldAsset,
    pub(in crate::root) delivery_mode: DeliveryMode,
    pub(in crate::root) broadcaster_choice: BroadcasterChoice,
    pub(in crate::root) cost_estimate: Option<PublicBroadcasterCostEstimate>,
    pub(in crate::root) fee_token: Address,
    pub(in crate::root) self_broadcast_gas_fee: SelfBroadcastGasFeeSelection,
    pub(in crate::root) self_broadcast_initial_gas_fee: Option<(u128, u128)>,
    pub(in crate::root) broadcaster_fee_mode: PublicBroadcasterFeeMode,
    pub(in crate::root) view_session: Arc<DesktopViewSession>,
    pub(in crate::root) vault_store: Arc<DesktopVaultStore>,
    pub(in crate::root) session: Arc<WalletSession>,
    pub(in crate::root) recipient: String,
    pub(in crate::root) amount: U256,
    pub(in crate::root) self_broadcast_public_account_uuid: Option<String>,
    pub(in crate::root) self_broadcast_gas_payer_display: Option<String>,
    pub(in crate::root) fee_rows: Vec<FeeRow>,
    pub(in crate::root) fee_policy: BroadcasterFeePolicy,
}

pub(in crate::root) struct UnshieldSpendDraft {
    pub(in crate::root) asset: UnshieldAsset,
    pub(in crate::root) unwrap: bool,
    pub(in crate::root) delivery_mode: DeliveryMode,
    pub(in crate::root) broadcaster_choice: BroadcasterChoice,
    pub(in crate::root) cost_estimate: Option<PublicBroadcasterCostEstimate>,
    pub(in crate::root) fee_token: Address,
    pub(in crate::root) self_broadcast_gas_fee: SelfBroadcastGasFeeSelection,
    pub(in crate::root) self_broadcast_initial_gas_fee: Option<(u128, u128)>,
    pub(in crate::root) broadcaster_fee_mode: PublicBroadcasterFeeMode,
    pub(in crate::root) view_session: Arc<DesktopViewSession>,
    pub(in crate::root) vault_store: Arc<DesktopVaultStore>,
    pub(in crate::root) session: Arc<WalletSession>,
    pub(in crate::root) recipient: Address,
    pub(in crate::root) amount: U256,
    pub(in crate::root) self_broadcast_public_account_uuid: Option<String>,
    pub(in crate::root) self_broadcast_gas_payer_display: Option<String>,
    pub(in crate::root) fee_rows: Vec<FeeRow>,
    pub(in crate::root) fee_policy: BroadcasterFeePolicy,
}

pub(in crate::root) fn private_send_authorization_summary(
    draft: &SendSpendDraft,
) -> SpendAuthorizationSummary {
    SpendAuthorizationSummary::new(
        "Private send",
        "Enter your vault password to authorize this private send.",
        vec![
            SpendAuthorizationSummaryRow::new(
                "Amount",
                private_amount_label(draft.amount, &draft.asset, true),
            )
            .with_icon(draft.asset.icon_path.clone()),
            SpendAuthorizationSummaryRow::new("Recipient", draft.recipient.clone()),
            SpendAuthorizationSummaryRow::new("Delivery", draft.delivery_mode.label()),
        ],
    )
}

pub(in crate::root) fn private_unshield_authorization_summary(
    draft: &UnshieldSpendDraft,
) -> SpendAuthorizationSummary {
    SpendAuthorizationSummary::new(
        "Private unshield",
        "Enter your vault password to authorize this unshield.",
        vec![
            SpendAuthorizationSummaryRow::new(
                "Amount",
                private_amount_label(draft.amount, &draft.asset, false),
            )
            .with_icon(draft.asset.icon_path.clone()),
            SpendAuthorizationSummaryRow::new("Recipient", draft.recipient.to_checksum(None)),
            SpendAuthorizationSummaryRow::new("Delivery", draft.delivery_mode.label()),
        ],
    )
}

pub(in crate::root) fn private_amount_label(
    amount: U256,
    asset: &UnshieldAsset,
    send: bool,
) -> String {
    let formatted = if send {
        format_send_amount_input(amount, asset.decimals)
    } else {
        format_unshield_amount_input(amount, asset.decimals)
    };
    format!("{formatted} {}", asset.label)
}

pub(in crate::root) struct UnshieldFormState {
    pub(in crate::root) asset: UnshieldAsset,
    pub(in crate::root) recipient_input: Entity<InputState>,
    pub(in crate::root) amount_input: Entity<InputState>,
    pub(in crate::root) asset_select:
        Entity<SelectState<SearchableVec<PrivateActionAssetSelectItem>>>,
    pub(in crate::root) asset_select_items: Vec<PrivateActionAssetSelectItem>,
    pub(in crate::root) unwrap: bool,
    pub(in crate::root) delivery_mode: DeliveryMode,
    pub(in crate::root) self_broadcast_gas_payer_uuid: Option<Arc<str>>,
    pub(in crate::root) self_broadcast_gas_payer_select:
        Entity<SelectState<SearchableVec<SelfBroadcastGasPayerSelectItem>>>,
    pub(in crate::root) self_broadcast_gas_fee: Eip1559GasFeeEditorState,
    pub(in crate::root) self_broadcast_estimated_native_gas_cost: Option<U256>,
    pub(in crate::root) selected_fee_token: Address,
    pub(in crate::root) broadcaster_choice: BroadcasterChoice,
    pub(in crate::root) broadcaster_fee_mode: PublicBroadcasterFeeMode,
    pub(in crate::root) allow_suspicious_broadcasters: bool,
    pub(in crate::root) transaction_fee_breakdown_open: bool,
    pub(in crate::root) pending_programmatic_amount_input: Option<String>,
    pub(in crate::root) cost_estimate_pending: bool,
    pub(in crate::root) estimating_cost: bool,
    pub(in crate::root) cost_estimate: Option<PublicBroadcasterCostEstimate>,
    pub(in crate::root) estimate_id: u64,
    pub(in crate::root) generation_id: u64,
    pub(in crate::root) generating: bool,
    pub(in crate::root) generation_stage: TransactionGenerationStage,
    pub(in crate::root) error: Option<Arc<str>>,
    pub(in crate::root) result: Option<UnshieldResult>,
}

pub(in crate::root) struct SendFormState {
    pub(in crate::root) asset: UnshieldAsset,
    pub(in crate::root) recipient_input: Entity<InputState>,
    pub(in crate::root) amount_input: Entity<InputState>,
    pub(in crate::root) asset_select:
        Entity<SelectState<SearchableVec<PrivateActionAssetSelectItem>>>,
    pub(in crate::root) asset_select_items: Vec<PrivateActionAssetSelectItem>,
    pub(in crate::root) delivery_mode: DeliveryMode,
    pub(in crate::root) self_broadcast_gas_payer_uuid: Option<Arc<str>>,
    pub(in crate::root) self_broadcast_gas_payer_select:
        Entity<SelectState<SearchableVec<SelfBroadcastGasPayerSelectItem>>>,
    pub(in crate::root) self_broadcast_gas_fee: Eip1559GasFeeEditorState,
    pub(in crate::root) self_broadcast_estimated_native_gas_cost: Option<U256>,
    pub(in crate::root) selected_fee_token: Address,
    pub(in crate::root) broadcaster_choice: BroadcasterChoice,
    pub(in crate::root) broadcaster_fee_mode: PublicBroadcasterFeeMode,
    pub(in crate::root) allow_suspicious_broadcasters: bool,
    pub(in crate::root) transaction_fee_breakdown_open: bool,
    pub(in crate::root) pending_programmatic_amount_input: Option<String>,
    pub(in crate::root) cost_estimate_pending: bool,
    pub(in crate::root) estimating_cost: bool,
    pub(in crate::root) cost_estimate: Option<PublicBroadcasterCostEstimate>,
    pub(in crate::root) estimate_id: u64,
    pub(in crate::root) generation_id: u64,
    pub(in crate::root) generating: bool,
    pub(in crate::root) generation_stage: TransactionGenerationStage,
    pub(in crate::root) error: Option<Arc<str>>,
    pub(in crate::root) result: Option<SendResult>,
}
