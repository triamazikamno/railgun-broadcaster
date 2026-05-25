use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::{Address, U256};
use gpui::{
    Animation, AnimationExt as _, App, AppContext, Context, ElementId, Entity, Focusable,
    InteractiveElement, IntoElement, MouseButton, ParentElement, Pixels, SharedString,
    StatefulInteractiveElement, Styled, Window, div, prelude::FluentBuilder as _, px, rgb,
};
use gpui_component::{
    Disableable, Icon, IconName, IndexPath, Selectable, Sizable, WindowExt,
    alert::Alert,
    button::{Button, ButtonGroup, ButtonVariants},
    input::{Input, InputEvent, InputState},
    popover::Popover,
    select::{SearchableVec, Select, SelectEvent, SelectItem, SelectState},
    spinner::Spinner,
};
use railgun_ui::short_address;
use rand::seq::IndexedRandom;
use tokio::sync::{mpsc, watch};
use ui::clipboard::clipboard_with_toast;
use ui::controls::{
    app_button, app_button_base, app_button_label, app_muted_text, app_strong_text,
};
use ui::theme::{self, APP_FONT_FAMILY, APP_TEXT_SIZE};
use wallet_ops::{
    DesktopSelfBroadcastResult, DesktopSendCalldataRequest, DesktopSendPublicBroadcasterRequest,
    DesktopSendSelfBroadcastRequest, DesktopUnshieldCalldataRequest,
    DesktopUnshieldPublicBroadcasterRequest, DesktopUnshieldSelfBroadcastRequest, ListUtxosOutput,
    PreparedSendCall, PreparedUnshieldCall, PublicAssetId, PublicBalanceAmount, PublicBalanceEntry,
    PublicBalanceSnapshot, PublicBroadcasterCandidate, PublicBroadcasterCostEstimate,
    PublicBroadcasterFeeMode, PublicBroadcasterResultKind, PublicBroadcasterSubmissionResult,
    SelfBroadcastGasFeeQuote, SelfBroadcastGasFeeSelection, SelfBroadcastSessionEvent,
    TransactionGenerationStage, fee_policy_eligible_public_broadcasters, parse_railgun_recipient,
    parse_send_amount, parse_unshield_amount, prepare_desktop_send_calldata,
    prepare_desktop_unshield_calldata, quote_desktop_self_broadcast_gas_fee,
    select_public_broadcaster_with_policy,
    settings::EffectiveTokenRegistry,
    sort_specific_public_broadcasters, submit_desktop_send_public_broadcaster,
    submit_desktop_send_self_broadcast, submit_desktop_unshield_public_broadcaster,
    submit_desktop_unshield_self_broadcast,
    vault::{PublicAccountMetadata, PublicAccountStatus},
};

use crate::assets::RailgunActionIcon;

use super::broadcaster_picker::{
    BroadcasterChoice, broadcaster_choice_supported_by_candidates,
    selected_broadcaster_fee_warning, selected_broadcaster_label,
    should_preserve_estimate_after_broadcaster_policy_change,
};
use super::gas_fee::{
    Eip1559GasFeeEditTarget, Eip1559GasFeeEditorState, Eip1559GasFeeMode, Eip1559GasFeeTarget,
    render_eip1559_gas_fee_editor,
};
use super::private_assets::refresh_form_asset_from_snapshot;
use super::private_broadcaster::{
    private_broadcaster_closed_active_progress, render_private_broadcaster_status_notice,
    render_private_self_broadcast_status_notice, render_private_submission_active_status_notice,
};
use super::public_account::public_account_display_label;
use super::public_balances::public_balance_entry_for_chain;
use super::public_broadcaster_cost::{
    cost_estimate_detail_text, public_broadcaster_cost_status,
    render_public_broadcaster_cost_estimate, render_public_broadcaster_cost_status,
    should_render_public_broadcaster_cost_preview,
};
use super::{
    ChainUtxoState, PRIVATE_ACTION_FORM_MAX_HEIGHT, PRIVATE_ASSET_LIST_WIDTH,
    PublicBroadcasterFeeTokenOption, WalletRoot, effective_public_broadcaster_fee_mode,
    format_exact_token_amount_for_display, format_report_chain, format_send_amount_input,
    format_unshield_amount_input, is_effective_wrapped_native_token, labeled_field,
    native_token_display_label, native_wrapped_output_labels, new_masked_input,
    new_prefilled_input, new_text_input, parse_address, public_balance_amount_label,
    public_broadcaster_fee_token_warning, public_broadcaster_submit_disabled_for_fee_token_options,
    send_form_max_entered_amount, should_show_broadcaster_fee_mode_toggle, token_label_row,
    unshield_form_max_entered_amount,
};

pub(super) const SEND_MISSING_PASSWORD_ERROR: &str =
    "Enter the vault password to prepare this send";
pub(super) const UNSHIELD_MISSING_PASSWORD_ERROR: &str =
    "Enter the vault password to prepare this unshield";
pub(super) const SEND_AUTHORIZATION_FAILED_ERROR: &str =
    "authorize public broadcaster send spend: unlock failed";
pub(super) const UNSHIELD_AUTHORIZATION_FAILED_ERROR: &str =
    "authorize public broadcaster unshield spend: unlock failed";
const SELF_BROADCAST_PRIVACY_WARNING: &str = "Self-broadcast links the selected Public account, RPC metadata, and transaction timing to this private action.";
const SELF_BROADCAST_ZERO_GAS_PAYER_WARNING: &str = "Selected gas payer has 0 native balance on this chain. Choose another Public account or fund this account before self-broadcasting.";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) enum DeliveryMode {
    ManualCalldata,
    #[default]
    PublicBroadcaster,
    SelfBroadcast,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DeliveryFormKind {
    Send,
    Unshield,
}

pub(super) struct PrivateActionFormState {
    pub(super) kind: DeliveryFormKind,
    pub(super) key: UnshieldAssetKey,
}

#[derive(Clone)]
pub(super) struct SelfBroadcastGasPayerSelectItem {
    public_account_uuid: Arc<str>,
    label: Arc<str>,
    address: Address,
    chain_id: u64,
    balance_label: Arc<str>,
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

pub(super) enum SendResult {
    Manual(PreparedSendCall),
    PublicBroadcaster(Box<PublicBroadcasterSubmissionResult>),
    SelfBroadcast(Box<DesktopSelfBroadcastResult>),
}

pub(super) enum UnshieldResult {
    Manual(PreparedUnshieldCall),
    PublicBroadcaster(Box<PublicBroadcasterSubmissionResult>),
    SelfBroadcast(Box<DesktopSelfBroadcastResult>),
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct UnshieldAsset {
    pub(super) chain_id: u64,
    pub(super) token: Address,
    pub(super) label: String,
    pub(super) decimals: Option<u8>,
    pub(super) total: U256,
    pub(super) poi_verified_total: U256,
    pub(super) max_batched: U256,
    pub(super) icon_path: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct UnshieldAssetKey {
    pub(super) chain_id: u64,
    pub(super) token: Address,
}

impl UnshieldAssetKey {
    pub(super) const fn new(chain_id: u64, token: Address) -> Self {
        Self { chain_id, token }
    }

    pub(super) const fn from_asset(asset: &UnshieldAsset) -> Self {
        Self::new(asset.chain_id, asset.token)
    }
}

pub(super) struct UnshieldFormState {
    pub(super) asset: UnshieldAsset,
    pub(super) recipient_input: Entity<InputState>,
    pub(super) amount_input: Entity<InputState>,
    pub(super) password_input: Entity<InputState>,
    pub(super) unwrap: bool,
    pub(super) delivery_mode: DeliveryMode,
    pub(super) self_broadcast_gas_payer_uuid: Option<Arc<str>>,
    pub(super) self_broadcast_gas_payer_select:
        Entity<SelectState<SearchableVec<SelfBroadcastGasPayerSelectItem>>>,
    pub(super) self_broadcast_gas_fee: Eip1559GasFeeEditorState,
    pub(super) self_broadcast_estimated_native_gas_cost: Option<U256>,
    pub(super) selected_fee_token: Address,
    pub(super) broadcaster_choice: BroadcasterChoice,
    pub(super) broadcaster_fee_mode: PublicBroadcasterFeeMode,
    pub(super) allow_suspicious_broadcasters: bool,
    pub(super) transaction_fee_breakdown_open: bool,
    pub(super) pending_programmatic_amount_input: Option<String>,
    pub(super) cost_estimate_pending: bool,
    pub(super) estimating_cost: bool,
    pub(super) cost_estimate: Option<PublicBroadcasterCostEstimate>,
    pub(super) estimate_id: u64,
    pub(super) generation_id: u64,
    pub(super) generating: bool,
    pub(super) generation_stage: TransactionGenerationStage,
    pub(super) error: Option<Arc<str>>,
    pub(super) result: Option<UnshieldResult>,
}

pub(super) struct SendFormState {
    pub(super) asset: UnshieldAsset,
    pub(super) recipient_input: Entity<InputState>,
    pub(super) amount_input: Entity<InputState>,
    pub(super) password_input: Entity<InputState>,
    pub(super) delivery_mode: DeliveryMode,
    pub(super) self_broadcast_gas_payer_uuid: Option<Arc<str>>,
    pub(super) self_broadcast_gas_payer_select:
        Entity<SelectState<SearchableVec<SelfBroadcastGasPayerSelectItem>>>,
    pub(super) self_broadcast_gas_fee: Eip1559GasFeeEditorState,
    pub(super) self_broadcast_estimated_native_gas_cost: Option<U256>,
    pub(super) selected_fee_token: Address,
    pub(super) broadcaster_choice: BroadcasterChoice,
    pub(super) broadcaster_fee_mode: PublicBroadcasterFeeMode,
    pub(super) allow_suspicious_broadcasters: bool,
    pub(super) transaction_fee_breakdown_open: bool,
    pub(super) pending_programmatic_amount_input: Option<String>,
    pub(super) cost_estimate_pending: bool,
    pub(super) estimating_cost: bool,
    pub(super) cost_estimate: Option<PublicBroadcasterCostEstimate>,
    pub(super) estimate_id: u64,
    pub(super) generation_id: u64,
    pub(super) generating: bool,
    pub(super) generation_stage: TransactionGenerationStage,
    pub(super) error: Option<Arc<str>>,
    pub(super) result: Option<SendResult>,
}

pub(super) fn private_action_input(state: &Entity<InputState>) -> Input {
    Input::new(state).px(px(12.0)).py(px(8.0))
}

pub(super) fn private_action_title_row(
    action: &'static str,
    label: &str,
    icon_path: Option<PathBuf>,
) -> gpui::Div {
    div()
        .flex()
        .items_center()
        .gap_1()
        .child(action)
        .child(token_label_row(
            SharedString::from(label.to_owned()),
            icon_path,
            px(20.0),
        ))
}

pub(super) fn send_element_id(key: UnshieldAssetKey, action: &str) -> SharedString {
    SharedString::from(format!(
        "wallet-send-{}-{}-{action}",
        key.chain_id,
        key.token.to_checksum(None)
    ))
}

pub(super) fn unshield_element_id(key: UnshieldAssetKey, action: &str) -> SharedString {
    SharedString::from(format!(
        "wallet-unshield-{}-{}-{action}",
        key.chain_id,
        key.token.to_checksum(None)
    ))
}

pub(super) fn delivery_element_id(
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    action: &str,
) -> SharedString {
    match kind {
        DeliveryFormKind::Send => send_element_id(key, action),
        DeliveryFormKind::Unshield => unshield_element_id(key, action),
    }
}

pub(super) fn format_form_error_for_asset(
    error: &str,
    asset: &UnshieldAsset,
    fee_token: Address,
    registry: Option<&EffectiveTokenRegistry>,
) -> String {
    if let Some(max_spendable) = form_error_public_broadcaster_fee_token_max_spendable(error) {
        return format!(
            "Broadcaster fee exceeds available fee-token balance: {}. Choose a fee token with more spendable balance or a lower-fee broadcaster.",
            format_exact_token_amount_for_display(
                asset.chain_id,
                fee_token,
                max_spendable,
                registry
            )
        );
    }

    if let Some(max_spendable) = form_error_public_broadcaster_max_entered_amount(error) {
        return format!(
            "Max POI-verified entered amount for public broadcaster: {}. Try a smaller amount or switch fee mode.",
            format_exact_asset_amount_for_display(max_spendable, asset)
        );
    }

    if let Some(max_spendable) = form_error_max_immediately_spendable(error) {
        return format!(
            "Amount exceeds max POI-verified amount for public broadcaster: {}. Try a smaller amount or switch fee mode.",
            format_exact_asset_amount_for_display(max_spendable, asset)
        );
    }

    match error {
        "entered amount must be greater than the broadcaster fee" => format!(
            "Entered amount must be greater than the broadcaster fee for {}. Choose add fee on top or enter a larger amount.",
            asset.label
        ),
        _ => error.to_string(),
    }
}

pub(super) fn format_exact_asset_amount_for_display(amount: U256, asset: &UnshieldAsset) -> String {
    asset.decimals.map_or_else(
        || format!("{amount} raw token units"),
        |decimals| {
            format!(
                "{} {}",
                format_send_amount_input(amount, Some(decimals)),
                asset.label
            )
        },
    )
}

pub(super) fn should_clear_private_action_error_on_password_change(
    kind: DeliveryFormKind,
    error: &str,
) -> bool {
    matches!(
        (kind, error),
        (
            DeliveryFormKind::Send,
            SEND_MISSING_PASSWORD_ERROR | SEND_AUTHORIZATION_FAILED_ERROR,
        ) | (
            DeliveryFormKind::Unshield,
            UNSHIELD_MISSING_PASSWORD_ERROR | UNSHIELD_AUTHORIZATION_FAILED_ERROR,
        )
    )
}

pub(super) fn form_error_clears_public_broadcaster_cost_estimate(
    kind: DeliveryFormKind,
    error: &str,
) -> bool {
    !should_clear_private_action_error_on_password_change(kind, error)
}

pub(super) fn send_public_broadcaster_estimate_input_error(
    recipient: &str,
    amount_raw: &str,
    asset: &UnshieldAsset,
) -> Option<String> {
    let recipient = recipient.trim();
    if !recipient.is_empty()
        && let Err(error) = parse_railgun_recipient(recipient)
    {
        return Some(error.to_string());
    }
    private_action_amount_input_error(amount_raw, asset, parse_send_amount)
}

pub(super) fn unshield_public_broadcaster_estimate_input_error(
    recipient: &str,
    amount_raw: &str,
    asset: &UnshieldAsset,
) -> Option<String> {
    let recipient = recipient.trim();
    if !recipient.is_empty() && recipient.parse::<Address>().is_err() {
        return Some("Enter a valid public EVM recipient address".to_string());
    }
    private_action_amount_input_error(amount_raw, asset, parse_unshield_amount)
}

fn private_action_amount_input_error(
    amount_raw: &str,
    asset: &UnshieldAsset,
    parse_amount: fn(&str, Option<u8>) -> Result<U256, eyre::Report>,
) -> Option<String> {
    match parse_amount(amount_raw, asset.decimals) {
        Ok(amount) if amount.is_zero() => Some("Enter an amount greater than zero".to_string()),
        Ok(amount) if amount > asset.max_batched => Some(format!(
            "Amount exceeds max POI-verified batched transaction: {}",
            format_send_amount_input(asset.max_batched, asset.decimals)
        )),
        Ok(_) => None,
        Err(error) => Some(error.to_string()),
    }
}

pub(super) fn form_error_public_broadcaster_max_entered_amount(error: &str) -> Option<U256> {
    const MARKER: &str = "public broadcaster max entered amount: ";
    form_error_decimal_after_marker(error, MARKER)
}

fn form_error_public_broadcaster_fee_token_max_spendable(error: &str) -> Option<U256> {
    const MARKER: &str = "public broadcaster fee-token max spendable: ";
    form_error_decimal_after_marker(error, MARKER)
}

fn form_error_max_immediately_spendable(error: &str) -> Option<U256> {
    const MARKER: &str = "max immediately spendable: ";
    form_error_decimal_after_marker(error, MARKER)
}

fn form_error_decimal_after_marker(error: &str, marker: &str) -> Option<U256> {
    let start = error.find(marker)? + marker.len();
    let digits = error[start..]
        .trim_start()
        .split(|ch: char| !ch.is_ascii_digit())
        .next()?;
    if digits.is_empty() {
        return None;
    }
    U256::from_str_radix(digits, 10).ok()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PrivateActionMetric {
    pub(super) label: &'static str,
    pub(super) amount: U256,
}

pub(super) fn private_action_metrics(asset: &UnshieldAsset) -> Vec<PrivateActionMetric> {
    let mut metrics = vec![PrivateActionMetric {
        label: "Total private balance",
        amount: asset.total,
    }];
    if asset.poi_verified_total != asset.total {
        metrics.push(PrivateActionMetric {
            label: "POI-verified balance",
            amount: asset.poi_verified_total,
        });
    }
    if asset.max_batched != asset.total {
        metrics.push(PrivateActionMetric {
            label: "Max batched transaction",
            amount: asset.max_batched,
        });
    }
    metrics
}

impl WalletRoot {
    pub(super) fn apply_public_broadcaster_error_amount_adjustments(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let mut reschedule = Vec::new();

        for (key, form) in &mut self.send_forms {
            if form.delivery_mode != DeliveryMode::PublicBroadcaster || form.generating {
                continue;
            }
            let Some(max_entered_amount) = form
                .error
                .as_deref()
                .and_then(form_error_public_broadcaster_max_entered_amount)
            else {
                continue;
            };
            if let Some(adjusted) = amount_adjustment_for_max_change(
                &form.amount_input,
                &form.asset,
                None,
                Some(max_entered_amount),
                cx,
            ) {
                form.pending_programmatic_amount_input = Some(adjusted.clone());
                form.amount_input
                    .update(cx, |input, cx| input.set_value(adjusted, window, cx));
                form.error = None;
                form.estimate_id = 0;
                form.cost_estimate_pending = false;
                form.estimating_cost = false;
                reschedule.push((DeliveryFormKind::Send, *key));
            }
        }

        for (key, form) in &mut self.unshield_forms {
            if form.delivery_mode != DeliveryMode::PublicBroadcaster || form.generating {
                continue;
            }
            let Some(max_entered_amount) = form
                .error
                .as_deref()
                .and_then(form_error_public_broadcaster_max_entered_amount)
            else {
                continue;
            };
            if let Some(adjusted) = amount_adjustment_for_max_change(
                &form.amount_input,
                &form.asset,
                None,
                Some(max_entered_amount),
                cx,
            ) {
                form.pending_programmatic_amount_input = Some(adjusted.clone());
                form.amount_input
                    .update(cx, |input, cx| input.set_value(adjusted, window, cx));
                form.error = None;
                form.estimate_id = 0;
                form.cost_estimate_pending = false;
                form.estimating_cost = false;
                reschedule.push((DeliveryFormKind::Unshield, *key));
            }
        }

        for (kind, key) in reschedule {
            self.schedule_public_broadcaster_cost_estimate(kind, key, cx);
        }
    }

    pub(super) fn refresh_open_form_assets_for_snapshot(
        &mut self,
        snapshot: &ListUtxosOutput,
        cx: &mut Context<'_, Self>,
    ) {
        let mut reschedule_estimates = Vec::new();
        for (key, form) in &mut self.send_forms {
            if key.chain_id != snapshot.chain_id {
                continue;
            }
            let updated = refresh_form_asset_from_snapshot(
                snapshot,
                &form.asset,
                true,
                Some(&self.effective_token_registry),
            );
            if form.asset == updated {
                continue;
            }
            form.asset = updated;
            if form.delivery_mode == DeliveryMode::PublicBroadcaster && !form.generating {
                form.cost_estimate = None;
                form.estimate_id = 0;
                form.cost_estimate_pending = false;
                form.estimating_cost = false;
                reschedule_estimates.push((DeliveryFormKind::Send, *key));
            }
        }
        for (key, form) in &mut self.unshield_forms {
            if key.chain_id != snapshot.chain_id {
                continue;
            }
            let updated = refresh_form_asset_from_snapshot(
                snapshot,
                &form.asset,
                false,
                Some(&self.effective_token_registry),
            );
            if form.asset == updated {
                continue;
            }
            form.asset = updated;
            if form.delivery_mode == DeliveryMode::PublicBroadcaster && !form.generating {
                form.cost_estimate = None;
                form.estimate_id = 0;
                form.cost_estimate_pending = false;
                form.estimating_cost = false;
                reschedule_estimates.push((DeliveryFormKind::Unshield, *key));
            }
        }
        for (kind, key) in reschedule_estimates {
            self.schedule_public_broadcaster_cost_estimate(kind, key, cx);
        }
    }
}

pub(super) fn adjusted_amount_for_max_change(
    current_amount: U256,
    old_max: Option<U256>,
    new_max: U256,
) -> Option<U256> {
    if current_amount > new_max {
        return Some(new_max);
    }
    if let Some(old_max) = old_max
        && current_amount == old_max
        && new_max > old_max
    {
        return Some(new_max);
    }
    None
}

fn amount_adjustment_for_max_change(
    input: &Entity<InputState>,
    asset: &UnshieldAsset,
    old_max: Option<U256>,
    new_max: Option<U256>,
    cx: &Context<'_, WalletRoot>,
) -> Option<String> {
    let new_max = new_max?;
    let current_value = input.read(cx).value().to_string();
    let Ok(current_amount) = parse_send_amount(current_value.as_str(), asset.decimals) else {
        return None;
    };
    let adjusted_amount = adjusted_amount_for_max_change(current_amount, old_max, new_max)?;
    Some(format_send_amount_input(adjusted_amount, asset.decimals))
}

pub(super) fn render_private_action_metrics(
    root: Entity<WalletRoot>,
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    asset: &UnshieldAsset,
    disabled: bool,
) -> gpui::Div {
    let decimals = asset.decimals;
    div().w_full().flex().flex_wrap().gap_2().children(
        private_action_metrics(asset)
            .into_iter()
            .map(move |metric| {
                render_private_action_metric(
                    root.clone(),
                    key,
                    kind,
                    delivery_element_id(key, kind, private_action_metric_id_suffix(metric.label)),
                    metric,
                    decimals,
                    disabled,
                )
            }),
    )
}

fn render_private_action_metric(
    root: Entity<WalletRoot>,
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    id: SharedString,
    metric: PrivateActionMetric,
    decimals: Option<u8>,
    disabled: bool,
) -> impl IntoElement {
    let value = format_unshield_amount_input(metric.amount, decimals);
    div()
        .id(id)
        .flex_1()
        .min_w(px(280.0))
        .px(px(12.0))
        .py(px(10.0))
        .rounded_md()
        .bg(rgb(theme::SURFACE_ELEVATED))
        .border_1()
        .border_color(rgb(theme::BORDER))
        .flex()
        .items_center()
        .justify_between()
        .gap_2()
        .when(!disabled, |this| {
            this.cursor_pointer()
                .hover(|this| this.bg(rgb(theme::SURFACE_HOVER)))
                .on_click(move |_event, window, cx| {
                    let amount = metric.amount;
                    root.update(cx, |root, cx| {
                        root.set_private_action_metric_amount(kind, key, amount, window, cx);
                    });
                })
        })
        .child(app_muted_text(metric.label).whitespace_nowrap().flex_none())
        .child(
            div()
                .flex_none()
                .whitespace_nowrap()
                .text_color(rgb(theme::WARNING))
                .font_weight(gpui::FontWeight::SEMIBOLD)
                .child(SharedString::from(value)),
        )
}

fn private_action_metric_id_suffix(label: &'static str) -> &'static str {
    match label {
        "Total private balance" => "metric-total",
        "POI-verified balance" => "metric-poi-verified",
        "Max batched transaction" => "metric-max-batched",
        _ => "metric",
    }
}

pub(super) fn render_unshield_generating_status(
    _tick: usize,
    stage: TransactionGenerationStage,
) -> gpui::Div {
    div()
        .flex()
        .items_center()
        .gap_3()
        .p(px(10.0))
        .rounded_md()
        .bg(rgb(theme::SURFACE_ELEVATED))
        .border_1()
        .border_color(rgb(theme::INFO))
        .child(
            Spinner::new()
                .icon(IconName::LoaderCircle)
                .color(rgb(theme::INFO).into())
                .with_size(px(18.0)),
        )
        .child(
            div()
                .flex()
                .flex_col()
                .gap_1()
                .child(
                    div()
                        .text_color(rgb(theme::TEXT))
                        .font_weight(gpui::FontWeight::SEMIBOLD)
                        .child(stage.label()),
                )
                .child(app_muted_text(stage.detail())),
        )
}

impl WalletRoot {
    fn active_self_broadcast_gas_payer_accounts(&self) -> Vec<PublicAccountMetadata> {
        self.public_accounts
            .iter()
            .filter(|account| account.status == PublicAccountStatus::Active)
            .cloned()
            .collect()
    }

    fn default_self_broadcast_gas_payer_uuid(&self) -> Option<Arc<str>> {
        default_self_broadcast_gas_payer_uuid(&self.active_self_broadcast_gas_payer_accounts())
    }

    fn new_self_broadcast_gas_payer_select(
        &self,
        chain_id: u64,
        selected_uuid: Option<&str>,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) -> Entity<SelectState<SearchableVec<SelfBroadcastGasPayerSelectItem>>> {
        let accounts = self.active_self_broadcast_gas_payer_accounts();
        let items = self_broadcast_gas_payer_select_items(
            &accounts,
            chain_id,
            self.public_balance_snapshot.as_deref(),
        );
        let selected_index = self_broadcast_gas_payer_select_index(&items, selected_uuid);
        cx.new(|cx| {
            SelectState::new(SearchableVec::new(items), selected_index, window, cx).searchable(true)
        })
    }

    pub(super) fn sync_self_broadcast_gas_payer_selects(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let accounts = self.active_self_broadcast_gas_payer_accounts();
        let snapshot = self.public_balance_snapshot.clone();
        for form in self.send_forms.values_mut() {
            let selected = normalized_self_broadcast_gas_payer_uuid(
                form.self_broadcast_gas_payer_uuid.as_ref(),
                &accounts,
            );
            form.self_broadcast_gas_payer_uuid.clone_from(&selected);
            sync_self_broadcast_gas_payer_select_entity(
                &form.self_broadcast_gas_payer_select,
                &accounts,
                form.asset.chain_id,
                snapshot.as_deref(),
                selected.as_ref(),
                window,
                cx,
            );
        }
        for form in self.unshield_forms.values_mut() {
            let selected = normalized_self_broadcast_gas_payer_uuid(
                form.self_broadcast_gas_payer_uuid.as_ref(),
                &accounts,
            );
            form.self_broadcast_gas_payer_uuid.clone_from(&selected);
            sync_self_broadcast_gas_payer_select_entity(
                &form.self_broadcast_gas_payer_select,
                &accounts,
                form.asset.chain_id,
                snapshot.as_deref(),
                selected.as_ref(),
                window,
                cx,
            );
        }
    }

    fn sync_self_broadcast_gas_payer_select(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let accounts = self.active_self_broadcast_gas_payer_accounts();
        let snapshot = self.public_balance_snapshot.clone();
        match kind {
            DeliveryFormKind::Send => {
                let Some(form) = self.send_forms.get_mut(&key) else {
                    return;
                };
                sync_self_broadcast_gas_payer_select_entity(
                    &form.self_broadcast_gas_payer_select,
                    &accounts,
                    form.asset.chain_id,
                    snapshot.as_deref(),
                    form.self_broadcast_gas_payer_uuid.as_ref(),
                    window,
                    cx,
                );
            }
            DeliveryFormKind::Unshield => {
                let Some(form) = self.unshield_forms.get_mut(&key) else {
                    return;
                };
                sync_self_broadcast_gas_payer_select_entity(
                    &form.self_broadcast_gas_payer_select,
                    &accounts,
                    form.asset.chain_id,
                    snapshot.as_deref(),
                    form.self_broadcast_gas_payer_uuid.as_ref(),
                    window,
                    cx,
                );
            }
        }
    }

    fn selected_self_broadcast_gas_payer_account(
        &self,
        selected_uuid: Option<&str>,
    ) -> Option<&PublicAccountMetadata> {
        let selected_uuid = selected_uuid?;
        self.public_accounts.iter().find(|account| {
            account.status == PublicAccountStatus::Active
                && account.public_account_uuid == selected_uuid
        })
    }
}

pub(super) fn default_self_broadcast_gas_payer_uuid(
    accounts: &[PublicAccountMetadata],
) -> Option<Arc<str>> {
    (accounts.len() == 1).then(|| Arc::from(accounts[0].public_account_uuid.as_str()))
}

#[cfg(test)]
pub(super) fn self_broadcast_gas_payer_matches_search(
    account: &PublicAccountMetadata,
    query: &str,
) -> bool {
    self_broadcast_gas_payer_fields_match(
        public_account_display_label(account).as_deref(),
        &account.address,
        query,
    )
}

fn self_broadcast_gas_payer_fields_match(
    label: Option<&str>,
    address: &Address,
    query: &str,
) -> bool {
    let query = query.trim().to_ascii_lowercase();
    if query.is_empty() {
        return true;
    }
    let full_address = address.to_checksum(None).to_ascii_lowercase();
    let lower_hex_address = format!("{address:#x}");
    let short = short_address(address).to_ascii_lowercase();
    label.is_some_and(|label| label.to_ascii_lowercase().contains(&query))
        || full_address.contains(&query)
        || lower_hex_address.contains(&query)
        || short.contains(&query)
}

fn self_broadcast_gas_payer_label(account: &PublicAccountMetadata) -> String {
    public_account_display_label(account).unwrap_or_else(|| short_address(&account.address))
}

fn self_broadcast_native_balance_entry(
    snapshot: Option<&PublicBalanceSnapshot>,
    chain_id: u64,
    public_account_uuid: &str,
) -> Option<PublicBalanceEntry> {
    public_balance_entry_for_chain(
        snapshot,
        chain_id,
        public_account_uuid,
        PublicAssetId::Native,
        PublicAccountStatus::Active,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SelfBroadcastNativeBalanceState {
    Unknown,
    Zero,
    Positive,
}

pub(super) fn self_broadcast_native_balance_state(
    snapshot: Option<&PublicBalanceSnapshot>,
    chain_id: u64,
    public_account_uuid: &str,
) -> SelfBroadcastNativeBalanceState {
    match self_broadcast_native_balance_entry(snapshot, chain_id, public_account_uuid)
        .map(|entry| entry.amount)
    {
        Some(PublicBalanceAmount::Available(amount)) if amount.is_zero() => {
            SelfBroadcastNativeBalanceState::Zero
        }
        Some(PublicBalanceAmount::Available(_)) => SelfBroadcastNativeBalanceState::Positive,
        Some(PublicBalanceAmount::Unavailable) | None => SelfBroadcastNativeBalanceState::Unknown,
    }
}

pub(super) fn self_broadcast_native_balance_label(
    snapshot: Option<&PublicBalanceSnapshot>,
    chain_id: u64,
    public_account_uuid: &str,
) -> String {
    self_broadcast_native_balance_entry(snapshot, chain_id, public_account_uuid).map_or_else(
        || "unavailable".to_string(),
        |entry| public_balance_amount_label(&entry.amount, entry.asset.decimals),
    )
}

pub(super) fn random_self_broadcast_gas_payer_uuid(
    accounts: &[PublicAccountMetadata],
    selected_uuid: Option<&str>,
    chain_id: u64,
    snapshot: Option<&PublicBalanceSnapshot>,
) -> Option<Arc<str>> {
    let candidates = accounts
        .iter()
        .filter(|account| {
            self_broadcast_gas_payer_random_candidate(account, selected_uuid, chain_id, snapshot)
        })
        .collect::<Vec<_>>();
    candidates
        .choose(&mut rand::rng())
        .map(|account| Arc::from(account.public_account_uuid.as_str()))
}

fn self_broadcast_initial_gas_values(
    selection: &SelfBroadcastGasFeeSelection,
    quote: Option<SelfBroadcastGasFeeQuote>,
) -> Option<(u128, u128)> {
    match *selection {
        SelfBroadcastGasFeeSelection::Auto => quote.map(|quote| {
            (
                quote.suggested_max_fee_per_gas,
                quote.suggested_max_priority_fee_per_gas,
            )
        }),
        SelfBroadcastGasFeeSelection::Custom {
            max_fee_per_gas,
            max_priority_fee_per_gas,
        } => Some((max_fee_per_gas, max_priority_fee_per_gas)),
    }
}

fn self_broadcast_gas_payer_random_candidate(
    account: &PublicAccountMetadata,
    selected_uuid: Option<&str>,
    chain_id: u64,
    snapshot: Option<&PublicBalanceSnapshot>,
) -> bool {
    Some(account.public_account_uuid.as_str()) != selected_uuid
        && self_broadcast_native_balance_state(snapshot, chain_id, &account.public_account_uuid)
            != SelfBroadcastNativeBalanceState::Zero
}

fn normalized_self_broadcast_gas_payer_uuid(
    selected_uuid: Option<&Arc<str>>,
    accounts: &[PublicAccountMetadata],
) -> Option<Arc<str>> {
    selected_uuid
        .filter(|uuid| {
            accounts
                .iter()
                .any(|account| account.public_account_uuid.as_str() == uuid.as_ref())
        })
        .cloned()
        .or_else(|| default_self_broadcast_gas_payer_uuid(accounts))
}

fn self_broadcast_gas_payer_select_items(
    accounts: &[PublicAccountMetadata],
    chain_id: u64,
    snapshot: Option<&PublicBalanceSnapshot>,
) -> Vec<SelfBroadcastGasPayerSelectItem> {
    accounts
        .iter()
        .map(|account| SelfBroadcastGasPayerSelectItem {
            public_account_uuid: Arc::from(account.public_account_uuid.as_str()),
            label: Arc::from(self_broadcast_gas_payer_label(account)),
            address: account.address,
            chain_id,
            balance_label: Arc::from(self_broadcast_native_balance_label(
                snapshot,
                chain_id,
                &account.public_account_uuid,
            )),
        })
        .collect()
}

fn self_broadcast_gas_payer_select_index(
    items: &[SelfBroadcastGasPayerSelectItem],
    selected_uuid: Option<&str>,
) -> Option<IndexPath> {
    let selected_uuid = selected_uuid?;
    items
        .iter()
        .position(|item| item.public_account_uuid.as_ref() == selected_uuid)
        .map(|index| IndexPath::default().row(index))
}

fn sync_self_broadcast_gas_payer_select_entity(
    select: &Entity<SelectState<SearchableVec<SelfBroadcastGasPayerSelectItem>>>,
    accounts: &[PublicAccountMetadata],
    chain_id: u64,
    snapshot: Option<&PublicBalanceSnapshot>,
    selected_uuid: Option<&Arc<str>>,
    window: &mut Window,
    cx: &mut Context<'_, WalletRoot>,
) {
    let items = self_broadcast_gas_payer_select_items(accounts, chain_id, snapshot);
    select.update(cx, |select, cx| {
        select.set_items(SearchableVec::new(items), window, cx);
        if let Some(uuid) = selected_uuid {
            select.set_selected_value(uuid, window, cx);
        } else {
            select.set_selected_index(None, window, cx);
        }
    });
}

pub(super) fn render_delivery_selector(
    root: Entity<WalletRoot>,
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    mode: DeliveryMode,
    generating: bool,
    self_broadcast_available: bool,
) -> gpui::Div {
    let selector_root = root;
    div().flex().flex_col().gap_2().child(
        ButtonGroup::new(delivery_element_id(key, kind, "mode-toggle"))
            .w_full()
            .children([
                private_action_segment_button(
                    delivery_element_id(key, kind, "public"),
                    "Public broadcaster",
                    mode == DeliveryMode::PublicBroadcaster,
                )
                .disabled(generating),
                private_action_segment_button_with_accessory(
                    delivery_element_id(key, kind, "self"),
                    "Self-broadcast",
                    mode == DeliveryMode::SelfBroadcast,
                    Some(render_self_broadcast_privacy_icon(
                        delivery_element_id(key, kind, "self-privacy-warning"),
                        mode == DeliveryMode::SelfBroadcast,
                    )),
                )
                .disabled(generating || !self_broadcast_available),
                private_action_segment_button(
                    delivery_element_id(key, kind, "manual"),
                    "Manual calldata",
                    mode == DeliveryMode::ManualCalldata,
                )
                .disabled(generating),
            ])
            .on_click(move |selected, window, cx| {
                let Some(index) = selected.first() else {
                    return;
                };
                let mode = match *index {
                    0 => DeliveryMode::PublicBroadcaster,
                    1 => DeliveryMode::SelfBroadcast,
                    2 => DeliveryMode::ManualCalldata,
                    _ => return,
                };
                selector_root.update(cx, |root, cx| match kind {
                    DeliveryFormKind::Send => {
                        root.set_send_delivery_mode(key, mode, window, cx);
                    }
                    DeliveryFormKind::Unshield => {
                        root.set_unshield_delivery_mode(key, mode, window, cx);
                    }
                });
            }),
    )
}

pub(super) fn render_public_broadcaster_settings(
    root: Entity<WalletRoot>,
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    allow_suspicious_broadcasters: bool,
    action_token: Address,
    broadcaster_fee_mode: PublicBroadcasterFeeMode,
    choice: &BroadcasterChoice,
    candidates: Vec<PublicBroadcasterCandidate>,
    fee_token_options: &[PublicBroadcasterFeeTokenOption],
    selected_fee_token: Address,
    generating: bool,
) -> gpui::Div {
    let fee_token_root = root.clone();
    let fee_mode_root = root.clone();
    let random_root = root.clone();
    let modal_root = root.clone();
    let policy_label_root = root.clone();
    let policy_switch_root = root;
    let sorted = sort_specific_public_broadcasters(candidates);
    let specific_label = selected_broadcaster_label(choice, &sorted);
    let random_selected = matches!(choice, BroadcasterChoice::Random);
    let specific_selected = matches!(choice, BroadcasterChoice::Specific { .. });
    let selector_disabled = generating || sorted.is_empty();
    let random_button = app_button(
        delivery_element_id(key, kind, "random"),
        "Random broadcaster",
    )
    .flex_1()
    .min_w(px(0.0))
    .selected(random_selected)
    .disabled(selector_disabled);
    let random_button = if random_selected {
        random_button.primary()
    } else {
        random_button
    };
    let specific_button = app_button(
        delivery_element_id(key, kind, "choose-specific"),
        specific_label,
    )
    .flex_1()
    .min_w(px(0.0))
    .selected(specific_selected)
    .disabled(selector_disabled);
    let specific_button = if specific_selected {
        specific_button.primary()
    } else {
        specific_button
    };

    let settings = div()
        .flex()
        .flex_col()
        .gap_2()
        .p(px(10.0))
        .rounded_md()
        .border_1()
        .border_color(rgb(theme::BORDER))
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .gap_3()
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .gap_1()
                        .child(app_muted_text("Allow suspicious broadcasters"))
                        .child(cost_estimate_detail_text(
                            "Suspicious broadcasters advertise fees outside the anchor range.",
                        ))
                        .when(!generating, |this| {
                            this.on_mouse_down(MouseButton::Left, move |_, _window, cx| {
                                cx.stop_propagation();
                                policy_label_root.update(cx, |root, cx| {
                                    root.set_allow_suspicious_broadcasters(
                                        kind,
                                        key,
                                        !allow_suspicious_broadcasters,
                                        cx,
                                    );
                                });
                            })
                        }),
                )
                .child(render_danger_switch(
                    delivery_element_id(key, kind, "allow-suspicious-broadcasters"),
                    allow_suspicious_broadcasters,
                    generating,
                    move |checked, _window, cx| {
                        policy_switch_root.update(cx, |root, cx| {
                            root.set_allow_suspicious_broadcasters(kind, key, checked, cx);
                        });
                    },
                )),
        )
        .child(render_fee_token_selector(
            fee_token_root,
            key,
            kind,
            fee_token_options,
            selected_fee_token,
            generating,
        ))
        .child(
            ButtonGroup::new(delivery_element_id(key, kind, "broadcaster-choice-toggle"))
                .w_full()
                .disabled(selector_disabled)
                .child(random_button)
                .child(specific_button)
                .on_click(move |selected, window, cx| {
                    let Some(index) = selected.first() else {
                        return;
                    };
                    if *index == 0 {
                        random_root.update(cx, |root, cx| match kind {
                            DeliveryFormKind::Send => {
                                root.set_send_broadcaster_choice(
                                    key,
                                    BroadcasterChoice::Random,
                                    cx,
                                );
                            }
                            DeliveryFormKind::Unshield => {
                                root.set_unshield_broadcaster_choice(
                                    key,
                                    BroadcasterChoice::Random,
                                    cx,
                                );
                            }
                        });
                    } else {
                        modal_root.update(cx, |root, cx| {
                            root.open_broadcaster_picker(kind, key, window, cx);
                        });
                    }
                }),
        )
        .when(
            should_show_broadcaster_fee_mode_toggle(action_token, selected_fee_token),
            |settings| {
                settings.child(render_broadcaster_fee_mode_toggle(
                    fee_mode_root,
                    key,
                    kind,
                    broadcaster_fee_mode,
                    generating,
                ))
            },
        );

    if sorted.is_empty() {
        return settings.child(app_muted_text(
            "No eligible broadcaster currently advertises this token.",
        ));
    }
    settings
}

pub(super) fn render_self_broadcast_settings(
    root: Entity<WalletRoot>,
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    accounts: &[PublicAccountMetadata],
    selected_uuid: Option<&str>,
    balance_snapshot: Option<&PublicBalanceSnapshot>,
    gas_payer_select: &Entity<SelectState<SearchableVec<SelfBroadcastGasPayerSelectItem>>>,
    gas_fee: &Eip1559GasFeeEditorState,
    generating: bool,
) -> gpui::Div {
    let random_root = root.clone();
    let gas_fee_root = root;
    let selected_uuid = selected_uuid.map(str::to_owned);
    let selected_account = selected_uuid.as_deref().and_then(|uuid| {
        accounts
            .iter()
            .find(|account| account.public_account_uuid == uuid)
    });
    let random_disabled = generating
        || !accounts.iter().any(|account| {
            self_broadcast_gas_payer_random_candidate(
                account,
                selected_uuid.as_deref(),
                key.chain_id,
                balance_snapshot,
            )
        });
    let missing_selection = !accounts.is_empty() && selected_account.is_none();
    let selected_zero_balance = selected_uuid.as_deref().is_some_and(|uuid| {
        self_broadcast_native_balance_state(balance_snapshot, key.chain_id, uuid)
            == SelfBroadcastNativeBalanceState::Zero
    });

    div()
        .flex()
        .flex_col()
        .gap_2()
        .p(px(10.0))
        .rounded_md()
        .border_1()
        .border_color(rgb(theme::BORDER))
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .gap_3()
                .child(
                    div().min_w(px(0.0)).flex().flex_col().gap_1().child(
                        div()
                            .flex()
                            .items_center()
                            .gap_1()
                            .child(app_muted_text("Gas payer"))
                            .when(selected_zero_balance, |this| {
                                this.child(render_self_broadcast_gas_payer_warning_icon(
                                    delivery_element_id(key, kind, "zero-gas-payer-warning"),
                                ))
                            }),
                    ),
                )
                .child(
                    div()
                        .flex_none()
                        .flex()
                        .items_center()
                        .gap_2()
                        .child(
                            app_button_base(delivery_element_id(key, kind, "random-gas-payer"))
                                .icon(Icon::new(RailgunActionIcon::Dices))
                                .ghost()
                                .small()
                                .compact()
                                .tooltip("Choose random gas payer")
                                .disabled(random_disabled)
                                .on_click(move |_event, window, cx| {
                                    random_root.update(cx, |root, cx| {
                                        root.choose_random_self_broadcast_gas_payer(
                                            kind, key, window, cx,
                                        );
                                    });
                                }),
                        )
                        .child(
                            div().w(px(320.0)).h(px(32.0)).child(
                                Select::new(gas_payer_select)
                                    .small()
                                    .w_full()
                                    .h(px(32.0))
                                    .placeholder(if missing_selection {
                                        "Gas payer required"
                                    } else {
                                        "Please select"
                                    })
                                    .menu_width(px(380.0))
                                    .when(missing_selection || selected_zero_balance, |this| {
                                        this.border_color(rgb(theme::WARNING))
                                    })
                                    .disabled(generating || accounts.is_empty()),
                            ),
                        ),
                ),
        )
        .when(accounts.is_empty(), |this| {
            this.child(app_muted_text(
                "No active Public accounts are available for self-broadcast gas payment.",
            ))
        })
        .child(render_eip1559_gas_fee_editor(
            gas_fee_root,
            Eip1559GasFeeTarget::Private { key, kind },
            gas_fee,
            generating,
        ))
}

fn self_broadcast_gas_payer_select_trigger_row(label: &str, address: &Address) -> gpui::Div {
    div()
        .flex()
        .items_center()
        .gap_1()
        .child(SharedString::from(label.to_string()))
        .child(
            app_muted_text(short_address(address))
                .font_family(APP_FONT_FAMILY)
                .text_size(px(12.0)),
        )
}

fn self_broadcast_gas_payer_select_menu_row(
    label: &str,
    address: &Address,
    chain_id: u64,
    balance: &str,
) -> gpui::Div {
    div()
        .flex()
        .items_center()
        .justify_between()
        .gap_3()
        .child(
            div()
                .min_w(px(0.0))
                .flex()
                .flex_col()
                .gap_1()
                .child(app_strong_text(label.to_string()))
                .child(
                    app_muted_text(short_address(address))
                        .font_family(APP_FONT_FAMILY)
                        .text_color(rgb(theme::TEXT_MUTED)),
                ),
        )
        .child(
            app_muted_text(format!(
                "{balance} {}",
                native_token_display_label(chain_id)
            ))
            .text_color(rgb(theme::TEXT_MUTED)),
        )
}

fn render_danger_switch(
    id: SharedString,
    checked: bool,
    disabled: bool,
    on_toggle: impl Fn(bool, &mut Window, &mut App) + 'static,
) -> impl IntoElement {
    let track_width = px(36.0);
    let track_height = px(20.0);
    let thumb_size = px(16.0);
    let inset = px(2.0);
    let max_x = track_width - thumb_size - inset * 2.0;
    let thumb_x = if checked { max_x } else { px(0.0) };
    let track_color = if checked {
        theme::DANGER
    } else {
        theme::SURFACE_HOVER
    };
    let thumb_color = if checked {
        theme::SURFACE
    } else {
        theme::TEXT_MUTED
    };

    div()
        .id(id)
        .w(track_width)
        .h(track_height)
        .flex()
        .items_center()
        .p(inset)
        .rounded_full()
        .bg(rgb(track_color))
        .opacity(if disabled { 0.5 } else { 1.0 })
        .when(!disabled, |this| {
            this.on_mouse_down(MouseButton::Left, move |_, window, cx| {
                cx.stop_propagation();
                on_toggle(!checked, window, cx);
            })
        })
        .child(
            div()
                .size(thumb_size)
                .rounded_full()
                .bg(rgb(thumb_color))
                .left(thumb_x)
                .with_animation(
                    ElementId::NamedInteger("danger-switch-thumb".into(), u64::from(checked)),
                    Animation::new(Duration::from_secs_f64(0.15)),
                    move |this, delta| {
                        let x = if checked {
                            max_x * delta
                        } else {
                            max_x - max_x * delta
                        };
                        this.left(x)
                    },
                ),
        )
}

pub(super) fn render_unshield_output_toggle(
    root: Entity<WalletRoot>,
    key: UnshieldAssetKey,
    chain_id: u64,
    unwrap: bool,
    generating: bool,
) -> gpui::Div {
    let Some((native_label, wrapped_label)) = native_wrapped_output_labels(chain_id) else {
        return div();
    };
    div()
        .flex()
        .flex_col()
        .gap_1()
        .child(app_muted_text("Output"))
        .child(
            ButtonGroup::new(unshield_element_id(key, "output-toggle"))
                .outline()
                .disabled(generating)
                .child(
                    app_button(unshield_element_id(key, "output-native"), native_label)
                        .selected(unwrap)
                        .disabled(generating),
                )
                .child(
                    app_button(unshield_element_id(key, "output-wrapped"), wrapped_label)
                        .selected(!unwrap)
                        .disabled(generating),
                )
                .on_click(move |selected, _window, cx| {
                    let Some(index) = selected.first() else {
                        return;
                    };
                    let unwrap = *index == 0;
                    root.update(cx, |root, cx| {
                        root.set_unshield_unwrap(key, unwrap, cx);
                    });
                }),
        )
}

impl WalletRoot {
    fn close_send_form(&mut self, key: UnshieldAssetKey, cx: &mut Context<'_, Self>) {
        self.send_forms.remove(&key);
        if self
            .private_action_form
            .as_ref()
            .is_some_and(|form| form.kind == DeliveryFormKind::Send && form.key == key)
        {
            self.private_action_form = None;
            self.broadcaster_picker = None;
        }
        if self
            .private_broadcaster_progress
            .as_ref()
            .is_some_and(|progress| progress.kind == DeliveryFormKind::Send && progress.key == key)
        {
            self.private_broadcaster_progress = None;
        }
        cx.notify();
    }

    fn close_unshield_form(&mut self, key: UnshieldAssetKey, cx: &mut Context<'_, Self>) {
        self.unshield_forms.remove(&key);
        if self
            .private_action_form
            .as_ref()
            .is_some_and(|form| form.kind == DeliveryFormKind::Unshield && form.key == key)
        {
            self.private_action_form = None;
            self.broadcaster_picker = None;
        }
        if self
            .private_broadcaster_progress
            .as_ref()
            .is_some_and(|progress| {
                progress.kind == DeliveryFormKind::Unshield && progress.key == key
            })
        {
            self.private_broadcaster_progress = None;
        }
        cx.notify();
    }

    fn open_private_action_dialog(
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        title_action: &'static str,
        asset_label: String,
        icon_path: Option<PathBuf>,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let root = cx.entity();
        window.open_dialog(cx, move |dialog, window, cx| {
            let dialog_width = (window.viewport_size().width * 0.92).min(PRIVATE_ASSET_LIST_WIDTH);
            let max_height =
                (window.viewport_size().height * 0.88).min(PRIVATE_ACTION_FORM_MAX_HEIGHT);
            let close_root = root.clone();
            let content_root = root.clone();
            dialog
                .w(dialog_width)
                .h(max_height)
                .title(private_action_title_row(
                    title_action,
                    &asset_label,
                    icon_path.clone(),
                ))
                .on_close(move |_event, _window, cx| {
                    close_root.update(cx, |root, cx| match kind {
                        DeliveryFormKind::Send => root.close_send_form(key, cx),
                        DeliveryFormKind::Unshield => root.close_unshield_form(key, cx),
                    });
                })
                .child(match kind {
                    DeliveryFormKind::Send => content_root
                        .read(cx)
                        .render_send_form(content_root.clone(), key),
                    DeliveryFormKind::Unshield => content_root
                        .read(cx)
                        .render_unshield_form(content_root.clone(), key),
                })
        });
    }

    pub(super) fn open_send_form(
        &mut self,
        asset: UnshieldAsset,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        window.close_all_dialogs(cx);
        let key = UnshieldAssetKey::from_asset(&asset);
        let dialog_asset_label = asset.label.clone();
        let dialog_icon_path = asset.icon_path.clone();
        let amount = format_send_amount_input(asset.max_batched, asset.decimals);
        let amount_input = new_prefilled_input(window, cx, "amount", amount);
        let recipient_input = new_text_input(window, cx, "0zk recipient");
        let focus_recipient_input = recipient_input.clone();
        let password_input = new_masked_input(window, cx, "vault password");
        let self_broadcast_gas_payer_uuid = self.default_self_broadcast_gas_payer_uuid();
        let gas_payer_select = self.new_self_broadcast_gas_payer_select(
            key.chain_id,
            self_broadcast_gas_payer_uuid.as_deref(),
            window,
            cx,
        );
        let gas_fee_editor = Eip1559GasFeeEditorState::new(window, cx);
        cx.subscribe_in(
            &password_input,
            window,
            move |this, _input, event: &InputEvent, window, cx| match event {
                InputEvent::PressEnter { .. } => {
                    this.generate_send_calldata_from_form(key, window, cx);
                }
                InputEvent::Change => {
                    this.clear_private_action_missing_password_error(
                        DeliveryFormKind::Send,
                        key,
                        cx,
                    );
                }
                _ => {}
            },
        )
        .detach();
        cx.subscribe(
            &recipient_input,
            move |this, _input, event: &InputEvent, cx| {
                if matches!(event, InputEvent::Change) {
                    this.clear_send_form_text_edit_state(key, cx);
                    this.debounce_public_broadcaster_cost_estimate(DeliveryFormKind::Send, key, cx);
                }
            },
        )
        .detach();
        cx.subscribe(
            &amount_input,
            move |this, _input, event: &InputEvent, cx| {
                if matches!(event, InputEvent::Change) {
                    if this.consume_programmatic_amount_input_change(
                        DeliveryFormKind::Send,
                        key,
                        cx,
                    ) {
                        return;
                    }
                    this.clear_send_form_text_edit_state(key, cx);
                    this.debounce_public_broadcaster_cost_estimate(DeliveryFormKind::Send, key, cx);
                }
            },
        )
        .detach();
        cx.subscribe_in(
            &gas_payer_select,
            window,
            move |this,
                  _select,
                  event: &SelectEvent<SearchableVec<SelfBroadcastGasPayerSelectItem>>,
                  window,
                  cx| {
                if let SelectEvent::Confirm(Some(uuid)) = event {
                    this.set_self_broadcast_gas_payer(
                        DeliveryFormKind::Send,
                        key,
                        Some(Arc::clone(uuid)),
                        window,
                        cx,
                    );
                }
            },
        )
        .detach();
        cx.subscribe(
            &gas_fee_editor.max_fee_input,
            move |this, _input, event: &InputEvent, cx| {
                if matches!(event, InputEvent::Change) {
                    this.clear_send_form_text_edit_state(key, cx);
                }
            },
        )
        .detach();
        cx.subscribe(
            &gas_fee_editor.max_priority_fee_input,
            move |this, _input, event: &InputEvent, cx| {
                if matches!(event, InputEvent::Change) {
                    this.clear_send_form_text_edit_state(key, cx);
                }
            },
        )
        .detach();
        self.send_forms.clear();
        self.unshield_forms.clear();
        self.private_broadcaster_progress = None;
        self.broadcaster_picker = None;
        let selected_fee_token =
            self.default_public_broadcaster_fee_token(key.chain_id, key.token, false, false);
        self.send_forms.insert(
            key,
            SendFormState {
                asset,
                recipient_input,
                amount_input,
                password_input,
                delivery_mode: DeliveryMode::PublicBroadcaster,
                self_broadcast_gas_payer_uuid,
                self_broadcast_gas_payer_select: gas_payer_select,
                self_broadcast_gas_fee: gas_fee_editor,
                self_broadcast_estimated_native_gas_cost: None,
                selected_fee_token,
                broadcaster_choice: BroadcasterChoice::Random,
                broadcaster_fee_mode: PublicBroadcasterFeeMode::DeductFromAmount,
                allow_suspicious_broadcasters: self.default_allow_suspicious_broadcasters,
                transaction_fee_breakdown_open: true,
                pending_programmatic_amount_input: None,
                cost_estimate_pending: false,
                estimating_cost: false,
                cost_estimate: None,
                estimate_id: 0,
                generation_id: 0,
                generating: false,
                generation_stage: TransactionGenerationStage::default(),
                error: None,
                result: None,
            },
        );
        self.private_action_form = Some(PrivateActionFormState {
            kind: DeliveryFormKind::Send,
            key,
        });
        self.refresh_public_broadcaster_anchor(DeliveryFormKind::Send, key, cx);
        self.schedule_public_broadcaster_cost_estimate(DeliveryFormKind::Send, key, cx);
        Self::open_private_action_dialog(
            DeliveryFormKind::Send,
            key,
            "Send",
            dialog_asset_label,
            dialog_icon_path,
            window,
            cx,
        );
        focus_recipient_input
            .read(cx)
            .focus_handle(cx)
            .focus(window);
        cx.notify();
    }

    fn clear_send_form_text_edit_state(
        &mut self,
        key: UnshieldAssetKey,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(form) = self.send_forms.get_mut(&key) else {
            return;
        };
        if form.generating
            || (form.result.is_none()
                && form.error.is_none()
                && form.cost_estimate.is_none()
                && !form.cost_estimate_pending
                && !form.estimating_cost)
        {
            return;
        }
        form.result = None;
        form.error = None;
        form.cost_estimate = None;
        form.estimate_id = 0;
        form.cost_estimate_pending = false;
        form.estimating_cost = false;
        cx.notify();
    }

    fn consume_programmatic_amount_input_change(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        cx: &Context<'_, Self>,
    ) -> bool {
        match kind {
            DeliveryFormKind::Send => self.send_forms.get_mut(&key).is_some_and(|form| {
                let Some(expected) = form.pending_programmatic_amount_input.take() else {
                    return false;
                };
                form.amount_input.read(cx).value().as_ref() == expected
            }),
            DeliveryFormKind::Unshield => self.unshield_forms.get_mut(&key).is_some_and(|form| {
                let Some(expected) = form.pending_programmatic_amount_input.take() else {
                    return false;
                };
                form.amount_input.read(cx).value().as_ref() == expected
            }),
        }
    }

    fn set_private_action_metric_amount(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        amount: U256,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let changed = self.set_programmatic_amount_input(kind, key, amount, window, cx);
        if changed {
            self.schedule_public_broadcaster_cost_estimate(kind, key, cx);
        }
    }

    fn set_programmatic_amount_input(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        amount: U256,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) -> bool {
        match kind {
            DeliveryFormKind::Send => self.send_forms.get_mut(&key).is_some_and(|form| {
                if form.generating {
                    return false;
                }
                let value = format_send_amount_input(amount, form.asset.decimals);
                form.pending_programmatic_amount_input = Some(value.clone());
                form.error = None;
                form.result = None;
                form.estimate_id = 0;
                form.cost_estimate_pending = false;
                form.estimating_cost = false;
                form.amount_input
                    .update(cx, |input, cx| input.set_value(value, window, cx));
                true
            }),
            DeliveryFormKind::Unshield => self.unshield_forms.get_mut(&key).is_some_and(|form| {
                if form.generating {
                    return false;
                }
                let value = format_unshield_amount_input(amount, form.asset.decimals);
                form.pending_programmatic_amount_input = Some(value.clone());
                form.error = None;
                form.result = None;
                form.estimate_id = 0;
                form.cost_estimate_pending = false;
                form.estimating_cost = false;
                form.amount_input
                    .update(cx, |input, cx| input.set_value(value, window, cx));
                true
            }),
        }
    }

    fn set_send_delivery_mode(
        &mut self,
        key: UnshieldAssetKey,
        mode: DeliveryMode,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let self_broadcast_gas_payer_uuid = if mode == DeliveryMode::SelfBroadcast {
            let default = self.default_self_broadcast_gas_payer_uuid();
            if default.is_none() && self.active_self_broadcast_gas_payer_accounts().is_empty() {
                return;
            }
            default
        } else {
            None
        };
        let Some(form) = self.send_forms.get_mut(&key) else {
            return;
        };
        if form.generating || form.delivery_mode == mode {
            return;
        }
        let old_max =
            send_form_max_entered_amount(form, form.delivery_mode, form.broadcaster_fee_mode);
        let new_max = send_form_max_entered_amount(form, mode, form.broadcaster_fee_mode);
        let adjusted =
            amount_adjustment_for_max_change(&form.amount_input, &form.asset, old_max, new_max, cx);
        form.delivery_mode = mode;
        if mode == DeliveryMode::SelfBroadcast {
            form.self_broadcast_gas_payer_uuid = self_broadcast_gas_payer_uuid;
        }
        form.self_broadcast_estimated_native_gas_cost = None;
        form.error = None;
        form.result = None;
        if mode == DeliveryMode::PublicBroadcaster || adjusted.is_some() {
            form.cost_estimate = None;
        }
        if let Some(adjusted) = adjusted {
            form.pending_programmatic_amount_input = Some(adjusted.clone());
            form.amount_input
                .update(cx, |input, cx| input.set_value(adjusted, window, cx));
        }
        form.estimate_id = 0;
        form.cost_estimate_pending = false;
        form.estimating_cost = false;
        cx.notify();
        if mode == DeliveryMode::PublicBroadcaster {
            self.refresh_public_broadcaster_anchor(DeliveryFormKind::Send, key, cx);
        } else if mode == DeliveryMode::SelfBroadcast {
            self.schedule_self_broadcast_public_balance_refresh(window, cx);
            self.refresh_self_broadcast_gas_fee_quote(DeliveryFormKind::Send, key, cx);
        }
        self.schedule_public_broadcaster_cost_estimate(DeliveryFormKind::Send, key, cx);
    }

    pub(super) fn set_send_broadcaster_choice(
        &mut self,
        key: UnshieldAssetKey,
        choice: BroadcasterChoice,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(form) = self.send_forms.get_mut(&key) else {
            return;
        };
        if form.generating || form.broadcaster_choice == choice {
            return;
        }
        form.broadcaster_choice = choice;
        form.error = None;
        form.result = None;
        form.estimate_id = 0;
        form.cost_estimate_pending = false;
        form.estimating_cost = false;
        cx.notify();
        self.schedule_public_broadcaster_cost_estimate(DeliveryFormKind::Send, key, cx);
    }

    fn set_send_fee_token(
        &mut self,
        key: UnshieldAssetKey,
        fee_token: Address,
        cx: &mut Context<'_, Self>,
    ) {
        let Some((chain_id, action_token, current_choice, generating, allow_suspicious)) =
            self.send_forms.get(&key).map(|form| {
                (
                    form.asset.chain_id,
                    form.asset.token,
                    form.broadcaster_choice.clone(),
                    form.generating,
                    form.allow_suspicious_broadcasters,
                )
            })
        else {
            return;
        };
        if generating {
            return;
        }
        let policy = self.public_broadcaster_fee_policy(allow_suspicious);
        let candidates =
            self.current_public_broadcaster_candidates(chain_id, fee_token, false, policy);
        let reset_specific =
            !broadcaster_choice_supported_by_candidates(&current_choice, &candidates, policy);
        let Some(form) = self.send_forms.get_mut(&key) else {
            return;
        };
        if form.selected_fee_token == fee_token && !reset_specific {
            return;
        }
        form.selected_fee_token = fee_token;
        if fee_token != action_token {
            form.broadcaster_fee_mode = PublicBroadcasterFeeMode::AddToAmount;
        }
        if reset_specific {
            form.broadcaster_choice = BroadcasterChoice::Random;
        }
        form.error = None;
        form.result = None;
        form.cost_estimate = None;
        form.estimate_id = 0;
        form.cost_estimate_pending = false;
        form.estimating_cost = false;
        cx.notify();
        self.refresh_public_broadcaster_anchor(DeliveryFormKind::Send, key, cx);
        self.schedule_public_broadcaster_cost_estimate(DeliveryFormKind::Send, key, cx);
    }

    fn set_send_allow_suspicious_broadcasters(
        &mut self,
        key: UnshieldAssetKey,
        allow: bool,
        cx: &mut Context<'_, Self>,
    ) {
        let Some((chain_id, fee_token, choice, generating, current_allow)) =
            self.send_forms.get(&key).map(|form| {
                (
                    form.asset.chain_id,
                    form.selected_fee_token,
                    form.broadcaster_choice.clone(),
                    form.generating,
                    form.allow_suspicious_broadcasters,
                )
            })
        else {
            return;
        };
        if generating || current_allow == allow {
            return;
        }
        let policy = self.public_broadcaster_fee_policy(allow);
        let candidates =
            self.current_public_broadcaster_candidates(chain_id, fee_token, false, policy);
        let preserve_estimate =
            should_preserve_estimate_after_broadcaster_policy_change(&choice, &candidates, policy);
        let reset_specific =
            matches!(choice, BroadcasterChoice::Specific { .. }) && !preserve_estimate;
        let Some(form) = self.send_forms.get_mut(&key) else {
            return;
        };
        form.allow_suspicious_broadcasters = allow;
        if reset_specific {
            form.broadcaster_choice = BroadcasterChoice::Random;
        }
        let should_reestimate = !preserve_estimate || matches!(choice, BroadcasterChoice::Random);
        if should_reestimate {
            form.error = None;
            form.result = None;
            form.estimate_id = 0;
            form.cost_estimate_pending = false;
            form.estimating_cost = false;
        }
        cx.notify();
        if should_reestimate {
            self.refresh_public_broadcaster_anchor(DeliveryFormKind::Send, key, cx);
            self.schedule_public_broadcaster_cost_estimate(DeliveryFormKind::Send, key, cx);
        }
    }

    fn set_send_broadcaster_fee_mode(
        &mut self,
        key: UnshieldAssetKey,
        fee_mode: PublicBroadcasterFeeMode,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(form) = self.send_forms.get_mut(&key) else {
            return;
        };
        if form.generating
            || form.selected_fee_token != form.asset.token
            || form.broadcaster_fee_mode == fee_mode
        {
            return;
        }
        let old_max =
            send_form_max_entered_amount(form, form.delivery_mode, form.broadcaster_fee_mode);
        let new_max = send_form_max_entered_amount(form, form.delivery_mode, fee_mode);
        let adjusted =
            amount_adjustment_for_max_change(&form.amount_input, &form.asset, old_max, new_max, cx);
        form.broadcaster_fee_mode = fee_mode;
        form.error = None;
        form.result = None;
        form.estimate_id = 0;
        form.cost_estimate_pending = false;
        form.estimating_cost = false;
        if let Some(adjusted) = adjusted {
            form.pending_programmatic_amount_input = Some(adjusted.clone());
            form.amount_input
                .update(cx, |input, cx| input.set_value(adjusted, window, cx));
        }
        cx.notify();
        self.schedule_public_broadcaster_cost_estimate(DeliveryFormKind::Send, key, cx);
    }

    pub(super) fn set_allow_suspicious_broadcasters(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        allow: bool,
        cx: &mut Context<'_, Self>,
    ) {
        match kind {
            DeliveryFormKind::Send => self.set_send_allow_suspicious_broadcasters(key, allow, cx),
            DeliveryFormKind::Unshield => {
                self.set_unshield_allow_suspicious_broadcasters(key, allow, cx);
            }
        }
    }

    pub(super) fn set_transaction_fee_breakdown_open(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        open: bool,
        cx: &mut Context<'_, Self>,
    ) {
        let changed = match kind {
            DeliveryFormKind::Send => self.send_forms.get_mut(&key).is_some_and(|form| {
                if form.transaction_fee_breakdown_open == open {
                    false
                } else {
                    form.transaction_fee_breakdown_open = open;
                    true
                }
            }),
            DeliveryFormKind::Unshield => self.unshield_forms.get_mut(&key).is_some_and(|form| {
                if form.transaction_fee_breakdown_open == open {
                    false
                } else {
                    form.transaction_fee_breakdown_open = open;
                    true
                }
            }),
        };
        if changed {
            cx.notify();
        }
    }

    fn set_self_broadcast_gas_payer(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        public_account_uuid: Option<Arc<str>>,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let changed = match kind {
            DeliveryFormKind::Send => self.send_forms.get_mut(&key).is_some_and(|form| {
                if form.generating || form.self_broadcast_gas_payer_uuid == public_account_uuid {
                    return false;
                }
                form.self_broadcast_gas_payer_uuid = public_account_uuid;
                form.self_broadcast_estimated_native_gas_cost = None;
                form.error = None;
                form.result = None;
                true
            }),
            DeliveryFormKind::Unshield => self.unshield_forms.get_mut(&key).is_some_and(|form| {
                if form.generating || form.self_broadcast_gas_payer_uuid == public_account_uuid {
                    return false;
                }
                form.self_broadcast_gas_payer_uuid = public_account_uuid;
                form.self_broadcast_estimated_native_gas_cost = None;
                form.error = None;
                form.result = None;
                true
            }),
        };
        if changed {
            self.sync_self_broadcast_gas_payer_select(kind, key, window, cx);
            cx.notify();
        }
    }

    fn choose_random_self_broadcast_gas_payer(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let accounts = self.active_self_broadcast_gas_payer_accounts();
        let selected_uuid = match kind {
            DeliveryFormKind::Send => self
                .send_forms
                .get(&key)
                .and_then(|form| form.self_broadcast_gas_payer_uuid.clone()),
            DeliveryFormKind::Unshield => self
                .unshield_forms
                .get(&key)
                .and_then(|form| form.self_broadcast_gas_payer_uuid.clone()),
        };
        let Some(account_uuid) = random_self_broadcast_gas_payer_uuid(
            &accounts,
            selected_uuid.as_deref(),
            key.chain_id,
            self.public_balance_snapshot.as_deref(),
        ) else {
            return;
        };
        self.set_self_broadcast_gas_payer(kind, key, Some(account_uuid), window, cx);
    }

    pub(super) fn set_self_broadcast_gas_fee_mode(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        mode: Eip1559GasFeeMode,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let changed = match kind {
            DeliveryFormKind::Send => self.send_forms.get_mut(&key).is_some_and(|form| {
                if form.generating || form.self_broadcast_gas_fee.mode == mode {
                    return false;
                }
                if mode == Eip1559GasFeeMode::Custom {
                    form.self_broadcast_gas_fee
                        .seed_custom_from_auto_if_empty(window, cx);
                }
                form.self_broadcast_gas_fee.mode = mode;
                form.self_broadcast_estimated_native_gas_cost = None;
                form.error = None;
                form.result = None;
                true
            }),
            DeliveryFormKind::Unshield => self.unshield_forms.get_mut(&key).is_some_and(|form| {
                if form.generating || form.self_broadcast_gas_fee.mode == mode {
                    return false;
                }
                if mode == Eip1559GasFeeMode::Custom {
                    form.self_broadcast_gas_fee
                        .seed_custom_from_auto_if_empty(window, cx);
                }
                form.self_broadcast_gas_fee.mode = mode;
                form.self_broadcast_estimated_native_gas_cost = None;
                form.error = None;
                form.result = None;
                true
            }),
        };
        if changed {
            cx.notify();
        }
    }

    pub(super) fn customize_self_broadcast_gas_fee_from_auto(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        target: Eip1559GasFeeEditTarget,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let mut focus_input: Option<Entity<InputState>> = None;
        let changed = match kind {
            DeliveryFormKind::Send => self.send_forms.get_mut(&key).is_some_and(|form| {
                if form.generating
                    || !form
                        .self_broadcast_gas_fee
                        .overwrite_custom_from_auto(window, cx)
                {
                    return false;
                }
                focus_input = Some(match target {
                    Eip1559GasFeeEditTarget::MaxFee => {
                        form.self_broadcast_gas_fee.max_fee_input.clone()
                    }
                    Eip1559GasFeeEditTarget::MaxTip => {
                        form.self_broadcast_gas_fee.max_priority_fee_input.clone()
                    }
                });
                form.self_broadcast_gas_fee.mode = Eip1559GasFeeMode::Custom;
                form.self_broadcast_estimated_native_gas_cost = None;
                form.error = None;
                form.result = None;
                true
            }),
            DeliveryFormKind::Unshield => self.unshield_forms.get_mut(&key).is_some_and(|form| {
                if form.generating
                    || !form
                        .self_broadcast_gas_fee
                        .overwrite_custom_from_auto(window, cx)
                {
                    return false;
                }
                focus_input = Some(match target {
                    Eip1559GasFeeEditTarget::MaxFee => {
                        form.self_broadcast_gas_fee.max_fee_input.clone()
                    }
                    Eip1559GasFeeEditTarget::MaxTip => {
                        form.self_broadcast_gas_fee.max_priority_fee_input.clone()
                    }
                });
                form.self_broadcast_gas_fee.mode = Eip1559GasFeeMode::Custom;
                form.self_broadcast_estimated_native_gas_cost = None;
                form.error = None;
                form.result = None;
                true
            }),
        };
        if changed {
            if let Some(input) = focus_input {
                input.read(cx).focus_handle(cx).focus(window);
            }
            cx.notify();
        }
    }

    pub(super) fn refresh_self_broadcast_gas_fee_quote(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        cx: &mut Context<'_, Self>,
    ) {
        let chain_id = key.chain_id;
        let effective_chain = self.effective_chain_configs.get(&chain_id).cloned();
        let refresh_id = match kind {
            DeliveryFormKind::Send => {
                let Some(form) = self.send_forms.get_mut(&key) else {
                    return;
                };
                if form.generating || form.self_broadcast_gas_fee.refreshing {
                    return;
                }
                form.self_broadcast_gas_fee.refresh_id =
                    form.self_broadcast_gas_fee.refresh_id.wrapping_add(1);
                form.self_broadcast_gas_fee.refreshing = true;
                form.self_broadcast_gas_fee.error = None;
                form.self_broadcast_gas_fee.refresh_id
            }
            DeliveryFormKind::Unshield => {
                let Some(form) = self.unshield_forms.get_mut(&key) else {
                    return;
                };
                if form.generating || form.self_broadcast_gas_fee.refreshing {
                    return;
                }
                form.self_broadcast_gas_fee.refresh_id =
                    form.self_broadcast_gas_fee.refresh_id.wrapping_add(1);
                form.self_broadcast_gas_fee.refreshing = true;
                form.self_broadcast_gas_fee.error = None;
                form.self_broadcast_gas_fee.refresh_id
            }
        };
        let http = self.http.clone();
        cx.spawn(async move |this, cx| {
            let result =
                quote_desktop_self_broadcast_gas_fee(chain_id, effective_chain.as_ref(), &http)
                    .await;
            let _ = this.update(cx, |root, cx| {
                let gas_fee = match kind {
                    DeliveryFormKind::Send => root
                        .send_forms
                        .get_mut(&key)
                        .map(|form| &mut form.self_broadcast_gas_fee),
                    DeliveryFormKind::Unshield => root
                        .unshield_forms
                        .get_mut(&key)
                        .map(|form| &mut form.self_broadcast_gas_fee),
                };
                let Some(gas_fee) = gas_fee else {
                    return;
                };
                if gas_fee.refresh_id != refresh_id {
                    return;
                }
                gas_fee.refreshing = false;
                match result {
                    Ok(quote) => {
                        gas_fee.quote = Some(quote);
                        gas_fee.error = None;
                    }
                    Err(error) => {
                        gas_fee.error = Some(Arc::from(format_report_chain(&error)));
                    }
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn clear_private_action_missing_password_error(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        cx: &mut Context<'_, Self>,
    ) {
        let cleared = match kind {
            DeliveryFormKind::Send => self.send_forms.get_mut(&key).is_some_and(|form| {
                if form.generating
                    || !form.error.as_deref().is_some_and(|error| {
                        should_clear_private_action_error_on_password_change(kind, error)
                    })
                {
                    return false;
                }
                form.error = None;
                true
            }),
            DeliveryFormKind::Unshield => self.unshield_forms.get_mut(&key).is_some_and(|form| {
                if form.generating
                    || !form.error.as_deref().is_some_and(|error| {
                        should_clear_private_action_error_on_password_change(kind, error)
                    })
                {
                    return false;
                }
                form.error = None;
                true
            }),
        };
        if cleared {
            cx.notify();
        }
    }

    pub(super) fn set_send_form_error(
        &mut self,
        key: UnshieldAssetKey,
        message: impl Into<Arc<str>>,
        cx: &mut Context<'_, Self>,
    ) {
        let message = message.into();
        if let Some(form) = self.send_forms.get_mut(&key) {
            form.generating = false;
            if form_error_clears_public_broadcaster_cost_estimate(
                DeliveryFormKind::Send,
                message.as_ref(),
            ) {
                form.cost_estimate = None;
            }
            form.cost_estimate_pending = false;
            form.estimating_cost = false;
            form.estimate_id = 0;
            form.result = None;
            form.error = Some(message);
            cx.notify();
        }
    }

    pub(super) fn open_unshield_form(
        &mut self,
        asset: UnshieldAsset,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        window.close_all_dialogs(cx);
        let key = UnshieldAssetKey::from_asset(&asset);
        let dialog_asset_label = asset.label.clone();
        let dialog_icon_path = asset.icon_path.clone();
        let amount = format_unshield_amount_input(asset.max_batched, asset.decimals);
        let amount_input = new_prefilled_input(window, cx, "amount", amount);
        let recipient_input = new_text_input(window, cx, "0x recipient");
        let focus_recipient_input = recipient_input.clone();
        let password_input = new_masked_input(window, cx, "vault password");
        let self_broadcast_gas_payer_uuid = self.default_self_broadcast_gas_payer_uuid();
        let gas_payer_select = self.new_self_broadcast_gas_payer_select(
            key.chain_id,
            self_broadcast_gas_payer_uuid.as_deref(),
            window,
            cx,
        );
        let gas_fee_editor = Eip1559GasFeeEditorState::new(window, cx);
        cx.subscribe_in(
            &password_input,
            window,
            move |this, _input, event: &InputEvent, window, cx| match event {
                InputEvent::PressEnter { .. } => {
                    this.generate_unshield_calldata_from_form(key, window, cx);
                }
                InputEvent::Change => {
                    this.clear_private_action_missing_password_error(
                        DeliveryFormKind::Unshield,
                        key,
                        cx,
                    );
                }
                _ => {}
            },
        )
        .detach();
        cx.subscribe(
            &recipient_input,
            move |this, _input, event: &InputEvent, cx| {
                if matches!(event, InputEvent::Change) {
                    this.clear_unshield_form_text_edit_state(key, cx);
                    this.debounce_public_broadcaster_cost_estimate(
                        DeliveryFormKind::Unshield,
                        key,
                        cx,
                    );
                }
            },
        )
        .detach();
        cx.subscribe(
            &amount_input,
            move |this, _input, event: &InputEvent, cx| {
                if matches!(event, InputEvent::Change) {
                    if this.consume_programmatic_amount_input_change(
                        DeliveryFormKind::Unshield,
                        key,
                        cx,
                    ) {
                        return;
                    }
                    this.clear_unshield_form_text_edit_state(key, cx);
                    this.debounce_public_broadcaster_cost_estimate(
                        DeliveryFormKind::Unshield,
                        key,
                        cx,
                    );
                }
            },
        )
        .detach();
        cx.subscribe_in(
            &gas_payer_select,
            window,
            move |this,
                  _select,
                  event: &SelectEvent<SearchableVec<SelfBroadcastGasPayerSelectItem>>,
                  window,
                  cx| {
                if let SelectEvent::Confirm(Some(uuid)) = event {
                    this.set_self_broadcast_gas_payer(
                        DeliveryFormKind::Unshield,
                        key,
                        Some(Arc::clone(uuid)),
                        window,
                        cx,
                    );
                }
            },
        )
        .detach();
        self.send_forms.clear();
        self.unshield_forms.clear();
        self.private_broadcaster_progress = None;
        self.broadcaster_picker = None;
        let selected_fee_token =
            self.default_public_broadcaster_fee_token(key.chain_id, key.token, false, false);
        self.unshield_forms.insert(
            key,
            UnshieldFormState {
                asset,
                recipient_input,
                amount_input,
                password_input,
                unwrap: false,
                delivery_mode: DeliveryMode::PublicBroadcaster,
                self_broadcast_gas_payer_uuid,
                self_broadcast_gas_payer_select: gas_payer_select,
                self_broadcast_gas_fee: gas_fee_editor,
                self_broadcast_estimated_native_gas_cost: None,
                selected_fee_token,
                broadcaster_choice: BroadcasterChoice::Random,
                broadcaster_fee_mode: PublicBroadcasterFeeMode::DeductFromAmount,
                allow_suspicious_broadcasters: self.default_allow_suspicious_broadcasters,
                transaction_fee_breakdown_open: true,
                pending_programmatic_amount_input: None,
                cost_estimate_pending: false,
                estimating_cost: false,
                cost_estimate: None,
                estimate_id: 0,
                generation_id: 0,
                generating: false,
                generation_stage: TransactionGenerationStage::default(),
                error: None,
                result: None,
            },
        );
        self.private_action_form = Some(PrivateActionFormState {
            kind: DeliveryFormKind::Unshield,
            key,
        });
        self.refresh_public_broadcaster_anchor(DeliveryFormKind::Unshield, key, cx);
        self.schedule_public_broadcaster_cost_estimate(DeliveryFormKind::Unshield, key, cx);
        Self::open_private_action_dialog(
            DeliveryFormKind::Unshield,
            key,
            "Unshield",
            dialog_asset_label,
            dialog_icon_path,
            window,
            cx,
        );
        focus_recipient_input
            .read(cx)
            .focus_handle(cx)
            .focus(window);
        cx.notify();
    }

    fn set_unshield_unwrap(
        &mut self,
        key: UnshieldAssetKey,
        unwrap: bool,
        cx: &mut Context<'_, Self>,
    ) {
        let unwrap_supported = self.unshield_forms.get(&key).is_some_and(|form| {
            is_effective_wrapped_native_token(
                &self.effective_chain_configs,
                form.asset.chain_id,
                form.asset.token,
            )
        });
        let Some(form) = self.unshield_forms.get_mut(&key) else {
            return;
        };
        if !unwrap_supported || form.generating || form.unwrap == unwrap {
            return;
        }
        form.unwrap = unwrap;
        form.error = None;
        form.result = None;
        form.estimate_id = 0;
        form.cost_estimate_pending = false;
        form.estimating_cost = false;
        cx.notify();
        if form.delivery_mode == DeliveryMode::PublicBroadcaster {
            self.refresh_public_broadcaster_anchor(DeliveryFormKind::Unshield, key, cx);
        }
        self.schedule_public_broadcaster_cost_estimate(DeliveryFormKind::Unshield, key, cx);
    }

    fn set_unshield_broadcaster_fee_mode(
        &mut self,
        key: UnshieldAssetKey,
        fee_mode: PublicBroadcasterFeeMode,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(form) = self.unshield_forms.get_mut(&key) else {
            return;
        };
        if form.generating
            || form.selected_fee_token != form.asset.token
            || form.broadcaster_fee_mode == fee_mode
        {
            return;
        }
        let old_max =
            unshield_form_max_entered_amount(form, form.delivery_mode, form.broadcaster_fee_mode);
        let new_max = unshield_form_max_entered_amount(form, form.delivery_mode, fee_mode);
        let adjusted =
            amount_adjustment_for_max_change(&form.amount_input, &form.asset, old_max, new_max, cx);
        form.broadcaster_fee_mode = fee_mode;
        form.error = None;
        form.result = None;
        form.estimate_id = 0;
        form.cost_estimate_pending = false;
        form.estimating_cost = false;
        if let Some(adjusted) = adjusted {
            form.pending_programmatic_amount_input = Some(adjusted.clone());
            form.amount_input
                .update(cx, |input, cx| input.set_value(adjusted, window, cx));
        }
        cx.notify();
        if form.delivery_mode == DeliveryMode::PublicBroadcaster {
            self.refresh_public_broadcaster_anchor(DeliveryFormKind::Unshield, key, cx);
        }
        self.schedule_public_broadcaster_cost_estimate(DeliveryFormKind::Unshield, key, cx);
    }

    fn clear_unshield_form_text_edit_state(
        &mut self,
        key: UnshieldAssetKey,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(form) = self.unshield_forms.get_mut(&key) else {
            return;
        };
        if form.generating
            || (form.result.is_none()
                && form.error.is_none()
                && form.cost_estimate.is_none()
                && !form.cost_estimate_pending
                && !form.estimating_cost)
        {
            return;
        }
        form.result = None;
        form.error = None;
        form.cost_estimate = None;
        form.estimate_id = 0;
        form.cost_estimate_pending = false;
        form.estimating_cost = false;
        cx.notify();
    }

    fn set_unshield_delivery_mode(
        &mut self,
        key: UnshieldAssetKey,
        mode: DeliveryMode,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let self_broadcast_gas_payer_uuid = if mode == DeliveryMode::SelfBroadcast {
            let default = self.default_self_broadcast_gas_payer_uuid();
            if default.is_none() && self.active_self_broadcast_gas_payer_accounts().is_empty() {
                return;
            }
            default
        } else {
            None
        };
        let Some(form) = self.unshield_forms.get_mut(&key) else {
            return;
        };
        if form.generating || form.delivery_mode == mode {
            return;
        }
        let old_max =
            unshield_form_max_entered_amount(form, form.delivery_mode, form.broadcaster_fee_mode);
        let new_max = unshield_form_max_entered_amount(form, mode, form.broadcaster_fee_mode);
        let adjusted =
            amount_adjustment_for_max_change(&form.amount_input, &form.asset, old_max, new_max, cx);
        form.delivery_mode = mode;
        if mode == DeliveryMode::SelfBroadcast {
            form.self_broadcast_gas_payer_uuid = self_broadcast_gas_payer_uuid;
        }
        form.self_broadcast_estimated_native_gas_cost = None;
        form.error = None;
        form.result = None;
        if mode == DeliveryMode::PublicBroadcaster || adjusted.is_some() {
            form.cost_estimate = None;
        }
        if let Some(adjusted) = adjusted {
            form.pending_programmatic_amount_input = Some(adjusted.clone());
            form.amount_input
                .update(cx, |input, cx| input.set_value(adjusted, window, cx));
        }
        form.estimate_id = 0;
        form.cost_estimate_pending = false;
        form.estimating_cost = false;
        cx.notify();
        if mode == DeliveryMode::PublicBroadcaster {
            self.refresh_public_broadcaster_anchor(DeliveryFormKind::Unshield, key, cx);
        } else if mode == DeliveryMode::SelfBroadcast {
            self.schedule_self_broadcast_public_balance_refresh(window, cx);
            self.refresh_self_broadcast_gas_fee_quote(DeliveryFormKind::Unshield, key, cx);
        }
        self.schedule_public_broadcaster_cost_estimate(DeliveryFormKind::Unshield, key, cx);
    }

    pub(super) fn set_unshield_broadcaster_choice(
        &mut self,
        key: UnshieldAssetKey,
        choice: BroadcasterChoice,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(form) = self.unshield_forms.get_mut(&key) else {
            return;
        };
        if form.generating || form.broadcaster_choice == choice {
            return;
        }
        form.broadcaster_choice = choice;
        form.error = None;
        form.result = None;
        form.estimate_id = 0;
        form.cost_estimate_pending = false;
        form.estimating_cost = false;
        cx.notify();
        self.schedule_public_broadcaster_cost_estimate(DeliveryFormKind::Unshield, key, cx);
    }

    fn set_unshield_fee_token(
        &mut self,
        key: UnshieldAssetKey,
        fee_token: Address,
        cx: &mut Context<'_, Self>,
    ) {
        let Some((chain_id, action_token, unwrap, current_choice, generating, allow_suspicious)) =
            self.unshield_forms.get(&key).map(|form| {
                (
                    form.asset.chain_id,
                    form.asset.token,
                    form.unwrap,
                    form.broadcaster_choice.clone(),
                    form.generating,
                    form.allow_suspicious_broadcasters,
                )
            })
        else {
            return;
        };
        if generating {
            return;
        }
        let policy = self.public_broadcaster_fee_policy(allow_suspicious);
        let candidates =
            self.current_public_broadcaster_candidates(chain_id, fee_token, unwrap, policy);
        let reset_specific =
            !broadcaster_choice_supported_by_candidates(&current_choice, &candidates, policy);
        let Some(form) = self.unshield_forms.get_mut(&key) else {
            return;
        };
        if form.selected_fee_token == fee_token && !reset_specific {
            return;
        }
        form.selected_fee_token = fee_token;
        if fee_token != action_token {
            form.broadcaster_fee_mode = PublicBroadcasterFeeMode::AddToAmount;
        }
        if reset_specific {
            form.broadcaster_choice = BroadcasterChoice::Random;
        }
        form.error = None;
        form.result = None;
        form.cost_estimate = None;
        form.estimate_id = 0;
        form.cost_estimate_pending = false;
        form.estimating_cost = false;
        cx.notify();
        self.refresh_public_broadcaster_anchor(DeliveryFormKind::Unshield, key, cx);
        self.schedule_public_broadcaster_cost_estimate(DeliveryFormKind::Unshield, key, cx);
    }

    fn set_unshield_allow_suspicious_broadcasters(
        &mut self,
        key: UnshieldAssetKey,
        allow: bool,
        cx: &mut Context<'_, Self>,
    ) {
        let Some((chain_id, fee_token, unwrap, choice, generating, current_allow)) =
            self.unshield_forms.get(&key).map(|form| {
                (
                    form.asset.chain_id,
                    form.selected_fee_token,
                    form.unwrap,
                    form.broadcaster_choice.clone(),
                    form.generating,
                    form.allow_suspicious_broadcasters,
                )
            })
        else {
            return;
        };
        if generating || current_allow == allow {
            return;
        }
        let policy = self.public_broadcaster_fee_policy(allow);
        let candidates =
            self.current_public_broadcaster_candidates(chain_id, fee_token, unwrap, policy);
        let preserve_estimate =
            should_preserve_estimate_after_broadcaster_policy_change(&choice, &candidates, policy);
        let reset_specific =
            matches!(choice, BroadcasterChoice::Specific { .. }) && !preserve_estimate;
        let Some(form) = self.unshield_forms.get_mut(&key) else {
            return;
        };
        form.allow_suspicious_broadcasters = allow;
        if reset_specific {
            form.broadcaster_choice = BroadcasterChoice::Random;
        }
        let should_reestimate = !preserve_estimate || matches!(choice, BroadcasterChoice::Random);
        if should_reestimate {
            form.error = None;
            form.result = None;
            form.estimate_id = 0;
            form.cost_estimate_pending = false;
            form.estimating_cost = false;
        }
        cx.notify();
        if should_reestimate {
            self.refresh_public_broadcaster_anchor(DeliveryFormKind::Unshield, key, cx);
            self.schedule_public_broadcaster_cost_estimate(DeliveryFormKind::Unshield, key, cx);
        }
    }

    pub(super) fn set_unshield_form_error(
        &mut self,
        key: UnshieldAssetKey,
        message: impl Into<Arc<str>>,
        cx: &mut Context<'_, Self>,
    ) {
        let message = message.into();
        if let Some(form) = self.unshield_forms.get_mut(&key) {
            form.generating = false;
            if form_error_clears_public_broadcaster_cost_estimate(
                DeliveryFormKind::Unshield,
                message.as_ref(),
            ) {
                form.cost_estimate = None;
            }
            form.cost_estimate_pending = false;
            form.estimating_cost = false;
            form.estimate_id = 0;
            form.result = None;
            form.error = Some(message);
            cx.notify();
        }
    }

    pub(super) fn generate_send_calldata_from_form(
        &mut self,
        key: UnshieldAssetKey,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(form) = self.send_forms.get(&key) else {
            return;
        };
        if form.generating {
            return;
        }
        let asset = form.asset.clone();
        let recipient_input = form.recipient_input.clone();
        let amount_input = form.amount_input.clone();
        let password_input = form.password_input.clone();
        let delivery_mode = form.delivery_mode;
        let broadcaster_choice = form.broadcaster_choice.clone();
        let cost_estimate = form.cost_estimate.clone();
        let fee_token = form.selected_fee_token;
        let self_broadcast_gas_payer_uuid = form.self_broadcast_gas_payer_uuid.clone();
        let self_broadcast_gas_fee = if delivery_mode == DeliveryMode::SelfBroadcast {
            match form.self_broadcast_gas_fee.selection(cx) {
                Ok(selection) => selection,
                Err(error) => {
                    self.set_send_form_error(key, error, cx);
                    return;
                }
            }
        } else {
            SelfBroadcastGasFeeSelection::Auto
        };
        let self_broadcast_initial_gas_fee = if delivery_mode == DeliveryMode::SelfBroadcast {
            self_broadcast_initial_gas_values(
                &self_broadcast_gas_fee,
                form.self_broadcast_gas_fee.quote,
            )
        } else {
            None
        };
        let broadcaster_fee_mode = effective_public_broadcaster_fee_mode(
            asset.token,
            fee_token,
            form.broadcaster_fee_mode,
        );
        let allow_suspicious_broadcasters = form.allow_suspicious_broadcasters;

        let Some(view_session) = self.view_session.clone() else {
            self.set_send_form_error(key, "Unlock the wallet vault before sending", cx);
            return;
        };
        let Some(vault_store) = self.vault_store.clone() else {
            self.set_send_form_error(key, "Wallet vault storage is unavailable", cx);
            return;
        };
        let Some(ChainUtxoState::Ready { session, .. }) = self.chain_states.get(&asset.chain_id)
        else {
            self.set_send_form_error(key, "Wait for wallet sync to finish before sending", cx);
            return;
        };
        let session = Arc::clone(session);
        if asset.max_batched.is_zero() {
            self.set_send_form_error(
                key,
                "No POI-verified private notes are spendable in a batched send",
                cx,
            );
            return;
        }

        let recipient_raw = recipient_input.read(cx).value().to_string();
        if let Err(error) = parse_railgun_recipient(recipient_raw.as_str()) {
            self.set_send_form_error(key, error.to_string(), cx);
            return;
        }
        let recipient = recipient_raw.trim().to_string();
        let amount_raw = amount_input.read(cx).value().to_string();
        let amount = match parse_send_amount(amount_raw.as_str(), asset.decimals) {
            Ok(amount) if !amount.is_zero() => amount,
            Ok(_) => {
                self.set_send_form_error(key, "Enter an amount greater than zero", cx);
                return;
            }
            Err(error) => {
                self.set_send_form_error(key, error.to_string(), cx);
                return;
            }
        };
        if amount > asset.max_batched {
            self.set_send_form_error(
                key,
                format!(
                    "Amount exceeds max POI-verified batched transaction: {}",
                    format_send_amount_input(asset.max_batched, asset.decimals)
                ),
                cx,
            );
            return;
        }

        let (self_broadcast_public_account_uuid, self_broadcast_gas_payer_display) =
            if delivery_mode == DeliveryMode::SelfBroadcast {
                let Some(uuid) = self_broadcast_gas_payer_uuid else {
                    self.set_send_form_error(key, "Choose a Public account to pay gas", cx);
                    return;
                };
                let Some(account) =
                    self.selected_self_broadcast_gas_payer_account(Some(uuid.as_ref()))
                else {
                    self.set_send_form_error(key, "Choose an active Public account to pay gas", cx);
                    return;
                };
                let gas_payer_display = public_account_display_label(account).map_or_else(
                    || short_address(&account.address),
                    |label| format!("{label} · {}", short_address(&account.address)),
                );
                (Some(uuid.to_string()), Some(gas_payer_display))
            } else {
                (None, None)
            };

        let fee_rows = if delivery_mode == DeliveryMode::PublicBroadcaster {
            let rows = self.monitor_fee_rows();
            let policy = self.public_broadcaster_fee_policy(allow_suspicious_broadcasters);
            let public_broadcaster_selection = Self::public_broadcaster_submission_selection(
                &broadcaster_choice,
                cost_estimate.as_ref(),
            );
            let candidates = self.current_public_broadcaster_candidates(
                asset.chain_id,
                fee_token,
                false,
                policy,
            );
            if let Err(error) = select_public_broadcaster_with_policy(
                &candidates,
                &public_broadcaster_selection,
                policy,
            ) {
                self.set_send_form_error(key, error.to_string(), cx);
                return;
            }
            rows
        } else {
            Vec::new()
        };
        let fee_policy = self.public_broadcaster_fee_policy(allow_suspicious_broadcasters);

        let password_empty = password_input.read(cx).value().trim().is_empty();
        if password_empty {
            self.set_send_form_error(key, SEND_MISSING_PASSWORD_ERROR, cx);
            return;
        }
        let vault_password = Self::read_and_clear_input(&password_input, window, cx);

        self.send_generation_seq = self.send_generation_seq.wrapping_add(1);
        let generation_id = self.send_generation_seq;
        let (progress_tx, progress_rx) = watch::channel(TransactionGenerationStage::default());
        let (self_broadcast_command_tx, self_broadcast_command_rx) =
            if delivery_mode == DeliveryMode::SelfBroadcast {
                let (tx, rx) = mpsc::unbounded_channel();
                (Some(tx), Some(rx))
            } else {
                (None, None)
            };
        let (self_broadcast_event_tx, self_broadcast_event_rx) =
            if delivery_mode == DeliveryMode::SelfBroadcast {
                let (tx, rx) = mpsc::unbounded_channel();
                (Some(tx), Some(rx))
            } else {
                (None, None)
            };
        if let Some(form) = self.send_forms.get_mut(&key) {
            form.generation_id = generation_id;
            form.generating = true;
            form.generation_stage = TransactionGenerationStage::default();
            form.cost_estimate_pending = false;
            form.estimating_cost = false;
            form.estimate_id = 0;
            form.self_broadcast_estimated_native_gas_cost = None;
            form.error = None;
            form.result = None;
        }
        cx.notify();

        match delivery_mode {
            DeliveryMode::PublicBroadcaster => {
                self.start_private_broadcaster_progress(
                    DeliveryFormKind::Send,
                    key,
                    generation_id,
                    asset.label.clone(),
                    asset.icon_path.clone(),
                    recipient.clone(),
                    cost_estimate.clone(),
                );
            }
            DeliveryMode::SelfBroadcast => {
                self.start_private_self_broadcast_progress(
                    DeliveryFormKind::Send,
                    key,
                    generation_id,
                    asset.label.clone(),
                    asset.icon_path.clone(),
                    recipient.clone(),
                    self_broadcast_gas_payer_display
                        .expect("self-broadcast gas payer was validated"),
                    self_broadcast_command_tx,
                    self_broadcast_initial_gas_fee,
                );
            }
            DeliveryMode::ManualCalldata => {}
        }

        let http = self.http.clone();
        let waku = Arc::clone(&self.waku);
        let chain_id = asset.chain_id;
        let token = asset.token;
        let join = match delivery_mode {
            DeliveryMode::ManualCalldata => {
                let request = DesktopSendCalldataRequest {
                    chain_id,
                    effective_chain: self.effective_chain_configs.get(&chain_id).cloned(),
                    view_session,
                    session,
                    vault_store,
                    vault_password,
                    token,
                    fee_token,
                    amount,
                    recipient,
                    verify_proof: true,
                    progress_tx: Some(progress_tx),
                };
                self.runtime.spawn(async move {
                    prepare_desktop_send_calldata(request, &http)
                        .await
                        .map(SendResult::Manual)
                })
            }
            DeliveryMode::PublicBroadcaster => {
                let request = DesktopSendPublicBroadcasterRequest {
                    chain_id,
                    effective_chain: self.effective_chain_configs.get(&chain_id).cloned(),
                    view_session,
                    session,
                    vault_store,
                    vault_password,
                    token,
                    fee_token,
                    amount,
                    recipient,
                    verify_proof: true,
                    fee_rows,
                    selection: Self::public_broadcaster_submission_selection(
                        &broadcaster_choice,
                        cost_estimate.as_ref(),
                    ),
                    fee_mode: broadcaster_fee_mode,
                    fee_policy,
                    anchor_cache: Some(Arc::clone(&self.public_broadcaster_anchor_cache)),
                    waku,
                    response_timeout: self.public_broadcaster_response_timeout,
                    republish_interval: self.public_broadcaster_republish_interval,
                    progress_tx: Some(progress_tx),
                };
                self.runtime.spawn(async move {
                    submit_desktop_send_public_broadcaster(request, &http)
                        .await
                        .map(|result| SendResult::PublicBroadcaster(Box::new(result)))
                })
            }
            DeliveryMode::SelfBroadcast => {
                let request = DesktopSendSelfBroadcastRequest {
                    chain_id,
                    effective_chain: self.effective_chain_configs.get(&chain_id).cloned(),
                    view_session,
                    session,
                    vault_store,
                    vault_password,
                    public_account_uuid: self_broadcast_public_account_uuid
                        .expect("self-broadcast gas payer was validated"),
                    token,
                    fee_token,
                    amount,
                    recipient,
                    verify_proof: true,
                    gas_fee: self_broadcast_gas_fee,
                    progress_tx: Some(progress_tx),
                    command_rx: self_broadcast_command_rx,
                    event_tx: self_broadcast_event_tx,
                };
                self.runtime.spawn(async move {
                    submit_desktop_send_self_broadcast(request, &http)
                        .await
                        .map(|result| SendResult::SelfBroadcast(Box::new(result)))
                })
            }
        };
        let terminal_progress_rx = progress_rx.clone();
        Self::watch_send_generation_stage(key, generation_id, progress_rx, window, cx);
        if let Some(event_rx) = self_broadcast_event_rx {
            Self::watch_self_broadcast_session_events(
                DeliveryFormKind::Send,
                key,
                generation_id,
                event_rx,
                window,
                cx,
            );
        }
        cx.spawn(async move |this, cx| {
            let result = join
                .await
                .unwrap_or_else(|error| Err(eyre::eyre!("send generation task failed: {error}")));
            let final_stage = *terminal_progress_rx.borrow();
            let _ = this.update(cx, |root, cx| {
                let mut progress_result = None;
                let mut self_broadcast_progress_result = None;
                let mut progress_error = None;
                {
                    let Some(form) = root.send_forms.get_mut(&key) else {
                        return;
                    };
                    if form.asset.chain_id != chain_id || form.asset.token != token {
                        return;
                    }
                    if form.generation_id != generation_id || !form.generating {
                        return;
                    }
                    form.generating = false;
                    match result {
                        Ok(result) => {
                            if let SendResult::PublicBroadcaster(result) = &result {
                                progress_result = Some((**result).clone());
                            }
                            if let SendResult::SelfBroadcast(result) = &result {
                                form.self_broadcast_estimated_native_gas_cost =
                                    Some(result.estimated_native_gas_cost);
                                self_broadcast_progress_result = Some((**result).clone());
                            }
                            form.error = None;
                            form.result = Some(result);
                        }
                        Err(error) => {
                            let message = format_report_chain(&error);
                            progress_error = Some(message.clone());
                            if form_error_clears_public_broadcaster_cost_estimate(
                                DeliveryFormKind::Send,
                                message.as_str(),
                            ) {
                                form.cost_estimate = None;
                            }
                            form.result = None;
                            form.error = Some(Arc::from(message));
                        }
                    }
                }
                if let Some(result) = progress_result {
                    root.finish_private_broadcaster_progress(
                        DeliveryFormKind::Send,
                        key,
                        generation_id,
                        final_stage,
                        result,
                        cx,
                    );
                }
                if let Some(result) = self_broadcast_progress_result {
                    root.finish_private_self_broadcast_progress(
                        DeliveryFormKind::Send,
                        key,
                        generation_id,
                        final_stage,
                        result,
                        cx,
                    );
                }
                if let Some(message) = progress_error {
                    root.fail_private_broadcaster_progress(
                        DeliveryFormKind::Send,
                        key,
                        generation_id,
                        final_stage,
                        message,
                        cx,
                    );
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn watch_send_generation_stage(
        key: UnshieldAssetKey,
        generation_id: u64,
        mut progress_rx: watch::Receiver<TransactionGenerationStage>,
        window: &Window,
        cx: &Context<'_, Self>,
    ) {
        cx.spawn_in(window, async move |this, cx| {
            while progress_rx.changed().await.is_ok() {
                let stage = *progress_rx.borrow_and_update();
                if this
                    .update_in(cx, |root, window, cx| {
                        let Some(form) = root.send_forms.get_mut(&key) else {
                            if root.update_private_broadcaster_progress_stage(
                                DeliveryFormKind::Send,
                                key,
                                generation_id,
                                stage,
                                cx,
                            ) {
                                root.show_private_broadcaster_progress_dialog(window, cx);
                            }
                            return;
                        };
                        if form.generation_id != generation_id || !form.generating {
                            if root.update_private_broadcaster_progress_stage(
                                DeliveryFormKind::Send,
                                key,
                                generation_id,
                                stage,
                                cx,
                            ) {
                                root.show_private_broadcaster_progress_dialog(window, cx);
                            }
                            return;
                        }
                        form.generation_stage = stage;
                        if root.update_private_broadcaster_progress_stage(
                            DeliveryFormKind::Send,
                            key,
                            generation_id,
                            stage,
                            cx,
                        ) {
                            root.show_private_broadcaster_progress_dialog(window, cx);
                        }
                        cx.notify();
                    })
                    .is_err()
                {
                    break;
                }
            }
        })
        .detach();
    }

    pub(super) fn generate_unshield_calldata_from_form(
        &mut self,
        key: UnshieldAssetKey,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(form) = self.unshield_forms.get(&key) else {
            return;
        };
        if form.generating {
            return;
        }
        let asset = form.asset.clone();
        let unwrap = form.unwrap;
        let recipient_input = form.recipient_input.clone();
        let amount_input = form.amount_input.clone();
        let password_input = form.password_input.clone();
        let delivery_mode = form.delivery_mode;
        let broadcaster_choice = form.broadcaster_choice.clone();
        let cost_estimate = form.cost_estimate.clone();
        let fee_token = form.selected_fee_token;
        let self_broadcast_gas_payer_uuid = form.self_broadcast_gas_payer_uuid.clone();
        let self_broadcast_gas_fee = if delivery_mode == DeliveryMode::SelfBroadcast {
            match form.self_broadcast_gas_fee.selection(cx) {
                Ok(selection) => selection,
                Err(error) => {
                    self.set_unshield_form_error(key, error, cx);
                    return;
                }
            }
        } else {
            SelfBroadcastGasFeeSelection::Auto
        };
        let self_broadcast_initial_gas_fee = if delivery_mode == DeliveryMode::SelfBroadcast {
            self_broadcast_initial_gas_values(
                &self_broadcast_gas_fee,
                form.self_broadcast_gas_fee.quote,
            )
        } else {
            None
        };
        let broadcaster_fee_mode = effective_public_broadcaster_fee_mode(
            asset.token,
            fee_token,
            form.broadcaster_fee_mode,
        );
        let allow_suspicious_broadcasters = form.allow_suspicious_broadcasters;

        let Some(view_session) = self.view_session.clone() else {
            self.set_unshield_form_error(key, "Unlock the wallet vault before unshielding", cx);
            return;
        };
        let Some(vault_store) = self.vault_store.clone() else {
            self.set_unshield_form_error(key, "Wallet vault storage is unavailable", cx);
            return;
        };
        let Some(ChainUtxoState::Ready { session, .. }) = self.chain_states.get(&asset.chain_id)
        else {
            self.set_unshield_form_error(
                key,
                "Wait for wallet sync to finish before unshielding",
                cx,
            );
            return;
        };
        let session = Arc::clone(session);
        if asset.max_batched.is_zero() {
            self.set_unshield_form_error(
                key,
                "No POI-verified private notes are spendable in a batched unshield",
                cx,
            );
            return;
        }

        let recipient_raw = recipient_input.read(cx).value().to_string();
        let Some(recipient) = parse_address(recipient_raw.trim()) else {
            self.set_unshield_form_error(key, "Enter a valid public EVM recipient address", cx);
            return;
        };
        let amount_raw = amount_input.read(cx).value().to_string();
        let amount = match parse_unshield_amount(amount_raw.as_str(), asset.decimals) {
            Ok(amount) if !amount.is_zero() => amount,
            Ok(_) => {
                self.set_unshield_form_error(key, "Enter an amount greater than zero", cx);
                return;
            }
            Err(error) => {
                self.set_unshield_form_error(key, error.to_string(), cx);
                return;
            }
        };
        if amount > asset.max_batched {
            self.set_unshield_form_error(
                key,
                format!(
                    "Amount exceeds max POI-verified batched transaction: {}",
                    format_unshield_amount_input(asset.max_batched, asset.decimals)
                ),
                cx,
            );
            return;
        }

        let (self_broadcast_public_account_uuid, self_broadcast_gas_payer_display) =
            if delivery_mode == DeliveryMode::SelfBroadcast {
                let Some(uuid) = self_broadcast_gas_payer_uuid else {
                    self.set_unshield_form_error(key, "Choose a Public account to pay gas", cx);
                    return;
                };
                let Some(account) =
                    self.selected_self_broadcast_gas_payer_account(Some(uuid.as_ref()))
                else {
                    self.set_unshield_form_error(
                        key,
                        "Choose an active Public account to pay gas",
                        cx,
                    );
                    return;
                };
                let gas_payer_display = public_account_display_label(account).map_or_else(
                    || short_address(&account.address),
                    |label| format!("{label} · {}", short_address(&account.address)),
                );
                (Some(uuid.to_string()), Some(gas_payer_display))
            } else {
                (None, None)
            };

        let fee_rows = if delivery_mode == DeliveryMode::PublicBroadcaster {
            let rows = self.monitor_fee_rows();
            let policy = self.public_broadcaster_fee_policy(allow_suspicious_broadcasters);
            let public_broadcaster_selection = Self::public_broadcaster_submission_selection(
                &broadcaster_choice,
                cost_estimate.as_ref(),
            );
            let candidates = self.current_public_broadcaster_candidates(
                asset.chain_id,
                fee_token,
                unwrap,
                policy,
            );
            if let Err(error) = select_public_broadcaster_with_policy(
                &candidates,
                &public_broadcaster_selection,
                policy,
            ) {
                self.set_unshield_form_error(key, error.to_string(), cx);
                return;
            }
            rows
        } else {
            Vec::new()
        };
        let fee_policy = self.public_broadcaster_fee_policy(allow_suspicious_broadcasters);

        let password_empty = password_input.read(cx).value().trim().is_empty();
        if password_empty {
            self.set_unshield_form_error(key, UNSHIELD_MISSING_PASSWORD_ERROR, cx);
            return;
        }
        let vault_password = Self::read_and_clear_input(&password_input, window, cx);

        self.unshield_generation_seq = self.unshield_generation_seq.wrapping_add(1);
        let generation_id = self.unshield_generation_seq;
        let (progress_tx, progress_rx) = watch::channel(TransactionGenerationStage::default());
        let (self_broadcast_command_tx, self_broadcast_command_rx) =
            if delivery_mode == DeliveryMode::SelfBroadcast {
                let (tx, rx) = mpsc::unbounded_channel();
                (Some(tx), Some(rx))
            } else {
                (None, None)
            };
        let (self_broadcast_event_tx, self_broadcast_event_rx) =
            if delivery_mode == DeliveryMode::SelfBroadcast {
                let (tx, rx) = mpsc::unbounded_channel();
                (Some(tx), Some(rx))
            } else {
                (None, None)
            };
        if let Some(form) = self.unshield_forms.get_mut(&key) {
            form.generation_id = generation_id;
            form.generating = true;
            form.generation_stage = TransactionGenerationStage::default();
            form.cost_estimate_pending = false;
            form.estimating_cost = false;
            form.estimate_id = 0;
            form.self_broadcast_estimated_native_gas_cost = None;
            form.error = None;
            form.result = None;
        }
        cx.notify();

        match delivery_mode {
            DeliveryMode::PublicBroadcaster => {
                self.start_private_broadcaster_progress(
                    DeliveryFormKind::Unshield,
                    key,
                    generation_id,
                    asset.label.clone(),
                    asset.icon_path.clone(),
                    recipient.to_checksum(None),
                    cost_estimate.clone(),
                );
            }
            DeliveryMode::SelfBroadcast => {
                self.start_private_self_broadcast_progress(
                    DeliveryFormKind::Unshield,
                    key,
                    generation_id,
                    asset.label.clone(),
                    asset.icon_path.clone(),
                    recipient.to_checksum(None),
                    self_broadcast_gas_payer_display
                        .expect("self-broadcast gas payer was validated"),
                    self_broadcast_command_tx,
                    self_broadcast_initial_gas_fee,
                );
            }
            DeliveryMode::ManualCalldata => {}
        }

        let http = self.http.clone();
        let waku = Arc::clone(&self.waku);
        let chain_id = asset.chain_id;
        let token = asset.token;
        let join = match delivery_mode {
            DeliveryMode::ManualCalldata => {
                let request = DesktopUnshieldCalldataRequest {
                    chain_id,
                    effective_chain: self.effective_chain_configs.get(&chain_id).cloned(),
                    view_session,
                    session,
                    vault_store,
                    vault_password,
                    token,
                    fee_token,
                    amount,
                    recipient,
                    unwrap,
                    verify_proof: true,
                    progress_tx: Some(progress_tx),
                };
                self.runtime.spawn(async move {
                    prepare_desktop_unshield_calldata(request, &http)
                        .await
                        .map(UnshieldResult::Manual)
                })
            }
            DeliveryMode::PublicBroadcaster => {
                let request = DesktopUnshieldPublicBroadcasterRequest {
                    chain_id,
                    effective_chain: self.effective_chain_configs.get(&chain_id).cloned(),
                    view_session,
                    session,
                    vault_store,
                    vault_password,
                    token,
                    fee_token,
                    amount,
                    recipient,
                    unwrap,
                    verify_proof: true,
                    fee_rows,
                    selection: Self::public_broadcaster_submission_selection(
                        &broadcaster_choice,
                        cost_estimate.as_ref(),
                    ),
                    fee_mode: broadcaster_fee_mode,
                    fee_policy,
                    anchor_cache: Some(Arc::clone(&self.public_broadcaster_anchor_cache)),
                    waku,
                    response_timeout: self.public_broadcaster_response_timeout,
                    republish_interval: self.public_broadcaster_republish_interval,
                    progress_tx: Some(progress_tx),
                };
                self.runtime.spawn(async move {
                    submit_desktop_unshield_public_broadcaster(request, &http)
                        .await
                        .map(|result| UnshieldResult::PublicBroadcaster(Box::new(result)))
                })
            }
            DeliveryMode::SelfBroadcast => {
                let request = DesktopUnshieldSelfBroadcastRequest {
                    chain_id,
                    effective_chain: self.effective_chain_configs.get(&chain_id).cloned(),
                    view_session,
                    session,
                    vault_store,
                    vault_password,
                    public_account_uuid: self_broadcast_public_account_uuid
                        .expect("self-broadcast gas payer was validated"),
                    token,
                    fee_token,
                    amount,
                    recipient,
                    unwrap,
                    verify_proof: true,
                    gas_fee: self_broadcast_gas_fee,
                    progress_tx: Some(progress_tx),
                    command_rx: self_broadcast_command_rx,
                    event_tx: self_broadcast_event_tx,
                };
                self.runtime.spawn(async move {
                    submit_desktop_unshield_self_broadcast(request, &http)
                        .await
                        .map(|result| UnshieldResult::SelfBroadcast(Box::new(result)))
                })
            }
        };
        let terminal_progress_rx = progress_rx.clone();
        Self::watch_unshield_generation_stage(key, generation_id, progress_rx, window, cx);
        if let Some(event_rx) = self_broadcast_event_rx {
            Self::watch_self_broadcast_session_events(
                DeliveryFormKind::Unshield,
                key,
                generation_id,
                event_rx,
                window,
                cx,
            );
        }
        cx.spawn(async move |this, cx| {
            let result = join.await.unwrap_or_else(|error| {
                Err(eyre::eyre!("unshield generation task failed: {error}"))
            });
            let final_stage = *terminal_progress_rx.borrow();
            let _ = this.update(cx, |root, cx| {
                let mut progress_result = None;
                let mut self_broadcast_progress_result = None;
                let mut progress_error = None;
                {
                    let Some(form) = root.unshield_forms.get_mut(&key) else {
                        return;
                    };
                    if form.asset.chain_id != chain_id || form.asset.token != token {
                        return;
                    }
                    if form.generation_id != generation_id || !form.generating {
                        return;
                    }
                    form.generating = false;
                    match result {
                        Ok(result) => {
                            if let UnshieldResult::PublicBroadcaster(result) = &result {
                                progress_result = Some((**result).clone());
                            }
                            if let UnshieldResult::SelfBroadcast(result) = &result {
                                form.self_broadcast_estimated_native_gas_cost =
                                    Some(result.estimated_native_gas_cost);
                                self_broadcast_progress_result = Some((**result).clone());
                            }
                            form.error = None;
                            form.result = Some(result);
                        }
                        Err(error) => {
                            let message = format_report_chain(&error);
                            progress_error = Some(message.clone());
                            if form_error_clears_public_broadcaster_cost_estimate(
                                DeliveryFormKind::Unshield,
                                message.as_str(),
                            ) {
                                form.cost_estimate = None;
                            }
                            form.result = None;
                            form.error = Some(Arc::from(message));
                        }
                    }
                }
                if let Some(result) = progress_result {
                    root.finish_private_broadcaster_progress(
                        DeliveryFormKind::Unshield,
                        key,
                        generation_id,
                        final_stage,
                        result,
                        cx,
                    );
                }
                if let Some(result) = self_broadcast_progress_result {
                    root.finish_private_self_broadcast_progress(
                        DeliveryFormKind::Unshield,
                        key,
                        generation_id,
                        final_stage,
                        result,
                        cx,
                    );
                }
                if let Some(message) = progress_error {
                    root.fail_private_broadcaster_progress(
                        DeliveryFormKind::Unshield,
                        key,
                        generation_id,
                        final_stage,
                        message,
                        cx,
                    );
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn watch_unshield_generation_stage(
        key: UnshieldAssetKey,
        generation_id: u64,
        mut progress_rx: watch::Receiver<TransactionGenerationStage>,
        window: &Window,
        cx: &Context<'_, Self>,
    ) {
        cx.spawn_in(window, async move |this, cx| {
            while progress_rx.changed().await.is_ok() {
                let stage = *progress_rx.borrow_and_update();
                if this
                    .update_in(cx, |root, window, cx| {
                        let Some(form) = root.unshield_forms.get_mut(&key) else {
                            if root.update_private_broadcaster_progress_stage(
                                DeliveryFormKind::Unshield,
                                key,
                                generation_id,
                                stage,
                                cx,
                            ) {
                                root.show_private_broadcaster_progress_dialog(window, cx);
                            }
                            return;
                        };
                        if form.generation_id != generation_id || !form.generating {
                            if root.update_private_broadcaster_progress_stage(
                                DeliveryFormKind::Unshield,
                                key,
                                generation_id,
                                stage,
                                cx,
                            ) {
                                root.show_private_broadcaster_progress_dialog(window, cx);
                            }
                            return;
                        }
                        form.generation_stage = stage;
                        if root.update_private_broadcaster_progress_stage(
                            DeliveryFormKind::Unshield,
                            key,
                            generation_id,
                            stage,
                            cx,
                        ) {
                            root.show_private_broadcaster_progress_dialog(window, cx);
                        }
                        cx.notify();
                    })
                    .is_err()
                {
                    break;
                }
            }
        })
        .detach();
    }

    fn watch_self_broadcast_session_events(
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        generation_id: u64,
        mut event_rx: mpsc::UnboundedReceiver<SelfBroadcastSessionEvent>,
        window: &Window,
        cx: &Context<'_, Self>,
    ) {
        cx.spawn_in(window, async move |this, cx| {
            while let Some(event) = event_rx.recv().await {
                let _ = this.update_in(cx, |root, window, cx| match event {
                    SelfBroadcastSessionEvent::StepFailed { stage, message } => {
                        if root.record_private_broadcaster_progress_step_error(
                            kind,
                            key,
                            generation_id,
                            stage,
                            &message,
                            cx,
                        ) {
                            root.show_private_broadcaster_progress_dialog(window, cx);
                        }
                    }
                    SelfBroadcastSessionEvent::AttemptSubmitted(attempt) => {
                        root.record_private_self_broadcast_attempt(
                            kind,
                            key,
                            generation_id,
                            attempt,
                            cx,
                        );
                    }
                    SelfBroadcastSessionEvent::AttemptRejected { message, .. } => {
                        root.record_private_self_broadcast_attempt_rejected(
                            kind,
                            key,
                            generation_id,
                            message,
                            cx,
                        );
                    }
                });
            }
        })
        .detach();
    }

    pub(super) fn render_send_form(&self, root: Entity<Self>, key: UnshieldAssetKey) -> gpui::Div {
        let Some(form) = self.send_forms.get(&key) else {
            return div();
        };
        let asset = &form.asset;
        let unit_hint = if asset.decimals.is_some() {
            format!("{} amount", asset.label)
        } else {
            "Raw base units for this unknown token".to_string()
        };
        let delivery_root = root.clone();
        let metrics_root = root.clone();
        let chooser_root = root.clone();
        let estimate_root = root.clone();
        let progress_root = root.clone();
        let submit_root = root;
        let self_broadcast_accounts = self.active_self_broadcast_gas_payer_accounts();
        let mut public_broadcaster_submit_disabled = false;
        let mut self_broadcast_submit_disabled = false;
        let public_broadcaster_submitted = matches!(
            form.result.as_ref(),
            Some(SendResult::PublicBroadcaster(result))
                if matches!(result.result, PublicBroadcasterResultKind::Submitted { .. })
        );
        let self_broadcast_submitted =
            matches!(form.result.as_ref(), Some(SendResult::SelfBroadcast(_)));
        let submitted = public_broadcaster_submitted || self_broadcast_submitted;

        let mut card =
            div()
                .w_full()
                .flex()
                .flex_col()
                .gap_3()
                .child(render_private_action_metrics(
                    metrics_root,
                    key,
                    DeliveryFormKind::Send,
                    asset,
                    form.generating,
                ));

        if asset.total > asset.max_batched {
            card = card.child(Alert::warning(
                send_element_id(key, "spend-capacity-warning"),
                "Spend capacity is limited by private note fragmentation and POI verification status. One send can spend up to 8 proof chunks.",
            ).small());
        }

        card = card.child(render_delivery_selector(
            delivery_root,
            key,
            DeliveryFormKind::Send,
            form.delivery_mode,
            form.generating,
            !self_broadcast_accounts.is_empty(),
        ));
        if form.delivery_mode == DeliveryMode::PublicBroadcaster {
            let policy = self.public_broadcaster_fee_policy(form.allow_suspicious_broadcasters);
            let fee_rows = self.monitor_fee_rows();
            let fee_token_options =
                self.current_public_broadcaster_fee_token_options(asset.chain_id, false, policy);
            public_broadcaster_submit_disabled =
                public_broadcaster_submit_disabled_for_fee_token_options(
                    &fee_token_options,
                    form.selected_fee_token,
                );
            let candidates = self.current_public_broadcaster_candidates(
                asset.chain_id,
                form.selected_fee_token,
                false,
                policy,
            );
            let visible_candidates = fee_policy_eligible_public_broadcasters(&candidates, policy);
            if let Some(warning) = public_broadcaster_fee_token_warning(
                &fee_rows,
                asset.chain_id,
                &fee_token_options,
                form.selected_fee_token,
            ) {
                card = card.child(
                    Alert::warning(
                        delivery_element_id(key, DeliveryFormKind::Send, "fee-token-warning"),
                        warning,
                    )
                    .small(),
                );
            }
            card = card.child(render_public_broadcaster_settings(
                chooser_root,
                key,
                DeliveryFormKind::Send,
                form.allow_suspicious_broadcasters,
                asset.token,
                form.broadcaster_fee_mode,
                &form.broadcaster_choice,
                visible_candidates,
                &fee_token_options,
                form.selected_fee_token,
                form.generating,
            ));
            if let Some(warning) = selected_broadcaster_fee_warning(
                &form.broadcaster_choice,
                &candidates,
                form.allow_suspicious_broadcasters,
            ) {
                card = card.child(
                    Alert::warning(
                        delivery_element_id(key, DeliveryFormKind::Send, "fee-policy-warning"),
                        warning,
                    )
                    .small(),
                );
            }
        } else if form.delivery_mode == DeliveryMode::SelfBroadcast {
            self_broadcast_submit_disabled = form
                .self_broadcast_gas_payer_uuid
                .as_deref()
                .and_then(|uuid| self.selected_self_broadcast_gas_payer_account(Some(uuid)))
                .is_none();
            card = card.child(render_self_broadcast_settings(
                chooser_root,
                key,
                DeliveryFormKind::Send,
                &self_broadcast_accounts,
                form.self_broadcast_gas_payer_uuid.as_deref(),
                self.public_balance_snapshot.as_deref(),
                &form.self_broadcast_gas_payer_select,
                &form.self_broadcast_gas_fee,
                form.generating,
            ));
        }

        card = card
            .child(
                div()
                    .flex()
                    .items_end()
                    .gap_3()
                    .child(
                        labeled_field(
                            "Recipient 0zk address",
                            private_action_input(&form.recipient_input).disabled(form.generating),
                        )
                        .flex_1()
                        .min_w(px(0.0)),
                    )
                    .child(
                        labeled_field(
                            unit_hint,
                            private_action_input(&form.amount_input).disabled(form.generating),
                        )
                        .w(px(220.0)),
                    ),
            )
            .child(
                div()
                    .flex()
                    .items_end()
                    .gap_3()
                    .child(
                        labeled_field(
                            "Vault password",
                            private_action_input(&form.password_input).disabled(form.generating),
                        )
                        .flex_1()
                        .min_w(px(0.0)),
                    )
                    .child(
                        app_button(
                            send_element_id(key, "generate"),
                            if form.generating {
                                "Preparing..."
                            } else if submitted {
                                "Submitted"
                            } else if form.delivery_mode == DeliveryMode::PublicBroadcaster {
                                "Submit via broadcaster"
                            } else if form.delivery_mode == DeliveryMode::SelfBroadcast {
                                "Self-broadcast"
                            } else {
                                "Generate calldata"
                            },
                        )
                        .primary()
                        .loading(form.generating)
                        .disabled(
                            form.generating
                                || public_broadcaster_submit_disabled
                                || self_broadcast_submit_disabled
                                || submitted,
                        )
                        .on_click(move |_event, window, cx| {
                            submit_root.update(cx, |root, cx| {
                                root.generate_send_calldata_from_form(key, window, cx);
                            });
                        }),
                    ),
            );

        if should_render_public_broadcaster_cost_preview(
            form.delivery_mode,
            form.result.is_some(),
            form.error.is_some(),
        ) {
            if let Some(estimate) = form.cost_estimate.as_ref() {
                let anchor_rate = self
                    .public_broadcaster_anchor_cache
                    .cached_rate(asset.chain_id, estimate.fee_token);
                card = card.child(render_public_broadcaster_cost_estimate(
                    estimate_root,
                    key,
                    DeliveryFormKind::Send,
                    asset,
                    estimate,
                    anchor_rate,
                    Some(&self.effective_token_registry),
                    form.transaction_fee_breakdown_open,
                    form.estimating_cost,
                ));
            } else if let Some(status) =
                public_broadcaster_cost_status(form.cost_estimate_pending, form.estimating_cost)
            {
                card = card.child(render_public_broadcaster_cost_status(
                    self.unshield_spinner_tick,
                    status,
                ));
            }
        }

        if form.generating
            && matches!(
                form.delivery_mode,
                DeliveryMode::PublicBroadcaster | DeliveryMode::SelfBroadcast
            )
            && let Some((flow, stage)) = private_broadcaster_closed_active_progress(
                self.private_broadcaster_progress.as_ref(),
                DeliveryFormKind::Send,
                key,
                form.generation_id,
            )
        {
            card = card.child(render_private_submission_active_status_notice(
                progress_root.clone(),
                key,
                DeliveryFormKind::Send,
                flow,
                stage,
            ));
        }

        if form.generating && form.delivery_mode == DeliveryMode::ManualCalldata {
            card = card.child(render_unshield_generating_status(
                self.unshield_spinner_tick,
                form.generation_stage,
            ));
        }

        if let Some(error) = form.error.as_ref() {
            card = card.child(
                Alert::error(
                    send_element_id(key, "form-error"),
                    format_form_error_for_asset(
                        error,
                        asset,
                        form.selected_fee_token,
                        Some(&self.effective_token_registry),
                    ),
                )
                .small(),
            );
        }

        if let Some(result) = form.result.as_ref() {
            match result {
                SendResult::Manual(result) => {
                    card = card.child(render_send_result(key, result));
                }
                SendResult::PublicBroadcaster(result) => {
                    card = card.child(render_private_broadcaster_status_notice(
                        progress_root,
                        key,
                        DeliveryFormKind::Send,
                        &result.result,
                    ));
                }
                SendResult::SelfBroadcast(result) => {
                    card = card.child(div().flex().flex_col().gap_2().child(
                        render_private_self_broadcast_status_notice(
                            progress_root,
                            key,
                            DeliveryFormKind::Send,
                            result,
                        ),
                    ));
                }
            }
        }

        card
    }

    pub(super) fn render_unshield_form(
        &self,
        root: Entity<Self>,
        key: UnshieldAssetKey,
    ) -> gpui::Div {
        let Some(form) = self.unshield_forms.get(&key) else {
            return div();
        };
        let asset = &form.asset;
        let unwrap_supported = is_effective_wrapped_native_token(
            &self.effective_chain_configs,
            asset.chain_id,
            asset.token,
        );
        let unit_hint = if asset.decimals.is_some() {
            format!("{} amount", asset.label)
        } else {
            "Raw base units for this unknown token".to_string()
        };
        let delivery_root = root.clone();
        let metrics_root = root.clone();
        let chooser_root = root.clone();
        let output_root = root.clone();
        let estimate_root = root.clone();
        let progress_root = root.clone();
        let submit_root = root;
        let self_broadcast_accounts = self.active_self_broadcast_gas_payer_accounts();
        let mut public_broadcaster_submit_disabled = false;
        let mut self_broadcast_submit_disabled = false;
        let public_broadcaster_submitted = matches!(
            form.result.as_ref(),
            Some(UnshieldResult::PublicBroadcaster(result))
                if matches!(result.result, PublicBroadcasterResultKind::Submitted { .. })
        );
        let self_broadcast_submitted =
            matches!(form.result.as_ref(), Some(UnshieldResult::SelfBroadcast(_)));
        let submitted = public_broadcaster_submitted || self_broadcast_submitted;

        let mut card =
            div()
                .w_full()
                .flex()
                .flex_col()
                .gap_3()
                .child(render_private_action_metrics(
                    metrics_root,
                    key,
                    DeliveryFormKind::Unshield,
                    asset,
                    form.generating,
                ));

        if asset.total > asset.max_batched {
            card = card.child(Alert::warning(
                unshield_element_id(key, "spend-capacity-warning"),
                "Spend capacity is limited by private note fragmentation and POI verification status.",
            ).small());
        }

        card = card.child(render_delivery_selector(
            delivery_root,
            key,
            DeliveryFormKind::Unshield,
            form.delivery_mode,
            form.generating,
            !self_broadcast_accounts.is_empty(),
        ));
        if form.delivery_mode == DeliveryMode::PublicBroadcaster {
            let policy = self.public_broadcaster_fee_policy(form.allow_suspicious_broadcasters);
            let fee_rows = self.monitor_fee_rows();
            let fee_token_options = self.current_public_broadcaster_fee_token_options(
                asset.chain_id,
                form.unwrap,
                policy,
            );
            public_broadcaster_submit_disabled =
                public_broadcaster_submit_disabled_for_fee_token_options(
                    &fee_token_options,
                    form.selected_fee_token,
                );
            let candidates = self.current_public_broadcaster_candidates(
                asset.chain_id,
                form.selected_fee_token,
                form.unwrap,
                policy,
            );
            let visible_candidates = fee_policy_eligible_public_broadcasters(&candidates, policy);
            if let Some(warning) = public_broadcaster_fee_token_warning(
                &fee_rows,
                asset.chain_id,
                &fee_token_options,
                form.selected_fee_token,
            ) {
                card = card.child(
                    Alert::warning(
                        delivery_element_id(key, DeliveryFormKind::Unshield, "fee-token-warning"),
                        warning,
                    )
                    .small(),
                );
            }
            card = card.child(render_public_broadcaster_settings(
                chooser_root,
                key,
                DeliveryFormKind::Unshield,
                form.allow_suspicious_broadcasters,
                asset.token,
                form.broadcaster_fee_mode,
                &form.broadcaster_choice,
                visible_candidates,
                &fee_token_options,
                form.selected_fee_token,
                form.generating,
            ));
            if let Some(warning) = selected_broadcaster_fee_warning(
                &form.broadcaster_choice,
                &candidates,
                form.allow_suspicious_broadcasters,
            ) {
                card = card.child(
                    Alert::warning(
                        delivery_element_id(key, DeliveryFormKind::Unshield, "fee-policy-warning"),
                        warning,
                    )
                    .small(),
                );
            }
        } else if form.delivery_mode == DeliveryMode::SelfBroadcast {
            self_broadcast_submit_disabled = form
                .self_broadcast_gas_payer_uuid
                .as_deref()
                .and_then(|uuid| self.selected_self_broadcast_gas_payer_account(Some(uuid)))
                .is_none();
            card = card.child(render_self_broadcast_settings(
                chooser_root,
                key,
                DeliveryFormKind::Unshield,
                &self_broadcast_accounts,
                form.self_broadcast_gas_payer_uuid.as_deref(),
                self.public_balance_snapshot.as_deref(),
                &form.self_broadcast_gas_payer_select,
                &form.self_broadcast_gas_fee,
                form.generating,
            ));
        }

        card = card
            .child(
                div()
                    .flex()
                    .items_end()
                    .gap_3()
                    .child(
                        labeled_field(
                            "Recipient",
                            private_action_input(&form.recipient_input).disabled(form.generating),
                        )
                        .flex_1()
                        .min_w(px(0.0)),
                    )
                    .children(unwrap_supported.then(|| {
                        render_unshield_output_toggle(
                            output_root.clone(),
                            key,
                            asset.chain_id,
                            form.unwrap,
                            form.generating,
                        )
                    }))
                    .child(
                        labeled_field(
                            unit_hint,
                            private_action_input(&form.amount_input).disabled(form.generating),
                        )
                        .w(px(220.0)),
                    ),
            )
            .child(
                div()
                    .flex()
                    .items_end()
                    .gap_3()
                    .child(
                        labeled_field(
                            "Vault password",
                            private_action_input(&form.password_input).disabled(form.generating),
                        )
                        .flex_1()
                        .min_w(px(0.0)),
                    )
                    .child(
                        app_button(
                            unshield_element_id(key, "generate"),
                            if form.generating {
                                "Preparing..."
                            } else if submitted {
                                "Submitted"
                            } else if form.delivery_mode == DeliveryMode::PublicBroadcaster {
                                "Submit via broadcaster"
                            } else if form.delivery_mode == DeliveryMode::SelfBroadcast {
                                "Self-broadcast"
                            } else {
                                "Generate calldata"
                            },
                        )
                        .primary()
                        .loading(form.generating)
                        .disabled(
                            form.generating
                                || public_broadcaster_submit_disabled
                                || self_broadcast_submit_disabled
                                || submitted,
                        )
                        .on_click(move |_event, window, cx| {
                            submit_root.update(cx, |root, cx| {
                                root.generate_unshield_calldata_from_form(key, window, cx);
                            });
                        }),
                    ),
            );

        if should_render_public_broadcaster_cost_preview(
            form.delivery_mode,
            form.result.is_some(),
            form.error.is_some(),
        ) {
            if let Some(estimate) = form.cost_estimate.as_ref() {
                let anchor_rate = self
                    .public_broadcaster_anchor_cache
                    .cached_rate(asset.chain_id, estimate.fee_token);
                card = card.child(render_public_broadcaster_cost_estimate(
                    estimate_root,
                    key,
                    DeliveryFormKind::Unshield,
                    asset,
                    estimate,
                    anchor_rate,
                    Some(&self.effective_token_registry),
                    form.transaction_fee_breakdown_open,
                    form.estimating_cost,
                ));
            } else if let Some(status) =
                public_broadcaster_cost_status(form.cost_estimate_pending, form.estimating_cost)
            {
                card = card.child(render_public_broadcaster_cost_status(
                    self.unshield_spinner_tick,
                    status,
                ));
            }
        }

        if form.generating
            && matches!(
                form.delivery_mode,
                DeliveryMode::PublicBroadcaster | DeliveryMode::SelfBroadcast
            )
            && let Some((flow, stage)) = private_broadcaster_closed_active_progress(
                self.private_broadcaster_progress.as_ref(),
                DeliveryFormKind::Unshield,
                key,
                form.generation_id,
            )
        {
            card = card.child(render_private_submission_active_status_notice(
                progress_root.clone(),
                key,
                DeliveryFormKind::Unshield,
                flow,
                stage,
            ));
        }

        if form.generating && form.delivery_mode == DeliveryMode::ManualCalldata {
            card = card.child(render_unshield_generating_status(
                self.unshield_spinner_tick,
                form.generation_stage,
            ));
        }

        if let Some(error) = form.error.as_ref() {
            card = card.child(
                Alert::error(
                    unshield_element_id(key, "form-error"),
                    format_form_error_for_asset(
                        error,
                        asset,
                        form.selected_fee_token,
                        Some(&self.effective_token_registry),
                    ),
                )
                .small(),
            );
        }

        if let Some(result) = form.result.as_ref() {
            match result {
                UnshieldResult::Manual(result) => {
                    card = card.child(render_unshield_result(key, result));
                }
                UnshieldResult::PublicBroadcaster(result) => {
                    card = card.child(render_private_broadcaster_status_notice(
                        progress_root,
                        key,
                        DeliveryFormKind::Unshield,
                        &result.result,
                    ));
                }
                UnshieldResult::SelfBroadcast(result) => {
                    card = card.child(div().flex().flex_col().gap_2().child(
                        render_private_self_broadcast_status_notice(
                            progress_root,
                            key,
                            DeliveryFormKind::Unshield,
                            result,
                        ),
                    ));
                }
            }
        }

        card
    }
}

fn render_fee_token_selector(
    root: Entity<WalletRoot>,
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    options: &[PublicBroadcasterFeeTokenOption],
    selected_fee_token: Address,
    generating: bool,
) -> gpui::Div {
    let selected_option = options
        .iter()
        .find(|option| option.token == selected_fee_token)
        .cloned();
    let options = options.to_vec();
    div()
        .flex()
        .items_center()
        .justify_between()
        .gap_3()
        .child(
            div()
                .min_w(px(0.0))
                .child(app_muted_text("Broadcaster fee token")),
        )
        .child(
            Popover::new(delivery_element_id(key, kind, "fee-token-selector"))
                .trigger(
                    Button::new(delivery_element_id(key, kind, "fee-token-selector-trigger"))
                        .outline()
                        .child(fee_token_selector_trigger_row(
                            selected_option.as_ref(),
                            selected_fee_token,
                        ))
                        .dropdown_caret(true)
                        .disabled(generating || options.is_empty()),
                )
                .content(move |_state, window, cx| {
                    let popover = cx.entity();
                    render_fee_token_selector_menu(
                        &root,
                        &popover,
                        key,
                        kind,
                        &options,
                        selected_fee_token,
                        window,
                    )
                }),
        )
}

fn render_fee_token_selector_menu(
    root: &Entity<WalletRoot>,
    popover: &Entity<gpui_component::popover::PopoverState>,
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    options: &[PublicBroadcasterFeeTokenOption],
    selected_fee_token: Address,
    _window: &mut Window,
) -> gpui::Div {
    div()
        .flex()
        .flex_col()
        .gap_1()
        .w(px(260.0))
        .children(options.iter().map(|option| {
            let selector_root = root.clone();
            let popover = popover.clone();
            let token = option.token;
            let selected = token == selected_fee_token;
            let disabled = option.eligible_broadcaster_count == 0;
            div()
                .id(fee_token_element_id(key, kind, token))
                .w_full()
                .p(px(8.0))
                .rounded_sm()
                .text_color(rgb(if selected {
                    theme::PRIMARY_FOREGROUND
                } else {
                    theme::TEXT
                }))
                .opacity(if disabled { 0.5 } else { 1.0 })
                .when(selected, |this| this.bg(rgb(theme::PRIMARY)))
                .when(!disabled && !selected, |this| {
                    this.cursor_pointer()
                        .hover(|this| this.bg(rgb(theme::SURFACE_HOVER)))
                })
                .when(!disabled, |this| {
                    this.on_mouse_down(MouseButton::Left, move |_, window, cx| {
                        cx.stop_propagation();
                        popover.update(cx, |state, cx| state.dismiss(window, cx));
                        selector_root.update(cx, |root, cx| match kind {
                            DeliveryFormKind::Send => root.set_send_fee_token(key, token, cx),
                            DeliveryFormKind::Unshield => {
                                root.set_unshield_fee_token(key, token, cx);
                            }
                        });
                    })
                })
                .child(fee_token_option_label_row(option, px(18.0)))
        }))
}

fn fee_token_element_id(
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    token: Address,
) -> SharedString {
    let action = format!("fee-token-{}", token.to_checksum(None));
    delivery_element_id(key, kind, &action)
}

fn fee_token_option_button_label(option: &PublicBroadcasterFeeTokenOption) -> String {
    format!(
        "{} · {}",
        option.label,
        broadcaster_count_label(option.eligible_broadcaster_count)
    )
}

fn fee_token_selector_trigger_row(
    option: Option<&PublicBroadcasterFeeTokenOption>,
    selected_fee_token: Address,
) -> gpui::Div {
    option.map_or_else(
        || {
            div()
                .flex()
                .items_center()
                .gap_1()
                .child(SharedString::from(short_address(&selected_fee_token)))
        },
        |option| fee_token_option_label_row(option, px(16.0)),
    )
}

fn fee_token_option_label_row(
    option: &PublicBroadcasterFeeTokenOption,
    icon_size: Pixels,
) -> gpui::Div {
    token_label_row(
        SharedString::from(fee_token_option_button_label(option)),
        option.icon_path.clone(),
        icon_size,
    )
}

fn broadcaster_count_label(count: usize) -> String {
    match count {
        0 => "no broadcasters".to_string(),
        1 => "1 broadcaster".to_string(),
        count => format!("{count} broadcasters"),
    }
}

fn render_broadcaster_fee_mode_toggle(
    root: Entity<WalletRoot>,
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    mode: PublicBroadcasterFeeMode,
    generating: bool,
) -> gpui::Div {
    let selector_root = root;
    div()
        .flex()
        .items_center()
        .justify_between()
        .gap_3()
        .child(div().min_w(px(0.0)).child(app_muted_text("Broadcaster fee")))
        .child(
            div().flex_none().child(
                ButtonGroup::new(delivery_element_id(key, kind, "fee-mode-toggle"))
                    .outline()
                    .compact()
                    .disabled(generating)
                    .child(fee_mode_segment_button(
                        delivery_element_id(key, kind, "fee-mode-deduct"),
                        delivery_element_id(key, kind, "fee-mode-deduct-info"),
                        "Deduct fee from amount",
                        "Recipient receives the entered amount minus the broadcaster fee.",
                        mode == PublicBroadcasterFeeMode::DeductFromAmount,
                    ))
                    .child(fee_mode_segment_button(
                        delivery_element_id(key, kind, "fee-mode-add"),
                        delivery_element_id(key, kind, "fee-mode-add-info"),
                        "Add fee on top",
                        "Recipient receives the full entered amount; broadcaster fee is added to spend.",
                        mode == PublicBroadcasterFeeMode::AddToAmount,
                    ))
                    .on_click(move |selected, window, cx| {
                        let Some(index) = selected.first() else {
                            return;
                        };
                        let mode = if *index == 0 {
                            PublicBroadcasterFeeMode::DeductFromAmount
                        } else {
                            PublicBroadcasterFeeMode::AddToAmount
                        };
                        selector_root.update(cx, |root, cx| match kind {
                            DeliveryFormKind::Send => {
                                root.set_send_broadcaster_fee_mode(key, mode, window, cx);
                            }
                            DeliveryFormKind::Unshield => {
                                root.set_unshield_broadcaster_fee_mode(key, mode, window, cx);
                            }
                        });
                    }),
            ),
        )
}

fn fee_mode_segment_button(
    id: SharedString,
    info_id: SharedString,
    label: &'static str,
    tooltip: &'static str,
    selected: bool,
) -> Button {
    Button::new(id).selected(selected).child(
        div()
            .flex()
            .items_center()
            .justify_center()
            .gap_1()
            .text_size(APP_TEXT_SIZE)
            .child(label)
            .child(render_fee_mode_info_icon(info_id, tooltip)),
    )
}

fn render_fee_mode_info_icon(id: SharedString, tooltip: &'static str) -> Button {
    Button::new(id)
        .text()
        .xsmall()
        .compact()
        .icon(IconName::Info)
        .text_color(rgb(theme::TEXT_MUTED))
        .tooltip(tooltip)
}

fn private_action_segment_button(id: SharedString, label: &'static str, selected: bool) -> Button {
    private_action_segment_button_with_accessory(id, label, selected, None)
}

fn private_action_segment_button_with_accessory(
    id: SharedString,
    label: &'static str,
    selected: bool,
    accessory: Option<gpui::AnyElement>,
) -> Button {
    let button = app_button_base(id)
        .flex_1()
        .min_w(px(0.0))
        .selected(selected)
        .child(
            div()
                .flex()
                .items_center()
                .justify_center()
                .gap_1()
                .child(app_button_label(label))
                .children(accessory),
        );
    if selected { button.primary() } else { button }
}

fn render_self_broadcast_privacy_icon(id: SharedString, selected: bool) -> gpui::AnyElement {
    let color = if selected {
        theme::PRIMARY_FOREGROUND
    } else {
        theme::WARNING
    };
    Button::new(id)
        .text()
        .xsmall()
        .compact()
        .icon(IconName::TriangleAlert)
        .text_color(rgb(color))
        .tooltip(SELF_BROADCAST_PRIVACY_WARNING)
        .into_any_element()
}

fn render_self_broadcast_gas_payer_warning_icon(id: SharedString) -> gpui::AnyElement {
    Button::new(id)
        .text()
        .xsmall()
        .compact()
        .icon(IconName::TriangleAlert)
        .text_color(rgb(theme::DANGER))
        .tooltip(SELF_BROADCAST_ZERO_GAS_PAYER_WARNING)
        .into_any_element()
}

pub(super) fn render_send_result(key: UnshieldAssetKey, result: &PreparedSendCall) -> gpui::Div {
    div()
        .flex()
        .flex_col()
        .gap_2()
        .p(px(12.0))
        .rounded_md()
        .bg(rgb(theme::SURFACE_ELEVATED))
        .border_1()
        .border_color(rgb(theme::SUCCESS))
        .child(app_strong_text("Prepared send calldata"))
        .child(app_muted_text(
            "Submit this transaction externally. The wallet has not broadcast it.",
        ))
        .child(render_unshield_copy_field(
            "To",
            result.to.to_checksum(None),
            send_element_id(key, "copy-to"),
        ))
        .child(render_unshield_copy_field(
            "Calldata",
            result.data.clone(),
            send_element_id(key, "copy-data"),
        ))
}

pub(super) fn render_unshield_result(
    key: UnshieldAssetKey,
    result: &PreparedUnshieldCall,
) -> gpui::Div {
    div()
        .flex()
        .flex_col()
        .gap_2()
        .p(px(12.0))
        .rounded_md()
        .bg(rgb(theme::SURFACE_ELEVATED))
        .border_1()
        .border_color(rgb(theme::SUCCESS))
        .child(app_strong_text("Prepared calldata"))
        .child(app_muted_text(
            "Submit this transaction externally. The wallet has not broadcast it.",
        ))
        .child(render_unshield_copy_field(
            "To",
            result.to.to_checksum(None),
            unshield_element_id(key, "copy-to"),
        ))
        .child(render_unshield_copy_field(
            "Calldata",
            result.data.clone(),
            unshield_element_id(key, "copy-data"),
        ))
}

fn render_unshield_copy_field(
    label: &'static str,
    value: String,
    button_id: SharedString,
) -> gpui::Div {
    div()
        .flex()
        .items_start()
        .gap_2()
        .child(
            div()
                .w(px(72.0))
                .flex_none()
                .text_color(rgb(theme::TEXT_MUTED))
                .child(label),
        )
        .child(
            div()
                .flex_1()
                .min_w(px(0.0))
                .p(px(8.0))
                .rounded_sm()
                .bg(rgb(theme::BACKGROUND))
                .border_1()
                .border_color(rgb(theme::BORDER))
                .font_family(APP_FONT_FAMILY)
                .text_size(APP_TEXT_SIZE)
                .child(SharedString::from(value.clone())),
        )
        .child(clipboard_with_toast(button_id, value))
}
