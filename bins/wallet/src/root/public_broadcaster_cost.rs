use std::sync::Arc;

use alloy::primitives::{Address, U256};
use gpui::{
    Context, Entity, InteractiveElement, IntoElement, ParentElement, SharedString,
    StatefulInteractiveElement, Styled, div, img, prelude::FluentBuilder as _, px, rgb,
};
use gpui_component::{
    Icon, IconName, Sizable, collapsible::Collapsible, spinner::Spinner, tooltip::Tooltip,
};
use railgun_ui::{format_token_amount, lookup_token};
use ui::clipboard::clipboard_with_toast;
use ui::controls::{app_muted_text, app_strong_text};
use ui::icons;
use ui::theme::{self, APP_FONT_FAMILY, APP_TEXT_SIZE};
use wallet_ops::{
    DesktopSendPublicBroadcasterEstimateRequest, DesktopUnshieldPublicBroadcasterEstimateRequest,
    FeeHandlingMode, PublicBroadcasterCandidate, PublicBroadcasterCostEstimate,
    PublicBroadcasterFeeBreakdown, PublicBroadcasterFeeMargin, PublicBroadcasterSubmissionResult,
    estimate_desktop_send_public_broadcaster_cost,
    estimate_desktop_unshield_public_broadcaster_cost, fixed_token_anchor_rate, parse_send_amount,
    parse_unshield_amount, public_broadcaster_fee_breakdown, public_broadcaster_service_gas_price,
    select_public_broadcaster_with_policy, settings::EffectiveTokenRegistry,
};

use super::broadcaster_picker::broadcaster_candidate_label;
use super::private_action::{
    delivery_element_id, send_public_broadcaster_estimate_input_error,
    unshield_public_broadcaster_estimate_input_error,
};
use super::private_broadcaster::PrivateBroadcasterProgressState;
use super::{
    COST_ESTIMATE_DEBOUNCE, ChainUtxoState, DeliveryFormKind, DeliveryMode, UnshieldAsset,
    UnshieldAssetKey, WalletRoot, broadcaster_candidate_anchor_rate, effective_fee_handling_mode,
    format_exact_token_amount_for_display, format_native_token_amount_for_display,
    format_report_chain, format_send_amount_input, should_show_distinct_amount,
};

const COST_ESTIMATE_DETAIL_TEXT_SIZE: gpui::Pixels = px(12.0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CostEstimateStatus {
    Estimating,
}

pub(super) struct PublicBroadcasterCostDisplay<'a> {
    pub(super) broadcaster: &'a PublicBroadcasterCandidate,
    registry: Option<&'a EffectiveTokenRegistry>,
    pub(super) chain_id: u64,
    pub(super) action_token: Address,
    fee_token: Address,
    pub(super) entered_amount: U256,
    receiver_amount: U256,
    pub(super) recipient_amount: U256,
    pub(super) total_private_spend: U256,
    fee_amount: U256,
    protocol_fee_amount: U256,
    pub(super) protocol_fee_bps: U256,
    fee_mode: FeeHandlingMode,
    gas_limit: u64,
    min_gas_price: u128,
    fee_anchor_rate: Option<U256>,
}

pub(super) struct PrivateBroadcasterProgressContext<'a> {
    pub(super) display: PublicBroadcasterCostDisplay<'a>,
    pub(super) settled: bool,
}

pub(super) fn format_public_broadcaster_fee_margin(
    chain_id: u64,
    fee_token: Address,
    margin: PublicBroadcasterFeeMargin,
    registry: Option<&EffectiveTokenRegistry>,
) -> String {
    match margin {
        PublicBroadcasterFeeMargin::Zero => {
            format_exact_token_amount_for_display(chain_id, fee_token, U256::ZERO, registry)
        }
        PublicBroadcasterFeeMargin::Positive(amount) => {
            format_exact_token_amount_for_display(chain_id, fee_token, amount, registry)
        }
        PublicBroadcasterFeeMargin::Negative(amount) => {
            format!(
                "-{}",
                format_exact_token_amount_for_display(chain_id, fee_token, amount, registry)
            )
        }
    }
}

pub(super) const fn should_render_public_broadcaster_cost_preview(
    delivery_mode: DeliveryMode,
    has_result: bool,
    has_error: bool,
) -> bool {
    matches!(delivery_mode, DeliveryMode::PublicBroadcaster) && !has_result && !has_error
}

fn format_gwei(wei: u128) -> String {
    format_token_amount(U256::from(wei), 9)
}

fn fee_handling_mode_summary(
    chain_id: u64,
    action_token: Address,
    fee_token: Address,
    fee_mode: FeeHandlingMode,
    entered_amount: U256,
    receiver_amount: U256,
    protocol_fee_amount: U256,
    fee_amount: U256,
    broadcaster: &PublicBroadcasterCandidate,
    registry: Option<&EffectiveTokenRegistry>,
) -> String {
    if action_token != fee_token {
        let fee_text =
            format_exact_token_amount_for_display(chain_id, fee_token, fee_amount, registry);
        if protocol_fee_amount.is_zero() {
            return format!(
                "Recipient receives the full entered amount; transaction fee is paid separately as {fee_text}."
            );
        }
        let protocol_text = format_exact_token_amount_for_display(
            chain_id,
            action_token,
            protocol_fee_amount,
            registry,
        );
        return match fee_mode {
            FeeHandlingMode::AddToAmount => format!(
                "Recipient receives the entered amount; {protocol_text} RAILGUN protocol fee is added to spend. Transaction fee is paid separately as {fee_text}."
            ),
            FeeHandlingMode::DeductFromAmount => format!(
                "Recipient receives the entered amount minus {protocol_text} RAILGUN protocol fee; transaction fee is paid separately as {fee_text}."
            ),
        };
    }
    match fee_mode {
        FeeHandlingMode::AddToAmount => {
            if protocol_fee_amount.is_zero() {
                "Recipient receives the full entered amount; transaction fee is added to spend."
                    .to_string()
            } else {
                "Recipient receives the entered amount; transaction fee and RAILGUN protocol fee are added to spend."
                    .to_string()
            }
        }
        FeeHandlingMode::DeductFromAmount => {
            let reduction = entered_amount.saturating_sub(receiver_amount);
            if reduction.is_zero() && protocol_fee_amount.is_zero() {
                "Recipient receives the entered amount because the transaction fee is zero."
                    .to_string()
            } else if protocol_fee_amount.is_zero() {
                format!(
                    "Recipient amount is reduced by {} because transaction fee is paid from the entered amount.",
                    format_exact_candidate_token_amount(broadcaster, reduction)
                )
            } else if reduction.is_zero() {
                format!(
                    "Recipient amount is reduced by {} RAILGUN protocol fee.",
                    format_exact_candidate_token_amount(broadcaster, protocol_fee_amount)
                )
            } else {
                format!(
                    "Recipient amount is reduced by {} transaction fee and {} RAILGUN protocol fee.",
                    format_exact_candidate_token_amount(broadcaster, reduction),
                    format_exact_candidate_token_amount(broadcaster, protocol_fee_amount)
                )
            }
        }
    }
}

fn format_exact_candidate_token_amount(
    candidate: &PublicBroadcasterCandidate,
    amount: U256,
) -> String {
    lookup_token(candidate.chain_id, &candidate.token).map_or_else(
        || format!("{amount} raw token units"),
        |info| {
            format!(
                "{} {}",
                format_send_amount_input(amount, Some(info.decimals)),
                info.symbol
            )
        },
    )
}

impl<'a> PublicBroadcasterCostDisplay<'a> {
    pub(super) const fn from_result(
        result: &'a PublicBroadcasterSubmissionResult,
        fee_anchor_rate: Option<U256>,
        registry: Option<&'a EffectiveTokenRegistry>,
    ) -> Self {
        Self {
            broadcaster: &result.broadcaster,
            registry,
            chain_id: result.broadcaster.chain_id,
            action_token: result.action_token,
            fee_token: result.fee_token,
            entered_amount: result.entered_amount,
            receiver_amount: result.receiver_amount,
            recipient_amount: result.recipient_amount,
            total_private_spend: result.total_private_spend,
            fee_amount: result.fee_amount,
            protocol_fee_amount: result.protocol_fee_amount,
            protocol_fee_bps: result.protocol_fee_bps,
            fee_mode: result.fee_mode,
            gas_limit: result.gas_limit,
            min_gas_price: result.min_gas_price,
            fee_anchor_rate,
        }
    }

    pub(super) const fn from_estimate(
        asset: &UnshieldAsset,
        estimate: &'a PublicBroadcasterCostEstimate,
        fee_anchor_rate: Option<U256>,
        registry: Option<&'a EffectiveTokenRegistry>,
    ) -> Self {
        Self::from_estimate_chain(asset.chain_id, estimate, fee_anchor_rate, registry)
    }

    pub(super) const fn from_estimate_chain(
        chain_id: u64,
        estimate: &'a PublicBroadcasterCostEstimate,
        fee_anchor_rate: Option<U256>,
        registry: Option<&'a EffectiveTokenRegistry>,
    ) -> Self {
        Self {
            broadcaster: &estimate.broadcaster,
            registry,
            chain_id,
            action_token: estimate.action_token,
            fee_token: estimate.fee_token,
            entered_amount: estimate.entered_amount,
            receiver_amount: estimate.receiver_amount,
            recipient_amount: estimate.recipient_amount,
            total_private_spend: estimate.total_private_spend,
            fee_amount: estimate.fee_amount,
            protocol_fee_amount: estimate.protocol_fee_amount,
            protocol_fee_bps: estimate.protocol_fee_bps,
            fee_mode: estimate.fee_mode,
            gas_limit: estimate.gas_limit,
            min_gas_price: estimate.min_gas_price,
            fee_anchor_rate,
        }
    }

    pub(super) fn private_spend_label(&self) -> &'static str {
        if self.action_token == self.fee_token {
            "Total private spend"
        } else {
            "Action-token private spend"
        }
    }

    pub(super) fn action_amount(&self, amount: U256) -> String {
        format_exact_token_amount_for_display(
            self.chain_id,
            self.action_token,
            amount,
            self.registry,
        )
    }

    pub(super) fn fee_amount(&self) -> String {
        format_exact_token_amount_for_display(
            self.chain_id,
            self.fee_token,
            self.fee_amount,
            self.registry,
        )
    }

    pub(super) fn fee_breakdown(&self) -> PublicBroadcasterFeeBreakdown {
        public_broadcaster_fee_breakdown(
            self.fee_amount,
            self.gas_limit,
            self.min_gas_price,
            self.fee_token_anchor_rate(),
        )
    }

    fn fee_token_anchor_rate(&self) -> Option<U256> {
        self.fee_anchor_rate
            .or_else(|| broadcaster_candidate_anchor_rate(self.broadcaster))
            .or_else(|| fixed_token_anchor_rate(self.chain_id, self.fee_token))
    }

    pub(super) fn native_gas_cost_value(
        &self,
        breakdown: &PublicBroadcasterFeeBreakdown,
    ) -> String {
        format_native_token_amount_for_display(self.chain_id, breakdown.native_gas_cost)
    }

    pub(super) fn broadcaster_fee_value(
        &self,
        breakdown: &PublicBroadcasterFeeBreakdown,
    ) -> String {
        breakdown.broadcaster_fee.map_or_else(
            || "unavailable (no anchor)".to_string(),
            |margin| {
                format_public_broadcaster_fee_margin(
                    self.chain_id,
                    self.fee_token,
                    margin,
                    self.registry,
                )
            },
        )
    }

    pub(super) fn protocol_fee_value(&self) -> String {
        format!(
            "{} ({} bps)",
            self.action_amount(self.protocol_fee_amount),
            self.protocol_fee_bps
        )
    }

    pub(super) fn gas_value(&self) -> String {
        format!(
            "~{} gas @ {} gwei",
            self.gas_limit,
            format_gwei(public_broadcaster_service_gas_price(self.min_gas_price))
        )
    }

    pub(super) fn fee_mode_summary(&self) -> String {
        fee_handling_mode_summary(
            self.chain_id,
            self.action_token,
            self.fee_token,
            self.fee_mode,
            self.entered_amount,
            self.receiver_amount,
            self.protocol_fee_amount,
            self.fee_amount,
            self.broadcaster,
            self.registry,
        )
    }
}

impl WalletRoot {
    pub(super) fn schedule_public_broadcaster_cost_estimate(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        cx: &mut Context<'_, Self>,
    ) {
        if !self.can_schedule_public_broadcaster_cost_estimate(kind, key) {
            return;
        }

        self.cost_estimate_seq = self.cost_estimate_seq.wrapping_add(1);
        let estimate_id = self.cost_estimate_seq;
        match kind {
            DeliveryFormKind::Send => {
                if let Some(form) = self.send_forms.get_mut(&key) {
                    form.estimate_id = estimate_id;
                    form.cost_estimate = None;
                    form.cost_estimate_pending = false;
                    form.estimating_cost = false;
                    form.error = None;
                }
            }
            DeliveryFormKind::Unshield => {
                if let Some(form) = self.unshield_forms.get_mut(&key) {
                    form.estimate_id = estimate_id;
                    form.cost_estimate = None;
                    form.cost_estimate_pending = false;
                    form.estimating_cost = false;
                    form.error = None;
                }
            }
        }
        cx.notify();

        match kind {
            DeliveryFormKind::Send => self.estimate_send_public_broadcaster_cost_from_form(key, cx),
            DeliveryFormKind::Unshield => {
                self.estimate_unshield_public_broadcaster_cost_from_form(key, cx);
            }
        }
    }

    pub(super) fn debounce_public_broadcaster_cost_estimate(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        cx: &mut Context<'_, Self>,
    ) {
        if !self.can_schedule_public_broadcaster_cost_estimate(kind, key) {
            return;
        }

        self.cost_estimate_seq = self.cost_estimate_seq.wrapping_add(1);
        let estimate_id = self.cost_estimate_seq;
        match kind {
            DeliveryFormKind::Send => {
                if let Some(form) = self.send_forms.get_mut(&key) {
                    form.estimate_id = estimate_id;
                    form.cost_estimate = None;
                    form.cost_estimate_pending = true;
                    form.estimating_cost = false;
                    form.error = None;
                }
            }
            DeliveryFormKind::Unshield => {
                if let Some(form) = self.unshield_forms.get_mut(&key) {
                    form.estimate_id = estimate_id;
                    form.cost_estimate = None;
                    form.cost_estimate_pending = true;
                    form.estimating_cost = false;
                    form.error = None;
                }
            }
        }
        cx.notify();

        cx.spawn(async move |this, cx| {
            tokio::time::sleep(COST_ESTIMATE_DEBOUNCE).await;
            let _ = this.update(cx, |root, cx| {
                let current_id = match kind {
                    DeliveryFormKind::Send => {
                        root.send_forms.get(&key).map(|form| form.estimate_id)
                    }
                    DeliveryFormKind::Unshield => {
                        root.unshield_forms.get(&key).map(|form| form.estimate_id)
                    }
                };
                if current_id != Some(estimate_id) {
                    return;
                }
                match kind {
                    DeliveryFormKind::Send => {
                        root.estimate_send_public_broadcaster_cost_from_form(key, cx);
                    }
                    DeliveryFormKind::Unshield => {
                        root.estimate_unshield_public_broadcaster_cost_from_form(key, cx);
                    }
                }
            });
        })
        .detach();
    }

    fn can_schedule_public_broadcaster_cost_estimate(
        &self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
    ) -> bool {
        match kind {
            DeliveryFormKind::Send => self.send_forms.get(&key).is_some_and(|form| {
                !form.generating && form.delivery_mode == DeliveryMode::PublicBroadcaster
            }),
            DeliveryFormKind::Unshield => self.unshield_forms.get(&key).is_some_and(|form| {
                !form.generating && form.delivery_mode == DeliveryMode::PublicBroadcaster
            }),
        }
    }

    pub(super) fn clear_pending_public_broadcaster_cost_estimate(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        cx: &mut Context<'_, Self>,
    ) {
        let changed = match kind {
            DeliveryFormKind::Send => self.send_forms.get_mut(&key).is_some_and(|form| {
                let changed = form.cost_estimate_pending || form.estimating_cost;
                form.cost_estimate_pending = false;
                form.estimating_cost = false;
                form.estimate_id = 0;
                changed
            }),
            DeliveryFormKind::Unshield => self.unshield_forms.get_mut(&key).is_some_and(|form| {
                let changed = form.cost_estimate_pending || form.estimating_cost;
                form.cost_estimate_pending = false;
                form.estimating_cost = false;
                form.estimate_id = 0;
                changed
            }),
        };
        if changed {
            cx.notify();
        }
    }

    fn estimate_send_public_broadcaster_cost_from_form(
        &mut self,
        key: UnshieldAssetKey,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(form) = self.send_forms.get(&key) else {
            return;
        };
        if form.generating
            || form.estimating_cost
            || form.delivery_mode != DeliveryMode::PublicBroadcaster
        {
            return;
        }
        let asset = form.asset.clone();
        let recipient = form.recipient_input.read(cx).value().trim().to_string();
        let amount_raw = form.amount_input.read(cx).value().to_string();
        let broadcaster_choice = form.broadcaster_choice.clone();
        let fee_token = form.selected_fee_token;
        let fee_mode = effective_fee_handling_mode(
            DeliveryFormKind::Send,
            asset.token,
            fee_token,
            form.fee_mode,
        );
        let allow_suspicious_broadcasters = form.allow_suspicious_broadcasters;
        if self.recipient_combobox_search_active(DeliveryFormKind::Send, key) {
            self.clear_pending_public_broadcaster_cost_estimate(DeliveryFormKind::Send, key, cx);
            return;
        }
        if let Some(error) = send_public_broadcaster_estimate_input_error(
            recipient.as_str(),
            amount_raw.as_str(),
            &asset,
        ) {
            self.set_send_form_error(key, error, cx);
            return;
        }
        if recipient.is_empty() {
            self.clear_pending_public_broadcaster_cost_estimate(DeliveryFormKind::Send, key, cx);
            return;
        }
        let Ok(amount) = parse_send_amount(amount_raw.as_str(), asset.decimals) else {
            self.clear_pending_public_broadcaster_cost_estimate(DeliveryFormKind::Send, key, cx);
            return;
        };
        let Some(ChainUtxoState::Ready { session, .. }) = self.chain_states.get(&asset.chain_id)
        else {
            self.clear_pending_public_broadcaster_cost_estimate(DeliveryFormKind::Send, key, cx);
            return;
        };
        let session = Arc::clone(session);
        let fee_rows = self.monitor_fee_rows();
        let policy = self.public_broadcaster_fee_policy(allow_suspicious_broadcasters);
        let candidates =
            self.current_public_broadcaster_candidates(asset.chain_id, fee_token, false, policy);
        let selection = Self::public_broadcaster_selection(&broadcaster_choice);
        if select_public_broadcaster_with_policy(&candidates, &selection, policy).is_err() {
            self.clear_pending_public_broadcaster_cost_estimate(DeliveryFormKind::Send, key, cx);
            return;
        }

        self.cost_estimate_seq = self.cost_estimate_seq.wrapping_add(1);
        let estimate_id = self.cost_estimate_seq;
        if let Some(form) = self.send_forms.get_mut(&key) {
            form.cost_estimate_pending = false;
            form.estimating_cost = true;
            form.error = None;
            form.estimate_id = estimate_id;
        }
        cx.notify();

        let request = DesktopSendPublicBroadcasterEstimateRequest {
            chain_id: asset.chain_id,
            effective_chain: self.effective_chain_configs.get(&asset.chain_id).cloned(),
            session,
            token: asset.token,
            fee_token,
            amount,
            recipient,
            fee_rows,
            selection,
            fee_mode,
            fee_policy: policy,
            anchor_cache: Some(Arc::clone(&self.public_broadcaster_anchor_cache)),
        };
        let http = self.http.clone();
        let join = self.runtime.spawn(async move {
            estimate_desktop_send_public_broadcaster_cost(request, &http).await
        });
        cx.spawn(async move |this, cx| {
            let result = match join.await {
                Ok(result) => result,
                Err(error) => Err(eyre::eyre!("send cost estimate task failed: {error}")),
            };
            let _ = this.update(cx, |root, cx| {
                let Some(form) = root.send_forms.get_mut(&key) else {
                    return;
                };
                if form.estimate_id != estimate_id {
                    return;
                }
                form.cost_estimate_pending = false;
                form.estimating_cost = false;
                match result {
                    Ok(estimate) => {
                        form.error = None;
                        form.cost_estimate = Some(estimate);
                    }
                    Err(error) => {
                        form.cost_estimate = None;
                        form.error = Some(Arc::from(format_report_chain(&error)));
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn estimate_unshield_public_broadcaster_cost_from_form(
        &mut self,
        key: UnshieldAssetKey,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(form) = self.unshield_forms.get(&key) else {
            return;
        };
        if form.generating
            || form.estimating_cost
            || form.delivery_mode != DeliveryMode::PublicBroadcaster
        {
            return;
        }
        let asset = form.asset.clone();
        let unwrap = form.unwrap;
        let recipient_raw = form.recipient_input.read(cx).value().to_string();
        let amount_raw = form.amount_input.read(cx).value().to_string();
        let broadcaster_choice = form.broadcaster_choice.clone();
        let fee_token = form.selected_fee_token;
        let fee_mode = effective_fee_handling_mode(
            DeliveryFormKind::Unshield,
            asset.token,
            fee_token,
            form.fee_mode,
        );
        let allow_suspicious_broadcasters = form.allow_suspicious_broadcasters;
        if self.recipient_combobox_search_active(DeliveryFormKind::Unshield, key) {
            self.clear_pending_public_broadcaster_cost_estimate(
                DeliveryFormKind::Unshield,
                key,
                cx,
            );
            return;
        }
        if let Some(error) = unshield_public_broadcaster_estimate_input_error(
            recipient_raw.as_str(),
            amount_raw.as_str(),
            &asset,
        ) {
            self.set_unshield_form_error(key, error, cx);
            return;
        }
        if recipient_raw.trim().is_empty() {
            self.clear_pending_public_broadcaster_cost_estimate(
                DeliveryFormKind::Unshield,
                key,
                cx,
            );
            return;
        }
        let Ok(recipient) = recipient_raw.trim().parse::<Address>() else {
            self.clear_pending_public_broadcaster_cost_estimate(
                DeliveryFormKind::Unshield,
                key,
                cx,
            );
            return;
        };
        let Ok(amount) = parse_unshield_amount(amount_raw.as_str(), asset.decimals) else {
            self.clear_pending_public_broadcaster_cost_estimate(
                DeliveryFormKind::Unshield,
                key,
                cx,
            );
            return;
        };
        let Some(ChainUtxoState::Ready { session, .. }) = self.chain_states.get(&asset.chain_id)
        else {
            self.clear_pending_public_broadcaster_cost_estimate(
                DeliveryFormKind::Unshield,
                key,
                cx,
            );
            return;
        };
        let session = Arc::clone(session);
        let fee_rows = self.monitor_fee_rows();
        let policy = self.public_broadcaster_fee_policy(allow_suspicious_broadcasters);
        let candidates =
            self.current_public_broadcaster_candidates(asset.chain_id, fee_token, unwrap, policy);
        let selection = Self::public_broadcaster_selection(&broadcaster_choice);
        if select_public_broadcaster_with_policy(&candidates, &selection, policy).is_err() {
            self.clear_pending_public_broadcaster_cost_estimate(
                DeliveryFormKind::Unshield,
                key,
                cx,
            );
            return;
        }

        self.cost_estimate_seq = self.cost_estimate_seq.wrapping_add(1);
        let estimate_id = self.cost_estimate_seq;
        if let Some(form) = self.unshield_forms.get_mut(&key) {
            form.cost_estimate_pending = false;
            form.estimating_cost = true;
            form.error = None;
            form.estimate_id = estimate_id;
        }
        cx.notify();

        let request = DesktopUnshieldPublicBroadcasterEstimateRequest {
            chain_id: asset.chain_id,
            effective_chain: self.effective_chain_configs.get(&asset.chain_id).cloned(),
            session,
            token: asset.token,
            fee_token,
            amount,
            recipient,
            unwrap,
            fee_rows,
            selection,
            fee_mode,
            fee_policy: policy,
            anchor_cache: Some(Arc::clone(&self.public_broadcaster_anchor_cache)),
        };
        let http = self.http.clone();
        let join = self.runtime.spawn(async move {
            estimate_desktop_unshield_public_broadcaster_cost(request, &http).await
        });
        cx.spawn(async move |this, cx| {
            let result = match join.await {
                Ok(result) => result,
                Err(error) => Err(eyre::eyre!("unshield cost estimate task failed: {error}")),
            };
            let _ = this.update(cx, |root, cx| {
                let Some(form) = root.unshield_forms.get_mut(&key) else {
                    return;
                };
                if form.estimate_id != estimate_id {
                    return;
                }
                form.cost_estimate_pending = false;
                form.estimating_cost = false;
                match result {
                    Ok(estimate) => {
                        form.error = None;
                        form.cost_estimate = Some(estimate);
                    }
                    Err(error) => {
                        form.cost_estimate = None;
                        form.error = Some(Arc::from(format_report_chain(&error)));
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }
}

struct PublicBroadcasterCostRowsOptions {
    show_broadcaster: bool,
    show_entered_amount: bool,
}

fn append_public_broadcaster_cost_rows(
    mut card: gpui::Div,
    root: Entity<WalletRoot>,
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    display: &PublicBroadcasterCostDisplay<'_>,
    options: &PublicBroadcasterCostRowsOptions,
    transaction_fee_breakdown_open: bool,
) -> gpui::Div {
    if options.show_broadcaster {
        card = card.child(cost_estimate_row(
            "Broadcaster",
            broadcaster_candidate_label(display.broadcaster),
        ));
    }
    if options.show_entered_amount {
        card = card.child(cost_estimate_row(
            "Entered amount",
            display.action_amount(display.entered_amount),
        ));
    }
    card = card
        .child(cost_estimate_row(
            "Recipient receives",
            display.action_amount(display.recipient_amount),
        ))
        .when(
            should_show_distinct_amount(display.entered_amount, display.total_private_spend),
            |card| {
                card.child(cost_estimate_row(
                    display.private_spend_label(),
                    display.action_amount(display.total_private_spend),
                ))
            },
        )
        .when(!display.protocol_fee_bps.is_zero(), |card| {
            card.child(cost_estimate_row(
                "RAILGUN protocol fee",
                display.protocol_fee_value(),
            ))
        })
        .child(render_transaction_fee_breakdown(
            root,
            key,
            kind,
            display,
            transaction_fee_breakdown_open,
        ));
    card
}

fn render_transaction_fee_breakdown(
    root: Entity<WalletRoot>,
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    display: &PublicBroadcasterCostDisplay<'_>,
    open: bool,
) -> impl IntoElement {
    let breakdown = display.fee_breakdown();
    let fee_amount = display.fee_amount();
    Collapsible::new()
        .open(open)
        .w_full()
        .rounded_md()
        .overflow_hidden()
        .child(
            div()
                .id(delivery_element_id(key, kind, "transaction-fee-breakdown"))
                .flex()
                .items_center()
                .justify_between()
                .gap_3()
                .py(px(5.0))
                .cursor_pointer()
                .on_click(move |_event, _window, cx| {
                    cx.stop_propagation();
                    root.update(cx, |root, cx| {
                        root.set_transaction_fee_breakdown_open(kind, key, !open, cx);
                    });
                })
                .child(
                    div()
                        .flex_1()
                        .min_w(px(0.0))
                        .text_color(rgb(theme::TEXT))
                        .child("Transaction fee"),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_end()
                        .gap_2()
                        .text_color(rgb(theme::TEXT))
                        .child(fee_amount)
                        .child(
                            Icon::new(if open {
                                IconName::ChevronUp
                            } else {
                                IconName::ChevronDown
                            })
                            .xsmall()
                            .text_color(rgb(theme::TEXT_MUTED)),
                        ),
                ),
        )
        .content(
            div()
                .flex()
                .flex_col()
                .gap_1()
                .px(px(10.0))
                .py(px(8.0))
                .border_t_1()
                .border_color(rgb(theme::BORDER))
                .child(transaction_fee_breakdown_row(
                    "Gas cost",
                    display.native_gas_cost_value(&breakdown),
                ))
                .child(transaction_fee_breakdown_row(
                    "Broadcaster's fee",
                    display.broadcaster_fee_value(&breakdown),
                ))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap_3()
                        .child(network_gas_breakdown_text("Network gas"))
                        .child(network_gas_breakdown_text(display.gas_value())),
                ),
        )
}

pub(super) fn render_public_broadcaster_tx_hash_row(
    tx_hash: String,
    button_id: SharedString,
) -> gpui::Div {
    div()
        .flex()
        .items_center()
        .gap_2()
        .child(
            div()
                .w(px(72.0))
                .flex_none()
                .text_color(rgb(theme::TEXT_MUTED))
                .child("Tx hash"),
        )
        .child(
            div()
                .flex_1()
                .min_w(px(0.0))
                .font_family(APP_FONT_FAMILY)
                .text_size(APP_TEXT_SIZE)
                .text_color(rgb(theme::TEXT))
                .child(SharedString::from(tx_hash.clone())),
        )
        .child(clipboard_with_toast(button_id, tx_hash))
}

pub(super) fn render_public_broadcaster_cost_estimate(
    root: Entity<WalletRoot>,
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    asset: &UnshieldAsset,
    estimate: &PublicBroadcasterCostEstimate,
    fee_anchor_rate: Option<U256>,
    registry: Option<&EffectiveTokenRegistry>,
    transaction_fee_breakdown_open: bool,
    refreshing: bool,
) -> gpui::Div {
    let refresh_root = root.clone();
    let display =
        PublicBroadcasterCostDisplay::from_estimate(asset, estimate, fee_anchor_rate, registry);
    let card = div()
        .flex()
        .flex_col()
        .gap_2()
        .p(px(12.0))
        .rounded_md()
        .bg(rgb(theme::SURFACE_ELEVATED))
        .border_1()
        .border_color(rgb(theme::BORDER_STRONG))
        .child(
            div()
                .flex()
                .items_start()
                .justify_between()
                .gap_3()
                .child(
                    div()
                        .flex_1()
                        .min_w(px(0.0))
                        .flex()
                        .flex_col()
                        .gap_1()
                        .child(app_strong_text("Estimated outcome"))
                        .child(cost_estimate_detail_text(
                            "Proof is not generated yet; the final fee may move slightly before publish.",
                        )),
                )
                .child(render_public_broadcaster_estimate_refresh_button(
                    refresh_root,
                    key,
                    kind,
                    refreshing,
                )),
        );
    append_public_broadcaster_cost_rows(
        card,
        root,
        key,
        kind,
        &display,
        &PublicBroadcasterCostRowsOptions {
            show_broadcaster: true,
            show_entered_amount: false,
        },
        transaction_fee_breakdown_open,
    )
    .child(cost_estimate_detail_text(format!(
        "Shape: {} proofs · {} inputs · {} private outputs · {} public outputs",
        estimate.transaction_count,
        estimate.input_count,
        estimate.private_output_count,
        estimate.public_output_count
    )))
    .child(cost_estimate_detail_text(display.fee_mode_summary()))
}

fn render_public_broadcaster_estimate_refresh_button(
    root: Entity<WalletRoot>,
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    refreshing: bool,
) -> impl IntoElement {
    div()
        .id(delivery_element_id(key, kind, "refresh-estimate"))
        .size(px(18.0))
        .flex()
        .items_center()
        .justify_center()
        .rounded_sm()
        .when(refreshing, |this| {
            this.child(
                Spinner::new()
                    .icon(IconName::LoaderCircle)
                    .color(rgb(theme::TEXT_MUTED).into())
                    .with_size(px(13.0)),
            )
        })
        .when(!refreshing, |this| {
            this.cursor_pointer()
                .hover(|this| this.bg(rgb(theme::SURFACE_HOVER)))
                .tooltip(|window, cx| Tooltip::new("Refresh estimate").build(window, cx))
                .on_click(move |_event, _window, cx| {
                    cx.stop_propagation();
                    root.update(cx, |root, cx| {
                        root.schedule_public_broadcaster_cost_estimate(kind, key, cx);
                    });
                })
                .child(
                    img(icons::refresh_ccw_icon_path())
                        .size(px(13.0))
                        .flex_none(),
                )
        })
}

pub(super) const fn public_broadcaster_cost_status(
    pending: bool,
    estimating: bool,
) -> Option<CostEstimateStatus> {
    if pending {
        None
    } else if estimating {
        Some(CostEstimateStatus::Estimating)
    } else {
        None
    }
}

pub(super) const fn public_broadcaster_cost_status_text(
    status: CostEstimateStatus,
) -> (&'static str, &'static str) {
    match status {
        CostEstimateStatus::Estimating => (
            "Estimating public broadcaster cost...",
            "Using current gas price, transaction fee rate, and selected private note shape.",
        ),
    }
}

pub(super) fn render_public_broadcaster_cost_status(
    _tick: usize,
    status: CostEstimateStatus,
) -> gpui::Div {
    let (title, detail) = public_broadcaster_cost_status_text(status);
    div()
        .flex()
        .items_center()
        .gap_3()
        .p(px(12.0))
        .rounded_md()
        .bg(rgb(theme::SURFACE_ELEVATED))
        .border_1()
        .border_color(rgb(theme::BORDER))
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
                .child(app_strong_text(title))
                .child(app_muted_text(detail)),
        )
}

fn cost_estimate_row(label: &'static str, value: String) -> gpui::Div {
    div()
        .flex()
        .items_center()
        .justify_between()
        .gap_3()
        .child(app_muted_text(label))
        .child(app_strong_text(value))
}

pub(super) fn cost_estimate_detail_text(text: impl Into<SharedString>) -> gpui::Div {
    div()
        .text_color(rgb(theme::TEXT_SUBTLE))
        .text_size(COST_ESTIMATE_DETAIL_TEXT_SIZE)
        .line_height(px(15.0))
        .child(text.into())
}

fn transaction_fee_breakdown_text(text: impl Into<SharedString>) -> gpui::Div {
    div()
        .text_color(rgb(theme::TEXT))
        .text_size(COST_ESTIMATE_DETAIL_TEXT_SIZE)
        .line_height(px(15.0))
        .child(text.into())
}

fn network_gas_breakdown_text(text: impl Into<SharedString>) -> gpui::Div {
    div()
        .text_color(rgb(theme::TEXT_MUTED))
        .text_size(COST_ESTIMATE_DETAIL_TEXT_SIZE)
        .line_height(px(15.0))
        .child(text.into())
}

fn transaction_fee_breakdown_row(label: &'static str, value: String) -> gpui::Div {
    div()
        .flex()
        .items_center()
        .justify_between()
        .gap_3()
        .child(transaction_fee_breakdown_text(label))
        .child(transaction_fee_breakdown_text(value))
}

pub(super) fn render_private_broadcaster_progress_context(
    progress: &PrivateBroadcasterProgressState,
    context: &PrivateBroadcasterProgressContext<'_>,
) -> gpui::Div {
    let display = &context.display;
    let breakdown = display.fee_breakdown();
    let fee_label = if context.settled {
        "Settled fee"
    } else {
        "Estimated fee"
    };
    div()
        .flex()
        .flex_col()
        .gap_2()
        .p(px(12.0))
        .rounded_md()
        .bg(rgb(theme::SURFACE_ELEVATED))
        .border_1()
        .border_color(rgb(theme::BORDER_STRONG))
        .child(app_strong_text("Transaction context"))
        .child(private_broadcaster_context_row(
            "Broadcaster",
            broadcaster_candidate_label(display.broadcaster),
        ))
        .child(private_broadcaster_context_row(
            "Recipient",
            progress.recipient.to_string(),
        ))
        .child(private_broadcaster_context_row(
            "Entered amount",
            display.action_amount(display.entered_amount),
        ))
        .child(private_broadcaster_context_row(
            "Recipient receives",
            display.action_amount(display.recipient_amount),
        ))
        .when(
            should_show_distinct_amount(display.entered_amount, display.total_private_spend),
            |card| {
                card.child(private_broadcaster_context_row(
                    display.private_spend_label(),
                    display.action_amount(display.total_private_spend),
                ))
            },
        )
        .when(!display.protocol_fee_bps.is_zero(), |card| {
            card.child(private_broadcaster_context_row(
                "RAILGUN protocol fee",
                display.protocol_fee_value(),
            ))
        })
        .child(private_broadcaster_context_row(
            fee_label,
            display.fee_amount(),
        ))
        .child(private_broadcaster_context_row(
            "Tx gas cost",
            display.native_gas_cost_value(&breakdown),
        ))
        .child(private_broadcaster_context_row(
            "Transaction fee",
            display.broadcaster_fee_value(&breakdown),
        ))
        .child(private_broadcaster_context_row(
            "Network gas",
            display.gas_value(),
        ))
        .child(cost_estimate_detail_text(display.fee_mode_summary()))
}

pub(super) fn private_broadcaster_context_row(label: &'static str, value: String) -> gpui::Div {
    div()
        .flex()
        .items_start()
        .justify_between()
        .gap_3()
        .child(app_muted_text(label).flex_none())
        .child(
            app_strong_text(value)
                .min_w(px(0.0))
                .text_align(gpui::TextAlign::Right)
                .whitespace_normal(),
        )
}
