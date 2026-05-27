use super::*;

pub(in crate::root) fn private_action_input(state: &Entity<InputState>) -> Input {
    Input::new(state).px(px(12.0)).py(px(8.0))
}

pub(in crate::root) fn private_action_title_row(
    action: &'static str,
    label: &str,
    icon_path: Option<WalletIconSource>,
    asset_select: Option<Entity<SelectState<SearchableVec<PrivateActionAssetSelectItem>>>>,
    asset_select_disabled: bool,
) -> gpui::Div {
    let row = div().flex().items_center().gap_1().child(action);
    if let Some(asset_select) = asset_select {
        row.child(private_action_asset_title_select(
            &asset_select,
            asset_select_disabled,
        ))
    } else {
        row.child(token_label_row(
            SharedString::from(label.to_owned()),
            icon_path,
            px(20.0),
        ))
    }
}

pub(in crate::root) fn send_element_id(key: UnshieldAssetKey, action: &str) -> SharedString {
    SharedString::from(format!(
        "wallet-send-{}-{}-{action}",
        key.chain_id,
        key.token.to_checksum(None)
    ))
}

pub(in crate::root) fn unshield_element_id(key: UnshieldAssetKey, action: &str) -> SharedString {
    SharedString::from(format!(
        "wallet-unshield-{}-{}-{action}",
        key.chain_id,
        key.token.to_checksum(None)
    ))
}

pub(in crate::root) fn delivery_element_id(
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    action: &str,
) -> SharedString {
    match kind {
        DeliveryFormKind::Send => send_element_id(key, action),
        DeliveryFormKind::Unshield => unshield_element_id(key, action),
    }
}

pub(in crate::root) fn format_form_error_for_asset(
    error: &str,
    asset: &UnshieldAsset,
    fee_token: Address,
    registry: Option<&EffectiveTokenRegistry>,
) -> String {
    if let Some(balance_error) = form_error_public_broadcaster_fee_token_balance(error) {
        let available = format_exact_token_amount_for_display(
            asset.chain_id,
            fee_token,
            balance_error.max_spendable,
            registry,
        );
        if let Some(required_fee) = balance_error.required_fee {
            let required = format_exact_token_amount_for_display(
                asset.chain_id,
                fee_token,
                required_fee,
                registry,
            );
            let shortfall = format_exact_token_amount_for_display(
                asset.chain_id,
                fee_token,
                required_fee.saturating_sub(balance_error.max_spendable),
                registry,
            );
            return format!(
                "Transaction fee exceeds available fee-token balance. Required fee: {required}; available: {available}; short by: {shortfall}. Choose a fee token with more spendable balance or a lower-fee broadcaster."
            );
        }
        return format!(
            "Transaction fee exceeds available fee-token balance: {available}. Choose a fee token with more spendable balance or a lower-fee broadcaster."
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
            "Entered amount must be greater than the transaction fee for {}. Choose add fee on top or enter a larger amount.",
            asset.label
        ),
        _ => error.to_string(),
    }
}

struct PublicBroadcasterFeeTokenBalanceError {
    max_spendable: U256,
    required_fee: Option<U256>,
}

pub(in crate::root) fn format_exact_asset_amount_for_display(
    amount: U256,
    asset: &UnshieldAsset,
) -> String {
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

pub(in crate::root) fn form_error_clears_public_broadcaster_cost_estimate(
    _kind: DeliveryFormKind,
    error: &str,
) -> bool {
    !is_spend_authorization_failure_error(error)
}

pub(in crate::root) fn send_public_broadcaster_estimate_input_error(
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

pub(in crate::root) fn unshield_public_broadcaster_estimate_input_error(
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

pub(in crate::root) fn private_action_amount_input_error(
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

pub(in crate::root) fn form_error_public_broadcaster_max_entered_amount(
    error: &str,
) -> Option<U256> {
    const MARKER: &str = "public broadcaster max entered amount: ";
    form_error_decimal_after_marker(error, MARKER)
}

fn form_error_public_broadcaster_fee_token_balance(
    error: &str,
) -> Option<PublicBroadcasterFeeTokenBalanceError> {
    const MAX_SPENDABLE_MARKER: &str = "public broadcaster fee-token max spendable: ";
    const REQUIRED_FEE_MARKER: &str = "; required fee: ";
    Some(PublicBroadcasterFeeTokenBalanceError {
        max_spendable: form_error_decimal_after_marker(error, MAX_SPENDABLE_MARKER)?,
        required_fee: form_error_decimal_after_marker(error, REQUIRED_FEE_MARKER),
    })
}

pub(in crate::root) fn form_error_max_immediately_spendable(error: &str) -> Option<U256> {
    const MARKER: &str = "max immediately spendable: ";
    form_error_decimal_after_marker(error, MARKER)
}

pub(in crate::root) fn form_error_decimal_after_marker(error: &str, marker: &str) -> Option<U256> {
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
pub(in crate::root) struct PrivateActionMetric {
    pub(in crate::root) label: &'static str,
    pub(in crate::root) amount: U256,
}

pub(in crate::root) fn private_action_metrics(asset: &UnshieldAsset) -> Vec<PrivateActionMetric> {
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

pub(in crate::root) fn private_action_metric_display_amount(
    amount: U256,
    decimals: Option<u8>,
) -> String {
    decimals.map_or_else(
        || amount.to_string(),
        |decimals| format_token_amount(amount, decimals),
    )
}

pub(in crate::root) fn private_action_assets_from_snapshot(
    kind: DeliveryFormKind,
    snapshot: &ListUtxosOutput,
    registry: Option<&EffectiveTokenRegistry>,
    anchor_cache: Option<&TokenAnchorRateCache>,
) -> Vec<UnshieldAsset> {
    format_private_asset_rows_from_snapshot(snapshot, registry, anchor_cache)
        .iter()
        .filter_map(|asset| match kind {
            DeliveryFormKind::Send => build_send_asset(snapshot, asset),
            DeliveryFormKind::Unshield => build_unshield_asset(snapshot, asset),
        })
        .collect()
}

impl WalletRoot {
    pub(in crate::root) fn apply_public_broadcaster_error_amount_adjustments(
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

    pub(in crate::root) fn refresh_open_form_assets_for_snapshot(
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

    pub(in crate::root) fn private_action_snapshot(
        &self,
        chain_id: u64,
    ) -> Option<&ListUtxosOutput> {
        match self.chain_states.get(&chain_id) {
            Some(
                ChainUtxoState::Ready { snapshot, .. } | ChainUtxoState::Syncing { snapshot, .. },
            ) => Some(snapshot),
            _ => None,
        }
    }

    pub(in crate::root) fn private_action_asset_options(
        &self,
        kind: DeliveryFormKind,
        chain_id: u64,
    ) -> Vec<UnshieldAsset> {
        self.private_action_snapshot(chain_id)
            .map_or_else(Vec::new, |snapshot| {
                private_action_assets_from_snapshot(
                    kind,
                    snapshot,
                    Some(&self.effective_token_registry),
                    Some(&self.public_broadcaster_anchor_cache),
                )
            })
    }

    pub(in crate::root) fn sync_private_action_asset_select_for_dialog(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some((chain_id, selected_token, select, current_items)) = (match kind {
            DeliveryFormKind::Send => self.send_forms.get(&key).map(|form| {
                (
                    form.asset.chain_id,
                    form.asset.token,
                    form.asset_select.clone(),
                    form.asset_select_items.clone(),
                )
            }),
            DeliveryFormKind::Unshield => self.unshield_forms.get(&key).map(|form| {
                (
                    form.asset.chain_id,
                    form.asset.token,
                    form.asset_select.clone(),
                    form.asset_select_items.clone(),
                )
            }),
        }) else {
            return;
        };
        let assets = self.private_action_asset_options(kind, chain_id);
        let items = private_action_asset_select_items(&assets);
        let selected_matches = select.read(cx).selected_value().copied() == Some(selected_token);
        if items == current_items && selected_matches {
            return;
        }
        match kind {
            DeliveryFormKind::Send => {
                if let Some(form) = self.send_forms.get_mut(&key) {
                    form.asset_select_items.clone_from(&items);
                }
            }
            DeliveryFormKind::Unshield => {
                if let Some(form) = self.unshield_forms.get_mut(&key) {
                    form.asset_select_items.clone_from(&items);
                }
            }
        }
        sync_private_action_asset_select_entity(&select, &assets, selected_token, window, cx);
    }
}

pub(in crate::root) fn adjusted_amount_for_max_change(
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

pub(in crate::root) fn amount_adjustment_for_max_change(
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

pub(in crate::root) fn render_private_action_metrics(
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

pub(in crate::root) fn render_private_action_metric(
    root: Entity<WalletRoot>,
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    id: SharedString,
    metric: PrivateActionMetric,
    decimals: Option<u8>,
    disabled: bool,
) -> impl IntoElement {
    let value = private_action_metric_display_amount(metric.amount, decimals);
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

pub(in crate::root) fn private_action_metric_id_suffix(label: &'static str) -> &'static str {
    match label {
        "Total private balance" => "metric-total",
        "POI-verified balance" => "metric-poi-verified",
        "Max batched transaction" => "metric-max-batched",
        _ => "metric",
    }
}

pub(in crate::root) fn render_unshield_generating_status(
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
