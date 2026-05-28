use super::{
    Alert, ButtonVariants, DeliveryFormKind, DeliveryMode, Disableable, Entity, ParentElement,
    PublicBroadcasterResultKind, SendResult, Sizable, Styled, UnshieldAssetKey, UnshieldResult,
    WalletRoot, app_button, delivery_element_id, div, fee_policy_eligible_public_broadcasters,
    format_form_error_for_asset, is_effective_wrapped_native_token, labeled_field,
    private_action_input, private_broadcaster_closed_active_progress,
    public_broadcaster_cost_status, public_broadcaster_fee_token_warning,
    public_broadcaster_submit_disabled_for_fee_token_options, px, render_delivery_selector,
    render_private_action_metrics, render_private_broadcaster_status_notice,
    render_private_self_broadcast_status_notice, render_private_submission_active_status_notice,
    render_public_broadcaster_cost_estimate, render_public_broadcaster_cost_status,
    render_public_broadcaster_settings, render_recipient_picker, render_self_broadcast_settings,
    render_send_result, render_unshield_generating_status, render_unshield_output_toggle,
    render_unshield_result, selected_broadcaster_fee_warning, send_element_id,
    should_render_public_broadcaster_cost_preview, unshield_element_id,
};

impl WalletRoot {
    pub(in crate::root) fn render_send_form(
        &self,
        root: Entity<Self>,
        key: UnshieldAssetKey,
    ) -> gpui::Div {
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
        let recipient_root = root.clone();
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
        let recipient_options = self.private_send_recipient_options();

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
                            render_recipient_picker(
                                recipient_root,
                                key,
                                DeliveryFormKind::Send,
                                &form.recipient_input,
                                &form.recipient_value,
                                form.recipient_suggestions_open,
                                form.recipient_suggestion_index,
                                &form.recipient_suggestions_scroll,
                                &recipient_options,
                                form.generating,
                            ),
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
                div().flex().items_end().gap_3().justify_end().child(
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

    pub(in crate::root) fn render_unshield_form(
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
        let recipient_root = root.clone();
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
        let recipient_options = self.private_unshield_recipient_options();

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
                            render_recipient_picker(
                                recipient_root,
                                key,
                                DeliveryFormKind::Unshield,
                                &form.recipient_input,
                                &form.recipient_value,
                                form.recipient_suggestions_open,
                                form.recipient_suggestion_index,
                                &form.recipient_suggestions_scroll,
                                &recipient_options,
                                form.generating,
                            ),
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
                div().flex().items_end().gap_3().justify_end().child(
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
