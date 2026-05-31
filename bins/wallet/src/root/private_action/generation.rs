use super::*;
use zeroize::Zeroizing;

const SOFTWARE_SELF_BROADCAST_GAS_PAYER_PASSWORD_REQUIRED: &str = concat!(
    "The selected gas payer is a software Public account, so self-broadcast requires the vault ",
    "password. Choose a hardware Public account, manual calldata, or public broadcaster delivery."
);

impl WalletRoot {
    pub(in crate::root) fn generate_send_calldata_from_form(
        &mut self,
        key: UnshieldAssetKey,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(draft) = self.send_spend_draft(key, cx) else {
            return;
        };
        let requires_gas_payer_password = self.selected_wallet_source().is_hardware_derived()
            && self_broadcast_requires_software_gas_payer_password(
                draft.delivery_mode,
                draft.self_broadcast_gas_payer_source,
            );
        let intent = if requires_gas_payer_password {
            SpendAuthorizationIntent::PrivateSendSelfBroadcastGasPassword(key)
        } else {
            SpendAuthorizationIntent::PrivateSend(key)
        };
        let summary = if requires_gas_payer_password {
            private_send_gas_payer_authorization_summary(&draft)
        } else {
            private_send_authorization_summary(&draft)
        };
        self.request_spend_authorization(intent, summary, window, cx);
    }

    pub(in crate::root) fn send_spend_draft(
        &mut self,
        key: UnshieldAssetKey,
        cx: &mut Context<'_, Self>,
    ) -> Option<SendSpendDraft> {
        let form = self.send_forms.get(&key)?;
        if form.generating {
            return None;
        }
        let asset = form.asset.clone();
        let recipient_input = form.recipient_input.clone();
        let amount_input = form.amount_input.clone();
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
                    return None;
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
        let fee_mode = effective_fee_handling_mode(
            DeliveryFormKind::Send,
            asset.token,
            fee_token,
            form.fee_mode,
        );
        let allow_suspicious_broadcasters = form.allow_suspicious_broadcasters;
        let favorites_only_broadcasters = form.favorites_only_broadcasters;

        let Some(view_session) = self.view_session.clone() else {
            self.set_send_form_error(key, "Unlock the wallet vault before sending", cx);
            return None;
        };
        let Some(vault_store) = self.vault_store.clone() else {
            self.set_send_form_error(key, "Wallet vault storage is unavailable", cx);
            return None;
        };
        let Some(ChainUtxoState::Ready { session, .. }) = self.chain_states.get(&asset.chain_id)
        else {
            self.set_send_form_error(key, "Wait for wallet sync to finish before sending", cx);
            return None;
        };
        let session = Arc::clone(session);
        if asset.max_batched.is_zero() {
            self.set_send_form_error(
                key,
                "No POI-verified private notes are spendable in a batched send",
                cx,
            );
            return None;
        }

        let recipient_raw = recipient_input.read(cx).value().to_string();
        if let Err(error) = parse_railgun_recipient(recipient_raw.as_str()) {
            self.set_send_form_error(key, error.to_string(), cx);
            return None;
        }
        let recipient = recipient_raw.trim().to_string();
        let amount_raw = amount_input.read(cx).value().to_string();
        let amount = match parse_send_amount(amount_raw.as_str(), asset.decimals) {
            Ok(amount) if !amount.is_zero() => amount,
            Ok(_) => {
                self.set_send_form_error(key, "Enter an amount greater than zero", cx);
                return None;
            }
            Err(error) => {
                self.set_send_form_error(key, error.to_string(), cx);
                return None;
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
            return None;
        }

        let (
            self_broadcast_public_account_uuid,
            self_broadcast_gas_payer_display,
            self_broadcast_gas_payer_source,
        ) = if delivery_mode == DeliveryMode::SelfBroadcast {
            let Some(uuid) = self_broadcast_gas_payer_uuid else {
                self.set_send_form_error(key, "Choose a Public account to pay gas", cx);
                return None;
            };
            let Some(account) = self.selected_self_broadcast_gas_payer_account(Some(uuid.as_ref()))
            else {
                self.set_send_form_error(key, "Choose an active Public account to pay gas", cx);
                return None;
            };
            let gas_payer_display = public_account_display_label(account).map_or_else(
                || short_address(&account.address),
                |label| format!("{label} · {}", short_address(&account.address)),
            );
            (
                Some(uuid.to_string()),
                Some(gas_payer_display),
                Some(account.source),
            )
        } else {
            (None, None, None)
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
                favorites_only_broadcasters,
                policy,
            );
            let trust_filter = self.public_broadcaster_trust_filter(favorites_only_broadcasters);
            if let Err(error) = select_public_broadcaster_with_policy_and_trust(
                &candidates,
                &public_broadcaster_selection,
                policy,
                &trust_filter,
            ) {
                self.set_send_form_error(key, error.to_string(), cx);
                return None;
            }
            rows
        } else {
            Vec::new()
        };
        let fee_policy = self.public_broadcaster_fee_policy(allow_suspicious_broadcasters);

        Some(SendSpendDraft {
            asset,
            delivery_mode,
            broadcaster_choice,
            cost_estimate,
            fee_token,
            self_broadcast_gas_fee,
            self_broadcast_initial_gas_fee,
            fee_mode,
            view_session,
            vault_store,
            session,
            recipient,
            amount,
            self_broadcast_public_account_uuid,
            self_broadcast_gas_payer_display,
            self_broadcast_gas_payer_source,
            fee_rows,
            fee_policy,
            favorites_only_broadcasters,
        })
    }

    pub(in crate::root) fn generate_send_calldata_authorized(
        &mut self,
        key: UnshieldAssetKey,
        spend_authorization: DesktopPrivateSpendAuthorization,
        window: &Window,
        cx: &mut Context<'_, Self>,
    ) {
        self.generate_send_calldata_authorized_with_gas_password(
            key,
            spend_authorization,
            None,
            window,
            cx,
        );
    }

    pub(in crate::root) fn generate_send_calldata_authorized_with_gas_password(
        &mut self,
        key: UnshieldAssetKey,
        spend_authorization: DesktopPrivateSpendAuthorization,
        gas_payer_password: Option<Zeroizing<String>>,
        window: &Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(draft) = self.send_spend_draft(key, cx) else {
            return;
        };
        let SendSpendDraft {
            asset,
            delivery_mode,
            broadcaster_choice,
            cost_estimate,
            fee_token,
            self_broadcast_gas_fee,
            self_broadcast_initial_gas_fee,
            fee_mode,
            view_session,
            vault_store,
            session,
            recipient,
            amount,
            self_broadcast_public_account_uuid,
            self_broadcast_gas_payer_display,
            self_broadcast_gas_payer_source,
            fee_rows,
            fee_policy,
            favorites_only_broadcasters,
        } = draft;

        let self_broadcast_vault_password = if delivery_mode == DeliveryMode::SelfBroadcast {
            if self_broadcast_gas_payer_source == Some(PublicAccountSource::HardwareDerived) {
                None
            } else if let Some(password) = gas_payer_password {
                Some(password)
            } else {
                match &spend_authorization {
                    DesktopPrivateSpendAuthorization::VaultPassword(password) => {
                        Some(password.clone())
                    }
                    DesktopPrivateSpendAuthorization::PreauthorizedSigner(_) => {
                        self.set_send_form_error(
                            key,
                            SOFTWARE_SELF_BROADCAST_GAS_PAYER_PASSWORD_REQUIRED,
                            cx,
                        );
                        return;
                    }
                }
            }
        } else {
            None
        };

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
                    self.public_broadcaster_response_timeout,
                    self.public_broadcaster_republish_interval,
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
                    spend_authorization,
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
                    spend_authorization,
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
                    fee_mode,
                    fee_policy,
                    trust_filter: self.public_broadcaster_trust_filter(favorites_only_broadcasters),
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
                    spend_authorization,
                    vault_password: self_broadcast_vault_password,
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
        if delivery_mode != DeliveryMode::ManualCalldata {
            self.set_private_broadcaster_task_abort_handle(
                DeliveryFormKind::Send,
                key,
                generation_id,
                join.abort_handle(),
            );
        }
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
                let mut clear_spend_authorization = false;
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
                            if is_spend_authorization_failure_error(&message) {
                                clear_spend_authorization = true;
                            }
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
                if clear_spend_authorization {
                    root.clear_spend_authorization(cx);
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

    pub(in crate::root) fn watch_send_generation_stage(
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

    pub(in crate::root) fn generate_unshield_calldata_from_form(
        &mut self,
        key: UnshieldAssetKey,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(draft) = self.unshield_spend_draft(key, cx) else {
            return;
        };
        let requires_gas_payer_password = self.selected_wallet_source().is_hardware_derived()
            && self_broadcast_requires_software_gas_payer_password(
                draft.delivery_mode,
                draft.self_broadcast_gas_payer_source,
            );
        let intent = if requires_gas_payer_password {
            SpendAuthorizationIntent::PrivateUnshieldSelfBroadcastGasPassword(key)
        } else {
            SpendAuthorizationIntent::PrivateUnshield(key)
        };
        let summary = if requires_gas_payer_password {
            private_unshield_gas_payer_authorization_summary(&draft)
        } else {
            private_unshield_authorization_summary(&draft)
        };
        self.request_spend_authorization(intent, summary, window, cx);
    }

    pub(in crate::root) fn unshield_spend_draft(
        &mut self,
        key: UnshieldAssetKey,
        cx: &mut Context<'_, Self>,
    ) -> Option<UnshieldSpendDraft> {
        let form = self.unshield_forms.get(&key)?;
        if form.generating {
            return None;
        }
        let asset = form.asset.clone();
        let unwrap = form.unwrap;
        let recipient_input = form.recipient_input.clone();
        let amount_input = form.amount_input.clone();
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
                    return None;
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
        let fee_mode = effective_fee_handling_mode(
            DeliveryFormKind::Unshield,
            asset.token,
            fee_token,
            form.fee_mode,
        );
        let allow_suspicious_broadcasters = form.allow_suspicious_broadcasters;
        let favorites_only_broadcasters = form.favorites_only_broadcasters;

        let Some(view_session) = self.view_session.clone() else {
            self.set_unshield_form_error(key, "Unlock the wallet vault before unshielding", cx);
            return None;
        };
        let Some(vault_store) = self.vault_store.clone() else {
            self.set_unshield_form_error(key, "Wallet vault storage is unavailable", cx);
            return None;
        };
        let Some(ChainUtxoState::Ready { session, .. }) = self.chain_states.get(&asset.chain_id)
        else {
            self.set_unshield_form_error(
                key,
                "Wait for wallet sync to finish before unshielding",
                cx,
            );
            return None;
        };
        let session = Arc::clone(session);
        if asset.max_batched.is_zero() {
            self.set_unshield_form_error(
                key,
                "No POI-verified private notes are spendable in a batched unshield",
                cx,
            );
            return None;
        }

        let recipient_raw = recipient_input.read(cx).value().to_string();
        let Some(recipient) = parse_address(recipient_raw.trim()) else {
            self.set_unshield_form_error(key, "Enter a valid public EVM recipient address", cx);
            return None;
        };
        let amount_raw = amount_input.read(cx).value().to_string();
        let amount = match parse_unshield_amount(amount_raw.as_str(), asset.decimals) {
            Ok(amount) if !amount.is_zero() => amount,
            Ok(_) => {
                self.set_unshield_form_error(key, "Enter an amount greater than zero", cx);
                return None;
            }
            Err(error) => {
                self.set_unshield_form_error(key, error.to_string(), cx);
                return None;
            }
        };
        let max_entered_amount = unshield_form_max_entered_amount(form, delivery_mode, fee_mode)
            .unwrap_or(asset.max_batched);
        if amount > max_entered_amount {
            self.set_unshield_form_error(
                key,
                format!(
                    "Amount exceeds max POI-verified batched transaction: {}",
                    format_unshield_amount_input(max_entered_amount, asset.decimals)
                ),
                cx,
            );
            return None;
        }

        let (
            self_broadcast_public_account_uuid,
            self_broadcast_gas_payer_display,
            self_broadcast_gas_payer_source,
        ) = if delivery_mode == DeliveryMode::SelfBroadcast {
            let Some(uuid) = self_broadcast_gas_payer_uuid else {
                self.set_unshield_form_error(key, "Choose a Public account to pay gas", cx);
                return None;
            };
            let Some(account) = self.selected_self_broadcast_gas_payer_account(Some(uuid.as_ref()))
            else {
                self.set_unshield_form_error(key, "Choose an active Public account to pay gas", cx);
                return None;
            };
            let gas_payer_display = public_account_display_label(account).map_or_else(
                || short_address(&account.address),
                |label| format!("{label} · {}", short_address(&account.address)),
            );
            (
                Some(uuid.to_string()),
                Some(gas_payer_display),
                Some(account.source),
            )
        } else {
            (None, None, None)
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
                favorites_only_broadcasters,
                policy,
            );
            let trust_filter = self.public_broadcaster_trust_filter(favorites_only_broadcasters);
            if let Err(error) = select_public_broadcaster_with_policy_and_trust(
                &candidates,
                &public_broadcaster_selection,
                policy,
                &trust_filter,
            ) {
                self.set_unshield_form_error(key, error.to_string(), cx);
                return None;
            }
            rows
        } else {
            Vec::new()
        };
        let fee_policy = self.public_broadcaster_fee_policy(allow_suspicious_broadcasters);

        Some(UnshieldSpendDraft {
            asset,
            unwrap,
            delivery_mode,
            broadcaster_choice,
            cost_estimate,
            fee_token,
            self_broadcast_gas_fee,
            self_broadcast_initial_gas_fee,
            fee_mode,
            view_session,
            vault_store,
            session,
            recipient,
            amount,
            self_broadcast_public_account_uuid,
            self_broadcast_gas_payer_display,
            self_broadcast_gas_payer_source,
            fee_rows,
            fee_policy,
            favorites_only_broadcasters,
        })
    }

    pub(in crate::root) fn generate_unshield_calldata_authorized(
        &mut self,
        key: UnshieldAssetKey,
        spend_authorization: DesktopPrivateSpendAuthorization,
        window: &Window,
        cx: &mut Context<'_, Self>,
    ) {
        self.generate_unshield_calldata_authorized_with_gas_password(
            key,
            spend_authorization,
            None,
            window,
            cx,
        );
    }

    pub(in crate::root) fn generate_unshield_calldata_authorized_with_gas_password(
        &mut self,
        key: UnshieldAssetKey,
        spend_authorization: DesktopPrivateSpendAuthorization,
        gas_payer_password: Option<Zeroizing<String>>,
        window: &Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(draft) = self.unshield_spend_draft(key, cx) else {
            return;
        };
        let UnshieldSpendDraft {
            asset,
            unwrap,
            delivery_mode,
            broadcaster_choice,
            cost_estimate,
            fee_token,
            self_broadcast_gas_fee,
            self_broadcast_initial_gas_fee,
            fee_mode,
            view_session,
            vault_store,
            session,
            recipient,
            amount,
            self_broadcast_public_account_uuid,
            self_broadcast_gas_payer_display,
            self_broadcast_gas_payer_source,
            fee_rows,
            fee_policy,
            favorites_only_broadcasters,
        } = draft;

        let self_broadcast_vault_password = if delivery_mode == DeliveryMode::SelfBroadcast {
            if self_broadcast_gas_payer_source == Some(PublicAccountSource::HardwareDerived) {
                None
            } else if let Some(password) = gas_payer_password {
                Some(password)
            } else {
                match &spend_authorization {
                    DesktopPrivateSpendAuthorization::VaultPassword(password) => {
                        Some(password.clone())
                    }
                    DesktopPrivateSpendAuthorization::PreauthorizedSigner(_) => {
                        self.set_unshield_form_error(
                            key,
                            SOFTWARE_SELF_BROADCAST_GAS_PAYER_PASSWORD_REQUIRED,
                            cx,
                        );
                        return;
                    }
                }
            }
        } else {
            None
        };

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
                    self.public_broadcaster_response_timeout,
                    self.public_broadcaster_republish_interval,
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
                    spend_authorization,
                    token,
                    fee_token,
                    amount,
                    fee_mode,
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
                    spend_authorization,
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
                    fee_mode,
                    fee_policy,
                    trust_filter: self.public_broadcaster_trust_filter(favorites_only_broadcasters),
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
                    spend_authorization,
                    vault_password: self_broadcast_vault_password,
                    public_account_uuid: self_broadcast_public_account_uuid
                        .expect("self-broadcast gas payer was validated"),
                    token,
                    fee_token,
                    amount,
                    fee_mode,
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
        if delivery_mode != DeliveryMode::ManualCalldata {
            self.set_private_broadcaster_task_abort_handle(
                DeliveryFormKind::Unshield,
                key,
                generation_id,
                join.abort_handle(),
            );
        }
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
                let mut clear_spend_authorization = false;
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
                            if is_spend_authorization_failure_error(&message) {
                                clear_spend_authorization = true;
                            }
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
                if clear_spend_authorization {
                    root.clear_spend_authorization(cx);
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

    pub(in crate::root) fn watch_unshield_generation_stage(
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

    pub(in crate::root) fn watch_self_broadcast_session_events(
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
                    SelfBroadcastSessionEvent::PendingOutputPoiProofsRequired { required } => {
                        root.set_private_self_broadcast_unshield_poi_step(
                            kind,
                            key,
                            generation_id,
                            required,
                            cx,
                        );
                    }
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
}
