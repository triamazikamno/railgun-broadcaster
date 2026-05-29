use super::*;

impl WalletRoot {
    pub(in crate::root) fn open_public_action_dialog(
        &mut self,
        public_account_uuid: Arc<str>,
        asset: PublicAssetId,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        window.close_all_dialogs(cx);
        self.set_public_selected_balance(public_account_uuid, asset, window, cx);
        self.public_form.action_mode = PublicActionMode::Shield;
        self.clear_public_action_dialog_inputs(window, cx);
        let root = cx.entity();
        let dialog_width = (window.viewport_size().width * 0.92).min(PUBLIC_ACTION_DIALOG_WIDTH);
        let content_width = secondary_dialog_content_width(dialog_width);
        let asset_label = public_asset_label(
            self.selected_chain,
            asset,
            Some(&self.effective_token_registry),
        );
        let icon_path = public_asset_icon_path(
            self.selected_chain,
            asset,
            Some(&self.effective_token_registry),
        );
        window.open_dialog(cx, move |dialog, _window, cx| {
            let close_root = root.clone();
            let content_root = root.clone();
            dialog
                .w(dialog_width)
                .title(public_action_title_row(
                    asset_label.clone(),
                    icon_path.clone(),
                ))
                .on_close(move |_event, window, cx| {
                    close_root.update(cx, |root, cx| {
                        root.clear_public_action_dialog_inputs(window, cx);
                    });
                })
                .child(
                    content_root
                        .read(cx)
                        .render_public_action_dialog_content(content_root.clone(), content_width),
                )
        });
        self.refresh_public_action_gas_fee_quote(PublicActionMode::Shield, cx);
        cx.defer_in(window, |root, window, cx| {
            root.focus_public_action_dialog_input(window, cx);
        });
    }

    pub(in crate::root) fn focus_public_action_dialog_input(
        &self,
        window: &mut Window,
        cx: &Context<'_, Self>,
    ) {
        match self.public_form.action_mode {
            PublicActionMode::Shield => self
                .public_form
                .shield_amount_input
                .read(cx)
                .focus_handle(cx)
                .focus(window),
            PublicActionMode::Send => self
                .public_form
                .send_recipient_input
                .read(cx)
                .focus_handle(cx)
                .focus(window),
        }
    }

    pub(in crate::root) fn render_public_action_dialog_content(
        &self,
        root: Entity<Self>,
        content_width: Pixels,
    ) -> gpui::Div {
        let mode = self.public_form.action_mode;
        let account = self.selected_public_account();
        let selected_asset = self.public_form.selected_asset;
        let balance_entry = self.selected_public_balance_entry();
        let asset_label = selected_asset.map_or_else(
            || "selected asset".to_string(),
            |asset| {
                public_asset_label(
                    self.selected_chain,
                    asset,
                    Some(&self.effective_token_registry),
                )
            },
        );
        let disabled = account.is_none() || selected_asset.is_none();
        let submitting = self.public_form.sending || self.public_form.shielding;
        let mode_root = root.clone();
        let submit_root = root.clone();
        let gas_fee_root = root.clone();
        let progress_root = root.clone();
        let max_root = root;
        let show_form_errors = !self.public_action_has_active_progress();
        let max_label = balance_entry.as_ref().and_then(public_action_max_label);
        let amount_hint = format!("{asset_label} amount");
        let mut content = div()
            .w(content_width)
            .flex()
            .flex_col()
            .gap_3()
            .children(account.map(|account| {
                app_muted_text(format!("From {}", short_address(&account.address)))
                    .font_family(APP_MONO_FONT_FAMILY)
            }))
            .child(
                ButtonGroup::new("wallet-public-action-mode-toggle")
                    .w_full()
                    .outline()
                    .disabled(submitting)
                    .child(public_action_segment_button(
                        "wallet-public-action-mode-shield".into(),
                        "Shield",
                        Icon::new(RailgunActionIcon::Shield),
                        mode == PublicActionMode::Shield,
                    ))
                    .child(public_action_segment_button(
                        "wallet-public-action-mode-send".into(),
                        "Send",
                        Icon::new(RailgunActionIcon::Send),
                        mode == PublicActionMode::Send,
                    ))
                    .on_click(move |selected, window, cx| {
                        let Some(index) = selected.first() else {
                            return;
                        };
                        let mode = if *index == 0 {
                            PublicActionMode::Shield
                        } else {
                            PublicActionMode::Send
                        };
                        mode_root.update(cx, |root, cx| {
                            root.set_public_action_mode(mode, window, cx);
                        });
                    }),
            );

        match mode {
            PublicActionMode::Shield => {
                content = content
                    .child(render_public_action_amount_input(
                        max_root,
                        PublicActionMode::Shield,
                        &self.public_form.shield_amount_input,
                        amount_hint,
                        max_label,
                        disabled || self.public_form.shielding,
                    ))
                    .child(render_eip1559_gas_fee_editor(
                        gas_fee_root,
                        Eip1559GasFeeTarget::Public {
                            mode: PublicActionMode::Shield,
                        },
                        &self.public_form.shield_gas_fee,
                        disabled || self.public_form.shielding,
                    ))
                    .child(
                        app_button(
                            "wallet-public-shield",
                            if self.public_form.shielding {
                                "Shielding..."
                            } else {
                                "Shield"
                            },
                        )
                        .primary()
                        .small()
                        .loading(self.public_form.shielding)
                        .disabled(disabled || self.public_form.shielding)
                        .on_click(move |_event, window, cx| {
                            submit_root.update(cx, |root, cx| {
                                root.submit_public_shield_from_form(window, cx);
                            });
                        }),
                    );
                if show_form_errors && let Some(error) = self.public_form.shield_error.as_ref() {
                    content = content.child(
                        Alert::error("wallet-public-shield-error", error.to_string()).small(),
                    );
                }
            }
            PublicActionMode::Send => {
                content = content
                    .child(
                        app_input(&self.public_form.send_recipient_input)
                            .disabled(disabled || self.public_form.sending),
                    )
                    .child(render_public_action_amount_input(
                        max_root,
                        PublicActionMode::Send,
                        &self.public_form.send_amount_input,
                        amount_hint,
                        max_label,
                        disabled || self.public_form.sending,
                    ))
                    .child(render_eip1559_gas_fee_editor(
                        gas_fee_root,
                        Eip1559GasFeeTarget::Public {
                            mode: PublicActionMode::Send,
                        },
                        &self.public_form.send_gas_fee,
                        disabled || self.public_form.sending,
                    ))
                    .child(
                        app_button(
                            "wallet-public-send",
                            if self.public_form.sending {
                                "Sending..."
                            } else {
                                "Send publicly"
                            },
                        )
                        .primary()
                        .small()
                        .loading(self.public_form.sending)
                        .disabled(disabled || self.public_form.sending)
                        .on_click(move |_event, window, cx| {
                            submit_root.update(cx, |root, cx| {
                                root.submit_public_send_from_form(window, cx);
                            });
                        }),
                    );
                if show_form_errors && let Some(error) = self.public_form.send_error.as_ref() {
                    content = content
                        .child(Alert::error("wallet-public-send-error", error.to_string()).small());
                }
            }
        }

        if !self.public_form.action_progress_dialog_open
            && let Some(active_step) =
                public_action_closed_active_step(&self.public_form.action_progress)
        {
            content = content.child(render_public_action_active_status_notice(
                progress_root,
                mode,
                active_step,
            ));
        }

        content
    }

    pub(in crate::root) fn clear_public_action_dialog_inputs(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        for input in [
            &self.public_form.send_recipient_input,
            &self.public_form.send_amount_input,
            &self.public_form.shield_amount_input,
        ] {
            input.update(cx, |input, cx| input.set_value("", window, cx));
        }
        self.public_form.send_error = None;
        self.public_form.shield_error = None;
        if !self.public_form.sending && !self.public_form.shielding {
            self.clear_public_action_progress_state();
        }
    }

    pub(in crate::root) fn set_public_action_mode(
        &mut self,
        mode: PublicActionMode,
        window: &Window,
        cx: &mut Context<'_, Self>,
    ) {
        if self.public_form.action_mode == mode {
            return;
        }
        self.public_form.action_mode = mode;
        self.public_form.send_error = None;
        self.public_form.shield_error = None;
        self.clear_public_action_progress_state();
        self.refresh_public_action_gas_fee_quote(mode, cx);
        cx.defer_in(window, |root, window, cx| {
            root.focus_public_action_dialog_input(window, cx);
        });
        cx.notify();
    }

    const fn public_action_has_active_progress(&self) -> bool {
        !self.public_form.action_progress.is_empty()
    }

    pub(in crate::root) fn clear_public_action_progress_state(&mut self) {
        if let Some(handle) = self.public_form.action_task_abort_handle.take() {
            handle.abort();
        }
        self.public_form.action_progress.clear();
        self.public_form.expanded_action_error_steps.clear();
        self.public_form.action_progress_dialog_open = false;
        self.public_form.action_progress_asset_label = Arc::from("");
        self.public_form.action_progress_icon_path = None;
        self.public_form.action_stop_available = false;
        self.public_form.action_stopped = false;
        self.public_form.action_command_tx = None;
        self.public_form.action_attempts.clear();
        self.public_form.action_current_gas_fee = None;
        self.public_form.action_action_error = None;
    }

    pub(in crate::root) fn set_public_action_gas_fee_mode(
        &mut self,
        action_mode: PublicActionMode,
        mode: Eip1559GasFeeMode,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let submitting = self.public_form.sending || self.public_form.shielding;
        let gas_fee = match action_mode {
            PublicActionMode::Shield => &mut self.public_form.shield_gas_fee,
            PublicActionMode::Send => &mut self.public_form.send_gas_fee,
        };
        if submitting || gas_fee.mode == mode {
            return;
        }
        if mode == Eip1559GasFeeMode::Custom {
            gas_fee.seed_custom_from_auto_if_empty(window, cx);
        }
        gas_fee.mode = mode;
        self.set_public_action_error(action_mode, None);
        cx.notify();
    }

    pub(in crate::root) fn customize_public_action_gas_fee_from_auto(
        &mut self,
        action_mode: PublicActionMode,
        target: Eip1559GasFeeEditTarget,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        if self.public_form.sending || self.public_form.shielding {
            return;
        }
        let gas_fee = match action_mode {
            PublicActionMode::Shield => &mut self.public_form.shield_gas_fee,
            PublicActionMode::Send => &mut self.public_form.send_gas_fee,
        };
        if !gas_fee.overwrite_custom_from_auto(window, cx) {
            return;
        }
        let focus_input = match target {
            Eip1559GasFeeEditTarget::MaxFee => gas_fee.max_fee_input.clone(),
            Eip1559GasFeeEditTarget::MaxTip => gas_fee.max_priority_fee_input.clone(),
        };
        gas_fee.mode = Eip1559GasFeeMode::Custom;
        self.set_public_action_error(action_mode, None);
        focus_input.read(cx).focus_handle(cx).focus(window);
        cx.notify();
    }

    pub(in crate::root) fn refresh_public_action_gas_fee_quote(
        &mut self,
        action_mode: PublicActionMode,
        cx: &mut Context<'_, Self>,
    ) {
        let submitting = self.public_form.sending || self.public_form.shielding;
        let gas_fee = match action_mode {
            PublicActionMode::Shield => &mut self.public_form.shield_gas_fee,
            PublicActionMode::Send => &mut self.public_form.send_gas_fee,
        };
        if submitting || gas_fee.refreshing {
            return;
        }
        gas_fee.refresh_id = gas_fee.refresh_id.wrapping_add(1);
        gas_fee.refreshing = true;
        gas_fee.error = None;
        let refresh_id = gas_fee.refresh_id;
        let chain_id = self.selected_chain;
        let effective_chain = self.effective_chain_configs.get(&chain_id).cloned();
        let http = self.http.clone();
        cx.spawn(async move |this, cx| {
            let result =
                quote_public_action_gas_fee(chain_id, effective_chain.as_ref(), &http).await;
            let _ = this.update(cx, |root, cx| {
                let gas_fee = match action_mode {
                    PublicActionMode::Shield => &mut root.public_form.shield_gas_fee,
                    PublicActionMode::Send => &mut root.public_form.send_gas_fee,
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

    pub(in crate::root) fn start_public_action_progress(
        &mut self,
        mode: PublicActionMode,
        asset: PublicAssetId,
        asset_label: String,
        icon_path: Option<WalletIconSource>,
        command_tx: Option<PublicActionCommandSender>,
        initial_gas_fee: Option<(u128, u128)>,
    ) -> u64 {
        self.public_form.action_generation = self.public_form.action_generation.wrapping_add(1);
        let generation = self.public_form.action_generation;
        self.public_form.expanded_action_error_steps.clear();
        self.public_form.action_progress_asset_label = Arc::from(asset_label);
        self.public_form.action_progress_icon_path = icon_path;
        self.public_form.action_progress_dialog_open = false;
        self.public_form.action_task_abort_handle = None;
        self.public_form.action_stop_available = true;
        self.public_form.action_stopped = false;
        self.public_form.action_command_tx = command_tx;
        self.public_form.action_attempts.clear();
        self.public_form.action_current_gas_fee = initial_gas_fee;
        self.public_form.action_action_error = None;
        self.public_form.action_progress = public_action_progress_steps(mode, asset)
            .into_iter()
            .map(|step| PublicActionStepState {
                step,
                status: PublicActionStepStatus::NotStarted,
                tx_hash: None,
                message: None,
            })
            .collect();
        if let Some(first) = self.public_form.action_progress.first_mut() {
            first.status = PublicActionStepStatus::Pending;
        }
        generation
    }

    pub(in crate::root) fn apply_public_action_progress_update(
        &mut self,
        generation: u64,
        update: PublicActionProgressUpdate,
        cx: &mut Context<'_, Self>,
    ) {
        if !public_action_accepts_update(
            self.public_form.action_generation,
            generation,
            self.public_form.action_stopped,
        ) {
            return;
        }
        let Some(step) = self
            .public_form
            .action_progress
            .iter_mut()
            .find(|step| step.step == update.step)
        else {
            return;
        };
        step.status = match update.status {
            PublicActionProgressStatus::Pending => PublicActionStepStatus::Pending,
            PublicActionProgressStatus::Done => PublicActionStepStatus::Done,
            PublicActionProgressStatus::Error => PublicActionStepStatus::Error,
        };
        if let Some(tx_hash) = update.tx_hash {
            step.tx_hash = Some(Arc::from(tx_hash));
        }
        if let Some(message) = update.message {
            step.message = Some(Arc::from(message));
        } else if update.status != PublicActionProgressStatus::Error {
            step.message = None;
        }
        cx.notify();
    }

    pub(in crate::root) fn fail_public_action_progress(
        &mut self,
        generation: u64,
        message: String,
        cx: &mut Context<'_, Self>,
    ) {
        if !public_action_accepts_update(
            self.public_form.action_generation,
            generation,
            self.public_form.action_stopped,
        ) {
            return;
        }
        if let Some(step) = self
            .public_form
            .action_progress
            .iter_mut()
            .find(|step| step.status == PublicActionStepStatus::Error)
        {
            let replace_message = match step.message.as_ref() {
                Some(existing) => message.len() > existing.len(),
                None => true,
            };
            if replace_message {
                step.message = Some(Arc::from(message));
            }
            cx.notify();
            return;
        }
        let step_index = self
            .public_form
            .action_progress
            .iter()
            .position(|step| step.status == PublicActionStepStatus::Pending)
            .or_else(|| {
                self.public_form
                    .action_progress
                    .iter()
                    .position(|step| step.status == PublicActionStepStatus::NotStarted)
            })
            .or_else(|| self.public_form.action_progress.len().checked_sub(1));
        if let Some(step_index) = step_index {
            let step = &mut self.public_form.action_progress[step_index];
            step.status = PublicActionStepStatus::Error;
            step.message = Some(Arc::from(message));
            self.public_form.action_command_tx = None;
            self.public_form.action_action_error = None;
            cx.notify();
        }
    }

    pub(in crate::root) fn spawn_public_action_progress_listener(
        generation: u64,
        chain_id: u64,
        active_wallet_id: Option<Arc<str>>,
        mut progress_rx: mpsc::UnboundedReceiver<PublicActionProgressUpdate>,
        cx: &Context<'_, Self>,
    ) {
        cx.spawn(async move |this, cx| {
            while let Some(update) = progress_rx.recv().await {
                let _ = this.update(cx, |root, cx| {
                    if root.selected_wallet_id != active_wallet_id
                        || root.selected_chain != chain_id
                    {
                        return;
                    }
                    root.apply_public_action_progress_update(generation, update, cx);
                });
            }
        })
        .detach();
    }

    pub(in crate::root) fn spawn_public_action_session_event_listener(
        generation: u64,
        chain_id: u64,
        active_wallet_id: Option<Arc<str>>,
        mut event_rx: mpsc::UnboundedReceiver<PublicActionSessionEvent>,
        cx: &Context<'_, Self>,
    ) {
        cx.spawn(async move |this, cx| {
            while let Some(event) = event_rx.recv().await {
                let _ = this.update(cx, |root, cx| {
                    if root.selected_wallet_id != active_wallet_id
                        || root.selected_chain != chain_id
                    {
                        return;
                    }
                    root.apply_public_action_session_event(generation, event, cx);
                });
            }
        })
        .detach();
    }

    pub(in crate::root) fn apply_public_action_session_event(
        &mut self,
        generation: u64,
        event: PublicActionSessionEvent,
        cx: &mut Context<'_, Self>,
    ) {
        if !public_action_accepts_update(
            self.public_form.action_generation,
            generation,
            self.public_form.action_stopped,
        ) {
            return;
        }
        match event {
            PublicActionSessionEvent::StepFailed { step, message } => {
                self.public_form.action_action_error = None;
                if let Some(progress_step) = self
                    .public_form
                    .action_progress
                    .iter_mut()
                    .find(|progress_step| progress_step.step == step)
                {
                    progress_step.status = PublicActionStepStatus::Error;
                    progress_step.message = Some(Arc::from(message));
                }
            }
            PublicActionSessionEvent::AttemptHandoff { step } => {
                if public_action_step_is_final_handoff(self.public_form.action_mode, step) {
                    self.public_form.action_stop_available = false;
                }
            }
            PublicActionSessionEvent::AttemptSubmitted { step, attempt } => {
                if public_action_step_is_final_handoff(self.public_form.action_mode, step) {
                    self.public_form.action_stop_available = false;
                }
                self.public_form.action_current_gas_fee =
                    Some((attempt.max_fee_per_gas, attempt.max_priority_fee_per_gas));
                self.public_form.action_action_error = None;
                self.public_form.action_attempts.push(attempt);
            }
            PublicActionSessionEvent::AttemptRejected { message, .. } => {
                self.public_form.action_action_error = Some(Arc::from(message));
            }
        }
        cx.notify();
    }

    pub(in crate::root) fn show_public_action_progress_dialog(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        if self.public_form.action_progress_dialog_open {
            return;
        }
        self.public_form.action_progress_dialog_open = true;
        let generation = self.public_form.action_generation;
        let mode = self.public_form.action_mode;
        let asset_label = Arc::clone(&self.public_form.action_progress_asset_label);
        let icon_path = self.public_form.action_progress_icon_path.clone();
        let root = cx.entity();
        let viewport_size = window.viewport_size();
        let dialog_width = (viewport_size.width * 0.92).min(PUBLIC_ACTION_DIALOG_WIDTH);
        let dialog_max_height = viewport_size.height * 0.84;
        let content_width = secondary_dialog_content_width(dialog_width);
        window.open_dialog(cx, move |dialog, _window, cx| {
            let close_root = root.clone();
            let content_root = root.clone();
            dialog
                .w(dialog_width)
                .max_h(dialog_max_height)
                .title(public_action_title_row(
                    format!("{} {}", public_action_mode_verb(mode), asset_label.as_ref()),
                    icon_path.clone(),
                ))
                .on_close(move |_event, _window, cx| {
                    close_root.update(cx, |root, cx| {
                        if root.public_form.action_generation == generation {
                            if root.public_form.action_stopped {
                                root.clear_public_action_progress_state();
                            } else {
                                root.public_form.action_progress_dialog_open = false;
                            }
                            cx.notify();
                        }
                    });
                })
                .child(
                    content_root
                        .read(cx)
                        .render_public_action_progress_dialog_content(&content_root, content_width),
                )
        });
    }

    pub(in crate::root) fn stop_public_action_progress(&mut self, cx: &mut Context<'_, Self>) {
        if public_action_progress_footer_action(
            self.public_form.action_stop_available,
            &self.public_form.action_progress,
        ) != ProgressFooterAction::Stop
        {
            return;
        }
        if let Some(handle) = self.public_form.action_task_abort_handle.take() {
            handle.abort();
        }
        self.public_form.action_command_tx = None;
        self.public_form.action_action_error = None;
        self.public_form.action_stop_available = false;
        self.public_form.action_stopped = true;
        match self.public_form.action_mode {
            PublicActionMode::Shield => self.public_form.shielding = false,
            PublicActionMode::Send => self.public_form.sending = false,
        }
        mark_public_action_active_step_stopped(&mut self.public_form.action_progress);
        cx.notify();
    }

    pub(in crate::root) fn close_public_action_progress_dialog(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        if self.public_form.action_stopped {
            self.clear_public_action_progress_state();
        } else {
            self.public_form.action_progress_dialog_open = false;
        }
        window.close_dialog(cx);
        cx.notify();
    }

    pub(in crate::root) fn render_public_action_progress_dialog_content(
        &self,
        root: &Entity<Self>,
        content_width: Pixels,
    ) -> gpui::Div {
        if self.public_form.action_progress.is_empty() {
            return div()
                .w(content_width)
                .child(app_muted_text("No active Public action."));
        }
        let mut content =
            div()
                .w(content_width)
                .flex()
                .flex_col()
                .gap_3()
                .child(render_public_action_stepper(
                    root,
                    &self.public_form.action_progress,
                    &self.public_form.expanded_action_error_steps,
                    self.public_form.action_progress_asset_label.as_ref(),
                    self.public_form.action_command_tx.is_some(),
                    self.public_form.action_current_gas_fee,
                    self.public_form.action_action_error.as_deref(),
                    self.public_form.action_generation,
                ));

        if let Some((max_fee, max_tip)) = self.public_form.action_current_gas_fee {
            content = content.child(
                div()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .p(px(12.0))
                    .rounded_md()
                    .bg(rgb(theme::SURFACE_ELEVATED))
                    .border_1()
                    .border_color(rgb(theme::BORDER))
                    .child(app_strong_text("Gas fee"))
                    .child(public_action_context_row(
                        "Max fee",
                        format!("{} gwei", format_gwei(max_fee)),
                    ))
                    .child(public_action_context_row(
                        "Max tip",
                        format!("{} gwei", format_gwei(max_tip)),
                    )),
            );
        }
        content = content.child(render_public_action_progress_footer(
            root.clone(),
            public_action_progress_footer_action(
                self.public_form.action_stop_available,
                &self.public_form.action_progress,
            ),
        ));
        content
    }

    pub(in crate::root) fn open_public_action_gas_retry_dialog(
        &self,
        generation: u64,
        retry_kind: PublicActionGasRetryKind,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        if self.public_form.action_generation != generation
            || self.public_form.action_command_tx.is_none()
        {
            return;
        }
        let (mut max_fee, mut max_tip) = self.public_form.action_current_gas_fee.unwrap_or((
            PUBLIC_ACTION_RETRY_DEFAULT_FEE_WEI,
            PUBLIC_ACTION_RETRY_DEFAULT_FEE_WEI,
        ));
        if retry_kind == PublicActionGasRetryKind::SpeedUp {
            max_fee = public_action_replacement_bumped_fee(max_fee);
            max_tip = public_action_replacement_bumped_fee(max_tip);
        }
        let root = cx.entity();
        let content = cx.new(|cx| {
            PublicActionGasRetryDialogContent::new(
                root, generation, retry_kind, max_fee, max_tip, window, cx,
            )
        });
        let dialog_width = (window.viewport_size().width * 0.92).min(px(460.0));
        window.open_dialog(cx, move |dialog, _window, _cx| {
            dialog.w(dialog_width).child(content.clone())
        });
    }

    pub(in crate::root) fn submit_public_action_gas_retry(
        &mut self,
        generation: u64,
        retry_kind: PublicActionGasRetryKind,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
        cx: &mut Context<'_, Self>,
    ) {
        if self.public_form.action_generation != generation {
            return;
        }
        let Some(command_tx) = self.public_form.action_command_tx.as_ref() else {
            return;
        };
        let kind = match retry_kind {
            PublicActionGasRetryKind::RetryEstimate => PublicActionCommandKind::Retry,
            PublicActionGasRetryKind::SpeedUp => PublicActionCommandKind::Replacement,
        };
        let send_result = command_tx.send(PublicActionCommand {
            kind,
            gas_fee: PublicActionGasFeeSelection::Custom {
                max_fee_per_gas,
                max_priority_fee_per_gas,
            },
        });
        self.public_form.action_action_error = send_result
            .err()
            .map(|_| Arc::from("Public action is no longer accepting retry commands."));
        cx.notify();
    }

    pub(in crate::root) fn set_public_action_error_details_open(
        &mut self,
        step: PublicActionProgressStep,
        open: bool,
        cx: &mut Context<'_, Self>,
    ) {
        if open {
            self.public_form.expanded_action_error_steps.insert(step);
        } else {
            self.public_form.expanded_action_error_steps.remove(&step);
        }
        cx.notify();
    }

    pub(in crate::root) fn set_public_action_amount_to_max(
        &mut self,
        mode: PublicActionMode,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(entry) = self.selected_public_balance_entry() else {
            return;
        };
        let Some(amount) = entry.amount.amount() else {
            return;
        };
        let decimals = entry.asset.decimals;
        if entry.asset.id != PublicAssetId::Native {
            self.set_public_action_amount_input(mode, amount, decimals, window, cx);
            self.set_public_action_error(mode, None);
            cx.notify();
            return;
        }

        let Some(public_account_uuid) = self.public_form.selected_account_uuid.clone() else {
            return;
        };
        let chain_id = self.selected_chain;
        let selected_wallet_id = self.selected_wallet_id.clone();
        let symbol = entry.asset.symbol;
        let http = self.http.clone();
        let steps = public_action_progress_steps(mode, PublicAssetId::Native);
        let effective_chain = self.effective_chain_configs.get(&chain_id).cloned();
        let gas_fee = match self.public_action_gas_fee_selection(mode, cx) {
            Ok(selection) => selection,
            Err(error) => {
                self.set_public_action_error(mode, Some(Arc::from(error)));
                cx.notify();
                return;
            }
        };
        let join = self.runtime.spawn(async move {
            estimate_public_native_action_gas_reserve(
                chain_id,
                &steps,
                effective_chain.as_ref(),
                gas_fee,
                &http,
            )
            .await
        });
        self.set_public_action_error(mode, None);
        cx.spawn_in(window, async move |this, cx| {
            let result = join.await;
            let _ = this.update_in(cx, |root, window, cx| {
                if root.selected_wallet_id != selected_wallet_id
                    || root.selected_chain != chain_id
                    || root.public_form.action_mode != mode
                    || root.public_form.selected_asset != Some(PublicAssetId::Native)
                    || root.public_form.selected_account_uuid.as_deref()
                        != Some(public_account_uuid.as_ref())
                {
                    return;
                }
                match result {
                    Ok(Ok(reserve)) => {
                        match public_action_max_amount_after_reserve(amount, reserve) {
                            Some(max_amount) => {
                                root.set_public_action_amount_input(
                                    mode, max_amount, decimals, window, cx,
                                );
                                root.set_public_action_error(mode, None);
                            }
                            None => root.set_public_action_error(
                                mode,
                                Some(Arc::from(format!(
                                    "Not enough {symbol} balance after estimated gas"
                                ))),
                            ),
                        }
                    }
                    Ok(Err(error)) => root.set_public_action_error(
                        mode,
                        Some(Arc::from(format!(
                            "Could not estimate gas reserve for Max: {}",
                            format_report_chain(&error)
                        ))),
                    ),
                    Err(error) => root.set_public_action_error(
                        mode,
                        Some(Arc::from(format!(
                            "Could not estimate gas reserve for Max: {error}"
                        ))),
                    ),
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    pub(in crate::root) fn set_public_action_amount_input(
        &self,
        mode: PublicActionMode,
        amount: U256,
        decimals: u8,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let value = format_send_amount_input(amount, Some(decimals));
        let input = match mode {
            PublicActionMode::Shield => &self.public_form.shield_amount_input,
            PublicActionMode::Send => &self.public_form.send_amount_input,
        };
        input.update(cx, |input, cx| input.set_value(value, window, cx));
    }

    pub(in crate::root) fn set_public_action_error(
        &mut self,
        mode: PublicActionMode,
        message: Option<Arc<str>>,
    ) {
        match mode {
            PublicActionMode::Shield => self.public_form.shield_error = message,
            PublicActionMode::Send => self.public_form.send_error = message,
        }
    }

    pub(in crate::root) fn public_action_gas_fee_selection(
        &self,
        mode: PublicActionMode,
        cx: &Context<'_, Self>,
    ) -> Result<PublicActionGasFeeSelection, String> {
        match mode {
            PublicActionMode::Shield => self.public_form.shield_gas_fee.selection(cx),
            PublicActionMode::Send => self.public_form.send_gas_fee.selection(cx),
        }
    }

    pub(in crate::root) fn public_action_initial_gas_values(
        &self,
        mode: PublicActionMode,
        selection: &PublicActionGasFeeSelection,
    ) -> Option<(u128, u128)> {
        match selection {
            PublicActionGasFeeSelection::Custom {
                max_fee_per_gas,
                max_priority_fee_per_gas,
            } => Some((*max_fee_per_gas, *max_priority_fee_per_gas)),
            PublicActionGasFeeSelection::Auto => {
                let quote = match mode {
                    PublicActionMode::Shield => self.public_form.shield_gas_fee.quote,
                    PublicActionMode::Send => self.public_form.send_gas_fee.quote,
                }?;
                Some((
                    quote.suggested_max_fee_per_gas,
                    quote.suggested_max_priority_fee_per_gas,
                ))
            }
        }
    }

    pub(in crate::root) fn submit_public_send_from_form(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        if self.public_form.sending {
            return;
        }
        self.clear_public_action_progress_state();
        let Some(draft) = self.public_send_draft(cx) else {
            return;
        };
        self.request_spend_authorization(
            SpendAuthorizationIntent::PublicSend,
            public_send_authorization_summary(&draft),
            window,
            cx,
        );
    }

    pub(in crate::root) fn public_send_draft(
        &mut self,
        cx: &mut Context<'_, Self>,
    ) -> Option<PublicSendDraft> {
        let Some(asset) = self.public_form.selected_asset else {
            self.public_form.send_error = Some(Arc::from("Select an asset to send"));
            cx.notify();
            return None;
        };
        let Some(public_account_uuid) = self.public_form.selected_account_uuid.clone() else {
            self.public_form.send_error = Some(Arc::from("Select a public account first"));
            cx.notify();
            return None;
        };
        let Some(view_session) = self.view_session.clone() else {
            self.public_form.send_error = Some(Arc::from("Wallet vault is locked"));
            cx.notify();
            return None;
        };
        let Some(vault_store) = self.vault_store.clone() else {
            self.public_form.send_error = Some(Arc::from("Wallet vault storage is unavailable"));
            cx.notify();
            return None;
        };
        let chain_id = self.selected_chain;
        let asset_decimals =
            public_asset_decimals(chain_id, asset, Some(&self.effective_token_registry));
        let asset_label =
            public_action_asset_label(chain_id, asset, Some(&self.effective_token_registry));
        let asset_icon_path =
            public_asset_icon_path(chain_id, asset, Some(&self.effective_token_registry));
        let public_account_label = self
            .public_account_for_uuid(Some(public_account_uuid.as_ref()))
            .map_or_else(
                || public_account_uuid.to_string(),
                |account| {
                    public_account_display_label(account)
                        .unwrap_or_else(|| short_address(&account.address))
                },
            );
        let amount_input = self
            .public_form
            .send_amount_input
            .read(cx)
            .value()
            .to_string();
        let amount = match parse_send_amount(&amount_input, asset_decimals) {
            Ok(amount) if !amount.is_zero() => amount,
            Ok(_) => {
                self.public_form.send_error = Some(Arc::from("Amount must be greater than zero"));
                cx.notify();
                return None;
            }
            Err(error) => {
                self.public_form.send_error = Some(Arc::from(error.to_string()));
                cx.notify();
                return None;
            }
        };
        let Some(recipient) = parse_address(
            self.public_form
                .send_recipient_input
                .read(cx)
                .value()
                .as_ref(),
        ) else {
            self.public_form.send_error = Some(Arc::from("Enter a valid EVM recipient address"));
            cx.notify();
            return None;
        };
        let gas_fee = match self.public_action_gas_fee_selection(PublicActionMode::Send, cx) {
            Ok(selection) => selection,
            Err(error) => {
                self.public_form.send_error = Some(Arc::from(error));
                cx.notify();
                return None;
            }
        };
        Some(PublicSendDraft {
            chain_id,
            asset,
            asset_label,
            asset_icon_path,
            asset_decimals,
            public_account_uuid,
            public_account_label,
            view_session,
            vault_store,
            amount,
            recipient,
            gas_fee,
        })
    }

    pub(in crate::root) fn submit_public_send_authorized(
        &mut self,
        vault_password: Zeroizing<String>,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        if self.public_form.sending {
            return;
        }
        let Some(draft) = self.public_send_draft(cx) else {
            return;
        };
        let PublicSendDraft {
            chain_id,
            asset,
            asset_label,
            public_account_uuid,
            view_session,
            vault_store,
            amount,
            recipient,
            gas_fee,
            ..
        } = draft;
        self.public_form.sending = true;
        self.public_form.send_error = None;
        let http = self.http.clone();
        let active_wallet_id = self.selected_wallet_id.clone();
        let icon_path =
            public_asset_icon_path(chain_id, asset, Some(&self.effective_token_registry));
        let initial_gas_fee =
            self.public_action_initial_gas_values(PublicActionMode::Send, &gas_fee);
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let generation = self.start_public_action_progress(
            PublicActionMode::Send,
            asset,
            asset_label,
            icon_path,
            Some(command_tx),
            initial_gas_fee,
        );
        let (progress_tx, progress_rx) = mpsc::unbounded_channel();
        Self::spawn_public_action_progress_listener(
            generation,
            chain_id,
            active_wallet_id.clone(),
            progress_rx,
            cx,
        );
        Self::spawn_public_action_session_event_listener(
            generation,
            chain_id,
            active_wallet_id.clone(),
            event_rx,
            cx,
        );
        self.show_public_action_progress_dialog(window, cx);
        let request = PublicSendRequest {
            chain_id,
            effective_chain: self.effective_chain_configs.get(&chain_id).cloned(),
            view_session,
            vault_store,
            vault_password,
            public_account_uuid: public_account_uuid.to_string(),
            asset,
            amount,
            recipient,
            gas_fee,
            command_rx: Some(command_rx),
            event_tx: Some(event_tx),
        };
        let submitted_public_account_uuid = Arc::clone(&public_account_uuid);
        let join = self.runtime.spawn(async move {
            submit_public_send_with_progress(request, &http, move |update| {
                let _ = progress_tx.send(update);
            })
            .await
        });
        self.public_form.action_task_abort_handle = Some(join.abort_handle());
        cx.spawn(async move |this, cx| {
            let result = join.await;
            let _ = this.update(cx, |root, cx| {
                if root.selected_wallet_id != active_wallet_id || root.selected_chain != chain_id {
                    return;
                }
                if !public_action_accepts_update(
                    root.public_form.action_generation,
                    generation,
                    root.public_form.action_stopped,
                ) {
                    return;
                }
                root.public_form.sending = false;
                root.public_form.action_task_abort_handle = None;
                match result {
                    Ok(Ok(_result)) => {
                        root.public_form.action_command_tx = None;
                        root.public_form.action_action_error = None;
                        match root
                            .public_account_for_uuid(Some(submitted_public_account_uuid.as_ref()))
                            .map(|account| account.status)
                        {
                            Some(PublicAccountStatus::Inactive) => {
                                root.schedule_inactive_public_balance_refresh(cx);
                            }
                            _ => root.schedule_public_balance_refresh(cx),
                        }
                    }
                    Ok(Err(error)) => {
                        let message = error.to_string();
                        if is_spend_authorization_failure_error(&message) {
                            root.clear_spend_authorization(cx);
                        }
                        root.public_form.action_command_tx = None;
                        root.fail_public_action_progress(generation, message.clone(), cx);
                        root.public_form.send_error = Some(Arc::from(message));
                    }
                    Err(error) => {
                        let message = format!("Public send task failed: {error}");
                        root.public_form.action_command_tx = None;
                        root.fail_public_action_progress(generation, message.clone(), cx);
                        root.public_form.send_error = Some(Arc::from(message));
                    }
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    pub(in crate::root) fn submit_public_shield_from_form(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        if self.public_form.shielding {
            return;
        }
        self.clear_public_action_progress_state();
        let Some(draft) = self.public_shield_draft(cx) else {
            return;
        };
        self.request_spend_authorization(
            SpendAuthorizationIntent::PublicShield,
            public_shield_authorization_summary(&draft),
            window,
            cx,
        );
    }

    pub(in crate::root) fn public_shield_draft(
        &mut self,
        cx: &mut Context<'_, Self>,
    ) -> Option<PublicShieldDraft> {
        let Some(asset) = self.public_form.selected_asset else {
            self.public_form.shield_error = Some(Arc::from("Select an asset to shield"));
            cx.notify();
            return None;
        };
        let Some(public_account_uuid) = self.public_form.selected_account_uuid.clone() else {
            self.public_form.shield_error = Some(Arc::from("Select a public account first"));
            cx.notify();
            return None;
        };
        let Some(view_session) = self.view_session.clone() else {
            self.public_form.shield_error = Some(Arc::from("Wallet vault is locked"));
            cx.notify();
            return None;
        };
        let Some(vault_store) = self.vault_store.clone() else {
            self.public_form.shield_error = Some(Arc::from("Wallet vault storage is unavailable"));
            cx.notify();
            return None;
        };
        let chain_id = self.selected_chain;
        let asset_decimals =
            public_asset_decimals(chain_id, asset, Some(&self.effective_token_registry));
        let asset_label =
            public_action_asset_label(chain_id, asset, Some(&self.effective_token_registry));
        let asset_icon_path =
            public_asset_icon_path(chain_id, asset, Some(&self.effective_token_registry));
        let public_account_label = self
            .public_account_for_uuid(Some(public_account_uuid.as_ref()))
            .map_or_else(
                || public_account_uuid.to_string(),
                |account| {
                    public_account_display_label(account)
                        .unwrap_or_else(|| short_address(&account.address))
                },
            );
        let amount_input = self
            .public_form
            .shield_amount_input
            .read(cx)
            .value()
            .to_string();
        let amount = match parse_send_amount(&amount_input, asset_decimals) {
            Ok(amount) if !amount.is_zero() => amount,
            Ok(_) => {
                self.public_form.shield_error = Some(Arc::from("Amount must be greater than zero"));
                cx.notify();
                return None;
            }
            Err(error) => {
                self.public_form.shield_error = Some(Arc::from(error.to_string()));
                cx.notify();
                return None;
            }
        };
        let gas_fee = match self.public_action_gas_fee_selection(PublicActionMode::Shield, cx) {
            Ok(selection) => selection,
            Err(error) => {
                self.public_form.shield_error = Some(Arc::from(error));
                cx.notify();
                return None;
            }
        };
        Some(PublicShieldDraft {
            chain_id,
            asset,
            asset_label,
            asset_icon_path,
            asset_decimals,
            public_account_uuid,
            public_account_label,
            view_session,
            vault_store,
            amount,
            gas_fee,
        })
    }

    pub(in crate::root) fn submit_public_shield_authorized(
        &mut self,
        vault_password: Zeroizing<String>,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        if self.public_form.shielding {
            return;
        }
        let Some(draft) = self.public_shield_draft(cx) else {
            return;
        };
        let PublicShieldDraft {
            chain_id,
            asset,
            asset_label,
            public_account_uuid,
            view_session,
            vault_store,
            amount,
            gas_fee,
            ..
        } = draft;
        self.public_form.shielding = true;
        self.public_form.shield_error = None;
        let http = self.http.clone();
        let active_wallet_id = self.selected_wallet_id.clone();
        let icon_path =
            public_asset_icon_path(chain_id, asset, Some(&self.effective_token_registry));
        let initial_gas_fee =
            self.public_action_initial_gas_values(PublicActionMode::Shield, &gas_fee);
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let generation = self.start_public_action_progress(
            PublicActionMode::Shield,
            asset,
            asset_label,
            icon_path,
            Some(command_tx),
            initial_gas_fee,
        );
        let (progress_tx, progress_rx) = mpsc::unbounded_channel();
        Self::spawn_public_action_progress_listener(
            generation,
            chain_id,
            active_wallet_id.clone(),
            progress_rx,
            cx,
        );
        Self::spawn_public_action_session_event_listener(
            generation,
            chain_id,
            active_wallet_id.clone(),
            event_rx,
            cx,
        );
        self.show_public_action_progress_dialog(window, cx);
        let request = PublicShieldRequest {
            chain_id,
            effective_chain: self.effective_chain_configs.get(&chain_id).cloned(),
            view_session,
            vault_store,
            vault_password,
            public_account_uuid: public_account_uuid.to_string(),
            asset,
            amount,
            gas_fee,
            command_rx: Some(command_rx),
            event_tx: Some(event_tx),
        };
        let submitted_public_account_uuid = Arc::clone(&public_account_uuid);
        let join = self.runtime.spawn(async move {
            submit_public_shield_with_progress(request, &http, move |update| {
                let _ = progress_tx.send(update);
            })
            .await
        });
        self.public_form.action_task_abort_handle = Some(join.abort_handle());
        cx.spawn(async move |this, cx| {
            let result = join.await;
            let _ = this.update(cx, |root, cx| {
                if root.selected_wallet_id != active_wallet_id || root.selected_chain != chain_id {
                    return;
                }
                if !public_action_accepts_update(
                    root.public_form.action_generation,
                    generation,
                    root.public_form.action_stopped,
                ) {
                    return;
                }
                root.public_form.shielding = false;
                root.public_form.action_task_abort_handle = None;
                match result {
                    Ok(Ok(_result)) => {
                        root.public_form.action_command_tx = None;
                        root.public_form.action_action_error = None;
                        match root
                            .public_account_for_uuid(Some(submitted_public_account_uuid.as_ref()))
                            .map(|account| account.status)
                        {
                            Some(PublicAccountStatus::Inactive) => {
                                root.schedule_inactive_public_balance_refresh(cx);
                            }
                            _ => root.schedule_public_balance_refresh(cx),
                        }
                    }
                    Ok(Err(error)) => {
                        let message = error.to_string();
                        if is_spend_authorization_failure_error(&message) {
                            root.clear_spend_authorization(cx);
                        }
                        root.public_form.action_command_tx = None;
                        root.fail_public_action_progress(generation, message.clone(), cx);
                        root.public_form.shield_error = Some(Arc::from(message));
                    }
                    Err(error) => {
                        let message = format!("Public shield task failed: {error}");
                        root.public_form.action_command_tx = None;
                        root.fail_public_action_progress(generation, message.clone(), cx);
                        root.public_form.shield_error = Some(Arc::from(message));
                    }
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }
}
