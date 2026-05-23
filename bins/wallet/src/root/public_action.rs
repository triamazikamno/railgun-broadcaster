use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;

use alloy::primitives::U256;
use gpui::{
    AppContext, Context, Entity, Focusable, InteractiveElement, IntoElement, ParentElement, Pixels,
    SharedString, StatefulInteractiveElement, Styled, Window, div, px, rgb,
};
use gpui_component::{
    Disableable, Icon, IconName, Selectable, Sizable, WindowExt,
    alert::Alert,
    button::{Button, ButtonGroup, ButtonVariants},
    collapsible::Collapsible,
    input::InputState,
    spinner::Spinner,
};
use railgun_ui::short_address;
use tokio::sync::mpsc;
use ui::clipboard::clipboard_with_toast;
use ui::controls::{app_button, app_input, app_muted_text, app_strong_text};
use ui::theme::{self, APP_MONO_FONT_FAMILY, APP_TEXT_SIZE};
use wallet_ops::{
    PublicActionProgressStatus, PublicActionProgressStep, PublicActionProgressUpdate,
    PublicAssetId, PublicBalanceEntry, PublicSendRequest, PublicShieldRequest,
    estimate_public_native_action_gas_reserve, parse_send_amount, submit_public_send_with_progress,
    submit_public_shield_with_progress, vault::PublicAccountStatus,
};

use super::dialogs::PublicActionDialogContent;
use super::public_balances::public_asset_icon_path;
use super::utxo::short_hash;
use super::{
    PUBLIC_ACTION_DIALOG_WIDTH, WalletRoot, format_report_chain, format_send_amount_input,
    native_token_display_label, parse_address, public_asset_decimals, public_asset_label,
    public_balance_amount_label, secondary_dialog_content_width, token_label_row,
};

use crate::assets::RailgunActionIcon;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PublicActionMode {
    Shield,
    Send,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PublicActionStepStatus {
    NotStarted,
    Pending,
    Done,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PublicActionStepState {
    pub(super) step: PublicActionProgressStep,
    pub(super) status: PublicActionStepStatus,
    pub(super) tx_hash: Option<Arc<str>>,
    pub(super) message: Option<Arc<str>>,
}

impl WalletRoot {
    pub(super) fn open_public_action_dialog(
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
        let content_root = root.clone();
        let dialog_width = (window.viewport_size().width * 0.92).min(PUBLIC_ACTION_DIALOG_WIDTH);
        let content_width = secondary_dialog_content_width(dialog_width);
        let content = cx.new(|cx| PublicActionDialogContent::new(content_root, content_width, cx));
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
        window.open_dialog(cx, move |dialog, _window, _cx| {
            let close_root = root.clone();
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
                .child(content.clone())
        });
        cx.defer_in(window, |root, window, cx| {
            root.focus_public_action_dialog_input(window, cx);
        });
    }

    fn focus_public_action_dialog_input(&self, window: &mut Window, cx: &Context<'_, Self>) {
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

    pub(super) fn render_public_action_dialog_content(
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
        let stepper_root = root.clone();
        let max_root = root;
        let show_form_errors = self.public_form.action_progress.is_empty();
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
                    .child(
                        app_input(&self.public_form.shield_password_input)
                            .disabled(disabled || self.public_form.shielding),
                    )
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
                    .child(
                        app_input(&self.public_form.send_password_input)
                            .disabled(disabled || self.public_form.sending),
                    )
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

        if !self.public_form.action_progress.is_empty() {
            let action_asset_label = selected_asset.map_or_else(
                || asset_label.clone(),
                |asset| {
                    public_action_asset_label(
                        self.selected_chain,
                        asset,
                        Some(&self.effective_token_registry),
                    )
                },
            );
            content = content.child(render_public_action_stepper(
                &stepper_root,
                &self.public_form.action_progress,
                &self.public_form.expanded_action_error_steps,
                &action_asset_label,
            ));
        }
        content
    }

    pub(super) fn clear_public_action_dialog_inputs(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        for input in [
            &self.public_form.send_recipient_input,
            &self.public_form.send_amount_input,
            &self.public_form.send_password_input,
            &self.public_form.shield_amount_input,
            &self.public_form.shield_password_input,
        ] {
            input.update(cx, |input, cx| input.set_value("", window, cx));
        }
        self.public_form.send_error = None;
        self.public_form.shield_error = None;
        if !self.public_form.sending && !self.public_form.shielding {
            self.public_form.action_progress.clear();
            self.public_form.expanded_action_error_steps.clear();
        }
    }

    fn set_public_action_mode(
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
        self.public_form.action_progress.clear();
        self.public_form.expanded_action_error_steps.clear();
        cx.defer_in(window, |root, window, cx| {
            root.focus_public_action_dialog_input(window, cx);
        });
        cx.notify();
    }

    fn start_public_action_progress(
        &mut self,
        mode: PublicActionMode,
        asset: PublicAssetId,
    ) -> u64 {
        self.public_form.action_generation = self.public_form.action_generation.wrapping_add(1);
        let generation = self.public_form.action_generation;
        self.public_form.expanded_action_error_steps.clear();
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

    fn apply_public_action_progress_update(
        &mut self,
        generation: u64,
        update: PublicActionProgressUpdate,
        cx: &mut Context<'_, Self>,
    ) {
        if self.public_form.action_generation != generation {
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

    fn fail_public_action_progress(
        &mut self,
        generation: u64,
        message: String,
        cx: &mut Context<'_, Self>,
    ) {
        if self.public_form.action_generation != generation {
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
            cx.notify();
        }
    }

    fn spawn_public_action_progress_listener(
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

    fn set_public_action_error_details_open(
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

    fn set_public_action_amount_to_max(
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
        let join = self.runtime.spawn(async move {
            estimate_public_native_action_gas_reserve(
                chain_id,
                &steps,
                effective_chain.as_ref(),
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

    fn set_public_action_amount_input(
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

    fn set_public_action_error(&mut self, mode: PublicActionMode, message: Option<Arc<str>>) {
        match mode {
            PublicActionMode::Shield => self.public_form.shield_error = message,
            PublicActionMode::Send => self.public_form.send_error = message,
        }
    }

    pub(super) fn submit_public_send_from_form(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        if self.public_form.sending {
            return;
        }
        self.public_form.action_progress.clear();
        self.public_form.expanded_action_error_steps.clear();
        let Some(asset) = self.public_form.selected_asset else {
            self.public_form.send_error = Some(Arc::from("Select an asset to send"));
            cx.notify();
            return;
        };
        let Some(public_account_uuid) = self.public_form.selected_account_uuid.clone() else {
            self.public_form.send_error = Some(Arc::from("Select a public account first"));
            cx.notify();
            return;
        };
        let Some(view_session) = self.view_session.clone() else {
            self.public_form.send_error = Some(Arc::from("Wallet vault is locked"));
            cx.notify();
            return;
        };
        let Some(vault_store) = self.vault_store.clone() else {
            self.public_form.send_error = Some(Arc::from("Wallet vault storage is unavailable"));
            cx.notify();
            return;
        };
        let amount_input = self
            .public_form
            .send_amount_input
            .read(cx)
            .value()
            .to_string();
        let amount = match parse_send_amount(
            &amount_input,
            public_asset_decimals(
                self.selected_chain,
                asset,
                Some(&self.effective_token_registry),
            ),
        ) {
            Ok(amount) if !amount.is_zero() => amount,
            Ok(_) => {
                self.public_form.send_error = Some(Arc::from("Amount must be greater than zero"));
                cx.notify();
                return;
            }
            Err(error) => {
                self.public_form.send_error = Some(Arc::from(error.to_string()));
                cx.notify();
                return;
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
            return;
        };
        let vault_password =
            Self::read_and_clear_input(&self.public_form.send_password_input, window, cx);
        if vault_password.trim().is_empty() {
            self.public_form.send_error = Some(Arc::from("Enter the vault password to send"));
            cx.notify();
            return;
        }
        self.public_form.sending = true;
        self.public_form.send_error = None;
        let chain_id = self.selected_chain;
        let http = self.http.clone();
        let active_wallet_id = self.selected_wallet_id.clone();
        let generation = self.start_public_action_progress(PublicActionMode::Send, asset);
        let (progress_tx, progress_rx) = mpsc::unbounded_channel();
        Self::spawn_public_action_progress_listener(
            generation,
            chain_id,
            active_wallet_id.clone(),
            progress_rx,
            cx,
        );
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
        };
        let submitted_public_account_uuid = Arc::clone(&public_account_uuid);
        let join = self.runtime.spawn(async move {
            submit_public_send_with_progress(request, &http, move |update| {
                let _ = progress_tx.send(update);
            })
            .await
        });
        cx.spawn(async move |this, cx| {
            let result = join.await;
            let _ = this.update(cx, |root, cx| {
                if root.selected_wallet_id != active_wallet_id || root.selected_chain != chain_id {
                    return;
                }
                if root.public_form.action_generation != generation {
                    return;
                }
                root.public_form.sending = false;
                match result {
                    Ok(Ok(_result)) => {
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
                        root.fail_public_action_progress(generation, message.clone(), cx);
                        root.public_form.send_error = Some(Arc::from(message));
                    }
                    Err(error) => {
                        let message = format!("Public send task failed: {error}");
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

    pub(super) fn submit_public_shield_from_form(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        if self.public_form.shielding {
            return;
        }
        self.public_form.action_progress.clear();
        self.public_form.expanded_action_error_steps.clear();
        let Some(asset) = self.public_form.selected_asset else {
            self.public_form.shield_error = Some(Arc::from("Select an asset to shield"));
            cx.notify();
            return;
        };
        let Some(public_account_uuid) = self.public_form.selected_account_uuid.clone() else {
            self.public_form.shield_error = Some(Arc::from("Select a public account first"));
            cx.notify();
            return;
        };
        let Some(view_session) = self.view_session.clone() else {
            self.public_form.shield_error = Some(Arc::from("Wallet vault is locked"));
            cx.notify();
            return;
        };
        let Some(vault_store) = self.vault_store.clone() else {
            self.public_form.shield_error = Some(Arc::from("Wallet vault storage is unavailable"));
            cx.notify();
            return;
        };
        let amount_input = self
            .public_form
            .shield_amount_input
            .read(cx)
            .value()
            .to_string();
        let amount = match parse_send_amount(
            &amount_input,
            public_asset_decimals(
                self.selected_chain,
                asset,
                Some(&self.effective_token_registry),
            ),
        ) {
            Ok(amount) if !amount.is_zero() => amount,
            Ok(_) => {
                self.public_form.shield_error = Some(Arc::from("Amount must be greater than zero"));
                cx.notify();
                return;
            }
            Err(error) => {
                self.public_form.shield_error = Some(Arc::from(error.to_string()));
                cx.notify();
                return;
            }
        };
        let vault_password =
            Self::read_and_clear_input(&self.public_form.shield_password_input, window, cx);
        if vault_password.trim().is_empty() {
            self.public_form.shield_error = Some(Arc::from("Enter the vault password to shield"));
            cx.notify();
            return;
        }
        self.public_form.shielding = true;
        self.public_form.shield_error = None;
        let chain_id = self.selected_chain;
        let http = self.http.clone();
        let active_wallet_id = self.selected_wallet_id.clone();
        let generation = self.start_public_action_progress(PublicActionMode::Shield, asset);
        let (progress_tx, progress_rx) = mpsc::unbounded_channel();
        Self::spawn_public_action_progress_listener(
            generation,
            chain_id,
            active_wallet_id.clone(),
            progress_rx,
            cx,
        );
        let request = PublicShieldRequest {
            chain_id,
            effective_chain: self.effective_chain_configs.get(&chain_id).cloned(),
            view_session,
            vault_store,
            vault_password,
            public_account_uuid: public_account_uuid.to_string(),
            asset,
            amount,
        };
        let submitted_public_account_uuid = Arc::clone(&public_account_uuid);
        let join = self.runtime.spawn(async move {
            submit_public_shield_with_progress(request, &http, move |update| {
                let _ = progress_tx.send(update);
            })
            .await
        });
        cx.spawn(async move |this, cx| {
            let result = join.await;
            let _ = this.update(cx, |root, cx| {
                if root.selected_wallet_id != active_wallet_id || root.selected_chain != chain_id {
                    return;
                }
                if root.public_form.action_generation != generation {
                    return;
                }
                root.public_form.shielding = false;
                match result {
                    Ok(Ok(_result)) => {
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
                        root.fail_public_action_progress(generation, message.clone(), cx);
                        root.public_form.shield_error = Some(Arc::from(message));
                    }
                    Err(error) => {
                        let message = format!("Public shield task failed: {error}");
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

pub(super) fn render_public_action_amount_input(
    root: Entity<WalletRoot>,
    mode: PublicActionMode,
    input: &Entity<InputState>,
    label: String,
    max_label: Option<String>,
    disabled: bool,
) -> gpui::Div {
    let max_root = root;
    let max_id = match mode {
        PublicActionMode::Shield => "wallet-public-shield-max",
        PublicActionMode::Send => "wallet-public-send-max",
    };
    div()
        .flex()
        .flex_col()
        .gap_1()
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .gap_2()
                .child(app_muted_text(label))
                .children(max_label.map(|label| {
                    app_button(max_id, format!("Max: {label}"))
                        .link()
                        .xsmall()
                        .compact()
                        .disabled(disabled)
                        .on_click(move |_event, window, cx| {
                            max_root.update(cx, |root, cx| {
                                root.set_public_action_amount_to_max(mode, window, cx);
                            });
                        })
                })),
        )
        .child(app_input(input).disabled(disabled))
}

pub(super) fn public_action_segment_button(
    id: SharedString,
    label: &'static str,
    icon: impl Into<Icon>,
    selected: bool,
) -> Button {
    let button = Button::new(id)
        .flex_1()
        .min_w(px(0.0))
        .selected(selected)
        .child(
            div()
                .flex()
                .items_center()
                .justify_center()
                .gap_1()
                .text_size(APP_TEXT_SIZE)
                .child(icon.into().small())
                .child(label),
        );
    if selected { button.primary() } else { button }
}

pub(super) fn public_action_title_row(label: String, icon_path: Option<PathBuf>) -> gpui::Div {
    div().flex().items_center().gap_1().child(token_label_row(
        SharedString::from(label),
        icon_path,
        px(20.0),
    ))
}

pub(super) fn public_action_max_label(entry: &PublicBalanceEntry) -> Option<String> {
    if entry.asset.id == PublicAssetId::Native {
        return entry
            .amount
            .amount()
            .map(|_| format!("{} after est. gas", entry.asset.symbol));
    }
    entry.amount.amount().map(|_| {
        format!(
            "{} {}",
            public_balance_amount_label(&entry.amount, entry.asset.decimals),
            entry.asset.symbol,
        )
    })
}

pub(super) fn public_action_max_amount_after_reserve(amount: U256, reserve: U256) -> Option<U256> {
    (amount > reserve).then_some(amount - reserve)
}

pub(super) fn public_action_asset_label(
    chain_id: u64,
    asset: PublicAssetId,
    registry: Option<&wallet_ops::settings::EffectiveTokenRegistry>,
) -> String {
    match asset {
        PublicAssetId::Native => native_token_display_label(chain_id).to_string(),
        PublicAssetId::Erc20(_) => public_asset_label(chain_id, asset, registry),
    }
}

pub(super) fn render_public_action_stepper(
    root: &Entity<WalletRoot>,
    steps: &[PublicActionStepState],
    expanded_error_steps: &BTreeSet<PublicActionProgressStep>,
    asset_label: &str,
) -> gpui::Div {
    let mut stepper = div()
        .flex()
        .flex_col()
        .gap_0()
        .p(px(10.0))
        .rounded_md()
        .bg(rgb(theme::SURFACE_HOVER_SUBTLE))
        .border_1()
        .border_color(rgb(theme::BORDER_SUBTLE));
    let last_index = steps.len().saturating_sub(1);
    for (index, step) in steps.iter().enumerate() {
        stepper = stepper.child(render_public_action_step(
            root,
            step,
            index == last_index,
            expanded_error_steps.contains(&step.step),
            asset_label,
        ));
    }
    stepper
}

fn render_public_action_step(
    root: &Entity<WalletRoot>,
    step: &PublicActionStepState,
    is_last: bool,
    error_details_open: bool,
    asset_label: &str,
) -> gpui::Div {
    let color = public_action_step_color(step.status);
    let title = public_action_step_label(step.step);
    let detail = public_action_step_detail(step.step, step.status);
    let mut body = div()
        .flex_1()
        .min_w(px(0.0))
        .flex()
        .flex_col()
        .gap_1()
        .pb(if is_last { px(0.0) } else { px(12.0) })
        .child(
            app_strong_text(title)
                .text_color(rgb(color))
                .line_height(gpui::relative(1.0)),
        );
    if step.status == PublicActionStepStatus::Error {
        body = body.child(render_public_action_step_error(
            root.clone(),
            step,
            asset_label,
            error_details_open,
        ));
    } else {
        body = body.child(
            app_muted_text(detail)
                .text_color(rgb(color))
                .line_height(gpui::relative(1.0)),
        );
    }
    body = body.children(
        step.tx_hash
            .as_ref()
            .map(|tx_hash| render_public_action_step_hash(step.step, tx_hash.as_ref())),
    );

    div()
        .flex()
        .items_start()
        .gap_3()
        .child(
            div()
                .flex()
                .flex_col()
                .items_center()
                .child(render_public_action_step_marker(step.status, color))
                .children((!is_last).then(|| {
                    div()
                        .w(px(2.0))
                        .flex_1()
                        .min_h(px(32.0))
                        .my(px(3.0))
                        .rounded_full()
                        .bg(rgb(color))
                })),
        )
        .child(body)
}

fn render_public_action_step_error(
    root: Entity<WalletRoot>,
    step: &PublicActionStepState,
    asset_label: &str,
    details_open: bool,
) -> gpui::Div {
    let summary = public_action_error_summary(step.step, step.message.as_deref(), asset_label);
    let details = public_action_error_details(&summary, step.message.as_deref());
    let copy_value =
        public_action_error_copy_value(step.step, asset_label, &summary, details.as_deref());
    let copy_id = SharedString::from(format!(
        "wallet-public-action-{}-error-copy",
        public_action_step_id(step.step),
    ));
    let mut error = div().flex().flex_col().gap_1().child(
        div()
            .flex()
            .items_start()
            .gap_1()
            .min_w(px(0.0))
            .child(
                app_muted_text(summary)
                    .flex_1()
                    .min_w(px(0.0))
                    .whitespace_normal()
                    .text_color(rgb(theme::DANGER))
                    .line_height(gpui::relative(1.0)),
            )
            .child(clipboard_with_toast(copy_id, copy_value)),
    );

    if let Some(details) = details {
        let step_kind = step.step;
        let toggle_root = root;
        let toggle_id = SharedString::from(format!(
            "wallet-public-action-{}-error-details-toggle",
            public_action_step_id(step_kind),
        ));
        error = error.child(
            Collapsible::new()
                .open(details_open)
                .child(
                    div()
                        .id(toggle_id)
                        .flex()
                        .items_center()
                        .gap_1()
                        .cursor_pointer()
                        .text_color(rgb(theme::TEXT_MUTED))
                        .on_click(move |_event, _window, cx| {
                            toggle_root.update(cx, |root, cx| {
                                root.set_public_action_error_details_open(
                                    step_kind,
                                    !details_open,
                                    cx,
                                );
                            });
                        })
                        .child(app_muted_text(if details_open {
                            "Hide details"
                        } else {
                            "Details"
                        }))
                        .child(
                            Icon::new(if details_open {
                                IconName::ChevronUp
                            } else {
                                IconName::ChevronDown
                            })
                            .xsmall()
                            .text_color(rgb(theme::TEXT_MUTED)),
                        ),
                )
                .content(
                    div().pt(px(2.0)).min_w(px(0.0)).child(
                        app_muted_text(details)
                            .font_family(APP_MONO_FONT_FAMILY)
                            .text_size(px(12.0))
                            .text_color(rgb(theme::TEXT_MUTED))
                            .whitespace_normal(),
                    ),
                ),
        );
    }
    error
}

pub(super) fn render_public_action_step_marker(
    status: PublicActionStepStatus,
    color: u32,
) -> gpui::Div {
    div()
        .size(px(26.0))
        .flex()
        .items_center()
        .justify_center()
        .rounded_full()
        .border_1()
        .border_color(rgb(color))
        .bg(rgb(theme::SURFACE))
        .text_color(rgb(color))
        .child(match status {
            PublicActionStepStatus::NotStarted => div()
                .size(px(7.0))
                .rounded_full()
                .bg(rgb(color))
                .into_any_element(),
            PublicActionStepStatus::Pending => Spinner::new()
                .icon(IconName::LoaderCircle)
                .color(rgb(color).into())
                .with_size(px(14.0))
                .into_any_element(),
            PublicActionStepStatus::Done => {
                Icon::new(IconName::CircleCheck).small().into_any_element()
            }
            PublicActionStepStatus::Error => Icon::new(IconName::TriangleAlert)
                .small()
                .into_any_element(),
        })
}

fn render_public_action_step_hash(step: PublicActionProgressStep, tx_hash: &str) -> gpui::Div {
    let button_id = SharedString::from(format!(
        "wallet-public-action-{}-tx-copy",
        public_action_step_id(step)
    ));
    div()
        .flex()
        .items_center()
        .gap_1()
        .child(
            app_muted_text(short_hash(tx_hash))
                .font_family(APP_MONO_FONT_FAMILY)
                .line_height(gpui::relative(1.0)),
        )
        .child(clipboard_with_toast(button_id, tx_hash.to_string()))
}

pub(super) const fn public_action_step_color(status: PublicActionStepStatus) -> u32 {
    match status {
        PublicActionStepStatus::NotStarted => theme::TEXT,
        PublicActionStepStatus::Pending => theme::WARNING,
        PublicActionStepStatus::Done => theme::SUCCESS,
        PublicActionStepStatus::Error => theme::DANGER,
    }
}

const fn public_action_step_label(step: PublicActionProgressStep) -> &'static str {
    match step {
        PublicActionProgressStep::Send => "Send",
        PublicActionProgressStep::Wrap => "Wrap",
        PublicActionProgressStep::Approve => "Approve",
        PublicActionProgressStep::Shield => "Shield",
    }
}

const fn public_action_step_detail(
    step: PublicActionProgressStep,
    status: PublicActionStepStatus,
) -> &'static str {
    match status {
        PublicActionStepStatus::NotStarted => match step {
            PublicActionProgressStep::Send => "Waiting to broadcast the transfer.",
            PublicActionProgressStep::Wrap => "Waiting to wrap the native token.",
            PublicActionProgressStep::Approve => "Waiting to approve the shield contract.",
            PublicActionProgressStep::Shield => "Waiting to shield into the Private wallet.",
        },
        PublicActionStepStatus::Pending => "Broadcasting and waiting for confirmation.",
        PublicActionStepStatus::Done => "Confirmed on-chain.",
        PublicActionStepStatus::Error => "Failed.",
    }
}

pub(super) fn public_action_error_summary(
    step: PublicActionProgressStep,
    details: Option<&str>,
    asset_label: &str,
) -> String {
    let details = details.unwrap_or_default().to_ascii_lowercase();
    if details.contains("estimate gas") {
        return match step {
            PublicActionProgressStep::Send => {
                "Could not estimate gas. Check amount, recipient, and gas balance.".to_string()
            }
            PublicActionProgressStep::Wrap => format!(
                "Could not estimate gas to wrap {asset_label}. Check amount and gas balance."
            ),
            PublicActionProgressStep::Approve => {
                "Could not estimate gas for approval. Check token balance and try again."
                    .to_string()
            }
            PublicActionProgressStep::Shield => {
                "Could not estimate gas for shielding. Try again or check the RPC/network."
                    .to_string()
            }
        };
    }
    if details.contains("revert") {
        return match step {
            PublicActionProgressStep::Send => "Transfer reverted on-chain.".to_string(),
            PublicActionProgressStep::Wrap => format!("Wrapping {asset_label} reverted on-chain."),
            PublicActionProgressStep::Approve => "Approval reverted on-chain.".to_string(),
            PublicActionProgressStep::Shield => "Shielding reverted on-chain.".to_string(),
        };
    }
    match step {
        PublicActionProgressStep::Send => {
            "Could not send publicly. Check amount, recipient, and gas balance.".to_string()
        }
        PublicActionProgressStep::Wrap => {
            format!("Could not wrap {asset_label}. Check amount and gas balance.")
        }
        PublicActionProgressStep::Approve => {
            "Could not approve the shield contract. Check token balance and try again.".to_string()
        }
        PublicActionProgressStep::Shield => {
            "Could not shield into the Private wallet. Try again or check the RPC/network."
                .to_string()
        }
    }
}

pub(super) fn public_action_error_details(summary: &str, details: Option<&str>) -> Option<String> {
    let details = details?.trim();
    if details.is_empty() || details == summary {
        None
    } else {
        Some(details.to_string())
    }
}

pub(super) fn public_action_error_copy_value(
    step: PublicActionProgressStep,
    asset_label: &str,
    summary: &str,
    details: Option<&str>,
) -> String {
    let mut value = format!(
        "Step: {}\nAsset: {asset_label}\nSummary: {summary}",
        public_action_step_label(step),
    );
    if let Some(details) = details {
        value.push_str("\nDetails: ");
        value.push_str(details);
    }
    value
}

const fn public_action_step_id(step: PublicActionProgressStep) -> &'static str {
    match step {
        PublicActionProgressStep::Send => "send",
        PublicActionProgressStep::Wrap => "wrap",
        PublicActionProgressStep::Approve => "approve",
        PublicActionProgressStep::Shield => "shield",
    }
}

pub(super) fn public_action_progress_steps(
    mode: PublicActionMode,
    asset: PublicAssetId,
) -> Vec<PublicActionProgressStep> {
    match mode {
        PublicActionMode::Send => vec![PublicActionProgressStep::Send],
        PublicActionMode::Shield if asset == PublicAssetId::Native => vec![
            PublicActionProgressStep::Wrap,
            PublicActionProgressStep::Approve,
            PublicActionProgressStep::Shield,
        ],
        PublicActionMode::Shield => vec![
            PublicActionProgressStep::Approve,
            PublicActionProgressStep::Shield,
        ],
    }
}
