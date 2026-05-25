use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;

use alloy::primitives::U256;
use gpui::{
    AppContext, Context, Entity, Focusable, InteractiveElement, IntoElement, ParentElement, Pixels,
    SharedString, StatefulInteractiveElement, Styled, Window, div, prelude::FluentBuilder as _, px,
    rgb,
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
    PublicActionCommand, PublicActionCommandKind, PublicActionCommandSender,
    PublicActionGasFeeSelection, PublicActionProgressStatus, PublicActionProgressStep,
    PublicActionProgressUpdate, PublicActionSessionEvent, PublicAssetId, PublicBalanceEntry,
    PublicSendRequest, PublicShieldRequest, estimate_public_native_action_gas_reserve,
    parse_send_amount, public_action_replacement_bumped_fee, quote_public_action_gas_fee,
    submit_public_send_with_progress, submit_public_shield_with_progress,
    vault::PublicAccountStatus,
};

use super::gas_fee::{
    Eip1559GasFeeEditTarget, Eip1559GasFeeMode, Eip1559GasFeeTarget, GasRetryInputs, format_gwei,
    render_eip1559_gas_fee_editor,
};
use super::public_balances::public_asset_icon_path;
use super::utxo::short_hash;
use super::{
    PUBLIC_ACTION_DIALOG_WIDTH, WalletRoot, format_report_chain, format_send_amount_input,
    native_token_display_label, parse_address, public_asset_decimals, public_asset_label,
    public_balance_amount_label, secondary_dialog_content_width, token_label_row,
};

use crate::assets::RailgunActionIcon;

const PUBLIC_ACTION_RETRY_DEFAULT_FEE_WEI: u128 = 1_000_000_000;

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
    Stopped,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PublicActionStepState {
    pub(super) step: PublicActionProgressStep,
    pub(super) status: PublicActionStepStatus,
    pub(super) tx_hash: Option<Arc<str>>,
    pub(super) message: Option<Arc<str>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProgressFooterAction {
    Stop,
    Close,
}

const STOPPED_PROGRESS_MESSAGE: &str =
    "Stopped locally. Already-submitted network work may continue.";

pub(super) const fn progress_footer_action(
    stop_available: bool,
    terminal: bool,
) -> ProgressFooterAction {
    if stop_available && !terminal {
        ProgressFooterAction::Stop
    } else {
        ProgressFooterAction::Close
    }
}

pub(super) const fn public_action_step_is_final_handoff(
    mode: PublicActionMode,
    step: PublicActionProgressStep,
) -> bool {
    match mode {
        PublicActionMode::Shield => matches!(step, PublicActionProgressStep::Shield),
        PublicActionMode::Send => matches!(step, PublicActionProgressStep::Send),
    }
}

pub(super) const fn public_action_accepts_update(
    current_generation: u64,
    update_generation: u64,
    stopped: bool,
) -> bool {
    current_generation == update_generation && !stopped
}

pub(super) fn public_action_progress_footer_action(
    stop_available: bool,
    steps: &[PublicActionStepState],
) -> ProgressFooterAction {
    progress_footer_action(stop_available, public_action_progress_is_terminal(steps))
}

pub(super) fn public_action_progress_is_terminal(steps: &[PublicActionStepState]) -> bool {
    !steps.is_empty()
        && (steps
            .iter()
            .all(|step| step.status == PublicActionStepStatus::Done)
            || steps.iter().any(|step| {
                matches!(
                    step.status,
                    PublicActionStepStatus::Error | PublicActionStepStatus::Stopped
                )
            }))
}

pub(super) fn mark_public_action_active_step_stopped(steps: &mut [PublicActionStepState]) -> bool {
    let step_index = steps
        .iter()
        .position(|step| step.status == PublicActionStepStatus::Pending)
        .or_else(|| {
            steps
                .iter()
                .position(|step| step.status == PublicActionStepStatus::Error)
        })
        .or_else(|| {
            steps
                .iter()
                .rposition(|step| step.status == PublicActionStepStatus::NotStarted)
        });
    let Some(step_index) = step_index else {
        return false;
    };
    let step = &mut steps[step_index];
    step.status = PublicActionStepStatus::Stopped;
    step.message = Some(Arc::from(STOPPED_PROGRESS_MESSAGE));
    true
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublicActionGasRetryKind {
    RetryEstimate,
    SpeedUp,
}

struct PublicActionGasRetryDialogContent {
    root: Entity<WalletRoot>,
    generation: u64,
    retry_kind: PublicActionGasRetryKind,
    gas_inputs: GasRetryInputs,
    error: Option<Arc<str>>,
}

impl PublicActionGasRetryDialogContent {
    fn new(
        root: Entity<WalletRoot>,
        generation: u64,
        retry_kind: PublicActionGasRetryKind,
        initial_max_fee_per_gas: u128,
        initial_max_priority_fee_per_gas: u128,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) -> Self {
        let gas_inputs = GasRetryInputs::new(
            initial_max_fee_per_gas,
            initial_max_priority_fee_per_gas,
            window,
            cx,
        );
        cx.observe(&root, |_this, _root, cx| cx.notify()).detach();
        gas_inputs.subscribe_clear_error(cx, |this, cx| {
            this.error = None;
            cx.notify();
        });
        Self {
            root,
            generation,
            retry_kind,
            gas_inputs,
            error: None,
        }
    }
}

impl gpui::Render for PublicActionGasRetryDialogContent {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<'_, Self>) -> impl IntoElement {
        let title = match self.retry_kind {
            PublicActionGasRetryKind::RetryEstimate => "Retry with custom gas",
            PublicActionGasRetryKind::SpeedUp => "Speed up transaction",
        };
        let detail = match self.retry_kind {
            PublicActionGasRetryKind::RetryEstimate => {
                "Retry this Public action step using these EIP-1559 fee values."
            }
            PublicActionGasRetryKind::SpeedUp => {
                "Uses the same nonce to replace the pending transaction. Values are prefilled +12.5%."
            }
        };
        let submit_root = self.root.clone();
        let gas_inputs = self.gas_inputs.clone();
        let generation = self.generation;
        let retry_kind = self.retry_kind;
        let dialog = cx.entity();
        div()
            .w_full()
            .flex()
            .flex_col()
            .gap_3()
            .child(app_strong_text(title))
            .child(app_muted_text(detail).whitespace_normal())
            .child(self.gas_inputs.render_fields())
            .when_some(self.error.as_ref(), |this, error| {
                this.child(app_muted_text(error.to_string()).text_color(rgb(theme::DANGER)))
            })
            .child(
                div()
                    .w_full()
                    .flex()
                    .flex_wrap()
                    .justify_end()
                    .gap_2()
                    .child(
                        app_button("public-action-gas-retry-cancel", "Cancel")
                            .flex_none()
                            .on_click(move |_event, window, cx| {
                                window.close_dialog(cx);
                            }),
                    )
                    .child(
                        app_button("public-action-gas-retry-confirm", "Submit")
                            .primary()
                            .flex_none()
                            .on_click(move |_event, window, cx| {
                                let (max_fee, max_tip) = match gas_inputs.parse(cx) {
                                    Ok(values) => values,
                                    Err(error) => {
                                        dialog.update(cx, |this, cx| {
                                            this.error = Some(Arc::from(error));
                                            cx.notify();
                                        });
                                        return;
                                    }
                                };
                                submit_root.update(cx, |root, cx| {
                                    root.submit_public_action_gas_retry(
                                        generation, retry_kind, max_fee, max_tip, cx,
                                    );
                                });
                                window.close_dialog(cx);
                            }),
                    ),
            )
    }
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
                    .child(
                        app_input(&self.public_form.shield_password_input)
                            .disabled(disabled || self.public_form.shielding),
                    )
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
                    .child(
                        app_input(&self.public_form.send_password_input)
                            .disabled(disabled || self.public_form.sending),
                    )
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
            self.clear_public_action_progress_state();
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

    pub(super) fn clear_public_action_progress_state(&mut self) {
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

    pub(super) fn set_public_action_gas_fee_mode(
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

    pub(super) fn customize_public_action_gas_fee_from_auto(
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

    pub(super) fn refresh_public_action_gas_fee_quote(
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

    fn start_public_action_progress(
        &mut self,
        mode: PublicActionMode,
        asset: PublicAssetId,
        asset_label: String,
        icon_path: Option<PathBuf>,
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

    fn apply_public_action_progress_update(
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

    fn fail_public_action_progress(
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

    fn spawn_public_action_session_event_listener(
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

    fn apply_public_action_session_event(
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

    fn show_public_action_progress_dialog(
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
        let dialog_width = (window.viewport_size().width * 0.92).min(PUBLIC_ACTION_DIALOG_WIDTH);
        let content_width = secondary_dialog_content_width(dialog_width);
        window.open_dialog(cx, move |dialog, _window, cx| {
            let close_root = root.clone();
            let content_root = root.clone();
            dialog
                .w(dialog_width)
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

    fn stop_public_action_progress(&mut self, cx: &mut Context<'_, Self>) {
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

    fn close_public_action_progress_dialog(
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

    pub(super) fn render_public_action_progress_dialog_content(
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

    fn open_public_action_gas_retry_dialog(
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

    fn submit_public_action_gas_retry(
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

    fn public_action_gas_fee_selection(
        &self,
        mode: PublicActionMode,
        cx: &Context<'_, Self>,
    ) -> Result<PublicActionGasFeeSelection, String> {
        match mode {
            PublicActionMode::Shield => self.public_form.shield_gas_fee.selection(cx),
            PublicActionMode::Send => self.public_form.send_gas_fee.selection(cx),
        }
    }

    fn public_action_initial_gas_values(
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

    pub(super) fn submit_public_send_from_form(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        if self.public_form.sending {
            return;
        }
        self.clear_public_action_progress_state();
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
        let gas_fee = match self.public_action_gas_fee_selection(PublicActionMode::Send, cx) {
            Ok(selection) => selection,
            Err(error) => {
                self.public_form.send_error = Some(Arc::from(error));
                cx.notify();
                return;
            }
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
        let asset_label =
            public_action_asset_label(chain_id, asset, Some(&self.effective_token_registry));
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

    pub(super) fn submit_public_shield_from_form(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        if self.public_form.shielding {
            return;
        }
        self.clear_public_action_progress_state();
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
        let gas_fee = match self.public_action_gas_fee_selection(PublicActionMode::Shield, cx) {
            Ok(selection) => selection,
            Err(error) => {
                self.public_form.shield_error = Some(Arc::from(error));
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
        let asset_label =
            public_action_asset_label(chain_id, asset, Some(&self.effective_token_registry));
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

fn public_action_context_row(label: &'static str, value: String) -> gpui::Div {
    div()
        .flex()
        .items_center()
        .justify_between()
        .gap_3()
        .child(app_muted_text(label))
        .child(
            app_strong_text(value)
                .text_size(px(13.0))
                .font_family(APP_MONO_FONT_FAMILY),
        )
}

fn render_public_action_active_status_notice(
    root: Entity<WalletRoot>,
    mode: PublicActionMode,
    step: &PublicActionStepState,
) -> gpui::Div {
    let step_kind = step.step;
    let title = match (mode, step.status) {
        (PublicActionMode::Shield, PublicActionStepStatus::Error) => {
            "Public shield needs attention"
        }
        (PublicActionMode::Send, PublicActionStepStatus::Error) => "Public send needs attention",
        (PublicActionMode::Shield, _) => "Public shield in progress",
        (PublicActionMode::Send, _) => "Public send in progress",
    };
    let detail = format!(
        "{}: {}",
        public_action_step_label(step.step),
        public_action_step_detail(step.step, step.status)
    );
    div()
        .flex()
        .items_center()
        .justify_between()
        .gap_3()
        .p(px(10.0))
        .rounded_md()
        .bg(rgb(theme::SURFACE_ELEVATED))
        .border_1()
        .border_color(rgb(theme::INFO))
        .child(
            div()
                .flex_1()
                .min_w(px(0.0))
                .flex()
                .flex_col()
                .gap_1()
                .child(app_strong_text(title))
                .child(app_muted_text(detail).whitespace_normal()),
        )
        .child(
            app_button(
                SharedString::from(format!(
                    "wallet-public-action-{}-view-progress",
                    public_action_step_id(step_kind)
                )),
                "View status",
            )
            .outline()
            .small()
            .on_click(move |_event, window, cx| {
                root.update(cx, |root, cx| {
                    root.show_public_action_progress_dialog(window, cx);
                });
            }),
        )
}

fn render_public_action_progress_footer(
    root: Entity<WalletRoot>,
    action: ProgressFooterAction,
) -> gpui::Div {
    let button_root = root;
    let (id, label) = match action {
        ProgressFooterAction::Stop => ("wallet-public-action-stop", "Stop"),
        ProgressFooterAction::Close => ("wallet-public-action-close", "Close"),
    };
    let button = app_button(id, label).small().flex_none();
    let button = match action {
        ProgressFooterAction::Stop => button.danger().icon(Icon::new(RailgunActionIcon::Square)),
        ProgressFooterAction::Close => button.outline(),
    };
    div()
        .w_full()
        .flex()
        .justify_end()
        .pt(px(2.0))
        .child(button.on_click(move |_event, window, cx| {
            button_root.update(cx, |root, cx| match action {
                ProgressFooterAction::Stop => root.stop_public_action_progress(cx),
                ProgressFooterAction::Close => root.close_public_action_progress_dialog(window, cx),
            });
        }))
}

pub(super) fn public_action_closed_active_step(
    steps: &[PublicActionStepState],
) -> Option<&PublicActionStepState> {
    steps
        .iter()
        .find(|step| step.status == PublicActionStepStatus::Pending)
        .or_else(|| {
            steps
                .iter()
                .find(|step| step.status == PublicActionStepStatus::Error)
        })
}

const fn public_action_mode_verb(mode: PublicActionMode) -> &'static str {
    match mode {
        PublicActionMode::Shield => "Shield",
        PublicActionMode::Send => "Send",
    }
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
    command_available: bool,
    current_gas_fee: Option<(u128, u128)>,
    action_error: Option<&str>,
    generation: u64,
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
            command_available,
            current_gas_fee,
            action_error,
            generation,
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
    command_available: bool,
    current_gas_fee: Option<(u128, u128)>,
    action_error: Option<&str>,
    generation: u64,
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
    if let Some(action) = render_public_action_step_action(
        root.clone(),
        step,
        command_available,
        current_gas_fee,
        action_error,
        generation,
    ) {
        body = body.child(action);
    }

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

fn render_public_action_step_action(
    root: Entity<WalletRoot>,
    step: &PublicActionStepState,
    command_available: bool,
    current_gas_fee: Option<(u128, u128)>,
    action_error: Option<&str>,
    generation: u64,
) -> Option<gpui::AnyElement> {
    if !command_available {
        return None;
    }
    let retry_kind = match step.status {
        PublicActionStepStatus::Error => PublicActionGasRetryKind::RetryEstimate,
        PublicActionStepStatus::Pending if step.tx_hash.is_some() && current_gas_fee.is_some() => {
            PublicActionGasRetryKind::SpeedUp
        }
        _ => return None,
    };
    let label = match retry_kind {
        PublicActionGasRetryKind::RetryEstimate => "Retry with custom gas",
        PublicActionGasRetryKind::SpeedUp => "Speed up transaction",
    };
    let mut action = div()
        .pt(px(4.0))
        .flex()
        .flex_col()
        .items_start()
        .gap_1()
        .child(
            app_button(public_action_retry_button_id(step.step, retry_kind), label)
                .small()
                .outline()
                .on_click(move |_event, window, cx| {
                    root.update(cx, |root, cx| {
                        root.open_public_action_gas_retry_dialog(
                            generation, retry_kind, window, cx,
                        );
                    });
                }),
        );
    if let Some(error) = action_error {
        action = action.child(
            app_muted_text(format!("Last retry failed: {error}"))
                .text_color(rgb(theme::DANGER))
                .whitespace_normal(),
        );
    }
    Some(action.into_any_element())
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
            PublicActionStepStatus::Stopped => Icon::new(RailgunActionIcon::Square)
                .small()
                .into_any_element(),
        })
}

#[cfg(test)]
pub(super) const fn public_action_step_uses_stop_marker(status: PublicActionStepStatus) -> bool {
    matches!(status, PublicActionStepStatus::Stopped)
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
        PublicActionStepStatus::Error | PublicActionStepStatus::Stopped => theme::DANGER,
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

pub(super) const fn public_action_step_detail(
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
        PublicActionStepStatus::Stopped => STOPPED_PROGRESS_MESSAGE,
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

fn public_action_retry_button_id(
    step: PublicActionProgressStep,
    retry_kind: PublicActionGasRetryKind,
) -> SharedString {
    let action = match retry_kind {
        PublicActionGasRetryKind::RetryEstimate => "retry-gas",
        PublicActionGasRetryKind::SpeedUp => "speed-up",
    };
    SharedString::from(format!(
        "wallet-public-action-{}-{action}",
        public_action_step_id(step)
    ))
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
