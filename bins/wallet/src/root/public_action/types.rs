use super::*;

pub(in crate::root) const PUBLIC_ACTION_RETRY_DEFAULT_FEE_WEI: u128 = 1_000_000_000;

pub(in crate::root) struct PublicSendDraft {
    pub(in crate::root) chain_id: u64,
    pub(in crate::root) asset: PublicAssetId,
    pub(in crate::root) asset_label: String,
    pub(in crate::root) asset_icon_path: Option<WalletIconSource>,
    pub(in crate::root) asset_decimals: Option<u8>,
    pub(in crate::root) public_account_uuid: Arc<str>,
    pub(in crate::root) public_account_label: String,
    pub(in crate::root) view_session: Arc<DesktopViewSession>,
    pub(in crate::root) vault_store: Arc<DesktopVaultStore>,
    pub(in crate::root) amount: U256,
    pub(in crate::root) recipient: Address,
    pub(in crate::root) gas_fee: PublicActionGasFeeSelection,
}

pub(in crate::root) struct PublicShieldDraft {
    pub(in crate::root) chain_id: u64,
    pub(in crate::root) asset: PublicAssetId,
    pub(in crate::root) asset_label: String,
    pub(in crate::root) asset_icon_path: Option<WalletIconSource>,
    pub(in crate::root) asset_decimals: Option<u8>,
    pub(in crate::root) public_account_uuid: Arc<str>,
    pub(in crate::root) public_account_label: String,
    pub(in crate::root) view_session: Arc<DesktopViewSession>,
    pub(in crate::root) vault_store: Arc<DesktopVaultStore>,
    pub(in crate::root) amount: U256,
    pub(in crate::root) gas_fee: PublicActionGasFeeSelection,
}

pub(in crate::root) fn public_send_authorization_summary(
    draft: &PublicSendDraft,
) -> SpendAuthorizationSummary {
    SpendAuthorizationSummary::new(
        "Public send",
        "Enter your vault password to authorize this public send.",
        vec![
            SpendAuthorizationSummaryRow::new("Amount", public_action_amount_label(draft))
                .with_icon(draft.asset_icon_path.clone()),
            SpendAuthorizationSummaryRow::new("From", draft.public_account_label.clone()),
            SpendAuthorizationSummaryRow::new("Recipient", draft.recipient.to_checksum(None)),
        ],
    )
}

pub(in crate::root) fn public_shield_authorization_summary(
    draft: &PublicShieldDraft,
) -> SpendAuthorizationSummary {
    SpendAuthorizationSummary::new(
        "Public shield",
        "Enter your vault password to authorize this public shield.",
        vec![
            SpendAuthorizationSummaryRow::new("Amount", public_shield_amount_label(draft))
                .with_icon(draft.asset_icon_path.clone()),
            SpendAuthorizationSummaryRow::new("From", draft.public_account_label.clone()),
            SpendAuthorizationSummaryRow::new("Recipient", "Selected private wallet"),
        ],
    )
}

pub(in crate::root) fn public_action_amount_label(draft: &PublicSendDraft) -> String {
    format!(
        "{} {}",
        format_send_amount_input(draft.amount, draft.asset_decimals),
        draft.asset_label
    )
}

pub(in crate::root) fn public_shield_amount_label(draft: &PublicShieldDraft) -> String {
    format!(
        "{} {}",
        format_send_amount_input(draft.amount, draft.asset_decimals),
        draft.asset_label
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::root) enum PublicActionMode {
    Shield,
    Send,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::root) enum PublicActionStepStatus {
    NotStarted,
    Pending,
    Done,
    Error,
    Stopped,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::root) struct PublicActionStepState {
    pub(in crate::root) step: PublicActionProgressStep,
    pub(in crate::root) status: PublicActionStepStatus,
    pub(in crate::root) tx_hash: Option<Arc<str>>,
    pub(in crate::root) message: Option<Arc<str>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::root) enum ProgressFooterAction {
    Stop,
    Close,
}

pub(in crate::root) const STOPPED_PROGRESS_MESSAGE: &str =
    "Stopped locally. Already-submitted network work may continue.";

pub(in crate::root) const fn progress_footer_action(
    stop_available: bool,
    terminal: bool,
) -> ProgressFooterAction {
    if stop_available && !terminal {
        ProgressFooterAction::Stop
    } else {
        ProgressFooterAction::Close
    }
}

pub(in crate::root) const fn public_action_step_is_final_handoff(
    mode: PublicActionMode,
    step: PublicActionProgressStep,
) -> bool {
    match mode {
        PublicActionMode::Shield => matches!(step, PublicActionProgressStep::Shield),
        PublicActionMode::Send => matches!(step, PublicActionProgressStep::Send),
    }
}

pub(in crate::root) const fn public_action_accepts_update(
    current_generation: u64,
    update_generation: u64,
    stopped: bool,
) -> bool {
    current_generation == update_generation && !stopped
}

pub(in crate::root) fn public_action_progress_footer_action(
    stop_available: bool,
    steps: &[PublicActionStepState],
) -> ProgressFooterAction {
    progress_footer_action(stop_available, public_action_progress_is_terminal(steps))
}

pub(in crate::root) fn public_action_progress_is_terminal(steps: &[PublicActionStepState]) -> bool {
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

pub(in crate::root) fn mark_public_action_active_step_stopped(
    steps: &mut [PublicActionStepState],
) -> bool {
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
pub(in crate::root) enum PublicActionGasRetryKind {
    RetryEstimate,
    SpeedUp,
}

pub(in crate::root) struct PublicActionGasRetryDialogContent {
    pub(in crate::root) root: Entity<WalletRoot>,
    pub(in crate::root) generation: u64,
    pub(in crate::root) retry_kind: PublicActionGasRetryKind,
    pub(in crate::root) gas_inputs: GasRetryInputs,
    pub(in crate::root) error: Option<Arc<str>>,
}

impl PublicActionGasRetryDialogContent {
    pub(in crate::root) fn new(
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
