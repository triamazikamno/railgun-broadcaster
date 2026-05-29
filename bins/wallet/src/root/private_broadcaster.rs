use std::sync::Arc;
use std::time::{Duration, Instant};

use gpui::{
    AppContext, Context, Entity, IntoElement, ParentElement, Pixels, SharedString, Styled, Window,
    div, prelude::FluentBuilder as _, px, rgb,
};
use gpui_component::{Icon, IconName, Sizable, WindowExt, button::ButtonVariants};
use ui::clipboard::clipboard_with_toast;
use ui::controls::{app_button, app_button_base, app_muted_text, app_strong_text};
use ui::theme;
use wallet_ops::{
    DesktopSelfBroadcastResult, PublicBroadcasterCostEstimate, PublicBroadcasterResultKind,
    PublicBroadcasterSubmissionResult, SelfBroadcastAttemptInfo, SelfBroadcastCommand,
    SelfBroadcastCommandKind, SelfBroadcastCommandSender, SelfBroadcastGasFeeSelection,
    TransactionGenerationStage, self_broadcast_replacement_bumped_fee,
};

use super::gas_fee::{GasRetryInputs, format_gwei};
use super::private_action::{delivery_element_id, private_action_title_row};
use super::public_action::{
    ProgressFooterAction, PublicActionStepStatus, progress_footer_action, public_action_step_color,
    render_public_action_step_marker,
};
use super::public_broadcaster_cost::{
    PrivateBroadcasterProgressContext, PublicBroadcasterCostDisplay, cost_estimate_detail_text,
    private_broadcaster_context_row, render_private_broadcaster_progress_context,
    render_public_broadcaster_tx_hash_row,
};
use super::{
    DeliveryFormKind, PRIVATE_BROADCASTER_PROGRESS_DIALOG_WIDTH, UnshieldAssetKey, WalletRoot,
    format_native_token_amount_for_display, secondary_dialog_content_width,
};

use crate::assets::{RailgunActionIcon, WalletIconSource};

const PRIVATE_BROADCASTER_PROGRESS_STAGES: [TransactionGenerationStage; 6] = [
    TransactionGenerationStage::SelectingPrivateNotes,
    TransactionGenerationStage::ProvingTransaction,
    TransactionGenerationStage::EstimatingBroadcasterFee,
    TransactionGenerationStage::GeneratingPoiProofs,
    TransactionGenerationStage::PublishingToBroadcaster,
    TransactionGenerationStage::WaitingForBroadcasterResponse,
];

const SELF_BROADCAST_PROGRESS_STAGES: [TransactionGenerationStage; 6] = [
    TransactionGenerationStage::SelectingPrivateNotes,
    TransactionGenerationStage::ProvingTransaction,
    TransactionGenerationStage::GeneratingPoiProofs,
    TransactionGenerationStage::EstimatingSelfBroadcastGas,
    TransactionGenerationStage::SigningSelfBroadcast,
    TransactionGenerationStage::WaitingForSelfBroadcastReceipt,
];
const SELF_BROADCAST_UNSHIELD_PROGRESS_STAGES: [TransactionGenerationStage; 5] = [
    TransactionGenerationStage::SelectingPrivateNotes,
    TransactionGenerationStage::ProvingTransaction,
    TransactionGenerationStage::EstimatingSelfBroadcastGas,
    TransactionGenerationStage::SigningSelfBroadcast,
    TransactionGenerationStage::WaitingForSelfBroadcastReceipt,
];
const SELF_BROADCAST_GAS_RETRY_DIALOG_WIDTH: Pixels = px(460.0);
const PUBLIC_BROADCASTER_STOP_RESEND_THRESHOLD: usize = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PrivateSubmissionProgressFlow {
    PublicBroadcaster,
    SelfBroadcast,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PrivateBroadcasterProgressStepState {
    pub(super) stage: TransactionGenerationStage,
    pub(super) status: PublicActionStepStatus,
    pub(super) message: Option<Arc<str>>,
}

pub(super) struct PrivateBroadcasterProgressState {
    pub(super) flow: PrivateSubmissionProgressFlow,
    pub(super) kind: DeliveryFormKind,
    pub(super) key: UnshieldAssetKey,
    pub(super) generation_id: u64,
    pub(super) asset_label: Arc<str>,
    pub(super) icon_path: Option<WalletIconSource>,
    pub(super) recipient: Arc<str>,
    pub(super) gas_payer: Option<Arc<str>>,
    pub(super) steps: Vec<PrivateBroadcasterProgressStepState>,
    pub(super) estimate: Option<PublicBroadcasterCostEstimate>,
    pub(super) result: Option<PublicBroadcasterSubmissionResult>,
    pub(super) self_broadcast_result: Option<DesktopSelfBroadcastResult>,
    pub(super) self_broadcast_command_tx: Option<SelfBroadcastCommandSender>,
    pub(super) self_broadcast_attempts: Vec<SelfBroadcastAttemptInfo>,
    pub(super) self_broadcast_current_gas_fee: Option<(u128, u128)>,
    pub(super) self_broadcast_action_error: Option<Arc<str>>,
    pub(super) public_broadcaster_response_timeout: Option<Duration>,
    pub(super) public_broadcaster_republish_interval: Option<Duration>,
    pub(super) public_broadcaster_wait_started_at: Option<Instant>,
    pub(super) task_abort_handle: Option<tokio::task::AbortHandle>,
    pub(super) stop_available: bool,
    pub(super) stopped: bool,
    pub(super) error: Option<Arc<str>>,
    pub(super) dialog_open: bool,
    pub(super) stage_seen: bool,
}

impl PrivateBroadcasterProgressState {
    fn accepts_update(
        &self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        generation_id: u64,
    ) -> bool {
        self.kind == kind
            && self.key == key
            && self.generation_id == generation_id
            && self.result.is_none()
            && self.self_broadcast_result.is_none()
            && self.error.is_none()
            && !self.stopped
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SelfBroadcastGasRetryKind {
    RetryEstimate,
    SpeedUp,
}

pub(super) struct SelfBroadcastGasRetryDialogContent {
    root: Entity<WalletRoot>,
    kind: DeliveryFormKind,
    key: UnshieldAssetKey,
    generation_id: u64,
    retry_kind: SelfBroadcastGasRetryKind,
    gas_inputs: GasRetryInputs,
    error: Option<Arc<str>>,
}

pub(super) const fn private_broadcaster_dialog_title_action(
    kind: DeliveryFormKind,
) -> &'static str {
    match kind {
        DeliveryFormKind::Send => "Send via broadcaster",
        DeliveryFormKind::Unshield => "Unshield via broadcaster",
    }
}

pub(super) const fn private_submission_dialog_title_action(
    flow: PrivateSubmissionProgressFlow,
    kind: DeliveryFormKind,
) -> &'static str {
    match flow {
        PrivateSubmissionProgressFlow::PublicBroadcaster => {
            private_broadcaster_dialog_title_action(kind)
        }
        PrivateSubmissionProgressFlow::SelfBroadcast => match kind {
            DeliveryFormKind::Send => "Self-broadcast send",
            DeliveryFormKind::Unshield => "Self-broadcast unshield",
        },
    }
}

impl SelfBroadcastGasRetryDialogContent {
    fn new(
        root: Entity<WalletRoot>,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        generation_id: u64,
        retry_kind: SelfBroadcastGasRetryKind,
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
            kind,
            key,
            generation_id,
            retry_kind,
            gas_inputs,
            error: None,
        }
    }
}

impl gpui::Render for SelfBroadcastGasRetryDialogContent {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<'_, Self>) -> impl IntoElement {
        let title = match self.retry_kind {
            SelfBroadcastGasRetryKind::RetryEstimate => "Retry with custom gas",
            SelfBroadcastGasRetryKind::SpeedUp => "Speed up transaction",
        };
        let detail = match self.retry_kind {
            SelfBroadcastGasRetryKind::RetryEstimate => {
                "Retry gas estimation and signing using these EIP-1559 fee values."
            }
            SelfBroadcastGasRetryKind::SpeedUp => {
                "Uses the same nonce to replace the pending transaction. Values are prefilled +12.5%."
            }
        };
        let submit_root = self.root.clone();
        let cancel_root = self.root.clone();
        let dialog = cx.entity();
        let gas_inputs = self.gas_inputs.clone();
        let kind = self.kind;
        let key = self.key;
        let generation_id = self.generation_id;
        let retry_kind = self.retry_kind;
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
                        app_button("self-broadcast-gas-retry-cancel", "Cancel")
                            .flex_none()
                            .on_click(move |_event, window, cx| {
                                let _ = &cancel_root;
                                window.close_dialog(cx);
                            }),
                    )
                    .child(
                        app_button("self-broadcast-gas-retry-confirm", "Submit")
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
                                    root.submit_self_broadcast_gas_retry(
                                        kind,
                                        key,
                                        generation_id,
                                        retry_kind,
                                        max_fee,
                                        max_tip,
                                        cx,
                                    );
                                });
                                window.close_dialog(cx);
                            }),
                    ),
            )
    }
}

pub(super) fn private_broadcaster_progress_steps() -> Vec<PrivateBroadcasterProgressStepState> {
    progress_steps(&PRIVATE_BROADCASTER_PROGRESS_STAGES)
}

pub(super) fn self_broadcast_progress_steps(
    kind: DeliveryFormKind,
) -> Vec<PrivateBroadcasterProgressStepState> {
    match kind {
        DeliveryFormKind::Send => progress_steps(&SELF_BROADCAST_PROGRESS_STAGES),
        DeliveryFormKind::Unshield => progress_steps(&SELF_BROADCAST_UNSHIELD_PROGRESS_STAGES),
    }
}

pub(super) fn ensure_self_broadcast_unshield_progress_stage(
    steps: &mut Vec<PrivateBroadcasterProgressStepState>,
    stage: TransactionGenerationStage,
) {
    if stage != TransactionGenerationStage::GeneratingPoiProofs
        || steps.iter().any(|step| step.stage == stage)
    {
        return;
    }
    let insert_index = steps
        .iter()
        .position(|step| step.stage == TransactionGenerationStage::EstimatingSelfBroadcastGas)
        .unwrap_or(steps.len());
    let status = if steps
        .get(insert_index)
        .is_some_and(|step| step.status != PublicActionStepStatus::NotStarted)
    {
        PublicActionStepStatus::Done
    } else {
        PublicActionStepStatus::NotStarted
    };
    steps.insert(
        insert_index,
        PrivateBroadcasterProgressStepState {
            stage,
            status,
            message: None,
        },
    );
}

fn ensure_private_broadcaster_progress_stage(
    progress: &mut PrivateBroadcasterProgressState,
    stage: TransactionGenerationStage,
) {
    if progress.flow == PrivateSubmissionProgressFlow::SelfBroadcast
        && progress.kind == DeliveryFormKind::Unshield
    {
        ensure_self_broadcast_unshield_progress_stage(&mut progress.steps, stage);
    }
}

fn progress_steps(
    stages: &[TransactionGenerationStage],
) -> Vec<PrivateBroadcasterProgressStepState> {
    stages
        .iter()
        .enumerate()
        .map(|(index, &stage)| PrivateBroadcasterProgressStepState {
            stage,
            status: if index == 0 {
                PublicActionStepStatus::Pending
            } else {
                PublicActionStepStatus::NotStarted
            },
            message: None,
        })
        .collect()
}

pub(super) fn private_broadcaster_closed_active_progress(
    progress: Option<&PrivateBroadcasterProgressState>,
    kind: DeliveryFormKind,
    key: UnshieldAssetKey,
    generation_id: u64,
) -> Option<(PrivateSubmissionProgressFlow, TransactionGenerationStage)> {
    let progress = progress?;
    if !progress.accepts_update(kind, key, generation_id)
        || progress.dialog_open
        || !progress.stage_seen
    {
        return None;
    }
    progress
        .steps
        .iter()
        .find(|step| step.status == PublicActionStepStatus::Pending)
        .map(|step| (progress.flow, step.stage))
}

#[cfg(test)]
pub(super) fn private_broadcaster_closed_active_stage(
    progress: Option<&PrivateBroadcasterProgressState>,
    kind: DeliveryFormKind,
    key: UnshieldAssetKey,
    generation_id: u64,
) -> Option<TransactionGenerationStage> {
    private_broadcaster_closed_active_progress(progress, kind, key, generation_id)
        .map(|(_, stage)| stage)
}

pub(super) const fn private_progress_stage_disables_stop(
    flow: PrivateSubmissionProgressFlow,
    stage: TransactionGenerationStage,
) -> bool {
    match flow {
        PrivateSubmissionProgressFlow::PublicBroadcaster => matches!(
            stage,
            TransactionGenerationStage::PublishingToBroadcaster
                | TransactionGenerationStage::WaitingForBroadcasterResponse
        ),
        PrivateSubmissionProgressFlow::SelfBroadcast => matches!(
            stage,
            TransactionGenerationStage::SigningSelfBroadcast
                | TransactionGenerationStage::WaitingForSelfBroadcastReceipt
        ),
    }
}

pub(super) fn private_broadcaster_progress_footer_action(
    progress: &PrivateBroadcasterProgressState,
) -> ProgressFooterAction {
    progress_footer_action(
        private_broadcaster_progress_stop_available(progress, Instant::now()),
        private_broadcaster_progress_is_terminal(progress),
    )
}

fn private_broadcaster_progress_stop_available(
    progress: &PrivateBroadcasterProgressState,
    now: Instant,
) -> bool {
    progress.stop_available || public_broadcaster_waiting_can_stop(progress, now)
}

fn public_broadcaster_waiting_can_stop(
    progress: &PrivateBroadcasterProgressState,
    now: Instant,
) -> bool {
    public_broadcaster_resend_count(progress, now)
        .is_some_and(|count| count >= PUBLIC_BROADCASTER_STOP_RESEND_THRESHOLD)
}

pub(super) fn private_broadcaster_progress_is_terminal(
    progress: &PrivateBroadcasterProgressState,
) -> bool {
    progress.stopped
        || progress.result.is_some()
        || progress.self_broadcast_result.is_some()
        || progress.error.is_some()
        || (!progress.steps.is_empty()
            && (progress
                .steps
                .iter()
                .all(|step| step.status == PublicActionStepStatus::Done)
                || progress.steps.iter().any(|step| {
                    matches!(
                        step.status,
                        PublicActionStepStatus::Error | PublicActionStepStatus::Stopped
                    )
                })))
}

pub(super) fn mark_private_broadcaster_active_step_stopped(
    steps: &mut [PrivateBroadcasterProgressStepState],
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
    step.message = None;
    true
}

impl WalletRoot {
    pub(super) fn clear_private_broadcaster_progress_state(&mut self) {
        if let Some(mut progress) = self.private_broadcaster_progress.take()
            && let Some(handle) = progress.task_abort_handle.take()
        {
            handle.abort();
        }
    }

    pub(super) fn set_private_broadcaster_task_abort_handle(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        generation_id: u64,
        handle: tokio::task::AbortHandle,
    ) {
        let Some(progress) = self.private_broadcaster_progress.as_mut() else {
            return;
        };
        if progress.kind == kind && progress.key == key && progress.generation_id == generation_id {
            progress.task_abort_handle = Some(handle);
        }
    }

    pub(super) fn start_private_broadcaster_progress(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        generation_id: u64,
        asset_label: String,
        icon_path: Option<WalletIconSource>,
        recipient: String,
        estimate: Option<PublicBroadcasterCostEstimate>,
        response_timeout: Duration,
        republish_interval: Duration,
    ) {
        let asset_label = Arc::<str>::from(asset_label);
        let dialog_open = self
            .private_broadcaster_progress
            .as_ref()
            .is_some_and(|progress| progress.dialog_open);
        self.private_broadcaster_progress = Some(PrivateBroadcasterProgressState {
            flow: PrivateSubmissionProgressFlow::PublicBroadcaster,
            kind,
            key,
            generation_id,
            asset_label: Arc::clone(&asset_label),
            icon_path,
            recipient: Arc::from(recipient),
            gas_payer: None,
            steps: private_broadcaster_progress_steps(),
            estimate,
            result: None,
            self_broadcast_result: None,
            self_broadcast_command_tx: None,
            self_broadcast_attempts: Vec::new(),
            self_broadcast_current_gas_fee: None,
            self_broadcast_action_error: None,
            public_broadcaster_response_timeout: Some(response_timeout),
            public_broadcaster_republish_interval: Some(republish_interval),
            public_broadcaster_wait_started_at: None,
            task_abort_handle: None,
            stop_available: true,
            stopped: false,
            error: None,
            dialog_open,
            stage_seen: false,
        });
    }

    pub(super) fn start_private_self_broadcast_progress(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        generation_id: u64,
        asset_label: String,
        icon_path: Option<WalletIconSource>,
        recipient: String,
        gas_payer: String,
        command_tx: Option<SelfBroadcastCommandSender>,
        current_gas_fee: Option<(u128, u128)>,
    ) {
        let asset_label = Arc::<str>::from(asset_label);
        let dialog_open = self
            .private_broadcaster_progress
            .as_ref()
            .is_some_and(|progress| progress.dialog_open);
        self.private_broadcaster_progress = Some(PrivateBroadcasterProgressState {
            flow: PrivateSubmissionProgressFlow::SelfBroadcast,
            kind,
            key,
            generation_id,
            asset_label: Arc::clone(&asset_label),
            icon_path,
            recipient: Arc::from(recipient),
            gas_payer: Some(Arc::from(gas_payer)),
            steps: self_broadcast_progress_steps(kind),
            estimate: None,
            result: None,
            self_broadcast_result: None,
            self_broadcast_command_tx: command_tx,
            self_broadcast_attempts: Vec::new(),
            self_broadcast_current_gas_fee: current_gas_fee,
            self_broadcast_action_error: None,
            public_broadcaster_response_timeout: None,
            public_broadcaster_republish_interval: None,
            public_broadcaster_wait_started_at: None,
            task_abort_handle: None,
            stop_available: true,
            stopped: false,
            error: None,
            dialog_open,
            stage_seen: false,
        });
    }

    pub(super) fn show_private_broadcaster_progress_dialog(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(progress) = self.private_broadcaster_progress.as_mut() else {
            return;
        };
        if progress.dialog_open {
            return;
        }
        progress.dialog_open = true;
        let flow = progress.flow;
        let kind = progress.kind;
        let key = progress.key;
        let generation_id = progress.generation_id;
        let asset_label = Arc::clone(&progress.asset_label);
        let icon_path = progress.icon_path.clone();
        let root = cx.entity();
        let viewport_size = window.viewport_size();
        let dialog_width =
            (viewport_size.width * 0.92).min(PRIVATE_BROADCASTER_PROGRESS_DIALOG_WIDTH);
        let dialog_max_height = viewport_size.height * 0.84;
        let content_width = secondary_dialog_content_width(dialog_width);
        window.open_dialog(cx, move |dialog, _window, cx| {
            let close_root = root.clone();
            let content_root = root.clone();
            dialog
                .w(dialog_width)
                .max_h(dialog_max_height)
                .title(private_action_title_row(
                    private_submission_dialog_title_action(flow, kind),
                    asset_label.as_ref(),
                    icon_path.clone(),
                    None,
                    false,
                ))
                .on_close(move |_event, _window, cx| {
                    close_root.update(cx, |root, cx| {
                        let matches_progress = root
                            .private_broadcaster_progress
                            .as_ref()
                            .is_some_and(|progress| {
                                progress.kind == kind
                                    && progress.key == key
                                    && progress.generation_id == generation_id
                            });
                        if !matches_progress {
                            return;
                        }
                        if root
                            .private_broadcaster_progress
                            .as_ref()
                            .is_some_and(|progress| progress.stopped)
                        {
                            root.clear_private_broadcaster_progress_state();
                        } else if let Some(progress) = root.private_broadcaster_progress.as_mut() {
                            progress.dialog_open = false;
                        }
                        cx.notify();
                    });
                })
                .child(
                    content_root
                        .read(cx)
                        .render_private_broadcaster_progress_dialog_content(
                            &content_root,
                            content_width,
                        ),
                )
        });
    }

    fn stop_private_broadcaster_progress(&mut self, cx: &mut Context<'_, Self>) {
        let Some(progress) = self.private_broadcaster_progress.as_mut() else {
            return;
        };
        if private_broadcaster_progress_footer_action(progress) != ProgressFooterAction::Stop {
            return;
        }
        let kind = progress.kind;
        let key = progress.key;
        let generation_id = progress.generation_id;
        if let Some(handle) = progress.task_abort_handle.take() {
            handle.abort();
        }
        progress.self_broadcast_command_tx = None;
        progress.self_broadcast_action_error = None;
        progress.stop_available = false;
        progress.stopped = true;
        progress.error = None;
        mark_private_broadcaster_active_step_stopped(&mut progress.steps);

        match kind {
            DeliveryFormKind::Send => {
                if let Some(form) = self.send_forms.get_mut(&key)
                    && form.generation_id == generation_id
                {
                    form.generating = false;
                    form.error = None;
                }
            }
            DeliveryFormKind::Unshield => {
                if let Some(form) = self.unshield_forms.get_mut(&key)
                    && form.generation_id == generation_id
                {
                    form.generating = false;
                    form.error = None;
                }
            }
        }
        cx.notify();
    }

    fn close_private_broadcaster_progress_dialog(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        if self
            .private_broadcaster_progress
            .as_ref()
            .is_some_and(|progress| progress.stopped)
        {
            self.clear_private_broadcaster_progress_state();
        } else if let Some(progress) = self.private_broadcaster_progress.as_mut() {
            progress.dialog_open = false;
        }
        window.close_dialog(cx);
        cx.notify();
    }

    pub(super) fn update_private_broadcaster_progress_stage(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        generation_id: u64,
        stage: TransactionGenerationStage,
        cx: &mut Context<'_, Self>,
    ) -> bool {
        let Some(progress) = self.private_broadcaster_progress.as_mut() else {
            return false;
        };
        if !progress.accepts_update(kind, key, generation_id) {
            return false;
        }
        let should_open_dialog = !progress.stage_seen && !progress.dialog_open;
        progress.stage_seen = true;
        if progress.flow == PrivateSubmissionProgressFlow::PublicBroadcaster
            && stage == TransactionGenerationStage::WaitingForBroadcasterResponse
            && progress.public_broadcaster_wait_started_at.is_none()
        {
            progress.public_broadcaster_wait_started_at = Some(Instant::now());
        }
        if private_progress_stage_disables_stop(progress.flow, stage) {
            progress.stop_available = false;
        }
        ensure_private_broadcaster_progress_stage(progress, stage);
        apply_private_broadcaster_progress_stage(&mut progress.steps, stage);
        cx.notify();
        should_open_dialog
    }

    pub(super) fn set_private_self_broadcast_unshield_poi_step(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        generation_id: u64,
        required: bool,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(progress) = self.private_broadcaster_progress.as_mut() else {
            return;
        };
        if !progress.accepts_update(kind, key, generation_id)
            || progress.flow != PrivateSubmissionProgressFlow::SelfBroadcast
            || progress.kind != DeliveryFormKind::Unshield
        {
            return;
        }
        if required {
            ensure_self_broadcast_unshield_progress_stage(
                &mut progress.steps,
                TransactionGenerationStage::GeneratingPoiProofs,
            );
        } else if let Some(index) = progress.steps.iter().position(|step| {
            step.stage == TransactionGenerationStage::GeneratingPoiProofs
                && step.status == PublicActionStepStatus::NotStarted
        }) {
            progress.steps.remove(index);
        }
        cx.notify();
    }

    pub(super) fn finish_private_broadcaster_progress(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        generation_id: u64,
        final_stage: TransactionGenerationStage,
        result: PublicBroadcasterSubmissionResult,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(progress) = self.private_broadcaster_progress.as_mut() else {
            return;
        };
        if !progress.accepts_update(kind, key, generation_id) {
            return;
        }
        finish_private_broadcaster_progress_steps_at_stage(
            &mut progress.steps,
            final_stage,
            &result.result,
        );
        progress.task_abort_handle = None;
        progress.stop_available = false;
        progress.result = Some(result);
        progress.error = None;
        cx.notify();
    }

    pub(super) fn finish_private_self_broadcast_progress(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        generation_id: u64,
        final_stage: TransactionGenerationStage,
        result: DesktopSelfBroadcastResult,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(progress) = self.private_broadcaster_progress.as_mut() else {
            return;
        };
        if !progress.accepts_update(kind, key, generation_id) {
            return;
        }
        ensure_private_broadcaster_progress_stage(progress, final_stage);
        finish_private_self_broadcast_progress_steps_at_stage(
            &mut progress.steps,
            final_stage,
            result.tx.status,
        );
        progress
            .self_broadcast_attempts
            .clone_from(&result.attempts);
        progress.self_broadcast_current_gas_fee =
            Some((result.max_fee_per_gas, result.max_priority_fee_per_gas));
        progress.self_broadcast_action_error = None;
        progress.self_broadcast_result = Some(result);
        progress.self_broadcast_command_tx = None;
        progress.task_abort_handle = None;
        progress.stop_available = false;
        progress.error = None;
        cx.notify();
    }

    pub(super) fn fail_private_broadcaster_progress(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        generation_id: u64,
        final_stage: TransactionGenerationStage,
        message: String,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(progress) = self.private_broadcaster_progress.as_mut() else {
            return;
        };
        if !progress.accepts_update(kind, key, generation_id) {
            return;
        }
        ensure_private_broadcaster_progress_stage(progress, final_stage);
        fail_private_broadcaster_progress_steps_at_stage(
            &mut progress.steps,
            final_stage,
            message.as_str(),
        );
        progress.self_broadcast_action_error = None;
        progress.error = Some(Arc::from(message));
        progress.self_broadcast_command_tx = None;
        progress.task_abort_handle = None;
        progress.stop_available = false;
        cx.notify();
    }

    pub(super) fn record_private_broadcaster_progress_step_error(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        generation_id: u64,
        stage: TransactionGenerationStage,
        message: &str,
        cx: &mut Context<'_, Self>,
    ) -> bool {
        let Some(progress) = self.private_broadcaster_progress.as_mut() else {
            return false;
        };
        if !progress.accepts_update(kind, key, generation_id) {
            return false;
        }
        progress.stage_seen = true;
        ensure_private_broadcaster_progress_stage(progress, stage);
        fail_private_broadcaster_progress_steps_at_stage(&mut progress.steps, stage, message);
        progress.self_broadcast_action_error = None;
        cx.notify();
        !progress.dialog_open
    }

    pub(super) fn record_private_self_broadcast_attempt(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        generation_id: u64,
        attempt: SelfBroadcastAttemptInfo,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(progress) = self.private_broadcaster_progress.as_mut() else {
            return;
        };
        if !progress.accepts_update(kind, key, generation_id) {
            return;
        }
        progress.self_broadcast_current_gas_fee =
            Some((attempt.max_fee_per_gas, attempt.max_priority_fee_per_gas));
        progress.self_broadcast_action_error = None;
        progress.stop_available = false;
        progress.self_broadcast_attempts.push(attempt);
        cx.notify();
    }

    pub(super) fn record_private_self_broadcast_attempt_rejected(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        generation_id: u64,
        message: String,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(progress) = self.private_broadcaster_progress.as_mut() else {
            return;
        };
        if !progress.accepts_update(kind, key, generation_id) {
            return;
        }
        progress.self_broadcast_action_error = Some(Arc::from(message));
        cx.notify();
    }

    pub(super) fn open_self_broadcast_gas_retry_dialog(
        &self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        generation_id: u64,
        retry_kind: SelfBroadcastGasRetryKind,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(progress) = self.private_broadcaster_progress.as_ref() else {
            return;
        };
        if !progress.accepts_update(kind, key, generation_id)
            || progress.self_broadcast_command_tx.is_none()
        {
            return;
        }
        let Some((mut max_fee, mut max_tip)) = progress.self_broadcast_current_gas_fee else {
            return;
        };
        if retry_kind == SelfBroadcastGasRetryKind::SpeedUp {
            max_fee = self_broadcast_replacement_bumped_fee(max_fee);
            max_tip = self_broadcast_replacement_bumped_fee(max_tip);
        }
        let root = cx.entity();
        let content = cx.new(|cx| {
            SelfBroadcastGasRetryDialogContent::new(
                root,
                kind,
                key,
                generation_id,
                retry_kind,
                max_fee,
                max_tip,
                window,
                cx,
            )
        });
        let dialog_width =
            (window.viewport_size().width * 0.92).min(SELF_BROADCAST_GAS_RETRY_DIALOG_WIDTH);
        window.open_dialog(cx, move |dialog, _window, _cx| {
            dialog.w(dialog_width).child(content.clone())
        });
    }

    fn submit_self_broadcast_gas_retry(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        generation_id: u64,
        retry_kind: SelfBroadcastGasRetryKind,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(progress) = self.private_broadcaster_progress.as_ref() else {
            return;
        };
        if !progress.accepts_update(kind, key, generation_id) {
            return;
        }
        let Some(command_tx) = progress.self_broadcast_command_tx.as_ref() else {
            return;
        };
        let command_kind = match retry_kind {
            SelfBroadcastGasRetryKind::RetryEstimate => SelfBroadcastCommandKind::Retry,
            SelfBroadcastGasRetryKind::SpeedUp => SelfBroadcastCommandKind::Replacement,
        };
        let send_result = command_tx.send(SelfBroadcastCommand {
            kind: command_kind,
            gas_fee: SelfBroadcastGasFeeSelection::Custom {
                max_fee_per_gas,
                max_priority_fee_per_gas,
            },
        });
        if let Some(progress) = self.private_broadcaster_progress.as_mut() {
            progress.self_broadcast_action_error = send_result.err().map(|_| {
                Arc::from("Self-broadcast session is no longer accepting retry commands.")
            });
        }
        cx.notify();
    }

    pub(super) fn render_private_broadcaster_progress_dialog_content(
        &self,
        root: &Entity<Self>,
        content_width: Pixels,
    ) -> gpui::Div {
        let Some(progress) = self.private_broadcaster_progress.as_ref() else {
            return div()
                .w(content_width)
                .child(app_muted_text("No active private submission."));
        };
        let mut content = div()
            .w(content_width)
            .flex()
            .flex_col()
            .gap_3()
            .child(render_private_broadcaster_progress_stepper(root, progress));

        match progress.flow {
            PrivateSubmissionProgressFlow::PublicBroadcaster => {
                if let Some(context) = self.private_broadcaster_progress_context(progress) {
                    let broadcaster_action =
                        self.render_public_broadcaster_preference_action(root, progress);
                    content = content.child(render_private_broadcaster_progress_context(
                        progress,
                        &context,
                        broadcaster_action,
                    ));
                } else {
                    content =
                        content.child(render_pending_public_broadcaster_progress_context(progress));
                }
            }
            PrivateSubmissionProgressFlow::SelfBroadcast => {
                content = content.child(render_self_broadcast_progress_context(progress));
            }
        }

        if let Some(result) = progress.result.as_ref()
            && let PublicBroadcasterResultKind::Submitted { tx_hash } = &result.result
        {
            content = content.child(render_public_broadcaster_tx_hash_row(
                tx_hash.clone(),
                delivery_element_id(progress.key, progress.kind, "progress-copy-public-tx"),
            ));
        }
        if let Some(result) = progress.self_broadcast_result.as_ref() {
            content = content.child(render_public_broadcaster_tx_hash_row(
                result.tx.tx_hash.clone(),
                delivery_element_id(progress.key, progress.kind, "progress-copy-self-tx"),
            ));
        }
        content = content.child(render_private_broadcaster_progress_footer(
            root.clone(),
            progress,
        ));
        content
    }

    fn private_broadcaster_progress_context<'a>(
        &'a self,
        progress: &'a PrivateBroadcasterProgressState,
    ) -> Option<PrivateBroadcasterProgressContext<'a>> {
        if let Some(result) = progress.result.as_ref() {
            let anchor_rate = self
                .public_broadcaster_anchor_cache
                .cached_rate(result.broadcaster.chain_id, result.fee_token);
            return Some(PrivateBroadcasterProgressContext {
                display: PublicBroadcasterCostDisplay::from_result(
                    result,
                    anchor_rate,
                    Some(&self.effective_token_registry),
                ),
                settled: true,
            });
        }
        let estimate = progress.estimate.as_ref()?;
        let anchor_rate = self
            .public_broadcaster_anchor_cache
            .cached_rate(progress.key.chain_id, estimate.fee_token);
        Some(PrivateBroadcasterProgressContext {
            display: PublicBroadcasterCostDisplay::from_estimate_chain(
                progress.key.chain_id,
                estimate,
                anchor_rate,
                Some(&self.effective_token_registry),
            ),
            settled: false,
        })
    }

    fn render_public_broadcaster_preference_action(
        &self,
        root: &Entity<Self>,
        progress: &PrivateBroadcasterProgressState,
    ) -> Option<gpui::AnyElement> {
        let address = public_broadcaster_progress_address(progress)?;
        if self.is_banned_broadcaster(address) {
            return Some(
                render_broadcaster_preference_progress_chip("Banned", theme::DANGER)
                    .into_any_element(),
            );
        }

        let submitted = progress.result.as_ref().is_some_and(|result| {
            matches!(
                &result.result,
                PublicBroadcasterResultKind::Submitted { .. }
            )
        });
        if submitted {
            if self.is_favorite_broadcaster(address) {
                return Some(
                    render_broadcaster_preference_progress_chip("Favorited", theme::WARNING)
                        .into_any_element(),
                );
            }
            let action_root = root.clone();
            let address = address.to_owned();
            return Some(
                app_button_base(delivery_element_id(
                    progress.key,
                    progress.kind,
                    "favorite-current-broadcaster",
                ))
                .outline()
                .xsmall()
                .icon(Icon::new(IconName::Star))
                .tooltip(
                    "Save this broadcaster to your favorites so future transactions can prefer it.",
                )
                .on_click(move |_event, _window, cx| {
                    let address = address.clone();
                    action_root.update(cx, |root, cx| {
                        root.add_favorite_broadcaster(&address, cx);
                    });
                })
                .into_any_element(),
            );
        }

        if public_broadcaster_waiting_can_stop(progress, Instant::now()) && !progress.stop_available
        {
            let action_root = root.clone();
            let address = address.to_owned();
            return Some(
                app_button(
                    delivery_element_id(progress.key, progress.kind, "ban-current-broadcaster"),
                    "Ban this broadcaster",
                )
                .danger()
                .outline()
                .xsmall()
                .tooltip("Exclude this broadcaster from future selections. This does not stop the current wait.")
                .on_click(move |_event, _window, cx| {
                    let address = address.clone();
                    action_root.update(cx, |root, cx| {
                        root.add_banned_broadcaster(&address, cx);
                    });
                })
                .into_any_element(),
            );
        }

        None
    }
}

fn public_broadcaster_progress_address(progress: &PrivateBroadcasterProgressState) -> Option<&str> {
    progress.result.as_ref().map_or_else(
        || {
            progress
                .estimate
                .as_ref()
                .map(|estimate| estimate.broadcaster.railgun_address.as_ref())
        },
        |result| Some(result.broadcaster.railgun_address.as_ref()),
    )
}

fn render_broadcaster_preference_progress_chip(label: &'static str, color: u32) -> gpui::Div {
    div()
        .flex_none()
        .px(px(8.0))
        .py(px(2.0))
        .rounded_full()
        .bg(super::rgb_with_alpha(color, 0.12))
        .text_color(rgb(color))
        .text_size(px(11.0))
        .child(label)
}

fn render_pending_public_broadcaster_progress_context(
    progress: &PrivateBroadcasterProgressState,
) -> gpui::Div {
    div()
        .flex()
        .flex_col()
        .gap_2()
        .p(px(12.0))
        .rounded_md()
        .bg(rgb(theme::SURFACE_ELEVATED))
        .border_1()
        .border_color(rgb(theme::BORDER))
        .child(app_strong_text("Transaction context"))
        .child(private_broadcaster_context_row(
            "Broadcaster",
            "Selecting during preparation".to_string(),
        ))
        .child(private_broadcaster_context_row(
            "Recipient",
            progress.recipient.to_string(),
        ))
        .child(cost_estimate_detail_text(
            "Fee and gas cost will appear after the transaction fee is calculated.",
        ))
}

fn render_self_broadcast_progress_context(progress: &PrivateBroadcasterProgressState) -> gpui::Div {
    let mut context = div()
        .flex()
        .flex_col()
        .gap_2()
        .p(px(12.0))
        .rounded_md()
        .bg(rgb(theme::SURFACE_ELEVATED))
        .border_1()
        .border_color(rgb(theme::BORDER))
        .child(app_strong_text("Transaction context"))
        .child(private_broadcaster_context_row(
            "Gas payer",
            progress
                .gas_payer
                .as_deref()
                .unwrap_or("Selected Public account")
                .to_string(),
        ))
        .child(private_broadcaster_context_row(
            "Recipient",
            progress.recipient.to_string(),
        ));
    if let Some(result) = progress.self_broadcast_result.as_ref() {
        context = context
            .child(private_broadcaster_context_row(
                "Max fee",
                format!("{} gwei", format_gwei(result.max_fee_per_gas)),
            ))
            .child(private_broadcaster_context_row(
                "Max tip",
                format!("{} gwei", format_gwei(result.max_priority_fee_per_gas)),
            ))
            .child(private_broadcaster_context_row(
                "Estimated gas cost",
                format_native_token_amount_for_display(
                    result.chain_id,
                    result.estimated_native_gas_cost,
                ),
            ))
            .child(private_broadcaster_context_row(
                "Receipt",
                if result.tx.status {
                    "confirmed"
                } else {
                    "reverted"
                }
                .to_string(),
            ))
            .child(private_broadcaster_context_row(
                "Block",
                result.tx.block_number.to_string(),
            ));
    }
    context
}

fn render_private_broadcaster_progress_footer(
    root: Entity<WalletRoot>,
    progress: &PrivateBroadcasterProgressState,
) -> gpui::Div {
    let now = Instant::now();
    let action = progress_footer_action(
        private_broadcaster_progress_stop_available(progress, now),
        private_broadcaster_progress_is_terminal(progress),
    );
    let button_root = root;
    let (id_suffix, label) = match action {
        ProgressFooterAction::Stop => (
            "progress-stop",
            if public_broadcaster_waiting_can_stop(progress, now) && !progress.stop_available {
                "Stop waiting"
            } else {
                "Stop"
            },
        ),
        ProgressFooterAction::Close => ("progress-close", "Close"),
    };
    let button = app_button(
        delivery_element_id(progress.key, progress.kind, id_suffix),
        label,
    )
    .small()
    .flex_none();
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
                ProgressFooterAction::Stop => root.stop_private_broadcaster_progress(cx),
                ProgressFooterAction::Close => {
                    root.close_private_broadcaster_progress_dialog(window, cx);
                }
            });
        }))
}

pub(super) fn apply_private_broadcaster_progress_stage(
    steps: &mut [PrivateBroadcasterProgressStepState],
    stage: TransactionGenerationStage,
) {
    let active_index = private_progress_stage_index(steps, stage);
    for (index, step) in steps.iter_mut().enumerate() {
        step.status = match index.cmp(&active_index) {
            std::cmp::Ordering::Less => PublicActionStepStatus::Done,
            std::cmp::Ordering::Equal => PublicActionStepStatus::Pending,
            std::cmp::Ordering::Greater => PublicActionStepStatus::NotStarted,
        };
        step.message = None;
    }
}

pub(super) fn finish_private_self_broadcast_progress_steps(
    steps: &mut [PrivateBroadcasterProgressStepState],
    receipt_status: bool,
) {
    if receipt_status {
        for step in steps {
            step.status = PublicActionStepStatus::Done;
            step.message = None;
        }
    } else {
        fail_private_broadcaster_progress_steps(
            steps,
            "Transaction receipt indicates the self-broadcast transaction reverted.",
        );
    }
}

pub(super) fn finish_private_broadcaster_progress_steps(
    steps: &mut [PrivateBroadcasterProgressStepState],
    result: &PublicBroadcasterResultKind,
) {
    match result {
        PublicBroadcasterResultKind::Submitted { .. } => {
            for step in steps {
                step.status = PublicActionStepStatus::Done;
                step.message = None;
            }
        }
        PublicBroadcasterResultKind::Failed { error } => {
            let message = format!("Broadcaster returned an error: {error}");
            fail_private_broadcaster_progress_steps(steps, &message);
        }
        PublicBroadcasterResultKind::TimedOut => fail_private_broadcaster_progress_steps(
            steps,
            "No decryptable broadcaster response arrived before the timeout.",
        ),
    }
}

pub(super) fn finish_private_broadcaster_progress_steps_at_stage(
    steps: &mut [PrivateBroadcasterProgressStepState],
    final_stage: TransactionGenerationStage,
    result: &PublicBroadcasterResultKind,
) {
    apply_private_broadcaster_progress_stage(steps, final_stage);
    finish_private_broadcaster_progress_steps(steps, result);
}

pub(super) fn finish_private_self_broadcast_progress_steps_at_stage(
    steps: &mut [PrivateBroadcasterProgressStepState],
    final_stage: TransactionGenerationStage,
    receipt_status: bool,
) {
    apply_private_broadcaster_progress_stage(steps, final_stage);
    finish_private_self_broadcast_progress_steps(steps, receipt_status);
}

pub(super) fn fail_private_broadcaster_progress_steps_at_stage(
    steps: &mut [PrivateBroadcasterProgressStepState],
    final_stage: TransactionGenerationStage,
    message: &str,
) {
    apply_private_broadcaster_progress_stage(steps, final_stage);
    fail_private_broadcaster_progress_steps(steps, message);
}

fn fail_private_broadcaster_progress_steps(
    steps: &mut [PrivateBroadcasterProgressStepState],
    message: &str,
) {
    let message = Arc::<str>::from(message);
    let error_index = steps
        .iter()
        .position(|step| step.status == PublicActionStepStatus::Pending)
        .or_else(|| {
            steps
                .iter()
                .position(|step| step.status == PublicActionStepStatus::NotStarted)
        })
        .or_else(|| steps.len().checked_sub(1));
    if let Some(error_index) = error_index {
        for (index, step) in steps.iter_mut().enumerate() {
            if index < error_index && step.status != PublicActionStepStatus::Error {
                step.status = PublicActionStepStatus::Done;
                step.message = None;
            } else if index == error_index {
                step.status = PublicActionStepStatus::Error;
                step.message = Some(Arc::clone(&message));
            } else if step.status != PublicActionStepStatus::Error {
                step.status = PublicActionStepStatus::NotStarted;
                step.message = None;
            }
        }
    }
}

fn private_progress_stage_index(
    steps: &[PrivateBroadcasterProgressStepState],
    stage: TransactionGenerationStage,
) -> usize {
    steps
        .iter()
        .position(|step| step.stage == stage)
        .unwrap_or_else(|| steps.len().saturating_sub(1))
}

pub(super) fn render_private_broadcaster_progress_stepper(
    root: &Entity<WalletRoot>,
    progress: &PrivateBroadcasterProgressState,
) -> gpui::Div {
    let steps = &progress.steps;
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
        stepper = stepper.child(render_private_broadcaster_progress_step(
            root.clone(),
            progress,
            step,
            index == last_index,
        ));
    }
    stepper
}

fn render_private_broadcaster_progress_step(
    root: Entity<WalletRoot>,
    progress: &PrivateBroadcasterProgressState,
    step: &PrivateBroadcasterProgressStepState,
    is_last: bool,
) -> gpui::Div {
    let color = public_action_step_color(step.status);
    let mut body = div()
        .flex_1()
        .min_w(px(0.0))
        .flex()
        .flex_col()
        .gap_1()
        .pb(if is_last { px(0.0) } else { px(12.0) })
        .child(
            app_strong_text(step.stage.label())
                .text_color(rgb(color))
                .line_height(gpui::relative(1.0)),
        );
    if step.status == PublicActionStepStatus::Error {
        let message = step
            .message
            .as_deref()
            .unwrap_or("This broadcaster submission step failed.");
        let copy_id = SharedString::from(format!(
            "wallet-private-broadcaster-{}-error-copy",
            private_broadcaster_stage_id(step.stage),
        ));
        body = body.child(
            div()
                .flex()
                .items_start()
                .gap_1()
                .child(
                    app_muted_text(message.to_string())
                        .flex_1()
                        .min_w(px(0.0))
                        .whitespace_normal()
                        .text_color(rgb(theme::DANGER))
                        .line_height(gpui::relative(1.0)),
                )
                .child(clipboard_with_toast(copy_id, message.to_string())),
        );
    } else {
        let detail = private_broadcaster_step_detail(progress, step, Instant::now());
        body = body.child(
            app_muted_text(detail)
                .text_color(rgb(color))
                .line_height(gpui::relative(1.0)),
        );
    }
    if let Some(action) = render_self_broadcast_step_action(root, progress, step) {
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

fn render_self_broadcast_step_action(
    root: Entity<WalletRoot>,
    progress: &PrivateBroadcasterProgressState,
    step: &PrivateBroadcasterProgressStepState,
) -> Option<gpui::AnyElement> {
    if progress.flow != PrivateSubmissionProgressFlow::SelfBroadcast
        || progress.self_broadcast_command_tx.is_none()
        || progress.stopped
        || progress.error.is_some()
        || progress.self_broadcast_result.is_some()
    {
        return None;
    }
    let retry_kind = match (step.stage, step.status) {
        (
            TransactionGenerationStage::EstimatingSelfBroadcastGas
            | TransactionGenerationStage::SigningSelfBroadcast,
            PublicActionStepStatus::Error,
        ) => SelfBroadcastGasRetryKind::RetryEstimate,
        (
            TransactionGenerationStage::WaitingForSelfBroadcastReceipt,
            PublicActionStepStatus::Pending,
        ) if !progress.self_broadcast_attempts.is_empty() => SelfBroadcastGasRetryKind::SpeedUp,
        _ => return None,
    };
    let label = match retry_kind {
        SelfBroadcastGasRetryKind::RetryEstimate => "Retry with custom gas",
        SelfBroadcastGasRetryKind::SpeedUp => "Speed up transaction",
    };
    let key = progress.key;
    let kind = progress.kind;
    let generation_id = progress.generation_id;
    let mut action = div()
        .pt(px(4.0))
        .flex()
        .flex_col()
        .items_start()
        .gap_1()
        .child(
            app_button(
                delivery_element_id(key, kind, private_broadcaster_retry_button_id(retry_kind)),
                label,
            )
            .small()
            .outline()
            .on_click(move |_event, window, cx| {
                root.update(cx, |root, cx| {
                    root.open_self_broadcast_gas_retry_dialog(
                        kind,
                        key,
                        generation_id,
                        retry_kind,
                        window,
                        cx,
                    );
                });
            }),
        );
    if let Some(error) = progress.self_broadcast_action_error.as_deref() {
        action = action.child(
            app_muted_text(format!("Last retry failed: {error}"))
                .text_color(rgb(theme::DANGER))
                .whitespace_normal(),
        );
    }
    Some(action.into_any_element())
}

const fn private_broadcaster_retry_button_id(kind: SelfBroadcastGasRetryKind) -> &'static str {
    match kind {
        SelfBroadcastGasRetryKind::RetryEstimate => "retry-self-gas",
        SelfBroadcastGasRetryKind::SpeedUp => "speed-up-self-tx",
    }
}

fn private_broadcaster_step_detail(
    progress: &PrivateBroadcasterProgressState,
    step: &PrivateBroadcasterProgressStepState,
    now: Instant,
) -> String {
    if step.status == PublicActionStepStatus::Pending
        && progress.flow == PrivateSubmissionProgressFlow::PublicBroadcaster
        && step.stage == TransactionGenerationStage::WaitingForBroadcasterResponse
        && let Some(detail) = public_broadcaster_wait_status_detail(progress, now)
    {
        return detail;
    }
    private_broadcaster_stage_detail(step.stage, step.status).to_string()
}

pub(super) fn public_broadcaster_wait_status_detail(
    progress: &PrivateBroadcasterProgressState,
    now: Instant,
) -> Option<String> {
    let resend_count = public_broadcaster_resend_count(progress, now)?;
    if resend_count == 0 {
        return Some("Waiting for broadcaster response".to_string());
    }
    let Some(remaining) = public_broadcaster_wait_time_left(progress, now) else {
        return Some(format!("Still waiting - re-sent {resend_count}x"));
    };
    Some(format!(
        "Still waiting - re-sent {resend_count}x - {} left",
        format_public_broadcaster_wait_remaining(remaining)
    ))
}

fn public_broadcaster_resend_count(
    progress: &PrivateBroadcasterProgressState,
    now: Instant,
) -> Option<usize> {
    if progress.flow != PrivateSubmissionProgressFlow::PublicBroadcaster {
        return None;
    }
    let started_at = progress.public_broadcaster_wait_started_at?;
    let republish_interval = progress.public_broadcaster_republish_interval?;
    if republish_interval.is_zero() {
        return None;
    }
    let elapsed = now.saturating_duration_since(started_at);
    let count = elapsed.as_nanos() / republish_interval.as_nanos();
    Some(count.min(usize::MAX as u128) as usize)
}

fn public_broadcaster_wait_time_left(
    progress: &PrivateBroadcasterProgressState,
    now: Instant,
) -> Option<Duration> {
    let started_at = progress.public_broadcaster_wait_started_at?;
    let timeout = progress.public_broadcaster_response_timeout?;
    let elapsed = now.saturating_duration_since(started_at);
    Some(timeout.saturating_sub(elapsed))
}

pub(super) fn format_public_broadcaster_wait_remaining(duration: Duration) -> String {
    let total_secs = duration.as_secs();
    let seconds = total_secs % 60;
    let total_minutes = total_secs / 60;
    if total_minutes < 60 {
        format!("{total_minutes}:{seconds:02}")
    } else {
        let minutes = total_minutes % 60;
        let hours = total_minutes / 60;
        format!("{hours}:{minutes:02}:{seconds:02}")
    }
}

const fn private_broadcaster_stage_detail(
    stage: TransactionGenerationStage,
    status: PublicActionStepStatus,
) -> &'static str {
    match status {
        PublicActionStepStatus::NotStarted => match stage {
            TransactionGenerationStage::SelectingPrivateNotes => "Waiting to select private notes.",
            TransactionGenerationStage::ProvingTransaction => "Waiting to generate the proof.",
            TransactionGenerationStage::EstimatingBroadcasterFee => {
                "Waiting to settle the transaction fee."
            }
            TransactionGenerationStage::GeneratingPoiProofs => "Waiting to generate POI proofs.",
            TransactionGenerationStage::PublishingToBroadcaster => {
                "Waiting to publish the encrypted request."
            }
            TransactionGenerationStage::WaitingForBroadcasterResponse => {
                "Waiting to listen for broadcaster response."
            }
            TransactionGenerationStage::EstimatingSelfBroadcastGas => "Waiting to estimate gas.",
            TransactionGenerationStage::SigningSelfBroadcast => "Waiting to sign transaction.",
            TransactionGenerationStage::WaitingForSelfBroadcastReceipt => {
                "Waiting for self-broadcast receipt."
            }
        },
        PublicActionStepStatus::Pending => stage.detail(),
        PublicActionStepStatus::Done => "Complete.",
        PublicActionStepStatus::Error => "Failed.",
        PublicActionStepStatus::Stopped => {
            "Stopped locally. Already-submitted network work may continue."
        }
    }
}

const fn private_broadcaster_stage_id(stage: TransactionGenerationStage) -> &'static str {
    match stage {
        TransactionGenerationStage::SelectingPrivateNotes => "select-notes",
        TransactionGenerationStage::ProvingTransaction => "prove",
        TransactionGenerationStage::EstimatingBroadcasterFee => "estimate-fee",
        TransactionGenerationStage::GeneratingPoiProofs => "poi-proofs",
        TransactionGenerationStage::PublishingToBroadcaster => "publish",
        TransactionGenerationStage::WaitingForBroadcasterResponse => "wait-response",
        TransactionGenerationStage::EstimatingSelfBroadcastGas => "estimate-self-gas",
        TransactionGenerationStage::SigningSelfBroadcast => "sign-self-broadcast",
        TransactionGenerationStage::WaitingForSelfBroadcastReceipt => "wait-self-receipt",
    }
}

pub(super) fn render_private_broadcaster_status_notice(
    root: Entity<WalletRoot>,
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    result: &PublicBroadcasterResultKind,
) -> gpui::Div {
    let (title, detail, border) = match result {
        PublicBroadcasterResultKind::Submitted { .. } => (
            "Submitted via public broadcaster",
            "Open the broadcaster status dialog for the transaction details.",
            theme::SUCCESS,
        ),
        PublicBroadcasterResultKind::Failed { .. } => (
            "Public broadcaster failed",
            "Open the broadcaster status dialog for the returned error.",
            theme::DANGER,
        ),
        PublicBroadcasterResultKind::TimedOut => (
            "Public broadcaster timed out",
            "Open the broadcaster status dialog for the timeout details.",
            theme::WARNING,
        ),
    };
    render_private_broadcaster_status_notice_box(root, key, kind, title, detail, border)
}

pub(super) fn render_private_self_broadcast_status_notice(
    root: Entity<WalletRoot>,
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    result: &DesktopSelfBroadcastResult,
) -> gpui::Div {
    let (title, detail, border) = if result.tx.status {
        (
            "Self-broadcast confirmed",
            "Open the self-broadcast status dialog for transaction details.",
            theme::SUCCESS,
        )
    } else {
        (
            "Self-broadcast reverted",
            "Open the self-broadcast status dialog for receipt details.",
            theme::DANGER,
        )
    };
    render_private_broadcaster_status_notice_box(root, key, kind, title, detail, border)
}

pub(super) fn render_private_submission_active_status_notice(
    root: Entity<WalletRoot>,
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    flow: PrivateSubmissionProgressFlow,
    stage: TransactionGenerationStage,
) -> gpui::Div {
    let title = match flow {
        PrivateSubmissionProgressFlow::PublicBroadcaster => "Public broadcaster in progress",
        PrivateSubmissionProgressFlow::SelfBroadcast => "Self-broadcast in progress",
    };
    render_private_broadcaster_status_notice_box(
        root,
        key,
        kind,
        title,
        format!("{}: {}", stage.label(), stage.detail()),
        theme::INFO,
    )
}

fn render_private_broadcaster_status_notice_box(
    root: Entity<WalletRoot>,
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    title: impl Into<SharedString>,
    detail: impl Into<SharedString>,
    border: u32,
) -> gpui::Div {
    let button_root = root;
    div()
        .flex()
        .items_center()
        .justify_between()
        .gap_3()
        .p(px(10.0))
        .rounded_md()
        .bg(rgb(theme::SURFACE_ELEVATED))
        .border_1()
        .border_color(rgb(border))
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
                delivery_element_id(key, kind, "view-broadcaster-progress"),
                "View status",
            )
            .outline()
            .small()
            .on_click(move |_event, window, cx| {
                button_root.update(cx, |root, cx| {
                    root.show_private_broadcaster_progress_dialog(window, cx);
                });
            }),
        )
}
