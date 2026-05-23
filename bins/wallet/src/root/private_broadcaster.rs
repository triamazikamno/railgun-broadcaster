use std::path::PathBuf;
use std::sync::Arc;

use gpui::{
    AppContext, Context, Entity, ParentElement, Pixels, SharedString, Styled, Window, div, px, rgb,
};
use gpui_component::{Sizable, WindowExt};
use ui::clipboard::clipboard_with_toast;
use ui::controls::{app_button, app_muted_text, app_strong_text};
use ui::theme;
use wallet_ops::{
    PublicBroadcasterCostEstimate, PublicBroadcasterResultKind, PublicBroadcasterSubmissionResult,
    TransactionGenerationStage,
};

use super::broadcaster_picker::broadcaster_candidate_label;
use super::dialogs::PrivateBroadcasterProgressDialogContent;
use super::private_action::{delivery_element_id, private_action_title_row};
use super::public_action::{
    PublicActionStepStatus, public_action_step_color, render_public_action_step_marker,
};
use super::public_broadcaster_cost::{
    PrivateBroadcasterProgressContext, PublicBroadcasterCostDisplay, cost_estimate_detail_text,
    private_broadcaster_context_row, render_private_broadcaster_progress_context,
    render_public_broadcaster_tx_hash_row,
};
use super::{
    DeliveryFormKind, PRIVATE_BROADCASTER_PROGRESS_DIALOG_WIDTH, UnshieldAssetKey, WalletRoot,
    secondary_dialog_content_width,
};

const PRIVATE_BROADCASTER_PROGRESS_STAGES: [TransactionGenerationStage; 6] = [
    TransactionGenerationStage::SelectingPrivateNotes,
    TransactionGenerationStage::ProvingTransaction,
    TransactionGenerationStage::EstimatingBroadcasterFee,
    TransactionGenerationStage::GeneratingPoiProofs,
    TransactionGenerationStage::PublishingToBroadcaster,
    TransactionGenerationStage::WaitingForBroadcasterResponse,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PrivateBroadcasterProgressStepState {
    pub(super) stage: TransactionGenerationStage,
    pub(super) status: PublicActionStepStatus,
    pub(super) message: Option<Arc<str>>,
}

pub(super) struct PrivateBroadcasterProgressState {
    pub(super) kind: DeliveryFormKind,
    pub(super) key: UnshieldAssetKey,
    pub(super) generation_id: u64,
    pub(super) asset_label: Arc<str>,
    pub(super) icon_path: Option<PathBuf>,
    pub(super) recipient: Arc<str>,
    pub(super) steps: Vec<PrivateBroadcasterProgressStepState>,
    pub(super) estimate: Option<PublicBroadcasterCostEstimate>,
    pub(super) result: Option<PublicBroadcasterSubmissionResult>,
    pub(super) error: Option<Arc<str>>,
    pub(super) dialog_open: bool,
    pub(super) stage_seen: bool,
}

pub(super) const fn private_broadcaster_dialog_title_action(
    kind: DeliveryFormKind,
) -> &'static str {
    match kind {
        DeliveryFormKind::Send => "Send via broadcaster",
        DeliveryFormKind::Unshield => "Unshield via broadcaster",
    }
}

pub(super) fn private_broadcaster_progress_steps() -> Vec<PrivateBroadcasterProgressStepState> {
    PRIVATE_BROADCASTER_PROGRESS_STAGES
        .into_iter()
        .enumerate()
        .map(|(index, stage)| PrivateBroadcasterProgressStepState {
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

pub(super) fn private_broadcaster_closed_active_stage(
    progress: Option<&PrivateBroadcasterProgressState>,
    kind: DeliveryFormKind,
    key: UnshieldAssetKey,
    generation_id: u64,
) -> Option<TransactionGenerationStage> {
    let progress = progress?;
    if progress.kind != kind
        || progress.key != key
        || progress.generation_id != generation_id
        || progress.dialog_open
        || !progress.stage_seen
        || progress.result.is_some()
        || progress.error.is_some()
    {
        return None;
    }
    progress
        .steps
        .iter()
        .find(|step| step.status == PublicActionStepStatus::Pending)
        .map(|step| step.stage)
}

impl WalletRoot {
    pub(super) fn start_private_broadcaster_progress(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        generation_id: u64,
        asset_label: String,
        icon_path: Option<PathBuf>,
        recipient: String,
        estimate: Option<PublicBroadcasterCostEstimate>,
    ) {
        let asset_label = Arc::<str>::from(asset_label);
        let dialog_open = self
            .private_broadcaster_progress
            .as_ref()
            .is_some_and(|progress| progress.dialog_open);
        self.private_broadcaster_progress = Some(PrivateBroadcasterProgressState {
            kind,
            key,
            generation_id,
            asset_label: Arc::clone(&asset_label),
            icon_path,
            recipient: Arc::from(recipient),
            steps: private_broadcaster_progress_steps(),
            estimate,
            result: None,
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
        let kind = progress.kind;
        let key = progress.key;
        let generation_id = progress.generation_id;
        let asset_label = Arc::clone(&progress.asset_label);
        let icon_path = progress.icon_path.clone();
        let content_root = cx.entity();
        let dialog_width =
            (window.viewport_size().width * 0.92).min(PRIVATE_BROADCASTER_PROGRESS_DIALOG_WIDTH);
        let content_width = secondary_dialog_content_width(dialog_width);
        let content = cx.new(|cx| {
            PrivateBroadcasterProgressDialogContent::new(content_root, content_width, cx)
        });
        let close_root = cx.entity();
        window.open_dialog(cx, move |dialog, _window, _cx| {
            let close_root = close_root.clone();
            dialog
                .w(dialog_width)
                .title(private_action_title_row(
                    private_broadcaster_dialog_title_action(kind),
                    asset_label.as_ref(),
                    icon_path.clone(),
                ))
                .on_close(move |_event, _window, cx| {
                    close_root.update(cx, |root, cx| {
                        if let Some(progress) = root.private_broadcaster_progress.as_mut()
                            && progress.kind == kind
                            && progress.key == key
                            && progress.generation_id == generation_id
                        {
                            progress.dialog_open = false;
                            cx.notify();
                        }
                    });
                })
                .child(content.clone())
        });
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
        if progress.kind != kind
            || progress.key != key
            || progress.generation_id != generation_id
            || progress.result.is_some()
            || progress.error.is_some()
        {
            return false;
        }
        let should_open_dialog = !progress.stage_seen && !progress.dialog_open;
        progress.stage_seen = true;
        apply_private_broadcaster_progress_stage(&mut progress.steps, stage);
        cx.notify();
        should_open_dialog
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
        if progress.kind != kind
            || progress.key != key
            || progress.generation_id != generation_id
            || progress.result.is_some()
            || progress.error.is_some()
        {
            return;
        }
        finish_private_broadcaster_progress_steps_at_stage(
            &mut progress.steps,
            final_stage,
            &result.result,
        );
        progress.result = Some(result);
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
        if progress.kind != kind
            || progress.key != key
            || progress.generation_id != generation_id
            || progress.result.is_some()
            || progress.error.is_some()
        {
            return;
        }
        fail_private_broadcaster_progress_steps_at_stage(
            &mut progress.steps,
            final_stage,
            message.as_str(),
        );
        progress.error = Some(Arc::from(message));
        cx.notify();
    }

    pub(super) fn render_private_broadcaster_progress_dialog_content(
        &self,
        content_width: Pixels,
    ) -> gpui::Div {
        let Some(progress) = self.private_broadcaster_progress.as_ref() else {
            return div()
                .w(content_width)
                .child(app_muted_text("No active broadcaster submission."));
        };
        let (title, detail, color) = private_broadcaster_progress_summary(progress);
        let mut content = div()
            .w(content_width)
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(app_strong_text(title).text_color(rgb(color)))
                    .child(app_muted_text(detail).whitespace_normal()),
            )
            .child(render_private_broadcaster_progress_stepper(&progress.steps));

        if let Some(context) = self.private_broadcaster_progress_context(progress) {
            content = content.child(render_private_broadcaster_progress_context(
                progress, &context,
            ));
        } else {
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
                        "Fee and gas cost will appear after the broadcaster fee is calculated.",
                    )),
            );
        }

        if let Some(result) = progress.result.as_ref()
            && let PublicBroadcasterResultKind::Submitted { tx_hash } = &result.result
        {
            content = content.child(render_public_broadcaster_tx_hash_row(
                tx_hash.clone(),
                delivery_element_id(progress.key, progress.kind, "progress-copy-public-tx"),
            ));
        }
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
}

pub(super) fn apply_private_broadcaster_progress_stage(
    steps: &mut [PrivateBroadcasterProgressStepState],
    stage: TransactionGenerationStage,
) {
    let active_index = private_broadcaster_progress_stage_index(stage);
    for (index, step) in steps.iter_mut().enumerate() {
        step.status = match index.cmp(&active_index) {
            std::cmp::Ordering::Less => PublicActionStepStatus::Done,
            std::cmp::Ordering::Equal => PublicActionStepStatus::Pending,
            std::cmp::Ordering::Greater => PublicActionStepStatus::NotStarted,
        };
        step.message = None;
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

const fn private_broadcaster_progress_stage_index(stage: TransactionGenerationStage) -> usize {
    match stage {
        TransactionGenerationStage::SelectingPrivateNotes => 0,
        TransactionGenerationStage::ProvingTransaction => 1,
        TransactionGenerationStage::EstimatingBroadcasterFee => 2,
        TransactionGenerationStage::GeneratingPoiProofs => 3,
        TransactionGenerationStage::PublishingToBroadcaster => 4,
        TransactionGenerationStage::WaitingForBroadcasterResponse => 5,
    }
}

pub(super) fn private_broadcaster_progress_summary(
    progress: &PrivateBroadcasterProgressState,
) -> (&'static str, String, u32) {
    if let Some(result) = progress.result.as_ref() {
        return match &result.result {
            PublicBroadcasterResultKind::Submitted { .. } => (
                "Submitted via public broadcaster",
                format!(
                    "{} accepted the private {} request.",
                    broadcaster_candidate_label(&result.broadcaster),
                    private_broadcaster_action_noun(progress.kind),
                ),
                theme::SUCCESS,
            ),
            PublicBroadcasterResultKind::Failed { error } => {
                ("Public broadcaster failed", error.clone(), theme::DANGER)
            }
            PublicBroadcasterResultKind::TimedOut => (
                "Public broadcaster timed out",
                "No decryptable broadcaster response arrived before the timeout.".to_string(),
                theme::WARNING,
            ),
        };
    }
    if let Some(error) = progress.error.as_ref() {
        return ("Submission failed", error.to_string(), theme::DANGER);
    }
    (
        "Submitting via public broadcaster",
        format!(
            "Preparing and publishing a private {} for {}.",
            private_broadcaster_action_noun(progress.kind),
            progress.asset_label.as_ref()
        ),
        theme::INFO,
    )
}

const fn private_broadcaster_action_noun(kind: DeliveryFormKind) -> &'static str {
    match kind {
        DeliveryFormKind::Send => "send",
        DeliveryFormKind::Unshield => "unshield",
    }
}

pub(super) fn render_private_broadcaster_progress_stepper(
    steps: &[PrivateBroadcasterProgressStepState],
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
        stepper = stepper.child(render_private_broadcaster_progress_step(
            step,
            index == last_index,
        ));
    }
    stepper
}

fn render_private_broadcaster_progress_step(
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
        body = body.child(
            app_muted_text(private_broadcaster_stage_detail(step.stage, step.status))
                .text_color(rgb(color))
                .line_height(gpui::relative(1.0)),
        );
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

const fn private_broadcaster_stage_detail(
    stage: TransactionGenerationStage,
    status: PublicActionStepStatus,
) -> &'static str {
    match status {
        PublicActionStepStatus::NotStarted => match stage {
            TransactionGenerationStage::SelectingPrivateNotes => "Waiting to select private notes.",
            TransactionGenerationStage::ProvingTransaction => "Waiting to generate the proof.",
            TransactionGenerationStage::EstimatingBroadcasterFee => {
                "Waiting to settle the broadcaster fee."
            }
            TransactionGenerationStage::GeneratingPoiProofs => "Waiting to generate POI proofs.",
            TransactionGenerationStage::PublishingToBroadcaster => {
                "Waiting to publish the encrypted request."
            }
            TransactionGenerationStage::WaitingForBroadcasterResponse => {
                "Waiting to listen for broadcaster response."
            }
        },
        PublicActionStepStatus::Pending => stage.detail(),
        PublicActionStepStatus::Done => "Complete.",
        PublicActionStepStatus::Error => "Failed.",
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

pub(super) fn render_private_broadcaster_active_status_notice(
    root: Entity<WalletRoot>,
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    stage: TransactionGenerationStage,
) -> gpui::Div {
    render_private_broadcaster_status_notice_box(
        root,
        key,
        kind,
        "Public broadcaster in progress",
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
