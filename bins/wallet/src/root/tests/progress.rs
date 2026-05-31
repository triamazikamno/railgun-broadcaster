use super::*;
use crate::root::public_action::{
    PublicActionGasRetryKind, public_action_discard_attempt_available,
    public_action_error_retry_kind, public_action_step_detail_for_context,
};
use wallet_ops::{DesktopSelfBroadcastResult, SelfBroadcastAttemptInfo, TxReceiptOutput};

#[test]
fn private_broadcaster_progress_stage_marks_prior_steps_done() {
    let mut steps = private_broadcaster_progress_steps();

    apply_private_broadcaster_progress_stage(
        &mut steps,
        TransactionGenerationStage::EstimatingBroadcasterFee,
    );

    let statuses = steps.iter().map(|step| step.status).collect::<Vec<_>>();
    assert_eq!(
        statuses,
        vec![
            PublicActionStepStatus::Done,
            PublicActionStepStatus::Done,
            PublicActionStepStatus::Pending,
            PublicActionStepStatus::NotStarted,
            PublicActionStepStatus::NotStarted,
            PublicActionStepStatus::NotStarted,
        ]
    );
}

#[test]
fn private_broadcaster_progress_submitted_marks_all_steps_done() {
    let mut steps = private_broadcaster_progress_steps();
    apply_private_broadcaster_progress_stage(
        &mut steps,
        TransactionGenerationStage::WaitingForBroadcasterResponse,
    );

    finish_private_broadcaster_progress_steps(
        &mut steps,
        &PublicBroadcasterResultKind::Submitted {
            tx_hash: "0xabc".to_string(),
        },
    );

    assert!(
        steps
            .iter()
            .all(|step| step.status == PublicActionStepStatus::Done)
    );
}

#[test]
fn private_broadcaster_progress_timeout_marks_waiting_step_error() {
    let mut steps = private_broadcaster_progress_steps();
    apply_private_broadcaster_progress_stage(
        &mut steps,
        TransactionGenerationStage::WaitingForBroadcasterResponse,
    );

    finish_private_broadcaster_progress_steps(&mut steps, &PublicBroadcasterResultKind::TimedOut);

    assert_eq!(
        steps.last().map(|step| step.status),
        Some(PublicActionStepStatus::Error)
    );
    assert!(
        steps
            .last()
            .and_then(|step| step.message.as_ref())
            .is_some()
    );
}

#[test]
fn private_broadcaster_terminal_failure_applies_latest_stage() {
    let mut steps = private_broadcaster_progress_steps();

    fail_private_broadcaster_progress_steps_at_stage(
        &mut steps,
        TransactionGenerationStage::PublishingToBroadcaster,
        "publish failed",
    );

    let statuses = steps.iter().map(|step| step.status).collect::<Vec<_>>();
    assert_eq!(
        statuses,
        vec![
            PublicActionStepStatus::Done,
            PublicActionStepStatus::Done,
            PublicActionStepStatus::Done,
            PublicActionStepStatus::Done,
            PublicActionStepStatus::Error,
            PublicActionStepStatus::NotStarted,
        ]
    );
    assert_eq!(steps[4].message.as_deref(), Some("publish failed"));
}

#[test]
fn private_broadcaster_terminal_result_applies_latest_stage_before_timeout() {
    let mut steps = private_broadcaster_progress_steps();

    finish_private_broadcaster_progress_steps_at_stage(
        &mut steps,
        TransactionGenerationStage::WaitingForBroadcasterResponse,
        &PublicBroadcasterResultKind::TimedOut,
    );

    assert_eq!(
        steps.last().map(|step| step.status),
        Some(PublicActionStepStatus::Error)
    );
    assert!(
        steps[..steps.len() - 1]
            .iter()
            .all(|step| step.status == PublicActionStepStatus::Done)
    );
}

#[test]
fn self_broadcast_progress_stage_sequence_tracks_direct_submission() {
    let mut steps = self_broadcast_progress_steps(DeliveryFormKind::Send);

    assert_eq!(
        steps.iter().map(|step| step.stage).collect::<Vec<_>>(),
        vec![
            TransactionGenerationStage::SelectingPrivateNotes,
            TransactionGenerationStage::ProvingTransaction,
            TransactionGenerationStage::GeneratingPoiProofs,
            TransactionGenerationStage::EstimatingSelfBroadcastGas,
            TransactionGenerationStage::SigningSelfBroadcast,
            TransactionGenerationStage::WaitingForSelfBroadcastReceipt,
        ]
    );

    apply_private_broadcaster_progress_stage(
        &mut steps,
        TransactionGenerationStage::SigningSelfBroadcast,
    );
    let statuses = steps.iter().map(|step| step.status).collect::<Vec<_>>();
    assert_eq!(
        statuses,
        vec![
            PublicActionStepStatus::Done,
            PublicActionStepStatus::Done,
            PublicActionStepStatus::Done,
            PublicActionStepStatus::Done,
            PublicActionStepStatus::Pending,
            PublicActionStepStatus::NotStarted,
        ]
    );
}

#[test]
fn self_broadcast_unshield_progress_omits_poi_until_requested() {
    let mut steps = self_broadcast_progress_steps(DeliveryFormKind::Unshield);

    assert_eq!(
        steps.iter().map(|step| step.stage).collect::<Vec<_>>(),
        vec![
            TransactionGenerationStage::SelectingPrivateNotes,
            TransactionGenerationStage::ProvingTransaction,
            TransactionGenerationStage::EstimatingSelfBroadcastGas,
            TransactionGenerationStage::SigningSelfBroadcast,
            TransactionGenerationStage::WaitingForSelfBroadcastReceipt,
        ]
    );

    apply_private_broadcaster_progress_stage(
        &mut steps,
        TransactionGenerationStage::EstimatingSelfBroadcastGas,
    );
    assert!(
        !steps
            .iter()
            .any(|step| step.stage == TransactionGenerationStage::GeneratingPoiProofs)
    );
    ensure_self_broadcast_unshield_progress_stage(
        &mut steps,
        TransactionGenerationStage::GeneratingPoiProofs,
    );
    assert_eq!(steps[2].status, PublicActionStepStatus::Done);

    let mut steps = self_broadcast_progress_steps(DeliveryFormKind::Unshield);
    ensure_self_broadcast_unshield_progress_stage(
        &mut steps,
        TransactionGenerationStage::GeneratingPoiProofs,
    );
    apply_private_broadcaster_progress_stage(
        &mut steps,
        TransactionGenerationStage::GeneratingPoiProofs,
    );
    assert_eq!(
        steps.iter().map(|step| step.stage).collect::<Vec<_>>(),
        vec![
            TransactionGenerationStage::SelectingPrivateNotes,
            TransactionGenerationStage::ProvingTransaction,
            TransactionGenerationStage::GeneratingPoiProofs,
            TransactionGenerationStage::EstimatingSelfBroadcastGas,
            TransactionGenerationStage::SigningSelfBroadcast,
            TransactionGenerationStage::WaitingForSelfBroadcastReceipt,
        ]
    );
    assert_eq!(steps[2].status, PublicActionStepStatus::Pending);
}

#[test]
fn self_broadcast_reverted_receipt_marks_receipt_step_error() {
    let mut steps = self_broadcast_progress_steps(DeliveryFormKind::Send);

    finish_private_self_broadcast_progress_steps_at_stage(
        &mut steps,
        TransactionGenerationStage::WaitingForSelfBroadcastReceipt,
        false,
    );

    assert_eq!(
        steps.last().map(|step| step.status),
        Some(PublicActionStepStatus::Error)
    );
    assert!(
        steps[..steps.len() - 1]
            .iter()
            .all(|step| step.status == PublicActionStepStatus::Done)
    );
    assert_eq!(
        steps.last().and_then(|step| step.message.as_deref()),
        Some("Transaction receipt indicates the self-broadcast transaction reverted.")
    );
}

#[test]
fn stopped_progress_status_uses_danger_stop_marker_and_copy() {
    assert_eq!(
        public_action_step_color(PublicActionStepStatus::Stopped),
        ui::theme::DANGER,
    );
    assert!(public_action_step_uses_stop_marker(
        PublicActionStepStatus::Stopped
    ));
    assert_eq!(
        public_action_step_detail(
            PublicActionProgressStep::Send,
            PublicActionStepStatus::Stopped,
        ),
        "Stopped locally. Already-submitted network work may continue.",
    );
    assert_eq!(
        public_action_step_detail_for_context(
            PublicActionProgressStep::ShieldKey,
            PublicActionStepStatus::Pending,
            true,
            false,
        ),
        "Approve the RAILGUN_SHIELD message on your hardware wallet.",
    );
    assert_eq!(
        public_action_step_detail_for_context(
            PublicActionProgressStep::Approve,
            PublicActionStepStatus::Pending,
            true,
            false,
        ),
        "Approve the transaction on your hardware wallet, then wait for broadcast.",
    );
}

#[test]
fn public_action_failed_step_retry_kind_distinguishes_gas_from_signing_cancel() {
    let gas_error = PublicActionStepState {
        step: PublicActionProgressStep::Wrap,
        status: PublicActionStepStatus::Error,
        tx_hash: None,
        message: Some(Arc::from("public-shield-wrap: estimate gas failed")),
    };
    let signing_cancel = PublicActionStepState {
        step: PublicActionProgressStep::Wrap,
        status: PublicActionStepStatus::Error,
        tx_hash: None,
        message: Some(Arc::from(
            "public-shield-wrap: hardware sign: Failure_ActionCancelled",
        )),
    };

    assert_eq!(
        public_action_error_retry_kind(&gas_error),
        PublicActionGasRetryKind::RetryEstimate,
    );
    assert_eq!(
        public_action_error_retry_kind(&signing_cancel),
        PublicActionGasRetryKind::RetryStep,
    );
    assert_eq!(
        public_action_error_summary(
            PublicActionProgressStep::Wrap,
            signing_cancel.message.as_deref(),
            "ETH",
        ),
        "Wrapping ETH was cancelled on the hardware wallet.",
    );
}

#[test]
fn public_action_discard_attempt_only_shows_for_active_failed_steps() {
    let failed = PublicActionStepState {
        step: PublicActionProgressStep::Wrap,
        status: PublicActionStepStatus::Error,
        tx_hash: None,
        message: Some(Arc::from("cancelled")),
    };
    let pending = PublicActionStepState {
        status: PublicActionStepStatus::Pending,
        ..failed.clone()
    };

    assert!(public_action_discard_attempt_available(true, &failed));
    assert!(!public_action_discard_attempt_available(false, &failed));
    assert!(!public_action_discard_attempt_available(true, &pending));
}

#[test]
fn progress_dialog_close_behavior_distinguishes_success_from_failure_and_stop() {
    let success_steps = vec![PublicActionStepState {
        step: PublicActionProgressStep::Send,
        status: PublicActionStepStatus::Done,
        tx_hash: Some(Arc::from("0xabc")),
        message: None,
    }];
    let failed_steps = vec![PublicActionStepState {
        status: PublicActionStepStatus::Error,
        message: Some(Arc::from("failed")),
        ..success_steps[0].clone()
    }];

    assert!(public_action_progress_is_successful(&success_steps));
    assert!(!public_action_progress_is_successful(&failed_steps));
    assert_eq!(
        progress_dialog_close_behavior(true, false),
        ProgressDialogCloseBehavior::AllAndClear,
    );
    assert_eq!(
        progress_dialog_close_behavior(false, true),
        ProgressDialogCloseBehavior::TopAndClear,
    );
    assert_eq!(
        progress_dialog_close_behavior(false, false),
        ProgressDialogCloseBehavior::TopOnly,
    );
}

#[test]
fn stopped_active_step_selection_prefers_pending_error_then_latest_not_started() {
    let mut steps = vec![
        PublicActionStepState {
            step: PublicActionProgressStep::Wrap,
            status: PublicActionStepStatus::Error,
            tx_hash: None,
            message: None,
        },
        PublicActionStepState {
            step: PublicActionProgressStep::Approve,
            status: PublicActionStepStatus::Pending,
            tx_hash: None,
            message: None,
        },
        PublicActionStepState {
            step: PublicActionProgressStep::Shield,
            status: PublicActionStepStatus::NotStarted,
            tx_hash: None,
            message: None,
        },
    ];
    assert!(mark_public_action_active_step_stopped(&mut steps));
    assert_eq!(steps[1].status, PublicActionStepStatus::Stopped);

    let mut steps = vec![
        PublicActionStepState {
            step: PublicActionProgressStep::Approve,
            status: PublicActionStepStatus::Error,
            tx_hash: None,
            message: None,
        },
        PublicActionStepState {
            step: PublicActionProgressStep::Shield,
            status: PublicActionStepStatus::NotStarted,
            tx_hash: None,
            message: None,
        },
    ];
    assert!(mark_public_action_active_step_stopped(&mut steps));
    assert_eq!(steps[0].status, PublicActionStepStatus::Stopped);

    let mut steps = vec![
        PublicActionStepState {
            step: PublicActionProgressStep::Approve,
            status: PublicActionStepStatus::NotStarted,
            tx_hash: None,
            message: None,
        },
        PublicActionStepState {
            step: PublicActionProgressStep::Shield,
            status: PublicActionStepStatus::NotStarted,
            tx_hash: None,
            message: None,
        },
    ];
    assert!(mark_public_action_active_step_stopped(&mut steps));
    assert_eq!(steps[1].status, PublicActionStepStatus::Stopped);

    let mut private_steps = self_broadcast_progress_steps(DeliveryFormKind::Send);
    assert!(mark_private_broadcaster_active_step_stopped(
        &mut private_steps
    ));
    assert_eq!(private_steps[0].status, PublicActionStepStatus::Stopped);
}

#[test]
fn public_send_stop_footer_follows_send_handoff_boundary() {
    let steps = vec![PublicActionStepState {
        step: PublicActionProgressStep::Send,
        status: PublicActionStepStatus::Pending,
        tx_hash: None,
        message: None,
    }];

    assert_eq!(
        progress_footer_action(true, false),
        ProgressFooterAction::Stop
    );
    assert_eq!(
        public_action_progress_footer_action(true, &steps),
        ProgressFooterAction::Stop,
    );
    assert!(public_action_step_is_final_handoff(
        PublicActionMode::Send,
        PublicActionProgressStep::Send,
    ));
    assert_eq!(
        public_action_progress_footer_action(false, &steps),
        ProgressFooterAction::Close,
    );
}

#[test]
fn public_shield_stop_footer_allows_prerequisites_until_final_shield() {
    let prerequisite_attempt_steps = vec![
        PublicActionStepState {
            step: PublicActionProgressStep::Wrap,
            status: PublicActionStepStatus::Pending,
            tx_hash: Some(Arc::from("0xwrap")),
            message: None,
        },
        PublicActionStepState {
            step: PublicActionProgressStep::Approve,
            status: PublicActionStepStatus::NotStarted,
            tx_hash: None,
            message: None,
        },
        PublicActionStepState {
            step: PublicActionProgressStep::Shield,
            status: PublicActionStepStatus::NotStarted,
            tx_hash: None,
            message: None,
        },
    ];

    assert!(!public_action_step_is_final_handoff(
        PublicActionMode::Shield,
        PublicActionProgressStep::Wrap,
    ));
    assert!(!public_action_step_is_final_handoff(
        PublicActionMode::Shield,
        PublicActionProgressStep::Approve,
    ));
    assert!(public_action_step_is_final_handoff(
        PublicActionMode::Shield,
        PublicActionProgressStep::Shield,
    ));
    assert_eq!(
        public_action_progress_footer_action(true, &prerequisite_attempt_steps),
        ProgressFooterAction::Stop,
    );
    let approve_attempt_steps = vec![
        PublicActionStepState {
            step: PublicActionProgressStep::Wrap,
            status: PublicActionStepStatus::Done,
            tx_hash: Some(Arc::from("0xwrap")),
            message: None,
        },
        PublicActionStepState {
            step: PublicActionProgressStep::Approve,
            status: PublicActionStepStatus::Pending,
            tx_hash: Some(Arc::from("0xapprove")),
            message: None,
        },
        PublicActionStepState {
            step: PublicActionProgressStep::Shield,
            status: PublicActionStepStatus::NotStarted,
            tx_hash: None,
            message: None,
        },
    ];
    assert_eq!(
        public_action_progress_footer_action(true, &approve_attempt_steps),
        ProgressFooterAction::Stop,
    );
    assert_eq!(
        public_action_progress_footer_action(false, &prerequisite_attempt_steps),
        ProgressFooterAction::Close,
    );
}

#[test]
fn private_self_broadcast_stop_footer_follows_signing_handoff_boundary() {
    let key = UnshieldAssetKey::new(1, Address::from([0x11; 20]));
    let mut progress = private_progress_state(PrivateSubmissionProgressFlow::SelfBroadcast, key);

    assert!(!private_progress_stage_disables_stop(
        PrivateSubmissionProgressFlow::SelfBroadcast,
        TransactionGenerationStage::EstimatingSelfBroadcastGas,
    ));
    assert!(private_progress_stage_disables_stop(
        PrivateSubmissionProgressFlow::SelfBroadcast,
        TransactionGenerationStage::SigningSelfBroadcast,
    ));
    assert_eq!(
        private_broadcaster_progress_footer_action(&progress),
        ProgressFooterAction::Stop,
    );
    progress.stop_available = false;
    assert_eq!(
        private_broadcaster_progress_footer_action(&progress),
        ProgressFooterAction::Close,
    );
}

#[test]
fn private_public_broadcaster_stop_footer_follows_publication_boundary() {
    let key = UnshieldAssetKey::new(1, Address::from([0x11; 20]));
    let mut progress =
        private_progress_state(PrivateSubmissionProgressFlow::PublicBroadcaster, key);

    assert!(!private_progress_stage_disables_stop(
        PrivateSubmissionProgressFlow::PublicBroadcaster,
        TransactionGenerationStage::GeneratingPoiProofs,
    ));
    assert!(private_progress_stage_disables_stop(
        PrivateSubmissionProgressFlow::PublicBroadcaster,
        TransactionGenerationStage::PublishingToBroadcaster,
    ));
    assert_eq!(
        private_broadcaster_progress_footer_action(&progress),
        ProgressFooterAction::Stop,
    );
    progress.stop_available = false;
    assert_eq!(
        private_broadcaster_progress_footer_action(&progress),
        ProgressFooterAction::Close,
    );
}

#[test]
fn private_public_broadcaster_stop_footer_reopens_after_two_re_sends() {
    let key = UnshieldAssetKey::new(1, Address::from([0x11; 20]));
    let mut progress =
        private_progress_state(PrivateSubmissionProgressFlow::PublicBroadcaster, key);
    progress.stop_available = false;
    progress.public_broadcaster_wait_started_at = Some(
        std::time::Instant::now()
            .checked_sub(Duration::from_secs(6))
            .expect("started before now"),
    );

    assert_eq!(
        private_broadcaster_progress_footer_action(&progress),
        ProgressFooterAction::Close,
    );

    progress.public_broadcaster_wait_started_at = Some(
        std::time::Instant::now()
            .checked_sub(Duration::from_secs(11))
            .expect("started before now"),
    );

    assert_eq!(
        private_broadcaster_progress_footer_action(&progress),
        ProgressFooterAction::Stop,
    );
}

#[test]
fn public_broadcaster_wait_status_detail_is_concise() {
    let key = UnshieldAssetKey::new(1, Address::from([0x11; 20]));
    let mut progress =
        private_progress_state(PrivateSubmissionProgressFlow::PublicBroadcaster, key);
    let now = std::time::Instant::now();

    progress.public_broadcaster_wait_started_at = Some(now);
    assert_eq!(
        public_broadcaster_wait_status_detail(&progress, now),
        Some("Waiting for broadcaster response".to_string()),
    );

    progress.public_broadcaster_wait_started_at = Some(
        now.checked_sub(Duration::from_secs(10))
            .expect("started before now"),
    );
    assert_eq!(
        public_broadcaster_wait_status_detail(&progress, now),
        Some("Still waiting - re-sent 2x - 1:50 left".to_string()),
    );

    progress.public_broadcaster_response_timeout = None;
    assert_eq!(
        public_broadcaster_wait_status_detail(&progress, now),
        Some("Still waiting - re-sent 2x".to_string()),
    );
    assert_eq!(
        format_public_broadcaster_wait_remaining(Duration::from_secs(3661)),
        "1:01:01",
    );
}

#[test]
fn stale_progress_update_guards_reject_stopped_generations() {
    assert!(public_action_accepts_update(7, 7, false));
    assert!(!public_action_accepts_update(7, 6, false));
    assert!(!public_action_accepts_update(7, 7, true));

    let key = UnshieldAssetKey::new(1, Address::from([0x11; 20]));
    let mut progress =
        private_progress_state(PrivateSubmissionProgressFlow::PublicBroadcaster, key);
    progress.stage_seen = true;
    progress.stopped = true;

    assert_eq!(
        private_broadcaster_closed_active_stage(Some(&progress), DeliveryFormKind::Send, key, 7,),
        None,
    );
}

#[test]
fn closed_private_broadcaster_progress_exposes_active_stage() {
    let key = UnshieldAssetKey::new(1, Address::from([0x11; 20]));
    let mut progress = PrivateBroadcasterProgressState {
        flow: PrivateSubmissionProgressFlow::PublicBroadcaster,
        kind: DeliveryFormKind::Send,
        key,
        generation_id: 7,
        asset_label: Arc::from("ETH"),
        icon_path: None,
        recipient: Arc::from("0zk"),
        gas_payer: None,
        steps: private_broadcaster_progress_steps(),
        estimate: None,
        result: None,
        self_broadcast_result: None,
        self_broadcast_command_tx: None,
        self_broadcast_attempts: Vec::new(),
        self_broadcast_current_gas_fee: None,
        self_broadcast_action_error: None,
        public_broadcaster_response_timeout: Some(Duration::from_secs(120)),
        public_broadcaster_republish_interval: Some(Duration::from_secs(5)),
        public_broadcaster_wait_started_at: None,
        task_abort_handle: None,
        stop_available: true,
        stopped: false,
        error: None,
        dialog_open: false,
        stage_seen: false,
    };
    assert_eq!(
        private_broadcaster_closed_active_stage(Some(&progress), DeliveryFormKind::Send, key, 7,),
        None
    );
    apply_private_broadcaster_progress_stage(
        &mut progress.steps,
        TransactionGenerationStage::PublishingToBroadcaster,
    );
    progress.stage_seen = true;

    assert_eq!(
        private_broadcaster_closed_active_stage(Some(&progress), DeliveryFormKind::Send, key, 7,),
        Some(TransactionGenerationStage::PublishingToBroadcaster)
    );

    progress.dialog_open = true;
    assert_eq!(
        private_broadcaster_closed_active_stage(Some(&progress), DeliveryFormKind::Send, key, 7,),
        None
    );

    progress.dialog_open = false;
    progress.error = Some(Arc::from("failed"));
    assert_eq!(
        private_broadcaster_closed_active_stage(Some(&progress), DeliveryFormKind::Send, key, 7,),
        None
    );
}

#[test]
fn closed_private_broadcaster_progress_exposes_failed_step_for_discard() {
    let key = UnshieldAssetKey::new(1, Address::from([0x11; 20]));
    let mut progress = private_progress_state(PrivateSubmissionProgressFlow::SelfBroadcast, key);
    progress.stage_seen = true;
    fail_private_broadcaster_progress_steps_at_stage(
        &mut progress.steps,
        TransactionGenerationStage::SigningSelfBroadcast,
        "hardware sign: Failure_ActionCancelled",
    );

    let active =
        private_broadcaster_closed_active_progress(Some(&progress), DeliveryFormKind::Send, key, 7)
            .expect("active failed step");

    assert_eq!(active.flow, PrivateSubmissionProgressFlow::SelfBroadcast);
    assert_eq!(
        active.step.stage,
        TransactionGenerationStage::SigningSelfBroadcast
    );
    assert_eq!(active.step.status, PublicActionStepStatus::Error);
    assert!(private_submission_discard_attempt_available(&active));
}

#[test]
fn private_self_broadcast_step_retry_kind_separates_signing_from_gas_and_speed_up() {
    let key = UnshieldAssetKey::new(1, Address::from([0x11; 20]));
    let mut progress = private_progress_state(PrivateSubmissionProgressFlow::SelfBroadcast, key);
    let gas_step = PrivateBroadcasterProgressStepState {
        stage: TransactionGenerationStage::EstimatingSelfBroadcastGas,
        status: PublicActionStepStatus::Error,
        message: Some(Arc::from("gas failed")),
    };
    let signing_step = PrivateBroadcasterProgressStepState {
        stage: TransactionGenerationStage::SigningSelfBroadcast,
        status: PublicActionStepStatus::Error,
        message: Some(Arc::from("cancelled")),
    };
    let receipt_step = PrivateBroadcasterProgressStepState {
        stage: TransactionGenerationStage::WaitingForSelfBroadcastReceipt,
        status: PublicActionStepStatus::Pending,
        message: None,
    };

    assert_eq!(
        self_broadcast_step_retry_kind(&progress, &gas_step),
        Some(SelfBroadcastGasRetryKind::RetryEstimate),
    );
    assert_eq!(
        self_broadcast_step_retry_kind(&progress, &signing_step),
        Some(SelfBroadcastGasRetryKind::RetryStep),
    );
    assert_eq!(
        self_broadcast_step_retry_kind(&progress, &receipt_step),
        None
    );
    progress
        .self_broadcast_attempts
        .push(SelfBroadcastAttemptInfo {
            tx_hash: "0xabc".to_string(),
            nonce: 7,
            gas_limit: 21_000,
            max_fee_per_gas: 1,
            max_priority_fee_per_gas: 1,
        });
    assert_eq!(
        self_broadcast_step_retry_kind(&progress, &receipt_step),
        Some(SelfBroadcastGasRetryKind::SpeedUp),
    );
}

#[test]
fn private_self_broadcast_success_requires_successful_receipt() {
    let key = UnshieldAssetKey::new(1, Address::from([0x11; 20]));
    let mut progress = private_progress_state(PrivateSubmissionProgressFlow::SelfBroadcast, key);
    progress.self_broadcast_result = Some(test_self_broadcast_result(true));
    assert!(private_broadcaster_progress_is_successful(&progress));

    progress.self_broadcast_result = Some(test_self_broadcast_result(false));
    assert!(!private_broadcaster_progress_is_successful(&progress));
}

fn test_self_broadcast_result(status: bool) -> DesktopSelfBroadcastResult {
    DesktopSelfBroadcastResult {
        chain_id: 1,
        public_account_uuid: "public-account".to_string(),
        gas_payer: Address::from([0x22; 20]),
        gas_limit: 21_000,
        rpc_gas_price: 1,
        max_fee_per_gas: 2,
        max_priority_fee_per_gas: 1,
        estimated_native_gas_cost: U256::from(21_000),
        live_native_balance: U256::from(42_000),
        tx: TxReceiptOutput {
            tx_hash: "0xabc".to_string(),
            status,
            block_number: 10,
            gas_used: 21_000,
        },
        attempts: Vec::new(),
    }
}
