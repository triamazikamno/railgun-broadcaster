use super::{
    PublicActionGasRetryKind, PublicActionMode, PublicActionProgressStep, PublicActionStepStatus,
    PublicAssetId, STOPPED_PROGRESS_MESSAGE, SharedString,
};

pub(in crate::root) const fn public_action_step_label(
    step: PublicActionProgressStep,
) -> &'static str {
    match step {
        PublicActionProgressStep::Send => "Send",
        PublicActionProgressStep::Wrap => "Wrap",
        PublicActionProgressStep::Approve => "Approve",
        PublicActionProgressStep::Shield => "Shield",
    }
}

pub(in crate::root) const fn public_action_step_detail(
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

pub(in crate::root) fn public_action_error_summary(
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

pub(in crate::root) fn public_action_error_details(
    summary: &str,
    details: Option<&str>,
) -> Option<String> {
    let details = details?.trim();
    if details.is_empty() || details == summary {
        None
    } else {
        Some(details.to_string())
    }
}

pub(in crate::root) fn public_action_error_copy_value(
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

pub(in crate::root) const fn public_action_step_id(step: PublicActionProgressStep) -> &'static str {
    match step {
        PublicActionProgressStep::Send => "send",
        PublicActionProgressStep::Wrap => "wrap",
        PublicActionProgressStep::Approve => "approve",
        PublicActionProgressStep::Shield => "shield",
    }
}

pub(in crate::root) fn public_action_retry_button_id(
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

pub(in crate::root) fn public_action_progress_steps(
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
