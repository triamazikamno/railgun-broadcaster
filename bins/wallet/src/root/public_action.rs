use std::collections::BTreeSet;
use std::sync::Arc;

use alloy::primitives::{Address, U256};
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
    vault::{DesktopVaultStore, DesktopViewSession, PublicAccountSource, PublicAccountStatus},
};
use zeroize::Zeroizing;

use super::gas_fee::{
    Eip1559GasFeeEditTarget, Eip1559GasFeeMode, Eip1559GasFeeTarget, GasRetryInputs, format_gwei,
    render_eip1559_gas_fee_editor,
};
use super::public_account::public_account_display_label;
use super::public_balances::public_asset_icon_path;
use super::spend_authorization::{
    SpendAuthorizationIntent, SpendAuthorizationSummary, SpendAuthorizationSummaryRow,
    is_spend_authorization_failure_error,
};
use super::utxo::short_hash;
use super::{
    PUBLIC_ACTION_DIALOG_WIDTH, WalletRoot, format_report_chain, format_send_amount_input,
    native_token_display_label, parse_address, public_asset_decimals, public_asset_label,
    public_balance_amount_label, secondary_dialog_content_width, token_label_row,
};

use crate::assets::{RailgunActionIcon, WalletIconSource};

mod controls;
mod progress;
mod root;
mod stepper;
mod types;

pub(super) use controls::*;
pub(super) use progress::*;
pub(super) use stepper::*;
pub(super) use types::*;
