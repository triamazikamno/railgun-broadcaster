use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::{Address, U256};
use broadcaster_monitor::FeeRow;
use gpui::{
    Animation, AnimationExt as _, App, AppContext, Context, ElementId, Entity, Focusable,
    InteractiveElement, IntoElement, KeyDownEvent, MouseButton, ParentElement, Pixels,
    ScrollHandle, SharedString, StatefulInteractiveElement, Styled, Window, deferred, div,
    prelude::FluentBuilder as _, px, rgb,
};
use gpui_component::{
    Disableable, Icon, IconName, IndexPath, Selectable, Sizable, WindowExt,
    alert::Alert,
    button::{Button, ButtonGroup, ButtonVariants},
    dialog::DialogButtonProps,
    input::{Escape as InputEscape, Input, InputEvent, InputState},
    popover::Popover,
    scroll::ScrollableElement,
    select::{SearchableVec, Select, SelectEvent, SelectItem, SelectState},
    spinner::Spinner,
};
use railgun_ui::{format_token_amount, short_address};
use rand::seq::IndexedRandom;
use tokio::sync::{mpsc, watch};
use ui::clipboard::clipboard_with_toast;
use ui::controls::{
    app_button, app_button_base, app_button_label, app_input, app_muted_text, app_strong_text,
};
use ui::theme::{self, APP_FONT_FAMILY, APP_TEXT_SIZE};
use wallet_ops::{
    BroadcasterFeePolicy, DesktopSelfBroadcastResult, DesktopSendCalldataRequest,
    DesktopSendPublicBroadcasterRequest, DesktopSendSelfBroadcastRequest,
    DesktopUnshieldCalldataRequest, DesktopUnshieldPublicBroadcasterRequest,
    DesktopUnshieldSelfBroadcastRequest, ListUtxosOutput, PreparedSendCall, PreparedUnshieldCall,
    PublicAssetId, PublicBalanceAmount, PublicBalanceEntry, PublicBalanceSnapshot,
    PublicBroadcasterCandidate, PublicBroadcasterCostEstimate, PublicBroadcasterFeeMode,
    PublicBroadcasterResultKind, PublicBroadcasterSubmissionResult, SelfBroadcastGasFeeQuote,
    SelfBroadcastGasFeeSelection, SelfBroadcastSessionEvent, TokenAnchorRateCache,
    TransactionGenerationStage, WalletSession, fee_policy_eligible_public_broadcasters,
    parse_railgun_recipient, parse_send_amount, parse_unshield_amount,
    prepare_desktop_send_calldata, prepare_desktop_unshield_calldata,
    quote_desktop_self_broadcast_gas_fee, select_public_broadcaster_with_policy,
    settings::EffectiveTokenRegistry,
    sort_specific_public_broadcasters, submit_desktop_send_public_broadcaster,
    submit_desktop_send_self_broadcast, submit_desktop_unshield_public_broadcaster,
    submit_desktop_unshield_self_broadcast,
    vault::{
        DesktopVaultStore, DesktopViewSession, PrivateAddressBookEntry, PublicAccountMetadata,
        PublicAccountStatus, PublicAddressBookEntry, WalletStatus,
    },
};
use zeroize::Zeroizing;

use crate::assets::{RailgunActionIcon, WalletIconSource};

use super::broadcaster_picker::{
    BroadcasterChoice, broadcaster_choice_supported_by_candidates,
    selected_broadcaster_fee_warning, selected_broadcaster_label,
    should_preserve_estimate_after_broadcaster_policy_change,
};
use super::gas_fee::{
    Eip1559GasFeeEditTarget, Eip1559GasFeeEditorState, Eip1559GasFeeMode, Eip1559GasFeeTarget,
    render_eip1559_gas_fee_editor,
};
use super::private_assets::{
    build_send_asset, build_unshield_asset, format_private_asset_rows_from_snapshot,
    refresh_form_asset_from_snapshot,
};
use super::private_broadcaster::{
    private_broadcaster_closed_active_progress, render_private_broadcaster_status_notice,
    render_private_self_broadcast_status_notice, render_private_submission_active_status_notice,
};
use super::public_account::public_account_display_label;
use super::public_balances::public_balance_entry_for_chain;
use super::public_broadcaster::resolve_selected_public_broadcaster_fee_token;
use super::public_broadcaster_cost::{
    cost_estimate_detail_text, public_broadcaster_cost_status,
    render_public_broadcaster_cost_estimate, render_public_broadcaster_cost_status,
    should_render_public_broadcaster_cost_preview,
};
use super::spend_authorization::{
    SpendAuthorizationIntent, SpendAuthorizationSummary, SpendAuthorizationSummaryRow,
    is_spend_authorization_failure_error,
};
use super::utxo::short_hash;
use super::{
    ChainUtxoState, PRIVATE_ACTION_FORM_MAX_HEIGHT, PRIVATE_ASSET_LIST_WIDTH,
    PublicBroadcasterFeeTokenOption, WalletRoot, effective_public_broadcaster_fee_mode,
    format_exact_token_amount_for_display, format_report_chain, format_send_amount_input,
    format_unshield_amount_input, is_effective_wrapped_native_token, labeled_field,
    native_token_display_label, native_wrapped_output_labels, new_prefilled_input, new_text_input,
    parse_address, public_balance_amount_label, public_broadcaster_fee_token_warning,
    public_broadcaster_submit_disabled_for_fee_token_options, secondary_dialog_content_width,
    send_form_max_entered_amount, should_show_broadcaster_fee_mode_toggle, token_label_row,
    unshield_form_max_entered_amount, vault_error_kind,
};

mod delivery;
mod form_lifecycle;
mod generation;
mod helpers;
mod recipient_picker;
mod render_forms;
mod render_helpers;
mod self_broadcast;
mod types;

pub(super) use delivery::*;
pub(super) use helpers::*;
pub(super) use recipient_picker::*;
pub(super) use render_helpers::*;
pub(super) use self_broadcast::*;
pub(super) use types::*;
