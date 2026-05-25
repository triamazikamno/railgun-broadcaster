use std::collections::BTreeSet;
use std::ops::Range;
use std::sync::Arc;

use alloy::primitives::Address;
use gpui::{
    Context, ElementId, Entity, Focusable, InteractiveElement, IntoElement, MouseButton,
    ParentElement, Pixels, SharedString, StatefulInteractiveElement, Styled, Window, div, img,
    prelude::FluentBuilder as _, px, rgb,
};
use gpui_component::{
    Disableable, Icon, IconName, Sizable, WindowExt,
    alert::Alert,
    button::{Button, ButtonVariants},
    checkbox::Checkbox,
    collapsible::Collapsible,
    input::InputState,
    menu::{DropdownMenu, PopupMenuItem},
    scroll::ScrollableElement,
    tooltip::Tooltip,
};
use qrcodegen::{QrCode, QrCodeEcc};
use railgun_ui::{chain_name, short_address};
use ui::clipboard::{clipboard_with_toast, copy_to_clipboard_with_toast};
use ui::controls::{app_button, app_button_base, app_input, app_muted_text, app_strong_text};
use ui::theme::{self, APP_MONO_FONT_FAMILY, APP_TEXT_SIZE};
use wallet_ops::{
    PublicActionAttemptInfo, PublicActionCommandSender, PublicActionProgressStep, PublicAssetId,
    PublicBalanceEntry,
    vault::{
        PublicAccountMetadata, PublicAccountSource, PublicAccountStatus,
        public_account_default_label,
    },
};

use crate::assets::{RailgunActionIcon, RailgunPublicAccountIcon};

use super::dialogs::PublicAccountDialogKind;
use super::gas_fee::Eip1559GasFeeEditorState;
use super::public_action::{PublicActionMode, PublicActionStepState};
use super::public_balances::{public_asset_icon_path, public_balance_amount_label};
use super::{
    PUBLIC_ACCOUNT_DIALOG_WIDTH, PUBLIC_ADDRESS_QR_DIALOG_WIDTH, WalletRoot,
    public_account_visible_balances_for_chain, rgb_with_alpha, secondary_dialog_content_width,
    vault_error_kind,
};

pub(super) const PUBLIC_ACCOUNT_IDENTICON_SIZE: Pixels = px(40.0);
pub(super) const PUBLIC_ACCOUNT_IDENTICON_CELL_SIZE: Pixels = px(8.0);
pub(super) const PUBLIC_ADDRESS_QR_MODULE_SIZE: Pixels = px(6.0);
pub(super) const PUBLIC_ADDRESS_QR_QUIET_ZONE_MODULES: i32 = 4;
pub(super) const PUBLIC_ADDRESS_QR_FOREGROUND: u32 = 0x1e3c67;
pub(super) const PUBLIC_ADDRESS_QR_BACKGROUND: u32 = 0xffffff;
pub(super) const PUBLIC_ACCOUNT_IDENTICON_GRID_SIZE: usize = 5;
pub(super) const PUBLIC_ACCOUNT_IDENTICON_SOURCE_COLUMNS: usize = 3;
pub(super) const PUBLIC_ACCOUNT_IDENTICON_CELL_COUNT: usize =
    PUBLIC_ACCOUNT_IDENTICON_GRID_SIZE * PUBLIC_ACCOUNT_IDENTICON_GRID_SIZE;
pub(super) const PUBLIC_ACCOUNT_IDENTICON_COLORS: [u32; 8] = [
    theme::PRIMARY,
    theme::SUCCESS,
    theme::WARNING_STRONG,
    theme::WARNING,
    theme::DANGER,
    theme::PURPLE,
    theme::BLUE,
    theme::OLIVE,
];
const PUBLIC_BALANCE_CHIP_MIN_WIDTH: Pixels = px(184.0);
const PUBLIC_BALANCE_CHIP_ACTION_SLOT_SIZE: Pixels = px(24.0);
const PUBLIC_BALANCE_CHIP_ACTION_ICON_SIZE: Pixels = px(20.0);

pub(super) struct PublicAccountFormState {
    pub(super) add_label_input: Entity<InputState>,
    pub(super) add_password_input: Entity<InputState>,
    pub(super) import_label_input: Entity<InputState>,
    pub(super) import_private_key_input: Entity<InputState>,
    pub(super) import_password_input: Entity<InputState>,
    pub(super) edit_label_input: Entity<InputState>,
    pub(super) search_input: Entity<InputState>,
    pub(super) send_recipient_input: Entity<InputState>,
    pub(super) send_amount_input: Entity<InputState>,
    pub(super) send_password_input: Entity<InputState>,
    pub(super) shield_amount_input: Entity<InputState>,
    pub(super) shield_password_input: Entity<InputState>,
    pub(super) send_gas_fee: Eip1559GasFeeEditorState,
    pub(super) shield_gas_fee: Eip1559GasFeeEditorState,
    pub(super) import_global: bool,
    pub(super) selected_account_uuid: Option<Arc<str>>,
    pub(super) editing_account_uuid: Option<Arc<str>>,
    pub(super) search_query: Arc<str>,
    pub(super) selected_asset: Option<PublicAssetId>,
    pub(super) action_mode: PublicActionMode,
    pub(super) action_generation: u64,
    pub(super) action_progress: Vec<PublicActionStepState>,
    pub(super) expanded_action_error_steps: BTreeSet<PublicActionProgressStep>,
    pub(super) action_progress_dialog_open: bool,
    pub(super) action_progress_asset_label: Arc<str>,
    pub(super) action_progress_icon_path: Option<std::path::PathBuf>,
    pub(super) action_command_tx: Option<PublicActionCommandSender>,
    pub(super) action_attempts: Vec<PublicActionAttemptInfo>,
    pub(super) action_current_gas_fee: Option<(u128, u128)>,
    pub(super) action_action_error: Option<Arc<str>>,
    pub(super) next_derived_index: Option<u32>,
    pub(super) next_account_label_number: u32,
    pub(super) error: Option<Arc<str>>,
    pub(super) send_error: Option<Arc<str>>,
    pub(super) shield_error: Option<Arc<str>>,
    pub(super) adding_account: bool,
    pub(super) importing_account: bool,
    pub(super) sending: bool,
    pub(super) shielding: bool,
    pub(super) active_accounts_open: bool,
    pub(super) inactive_accounts_open: bool,
    pub(super) pending_global_delete_uuid: Option<Arc<str>>,
}

impl WalletRoot {
    pub(super) fn open_public_account_dialog(
        &mut self,
        kind: PublicAccountDialogKind,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        window.close_all_dialogs(cx);
        self.public_form.error = None;
        self.clear_public_account_dialog_inputs(kind, window, cx);
        let root = cx.entity();
        let dialog_width = (window.viewport_size().width * 0.92).min(PUBLIC_ACCOUNT_DIALOG_WIDTH);
        let content_width = secondary_dialog_content_width(dialog_width);
        window.open_dialog(cx, move |dialog, _window, cx| {
            let close_root = root.clone();
            let content_root = root.clone();
            dialog
                .w(dialog_width)
                .title(app_strong_text(kind.title()))
                .on_close(move |_event, window, cx| {
                    close_root.update(cx, |root, cx| {
                        root.public_form.error = None;
                        root.clear_public_account_dialog_inputs(kind, window, cx);
                    });
                })
                .child(content_root.read(cx).render_public_account_dialog_content(
                    content_root.clone(),
                    kind,
                    content_width,
                ))
        });
        cx.defer_in(window, move |root, window, cx| {
            root.focus_public_account_dialog_input(kind, window, cx);
        });
    }

    pub(super) fn open_public_account_edit_dialog(
        &mut self,
        public_account_uuid: Arc<str>,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        window.close_all_dialogs(cx);
        self.public_form.error = None;
        self.public_form.editing_account_uuid = Some(public_account_uuid);
        self.sync_public_edit_label_input(window, cx);
        let root = cx.entity();
        let dialog_width = (window.viewport_size().width * 0.92).min(PUBLIC_ACCOUNT_DIALOG_WIDTH);
        let content_width = secondary_dialog_content_width(dialog_width);
        window.open_dialog(cx, move |dialog, _window, cx| {
            let close_root = root.clone();
            let content_root = root.clone();
            dialog
                .w(dialog_width)
                .title(app_strong_text(PublicAccountDialogKind::EditLabel.title()))
                .on_close(move |_event, window, cx| {
                    close_root.update(cx, |root, cx| {
                        root.public_form.error = None;
                        root.clear_public_account_dialog_inputs(
                            PublicAccountDialogKind::EditLabel,
                            window,
                            cx,
                        );
                    });
                })
                .child(content_root.read(cx).render_public_account_dialog_content(
                    content_root.clone(),
                    PublicAccountDialogKind::EditLabel,
                    content_width,
                ))
        });
        cx.defer_in(window, |root, window, cx| {
            root.focus_public_account_dialog_input(PublicAccountDialogKind::EditLabel, window, cx);
        });
    }

    pub(super) fn open_public_address_qr_dialog(
        &self,
        public_account_uuid: &str,
        label: Option<String>,
        address: Address,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        window.close_all_dialogs(cx);
        let dialog_width =
            (window.viewport_size().width * 0.92).min(PUBLIC_ADDRESS_QR_DIALOG_WIDTH);
        let content_width = secondary_dialog_content_width(dialog_width);
        let address_text = SharedString::from(public_address_qr_payload(address));
        let account_label = label.map(SharedString::from);
        let chain_label = chain_name(self.selected_chain)
            .map_or_else(|| format!("chain {}", self.selected_chain), str::to_owned);
        let copy_id = SharedString::from(format!(
            "wallet-public-address-qr-copy-{public_account_uuid}"
        ));
        window.open_dialog(cx, move |dialog, _window, _cx| {
            dialog
                .w(dialog_width)
                .title(app_strong_text("Public account address"))
                .child(render_public_address_qr_dialog_content(
                    account_label.clone(),
                    address_text.clone(),
                    &chain_label,
                    copy_id.clone(),
                    content_width,
                ))
        });
    }

    fn focus_public_account_dialog_input(
        &self,
        kind: PublicAccountDialogKind,
        window: &mut Window,
        cx: &Context<'_, Self>,
    ) {
        match kind {
            PublicAccountDialogKind::Derive => self
                .public_form
                .add_password_input
                .read(cx)
                .focus_handle(cx)
                .focus(window),
            PublicAccountDialogKind::Import => self
                .public_form
                .import_private_key_input
                .read(cx)
                .focus_handle(cx)
                .focus(window),
            PublicAccountDialogKind::EditLabel => self
                .public_form
                .edit_label_input
                .read(cx)
                .focus_handle(cx)
                .focus(window),
        }
    }

    pub(super) fn render_public_wallet_body(&self, root: &Entity<Self>) -> gpui::AnyElement {
        let refresh_root = root.clone();

        div()
            .size_full()
            .min_w(px(0.0))
            .min_h(px(0.0))
            .overflow_y_scrollbar()
            .child(
                div()
                    .w(px(980.0))
                    .max_w_full()
                    .mx_auto()
                    .flex()
                    .flex_col()
                    .gap_4()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_3()
                            .child(div().flex_1().min_w(px(0.0)))
                            .child(
                                app_button(
                                    "wallet-public-refresh",
                                    if self.public_balance_refreshing {
                                        "Refreshing..."
                                    } else {
                                        "Refresh"
                                    },
                                )
                                .outline()
                                .small()
                                .loading(self.public_balance_refreshing)
                                .disabled(
                                    self.public_balance_refreshing
                                        || !self.has_active_public_accounts(),
                                )
                                .on_click(
                                    move |_event, _window, cx| {
                                        refresh_root.update(cx, |root, cx| {
                                            root.schedule_public_balance_refresh(cx);
                                        });
                                    },
                                ),
                            )
                            .child(self.render_public_add_account_dropdown(root)),
                    )
                    .children(self.public_balance_error.as_ref().map(|message| {
                        Alert::warning("wallet-public-balance-error", message.to_string())
                            .title("Public balances unavailable")
                            .small()
                    }))
                    .children(self.public_form.error.as_ref().map(|message| {
                        Alert::error("wallet-public-error", message.to_string()).small()
                    }))
                    .child(self.render_public_account_list(root)),
            )
            .into_any_element()
    }

    pub(super) fn clear_public_wallet_runtime_state(&mut self) {
        self.public_accounts.clear();
        self.public_balance_snapshot = None;
        self.public_balance_error = None;
        self.public_balance_refreshing = false;
        self.public_balance_generation = self.public_balance_generation.wrapping_add(1);
        self.public_inactive_balance_error = None;
        self.public_inactive_balance_refreshing = false;
        self.public_inactive_balance_generation =
            self.public_inactive_balance_generation.wrapping_add(1);
        self.public_form.selected_account_uuid = None;
        self.public_form.editing_account_uuid = None;
        self.public_form.selected_asset = None;
        self.clear_public_action_progress_state();
        self.public_form.next_derived_index = None;
        self.public_form.next_account_label_number = 1;
        self.public_form.error = None;
        self.public_form.send_error = None;
        self.public_form.shield_error = None;
        self.public_form.adding_account = false;
        self.public_form.importing_account = false;
        self.public_form.sending = false;
        self.public_form.shielding = false;
        self.public_form.active_accounts_open = true;
        self.public_form.inactive_accounts_open = false;
        self.public_form.pending_global_delete_uuid = None;
    }

    pub(super) fn reset_public_wallet_state(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        self.clear_public_wallet_runtime_state();
        for input in [
            &self.public_form.add_label_input,
            &self.public_form.add_password_input,
            &self.public_form.import_label_input,
            &self.public_form.import_private_key_input,
            &self.public_form.import_password_input,
            &self.public_form.edit_label_input,
            &self.public_form.send_recipient_input,
            &self.public_form.send_amount_input,
            &self.public_form.send_password_input,
            &self.public_form.shield_amount_input,
            &self.public_form.shield_password_input,
        ] {
            input.update(cx, |input, cx| input.set_value("", window, cx));
        }
        self.public_form.import_global = false;
        self.public_form.action_mode = PublicActionMode::Shield;
    }

    pub(super) fn clear_public_account_dialog_inputs(
        &mut self,
        kind: PublicAccountDialogKind,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let default_label =
            public_account_default_label(self.public_form.next_account_label_number);
        match kind {
            PublicAccountDialogKind::Derive => {
                self.public_form
                    .add_label_input
                    .update(cx, |input, cx| input.set_value(&default_label, window, cx));
                self.public_form
                    .add_password_input
                    .update(cx, |input, cx| input.set_value("", window, cx));
            }
            PublicAccountDialogKind::Import => {
                self.public_form
                    .import_label_input
                    .update(cx, |input, cx| input.set_value(&default_label, window, cx));
                self.public_form
                    .import_private_key_input
                    .update(cx, |input, cx| input.set_value("", window, cx));
                self.public_form
                    .import_password_input
                    .update(cx, |input, cx| input.set_value("", window, cx));
                self.public_form.import_global = false;
            }
            PublicAccountDialogKind::EditLabel => {
                self.public_form.editing_account_uuid = None;
                self.public_form
                    .edit_label_input
                    .update(cx, |input, cx| input.set_value("", window, cx));
            }
        }
    }

    pub(super) fn reload_public_accounts(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(store) = self.vault_store.as_ref() else {
            self.public_form.error = Some(Arc::from("Wallet vault storage is unavailable"));
            return;
        };
        let Some(view_session) = self.view_session.as_ref() else {
            self.public_accounts.clear();
            self.public_form.selected_account_uuid = None;
            self.sync_self_broadcast_gas_payer_selects(window, cx);
            return;
        };
        match store.list_public_accounts_for_session(view_session.as_ref(), true) {
            Ok(accounts) => {
                self.public_form.next_account_label_number =
                    next_public_account_label_number(accounts.len());
                let selected = self
                    .public_form
                    .selected_account_uuid
                    .as_ref()
                    .filter(|selected| {
                        accounts.iter().any(|account| {
                            account.public_account_uuid.as_str() == selected.as_ref()
                        })
                    })
                    .cloned()
                    .or_else(|| {
                        accounts
                            .iter()
                            .find(|account| account.status == PublicAccountStatus::Active)
                            .map(|account| Arc::from(account.public_account_uuid.as_str()))
                    });
                self.public_accounts = accounts;
                self.public_form.selected_account_uuid = selected;
                self.public_form.next_derived_index = store
                    .next_derived_public_account_index_for_session(view_session.as_ref())
                    .ok();
                self.sync_self_broadcast_gas_payer_selects(window, cx);
                self.sync_public_edit_label_input(window, cx);
            }
            Err(error) => {
                tracing::warn!(
                    error_kind = vault_error_kind(&error),
                    "load public accounts failed"
                );
                self.public_form.error = Some(Arc::from(error.to_string()));
            }
        }
    }

    pub(super) fn sync_public_edit_label_input(
        &self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let account_uuid = self
            .public_form
            .editing_account_uuid
            .as_ref()
            .or(self.public_form.selected_account_uuid.as_ref());
        let label = self
            .public_account_for_uuid(account_uuid.map(AsRef::as_ref))
            .and_then(|account| account.label.clone())
            .unwrap_or_default();
        self.public_form
            .edit_label_input
            .update(cx, |input, cx| input.set_value(&label, window, cx));
    }

    pub(super) fn selected_public_account(&self) -> Option<&PublicAccountMetadata> {
        self.public_account_for_uuid(
            self.public_form
                .selected_account_uuid
                .as_ref()
                .map(AsRef::as_ref),
        )
    }

    pub(super) fn public_account_for_uuid(
        &self,
        public_account_uuid: Option<&str>,
    ) -> Option<&PublicAccountMetadata> {
        let selected = public_account_uuid?;
        self.public_accounts
            .iter()
            .find(|account| account.public_account_uuid == selected)
    }

    pub(super) fn set_public_selected_balance(
        &mut self,
        public_account_uuid: Arc<str>,
        asset: PublicAssetId,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        self.public_form.selected_account_uuid = Some(public_account_uuid);
        self.public_form.selected_asset = Some(asset);
        self.public_form.pending_global_delete_uuid = None;
        self.public_form.send_error = None;
        self.public_form.shield_error = None;
        self.sync_public_edit_label_input(window, cx);
        cx.notify();
    }

    pub(super) fn set_public_account_section_open(
        &mut self,
        status: PublicAccountStatus,
        open: bool,
        cx: &mut Context<'_, Self>,
    ) {
        let current = match status {
            PublicAccountStatus::Active => &mut self.public_form.active_accounts_open,
            PublicAccountStatus::Inactive => &mut self.public_form.inactive_accounts_open,
        };
        if *current != open {
            *current = open;
            cx.notify();
        }
    }

    pub(super) fn has_active_public_accounts(&self) -> bool {
        self.public_accounts
            .iter()
            .any(|account| account.status == PublicAccountStatus::Active)
    }

    pub(super) fn add_public_derived_account_from_input(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        if self.public_form.adding_account {
            return;
        }
        let Some(store) = self.vault_store.clone() else {
            self.public_form.error = Some(Arc::from("Wallet vault storage is unavailable"));
            cx.notify();
            return;
        };
        let Some(view_session) = self.view_session.clone() else {
            self.public_form.error = Some(Arc::from("Wallet vault is locked"));
            cx.notify();
            return;
        };
        let label = self
            .public_form
            .add_label_input
            .read(cx)
            .value()
            .trim()
            .to_string();
        if label.is_empty() {
            self.public_form.error = Some(Arc::from("Enter an account label"));
            cx.notify();
            return;
        }
        let password = Self::read_and_clear_input(&self.public_form.add_password_input, window, cx);
        if password.trim().is_empty() {
            self.public_form.error = Some(Arc::from("Enter the vault password to add an account"));
            cx.notify();
            return;
        }
        self.public_form.adding_account = true;
        self.public_form.error = None;
        let result = store.add_derived_public_account(
            password.as_str(),
            view_session.as_ref(),
            Some(&label),
        );
        self.public_form.adding_account = false;
        match result {
            Ok(account) => {
                self.public_form.selected_account_uuid =
                    Some(Arc::from(account.public_account_uuid.as_str()));
                self.public_form
                    .add_label_input
                    .update(cx, |input, cx| input.set_value("", window, cx));
                self.reload_public_accounts(window, cx);
                self.schedule_public_balance_refresh(cx);
                window.close_all_dialogs(cx);
            }
            Err(error) => {
                self.public_form.error = Some(Arc::from(error.to_string()));
            }
        }
        cx.notify();
    }

    pub(super) fn import_public_account_from_input(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        if self.public_form.importing_account {
            return;
        }
        let Some(store) = self.vault_store.clone() else {
            self.public_form.error = Some(Arc::from("Wallet vault storage is unavailable"));
            cx.notify();
            return;
        };
        let Some(view_session) = self.view_session.clone() else {
            self.public_form.error = Some(Arc::from("Wallet vault is locked"));
            cx.notify();
            return;
        };
        let label = self
            .public_form
            .import_label_input
            .read(cx)
            .value()
            .trim()
            .to_string();
        if label.is_empty() {
            self.public_form.error = Some(Arc::from("Enter an account label"));
            cx.notify();
            return;
        }
        let private_key =
            Self::read_and_clear_input(&self.public_form.import_private_key_input, window, cx);
        let password =
            Self::read_and_clear_input(&self.public_form.import_password_input, window, cx);
        if private_key.trim().is_empty() || password.trim().is_empty() {
            self.public_form.error = Some(Arc::from(
                "Enter a private key and vault password to import an account",
            ));
            cx.notify();
            return;
        }
        let global = self.public_form.import_global;
        self.public_form.importing_account = true;
        self.public_form.error = None;
        let result = store.import_public_account(
            password.as_str(),
            view_session.as_ref(),
            private_key.as_str(),
            Some(&label),
            global,
        );
        self.public_form.importing_account = false;
        match result {
            Ok(account) => {
                self.public_form.selected_account_uuid =
                    Some(Arc::from(account.public_account_uuid.as_str()));
                self.public_form
                    .import_label_input
                    .update(cx, |input, cx| input.set_value("", window, cx));
                self.public_form.import_global = false;
                self.reload_public_accounts(window, cx);
                self.schedule_public_balance_refresh(cx);
                window.close_all_dialogs(cx);
            }
            Err(error) => {
                self.public_form.error = Some(Arc::from(error.to_string()));
            }
        }
        cx.notify();
    }

    pub(super) fn update_selected_public_account_label(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(store) = self.vault_store.clone() else {
            return;
        };
        let Some(view_session) = self.view_session.clone() else {
            return;
        };
        let Some(account_uuid) = self
            .public_form
            .editing_account_uuid
            .clone()
            .or_else(|| self.public_form.selected_account_uuid.clone())
        else {
            self.public_form.error = Some(Arc::from("Select a public account first"));
            cx.notify();
            return;
        };
        let label = self
            .public_form
            .edit_label_input
            .read(cx)
            .value()
            .trim()
            .to_string();
        if label.is_empty() {
            self.public_form.error = Some(Arc::from("Enter an account label"));
            cx.notify();
            return;
        }
        match store.update_public_account_label(
            view_session.as_ref(),
            account_uuid.as_ref(),
            Some(&label),
        ) {
            Ok(_) => {
                self.public_form.editing_account_uuid = None;
                self.reload_public_accounts(window, cx);
                window.close_all_dialogs(cx);
            }
            Err(error) => self.public_form.error = Some(Arc::from(error.to_string())),
        }
        cx.notify();
    }

    pub(super) fn deactivate_public_account(
        &mut self,
        public_account_uuid: &str,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(store) = self.vault_store.clone() else {
            return;
        };
        let Some(view_session) = self.view_session.clone() else {
            return;
        };
        match store
            .deactivate_derived_public_account(view_session.as_ref(), public_account_uuid.as_ref())
        {
            Ok(_) => {
                if self.public_form.selected_account_uuid.as_deref() == Some(public_account_uuid) {
                    self.public_form.selected_account_uuid = None;
                }
                self.reload_public_accounts(window, cx);
                self.schedule_public_balance_refresh(cx);
            }
            Err(error) => self.public_form.error = Some(Arc::from(error.to_string())),
        }
        cx.notify();
    }

    pub(super) fn activate_public_account(
        &mut self,
        public_account_uuid: &str,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(store) = self.vault_store.clone() else {
            return;
        };
        let Some(view_session) = self.view_session.clone() else {
            return;
        };
        match store
            .activate_derived_public_account(view_session.as_ref(), public_account_uuid.as_ref())
        {
            Ok(account) => {
                self.public_form.selected_account_uuid =
                    Some(Arc::from(account.public_account_uuid.as_str()));
                self.reload_public_accounts(window, cx);
                self.schedule_public_balance_refresh(cx);
            }
            Err(error) => self.public_form.error = Some(Arc::from(error.to_string())),
        }
        cx.notify();
    }

    pub(super) fn delete_public_account(
        &mut self,
        public_account_uuid: &str,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(account) = self
            .public_account_for_uuid(Some(public_account_uuid))
            .cloned()
        else {
            return;
        };
        if account.is_global()
            && self.public_form.pending_global_delete_uuid.as_deref()
                != Some(account.public_account_uuid.as_str())
        {
            self.public_form.pending_global_delete_uuid =
                Some(Arc::from(account.public_account_uuid.as_str()));
            cx.notify();
            return;
        }
        let Some(store) = self.vault_store.clone() else {
            return;
        };
        let Some(view_session) = self.view_session.clone() else {
            return;
        };
        match store
            .delete_imported_public_account(view_session.as_ref(), &account.public_account_uuid)
        {
            Ok(_) => {
                if self.public_form.selected_account_uuid.as_deref() == Some(public_account_uuid) {
                    self.public_form.selected_account_uuid = None;
                }
                self.public_form.pending_global_delete_uuid = None;
                self.reload_public_accounts(window, cx);
                self.schedule_public_balance_refresh(cx);
            }
            Err(error) => self.public_form.error = Some(Arc::from(error.to_string())),
        }
        cx.notify();
    }

    pub(super) fn public_account_visible_balances(
        &self,
        public_account_uuid: &str,
        status: PublicAccountStatus,
    ) -> Vec<PublicBalanceEntry> {
        public_account_visible_balances_for_chain(
            self.public_balance_snapshot.as_deref(),
            self.selected_chain,
            public_account_uuid,
            status,
        )
    }

    pub(super) fn render_public_add_account_dropdown(
        &self,
        root: &Entity<Self>,
    ) -> impl IntoElement {
        let derive_root = root.clone();
        let import_root = root.clone();
        app_button("wallet-public-add-account-trigger", "Add account")
            .primary()
            .small()
            .dropdown_caret(true)
            .disabled(
                self.vault_store.is_none()
                    || self.view_session.is_none()
                    || self.public_form.adding_account
                    || self.public_form.importing_account,
            )
            .dropdown_menu(move |menu, _window, _cx| {
                let derive_root = derive_root.clone();
                let import_root = import_root.clone();
                menu.min_w(px(190.0))
                    .item(PopupMenuItem::new("Derive from private").on_click(
                        move |_event, window, cx| {
                            derive_root.update(cx, |root, cx| {
                                root.open_public_account_dialog(
                                    PublicAccountDialogKind::Derive,
                                    window,
                                    cx,
                                );
                            });
                        },
                    ))
                    .item(PopupMenuItem::new("Import private key").on_click(
                        move |_event, window, cx| {
                            import_root.update(cx, |root, cx| {
                                root.open_public_account_dialog(
                                    PublicAccountDialogKind::Import,
                                    window,
                                    cx,
                                );
                            });
                        },
                    ))
            })
    }

    pub(super) fn render_public_account_dialog_content(
        &self,
        root: Entity<Self>,
        kind: PublicAccountDialogKind,
        content_width: Pixels,
    ) -> gpui::Div {
        match kind {
            PublicAccountDialogKind::Derive => {
                let add_root = root;
                let next_index = self.public_form.next_derived_index.map_or_else(
                    || "Next index unavailable".to_string(),
                    |index| format!("Next derived index: {index}"),
                );
                div()
                    .w(content_width)
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(app_muted_text(
                        "Derive a Public EVM account from the selected Private wallet mnemonic.",
                    ))
                    .child(app_muted_text(next_index))
                    .child(app_input(&self.public_form.add_label_input))
                    .child(app_input(&self.public_form.add_password_input))
                    .children(self.public_form.error.as_ref().map(|message| {
                        Alert::error("wallet-public-add-derived-error", message.to_string()).small()
                    }))
                    .child(
                        app_button(
                            "wallet-public-add-derived-submit",
                            if self.public_form.adding_account {
                                "Deriving..."
                            } else {
                                "Derive account"
                            },
                        )
                        .primary()
                        .small()
                        .loading(self.public_form.adding_account)
                        .disabled(self.public_form.adding_account)
                        .on_click(move |_event, window, cx| {
                            add_root.update(cx, |root, cx| {
                                root.add_public_derived_account_from_input(window, cx);
                            });
                        }),
                    )
            }
            PublicAccountDialogKind::Import => {
                let import_root = root.clone();
                let global_root = root;
                div()
                    .w(content_width)
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(app_muted_text(
                        "Import an EVM private key as a vaulted Public account.",
                    ))
                    .child(app_input(&self.public_form.import_label_input))
                    .child(app_input(&self.public_form.import_private_key_input))
                    .child(app_input(&self.public_form.import_password_input))
                    .child(
                        Checkbox::new("wallet-public-import-global")
                            .label("Global account")
                            .checked(self.public_form.import_global)
                            .small()
                            .on_click(move |checked, _window, cx| {
                                let checked = *checked;
                                global_root.update(cx, |root, cx| {
                                    root.public_form.import_global = checked;
                                    cx.notify();
                                });
                            }),
                    )
                    .children(self.public_form.error.as_ref().map(|message| {
                        Alert::error("wallet-public-import-error", message.to_string()).small()
                    }))
                    .child(
                        app_button(
                            "wallet-public-import-submit",
                            if self.public_form.importing_account {
                                "Importing..."
                            } else {
                                "Import account"
                            },
                        )
                        .primary()
                        .small()
                        .loading(self.public_form.importing_account)
                        .disabled(self.public_form.importing_account)
                        .on_click(move |_event, window, cx| {
                            import_root.update(cx, |root, cx| {
                                root.import_public_account_from_input(window, cx);
                            });
                        }),
                    )
            }
            PublicAccountDialogKind::EditLabel => {
                let save_root = root;
                div()
                    .w(content_width)
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(app_input(&self.public_form.edit_label_input))
                    .children(self.public_form.error.as_ref().map(|message| {
                        Alert::error("wallet-public-edit-label-error", message.to_string()).small()
                    }))
                    .child(
                        app_button("wallet-public-save-label", "Save")
                            .primary()
                            .small()
                            .on_click(move |_event, window, cx| {
                                save_root.update(cx, |root, cx| {
                                    root.update_selected_public_account_label(window, cx);
                                });
                            }),
                    )
            }
        }
    }

    pub(super) fn render_public_account_list(&self, root: &Entity<Self>) -> gpui::Div {
        let search_query = self.public_form.search_query.as_ref();
        let search_active = !search_query.is_empty();
        let clear_search_input = self.public_form.search_input.clone();
        let search_input =
            app_input(&self.public_form.search_input)
                .small()
                .when(search_active, |input| {
                    input.suffix(
                        app_button_base("wallet-public-account-search-clear")
                            .ghost()
                            .xsmall()
                            .tooltip("Clear search")
                            .icon(IconName::Close)
                            .on_click(move |_event, window, cx| {
                                clear_search_input.update(cx, |input, cx| {
                                    input.set_value("", window, cx);
                                });
                            }),
                    )
                });
        let mut card = div().w_full().flex().flex_col().gap_4();
        let controls = div()
            .w_full()
            .flex()
            .items_center()
            .justify_start()
            .gap_2()
            .child(div().w(px(260.0)).child(search_input));
        card = card.child(controls);
        if self.public_accounts.is_empty() {
            return card.child(app_muted_text(
                "No Public accounts yet. Add a derived account or import a private key.",
            ));
        }
        let accounts = if search_active {
            self.public_accounts
                .iter()
                .filter(|account| public_account_matches_search(account, search_query))
                .cloned()
                .collect::<Vec<_>>()
        } else {
            self.public_accounts.clone()
        };
        if accounts.is_empty() {
            return card.child(app_muted_text("No Public accounts match this search."));
        }

        let active_accounts = accounts
            .iter()
            .filter(|account| account.status == PublicAccountStatus::Active)
            .cloned()
            .collect::<Vec<_>>();
        let inactive_accounts = accounts
            .into_iter()
            .filter(|account| account.status == PublicAccountStatus::Inactive)
            .collect::<Vec<_>>();
        let active_open =
            self.public_form.active_accounts_open || (search_active && !active_accounts.is_empty());
        let inactive_open = self.public_form.inactive_accounts_open
            || (search_active && !inactive_accounts.is_empty());
        card = card
            .child(self.render_public_account_section(
                root,
                PublicAccountStatus::Active,
                "Active",
                &active_accounts,
                active_open,
            ))
            .child(self.render_public_account_section(
                root,
                PublicAccountStatus::Inactive,
                "Inactive",
                &inactive_accounts,
                inactive_open,
            ));
        card
    }

    fn render_public_account_section(
        &self,
        root: &Entity<Self>,
        status: PublicAccountStatus,
        title: &'static str,
        accounts: &[PublicAccountMetadata],
        open: bool,
    ) -> impl IntoElement {
        let section_id = public_account_status_id(status);
        let toggle_root = root.clone();
        let fetch_root = root.clone();
        let toggle_button_root = root.clone();
        let count = accounts.len();
        let mut header_actions = div()
            .flex()
            .flex_none()
            .items_center()
            .justify_end()
            .gap_2();
        if status == PublicAccountStatus::Inactive && open && count > 0 {
            header_actions = header_actions.child(
                app_button(
                    "wallet-public-inactive-fetch-balances",
                    if self.public_inactive_balance_refreshing {
                        "Fetching..."
                    } else {
                        "Fetch balances"
                    },
                )
                .outline()
                .xsmall()
                .loading(self.public_inactive_balance_refreshing)
                .disabled(self.public_inactive_balance_refreshing)
                .on_mouse_down(MouseButton::Left, move |_event, _window, cx| {
                    cx.stop_propagation();
                })
                .on_click(move |_event, _window, cx| {
                    cx.stop_propagation();
                    fetch_root.update(cx, |root, cx| {
                        root.schedule_inactive_public_balance_refresh(cx);
                    });
                }),
            );
        }
        header_actions = header_actions.child(
            app_button_base(SharedString::from(format!(
                "wallet-public-{section_id}-accounts-toggle"
            )))
            .ghost()
            .xsmall()
            .text_color(rgb(theme::PRIMARY))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_1()
                    .child(if open { "Hide" } else { "Show" })
                    .child(
                        Icon::new(if open {
                            IconName::ChevronUp
                        } else {
                            IconName::ChevronDown
                        })
                        .xsmall()
                        .text_color(rgb(theme::PRIMARY)),
                    ),
            )
            .on_mouse_down(MouseButton::Left, move |_event, _window, cx| {
                cx.stop_propagation();
            })
            .on_click(move |_event, _window, cx| {
                cx.stop_propagation();
                toggle_button_root.update(cx, |root, cx| {
                    root.set_public_account_section_open(status, !open, cx);
                });
            }),
        );
        let header = div()
            .id(SharedString::from(format!(
                "wallet-public-{section_id}-accounts-header"
            )))
            .w_full()
            .flex()
            .items_center()
            .justify_between()
            .gap_3()
            .px(px(10.0))
            .py(px(3.0))
            .rounded_md()
            .border_1()
            .border_color(rgb(theme::BORDER))
            .bg(rgb(theme::SURFACE))
            .cursor_pointer()
            .on_click(move |_event, _window, cx| {
                toggle_root.update(cx, |root, cx| {
                    root.set_public_account_section_open(status, !open, cx);
                });
            })
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .text_size(px(12.0))
                    .text_color(rgb(theme::TEXT_MUTED))
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .child(SharedString::from(format!(
                        "{} · {count}",
                        title.to_ascii_uppercase()
                    ))),
            )
            .child(header_actions);

        let mut content = div().w_full().flex().flex_col().gap_3().pt(px(4.0));
        if status == PublicAccountStatus::Inactive {
            content =
                content.children(self.public_inactive_balance_error.as_ref().map(|message| {
                    Alert::warning("wallet-public-inactive-balance-error", message.to_string())
                        .title("Inactive balances unavailable")
                        .small()
                }));
        }
        if accounts.is_empty() {
            content = content.child(app_muted_text(if status == PublicAccountStatus::Active {
                "No active Public accounts."
            } else {
                "No inactive Public accounts."
            }));
        } else {
            for account in accounts {
                content = content.child(self.render_public_account_card(root, account));
            }
        }

        Collapsible::new()
            .open(open)
            .w_full()
            .child(header)
            .content(content)
    }

    fn render_public_account_card(
        &self,
        root: &Entity<Self>,
        account: &PublicAccountMetadata,
    ) -> gpui::Div {
        let selected = self
            .public_form
            .selected_account_uuid
            .as_ref()
            .is_some_and(|selected| selected.as_ref() == account.public_account_uuid);
        let account_uuid = Arc::from(account.public_account_uuid.as_str());
        let row_group = SharedString::from(format!(
            "wallet-public-account-row-{}",
            account.public_account_uuid
        ));
        let edit_root = root.clone();
        let address_dialog_root = root.clone();
        let deactivate_root = root.clone();
        let activate_root = root.clone();
        let delete_root = root.clone();
        let address_display = short_address(&account.address);
        let edit_uuid = Arc::clone(&account_uuid);
        let address_dialog_uuid = Arc::clone(&account_uuid);
        let address_dialog_address = account.address;
        let source_badge = public_account_metadata_badge(
            SharedString::from(format!(
                "wallet-public-account-source-{}",
                account.public_account_uuid
            )),
            Icon::new(public_account_source_icon(account.source)),
            public_account_source_label(account.source),
        );
        let mut metadata_badges = div().flex().items_center().gap_1().child(source_badge);
        if account.is_global() {
            metadata_badges = metadata_badges.child(public_account_metadata_badge(
                SharedString::from(format!(
                    "wallet-public-account-scope-{}",
                    account.public_account_uuid
                )),
                Icon::new(RailgunPublicAccountIcon::Global),
                "Available across wallets",
            ));
        }
        let account_label = public_account_display_label(account);
        let address_dialog_label = account_label.clone();
        let action_buttons = div()
            .group(row_group.clone())
            .flex()
            .flex_none()
            .items_center()
            .gap_1()
            .opacity(0.0)
            .group_hover(row_group.clone(), |this| this.opacity(1.0))
            .hover(|this| this.opacity(1.0))
            .on_mouse_down(MouseButton::Left, move |_event, _window, cx| {
                cx.stop_propagation();
            })
            .child(
                public_account_icon_button(
                    SharedString::from(format!(
                        "wallet-public-edit-{}",
                        account.public_account_uuid
                    )),
                    Icon::new(RailgunActionIcon::Pencil),
                    "Edit label",
                )
                .on_click(move |_event, window, cx| {
                    let account_uuid = Arc::clone(&edit_uuid);
                    edit_root.update(cx, |root, cx| {
                        root.open_public_account_edit_dialog(account_uuid, window, cx);
                    });
                }),
            );
        let action_buttons = match account.source {
            PublicAccountSource::Derived => {
                let status_uuid = Arc::clone(&account_uuid);
                let inactive = account.status == PublicAccountStatus::Inactive;
                action_buttons.child(
                    public_account_icon_button(
                        SharedString::from(format!(
                            "wallet-public-{}-{}",
                            if inactive { "activate" } else { "deactivate" },
                            account.public_account_uuid
                        )),
                        if inactive {
                            IconName::Eye
                        } else {
                            IconName::EyeOff
                        },
                        if inactive {
                            "Activate account"
                        } else {
                            "Deactivate account"
                        },
                    )
                    .on_click(move |_event, window, cx| {
                        let account_uuid = Arc::clone(&status_uuid);
                        if inactive {
                            activate_root.update(cx, |root, cx| {
                                root.activate_public_account(&account_uuid, window, cx);
                            });
                        } else {
                            deactivate_root.update(cx, |root, cx| {
                                root.deactivate_public_account(&account_uuid, window, cx);
                            });
                        }
                    }),
                )
            }
            PublicAccountSource::Imported => {
                let delete_uuid = Arc::clone(&account_uuid);
                let confirming_global_delete = account.is_global()
                    && self.public_form.pending_global_delete_uuid.as_deref()
                        == Some(account.public_account_uuid.as_str());
                action_buttons.child(
                    public_account_icon_button(
                        SharedString::from(format!(
                            "wallet-public-delete-{}",
                            account.public_account_uuid
                        )),
                        Icon::new(RailgunActionIcon::Trash2),
                        if confirming_global_delete {
                            "Confirm global delete"
                        } else {
                            "Delete account"
                        },
                    )
                    .danger()
                    .on_click(move |_event, window, cx| {
                        let account_uuid = Arc::clone(&delete_uuid);
                        delete_root.update(cx, |root, cx| {
                            root.delete_public_account(&account_uuid, window, cx);
                        });
                    }),
                )
            }
        };
        let account_label = account_label.map_or_else(
            || {
                app_strong_text(" ")
                    .text_size(theme::ACCOUNT_LABEL_TEXT_SIZE)
                    .whitespace_nowrap()
                    .opacity(0.0)
            },
            |label| {
                app_strong_text(label)
                    .text_size(theme::ACCOUNT_LABEL_TEXT_SIZE)
                    .whitespace_nowrap()
            },
        );
        let mut account_content = div()
            .w_full()
            .flex_1()
            .min_w(px(0.0))
            .flex()
            .flex_col()
            .gap_1()
            .child(
                div()
                    .w_full()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(div().flex_1().min_w(px(0.0)).child(account_label))
                    .child(action_buttons),
            )
            .child(
                div()
                    .w_full()
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap_2()
                    .child(
                        div()
                            .min_w(px(0.0))
                            .flex_1()
                            .flex()
                            .items_center()
                            .gap_1()
                            .child(
                                div()
                                    .id(SharedString::from(format!(
                                        "wallet-public-address-qr-action-{}",
                                        account.public_account_uuid
                                    )))
                                    .flex()
                                    .items_center()
                                    .gap_1()
                                    .rounded_sm()
                                    .px(px(2.0))
                                    .py(px(1.0))
                                    .cursor_pointer()
                                    .hover(|this| this.bg(rgb(theme::SURFACE_HOVER_SUBTLE)))
                                    .tooltip(|window, cx| {
                                        Tooltip::new("Show address QR code").build(window, cx)
                                    })
                                    .on_mouse_down(MouseButton::Left, move |_event, _window, cx| {
                                        cx.stop_propagation();
                                    })
                                    .on_click(move |_event, window, cx| {
                                        cx.stop_propagation();
                                        let account_uuid = Arc::clone(&address_dialog_uuid);
                                        let label = address_dialog_label.clone();
                                        address_dialog_root.update(cx, |root, cx| {
                                            root.open_public_address_qr_dialog(
                                                account_uuid.as_ref(),
                                                label,
                                                address_dialog_address,
                                                window,
                                                cx,
                                            );
                                        });
                                    })
                                    .child(
                                        app_muted_text(address_display)
                                            .font_family(APP_MONO_FONT_FAMILY)
                                            .text_size(theme::ACCOUNT_ADDRESS_TEXT_SIZE)
                                            .text_color(rgb(theme::TEXT_SUBTLE))
                                            .whitespace_nowrap(),
                                    )
                                    .child(
                                        div()
                                            .group(row_group.clone())
                                            .flex_none()
                                            .opacity(0.0)
                                            .group_hover(row_group.clone(), |this| {
                                                this.opacity(1.0)
                                            })
                                            .child(
                                                Icon::new(RailgunActionIcon::QrCode)
                                                    .xsmall()
                                                    .text_color(rgb(theme::TEXT)),
                                            ),
                                    ),
                            ),
                    )
                    .child(metadata_badges),
            );

        let visible_balances =
            self.public_account_visible_balances(&account.public_account_uuid, account.status);
        if !visible_balances.is_empty() {
            let mut balance_chips = div().w_full().flex().flex_wrap().gap_2().pt(px(2.0));
            for (balance_index, entry) in visible_balances.iter().enumerate() {
                balance_chips = balance_chips.child(self.render_public_account_balance_chip(
                    root,
                    Arc::clone(&account_uuid),
                    selected,
                    balance_index,
                    entry,
                ));
            }
            account_content = account_content.child(balance_chips);
        }
        let mut account_card = div()
            .group(row_group)
            .w_full()
            .flex()
            .flex_col()
            .gap_2()
            .p(px(14.0))
            .rounded_md()
            .border_1()
            .border_color(rgb(theme::BORDER))
            .bg(rgb(theme::SURFACE))
            .hover(|row| row.border_color(rgb(theme::PRIMARY)))
            .child(
                div()
                    .flex()
                    .items_start()
                    .gap_4()
                    .child(render_public_account_identicon(&account.address))
                    .child(account_content),
            );
        if account.is_global()
            && self.public_form.pending_global_delete_uuid.as_deref()
                == Some(account.public_account_uuid.as_str())
        {
            account_card = account_card.child(
                Alert::warning(
                    SharedString::from(format!(
                        "wallet-public-global-delete-warning-{}",
                        account.public_account_uuid
                    )),
                    "Deleting this global account removes it from every Private wallet.",
                )
                .small(),
            );
        }
        account_card
    }

    fn render_public_account_balance_chip(
        &self,
        root: &Entity<Self>,
        account_uuid: Arc<str>,
        selected_account: bool,
        index: usize,
        entry: &PublicBalanceEntry,
    ) -> impl IntoElement {
        let select_root = root.clone();
        let asset = entry.asset.id;
        let selected = selected_account && self.public_form.selected_asset == Some(asset);
        let icon_path = public_asset_icon_path(
            self.selected_chain,
            asset,
            Some(&self.effective_token_registry),
        );
        let amount_label = public_balance_amount_label(&entry.amount, entry.asset.decimals);
        let symbol = entry.asset.symbol.clone();
        let tooltip = SharedString::from(format!("Shield/send {symbol}"));
        let balance_id = SharedString::from(format!(
            "wallet-public-account-balance-{}-{index}",
            account_uuid.as_ref()
        ));
        let balance_group = SharedString::from(format!(
            "wallet-public-account-balance-group-{}-{index}",
            account_uuid.as_ref()
        ));
        let mut asset_label = div().flex().items_center().gap_1();
        if let Some(path) = icon_path {
            asset_label = asset_label.child(img(path).size(px(16.0)).rounded_full().flex_none());
        }
        div()
            .id(balance_id)
            .group(balance_group.clone())
            .min_w(PUBLIC_BALANCE_CHIP_MIN_WIDTH)
            .flex_none()
            .flex()
            .items_center()
            .gap_2()
            .px(px(8.0))
            .py(px(5.0))
            .rounded_md()
            .border_1()
            .border_color(if selected {
                rgb(theme::PRIMARY)
            } else {
                rgb(theme::BORDER_SUBTLE)
            })
            .bg(if selected {
                rgb(theme::SURFACE_HOVER_SUBTLE)
            } else {
                rgb(theme::SURFACE)
            })
            .text_size(APP_TEXT_SIZE)
            .cursor_pointer()
            .hover(|this| {
                this.bg(rgb(theme::SURFACE_ELEVATED))
                    .border_color(if selected {
                        rgb(theme::PRIMARY)
                    } else {
                        rgb(theme::BORDER)
                    })
            })
            .tooltip(move |window, cx| Tooltip::new(tooltip.clone()).build(window, cx))
            .on_mouse_down(MouseButton::Left, move |_event, _window, cx| {
                cx.stop_propagation();
            })
            .on_click(move |_event, window, cx| {
                let account_uuid = Arc::clone(&account_uuid);
                select_root.update(cx, |root, cx| {
                    root.open_public_action_dialog(account_uuid, asset, window, cx);
                });
            })
            .child(
                asset_label
                    .flex_none()
                    .text_color(rgb(theme::TEXT_MUTED))
                    .child(SharedString::from(symbol)),
            )
            .child(
                div()
                    .flex_none()
                    .text_color(rgb(theme::WARNING))
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .child(SharedString::from(amount_label)),
            )
            .child(div().flex_1())
            .child(
                div()
                    .group(balance_group.clone())
                    .size(PUBLIC_BALANCE_CHIP_ACTION_SLOT_SIZE)
                    .flex_none()
                    .flex()
                    .items_center()
                    .justify_center()
                    .opacity(0.0)
                    .group_hover(balance_group, |this| this.opacity(1.0))
                    .hover(|this| this.opacity(1.0))
                    .child(
                        Icon::new(RailgunActionIcon::Shield)
                            .with_size(PUBLIC_BALANCE_CHIP_ACTION_ICON_SIZE)
                            .text_color(rgb(theme::WARNING_STRONG)),
                    ),
            )
    }
}

fn public_account_icon_button(
    id: impl Into<ElementId>,
    icon: impl Into<Icon>,
    tooltip: impl Into<SharedString>,
) -> Button {
    Button::new(id)
        .icon(icon)
        .ghost()
        .xsmall()
        .compact()
        .tooltip(tooltip)
}

fn public_account_metadata_badge(
    id: impl Into<ElementId>,
    icon: impl Into<Icon>,
    tooltip: impl Into<SharedString>,
) -> impl IntoElement {
    let tooltip = tooltip.into();
    div()
        .id(id)
        .flex()
        .size(px(18.0))
        .items_center()
        .justify_center()
        .rounded_sm()
        .bg(rgb(theme::SURFACE))
        .tooltip(move |window, cx| Tooltip::new(tooltip.clone()).build(window, cx))
        .child(Icon::new(icon).xsmall().text_color(rgb(theme::TEXT_MUTED)))
}

const fn public_account_status_id(status: PublicAccountStatus) -> &'static str {
    match status {
        PublicAccountStatus::Active => "active",
        PublicAccountStatus::Inactive => "inactive",
    }
}

pub(super) fn render_public_account_identicon(address: &Address) -> gpui::Div {
    let pattern = public_account_identicon_pattern(address);
    let foreground = public_account_identicon_color(address);
    let mut icon = div()
        .size(PUBLIC_ACCOUNT_IDENTICON_SIZE)
        .flex_none()
        .flex()
        .flex_col()
        .items_center()
        .justify_center()
        .gap_0();
    for row in pattern.chunks_exact(PUBLIC_ACCOUNT_IDENTICON_GRID_SIZE) {
        let mut row_div = div().flex().gap_0();
        for active in row {
            let cell = div().size(PUBLIC_ACCOUNT_IDENTICON_CELL_SIZE);
            row_div = row_div.child(if *active {
                cell.bg(rgb(foreground))
            } else {
                cell
            });
        }
        icon = icon.child(row_div);
    }
    icon
}

pub(super) fn public_account_identicon_pattern(
    address: &Address,
) -> [bool; PUBLIC_ACCOUNT_IDENTICON_CELL_COUNT] {
    let mut pattern = [false; PUBLIC_ACCOUNT_IDENTICON_CELL_COUNT];
    let mut has_foreground = false;
    for (row_index, row) in pattern
        .chunks_exact_mut(PUBLIC_ACCOUNT_IDENTICON_GRID_SIZE)
        .enumerate()
    {
        for column in 0..PUBLIC_ACCOUNT_IDENTICON_SOURCE_COLUMNS {
            let bit_index = row_index * PUBLIC_ACCOUNT_IDENTICON_SOURCE_COLUMNS + column;
            let active = public_account_identicon_bit(address, bit_index);
            has_foreground |= active;
            row[column] = active;
            row[PUBLIC_ACCOUNT_IDENTICON_GRID_SIZE - column - 1] = active;
        }
    }
    if !has_foreground {
        pattern[PUBLIC_ACCOUNT_IDENTICON_CELL_COUNT / 2] = true;
    }
    pattern
}

fn public_account_identicon_bit(address: &Address, bit_index: usize) -> bool {
    let bytes = address.as_slice();
    let byte = bytes[(bit_index * 7) % bytes.len()];
    let shift = (bit_index * 5) % u8::BITS as usize;
    ((byte >> shift) & 1) == 1
}

pub(super) fn public_account_identicon_color(address: &Address) -> u32 {
    let bytes = address.as_slice();
    let color_index = usize::from(bytes[3] ^ bytes[7] ^ bytes[11] ^ bytes[15] ^ bytes[19])
        % PUBLIC_ACCOUNT_IDENTICON_COLORS.len();
    PUBLIC_ACCOUNT_IDENTICON_COLORS[color_index]
}

pub(super) fn render_public_address_qr_dialog_content(
    label: Option<SharedString>,
    address: SharedString,
    chain_label: &str,
    copy_id: SharedString,
    content_width: Pixels,
) -> gpui::Div {
    let receive_warning = SharedString::from(format!(
        "Send only public {chain_label} assets to this address."
    ));
    let address_copy_value = address.clone();
    let copy_row_id = SharedString::from(format!("{}-row", copy_id.as_ref()));
    div()
        .w(content_width)
        .flex()
        .flex_col()
        .items_center()
        .gap_4()
        .child(
            div()
                .w_full()
                .rounded_md()
                .border_1()
                .border_color(rgb(theme::BORDER))
                .bg(rgb_with_alpha(theme::PRIMARY, 0.08))
                .p(px(10.0))
                .text_color(rgb(theme::TEXT_MUTED))
                .text_size(APP_TEXT_SIZE)
                .line_height(px(18.0))
                .child(receive_warning),
        )
        .children(label.map(|label| {
            div()
                .text_color(rgb(theme::TEXT))
                .text_size(theme::ACCOUNT_LABEL_TEXT_SIZE)
                .font_weight(gpui::FontWeight::SEMIBOLD)
                .child(label)
        }))
        .child(render_public_address_qr_code(address.as_ref()))
        .child(
            div()
                .id(copy_row_id)
                .w_full()
                .flex()
                .items_center()
                .gap_2()
                .rounded_md()
                .border_1()
                .border_color(rgb(theme::BORDER))
                .bg(rgb(theme::SURFACE_ELEVATED))
                .px(px(10.0))
                .py(px(8.0))
                .cursor_pointer()
                .hover(|this| {
                    this.bg(rgb(theme::SURFACE_HOVER_SUBTLE))
                        .border_color(rgb(theme::BORDER_STRONG))
                })
                .tooltip(|window, cx| Tooltip::new("Copy address").build(window, cx))
                .on_click(move |_event, window, cx| {
                    copy_to_clipboard_with_toast(address_copy_value.clone(), window, cx);
                })
                .child(
                    div()
                        .flex_1()
                        .min_w(px(0.0))
                        .text_color(rgb(theme::TEXT))
                        .text_size(px(12.0))
                        .font_family(APP_MONO_FONT_FAMILY)
                        .line_height(px(17.0))
                        .child(address.clone()),
                )
                .child(clipboard_with_toast(copy_id, address)),
        )
}

fn render_public_address_qr_code(payload: &str) -> gpui::Div {
    let Ok(qr) = QrCode::encode_text(payload, QrCodeEcc::Medium) else {
        return div()
            .p(px(14.0))
            .rounded_md()
            .border_1()
            .border_color(rgb(theme::DANGER))
            .bg(rgb(theme::SURFACE_ELEVATED))
            .text_color(rgb(theme::DANGER))
            .child("QR code unavailable");
    };
    let mut grid = div()
        .flex()
        .flex_col()
        .flex_none()
        .rounded_md()
        .border_1()
        .border_color(rgb(theme::BORDER_STRONG))
        .bg(rgb(PUBLIC_ADDRESS_QR_BACKGROUND))
        .p(px(6.0));
    let module_range = public_address_qr_module_range(qr.size());
    for y in module_range.clone() {
        let mut row = div().flex().flex_none();
        for x in module_range.clone() {
            let active = x >= 0 && y >= 0 && x < qr.size() && y < qr.size() && qr.get_module(x, y);
            row = row.child(
                div()
                    .size(PUBLIC_ADDRESS_QR_MODULE_SIZE)
                    .flex_none()
                    .bg(rgb(if active {
                        PUBLIC_ADDRESS_QR_FOREGROUND
                    } else {
                        PUBLIC_ADDRESS_QR_BACKGROUND
                    })),
            );
        }
        grid = grid.child(row);
    }
    grid
}

pub(super) fn public_account_matches_search(account: &PublicAccountMetadata, query: &str) -> bool {
    let query = query.trim().to_ascii_lowercase();
    if query.is_empty() {
        return true;
    }
    account
        .label
        .as_deref()
        .is_some_and(|label| label.to_ascii_lowercase().contains(&query))
        || format!("{:#x}", account.address).contains(&query)
}

pub(super) fn public_account_display_label(account: &PublicAccountMetadata) -> Option<String> {
    account
        .label
        .as_ref()
        .filter(|label| !label.trim().is_empty())
        .cloned()
}

pub(super) fn public_address_qr_payload(address: Address) -> String {
    format!("{address:#x}")
}

pub(super) const fn public_address_qr_module_range(qr_size: i32) -> Range<i32> {
    -PUBLIC_ADDRESS_QR_QUIET_ZONE_MODULES..qr_size + PUBLIC_ADDRESS_QR_QUIET_ZONE_MODULES
}

pub(super) fn next_public_account_label_number(account_count: usize) -> u32 {
    u32::try_from(account_count)
        .ok()
        .and_then(|count| count.checked_add(1))
        .unwrap_or(u32::MAX)
}

pub(super) const fn public_account_source_label(source: PublicAccountSource) -> &'static str {
    match source {
        PublicAccountSource::Derived => "Derived",
        PublicAccountSource::Imported => "Imported",
    }
}

pub(super) const fn public_account_source_icon(
    source: PublicAccountSource,
) -> RailgunPublicAccountIcon {
    match source {
        PublicAccountSource::Derived => RailgunPublicAccountIcon::Derived,
        PublicAccountSource::Imported => RailgunPublicAccountIcon::Imported,
    }
}
