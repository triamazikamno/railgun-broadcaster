use std::sync::Arc;

use gpui::{AppContext, Context, Entity, Focusable, ParentElement, Window, px};
use gpui_component::{WindowExt, input::InputState, select::SearchableVec};
use ui::controls::app_strong_text;
use wallet_ops::vault::{
    DesktopViewSession, PRIMARY_WALLET_LABEL, VaultError, WalletMetadataBundle, WalletSource,
    default_wallet_label_for_metadata, generate_opaque_id, generate_seed_material,
    sort_wallet_metadata,
};
use zeroize::Zeroizing;

use super::dialogs::AddWalletDialogContent;
use super::wallet_header::WalletSelectItem;
use super::{ChainUtxoState, WalletRoot, WalletTab, secondary_dialog_content_width};

pub(super) enum VaultState {
    CreateVault,
    UnlockVault,
    SetupWallet,
    ViewUnlocked,
    Error(Arc<str>),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum WalletSetupMode {
    Choose,
    GeneratedReview,
    Import,
}

#[derive(Clone)]
pub(super) struct WalletOption {
    pub(super) wallet_id: Arc<str>,
    pub(super) label: Arc<str>,
    pub(super) source: WalletSource,
}

pub(super) fn wallet_options_from_metadata(
    mut metadata: Vec<WalletMetadataBundle>,
) -> Vec<WalletOption> {
    metadata.retain(|metadata| metadata.status == wallet_ops::vault::WalletStatus::Active);
    sort_wallet_metadata(&mut metadata);
    metadata
        .into_iter()
        .map(|metadata| WalletOption {
            wallet_id: Arc::from(metadata.wallet_uuid),
            label: Arc::from(metadata.label),
            source: metadata.source,
        })
        .collect()
}

pub(super) const fn vault_error_kind(error: &VaultError) -> &'static str {
    match error {
        VaultError::Random => "random",
        VaultError::InvalidKdfParams => "invalid_kdf_params",
        VaultError::Kdf => "kdf",
        VaultError::KeySeparation => "key_separation",
        VaultError::Encrypt => "encrypt",
        VaultError::Decrypt => "decrypt",
        VaultError::Encode(_) => "encode",
        VaultError::Decode(_) => "decode",
        VaultError::Db(_) => "db",
        VaultError::Io(_) => "io",
        VaultError::Key(_) => "key",
        VaultError::UnsupportedVersion(_) => "unsupported_version",
        VaultError::VaultAlreadyExists => "vault_already_exists",
        VaultError::VaultNotFound => "vault_not_found",
        VaultError::UnlockFailed => "unlock_failed",
        VaultError::InvalidSpendGrant => "invalid_spend_grant",
        VaultError::WalletNotFound => "wallet_not_found",
        VaultError::InvalidWalletLabel => "invalid_wallet_label",
        VaultError::DuplicateWalletLabel => "duplicate_wallet_label",
        VaultError::InvalidWalletOrder => "invalid_wallet_order",
        VaultError::LastActiveWallet => "last_active_wallet",
        VaultError::WalletDisplayOrderOverflow => "wallet_display_order_overflow",
        VaultError::PublicAccountNotFound => "public_account_not_found",
        VaultError::DuplicatePublicAccountAddress => "duplicate_public_account_address",
        VaultError::InvalidPublicAccountOperation => "invalid_public_account_operation",
        VaultError::PublicAccountDisplayOrderOverflow => "public_account_display_order_overflow",
        VaultError::InvalidPublicEvmPrivateKey => "invalid_public_evm_private_key",
        VaultError::PublicEvmKeyDerivation => "public_evm_key_derivation",
    }
}

impl WalletRoot {
    pub(super) fn set_wallet_name_input(
        &self,
        value: &str,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let value = value.to_owned();
        self.wallet_name_input
            .update(cx, |input, cx| input.set_value(&value, window, cx));
    }

    fn set_default_wallet_name_from_password(
        &self,
        password: &str,
        window: &Window,
        cx: &mut Context<'_, Self>,
    ) {
        let label = self
            .vault_store
            .as_ref()
            .and_then(|store| store.default_wallet_label(password).ok())
            .unwrap_or_else(|| PRIMARY_WALLET_LABEL.to_owned());
        Self::defer_wallet_name_input(label, window, cx);
    }

    fn defer_wallet_name_input(value: String, window: &Window, cx: &mut Context<'_, Self>) {
        cx.defer_in(window, move |root, window, cx| {
            root.set_wallet_name_input(&value, window, cx);
        });
    }

    pub(super) fn select_wallet(
        &mut self,
        wallet_id: &str,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        if self.selected_wallet_id.as_deref() == Some(wallet_id) {
            return;
        }
        window.close_all_dialogs(cx);
        self.switch_active_wallet(wallet_id, window, cx);
    }

    pub(super) fn open_add_wallet_dialog(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        window.close_all_dialogs(cx);
        self.generated_seed = None;
        self.vault_error = None;
        self.wallet_setup_mode = WalletSetupMode::Choose;
        let label = default_wallet_label_for_metadata(&self.wallet_metadata);
        let root = cx.entity();
        let dialog_width = (window.viewport_size().width * 0.92).min(px(520.0));
        let content_width = secondary_dialog_content_width(dialog_width);
        let content = cx.new(|cx| AddWalletDialogContent::new(root, content_width, cx));
        window.open_dialog(cx, move |dialog, _window, _cx| {
            dialog
                .w(dialog_width)
                .title(app_strong_text("Add wallet"))
                .child(content.clone())
        });
        cx.defer_in(window, move |root, window, cx| {
            root.set_wallet_name_input(&label, window, cx);
            root.add_wallet_password_input
                .update(cx, |input, cx| input.set_value("", window, cx));
        });
    }

    fn switch_active_wallet(
        &mut self,
        wallet_id: &str,
        window: &Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(store) = self.vault_store.clone() else {
            self.set_vault_error("Wallet vault storage is unavailable", cx);
            return;
        };
        let Some(current_session) = self.view_session.clone() else {
            self.set_vault_error("Wallet vault is locked", cx);
            return;
        };

        let current_wallet_id: Arc<str> = Arc::from(current_session.wallet_id().to_owned());
        let active_wallet_generation = self.active_wallet_generation;
        self.wallet_switch_generation = self.wallet_switch_generation.wrapping_add(1);
        let switch_generation = self.wallet_switch_generation;
        self.vault_error = None;
        let wallet_id_string = wallet_id.to_owned();
        let metadata = self.wallet_metadata.clone();
        let join = self.runtime.spawn_blocking(move || {
            store.load_view_session_with_view_session(current_session.as_ref(), &wallet_id_string)
        });
        cx.spawn_in(window, async move |this, cx| {
            let result = join.await;
            let _ = this.update_in(cx, |root, window, cx| {
                if root.wallet_switch_generation != switch_generation
                    || !root.is_active_wallet_generation(
                        current_wallet_id.as_ref(),
                        active_wallet_generation,
                    )
                {
                    return;
                }
                match result {
                    Ok(Ok(session)) => root.install_view_session(session, metadata, window, cx),
                    Ok(Err(error)) => {
                        root.handle_vault_error(&error, cx);
                        root.sync_wallet_select(window, cx);
                    }
                    Err(error) => {
                        root.set_vault_error(
                            format!("Failed to switch wallet: {error}").as_str(),
                            cx,
                        );
                        root.sync_wallet_select(window, cx);
                    }
                }
            });
        })
        .detach();
        cx.notify();
    }

    #[allow(dead_code)]
    fn deactivate_wallet_and_switch(
        &mut self,
        wallet_id: &str,
        password: &str,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(store) = self.vault_store.clone() else {
            self.set_vault_error("Wallet vault storage is unavailable", cx);
            return;
        };
        if let Err(error) = store.deactivate_wallet(password, wallet_id) {
            self.handle_vault_error(&error, cx);
            return;
        }
        let metadata = match store.list_wallet_metadata(password) {
            Ok(metadata) => metadata,
            Err(error) => {
                self.handle_vault_error(&error, cx);
                return;
            }
        };
        self.wallet_metadata.clone_from(&metadata);
        self.wallet_options = wallet_options_from_metadata(metadata.clone());

        if self.selected_wallet_id.as_deref() != Some(wallet_id) {
            self.sync_wallet_select(window, cx);
            cx.notify();
            return;
        }

        let Some(next_wallet_id) = self
            .wallet_options
            .first()
            .map(|option| Arc::clone(&option.wallet_id))
        else {
            self.set_vault_error("No active wallet remains after deactivation", cx);
            return;
        };
        match store.load_view_session(password, next_wallet_id.as_ref()) {
            Ok(session) => self.install_view_session(session, metadata, window, cx),
            Err(error) => self.handle_vault_error(&error, cx),
        }
    }

    pub(super) fn focus_vault_input_if_requested(
        &mut self,
        window: &mut Window,
        cx: &Context<'_, Self>,
    ) {
        if !self.focus_vault_input_on_render {
            return;
        }

        match self.vault_state {
            VaultState::CreateVault => self
                .new_password_input
                .read(cx)
                .focus_handle(cx)
                .focus(window),
            VaultState::UnlockVault => self
                .unlock_password_input
                .read(cx)
                .focus_handle(cx)
                .focus(window),
            VaultState::SetupWallet if self.wallet_setup_mode == WalletSetupMode::Import => self
                .import_mnemonic_input
                .read(cx)
                .focus_handle(cx)
                .focus(window),
            VaultState::SetupWallet | VaultState::ViewUnlocked | VaultState::Error(_) => {}
        }
        self.focus_vault_input_on_render = false;
    }

    pub(super) fn create_vault_from_inputs(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(store) = self.vault_store.as_ref() else {
            self.set_vault_error("Wallet vault storage is unavailable", cx);
            return;
        };
        let password = Self::read_and_clear_input(&self.new_password_input, window, cx);
        let confirm = Self::read_and_clear_input(&self.confirm_password_input, window, cx);

        if password.trim().is_empty() {
            self.set_vault_error("Enter a vault password to continue", cx);
            return;
        }
        if password.as_str() != confirm.as_str() {
            self.set_vault_error("Vault passwords do not match", cx);
            return;
        }

        match store.create_vault(password.as_str()) {
            Ok(_) => {
                Self::defer_wallet_name_input(PRIMARY_WALLET_LABEL.to_owned(), window, cx);
                self.setup_password = Some(password);
                self.vault_error = None;
                self.vault_state = VaultState::SetupWallet;
                self.wallet_setup_mode = WalletSetupMode::Choose;
                cx.notify();
            }
            Err(VaultError::VaultAlreadyExists) => {
                self.vault_state = VaultState::UnlockVault;
                self.focus_vault_input_on_render = true;
                self.set_vault_error("A wallet vault already exists. Unlock it to continue.", cx);
            }
            Err(error) => self.handle_vault_error(&error, cx),
        }
    }

    pub(super) fn unlock_vault_from_input(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        if self.unlock_in_progress {
            return;
        }
        let Some(store) = self.vault_store.as_ref() else {
            self.set_vault_error("Wallet vault storage is unavailable", cx);
            return;
        };
        let password = Self::read_and_clear_input(&self.unlock_password_input, window, cx);
        if password.trim().is_empty() {
            self.set_vault_error("Enter the vault password to continue", cx);
            return;
        }

        let store = Arc::clone(store);
        self.unlock_in_progress = true;
        self.vault_error = None;
        cx.notify();

        let join = self.runtime.spawn_blocking(move || {
            let metadata = store.list_wallet_metadata(password.as_str())?;
            let active = wallet_options_from_metadata(metadata.clone());
            let Some(wallet_id) = active.first().map(|option| option.wallet_id.to_string()) else {
                return Ok((None, metadata, password));
            };
            let session = store.load_view_session(password.as_str(), &wallet_id)?;
            Ok((Some(session), metadata, password))
        });
        cx.spawn_in(window, async move |this, cx| {
            let result = join.await;
            let _ = this.update_in(cx, |root, window, cx| {
                root.unlock_in_progress = false;
                match result {
                    Ok(Ok((Some(session), metadata, _password))) => {
                        root.enter_view_unlocked(session, metadata, window, cx);
                    }
                    Ok(Ok((None, _metadata, password))) => {
                        root.set_default_wallet_name_from_password(password.as_str(), window, cx);
                        root.setup_password = Some(password);
                        root.vault_error = None;
                        root.vault_state = VaultState::SetupWallet;
                        root.wallet_setup_mode = WalletSetupMode::Choose;
                        cx.notify();
                    }
                    Ok(Err(error)) => {
                        root.focus_vault_input_on_render = true;
                        root.handle_vault_error(&error, cx);
                    }
                    Err(error) => {
                        tracing::warn!(%error, "desktop wallet vault unlock task failed");
                        root.focus_vault_input_on_render = true;
                        root.set_vault_error(
                            "Unlock failed. Check the password and try again.",
                            cx,
                        );
                    }
                }
            });
        })
        .detach();
    }

    pub(super) fn choose_generated_wallet(&mut self, cx: &mut Context<'_, Self>) {
        match generate_seed_material() {
            Ok(seed) => {
                self.generated_seed = Some(seed);
                self.vault_error = None;
                self.wallet_setup_mode = WalletSetupMode::GeneratedReview;
                cx.notify();
            }
            Err(error) => self.handle_vault_error(&error, cx),
        }
    }

    pub(super) fn choose_import_wallet(&mut self, window: &Window, cx: &mut Context<'_, Self>) {
        self.generated_seed = None;
        self.vault_error = None;
        self.wallet_setup_mode = WalletSetupMode::Import;
        cx.notify();
        cx.defer_in(window, |root, window, cx| {
            if root.wallet_setup_mode == WalletSetupMode::Import {
                root.import_mnemonic_input
                    .read(cx)
                    .focus_handle(cx)
                    .focus(window);
            }
        });
    }

    pub(super) fn back_to_wallet_setup_choice(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        self.generated_seed = None;
        self.import_mnemonic_input
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.vault_error = None;
        self.wallet_setup_mode = WalletSetupMode::Choose;
        cx.notify();
    }

    fn wallet_creation_password(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) -> Option<Zeroizing<String>> {
        if matches!(self.vault_state, VaultState::ViewUnlocked) {
            let password = Self::read_and_clear_input(&self.add_wallet_password_input, window, cx);
            if password.trim().is_empty() {
                self.set_vault_error("Enter the vault password to add a wallet", cx);
                return None;
            }
            return Some(password);
        }
        let Some(password) = self.setup_password.as_ref() else {
            self.set_vault_error("Unlock the wallet vault before adding a wallet", cx);
            return None;
        };
        Some(Zeroizing::new(password.to_string()))
    }

    fn wallet_name_from_input(&self, cx: &Context<'_, Self>) -> String {
        self.wallet_name_input.read(cx).value().to_string()
    }

    pub(super) fn store_generated_wallet(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let wallet_id = match generate_opaque_id() {
            Ok(wallet_id) => wallet_id,
            Err(error) => {
                self.handle_vault_error(&error, cx);
                return;
            }
        };
        let label = self.wallet_name_from_input(cx);
        let Some(password) = self.wallet_creation_password(window, cx) else {
            return;
        };
        let result = {
            let Some(store) = self.vault_store.as_ref() else {
                self.set_vault_error("Wallet vault storage is unavailable", cx);
                return;
            };
            let Some(seed) = self.generated_seed.as_ref() else {
                self.set_vault_error("Generate a recovery phrase before creating the wallet", cx);
                return;
            };
            let metadata = store.new_wallet_metadata(
                password.as_str(),
                &wallet_id,
                0,
                WalletSource::Generated,
                &label,
            );
            let metadata = match metadata {
                Ok(metadata) => metadata,
                Err(error) => return self.handle_vault_error(&error, cx),
            };
            store
                .store_generated_wallet_with_metadata(
                    password.as_str(),
                    &wallet_id,
                    0,
                    "english",
                    seed,
                    &metadata,
                )
                .and_then(|_| {
                    let metadata = store.list_wallet_metadata(password.as_str())?;
                    let session = store.load_view_session(password.as_str(), &wallet_id)?;
                    Ok((session, metadata))
                })
        };

        match result {
            Ok((session, metadata)) => self.enter_view_unlocked(session, metadata, window, cx),
            Err(error) => self.handle_vault_error(&error, cx),
        }
    }

    pub(super) fn store_imported_wallet(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let mnemonic = Self::read_and_clear_input(&self.import_mnemonic_input, window, cx);
        if mnemonic.trim().is_empty() {
            self.set_vault_error("Paste a recovery phrase to import", cx);
            return;
        }
        let wallet_id = match generate_opaque_id() {
            Ok(wallet_id) => wallet_id,
            Err(error) => {
                self.handle_vault_error(&error, cx);
                return;
            }
        };
        let label = self.wallet_name_from_input(cx);
        let Some(password) = self.wallet_creation_password(window, cx) else {
            return;
        };

        let result = {
            let Some(store) = self.vault_store.as_ref() else {
                self.set_vault_error("Wallet vault storage is unavailable", cx);
                return;
            };
            let metadata = store.new_wallet_metadata(
                password.as_str(),
                &wallet_id,
                0,
                WalletSource::Imported,
                &label,
            );
            let metadata = match metadata {
                Ok(metadata) => metadata,
                Err(error) => return self.handle_vault_error(&error, cx),
            };
            store
                .import_wallet_mnemonic_with_metadata(
                    password.as_str(),
                    &wallet_id,
                    0,
                    "english",
                    mnemonic.as_str(),
                    &metadata,
                )
                .and_then(|_| {
                    let metadata = store.list_wallet_metadata(password.as_str())?;
                    let session = store.load_view_session(password.as_str(), &wallet_id)?;
                    Ok((session, metadata))
                })
        };

        match result {
            Ok((session, metadata)) => self.enter_view_unlocked(session, metadata, window, cx),
            Err(error) => self.handle_vault_error(&error, cx),
        }
    }

    fn install_view_session(
        &mut self,
        session: DesktopViewSession,
        metadata: Vec<WalletMetadataBundle>,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let session = Arc::new(session);
        let wallet_id: Arc<str> = Arc::from(session.wallet_id().to_owned());
        window.close_all_dialogs(cx);
        self.active_wallet_generation = self.active_wallet_generation.wrapping_add(1);
        self.view_session = Some(session);
        self.wallet_metadata = metadata;
        self.wallet_options = wallet_options_from_metadata(self.wallet_metadata.clone());
        self.selected_wallet_id = Some(wallet_id);
        self.sync_wallet_select(window, cx);
        self.reset_wallet_scoped_state(cx);
        self.reload_public_accounts(window, cx);
        self.setup_password = None;
        self.generated_seed = None;
        self.add_wallet_password_input
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.import_mnemonic_input
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.vault_error = None;
        self.vault_state = VaultState::ViewUnlocked;
        self.wallet_setup_mode = WalletSetupMode::Choose;
        self.ensure_chain_load(self.selected_chain, cx);
        cx.notify();
    }

    #[allow(clippy::needless_pass_by_ref_mut)]
    fn sync_wallet_select(&mut self, window: &mut Window, cx: &mut Context<'_, Self>) {
        let items: Vec<_> = self
            .wallet_options
            .iter()
            .map(|option| WalletSelectItem {
                wallet_id: Arc::clone(&option.wallet_id),
                label: Arc::clone(&option.label),
            })
            .collect();
        let selected_wallet_id = self.selected_wallet_id.clone();
        self.wallet_select.update(cx, |select, cx| {
            select.set_items(SearchableVec::new(items), window, cx);
            if let Some(wallet_id) = selected_wallet_id.as_ref() {
                select.set_selected_value(wallet_id, window, cx);
            } else {
                select.set_selected_index(None, window, cx);
            }
        });
    }

    fn enter_view_unlocked(
        &mut self,
        session: DesktopViewSession,
        metadata: Vec<WalletMetadataBundle>,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        self.install_view_session(session, metadata, window, cx);
    }

    pub(super) fn lock_vault(&mut self, window: &mut Window, cx: &mut Context<'_, Self>) {
        if let Some(store) = self.session_store.get().cloned() {
            self.runtime.spawn(async move {
                store.shutdown().await;
            });
        }
        window.close_all_dialogs(cx);
        self.view_session = None;
        self.wallet_metadata.clear();
        self.wallet_options.clear();
        self.selected_wallet_id = None;
        self.active_wallet_generation = self.active_wallet_generation.wrapping_add(1);
        self.sync_wallet_select(window, cx);
        self.send_forms.clear();
        self.unshield_forms.clear();
        self.reset_public_wallet_state(window, cx);
        self.private_action_form = None;
        self.private_broadcaster_progress = None;
        self.broadcaster_picker = None;
        self.active_wallet_tab = WalletTab::default();
        self.setup_password = None;
        self.generated_seed = None;
        self.vault_error = None;
        self.repair_cache_error = None;
        self.vault_state = VaultState::UnlockVault;
        self.wallet_setup_mode = WalletSetupMode::Choose;
        self.session_store = Arc::new(tokio::sync::OnceCell::new());
        self.focus_vault_input_on_render = true;
        for state in self.chain_states.values_mut() {
            *state = ChainUtxoState::Idle;
        }
        self.sync_utxo_table(cx);
        cx.notify();
    }

    pub(super) fn read_and_clear_input(
        input: &Entity<InputState>,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) -> Zeroizing<String> {
        let value = Zeroizing::new(input.read(cx).value().to_string());
        input.update(cx, |input, cx| input.set_value("", window, cx));
        value
    }

    fn handle_vault_error(&mut self, error: &VaultError, cx: &mut Context<'_, Self>) {
        tracing::warn!(
            error_kind = vault_error_kind(error),
            "desktop wallet vault operation failed"
        );
        let message: Arc<str> = match error {
            VaultError::UnlockFailed => "Unlock failed. Check the password and try again.".into(),
            VaultError::Key(_) => "Invalid recovery phrase. Paste it again to retry.".into(),
            VaultError::VaultNotFound => {
                "Wallet vault not found. Create a new vault to continue.".into()
            }
            _ => "Wallet vault operation failed. See logs for non-sensitive diagnostics.".into(),
        };
        self.set_vault_error(message, cx);
    }

    fn set_vault_error(&mut self, message: impl Into<Arc<str>>, cx: &mut Context<'_, Self>) {
        self.vault_error = Some(message.into());
        cx.notify();
    }
}
