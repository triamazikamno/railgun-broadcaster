use gpui::{
    Entity, IntoElement, ParentElement, SharedString, Styled, Window, div,
    prelude::FluentBuilder as _, px, rgb,
};
use gpui_component::{Disableable, IconName, WindowExt, button::ButtonVariants};
use ui::controls::{app_button, app_button_base, app_input, app_muted_text, app_strong_text};
use ui::theme::{self, APP_TEXT_SIZE};

use super::settings::settings_dialog_dimensions;
use super::shell::render_wallet_hero_screen;
use super::{VaultState, WalletRoot, WalletSetupMode, rgb_with_alpha};

impl WalletRoot {
    pub(super) const fn titlebar_color(&self) -> u32 {
        if matches!(self.vault_state, VaultState::ViewUnlocked) {
            theme::SURFACE
        } else {
            theme::BACKGROUND
        }
    }

    pub(super) fn render_locked_vault_screen(
        &self,
        root: Entity<Self>,
        window: &Window,
    ) -> gpui::Div {
        let card = self.render_vault_card(root.clone());
        render_wallet_hero_screen(window, card).when(
            should_show_pre_unlock_settings_action(&self.vault_state),
            |this| this.child(Self::render_pre_unlock_settings_gear(root)),
        )
    }

    pub(super) fn render_add_wallet_dialog_content(
        &self,
        root: Entity<Self>,
        content_width: gpui::Pixels,
    ) -> gpui::AnyElement {
        div()
            .w(content_width)
            .child(self.render_wallet_setup(root))
            .into_any_element()
    }

    const fn vault_dialog_title(&self) -> &'static str {
        match &self.vault_state {
            VaultState::CreateVault => "Create wallet vault",
            VaultState::UnlockVault => "Unlock wallet",
            VaultState::SetupWallet => match self.wallet_setup_mode {
                WalletSetupMode::Choose => "Add your first wallet",
                WalletSetupMode::GeneratedReview => "Save recovery phrase",
                WalletSetupMode::Import => "Import wallet",
            },
            VaultState::ViewUnlocked => "Wallet",
            VaultState::Error(_) => "Wallet vault unavailable",
        }
    }

    fn render_vault_dialog_content(&self, root: Entity<Self>) -> gpui::AnyElement {
        match &self.vault_state {
            VaultState::CreateVault => self.render_create_vault(root).into_any_element(),
            VaultState::UnlockVault => self.render_unlock_vault(root).into_any_element(),
            VaultState::SetupWallet => self.render_wallet_setup(root).into_any_element(),
            VaultState::ViewUnlocked => div().into_any_element(),
            VaultState::Error(message) => self.render_vault_fatal(message).into_any_element(),
        }
    }

    fn render_vault_card(&self, root: Entity<Self>) -> gpui::AnyElement {
        div()
            .w_full()
            .p(px(28.0))
            .flex()
            .flex_col()
            .gap_5()
            .rounded_lg()
            .border_1()
            .border_color(rgb(theme::BORDER_STRONG))
            .bg(rgb_with_alpha(theme::SURFACE_ELEVATED, 0.86))
            .child(
                app_strong_text(self.vault_dialog_title())
                    .text_size(px(22.0))
                    .line_height(px(28.0)),
            )
            .child(self.render_vault_dialog_content(root))
            .into_any_element()
    }

    fn render_pre_unlock_settings_gear(root: Entity<Self>) -> gpui::Div {
        div().absolute().right(px(24.0)).bottom(px(24.0)).child(
            app_button_base("pre-unlock-wallet-settings")
                .outline()
                .h(px(40.0))
                .w(px(40.0))
                .tooltip("Settings")
                .icon(IconName::Settings)
                .on_click(move |_event, window, cx| {
                    root.update(cx, |root, cx| {
                        root.open_pre_unlock_settings_dialog(window, cx);
                    });
                }),
        )
    }

    fn open_pre_unlock_settings_dialog(
        &self,
        window: &mut Window,
        cx: &mut gpui::Context<'_, Self>,
    ) {
        let (dialog_width, content_height, dialog_max_height) = settings_dialog_dimensions(window);
        let editor = self.settings_editor.clone();
        let settings_error = self.settings_error.clone();
        window.open_dialog(cx, move |dialog, _window, _cx| {
            let content = if let Some(editor) = editor.clone() {
                div()
                    .h(content_height)
                    .min_h(px(0.0))
                    .child(editor)
                    .into_any_element()
            } else {
                div()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(app_muted_text(
                        "Settings are stored in the selected wallet database and are readable before vault unlock.",
                    ))
                    .child(app_muted_text(settings_error.as_ref().map_or_else(
                        || "Settings are unavailable".to_string(),
                        ToString::to_string,
                    )))
                    .into_any_element()
            };
            dialog
                .w(dialog_width)
                .max_h(dialog_max_height)
                .margin_top(px(16.0))
                .title(app_strong_text("Settings"))
                .child(content)
        });
    }

    fn render_create_vault(&self, root: Entity<Self>) -> gpui::Div {
        let submit_root = root;
        let mut body = vault_dialog_body(
            "Choose one password for this desktop wallet vault. It will be required every time the app starts.",
        );
        if let Some(error) = self.render_vault_error() {
            body = body.child(error);
        }

        body.child(app_input(&self.new_password_input))
            .child(app_input(&self.confirm_password_input))
            .child(
                app_button("create-wallet-vault", "Create vault")
                    .primary()
                    .w_full()
                    .on_click(move |_event, window, cx| {
                        submit_root.update(cx, |root, cx| {
                            root.create_vault_from_inputs(window, cx);
                        });
                    }),
            )
            .child(
                div()
                    .text_size(APP_TEXT_SIZE)
                    .text_color(rgb(theme::TEXT_MUTED))
                    .child("No OS keychain or mnemonic startup argument is used in v1."),
            )
    }

    fn render_unlock_vault(&self, root: Entity<Self>) -> gpui::Div {
        let submit_root = root;
        let mut body =
            vault_dialog_body("Enter the vault password to view wallet balances and history.");
        if let Some(error) = self.render_vault_error() {
            body = body.child(error);
        }

        body.child(app_input(&self.unlock_password_input).disabled(self.unlock_in_progress))
            .child(
                app_button("unlock-wallet-vault", "Unlock vault")
                    .primary()
                    .w_full()
                    .loading(self.unlock_in_progress)
                    .disabled(self.unlock_in_progress)
                    .on_click(move |_event, window, cx| {
                        submit_root.update(cx, |root, cx| {
                            root.unlock_vault_from_input(window, cx);
                        });
                    }),
            )
    }

    fn render_wallet_setup(&self, root: Entity<Self>) -> gpui::AnyElement {
        match self.wallet_setup_mode {
            WalletSetupMode::Choose => self.render_wallet_setup_choice(root),
            WalletSetupMode::GeneratedReview => self.render_generated_wallet_review(root),
            WalletSetupMode::Import => self.render_import_wallet(root),
        }
    }

    fn render_wallet_setup_choice(&self, root: Entity<Self>) -> gpui::AnyElement {
        let generate_root = root.clone();
        let import_root = root;
        let mut body = vault_dialog_body(
            "Generate a new recovery phrase or import an existing one. Seed material will be encrypted into the vault.",
        );
        if let Some(error) = self.render_vault_error() {
            body = body.child(error);
        }

        body.child(
            app_button("generate-vault-wallet", "Generate new wallet")
                .primary()
                .w_full()
                .on_click(move |_event, _window, cx| {
                    generate_root.update(cx, |root, cx| {
                        root.choose_generated_wallet(cx);
                    });
                }),
        )
        .child(
            app_button("import-vault-wallet", "Import recovery phrase")
                .outline()
                .w_full()
                .on_click(move |_event, window, cx| {
                    import_root.update(cx, |root, cx| {
                        root.choose_import_wallet(window, cx);
                    });
                }),
        )
        .into_any_element()
    }

    fn render_generated_wallet_review(&self, root: Entity<Self>) -> gpui::AnyElement {
        let confirm_root = root.clone();
        let back_root = root;
        let phrase = self
            .generated_seed
            .as_ref()
            .map_or_else(String::new, |seed| seed.mnemonic.to_string());
        let mut body = vault_dialog_body(
            "Write this phrase down before continuing. It is shown once and then encrypted into the vault.",
        );
        if let Some(error) = self.render_vault_error() {
            body = body.child(error);
        }

        body = body.child(app_input(&self.wallet_name_input));
        if matches!(self.vault_state, VaultState::ViewUnlocked) {
            body = body.child(app_input(&self.add_wallet_password_input));
        }

        body.child(
            div()
                .w_full()
                .p(px(14.0))
                .rounded_md()
                .border_1()
                .border_color(rgb(theme::BORDER_STRONG))
                .bg(rgb(theme::SURFACE_ELEVATED))
                .text_color(rgb(theme::WARNING))
                .text_size(APP_TEXT_SIZE)
                .line_height(px(21.0))
                .child(SharedString::from(phrase)),
        )
        .child(
            app_button("confirm-generated-wallet", "I saved it, create wallet")
                .primary()
                .w_full()
                .on_click(move |_event, window, cx| {
                    confirm_root.update(cx, |root, cx| {
                        root.store_generated_wallet(window, cx);
                    });
                }),
        )
        .child(
            app_button("back-generated-wallet", "Back")
                .ghost()
                .w_full()
                .on_click(move |_event, window, cx| {
                    back_root.update(cx, |root, cx| {
                        root.back_to_wallet_setup_choice(window, cx);
                    });
                }),
        )
        .into_any_element()
    }

    fn render_import_wallet(&self, root: Entity<Self>) -> gpui::AnyElement {
        let import_root = root.clone();
        let back_root = root;
        let mut body = vault_dialog_body(
            "Paste the recovery phrase. The phrase is validated, converted to canonical entropy, and cleared from the input.",
        );
        if let Some(error) = self.render_vault_error() {
            body = body.child(error);
        }

        body.child(app_input(&self.wallet_name_input))
            .when(
                matches!(self.vault_state, VaultState::ViewUnlocked),
                |this| this.child(app_input(&self.add_wallet_password_input)),
            )
            .child(app_input(&self.import_mnemonic_input))
            .child(
                app_button("store-imported-wallet", "Import wallet")
                    .primary()
                    .w_full()
                    .on_click(move |_event, window, cx| {
                        import_root.update(cx, |root, cx| {
                            root.store_imported_wallet(window, cx);
                        });
                    }),
            )
            .child(
                app_button("back-import-wallet", "Back")
                    .ghost()
                    .w_full()
                    .on_click(move |_event, window, cx| {
                        back_root.update(cx, |root, cx| {
                            root.back_to_wallet_setup_choice(window, cx);
                        });
                    }),
            )
            .into_any_element()
    }

    fn render_vault_fatal(&self, message: &str) -> gpui::Div {
        let mut body = vault_dialog_body(SharedString::from(message.to_owned()));
        if let Some(error) = self.render_vault_error() {
            body = body.child(error);
        }
        body
    }

    fn render_vault_error(&self) -> Option<gpui::AnyElement> {
        self.vault_error.as_ref().map(|message| {
            div()
                .w_full()
                .p(px(10.0))
                .rounded_md()
                .bg(rgb(theme::DANGER_BG))
                .border_1()
                .border_color(rgb(theme::DANGER))
                .text_color(rgb(theme::DANGER))
                .text_size(APP_TEXT_SIZE)
                .child(SharedString::from(message.to_string()))
                .into_any_element()
        })
    }
}

pub(super) const fn should_show_pre_unlock_settings_action(vault_state: &VaultState) -> bool {
    !matches!(vault_state, VaultState::ViewUnlocked)
}

fn vault_dialog_body(subtitle: impl Into<SharedString>) -> gpui::Div {
    let subtitle = subtitle.into();
    div()
        .w_full()
        .flex()
        .flex_col()
        .gap_3()
        .child(app_muted_text(subtitle).line_height(px(18.0)))
}
