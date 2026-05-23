use std::collections::HashMap;

use gpui::{App, Entity, Global, KeyBinding, WeakEntity, Window, WindowId};

use super::TABLE_KEY_CONTEXT;
use super::startup::WalletStartupRoot;

#[derive(Clone, Debug, Default, Eq, PartialEq, gpui::Action)]
#[action(no_json)]
pub(crate) struct UtxoPageUp;

#[derive(Clone, Debug, Default, Eq, PartialEq, gpui::Action)]
#[action(no_json)]
pub(crate) struct UtxoPageDown;

#[derive(Clone, Debug, Default, Eq, PartialEq, gpui::Action)]
#[action(no_json)]
pub(crate) struct UtxoHome;

#[derive(Clone, Debug, Default, Eq, PartialEq, gpui::Action)]
#[action(no_json)]
pub(crate) struct UtxoEnd;

#[derive(Clone, Debug, Default, Eq, PartialEq, gpui::Action)]
#[action(no_json)]
pub(crate) struct OpenSettings;

#[derive(Clone, Debug, Default, Eq, PartialEq, gpui::Action)]
#[action(no_json)]
pub(crate) struct LockVault;

#[derive(Default)]
struct WalletShortcutRegistry {
    roots_by_window: HashMap<WindowId, WeakEntity<WalletStartupRoot>>,
}

impl Global for WalletShortcutRegistry {}

#[derive(Clone, Copy)]
enum WalletShortcutAction {
    OpenSettings,
    LockVault,
}

pub(crate) fn install_wallet_action_bindings(app: &mut App) {
    app.bind_keys([
        KeyBinding::new("cmd-,", OpenSettings, None),
        KeyBinding::new("cmd-l", LockVault, None),
    ]);
    app.on_action(|_: &OpenSettings, cx| {
        dispatch_wallet_shortcut(WalletShortcutAction::OpenSettings, cx);
    });
    app.on_action(|_: &LockVault, cx| {
        dispatch_wallet_shortcut(WalletShortcutAction::LockVault, cx);
    });
}

pub(super) fn register_wallet_shortcut_root(
    window: &Window,
    root: &Entity<WalletStartupRoot>,
    cx: &mut App,
) {
    let window_id = window.window_handle().window_id();
    cx.default_global::<WalletShortcutRegistry>()
        .roots_by_window
        .insert(window_id, root.downgrade());
}

fn dispatch_wallet_shortcut(action: WalletShortcutAction, cx: &mut App) {
    let Some(window_handle) = cx.active_window() else {
        return;
    };
    let window_id = window_handle.window_id();
    let Some(root) = cx
        .try_global::<WalletShortcutRegistry>()
        .and_then(|registry| registry.roots_by_window.get(&window_id))
        .and_then(WeakEntity::upgrade)
    else {
        return;
    };

    cx.defer(move |cx| {
        let _ = window_handle.update(cx, |_, window, cx| {
            root.update(cx, |root, cx| match action {
                WalletShortcutAction::OpenSettings => root.open_settings_from_shortcut(window, cx),
                WalletShortcutAction::LockVault => root.lock_vault_from_shortcut(window, cx),
            });
        });
    });
}

pub(crate) fn install_utxo_navigation_bindings(app: &mut App) {
    app.bind_keys([
        KeyBinding::new("pageup", UtxoPageUp, Some(TABLE_KEY_CONTEXT)),
        KeyBinding::new("pagedown", UtxoPageDown, Some(TABLE_KEY_CONTEXT)),
        KeyBinding::new("home", UtxoHome, Some(TABLE_KEY_CONTEXT)),
        KeyBinding::new("end", UtxoEnd, Some(TABLE_KEY_CONTEXT)),
    ]);
}
