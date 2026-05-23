use gpui::{App, KeyBinding};

use super::TABLE_KEY_CONTEXT;

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

pub(crate) fn install_utxo_navigation_bindings(app: &mut App) {
    app.bind_keys([
        KeyBinding::new("pageup", UtxoPageUp, Some(TABLE_KEY_CONTEXT)),
        KeyBinding::new("pagedown", UtxoPageDown, Some(TABLE_KEY_CONTEXT)),
        KeyBinding::new("home", UtxoHome, Some(TABLE_KEY_CONTEXT)),
        KeyBinding::new("end", UtxoEnd, Some(TABLE_KEY_CONTEXT)),
    ]);
}
