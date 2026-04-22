//! Shared click-to-copy behavior for the viewer UI.
//!
//! Every interactive cell that copies something should call [`copy_with_toast`]
//! so the clipboard write and the user-facing confirmation stay coupled.

use gpui::{App, ClipboardItem, Window};
use gpui_component::{WindowExt, notification::Notification};

const COPIED_MESSAGE: &str = "Copied to clipboard!";

/// Write `text` to the system clipboard and push a brief success toast to
/// the window's `NotificationList`. Intended to be called from `on_click`
/// closures on stateful elements.
pub(crate) fn copy_with_toast(text: impl Into<String>, window: &mut Window, cx: &mut App) {
    cx.write_to_clipboard(ClipboardItem::new_string(text.into()));
    window.push_notification(Notification::success(COPIED_MESSAGE), cx);
}
