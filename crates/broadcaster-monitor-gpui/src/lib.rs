// Hex color literals are intentionally written `0xRRGGBB` style.
#![allow(clippy::unreadable_literal)]

mod fees_view;
mod peers_view;
mod root;

pub use root::{BroadcasterMonitorPane, open_monitor_window};
