// Hex color literals are intentionally written `0xRRGGBB` style.
#![allow(clippy::unreadable_literal)]

pub(crate) mod clipboard;
pub(crate) mod fees_view;
pub(crate) mod log_view;
pub(crate) mod peers_view;
pub(crate) mod root;
pub(crate) mod table_columns;
pub(crate) mod tokens;

pub(crate) use root::open_main_window;
