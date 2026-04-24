use std::path::PathBuf;

#[must_use]
pub fn logs_icon_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("assets")
        .join("icons")
        .join("logs.svg")
}

#[must_use]
pub fn close_icon_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("assets")
        .join("icons")
        .join("close.svg")
}
