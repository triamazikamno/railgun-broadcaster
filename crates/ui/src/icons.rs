use std::path::PathBuf;

#[must_use]
pub fn logs_icon_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("assets")
        .join("icons")
        .join("logs.svg")
}

#[must_use]
pub fn activity_icon_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("assets")
        .join("icons")
        .join("activity.svg")
}

#[must_use]
pub fn close_icon_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("assets")
        .join("icons")
        .join("close.svg")
}

#[must_use]
pub fn search_icon_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("assets")
        .join("icons")
        .join("search.svg")
}

#[must_use]
pub fn wallet_icon_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("assets")
        .join("icons")
        .join("wallet.svg")
}

#[must_use]
pub fn shield_check_icon_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("assets")
        .join("icons")
        .join("shield-check.svg")
}

#[must_use]
pub fn globe_icon_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("assets")
        .join("icons")
        .join("globe.svg")
}

#[must_use]
pub fn wrench_icon_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("assets")
        .join("icons")
        .join("wrench.svg")
}

#[must_use]
pub fn lock_icon_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("assets")
        .join("icons")
        .join("lock.svg")
}

#[must_use]
pub fn robot_icon_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("assets")
        .join("icons")
        .join("robot.svg")
}

#[must_use]
pub fn refresh_ccw_icon_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("assets")
        .join("icons")
        .join("refresh-ccw.svg")
}
