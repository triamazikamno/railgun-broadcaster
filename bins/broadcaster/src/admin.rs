use std::sync::Arc;

use axum::{
    Router,
    extract::{Json, State},
    http::{HeaderMap, StatusCode, header},
    routing::post,
};
use config::AdminConfig;
use eyre::{Result, WrapErr};
use serde::{Deserialize, Serialize};
use sync_service::SyncManager;
use sync_service::manager::SyncManagerError;
use tokio::net::TcpListener;
use tracing::info;

#[derive(Clone)]
struct AdminState {
    token: String,
    sync_manager: Arc<SyncManager>,
}

#[derive(Deserialize)]
struct ResetWalletRequest {
    cache_key: String,
    from_block: Option<u64>,
}

#[derive(Serialize)]
struct ResetWalletResponse {
    ok: bool,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

type HandlerResult<T> = std::result::Result<T, (StatusCode, Json<ErrorResponse>)>;

pub async fn run(cfg: AdminConfig, sync_manager: Arc<SyncManager>) -> Result<()> {
    let state = AdminState {
        token: cfg.token,
        sync_manager,
    };
    let app = Router::new()
        .route("/admin/reset-wallet", post(reset_wallet))
        .with_state(state);
    let listener = TcpListener::bind(&cfg.listen_addr)
        .await
        .wrap_err("bind admin listener")?;
    info!(addr = %cfg.listen_addr, "admin server listening");
    axum::serve(listener, app)
        .await
        .wrap_err("admin server failed")?;
    Ok(())
}

async fn reset_wallet(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(payload): Json<ResetWalletRequest>,
) -> HandlerResult<Json<ResetWalletResponse>> {
    if !is_authorized(&headers, &state.token) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "unauthorized".to_string(),
            }),
        ));
    }

    if payload.cache_key.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "cache_key is required".to_string(),
            }),
        ));
    }

    match state
        .sync_manager
        .reset_wallet(&payload.cache_key, payload.from_block)
        .await
    {
        Ok(()) => Ok(Json(ResetWalletResponse { ok: true })),
        Err(SyncManagerError::WalletNotFound) => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "wallet not found".to_string(),
            }),
        )),
        Err(err) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: err.to_string(),
            }),
        )),
    }
}

fn is_authorized(headers: &HeaderMap, token: &str) -> bool {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return false;
    };
    let Ok(value) = value.to_str() else {
        return false;
    };
    value
        .strip_prefix("Bearer ")
        .is_some_and(|provided| provided == token)
}
