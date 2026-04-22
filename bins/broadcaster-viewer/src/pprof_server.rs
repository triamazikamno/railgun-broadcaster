//! Diagnostic CPU-profiling HTTP endpoint.
//!
//! - `GET /debug/pprof/profile?seconds=N&frequency=N` with `Accept: text/html`
//!   or `Accept: image/svg+xml` returns a flamegraph SVG (open in browser).
//! - Any other Accept returns a protobuf pprof profile, consumable by
//!   `go tool pprof http://.../debug/pprof/profile`.

use axum::Router;
use axum::body::Body;
use axum::extract::Query;
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use eyre::{Result, WrapErr};
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio::time::{self, Duration};
use tracing::info;

#[derive(Debug, Default, Deserialize)]
struct ProfileParams {
    seconds: Option<u64>,
    frequency: Option<i32>,
}

/// Build and serve the pprof router on `addr` until the task is dropped.
pub(crate) async fn start(addr: &str) -> Result<()> {
    let router = Router::new().route("/debug/pprof/profile", get(profile));
    let listener = TcpListener::bind(addr)
        .await
        .wrap_err_with(|| format!("bind pprof listener on {addr}"))?;
    info!(
        addr,
        "pprof endpoint listening; open http://{addr}/debug/pprof/profile in a browser"
    );
    axum::serve(listener, router)
        .await
        .wrap_err("pprof axum server exited")?;
    Ok(())
}

async fn profile(req: Request<Body>) -> impl IntoResponse {
    use ::pprof::protos::Message;

    let params: Query<ProfileParams> = Query(
        serde_urlencoded::from_str(req.uri().query().unwrap_or_default()).unwrap_or_default(),
    );

    let report =
        match dump_rsprof(params.seconds.unwrap_or(10), params.frequency.unwrap_or(99)).await {
            Ok(report) => report,
            Err(error) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Response::new(Body::from(format!("failed to create report: {error:?}"))),
                );
            }
        };

    let mut body: Vec<u8> = Vec::new();
    let wants_svg = req
        .headers()
        .get_all("Accept")
        .iter()
        .flat_map(|i| i.to_str().unwrap_or_default().split(','))
        .any(|i| i.trim() == "text/html" || i.trim() == "image/svg+xml");

    if wants_svg {
        if let Err(error) = report.flamegraph(&mut body) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Response::new(Body::from(format!(
                    "failed to create flamegraph: {error:?}"
                ))),
            );
        }
    } else {
        match report.pprof() {
            Ok(profile) => {
                if let Err(error) = profile.encode(&mut body) {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Response::new(Body::from(format!(
                            "failed to encode pprof report: {error:?}"
                        ))),
                    );
                }
            }
            Err(error) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Response::new(Body::from(format!(
                        "failed to create pprof report: {error:?}"
                    ))),
                );
            }
        }
    }
    (StatusCode::OK, Response::new(Body::from(body)))
}

async fn dump_rsprof(seconds: u64, frequency: i32) -> pprof::Result<pprof::Report> {
    let guard = pprof::ProfilerGuardBuilder::default()
        .frequency(frequency)
        .blocklist(&[
            "libc",
            "libgcc",
            "pthread",
            "vdso",
            "libunwind",
            "backtrace",
        ])
        .build()?;
    info!(
        seconds,
        frequency, "pprof: start sampling for {seconds}s at {frequency} Hz"
    );

    time::sleep(Duration::from_secs(seconds)).await;

    info!(
        seconds,
        frequency, "pprof: sampling complete, building report"
    );
    guard.report().build()
}
