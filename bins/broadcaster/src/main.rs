use broadcaster_core::crypto::snark_proof::Prover;
mod admin;

use broadcaster_service::{BroadcasterManager, BroadcasterService};
use config::Config;
use eyre::{Result, WrapErr, bail, eyre};
use local_db::{DbConfig, DbStore};
use poi::poi::{Poi, PoiRpcClient};
use railgun_wallet::ProverService;
use railgun_wallet::artifacts::ArtifactSource;
use std::fs;
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::sync::Arc;
use structopt::StructOpt;
use sync_service::SyncManager;
use tracing::metadata::LevelFilter;
use tracing::{Instrument, error, info};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};
use waku_relay::client::Client;

#[derive(StructOpt)]
#[structopt(name = "main")]
struct Options {
    #[structopt(short, long)]
    pub cfg: PathBuf,
    #[structopt(short, long)]
    pub debug_log: Option<PathBuf>,
    #[structopt(long)]
    pub debug_level: Option<String>,
}

const DEFAULT_DEBUG_LEVEL: &str = "info,railgun=debug,waku_relay=debug,broadcaster_service=debug";

#[tokio::main]
async fn main() -> Result<()> {
    let opt: Options = Options::from_args();

    let (console_non_blocking, _console_guard) = tracing_appender::non_blocking(std::io::stdout());
    let debug_log = opt
        .debug_log
        .map(|path| {
            OpenOptions::new()
                .read(true)
                .append(true)
                .create(true)
                .open(path)
                .wrap_err("open debug log for writing")
        })
        .transpose()?
        .map(tracing_appender::non_blocking);
    tracing_subscriber::registry()
        .with(debug_log.as_ref().map(|(handle, _)| {
            let debug_level = opt.debug_level.as_deref().unwrap_or(DEFAULT_DEBUG_LEVEL);
            let filter = EnvFilter::builder()
                .parse(debug_level)
                .unwrap_or_else(|error| {
                    println!("failed to build debug log filter: {error:?}, using default: {DEFAULT_DEBUG_LEVEL}");
                    EnvFilter::builder()
                        .parse(DEFAULT_DEBUG_LEVEL)
                        .unwrap_or_else(|_| EnvFilter::builder().from_env_lossy())
                });
            tracing_logfmt::builder()
                .with_span_name(false)
                .with_span_path(true)
                .with_level(false)
                .with_target(false)
                .with_timestamp(true)
                .layer()
                .with_writer(handle.clone())
                .with_filter(filter)
        }))
        .with(
            tracing_subscriber::fmt::layer()
                // .without_time()
                .with_target(false)
                .with_ansi(true)
                .with_writer(console_non_blocking)
                .with_filter(
                    EnvFilter::builder()
                        .with_default_directive(LevelFilter::INFO.into())
                        .from_env_lossy(),
                ),
        )
        .init();

    let cfg: Config = {
        let data = fs::read_to_string(&opt.cfg).wrap_err("read a config file")?;
        if opt
            .cfg
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        {
            serde_json::from_str(&data).wrap_err("parse config")?
        } else if opt
            .cfg
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("yaml"))
        {
            serde_yaml::from_str(&data).wrap_err("parse config")?
        } else {
            bail!("unsupported config file format");
        }
    };
    let db_dir = cfg.db_dir.clone().unwrap_or_else(|| PathBuf::from("db"));
    let db = Arc::new(DbStore::open(DbConfig { root_dir: db_dir }).wrap_err("open local db")?);
    let sync_manager = Arc::new(SyncManager::new(db.clone()));
    if let Some(admin_cfg) = cfg.admin.clone() {
        let sync_manager = sync_manager.clone();
        tokio::spawn(async move {
            if let Err(err) = admin::run(admin_cfg, sync_manager).await {
                error!(?err, "admin server failed");
            }
        });
    }

    let mut artifact_source = ArtifactSource::default();
    if let Some(path) = cfg.artifacts_metadata_dir.clone() {
        artifact_source = artifact_source
            .with_metadata_dir(path)
            .wrap_err("set artifacts metadata dir")?;
    }
    if let Some(path) = cfg.artifacts_cache_dir.clone() {
        artifact_source = artifact_source.with_cache_dir(path);
    }
    let prover = Arc::new(ProverService::new_with_db(artifact_source, db.clone()));

    let waku_client = Arc::new(Client::new(&cfg.waku).wrap_err("create waku relay client")?);
    let snark_prover = Arc::new(Prover::new().await.wrap_err("create snark prover")?);

    let poi_verifier = cfg.poi_rpc.as_ref().map(|poi_rpc| {
        Arc::new(Poi::new(
            PoiRpcClient::new(poi_rpc.clone()),
            snark_prover.clone(),
            cfg.required_poi_list.clone(),
        ))
    });
    let mut services = Vec::with_capacity(cfg.chains.len());
    for chain_cfg in cfg.chains.clone() {
        let chain_id = chain_cfg.chain_id;
        info!(chain_id, "starting broadcaster service");
        let service = BroadcasterService::new(
            chain_cfg,
            waku_client.clone(),
            poi_verifier.clone(),
            cfg.required_poi_list.clone(),
            sync_manager.clone(),
            prover.clone(),
            cfg.query_rpc_cooldown.into_inner(),
        )
        .instrument(tracing::info_span!("service", chain_id))
        .await
        .wrap_err(eyre!("init broadcaster service for chain={chain_id}"))?;
        info!(address=%service.addr(), chain_id, "derived address");

        service
            .update_prices()
            .await
            .wrap_err(eyre!("update prices failed for chain={chain_id}"))?;
        info!(address=%service.addr(), chain_id, "spawning workers");
        service.spawn_fees_publisher();
        service.spawn_tx_submitter();
        services.push(service);
    }

    let manager = BroadcasterManager::new(services, waku_client);
    Ok(manager.run().await?)
}
