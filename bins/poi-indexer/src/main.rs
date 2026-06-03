use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use clap::Parser;
use ed25519_dalek::SigningKey;
use eyre::{Result, WrapErr, eyre};
use poi_indexer_core::audit::{Audit, Retention};
use poi_indexer_core::blocked::content_hash;
use poi_indexer_core::config::Config;
use poi_indexer_core::manifest::{
    ArtifactDescriptor, Manifest, ManifestEntry, load_publisher_signing_key,
};
use poi_indexer_core::publish::ipfs::{
    FilebaseIpfsClient, IpfsClient, MultiPinner, pin_blocked_shields, pin_manifest,
    pin_snapshot_file,
};
use poi_indexer_core::publish::ipns::{IpnsPublisher, IpnsPublisherConfig, IpnsPublisherTask};
use poi_indexer_core::scrape::Orchestrator;
use poi_indexer_core::snapshot::format::FORMAT_VERSION;
use poi_indexer_core::snapshot::{Lifecycle, SnapshotKind};
use poi_indexer_core::status::{SharedStatus, Status};
use poi_indexer_core::store::{Store, StoredPublication, run_migrations};
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

const FILEBASE_ACCESS_KEY_ENV: &str = "POI_INDEXER_FILEBASE_ACCESS_KEY";
const FILEBASE_SECRET_KEY_ENV: &str = "POI_INDEXER_FILEBASE_SECRET_KEY";
const FILEBASE_BUCKET_ENV: &str = "POI_INDEXER_FILEBASE_BUCKET";
const FILEBASE_REGION: &str = "us-east-1";
const FILEBASE_KEY_PREFIX: &str = "poi-indexer";
const EVM_CHAIN_TYPE: u8 = 0;
const RETENTION_SWEEP_INTERVAL_CAP: Duration = Duration::from_secs(10 * 60);

#[derive(Debug, Parser)]
#[command(name = "poi-indexer")]
struct Options {
    #[arg(long, env = "POI_INDEXER_CONFIG")]
    config: PathBuf,
    #[arg(
        long,
        env = "POI_INDEXER_STATUS_BIND_ADDR",
        default_value = "127.0.0.1:8080"
    )]
    status_bind_addr: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let options = Options::parse();
    let config = load_config(&options.config).wrap_err("load config")?;
    let pool = config
        .connect_postgres()
        .await
        .wrap_err("validate config")?;
    run_migrations(&pool)
        .await
        .wrap_err("run database migrations")?;
    let store = Store::new(pool.clone());
    let status =
        Status::for_pairs(&config.list_keys, &config.chain_ids, config.page_size_max).shared();
    let orchestrator = Orchestrator::from_config(&config, store.clone())
        .wrap_err("initialize scraper orchestrator")?
        .with_status(status.clone());
    let publisher_key = load_publisher_signing_key(&config.publisher_signing_key_path)
        .wrap_err("load publisher signing key")?;
    let ipfs_pinner = init_ipfs_pinner(&config).wrap_err("initialize IPFS pinner")?;
    let ipns_config =
        IpnsPublisherConfig::from_indexer_config(&config).wrap_err("initialize IPNS config")?;
    let (ipns_publisher, ipns_task) =
        IpnsPublisher::new(&publisher_key, ipns_config).wrap_err("initialize IPNS publisher")?;
    let status_listener = TcpListener::bind(options.status_bind_addr)
        .await
        .wrap_err("bind status HTTP listener")?;
    info!(
        upstream_url = %config.upstream_url,
        chain_count = config.chain_ids.len(),
        list_count = config.list_keys.len(),
        "loaded poi indexer config"
    );

    run_background_tasks(
        config,
        store,
        orchestrator,
        publisher_key,
        ipfs_pinner,
        ipns_publisher,
        ipns_task,
        status_listener,
        status,
    )
    .await
}

fn load_config(path: &PathBuf) -> Result<Config> {
    let data = fs::read_to_string(path).wrap_err("read config file")?;
    serde_yaml::from_str(&data).wrap_err("parse yaml config")
}

fn init_ipfs_pinner(config: &Config) -> Result<Arc<dyn IpfsClient>> {
    let access_key = required_env(FILEBASE_ACCESS_KEY_ENV)?;
    let secret_key = required_env(FILEBASE_SECRET_KEY_ENV)?;
    let bucket = required_env(FILEBASE_BUCKET_ENV)?;
    let client: Arc<dyn IpfsClient> = Arc::new(
        FilebaseIpfsClient::with_endpoint(
            access_key,
            secret_key,
            bucket,
            config.ipfs_endpoint.clone(),
            FILEBASE_REGION,
            FILEBASE_KEY_PREFIX,
        )
        .wrap_err("build Filebase IPFS client")?,
    );
    let pinner = MultiPinner::new(vec![client], 1).wrap_err("build quorum pinner")?;

    Ok(Arc::new(pinner))
}

fn required_env(name: &str) -> Result<String> {
    env::var(name).wrap_err_with(|| format!("read {name}"))
}

async fn run_background_tasks(
    config: Config,
    store: Store,
    orchestrator: Orchestrator,
    publisher_key: SigningKey,
    ipfs_pinner: Arc<dyn IpfsClient>,
    ipns_publisher: IpnsPublisher,
    ipns_task: IpnsPublisherTask,
    status_listener: TcpListener,
    status: SharedStatus,
) -> Result<()> {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut tasks = JoinSet::new();

    tasks.spawn({
        let shutdown = shutdown_rx.clone();
        async move {
            ipns_task
                .run(shutdown)
                .await
                .wrap_err("IPNS publisher task")
        }
    });
    tasks.spawn({
        let orchestrator = orchestrator.clone();
        let shutdown = shutdown_rx.clone();
        let idle_interval = *config.polite_interval;
        async move {
            run_scraper_loop(orchestrator, idle_interval, shutdown)
                .await
                .wrap_err("scraper orchestrator task")
        }
    });
    tasks.spawn({
        let orchestrator = orchestrator.clone();
        let shutdown = shutdown_rx.clone();
        async move {
            orchestrator
                .run_blocked_shield_resync_loop_or_shutdown(shutdown)
                .await
                .wrap_err("blocked-shield resync task")
        }
    });
    tasks.spawn({
        let scheduler = PublicationScheduler::new(
            config.clone(),
            store.clone(),
            ipfs_pinner.clone(),
            publisher_key,
            ipns_publisher,
            status.clone(),
        );
        let shutdown = shutdown_rx.clone();
        async move {
            run_publication_scheduler(scheduler, shutdown)
                .await
                .wrap_err("publication scheduler task")
        }
    });
    tasks.spawn({
        let store = store.clone();
        let ipfs_pinner = ipfs_pinner.clone();
        let retention_interval =
            checked_interval(*config.retention_interval, "retention_interval")?;
        let shutdown = shutdown_rx.clone();
        async move {
            run_retention_sweeper(store, ipfs_pinner, retention_interval, shutdown)
                .await
                .wrap_err("retention sweeper task")
        }
    });
    tasks.spawn({
        let status = status.clone();
        let shutdown = shutdown_rx.clone();
        async move {
            serve_status(status_listener, status, shutdown)
                .await
                .wrap_err("status HTTP task")
        }
    });

    let first_exit = tokio::select! {
        result = wait_for_shutdown() => result.wrap_err("wait for shutdown signal"),
        result = next_task_result(&mut tasks) => result,
    };

    if shutdown_tx.send(true).is_err() {
        info!("shutdown signal had no receivers");
    }

    let drain_result = drain_background_tasks(&mut tasks).await;
    match (first_exit, drain_result) {
        (Err(error), _) | (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

async fn run_scraper_loop(
    orchestrator: Orchestrator,
    idle_interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    loop {
        if shutdown_requested(&shutdown) {
            return Ok(());
        }

        if let Err(error) = orchestrator
            .run_until_caught_up_or_shutdown(shutdown.clone())
            .await
            .wrap_err("run scraper until caught up")
        {
            warn!(
                error = %format_report_chain(&error),
                "POI scraper cycle failed; backing off before retry"
            );
        }

        if sleep_or_shutdown(idle_interval, &mut shutdown).await {
            return Ok(());
        }
    }
}

async fn run_publication_scheduler(
    mut scheduler: PublicationScheduler,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let publish_interval = checked_interval(
        *scheduler.config.delta_publish_interval,
        "delta_publish_interval",
    )?;
    let mut interval = tokio::time::interval(publish_interval);

    loop {
        if interval_tick_or_shutdown(&mut interval, &mut shutdown).await {
            return Ok(());
        }

        if let Err(error) = scheduler.publish_cycle(SystemTime::now()).await {
            scheduler.set_ipfs_reachable(false).await;
            info!(?error, "POI publication cycle failed");
        }
    }
}

async fn run_retention_sweeper(
    store: Store,
    ipfs_client: Arc<dyn IpfsClient>,
    retention_interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let sweep_interval = retention_interval.min(RETENTION_SWEEP_INTERVAL_CAP);
    let mut interval = tokio::time::interval(sweep_interval);
    loop {
        if interval_tick_or_shutdown(&mut interval, &mut shutdown).await {
            return Ok(());
        }

        match Retention::sweep(
            store.pool(),
            ipfs_client.as_ref(),
            SystemTime::now(),
            retention_interval,
        )
        .await
        {
            Ok(sweep) => info!(
                unpinned_count = sweep.unpinned_cids.len(),
                failed_count = sweep.failed_cids.len(),
                "completed POI snapshot retention sweep"
            ),
            Err(error) => info!(error = %error, "POI snapshot retention sweep failed"),
        }
    }
}

struct PublicationScheduler {
    config: Config,
    store: Store,
    lifecycle: Lifecycle,
    ipfs_client: Arc<dyn IpfsClient>,
    signing_key: SigningKey,
    ipns_publisher: IpnsPublisher,
    status: SharedStatus,
    last_manifest_cid: Option<String>,
    manifest_needs_publish: bool,
    last_ipns_publish_at: Option<SystemTime>,
    last_ipns_sequence: Option<u64>,
    ipns_sequence_loaded: bool,
}

struct PublishedManifest {
    cid: String,
    sequence: u64,
}

impl PublicationScheduler {
    fn new(
        config: Config,
        store: Store,
        ipfs_client: Arc<dyn IpfsClient>,
        signing_key: SigningKey,
        ipns_publisher: IpnsPublisher,
        status: SharedStatus,
    ) -> Self {
        let lifecycle = Lifecycle::new(
            store.clone(),
            config.upstream_url.clone(),
            EVM_CHAIN_TYPE,
            upstream_endpoint_hash(&config.upstream_url),
        );

        Self {
            config,
            store,
            lifecycle,
            ipfs_client,
            signing_key,
            ipns_publisher,
            status,
            last_manifest_cid: None,
            manifest_needs_publish: true,
            last_ipns_publish_at: None,
            last_ipns_sequence: None,
            ipns_sequence_loaded: false,
        }
    }

    async fn publish_cycle(&mut self, now: SystemTime) -> Result<()> {
        let mut published_snapshot = false;
        for list_key in &self.config.list_keys {
            for chain_id in &self.config.chain_ids {
                match self.publish_pair(list_key, *chain_id, now).await {
                    Ok(pair_published) => {
                        if pair_published {
                            published_snapshot = true;
                            self.manifest_needs_publish = true;
                        }
                    }
                    Err(error) => {
                        self.set_ipfs_reachable(false).await;
                        warn!(
                            list_key = %list_key_hex(list_key),
                            chain_id,
                            error = %error,
                            "POI snapshot publication failed for pair; continuing cycle"
                        );
                    }
                }
            }
        }

        if published_snapshot || self.manifest_needs_publish || self.last_manifest_cid.is_none() {
            self.publish_manifest_and_ipns(now).await?;
            return Ok(());
        }

        let manifest_cid = self
            .last_manifest_cid
            .clone()
            .expect("last manifest CID checked above");
        if !self.cid_is_available(&manifest_cid, "manifest").await? {
            warn!(
                manifest_cid,
                "published POI manifest CID is missing from IPFS service; repinning manifest"
            );
            self.publish_manifest_and_ipns(now).await?;
            return Ok(());
        }

        if self.should_republish_ipns(now) {
            let sequence = self.next_ipns_sequence(now).await?;
            self.publish_ipns(&manifest_cid, sequence).await?;
            self.last_ipns_publish_at = Some(now);
        }

        Ok(())
    }

    async fn publish_manifest_and_ipns(&mut self, now: SystemTime) -> Result<()> {
        if let Some(manifest) = self.publish_manifest(now).await? {
            self.last_manifest_cid = Some(manifest.cid.clone());
            self.manifest_needs_publish = false;
            self.publish_ipns(&manifest.cid, manifest.sequence).await?;
            self.last_ipns_publish_at = Some(now);
        }
        Ok(())
    }

    async fn publish_pair(
        &self,
        list_key: &alloy_primitives::FixedBytes<32>,
        chain_id: u64,
        now: SystemTime,
    ) -> Result<bool> {
        let Some(tip) = self
            .store
            .chain_tip(list_key, chain_id, &self.config.upstream_url)
            .await
            .wrap_err("read chain tip for publication")?
        else {
            return Ok(false);
        };
        let Some(tip_merkleroot) = tip.last_tip_merkleroot else {
            return Ok(false);
        };
        let publications = self
            .store
            .active_publications(list_key, chain_id, &self.config.upstream_url)
            .await
            .wrap_err("read active snapshot publications")?;
        let active_base = active_base(&publications);
        let last_published_tip = published_tip(&publications);

        if last_published_tip.is_some_and(|published_tip| tip.last_event_index < published_tip) {
            info!(
                list_key = %list_key_hex(list_key),
                chain_id,
                chain_tip = tip.last_event_index,
                published_tip = last_published_tip,
                "skipping publication because active snapshots are ahead of chain tip"
            );
            return Ok(false);
        }

        let published_snapshot = if let Some(missing_cid) = first_missing_publication_cid(
            self.ipfs_client.as_ref(),
            &publications,
            list_key,
            chain_id,
        )
        .await?
        {
            warn!(
                list_key = %list_key_hex(list_key),
                chain_id,
                missing_cid,
                "active POI snapshot CID is missing from IPFS service; rebuilding base snapshot"
            );
            self.publish_snapshot(
                list_key,
                chain_id,
                SnapshotKind::Base,
                0,
                tip.last_event_index,
                &tip_merkleroot,
            )
            .await?;
            true
        } else {
            let should_rebuild_base = active_base.is_none_or(|base| {
                Lifecycle::should_rebuild_base(
                    Some(base.published_at),
                    now,
                    *self.config.base_rebuild_interval,
                )
            });
            if should_rebuild_base {
                self.publish_snapshot(
                    list_key,
                    chain_id,
                    SnapshotKind::Base,
                    0,
                    tip.last_event_index,
                    &tip_merkleroot,
                )
                .await?;
                true
            } else if let Some(published_tip) = last_published_tip
                && tip.last_event_index > published_tip
            {
                self.publish_snapshot(
                    list_key,
                    chain_id,
                    SnapshotKind::Delta,
                    published_tip + 1,
                    tip.last_event_index,
                    &tip_merkleroot,
                )
                .await?;
                true
            } else {
                false
            }
        };

        let published_blocked_shields = self
            .publish_blocked_shields_artifact(list_key, chain_id)
            .await?;

        Ok(published_snapshot || published_blocked_shields)
    }

    async fn publish_snapshot(
        &self,
        list_key: &alloy_primitives::FixedBytes<32>,
        chain_id: u64,
        kind: SnapshotKind,
        start_index: u64,
        end_index: u64,
        tip_merkleroot: &[u8; 32],
    ) -> Result<()> {
        let bytes = match kind {
            SnapshotKind::Base => self
                .lifecycle
                .build_base(list_key, chain_id, end_index)
                .await
                .wrap_err("build base snapshot")?,
            SnapshotKind::Delta => self
                .lifecycle
                .build_delta(list_key, chain_id, start_index, end_index)
                .await
                .wrap_err("build delta snapshot")?,
        };
        let cid = pin_snapshot_file(self.ipfs_client.as_ref(), &bytes)
            .await
            .wrap_err("pin snapshot to IPFS")?;
        let byte_size = u64::try_from(bytes.len()).wrap_err("snapshot byte size overflow")?;
        let artifact_hash = content_hash(&bytes);

        let mut tx = self
            .store
            .begin()
            .await
            .wrap_err("begin audit transaction")?;
        Audit::record_publication(
            &mut tx,
            list_key,
            chain_id,
            &self.config.upstream_url,
            kind,
            start_index,
            end_index,
            &cid,
            byte_size,
            &artifact_hash,
            FORMAT_VERSION,
            tip_merkleroot,
        )
        .await
        .wrap_err("record snapshot publication")?;
        tx.commit()
            .await
            .wrap_err("commit snapshot publication audit")?;

        info!(
            list_key = %list_key_hex(list_key),
            chain_id,
            kind = snapshot_kind_label(kind),
            start_index,
            end_index,
            byte_size,
            sha256 = %prefixed_hex(&artifact_hash),
            cid = %cid,
            "published POI snapshot"
        );
        Ok(())
    }

    async fn publish_blocked_shields_artifact(
        &self,
        list_key: &alloy_primitives::FixedBytes<32>,
        chain_id: u64,
    ) -> Result<bool> {
        let artifact = self
            .lifecycle
            .build_blocked_shields_artifact(list_key, chain_id)
            .await
            .wrap_err("build blocked-shields artifact")?;
        let bytes = artifact
            .to_bytes()
            .wrap_err("serialize blocked-shields artifact")?;
        let artifact_hash = content_hash(&bytes);
        let active = self
            .store
            .active_blocked_shields_publication(list_key, chain_id, &self.config.upstream_url)
            .await
            .wrap_err("read active blocked-shields publication")?;

        if let Some(active) = &active
            && active.content_hash == artifact_hash
        {
            if self
                .cid_is_available(&active.cid, "blocked-shields")
                .await?
            {
                return Ok(false);
            }
            warn!(
                list_key = %list_key_hex(list_key),
                chain_id,
                cid = %active.cid,
                "active blocked-shields artifact CID is missing from IPFS service; repinning"
            );
        }

        let cid = pin_blocked_shields(self.ipfs_client.as_ref(), &bytes)
            .await
            .wrap_err("pin blocked-shields artifact to IPFS")?;
        let byte_size =
            u64::try_from(bytes.len()).wrap_err("blocked-shields artifact byte size overflow")?;

        let mut tx = self
            .store
            .begin()
            .await
            .wrap_err("begin blocked-shields audit transaction")?;
        Audit::record_blocked_shields_publication(
            &mut tx,
            list_key,
            chain_id,
            &self.config.upstream_url,
            &cid,
            byte_size,
            FORMAT_VERSION,
            &artifact_hash,
        )
        .await
        .wrap_err("record blocked-shields publication")?;
        tx.commit()
            .await
            .wrap_err("commit blocked-shields publication audit")?;

        info!(
            list_key = %list_key_hex(list_key),
            chain_id,
            byte_size,
            blocked_shield_count = artifact.blocked_shields.len(),
            cid = %cid,
            "published blocked-shields artifact"
        );
        Ok(true)
    }

    async fn publish_manifest(&mut self, now: SystemTime) -> Result<Option<PublishedManifest>> {
        let entries = self.manifest_entries().await?;
        if entries.is_empty() {
            return Ok(None);
        }

        let sequence = self.next_ipns_sequence(now).await?;
        let mut manifest = Manifest::new(
            FORMAT_VERSION,
            unix_millis(now)?,
            sequence,
            String::new(),
            entries,
        );
        manifest
            .sign_manifest(&self.signing_key)
            .wrap_err("sign manifest")?;
        let manifest_bytes = serde_json::to_vec(&manifest).wrap_err("serialize manifest")?;
        let byte_size =
            u64::try_from(manifest_bytes.len()).wrap_err("manifest byte size overflow")?;
        let manifest_hash = content_hash(&manifest_bytes);
        let manifest_cid = pin_manifest(self.ipfs_client.as_ref(), &manifest_bytes)
            .await
            .wrap_err("pin manifest to IPFS")?;
        let audit_result = async {
            let mut tx = self
                .store
                .begin()
                .await
                .wrap_err("begin manifest audit transaction")?;
            Audit::record_manifest_pin(
                &mut tx,
                &manifest_cid,
                sequence,
                byte_size,
                &manifest_hash,
                FORMAT_VERSION,
            )
            .await
            .wrap_err("record manifest pin")?;
            tx.commit().await.wrap_err("commit manifest pin audit")?;
            Ok::<(), eyre::Report>(())
        }
        .await;
        if let Err(error) = audit_result {
            if let Err(unpin_error) = self.ipfs_client.unpin(&manifest_cid).await {
                warn!(
                    cid = %manifest_cid,
                    error = %unpin_error,
                    "failed to unpin unaudited POI manifest CID"
                );
            }
            return Err(error);
        }
        let manifest_cid = manifest_cid.to_string();

        self.status
            .write()
            .await
            .record_manifest_publication(manifest_cid.clone());
        info!(
            manifest_cid = %manifest_cid,
            sequence,
            byte_size,
            sha256 = %prefixed_hex(&manifest_hash),
            "published POI manifest"
        );
        Ok(Some(PublishedManifest {
            cid: manifest_cid,
            sequence,
        }))
    }

    async fn manifest_entries(&self) -> Result<Vec<ManifestEntry>> {
        let mut entries = Vec::new();
        for list_key in &self.config.list_keys {
            for chain_id in &self.config.chain_ids {
                let publications = self
                    .store
                    .active_publications(list_key, *chain_id, &self.config.upstream_url)
                    .await
                    .wrap_err("read active publications for manifest")?;
                let Some(base) = active_base(&publications) else {
                    continue;
                };
                let Some(blocked_shields) = self
                    .store
                    .active_blocked_shields_publication(
                        list_key,
                        *chain_id,
                        &self.config.upstream_url,
                    )
                    .await
                    .wrap_err("read active blocked-shields publication for manifest")?
                else {
                    continue;
                };
                let deltas = active_deltas(&publications);
                let current = deltas.last().copied().unwrap_or(base);
                let tip_merkleroot = current
                    .tip_merkleroot
                    .ok_or_else(|| eyre!("published snapshot is missing tip merkleroot"))?;

                entries.push(ManifestEntry {
                    list_key: list_key_hex(list_key),
                    chain_id: *chain_id,
                    base: artifact_descriptor(base),
                    deltas: deltas
                        .iter()
                        .map(|publication| artifact_descriptor(publication))
                        .collect(),
                    blocked_shields: blocked_shields_descriptor(&blocked_shields),
                    current_tip_index: current.end_index,
                    current_tip_merkleroot: format!("0x{}", hex::encode(tip_merkleroot)),
                });
            }
        }

        entries.sort_by(|left, right| {
            left.list_key
                .cmp(&right.list_key)
                .then_with(|| left.chain_id.cmp(&right.chain_id))
        });
        Ok(entries)
    }

    async fn publish_ipns(&self, manifest_cid: &str, sequence: u64) -> Result<()> {
        self.ipns_publisher
            .publish_manifest_cid(manifest_cid, sequence)
            .await
            .wrap_err("publish manifest CID to IPNS")?;
        let parsed_cid = manifest_cid
            .parse()
            .wrap_err_with(|| format!("parse published manifest CID {manifest_cid}"))?;
        let mut tx = self
            .store
            .begin()
            .await
            .wrap_err("begin manifest IPNS audit transaction")?;
        Audit::record_manifest_ipns_publication(&mut tx, &parsed_cid)
            .await
            .wrap_err("record manifest IPNS publication")?;
        tx.commit().await.wrap_err("commit manifest IPNS audit")?;
        info!(manifest_cid, sequence, "published POI manifest CID to IPNS");
        Ok(())
    }

    async fn cid_is_available(&self, cid: &str, label: &'static str) -> Result<bool> {
        cid_is_available(self.ipfs_client.as_ref(), cid, label).await
    }

    fn should_republish_ipns(&self, now: SystemTime) -> bool {
        self.last_manifest_cid.is_some()
            && self.last_ipns_publish_at.is_none_or(|last_published_at| {
                now.duration_since(last_published_at)
                    .is_ok_and(|elapsed| elapsed >= *self.config.ipns_republish_interval)
            })
    }

    async fn next_ipns_sequence(&mut self, now: SystemTime) -> Result<u64> {
        if !self.ipns_sequence_loaded {
            self.last_ipns_sequence = self
                .store
                .last_ipns_sequence()
                .await
                .wrap_err("load persisted IPNS sequence")?;
            self.ipns_sequence_loaded = true;
        }
        let sequence = unix_millis(now)?;
        let sequence = self.last_ipns_sequence.map_or(sequence, |last_sequence| {
            sequence.max(last_sequence.saturating_add(1))
        });
        self.store
            .record_ipns_sequence(sequence)
            .await
            .wrap_err("persist IPNS sequence")?;
        self.last_ipns_sequence = Some(sequence);
        Ok(sequence)
    }

    async fn set_ipfs_reachable(&self, reachable: bool) {
        self.status.write().await.set_ipfs_reachable(reachable);
    }
}

fn active_base(publications: &[StoredPublication]) -> Option<&StoredPublication> {
    publications
        .iter()
        .rfind(|publication| matches!(publication.kind, SnapshotKind::Base))
}

fn active_deltas(publications: &[StoredPublication]) -> Vec<&StoredPublication> {
    let mut deltas = publications
        .iter()
        .filter(|publication| matches!(publication.kind, SnapshotKind::Delta))
        .collect::<Vec<_>>();
    deltas.sort_by_key(|publication| publication.start_index);
    deltas
}

fn published_tip(publications: &[StoredPublication]) -> Option<u64> {
    publications
        .iter()
        .map(|publication| publication.end_index)
        .max()
}

async fn first_missing_publication_cid(
    ipfs_client: &dyn IpfsClient,
    publications: &[StoredPublication],
    list_key: &alloy_primitives::FixedBytes<32>,
    chain_id: u64,
) -> Result<Option<String>> {
    for publication in publications {
        if !cid_is_available(ipfs_client, &publication.cid, "snapshot")
            .await
            .wrap_err_with(|| {
                format!(
                    "check published snapshot availability for list_key={} chain_id={chain_id} cid={}",
                    list_key_hex(list_key),
                    publication.cid
                )
            })?
        {
            return Ok(Some(publication.cid.clone()));
        }
    }

    Ok(None)
}

async fn cid_is_available(
    ipfs_client: &dyn IpfsClient,
    cid: &str,
    label: &'static str,
) -> Result<bool> {
    let parsed_cid = cid
        .parse()
        .wrap_err_with(|| format!("parse published {label} CID {cid}"))?;
    ipfs_client
        .contains(&parsed_cid)
        .await
        .wrap_err_with(|| format!("check published {label} CID availability {cid}"))
}

fn upstream_endpoint_hash(upstream_url: &str) -> [u8; 32] {
    Sha256::digest(upstream_url.as_bytes()).into()
}

fn list_key_hex(list_key: &alloy_primitives::FixedBytes<32>) -> String {
    format!("0x{}", hex::encode(list_key.as_slice()))
}

fn artifact_descriptor(publication: &StoredPublication) -> ArtifactDescriptor {
    ArtifactDescriptor {
        cid: publication.cid.clone(),
        sha256: prefixed_hex(&publication.content_hash),
        byte_size: publication.byte_size,
    }
}

fn blocked_shields_descriptor(
    publication: &poi_indexer_core::store::StoredBlockedShieldsPublication,
) -> ArtifactDescriptor {
    ArtifactDescriptor {
        cid: publication.cid.clone(),
        sha256: prefixed_hex(&publication.content_hash),
        byte_size: publication.byte_size,
    }
}

fn prefixed_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

const fn snapshot_kind_label(kind: SnapshotKind) -> &'static str {
    match kind {
        SnapshotKind::Base => "base",
        SnapshotKind::Delta => "delta",
    }
}

fn unix_millis(now: SystemTime) -> Result<u64> {
    let duration = now
        .duration_since(UNIX_EPOCH)
        .wrap_err("system clock is before unix epoch")?;
    duration
        .as_millis()
        .try_into()
        .wrap_err("unix millisecond timestamp overflow")
}

fn checked_interval(duration: Duration, field: &'static str) -> Result<Duration> {
    if duration.is_zero() {
        Err(eyre!("{field} must be greater than zero"))
    } else {
        Ok(duration)
    }
}

fn format_report_chain(error: &eyre::Report) -> String {
    error
        .chain()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ")
}

fn status_router(status: SharedStatus) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/status", get(status_response))
        .with_state(status)
}

async fn health() -> &'static str {
    "ok"
}

async fn status_response(State(status): State<SharedStatus>) -> Json<Status> {
    Json(status.read().await.snapshot_at(SystemTime::now()))
}

async fn serve_status(
    listener: TcpListener,
    status: SharedStatus,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    axum::serve(listener, status_router(status))
        .with_graceful_shutdown(async move {
            wait_for_shutdown_rx(&mut shutdown).await;
        })
        .await
        .wrap_err("serve status HTTP")
}

async fn wait_for_shutdown_rx(shutdown: &mut watch::Receiver<bool>) {
    if shutdown_requested(shutdown) {
        return;
    }
    let _ = shutdown.changed().await;
}

async fn next_task_result(tasks: &mut JoinSet<Result<()>>) -> Result<()> {
    match tasks.join_next().await {
        Some(Ok(Ok(()))) => Err(eyre!("background task exited unexpectedly")),
        Some(Ok(Err(error))) => Err(error),
        Some(Err(error)) => Err(error).wrap_err("background task panicked"),
        None => Ok(()),
    }
}

async fn drain_background_tasks(tasks: &mut JoinSet<Result<()>>) -> Result<()> {
    let mut first_error = None;
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
            Err(error) => {
                if first_error.is_none() {
                    first_error = Some(eyre!(error).wrap_err("background task panicked"));
                }
            }
        }
    }

    first_error.map_or(Ok(()), Err)
}

fn shutdown_requested(shutdown: &watch::Receiver<bool>) -> bool {
    *shutdown.borrow()
}

async fn shutdown_changed_or_requested(shutdown: &mut watch::Receiver<bool>) -> bool {
    shutdown.changed().await.is_err() || shutdown_requested(shutdown)
}

async fn interval_tick_or_shutdown(
    interval: &mut tokio::time::Interval,
    shutdown: &mut watch::Receiver<bool>,
) -> bool {
    tokio::select! {
        _ = interval.tick() => shutdown_requested(shutdown),
        shutdown = shutdown_changed_or_requested(shutdown) => shutdown,
    }
}

async fn sleep_or_shutdown(duration: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    if duration.is_zero() {
        return shutdown_requested(shutdown);
    }

    tokio::select! {
        () = tokio::time::sleep(duration) => shutdown_requested(shutdown),
        shutdown = shutdown_changed_or_requested(shutdown) => shutdown,
    }
}

#[cfg(unix)]
async fn wait_for_shutdown() -> Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigterm = signal(SignalKind::terminate()).wrap_err("install SIGTERM handler")?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            result.wrap_err("listen for SIGINT")?;
        }
        _ = sigterm.recv() => {}
    }
    info!("shutdown signal received");
    Ok(())
}

#[cfg(not(unix))]
async fn wait_for_shutdown() -> Result<()> {
    tokio::signal::ctrl_c()
        .await
        .wrap_err("listen for shutdown signal")?;
    info!("shutdown signal received");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::FixedBytes;
    use async_trait::async_trait;
    use cid::Cid;
    use poi_indexer_core::publish::ipfs::{IpfsError, raw_block_cid};
    use std::collections::HashSet;
    use std::sync::Mutex;

    #[tokio::test]
    async fn status_server_returns_health_and_status() -> Result<()> {
        let list_key = FixedBytes::from([1_u8; 32]);
        let status = Status::for_pairs(&[list_key], &[1], 500).shared();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .wrap_err("bind test status listener")?;
        let addr = listener.local_addr().wrap_err("read test listener addr")?;
        let server_status = status.clone();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server =
            tokio::spawn(async move { serve_status(listener, server_status, shutdown_rx).await });

        let health = reqwest::get(format!("http://{addr}/health"))
            .await
            .wrap_err("GET /health")?;
        assert!(health.status().is_success());

        let status = reqwest::get(format!("http://{addr}/status"))
            .await
            .wrap_err("GET /status")?
            .json::<Status>()
            .await
            .wrap_err("decode /status")?;
        assert_eq!(status.pairs.len(), 1);
        assert_eq!(status.pairs[0].chain_id, 1);
        assert_eq!(status.pairs[0].current_page_size, 500);

        shutdown_tx.send(true).wrap_err("send shutdown")?;
        server.await.wrap_err("join status server")??;
        Ok(())
    }

    #[tokio::test]
    async fn missing_publication_cid_detects_deleted_delta() -> Result<()> {
        let list_key = FixedBytes::from([2_u8; 32]);
        let base_cid = raw_block_cid(b"base")?;
        let delta_cid = raw_block_cid(b"delta")?;
        let client = AvailabilityClient::new([base_cid]);
        let publications = vec![
            stored_publication(SnapshotKind::Base, 0, 3, base_cid),
            stored_publication(SnapshotKind::Delta, 4, 4, delta_cid),
        ];

        let missing = first_missing_publication_cid(&client, &publications, &list_key, 1).await?;

        assert_eq!(missing, Some(delta_cid.to_string()));
        Ok(())
    }

    #[tokio::test]
    async fn missing_publication_cid_accepts_all_present() -> Result<()> {
        let list_key = FixedBytes::from([3_u8; 32]);
        let base_cid = raw_block_cid(b"base")?;
        let delta_cid = raw_block_cid(b"delta")?;
        let client = AvailabilityClient::new([base_cid, delta_cid]);
        let publications = vec![
            stored_publication(SnapshotKind::Base, 0, 3, base_cid),
            stored_publication(SnapshotKind::Delta, 4, 4, delta_cid),
        ];

        let missing = first_missing_publication_cid(&client, &publications, &list_key, 1).await?;

        assert_eq!(missing, None);
        Ok(())
    }

    fn stored_publication(
        kind: SnapshotKind,
        start_index: u64,
        end_index: u64,
        cid: Cid,
    ) -> StoredPublication {
        StoredPublication {
            kind,
            start_index,
            end_index,
            cid: cid.to_string(),
            byte_size: 1,
            content_hash: [8_u8; 32],
            tip_merkleroot: Some([9_u8; 32]),
            published_at: UNIX_EPOCH,
        }
    }

    #[derive(Debug)]
    struct AvailabilityClient {
        present: Mutex<HashSet<String>>,
    }

    impl AvailabilityClient {
        fn new(cids: impl IntoIterator<Item = Cid>) -> Self {
            Self {
                present: Mutex::new(cids.into_iter().map(|cid| cid.to_string()).collect()),
            }
        }
    }

    #[async_trait]
    impl IpfsClient for AvailabilityClient {
        fn service_name(&self) -> &'static str {
            "availability"
        }

        async fn pin_bytes(&self, bytes: &[u8]) -> std::result::Result<Cid, IpfsError> {
            raw_block_cid(bytes)
        }

        async fn unpin(&self, _cid: &Cid) -> std::result::Result<(), IpfsError> {
            Ok(())
        }

        async fn contains(&self, cid: &Cid) -> std::result::Result<bool, IpfsError> {
            Ok(self
                .present
                .lock()
                .expect("present CID lock")
                .contains(&cid.to_string()))
        }
    }
}
