use alloy_primitives::FixedBytes;
use async_trait::async_trait;
use cid::Cid;
use poi::poi::{PoiEventType, SignedBlockedShield, SignedPoiEvent};
use poi_indexer_core::audit::{Audit, Retention};
use poi_indexer_core::publish::ipfs::{IpfsClient, IpfsError, raw_block_cid};
use poi_indexer_core::snapshot::SnapshotKind;
use poi_indexer_core::store::{Store, run_migrations};
use sqlx::postgres::PgPoolOptions;
use std::sync::Mutex;
use std::time::{Duration, UNIX_EPOCH};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

#[tokio::test]
async fn migrations_apply_and_tables_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let node = match Postgres::default().start().await {
        Ok(node) => node,
        Err(err) if is_docker_unavailable(&err) => {
            eprintln!("skipping Postgres migration smoke test: Docker is unavailable");
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    let connection_string = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        node.get_host_port_ipv4(5432).await?
    );
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&connection_string)
        .await?;

    run_migrations(&pool).await?;

    let list_key = vec![1_u8; 32];
    let blinded_commitment = vec![2_u8; 32];
    let signature = vec![3_u8; 64];
    let commitment_hash = vec![4_u8; 32];
    let tip_merkleroot = vec![5_u8; 32];

    sqlx::query(
        "INSERT INTO poi_events \
         (list_key, chain_id, event_index, blinded_commitment, signature, event_type) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&list_key)
    .bind(1_i64)
    .bind(0_i64)
    .bind(&blinded_commitment)
    .bind(&signature)
    .bind(0_i16)
    .execute(&pool)
    .await?;

    sqlx::query(
        "INSERT INTO blocked_shields \
         (list_key, chain_id, blinded_commitment, commitment_hash, signature, block_reason) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&list_key)
    .bind(1_i64)
    .bind(&blinded_commitment)
    .bind(&commitment_hash)
    .bind(&signature)
    .bind("fixture")
    .execute(&pool)
    .await?;

    sqlx::query(
        "INSERT INTO chain_tips \
         (list_key, chain_id, upstream_url, last_event_index, last_tip_merkleroot) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&list_key)
    .bind(1_i64)
    .bind("https://ppoi.example.invalid")
    .bind(0_i64)
    .bind(&tip_merkleroot)
    .execute(&pool)
    .await?;

    sqlx::query(
        "INSERT INTO published_snapshots \
         (list_key, chain_id, upstream_url, kind, start_index, end_index, cid, byte_size, format_version, tip_merkleroot) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(&list_key)
    .bind(1_i64)
    .bind("https://ppoi.example.invalid")
    .bind("base")
    .bind(0_i64)
    .bind(0_i64)
    .bind("bafyfixture")
    .bind(128_i64)
    .bind(2_i32)
    .bind(&tip_merkleroot)
    .execute(&pool)
    .await?;

    sqlx::query(
        "INSERT INTO published_blocked_shields \
         (list_key, chain_id, upstream_url, cid, byte_size, format_version, content_hash) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&list_key)
    .bind(1_i64)
    .bind("https://ppoi.example.invalid")
    .bind("bafyblockedfixture")
    .bind(64_i64)
    .bind(2_i32)
    .bind(vec![6_u8; 32])
    .execute(&pool)
    .await?;

    assert_eq!(row_count(&pool, "poi_events").await?, 1);
    assert_eq!(row_count(&pool, "blocked_shields").await?, 1);
    assert_eq!(row_count(&pool, "chain_tips").await?, 1);
    assert_eq!(row_count(&pool, "published_snapshots").await?, 1);
    assert_eq!(row_count(&pool, "published_blocked_shields").await?, 1);

    Ok(())
}

#[tokio::test]
async fn migrations_skip_when_schema_version_is_current() -> Result<(), Box<dyn std::error::Error>>
{
    let node = match Postgres::default().start().await {
        Ok(node) => node,
        Err(err) if is_docker_unavailable(&err) => {
            eprintln!("skipping Postgres migration version test: Docker is unavailable");
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    let connection_string = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        node.get_host_port_ipv4(5432).await?
    );
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&connection_string)
        .await?;

    sqlx::query(
        r"
        CREATE TABLE poi_indexer_schema_version (
            id BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
            version INTEGER NOT NULL,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        ",
    )
    .execute(&pool)
    .await?;
    sqlx::query(
        "INSERT INTO poi_indexer_schema_version (id, version, applied_at) VALUES (TRUE, 4, now())",
    )
    .execute(&pool)
    .await?;

    run_migrations(&pool).await?;

    assert!(!table_exists(&pool, "poi_events").await?);
    assert_eq!(schema_version(&pool).await?, 4);

    Ok(())
}

#[tokio::test]
async fn store_methods_are_idempotent_and_monotonic() -> Result<(), Box<dyn std::error::Error>> {
    let node = match Postgres::default().start().await {
        Ok(node) => node,
        Err(err) if is_docker_unavailable(&err) => {
            eprintln!("skipping Postgres store smoke test: Docker is unavailable");
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    let connection_string = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        node.get_host_port_ipv4(5432).await?
    );
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&connection_string)
        .await?;

    run_migrations(&pool).await?;

    let store = Store::new(pool.clone());
    let list_key = FixedBytes::from([9_u8; 32]);
    let upstream_url = "https://ppoi.example.invalid";
    let other_upstream_url = "https://ppoi-other.example.invalid";
    let events = vec![
        signed_event(0, 1, PoiEventType::Shield),
        signed_event(1, 2, PoiEventType::Transact),
    ];
    let blocked_shield = signed_blocked_shield(3, 4, 5, Some("first"));
    let updated_blocked_shield = signed_blocked_shield(3, 4, 6, Some("second"));
    let removed_blocked_shield = signed_blocked_shield(7, 8, 9, Some("removed"));

    assert_eq!(store.last_ipns_sequence().await?, None);
    store.record_ipns_sequence(5).await?;
    store.record_ipns_sequence(4).await?;
    assert_eq!(store.last_ipns_sequence().await?, Some(5));

    let mut tx = store.begin().await?;
    Store::insert_events(&mut tx, &list_key, 1, &events).await?;
    Store::insert_events(&mut tx, &list_key, 1, &events).await?;
    Store::advance_chain_tip(
        &mut tx,
        &list_key,
        1,
        upstream_url,
        1,
        Some(&hex_bytes(7, 32)),
    )
    .await?;
    let regression = Store::advance_chain_tip(
        &mut tx,
        &list_key,
        1,
        upstream_url,
        0,
        Some(&hex_bytes(8, 32)),
    )
    .await
    .expect_err("backward chain tip should be rejected");
    assert!(matches!(
        regression,
        poi_indexer_core::store::StoreError::ChainTipRegression { .. }
    ));
    Store::upsert_blocked_shields(&mut tx, &list_key, 1, &[blocked_shield]).await?;
    Store::upsert_blocked_shields(
        &mut tx,
        &list_key,
        1,
        std::slice::from_ref(&updated_blocked_shield),
    )
    .await?;
    Store::upsert_blocked_shields(&mut tx, &list_key, 1, &[removed_blocked_shield]).await?;
    tx.commit().await?;

    let stored_events = store.page_event_range(&list_key, 1, 0, 10).await?;
    assert_eq!(stored_events.len(), 2);
    assert_eq!(stored_events[0].event_index, 0);
    assert_eq!(stored_events[1].event_index, 1);
    assert_eq!(
        store.last_event_index(&list_key, 1, upstream_url).await?,
        Some(1)
    );

    let stored_tip_root: Vec<u8> = sqlx::query_scalar(
        "SELECT last_tip_merkleroot FROM chain_tips \
         WHERE list_key = $1 AND chain_id = $2 AND upstream_url = $3",
    )
    .bind(list_key.as_slice())
    .bind(1_i64)
    .bind(upstream_url)
    .fetch_one(&pool)
    .await?;
    assert_eq!(stored_tip_root, vec![7_u8; 32]);

    let blocked_shields = store.all_blocked_shields(&list_key, 1).await?;
    assert_eq!(blocked_shields.len(), 2);
    assert_eq!(blocked_shields[0].block_reason.as_deref(), Some("second"));
    assert_eq!(blocked_shields[0].signature, [6_u8; 64]);

    let mut tx = store.begin().await?;
    Store::replace_blocked_shields(
        &mut tx,
        &list_key,
        1,
        std::slice::from_ref(&updated_blocked_shield),
    )
    .await?;
    tx.commit().await?;
    let blocked_shields = store.all_blocked_shields(&list_key, 1).await?;
    assert_eq!(blocked_shields.len(), 1);
    assert_eq!(blocked_shields[0].blinded_commitment, [4_u8; 32]);

    let old_base_cid = raw_block_cid(b"old base")?;
    let delta_cid = raw_block_cid(b"delta")?;
    let new_base_cid = raw_block_cid(b"new base")?;
    let switched_upstream_base_cid = new_base_cid;
    let old_blocked_cid = raw_block_cid(b"old blocked")?;
    let new_blocked_cid = raw_block_cid(b"new blocked")?;
    let mut tx = store.begin().await?;
    Audit::record_publication(
        &mut tx,
        &list_key,
        1,
        upstream_url,
        SnapshotKind::Base,
        0,
        1,
        &old_base_cid,
        256,
        &[17_u8; 32],
        1,
        &[7_u8; 32],
    )
    .await?;
    Audit::record_publication(
        &mut tx,
        &list_key,
        1,
        upstream_url,
        SnapshotKind::Delta,
        2,
        2,
        &delta_cid,
        128,
        &[18_u8; 32],
        1,
        &[7_u8; 32],
    )
    .await?;
    Audit::record_publication(
        &mut tx,
        &list_key,
        1,
        upstream_url,
        SnapshotKind::Base,
        0,
        2,
        &new_base_cid,
        384,
        &[19_u8; 32],
        1,
        &[7_u8; 32],
    )
    .await?;
    Audit::record_publication(
        &mut tx,
        &list_key,
        1,
        other_upstream_url,
        SnapshotKind::Base,
        0,
        2,
        &switched_upstream_base_cid,
        384,
        &[20_u8; 32],
        1,
        &[7_u8; 32],
    )
    .await?;
    Audit::record_blocked_shields_publication(
        &mut tx,
        &list_key,
        1,
        upstream_url,
        &old_blocked_cid,
        128,
        2,
        &[10_u8; 32],
    )
    .await?;
    Audit::record_blocked_shields_publication(
        &mut tx,
        &list_key,
        1,
        upstream_url,
        &new_blocked_cid,
        128,
        2,
        &[11_u8; 32],
    )
    .await?;
    tx.commit().await?;

    let (total_publications, superseded_publications): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COUNT(superseded_at) FROM published_snapshots \
         WHERE list_key = $1 AND chain_id = $2",
    )
    .bind(list_key.as_slice())
    .bind(1_i64)
    .fetch_one(&pool)
    .await?;
    assert_eq!(total_publications, 4);
    assert_eq!(superseded_publications, 3);
    let active_blocked = store
        .active_blocked_shields_publication(&list_key, 1, upstream_url)
        .await?
        .expect("active blocked-shields publication");
    assert_eq!(active_blocked.cid, new_blocked_cid.to_string());
    assert_eq!(active_blocked.content_hash, [11_u8; 32]);
    assert!(
        store
            .active_publications(&list_key, 1, upstream_url)
            .await?
            .is_empty()
    );
    let switched_upstream_publications = store
        .active_publications(&list_key, 1, other_upstream_url)
        .await?;
    assert_eq!(switched_upstream_publications.len(), 1);
    assert_eq!(
        switched_upstream_publications[0].cid,
        switched_upstream_base_cid.to_string()
    );
    assert_eq!(switched_upstream_publications[0].content_hash, [20_u8; 32]);

    sqlx::query(
        "UPDATE published_snapshots \
         SET superseded_at = to_timestamp(100) \
         WHERE superseded_at IS NOT NULL",
    )
    .execute(&pool)
    .await?;
    sqlx::query(
        "UPDATE published_blocked_shields \
         SET superseded_at = to_timestamp(100) \
         WHERE superseded_at IS NOT NULL",
    )
    .execute(&pool)
    .await?;

    let ipfs_client = RecordingIpfsClient::default();
    let sweep = Retention::sweep(
        &pool,
        &ipfs_client,
        UNIX_EPOCH + Duration::from_secs(200),
        Duration::from_secs(50),
    )
    .await?;
    let mut unpinned = ipfs_client.unpinned_cids();
    let mut expected = vec![
        delta_cid.to_string(),
        old_base_cid.to_string(),
        old_blocked_cid.to_string(),
    ];
    expected.sort();
    unpinned.sort();
    assert_eq!(unpinned, expected);
    assert_eq!(sorted_cids(sweep.unpinned_cids), expected);
    assert_eq!(row_count(&pool, "published_snapshots").await?, 4);

    let second_sweep = Retention::sweep(
        &pool,
        &ipfs_client,
        UNIX_EPOCH + Duration::from_secs(300),
        Duration::from_secs(50),
    )
    .await?;
    assert!(second_sweep.unpinned_cids.is_empty());
    assert_eq!(ipfs_client.unpinned_cids(), expected);

    Ok(())
}

fn is_docker_unavailable(error: &impl std::fmt::Debug) -> bool {
    let message = format!("{error:?}");
    message.contains("SocketNotFoundError") || message.contains("Connection refused")
}

async fn row_count(pool: &sqlx::PgPool, table: &str) -> Result<i64, sqlx::Error> {
    let sql = format!("SELECT COUNT(*) FROM {table}");
    sqlx::query_scalar(&sql).fetch_one(pool).await
}

async fn table_exists(pool: &sqlx::PgPool, table: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.tables
            WHERE table_schema = 'public' AND table_name = $1
        )
        ",
    )
    .bind(table)
    .fetch_one(pool)
    .await
}

async fn schema_version(pool: &sqlx::PgPool) -> Result<i32, sqlx::Error> {
    sqlx::query_scalar("SELECT version FROM poi_indexer_schema_version WHERE id = TRUE")
        .fetch_one(pool)
        .await
}

fn signed_event(index: u64, byte: u8, event_type: PoiEventType) -> SignedPoiEvent {
    SignedPoiEvent {
        index,
        blinded_commitment: hex_bytes(byte, 32),
        signature: hex_bytes(byte + 10, 64),
        event_type,
    }
}

fn signed_blocked_shield(
    commitment_hash_byte: u8,
    blinded_commitment_byte: u8,
    signature_byte: u8,
    block_reason: Option<&str>,
) -> SignedBlockedShield {
    SignedBlockedShield {
        commitment_hash: hex_bytes(commitment_hash_byte, 32),
        blinded_commitment: hex_bytes(blinded_commitment_byte, 32),
        block_reason: block_reason.map(ToString::to_string),
        signature: hex_bytes(signature_byte, 64),
    }
}

fn hex_bytes(byte: u8, len: usize) -> String {
    format!("0x{}", hex::encode(vec![byte; len]))
}

#[derive(Debug, Default)]
struct RecordingIpfsClient {
    unpinned: Mutex<Vec<Cid>>,
}

impl RecordingIpfsClient {
    fn unpinned_cids(&self) -> Vec<String> {
        sorted_cids(self.unpinned.lock().expect("unpinned cids lock").clone())
    }
}

#[async_trait]
impl IpfsClient for RecordingIpfsClient {
    fn service_name(&self) -> &'static str {
        "recording"
    }

    async fn pin_bytes(&self, bytes: &[u8]) -> Result<Cid, IpfsError> {
        raw_block_cid(bytes)
    }

    async fn unpin(&self, cid: &Cid) -> Result<(), IpfsError> {
        self.unpinned.lock().expect("unpinned cids lock").push(*cid);
        Ok(())
    }

    async fn contains(&self, _cid: &Cid) -> Result<bool, IpfsError> {
        Ok(true)
    }
}

fn sorted_cids(cids: Vec<Cid>) -> Vec<String> {
    let mut cids = cids
        .into_iter()
        .map(|cid| cid.to_string())
        .collect::<Vec<_>>();
    cids.sort();
    cids
}
