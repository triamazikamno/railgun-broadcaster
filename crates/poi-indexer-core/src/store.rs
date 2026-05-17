use crate::snapshot::SnapshotKind;
use alloy_primitives::FixedBytes;
use poi::poi::{PoiEventType, SignedBlockedShield, SignedPoiEvent};
use sqlx::{PgPool, Postgres, Transaction};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::info;

const IPNS_SEQUENCE_STATE_KEY: &str = "ipns_last_sequence";
const CURRENT_SCHEMA_VERSION: i32 = 4;

#[derive(Debug, Clone)]
pub struct Store {
    pool: PgPool,
}

impl Store {
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn begin(&self) -> Result<Transaction<'_, Postgres>, StoreError> {
        self.pool.begin().await.map_err(StoreError::Sqlx)
    }

    pub async fn last_event_index(
        &self,
        list_key: &FixedBytes<32>,
        chain_id: u64,
        upstream_url: &str,
    ) -> Result<Option<u64>, StoreError> {
        let chain_id = u64_to_i64(chain_id, "chain_id")?;
        let index = sqlx::query_scalar::<_, i64>(
            r"
            SELECT last_event_index
            FROM chain_tips
            WHERE list_key = $1 AND chain_id = $2 AND upstream_url = $3
            ",
        )
        .bind(list_key.as_slice())
        .bind(chain_id)
        .bind(upstream_url)
        .fetch_optional(&self.pool)
        .await?;

        index
            .map(|index| i64_to_u64(index, "last_event_index"))
            .transpose()
    }

    pub async fn chain_tip(
        &self,
        list_key: &FixedBytes<32>,
        chain_id: u64,
        upstream_url: &str,
    ) -> Result<Option<StoredChainTip>, StoreError> {
        let chain_id = u64_to_i64(chain_id, "chain_id")?;
        let row = sqlx::query_as::<_, (i64, Option<Vec<u8>>)>(
            r"
            SELECT last_event_index, last_tip_merkleroot
            FROM chain_tips
            WHERE list_key = $1 AND chain_id = $2 AND upstream_url = $3
            ",
        )
        .bind(list_key.as_slice())
        .bind(chain_id)
        .bind(upstream_url)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|(last_event_index, last_tip_merkleroot)| {
            Ok(StoredChainTip {
                last_event_index: i64_to_u64(last_event_index, "last_event_index")?,
                last_tip_merkleroot: last_tip_merkleroot
                    .map(|bytes| exact_array("last_tip_merkleroot", &bytes))
                    .transpose()?,
            })
        })
        .transpose()
    }

    pub async fn active_publications(
        &self,
        list_key: &FixedBytes<32>,
        chain_id: u64,
        upstream_url: &str,
    ) -> Result<Vec<StoredPublication>, StoreError> {
        let chain_id = u64_to_i64(chain_id, "chain_id")?;
        let rows =
            sqlx::query_as::<_, (String, i64, i64, String, i64, Vec<u8>, Option<Vec<u8>>, i64)>(
                r"
            SELECT
                kind,
                start_index,
                end_index,
                cid,
                byte_size,
                content_hash,
                tip_merkleroot,
                EXTRACT(EPOCH FROM published_at)::BIGINT AS published_at_unix_seconds
            FROM published_snapshots
            WHERE list_key = $1
                AND chain_id = $2
                AND upstream_url = $3
                AND superseded_at IS NULL
                AND content_hash IS NOT NULL
            ORDER BY
                CASE kind WHEN 'base' THEN 0 ELSE 1 END,
                start_index ASC,
                id ASC
            ",
            )
            .bind(list_key.as_slice())
            .bind(chain_id)
            .bind(upstream_url)
            .fetch_all(&self.pool)
            .await?;

        rows.into_iter()
            .map(
                |(
                    kind,
                    start_index,
                    end_index,
                    cid,
                    byte_size,
                    content_hash,
                    tip_merkleroot,
                    published_at,
                )| {
                    Ok(StoredPublication {
                        kind: parse_snapshot_kind(&kind)?,
                        start_index: i64_to_u64(start_index, "start_index")?,
                        end_index: i64_to_u64(end_index, "end_index")?,
                        cid,
                        byte_size: i64_to_u64(byte_size, "byte_size")?,
                        content_hash: exact_array("snapshot_content_hash", &content_hash)?,
                        tip_merkleroot: tip_merkleroot
                            .map(|bytes| exact_array("tip_merkleroot", &bytes))
                            .transpose()?,
                        published_at: i64_to_system_time(published_at, "published_at")?,
                    })
                },
            )
            .collect()
    }

    pub async fn active_blocked_shields_publication(
        &self,
        list_key: &FixedBytes<32>,
        chain_id: u64,
        upstream_url: &str,
    ) -> Result<Option<StoredBlockedShieldsPublication>, StoreError> {
        let chain_id = u64_to_i64(chain_id, "chain_id")?;
        let row = sqlx::query_as::<_, (String, i64, Vec<u8>, i64)>(
            r"
            SELECT
                cid,
                byte_size,
                content_hash,
                EXTRACT(EPOCH FROM published_at)::BIGINT AS published_at_unix_seconds
            FROM published_blocked_shields
            WHERE list_key = $1
                AND chain_id = $2
                AND upstream_url = $3
                AND superseded_at IS NULL
            ORDER BY id DESC
            LIMIT 1
            ",
        )
        .bind(list_key.as_slice())
        .bind(chain_id)
        .bind(upstream_url)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|(cid, byte_size, content_hash, published_at)| {
            Ok(StoredBlockedShieldsPublication {
                cid,
                byte_size: i64_to_u64(byte_size, "byte_size")?,
                content_hash: exact_array("blocked_shields_content_hash", &content_hash)?,
                published_at: i64_to_system_time(published_at, "published_at")?,
            })
        })
        .transpose()
    }

    pub async fn insert_events(
        tx: &mut Transaction<'_, Postgres>,
        list_key: &FixedBytes<32>,
        chain_id: u64,
        events: &[SignedPoiEvent],
    ) -> Result<(), StoreError> {
        let chain_id = u64_to_i64(chain_id, "chain_id")?;
        for event in events {
            let event_index = u64_to_i64(event.index, "event_index")?;
            let blinded_commitment = decode_fixed_hex::<BLINDED_COMMITMENT_BYTES>(
                "blinded_commitment",
                &event.blinded_commitment,
            )?;
            let signature = decode_fixed_hex::<SIGNATURE_BYTES>("signature", &event.signature)?;

            sqlx::query(
                r"
                INSERT INTO poi_events (
                    list_key, chain_id, event_index, blinded_commitment, signature, event_type
                )
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (list_key, chain_id, event_index) DO NOTHING
                ",
            )
            .bind(list_key.as_slice())
            .bind(chain_id)
            .bind(event_index)
            .bind(blinded_commitment.as_slice())
            .bind(signature.as_slice())
            .bind(event_type_discriminant(event.event_type))
            .execute(&mut **tx)
            .await?;
        }
        Ok(())
    }

    pub async fn advance_chain_tip(
        tx: &mut Transaction<'_, Postgres>,
        list_key: &FixedBytes<32>,
        chain_id: u64,
        upstream_url: &str,
        last_event_index: u64,
        last_tip_merkleroot: Option<&str>,
    ) -> Result<(), StoreError> {
        let chain_id_u64 = chain_id;
        let chain_id = u64_to_i64(chain_id, "chain_id")?;
        let proposed_event_index = last_event_index;
        let last_event_index = u64_to_i64(last_event_index, "last_event_index")?;
        let last_tip_merkleroot = last_tip_merkleroot
            .map(|root| decode_fixed_hex::<MERKLEROOT_BYTES>("last_tip_merkleroot", root))
            .transpose()?;

        let row = sqlx::query_scalar::<_, i64>(
            r"
            INSERT INTO chain_tips (
                list_key, chain_id, upstream_url, last_event_index, last_tip_merkleroot
            )
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (list_key, chain_id, upstream_url) DO UPDATE SET
                last_event_index = EXCLUDED.last_event_index,
                last_tip_merkleroot = EXCLUDED.last_tip_merkleroot,
                updated_at = now()
            WHERE EXCLUDED.last_event_index >= chain_tips.last_event_index
            RETURNING last_event_index
            ",
        )
        .bind(list_key.as_slice())
        .bind(chain_id)
        .bind(upstream_url)
        .bind(last_event_index)
        .bind(last_tip_merkleroot.as_ref().map(<[u8; 32]>::as_slice))
        .fetch_optional(&mut **tx)
        .await?;

        if row.is_none() {
            return Err(StoreError::ChainTipRegression {
                list_key: format!("0x{}", hex::encode(list_key.as_slice())),
                chain_id: chain_id_u64,
                upstream_url: upstream_url.to_string(),
                proposed: proposed_event_index,
            });
        }

        Ok(())
    }

    pub async fn upsert_blocked_shields(
        tx: &mut Transaction<'_, Postgres>,
        list_key: &FixedBytes<32>,
        chain_id: u64,
        records: &[SignedBlockedShield],
    ) -> Result<(), StoreError> {
        let chain_id = u64_to_i64(chain_id, "chain_id")?;
        for record in records {
            let commitment_hash = decode_fixed_hex::<COMMITMENT_HASH_BYTES>(
                "commitment_hash",
                &record.commitment_hash,
            )?;
            let blinded_commitment = decode_fixed_hex::<BLINDED_COMMITMENT_BYTES>(
                "blinded_commitment",
                &record.blinded_commitment,
            )?;
            let signature = decode_fixed_hex::<SIGNATURE_BYTES>("signature", &record.signature)?;

            sqlx::query(
                r"
                INSERT INTO blocked_shields (
                    list_key, chain_id, blinded_commitment, commitment_hash, signature, block_reason
                )
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (list_key, chain_id, blinded_commitment) DO UPDATE SET
                    commitment_hash = EXCLUDED.commitment_hash,
                    signature = EXCLUDED.signature,
                    block_reason = EXCLUDED.block_reason,
                    fetched_at = now()
                ",
            )
            .bind(list_key.as_slice())
            .bind(chain_id)
            .bind(blinded_commitment.as_slice())
            .bind(commitment_hash.as_slice())
            .bind(signature.as_slice())
            .bind(&record.block_reason)
            .execute(&mut **tx)
            .await?;
        }
        Ok(())
    }

    pub async fn replace_blocked_shields(
        tx: &mut Transaction<'_, Postgres>,
        list_key: &FixedBytes<32>,
        chain_id: u64,
        records: &[SignedBlockedShield],
    ) -> Result<(), StoreError> {
        let chain_id_i64 = u64_to_i64(chain_id, "chain_id")?;
        sqlx::query(
            r"
            DELETE FROM blocked_shields
            WHERE list_key = $1 AND chain_id = $2
            ",
        )
        .bind(list_key.as_slice())
        .bind(chain_id_i64)
        .execute(&mut **tx)
        .await?;

        Self::upsert_blocked_shields(tx, list_key, chain_id, records).await
    }

    pub async fn page_event_range(
        &self,
        list_key: &FixedBytes<32>,
        chain_id: u64,
        start_index: u64,
        end_index: u64,
    ) -> Result<Vec<StoredEvent>, StoreError> {
        let chain_id = u64_to_i64(chain_id, "chain_id")?;
        let start_index = u64_to_i64(start_index, "start_index")?;
        let end_index = u64_to_i64(end_index, "end_index")?;
        let rows = sqlx::query_as::<_, (i64, Vec<u8>, Vec<u8>, i16)>(
            r"
            SELECT event_index, blinded_commitment, signature, event_type
            FROM poi_events
            WHERE list_key = $1
                AND chain_id = $2
                AND event_index BETWEEN $3 AND $4
            ORDER BY event_index ASC
            ",
        )
        .bind(list_key.as_slice())
        .bind(chain_id)
        .bind(start_index)
        .bind(end_index)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|(event_index, blinded_commitment, signature, event_type)| {
                Ok(StoredEvent {
                    event_index: i64_to_u64(event_index, "event_index")?,
                    blinded_commitment: exact_array("blinded_commitment", &blinded_commitment)?,
                    signature: exact_array("signature", &signature)?,
                    event_type: event_type_from_discriminant(event_type)?,
                })
            })
            .collect()
    }

    pub async fn all_blocked_shields(
        &self,
        list_key: &FixedBytes<32>,
        chain_id: u64,
    ) -> Result<Vec<StoredBlockedShield>, StoreError> {
        let chain_id = u64_to_i64(chain_id, "chain_id")?;
        let rows = sqlx::query_as::<_, (Vec<u8>, Vec<u8>, Option<String>, Vec<u8>)>(
            r"
            SELECT commitment_hash, blinded_commitment, block_reason, signature
            FROM blocked_shields
            WHERE list_key = $1 AND chain_id = $2
            ORDER BY blinded_commitment ASC
            ",
        )
        .bind(list_key.as_slice())
        .bind(chain_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(
                |(commitment_hash, blinded_commitment, block_reason, signature)| {
                    Ok(StoredBlockedShield {
                        commitment_hash: exact_array("commitment_hash", &commitment_hash)?,
                        blinded_commitment: exact_array("blinded_commitment", &blinded_commitment)?,
                        block_reason,
                        signature: exact_array("signature", &signature)?,
                    })
                },
            )
            .collect()
    }

    pub async fn last_ipns_sequence(&self) -> Result<Option<u64>, StoreError> {
        let value = sqlx::query_scalar::<_, i64>("SELECT value FROM indexer_state WHERE key = $1")
            .bind(IPNS_SEQUENCE_STATE_KEY)
            .fetch_optional(&self.pool)
            .await?;

        value
            .map(|value| i64_to_u64(value, "ipns_last_sequence"))
            .transpose()
    }

    pub async fn record_ipns_sequence(&self, sequence: u64) -> Result<(), StoreError> {
        let sequence = u64_to_i64(sequence, "ipns_last_sequence")?;
        sqlx::query(
            r"
            INSERT INTO indexer_state (key, value)
            VALUES ($1, $2)
            ON CONFLICT (key) DO UPDATE SET
                value = GREATEST(indexer_state.value, EXCLUDED.value),
                updated_at = now()
            ",
        )
        .bind(IPNS_SEQUENCE_STATE_KEY)
        .bind(sequence)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEvent {
    pub event_index: u64,
    pub blinded_commitment: [u8; 32],
    pub signature: [u8; 64],
    pub event_type: PoiEventType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredBlockedShield {
    pub commitment_hash: [u8; 32],
    pub blinded_commitment: [u8; 32],
    pub block_reason: Option<String>,
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredChainTip {
    pub last_event_index: u64,
    pub last_tip_merkleroot: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPublication {
    pub kind: SnapshotKind,
    pub start_index: u64,
    pub end_index: u64,
    pub cid: String,
    pub byte_size: u64,
    pub content_hash: [u8; 32],
    pub tip_merkleroot: Option<[u8; 32]>,
    pub published_at: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredBlockedShieldsPublication {
    pub cid: String,
    pub byte_size: u64,
    pub content_hash: [u8; 32],
    pub published_at: SystemTime,
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database operation failed")]
    Sqlx(#[from] sqlx::Error),
    #[error("invalid hex in {field}")]
    Hex {
        field: &'static str,
        #[source]
        source: hex::FromHexError,
    },
    #[error("decoded {field} has {actual} bytes, expected {expected}")]
    HexLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("{field} value {value} is outside supported range")]
    IntegerOutOfRange { field: &'static str, value: String },
    #[error(
        "chain tip would regress for list_key={list_key} chain_id={chain_id} upstream={upstream_url} proposed={proposed}"
    )]
    ChainTipRegression {
        list_key: String,
        chain_id: u64,
        upstream_url: String,
        proposed: u64,
    },
    #[error("invalid stored POI event type {0}")]
    InvalidEventType(i16),
    #[error("invalid stored snapshot kind {0}")]
    InvalidSnapshotKind(String),
}

pub async fn run_migrations(pool: &PgPool) -> Result<(), StoreError> {
    sqlx::query(SCHEMA_VERSION_TABLE).execute(pool).await?;

    let mut tx = pool.begin().await?;
    sqlx::query(
        r"
        INSERT INTO poi_indexer_schema_version (id, version, applied_at)
        VALUES (TRUE, 0, now())
        ON CONFLICT (id) DO NOTHING
        ",
    )
    .execute(&mut *tx)
    .await?;

    let current_version = sqlx::query_scalar::<_, i32>(
        r"
        SELECT version
        FROM poi_indexer_schema_version
        WHERE id = TRUE
        FOR UPDATE
        ",
    )
    .fetch_one(&mut *tx)
    .await?;

    if current_version >= CURRENT_SCHEMA_VERSION {
        tx.commit().await?;
        info!(version = current_version, "POI indexer schema is current");
        return Ok(());
    }

    info!(
        from_version = current_version,
        to_version = CURRENT_SCHEMA_VERSION,
        "applying POI indexer schema migrations"
    );

    for &(target_version, statements) in VERSIONED_MIGRATIONS {
        if target_version <= current_version {
            continue;
        }

        for statement in statements {
            sqlx::query(statement).execute(&mut *tx).await?;
        }

        sqlx::query(
            r"
            UPDATE poi_indexer_schema_version
            SET version = $1, applied_at = now()
            WHERE id = TRUE
            ",
        )
        .bind(target_version)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(())
}

const BLINDED_COMMITMENT_BYTES: usize = 32;
const COMMITMENT_HASH_BYTES: usize = 32;
const MERKLEROOT_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;

const SCHEMA_VERSION_TABLE: &str = r"
CREATE TABLE IF NOT EXISTS poi_indexer_schema_version (
    id BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    version INTEGER NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
)
";

const VERSIONED_MIGRATIONS: &[(i32, &[&str])] = &[(4, V4_MIGRATIONS)];

const V4_MIGRATIONS: &[&str] = &[
    r"
    CREATE TABLE IF NOT EXISTS poi_events (
        list_key BYTEA NOT NULL,
        chain_id BIGINT NOT NULL,
        event_index BIGINT NOT NULL,
        blinded_commitment BYTEA NOT NULL,
        signature BYTEA NOT NULL,
        event_type SMALLINT NOT NULL,
        fetched_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (list_key, chain_id, event_index)
    )
    ",
    r"
    CREATE TABLE IF NOT EXISTS blocked_shields (
        list_key BYTEA NOT NULL,
        chain_id BIGINT NOT NULL,
        blinded_commitment BYTEA NOT NULL,
        commitment_hash BYTEA NOT NULL,
        signature BYTEA NOT NULL,
        block_reason TEXT,
        fetched_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (list_key, chain_id, blinded_commitment)
    )
    ",
    r"
    CREATE TABLE IF NOT EXISTS chain_tips (
        list_key BYTEA NOT NULL,
        chain_id BIGINT NOT NULL,
        upstream_url TEXT NOT NULL,
        last_event_index BIGINT NOT NULL,
        last_tip_merkleroot BYTEA,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (list_key, chain_id, upstream_url)
    )
    ",
    r"
    CREATE TABLE IF NOT EXISTS published_snapshots (
        id BIGSERIAL PRIMARY KEY,
        list_key BYTEA NOT NULL,
        chain_id BIGINT NOT NULL,
        upstream_url TEXT NOT NULL,
        kind TEXT NOT NULL,
        start_index BIGINT NOT NULL,
        end_index BIGINT NOT NULL,
        cid TEXT NOT NULL,
        byte_size BIGINT NOT NULL,
        content_hash BYTEA,
        format_version INTEGER NOT NULL,
        tip_merkleroot BYTEA,
        published_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        superseded_at TIMESTAMPTZ,
        unpinned_at TIMESTAMPTZ
    )
    ",
    r"
    CREATE TABLE IF NOT EXISTS published_blocked_shields (
        id BIGSERIAL PRIMARY KEY,
        list_key BYTEA NOT NULL,
        chain_id BIGINT NOT NULL,
        upstream_url TEXT NOT NULL,
        cid TEXT NOT NULL,
        byte_size BIGINT NOT NULL,
        format_version INTEGER NOT NULL,
        content_hash BYTEA NOT NULL,
        published_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        superseded_at TIMESTAMPTZ,
        unpinned_at TIMESTAMPTZ
    )
    ",
    r"
    CREATE TABLE IF NOT EXISTS indexer_state (
        key TEXT PRIMARY KEY,
        value BIGINT NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
    ",
    r"
    ALTER TABLE poi_events
        ALTER COLUMN event_type TYPE SMALLINT USING CASE event_type::TEXT
            WHEN 'Shield' THEN 0
            WHEN 'Transact' THEN 1
            WHEN 'Unshield' THEN 2
            WHEN 'LegacyTransact' THEN 3
            ELSE event_type::SMALLINT
        END
    ",
    r"
    ALTER TABLE published_snapshots
        ADD COLUMN IF NOT EXISTS upstream_url TEXT
    ",
    r"
    WITH upstream_counts AS (
        SELECT
            list_key,
            chain_id,
            COUNT(DISTINCT upstream_url) AS upstream_count,
            MIN(upstream_url) AS upstream_url
        FROM chain_tips
        GROUP BY list_key, chain_id
    )
    UPDATE published_snapshots AS snapshots
    SET upstream_url = upstream_counts.upstream_url
    FROM upstream_counts
    WHERE snapshots.list_key = upstream_counts.list_key
        AND snapshots.chain_id = upstream_counts.chain_id
        AND upstream_counts.upstream_count = 1
        AND snapshots.upstream_url IS NULL
    ",
    r"
    UPDATE published_snapshots
    SET upstream_url = '__unknown_upstream__'
    WHERE upstream_url IS NULL
    ",
    r"
    ALTER TABLE published_snapshots
        ALTER COLUMN upstream_url SET NOT NULL
    ",
    r"
    ALTER TABLE published_snapshots
        ADD COLUMN IF NOT EXISTS unpinned_at TIMESTAMPTZ
    ",
    r"
    ALTER TABLE published_snapshots
        ADD COLUMN IF NOT EXISTS content_hash BYTEA
    ",
    r"
    UPDATE published_snapshots
    SET superseded_at = now()
    WHERE content_hash IS NULL
        AND superseded_at IS NULL
    ",
    r"
    UPDATE published_snapshots
    SET superseded_at = now()
    WHERE upstream_url = '__unknown_upstream__'
        AND superseded_at IS NULL
    ",
    r"
    DO $$
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'poi_events_event_type_check') THEN
            ALTER TABLE poi_events
                ADD CONSTRAINT poi_events_event_type_check CHECK (event_type BETWEEN 0 AND 3);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'poi_events_list_key_len_check') THEN
            ALTER TABLE poi_events
                ADD CONSTRAINT poi_events_list_key_len_check CHECK (octet_length(list_key) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'poi_events_blinded_len_check') THEN
            ALTER TABLE poi_events
                ADD CONSTRAINT poi_events_blinded_len_check CHECK (octet_length(blinded_commitment) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'poi_events_signature_len_check') THEN
            ALTER TABLE poi_events
                ADD CONSTRAINT poi_events_signature_len_check CHECK (octet_length(signature) = 64);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'blocked_shields_list_key_len_check') THEN
            ALTER TABLE blocked_shields
                ADD CONSTRAINT blocked_shields_list_key_len_check CHECK (octet_length(list_key) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'blocked_shields_blinded_len_check') THEN
            ALTER TABLE blocked_shields
                ADD CONSTRAINT blocked_shields_blinded_len_check CHECK (octet_length(blinded_commitment) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'blocked_shields_commitment_len_check') THEN
            ALTER TABLE blocked_shields
                ADD CONSTRAINT blocked_shields_commitment_len_check CHECK (octet_length(commitment_hash) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'blocked_shields_signature_len_check') THEN
            ALTER TABLE blocked_shields
                ADD CONSTRAINT blocked_shields_signature_len_check CHECK (octet_length(signature) = 64);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chain_tips_tip_root_len_check') THEN
            ALTER TABLE chain_tips
                ADD CONSTRAINT chain_tips_tip_root_len_check CHECK (last_tip_merkleroot IS NULL OR octet_length(last_tip_merkleroot) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'published_snapshots_kind_check') THEN
            ALTER TABLE published_snapshots
                ADD CONSTRAINT published_snapshots_kind_check CHECK (kind IN ('base', 'delta'));
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'published_snapshots_tip_root_len_check') THEN
            ALTER TABLE published_snapshots
                ADD CONSTRAINT published_snapshots_tip_root_len_check CHECK (tip_merkleroot IS NULL OR octet_length(tip_merkleroot) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'published_snapshots_content_hash_len_check') THEN
            ALTER TABLE published_snapshots
                ADD CONSTRAINT published_snapshots_content_hash_len_check CHECK (content_hash IS NULL OR octet_length(content_hash) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'published_blocked_shields_list_key_len_check') THEN
            ALTER TABLE published_blocked_shields
                ADD CONSTRAINT published_blocked_shields_list_key_len_check CHECK (octet_length(list_key) = 32);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'published_blocked_shields_content_hash_len_check') THEN
            ALTER TABLE published_blocked_shields
                ADD CONSTRAINT published_blocked_shields_content_hash_len_check CHECK (octet_length(content_hash) = 32);
        END IF;
    END $$
    ",
    "CREATE INDEX IF NOT EXISTS poi_events_lookup ON poi_events (list_key, chain_id, blinded_commitment)",
    "CREATE INDEX IF NOT EXISTS published_snapshots_active_lookup ON published_snapshots (list_key, chain_id, upstream_url, kind, start_index, id) WHERE superseded_at IS NULL",
    "CREATE INDEX IF NOT EXISTS published_snapshots_retention_lookup ON published_snapshots (superseded_at, unpinned_at, cid) WHERE superseded_at IS NOT NULL AND unpinned_at IS NULL",
    "CREATE INDEX IF NOT EXISTS published_snapshots_cid_live_lookup ON published_snapshots (cid) WHERE superseded_at IS NULL",
    "CREATE INDEX IF NOT EXISTS published_blocked_shields_active_lookup ON published_blocked_shields (list_key, chain_id, upstream_url, id) WHERE superseded_at IS NULL",
    "CREATE INDEX IF NOT EXISTS published_blocked_shields_retention_lookup ON published_blocked_shields (superseded_at, unpinned_at, cid) WHERE superseded_at IS NOT NULL AND unpinned_at IS NULL",
    "CREATE INDEX IF NOT EXISTS published_blocked_shields_cid_live_lookup ON published_blocked_shields (cid) WHERE superseded_at IS NULL",
];

fn decode_fixed_hex<const N: usize>(
    field: &'static str,
    value: &str,
) -> Result<[u8; N], StoreError> {
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .map_err(|source| StoreError::Hex { field, source })?;
    exact_array(field, &bytes)
}

fn exact_array<const N: usize>(field: &'static str, bytes: &[u8]) -> Result<[u8; N], StoreError> {
    bytes.try_into().map_err(|_| StoreError::HexLength {
        field,
        expected: N,
        actual: bytes.len(),
    })
}

fn u64_to_i64(value: u64, field: &'static str) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::IntegerOutOfRange {
        field,
        value: value.to_string(),
    })
}

fn i64_to_u64(value: i64, field: &'static str) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::IntegerOutOfRange {
        field,
        value: value.to_string(),
    })
}

fn i64_to_system_time(value: i64, field: &'static str) -> Result<SystemTime, StoreError> {
    let seconds = i64_to_u64(value, field)?;
    Ok(UNIX_EPOCH + Duration::from_secs(seconds))
}

fn parse_snapshot_kind(value: &str) -> Result<SnapshotKind, StoreError> {
    match value {
        "base" => Ok(SnapshotKind::Base),
        "delta" => Ok(SnapshotKind::Delta),
        _ => Err(StoreError::InvalidSnapshotKind(value.to_string())),
    }
}

const fn event_type_discriminant(event_type: PoiEventType) -> i16 {
    match event_type {
        PoiEventType::Shield => 0,
        PoiEventType::Transact => 1,
        PoiEventType::Unshield => 2,
        PoiEventType::LegacyTransact => 3,
    }
}

const fn event_type_from_discriminant(value: i16) -> Result<PoiEventType, StoreError> {
    match value {
        0 => Ok(PoiEventType::Shield),
        1 => Ok(PoiEventType::Transact),
        2 => Ok(PoiEventType::Unshield),
        3 => Ok(PoiEventType::LegacyTransact),
        _ => Err(StoreError::InvalidEventType(value)),
    }
}
