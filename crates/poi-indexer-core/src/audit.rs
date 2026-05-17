use crate::publish::ipfs::IpfsClient;
use crate::snapshot::SnapshotKind;
use alloy_primitives::FixedBytes;
use cid::Cid;
use sqlx::{PgPool, Postgres, Transaction};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::warn;

pub struct Audit;

impl Audit {
    pub async fn record_publication(
        tx: &mut Transaction<'_, Postgres>,
        list_key: &FixedBytes<32>,
        chain_id: u64,
        upstream_url: &str,
        kind: SnapshotKind,
        start_index: u64,
        end_index: u64,
        cid: &Cid,
        byte_size: u64,
        content_hash: &[u8; 32],
        format_version: u16,
        tip_merkleroot: &[u8; 32],
    ) -> Result<(), AuditError> {
        let chain_id = u64_to_i64(chain_id, "chain_id")?;
        let start_index = u64_to_i64(start_index, "start_index")?;
        let end_index = u64_to_i64(end_index, "end_index")?;
        let byte_size = u64_to_i64(byte_size, "byte_size")?;
        let format_version = i32::from(format_version);

        if matches!(kind, SnapshotKind::Base) {
            sqlx::query(
                r"
                UPDATE published_snapshots
                SET superseded_at = now()
                WHERE list_key = $1
                    AND chain_id = $2
                    AND superseded_at IS NULL
                ",
            )
            .bind(list_key.as_slice())
            .bind(chain_id)
            .execute(&mut **tx)
            .await?;
        }

        sqlx::query(
            r"
            INSERT INTO published_snapshots (
                list_key,
                chain_id,
                upstream_url,
                kind,
                start_index,
                end_index,
                cid,
                byte_size,
                content_hash,
                format_version,
                tip_merkleroot
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ",
        )
        .bind(list_key.as_slice())
        .bind(chain_id)
        .bind(upstream_url)
        .bind(snapshot_kind_str(kind))
        .bind(start_index)
        .bind(end_index)
        .bind(cid.to_string())
        .bind(byte_size)
        .bind(content_hash.as_slice())
        .bind(format_version)
        .bind(tip_merkleroot.as_slice())
        .execute(&mut **tx)
        .await?;

        Ok(())
    }

    pub async fn record_blocked_shields_publication(
        tx: &mut Transaction<'_, Postgres>,
        list_key: &FixedBytes<32>,
        chain_id: u64,
        upstream_url: &str,
        cid: &Cid,
        byte_size: u64,
        format_version: u16,
        content_hash: &[u8; 32],
    ) -> Result<(), AuditError> {
        let chain_id = u64_to_i64(chain_id, "chain_id")?;
        let byte_size = u64_to_i64(byte_size, "byte_size")?;
        let format_version = i32::from(format_version);

        sqlx::query(
            r"
            UPDATE published_blocked_shields
            SET superseded_at = now()
            WHERE list_key = $1
                AND chain_id = $2
                AND superseded_at IS NULL
            ",
        )
        .bind(list_key.as_slice())
        .bind(chain_id)
        .execute(&mut **tx)
        .await?;

        sqlx::query(
            r"
            INSERT INTO published_blocked_shields (
                list_key,
                chain_id,
                upstream_url,
                cid,
                byte_size,
                format_version,
                content_hash
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ",
        )
        .bind(list_key.as_slice())
        .bind(chain_id)
        .bind(upstream_url)
        .bind(cid.to_string())
        .bind(byte_size)
        .bind(format_version)
        .bind(content_hash.as_slice())
        .execute(&mut **tx)
        .await?;

        Ok(())
    }
}

pub struct Retention;

impl Retention {
    pub async fn sweep(
        pool: &PgPool,
        ipfs_client: &dyn IpfsClient,
        now: SystemTime,
        retention_interval: Duration,
    ) -> Result<RetentionSweep, AuditError> {
        let cutoff = unix_seconds(
            now.checked_sub(retention_interval)
                .ok_or(AuditError::TimeBeforeUnixEpoch)?,
        )?;
        let swept_at = unix_seconds(now)?;
        let cids = sqlx::query_scalar::<_, String>(
            r"
            WITH candidates AS (
                SELECT cid
                FROM published_snapshots
                WHERE superseded_at IS NOT NULL
                    AND superseded_at <= to_timestamp($1)
                    AND unpinned_at IS NULL
                UNION
                SELECT cid
                FROM published_blocked_shields
                WHERE superseded_at IS NOT NULL
                    AND superseded_at <= to_timestamp($1)
                    AND unpinned_at IS NULL
            )
            SELECT DISTINCT candidates.cid
            FROM candidates
            WHERE NOT EXISTS (
                    SELECT 1
                    FROM published_snapshots AS active
                    WHERE active.cid = candidates.cid
                        AND active.superseded_at IS NULL
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM published_blocked_shields AS active
                    WHERE active.cid = candidates.cid
                        AND active.superseded_at IS NULL
                )
            ORDER BY candidates.cid ASC
            ",
        )
        .bind(cutoff)
        .fetch_all(pool)
        .await?;

        let mut unpinned_cids = Vec::with_capacity(cids.len());
        let mut failed_cids = Vec::new();
        for cid_text in cids {
            let cid = parse_cid(&cid_text)?;
            if let Err(error) = ipfs_client.unpin(&cid).await {
                warn!(cid = %cid, error = %error, "failed to unpin superseded POI artifact CID");
                failed_cids.push(RetentionFailure {
                    cid,
                    error: error.to_string(),
                });
                continue;
            }
            sqlx::query(
                r"
                UPDATE published_snapshots
                SET unpinned_at = to_timestamp($1)
                WHERE cid = $2
                    AND superseded_at IS NOT NULL
                    AND superseded_at <= to_timestamp($3)
                    AND unpinned_at IS NULL
                    AND NOT EXISTS (
                        SELECT 1
                        FROM published_snapshots AS active
                        WHERE active.cid = $2
                            AND active.superseded_at IS NULL
                    )
                    AND NOT EXISTS (
                        SELECT 1
                        FROM published_blocked_shields AS active
                        WHERE active.cid = $2
                            AND active.superseded_at IS NULL
                    )
                ",
            )
            .bind(swept_at)
            .bind(&cid_text)
            .bind(cutoff)
            .execute(pool)
            .await?;
            sqlx::query(
                r"
                UPDATE published_blocked_shields
                SET unpinned_at = to_timestamp($1)
                WHERE cid = $2
                    AND superseded_at IS NOT NULL
                    AND superseded_at <= to_timestamp($3)
                    AND unpinned_at IS NULL
                    AND NOT EXISTS (
                        SELECT 1
                        FROM published_snapshots AS active
                        WHERE active.cid = $2
                            AND active.superseded_at IS NULL
                    )
                    AND NOT EXISTS (
                        SELECT 1
                        FROM published_blocked_shields AS active
                        WHERE active.cid = $2
                            AND active.superseded_at IS NULL
                    )
                ",
            )
            .bind(swept_at)
            .bind(&cid_text)
            .bind(cutoff)
            .execute(pool)
            .await?;
            unpinned_cids.push(cid);
        }

        Ok(RetentionSweep {
            unpinned_cids,
            failed_cids,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionSweep {
    pub unpinned_cids: Vec<Cid>,
    pub failed_cids: Vec<RetentionFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionFailure {
    pub cid: Cid,
    pub error: String,
}

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("database operation failed")]
    Sqlx(#[from] sqlx::Error),
    #[error("invalid stored publication CID {cid}")]
    InvalidCid {
        cid: String,
        #[source]
        source: cid::Error,
    },
    #[error("{field} value {value} is outside supported range")]
    IntegerOutOfRange { field: &'static str, value: String },
    #[error("retention cutoff is before unix epoch")]
    TimeBeforeUnixEpoch,
}

const fn snapshot_kind_str(kind: SnapshotKind) -> &'static str {
    match kind {
        SnapshotKind::Base => "base",
        SnapshotKind::Delta => "delta",
    }
}

fn u64_to_i64(value: u64, field: &'static str) -> Result<i64, AuditError> {
    i64::try_from(value).map_err(|_| AuditError::IntegerOutOfRange {
        field,
        value: value.to_string(),
    })
}

fn unix_seconds(value: SystemTime) -> Result<i64, AuditError> {
    let duration = value
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AuditError::TimeBeforeUnixEpoch)?;
    u64_to_i64(duration.as_secs(), "retention cutoff")
}

fn parse_cid(value: &str) -> Result<Cid, AuditError> {
    Cid::try_from(value).map_err(|source| AuditError::InvalidCid {
        cid: value.to_string(),
        source,
    })
}
