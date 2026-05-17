# POI Indexer

`poi-indexer` mirrors a POI JSON-RPC node into Postgres, builds binary POI
snapshots plus current blocked-shields artifacts, pins artifacts and manifests
to IPFS, and updates IPNS under the publisher key.

## Prerequisites

- Rust workspace dependencies from the repository root.
- PostgreSQL reachable from the indexer host.
- Filebase S3/IPFS bucket credentials for v1 pinning.
- A 32-byte ed25519 publisher signing key stored on local disk.

## Publisher Key

The key file may contain either 32 raw bytes or hex text for the 32-byte
ed25519 signing seed.

```bash
mkdir -p secrets
openssl rand -hex 32 > secrets/poi-indexer-publisher.key
chmod 600 secrets/poi-indexer-publisher.key
```

The same key signs the manifest and publishes the IPNS record, so wallets need
only one publisher trust anchor.

## Configuration

Start from the repository-root example:

```bash
cp config.poi-indexer.example.yaml config.poi-indexer.yaml
```

Important fields:

- `upstream_url`: POI JSON-RPC endpoint to mirror, for example `https://ppoi.fdi.network`.
- `list_keys`: upstream list operator public keys to mirror.
- `chain_ids`: supported chain IDs: `1`, `56`, `137`, `42161`.
- `postgres_connection_string`: durable store connection string.
- `ipfs_endpoint`: Filebase S3-compatible endpoint, normally `https://s3.filebase.com`.
- `publisher_signing_key_path`: key file described above.
- `delta_publish_interval`, `base_rebuild_interval`, `retention_interval`: publication and cleanup cadences.
- `per_pair_concurrency_limit`: maximum concurrent `(list_key, chain_id)` sync workers.

The binary applies a small inline, idempotent Postgres schema setup at startup;
it does not need external migration files beside the deployed executable.

The v1 Filebase publisher uses normal S3 `PutObject` uploads. Filebase returns
the IPFS CID in object metadata, and the indexer copies each object to a stable
CID-based key so later retention sweeps can delete it by CID.

Manifest entries publish signed artifact descriptors for every base snapshot,
delta snapshot, and blocked-shields artifact. Each descriptor contains the IPFS
`cid`, SHA-256 as `sha256`, and `byte_size`; wallets must verify those bytes
before parsing artifacts. IPFS/Filebase/gateways are transport only, while the
publisher signature and upstream list-key signatures are the trust boundaries.

Use the root Filebase S3 endpoint, not a bucket-specific host such as
`https://<bucket>.s3.filebase.io`. The bucket is supplied separately with
`POI_INDEXER_FILEBASE_BUCKET`.

Filebase credentials are read from environment variables:

```bash
export POI_INDEXER_FILEBASE_ACCESS_KEY=...
export POI_INDEXER_FILEBASE_SECRET_KEY=...
export POI_INDEXER_FILEBASE_BUCKET=...
```

## Running

```bash
cargo run --bin poi-indexer -- --config config.poi-indexer.yaml
```

The status server binds to `127.0.0.1:8080` by default. Override with
`--status-bind-addr` or `POI_INDEXER_STATUS_BIND_ADDR`.

```bash
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8080/status
```

## First Run

The first bootstrap can take multiple hours because the public upstream slows
down at deep offsets. The indexer is resumable: after each committed page it
persists `chain_tips`, so a restart continues from the last committed cursor.

During bootstrap, expect:

- Adaptive page sizes to shrink during slow upstream ranges and grow again after successes.
- Base snapshots and blocked-shields artifacts to be published once a chain/list has a persisted tip.
- Deltas to be published on later `delta_publish_interval` ticks.

## Common Failures

- Upstream unreachable: page failures and retry/backoff state appear in `/status`; the scraper retries bounded failures and shrinks page size before surfacing a hard error.
- Postgres connection lost: scrape, publication, and retention cycles log failures and retry; restore Postgres and the next cycle resumes from durable state.
- IPFS pinning quota exceeded: publication cycles log the pinning error and retry on the next publication tick; existing published artifacts remain in Postgres for audit.
- Provider data loss or cleared bucket: publication cycles verify active snapshot and blocked-shields CIDs before publishing a descriptor manifest. If an active snapshot CID is missing, the indexer rebuilds a fresh base snapshot for that `(list_key, chain_id)` and supersedes the old active base/deltas. If an active blocked-shields CID is missing, the indexer repins the current blocked-shields artifact. Superseded CIDs remain in the audit tables and are cleaned up by retention later.
- IPNS DHT publish timeout: manifest pinning may succeed while IPNS update fails; the scheduler retries on the next publication or republish tick.
- Retention sweep behavior: superseded CIDs older than `retention_interval` are unpinned, but `published_snapshots` and `published_blocked_shields` rows are retained permanently for audit.
