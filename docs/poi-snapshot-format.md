# POI Snapshot Format v2

This document is the stable contract for files produced by `poi-indexer`.
Wallet ingestion is implemented separately, but readers can use this layout to
download snapshots, verify upstream signatures, and rebuild the POI tree.

## Snapshot Files

Each snapshot is scoped to one `(list_key, chain_id, kind)` tuple. `kind` is
`base` or `delta`. Snapshots contain POI events only; the current blocked-shield
set is published as a separate manifest-referenced artifact.

- Base snapshot: covers events `[0, N]` and includes no blocked shields.
- Delta snapshot: covers events `[N + 1, M]` and includes no blocked shields.

All integers are little-endian. There is no padding between records.

## Header

| Offset | Size | Field |
| --- | ---: | --- |
| 0 | 8 | Magic bytes `POISNAP\0` |
| 8 | 2 | Format version, currently `2` |
| 10 | 2 | Header length, currently `176` |
| 12 | 1 | Chain type, `0` for EVM |
| 13 | 1 | Snapshot kind: `0` base, `1` delta |
| 14 | 2 | Reserved, zero in v2 |
| 16 | 32 | POI list key, raw ed25519 public key bytes |
| 48 | 8 | Chain ID |
| 56 | 8 | Inclusive start event index |
| 64 | 8 | Inclusive end event index |
| 72 | 8 | Event record count |
| 80 | 8 | Blocked-shield record count, always `0` in v2 snapshots |
| 88 | 32 | Tip POI merkleroot at `end_index` |
| 120 | 32 | SHA-256 hash of upstream endpoint string |
| 152 | 8 | Creation time as Unix seconds |
| 160 | 8 | Byte offset of event records |
| 168 | 8 | Byte offset of blocked-shield records |

## Event Records

Each event record is exactly 97 bytes:

| Offset | Size | Field |
| --- | ---: | --- |
| 0 | 32 | Blinded commitment |
| 32 | 64 | Upstream ed25519 signature bytes |
| 96 | 1 | Event type discriminant |

Event type discriminants:

- `0`: `Shield`
- `1`: `Transact`
- `2`: `Unshield`
- `3`: `LegacyTransact`

Records are written in strictly increasing `event_index` order. The first event
record corresponds to `start_index`; subsequent records increment by one.

## Blocked-Shields Artifact

Each manifest entry has a `blocked_shields` artifact descriptor pointing to the
current blocked-shields artifact for that `(list_key, chain_id)`. The artifact
is deterministic JSON sorted by `blinded_commitment`, then `commitment_hash`.

Example:

```json
{
  "format_version": 2,
  "list_key": "0xefc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88",
  "chain_id": 1,
  "chain_type": 0,
  "upstream_endpoint_hash": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "blocked_shields": [
    {
      "commitment_hash": "0x...",
      "blinded_commitment": "0x...",
      "signature": "0x...",
      "block_reason": "Address is blocked"
    }
  ]
}
```

When `blockReason` is absent in the upstream response, `block_reason` is omitted
from the artifact record. When the upstream response contains an empty string,
`block_reason` is present as `""`. This preserves the distinction between an
absent reason and a present empty string.

The artifact descriptor is authenticated by the publisher-signed manifest and
contains the CID, SHA-256, and byte size. Each blocked-shield record's content
remains authenticated by the upstream operator's ed25519 signature.

The legacy binary blocked-shield record layout is not used by v2 snapshots:

| Offset | Size | Field |
| --- | ---: | --- |
| 0 | 32 | Commitment hash |
| 32 | 32 | Blinded commitment |
| 64 | 64 | Upstream ed25519 signature bytes |
| 128 | 1 | Block reason presence flag: `0` absent, `1` present |

When the presence flag is `0`, the record ends at byte `129` and `blockReason`
is omitted from the signed message. When the flag is `1`, it is followed by a
4-byte little-endian reason length and then that many UTF-8 bytes.

## Upstream Signature Verification

The `list_key` is the upstream list operator's raw 32-byte ed25519 public key.
Snapshot readers verify the preserved upstream signatures directly.

POI event signed message bytes are exactly:

```text
{"index":<n>,"blindedCommitment":"<hex>","type":"<variant>"}
```

Fields must appear in that order. `index` is a JSON number. `blindedCommitment`
and `type` are JSON strings.

Blocked-shield signed message bytes are exactly:

```text
{"commitmentHash":"<hex>","blindedCommitment":"<hex>"}
```

When `blockReason` is present, it is appended as the third field:

```text
{"commitmentHash":"<hex>","blindedCommitment":"<hex>","blockReason":"<text>"}
```

When `blockReason` is absent, the field is omitted entirely. It is not encoded
as `null` or an empty string.

## No Bundle Signature

Snapshot format v2 intentionally does not include an indexer/publisher bundle
signature. Event authenticity comes from the upstream operator's per-event
signatures preserved in each record. The publisher signs the manifest instead,
which authenticates the distribution channel and the selected CID set.

## No Per-Event Validated Merkleroot

Snapshots carry only the tip POI merkleroot in the header. Historical per-event
`validated_merkleroot` values are omitted because v2 wallet bootstrap needs the
current reconstructed tree root, not every historical root. This keeps files
smaller while preserving event authenticity through upstream signatures. A
future format can add historical roots behind a new `format_version`.

## Manifest Schema

The manifest is deterministic JSON. The publisher signs the manifest body
excluding `publisher_signature`; then the hex signature is inserted into the
top-level `publisher_signature` field.

Example:

```json
{
  "format_version": 2,
  "issued_at_ms": 1767225600000,
  "sequence": 1767225600000,
  "publisher_pubkey": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "entries": [
    {
      "list_key": "0xefc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88",
      "chain_id": 1,
      "base": {
        "cid": "bafybase...",
        "sha256": "0x1111111111111111111111111111111111111111111111111111111111111111",
        "byte_size": 1048576
      },
      "deltas": [
        {
          "cid": "bafydelta1...",
          "sha256": "0x2222222222222222222222222222222222222222222222222222222222222222",
          "byte_size": 65536
        },
        {
          "cid": "bafydelta2...",
          "sha256": "0x3333333333333333333333333333333333333333333333333333333333333333",
          "byte_size": 32768
        }
      ],
      "blocked_shields": {
        "cid": "bafyblocked...",
        "sha256": "0x4444444444444444444444444444444444444444444444444444444444444444",
        "byte_size": 4096
      },
      "current_tip_index": 12345,
      "current_tip_merkleroot": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }
  ],
  "publisher_signature": "<64-byte-ed25519-signature-hex>"
}
```

Manifest entries are sorted by `list_key`, then `chain_id` before signing.
For each entry, a reader downloads `base.cid`, then every descriptor in `deltas`
in order. Before parsing, the reader verifies the downloaded byte length equals
`byte_size` and SHA-256 equals `sha256`. Applying those files must reproduce
events `[0, current_tip_index]`. The reader also downloads `blocked_shields` to
obtain the current blocked set for the same pair. `sequence` is strictly
monotonic across manifest publications and is also used as the IPNS record
sequence for the manifest publication.

## Manifest Signature Verification

To verify a manifest:

1. Remove `publisher_signature` from the JSON object.
2. Rebuild deterministic body bytes with fields `format_version`, `issued_at_ms`, `sequence`, `publisher_pubkey`, `entries`, including each artifact descriptor's `cid`, `sha256`, and `byte_size`.
3. Sort `entries` by `list_key`, then `chain_id`.
4. Verify `publisher_signature` as ed25519 over those body bytes using `publisher_pubkey`.

After each manifest publication, the indexer publishes an IPNS record pointing
to the manifest CID. The IPNS key is derived from the same ed25519 publisher key.
