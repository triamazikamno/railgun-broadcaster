use thiserror::Error;

use crate::poi::PoiEventType;

pub mod format {
    pub const MAGIC: &[u8; 8] = b"POISNAP\0";
    pub const FORMAT_VERSION: u16 = 2;

    pub const MAGIC_OFFSET: usize = 0;
    pub const MAGIC_BYTES: usize = 8;
    pub const FORMAT_VERSION_OFFSET: usize = MAGIC_OFFSET + MAGIC_BYTES;
    pub const FORMAT_VERSION_BYTES: usize = 2;
    pub const HEADER_LEN_OFFSET: usize = FORMAT_VERSION_OFFSET + FORMAT_VERSION_BYTES;
    pub const HEADER_LEN_BYTES: usize = 2;
    pub const CHAIN_TYPE_OFFSET: usize = HEADER_LEN_OFFSET + HEADER_LEN_BYTES;
    pub const CHAIN_TYPE_BYTES: usize = 1;
    pub const SNAPSHOT_KIND_OFFSET: usize = CHAIN_TYPE_OFFSET + CHAIN_TYPE_BYTES;
    pub const SNAPSHOT_KIND_BYTES: usize = 1;
    pub const RESERVED_OFFSET: usize = SNAPSHOT_KIND_OFFSET + SNAPSHOT_KIND_BYTES;
    pub const RESERVED_BYTES: usize = 2;
    pub const LIST_KEY_OFFSET: usize = RESERVED_OFFSET + RESERVED_BYTES;
    pub const LIST_KEY_BYTES: usize = 32;
    pub const CHAIN_ID_OFFSET: usize = LIST_KEY_OFFSET + LIST_KEY_BYTES;
    pub const CHAIN_ID_BYTES: usize = 8;
    pub const START_INDEX_OFFSET: usize = CHAIN_ID_OFFSET + CHAIN_ID_BYTES;
    pub const START_INDEX_BYTES: usize = 8;
    pub const END_INDEX_OFFSET: usize = START_INDEX_OFFSET + START_INDEX_BYTES;
    pub const END_INDEX_BYTES: usize = 8;
    pub const EVENT_COUNT_OFFSET: usize = END_INDEX_OFFSET + END_INDEX_BYTES;
    pub const EVENT_COUNT_BYTES: usize = 8;
    pub const BLOCKED_SHIELD_COUNT_OFFSET: usize = EVENT_COUNT_OFFSET + EVENT_COUNT_BYTES;
    pub const BLOCKED_SHIELD_COUNT_BYTES: usize = 8;
    pub const TIP_MERKLEROOT_OFFSET: usize =
        BLOCKED_SHIELD_COUNT_OFFSET + BLOCKED_SHIELD_COUNT_BYTES;
    pub const TIP_MERKLEROOT_BYTES: usize = 32;
    pub const UPSTREAM_ENDPOINT_HASH_OFFSET: usize = TIP_MERKLEROOT_OFFSET + TIP_MERKLEROOT_BYTES;
    pub const UPSTREAM_ENDPOINT_HASH_BYTES: usize = 32;
    pub const CREATED_AT_OFFSET: usize =
        UPSTREAM_ENDPOINT_HASH_OFFSET + UPSTREAM_ENDPOINT_HASH_BYTES;
    pub const CREATED_AT_BYTES: usize = 8;
    pub const EVENTS_OFFSET_OFFSET: usize = CREATED_AT_OFFSET + CREATED_AT_BYTES;
    pub const EVENTS_OFFSET_BYTES: usize = 8;
    pub const BLOCKED_SHIELDS_OFFSET_OFFSET: usize = EVENTS_OFFSET_OFFSET + EVENTS_OFFSET_BYTES;
    pub const BLOCKED_SHIELDS_OFFSET_BYTES: usize = 8;
    pub const HEADER_LEN: usize = BLOCKED_SHIELDS_OFFSET_OFFSET + BLOCKED_SHIELDS_OFFSET_BYTES;
    pub const HEADER_LEN_U16: u16 = 176;
    pub const HEADER_LEN_U64: u64 = 176;

    pub const EVENT_BLINDED_COMMITMENT_OFFSET: usize = 0;
    pub const EVENT_BLINDED_COMMITMENT_BYTES: usize = 32;
    pub const EVENT_SIGNATURE_OFFSET: usize =
        EVENT_BLINDED_COMMITMENT_OFFSET + EVENT_BLINDED_COMMITMENT_BYTES;
    pub const EVENT_SIGNATURE_BYTES: usize = 64;
    pub const EVENT_TYPE_OFFSET: usize = EVENT_SIGNATURE_OFFSET + EVENT_SIGNATURE_BYTES;
    pub const EVENT_TYPE_BYTES: usize = 1;
    pub const EVENT_RECORD_BYTES: usize = EVENT_TYPE_OFFSET + EVENT_TYPE_BYTES;
    pub const EVENT_RECORD_BYTES_U64: u64 = 97;

    pub const BLOCKED_COMMITMENT_HASH_OFFSET: usize = 0;
    pub const BLOCKED_COMMITMENT_HASH_BYTES: usize = 32;
    pub const BLOCKED_BLINDED_COMMITMENT_OFFSET: usize =
        BLOCKED_COMMITMENT_HASH_OFFSET + BLOCKED_COMMITMENT_HASH_BYTES;
    pub const BLOCKED_BLINDED_COMMITMENT_BYTES: usize = 32;
    pub const BLOCKED_SIGNATURE_OFFSET: usize =
        BLOCKED_BLINDED_COMMITMENT_OFFSET + BLOCKED_BLINDED_COMMITMENT_BYTES;
    pub const BLOCKED_SIGNATURE_BYTES: usize = 64;
    pub const BLOCKED_REASON_PRESENT_OFFSET: usize =
        BLOCKED_SIGNATURE_OFFSET + BLOCKED_SIGNATURE_BYTES;
    pub const BLOCKED_REASON_PRESENT_BYTES: usize = 1;
    pub const BLOCKED_REASON_LEN_OFFSET: usize =
        BLOCKED_REASON_PRESENT_OFFSET + BLOCKED_REASON_PRESENT_BYTES;
    pub const BLOCKED_REASON_LEN_BYTES: usize = 4;
    pub const BLOCKED_SHIELD_FIXED_RECORD_BYTES: usize = BLOCKED_REASON_PRESENT_OFFSET + 1;
    pub const BLOCKED_REASON_ABSENT: u8 = 0;
    pub const BLOCKED_REASON_PRESENT: u8 = 1;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotKind {
    Base,
    Delta,
}

impl SnapshotKind {
    const fn discriminant(self) -> u8 {
        match self {
            Self::Base => 0,
            Self::Delta => 1,
        }
    }

    const fn from_discriminant(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Base),
            1 => Some(Self::Delta),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotHeaderInput {
    pub list_key: [u8; 32],
    pub chain_id: u64,
    pub chain_type: u8,
    pub kind: SnapshotKind,
    pub start_index: u64,
    pub end_index: u64,
    pub tip_merkleroot: [u8; 32],
    pub upstream_endpoint_hash: [u8; 32],
    pub created_at_unix_seconds: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotHeader {
    pub format_version: u16,
    pub header_len: u16,
    pub list_key: [u8; 32],
    pub chain_id: u64,
    pub chain_type: u8,
    pub kind: SnapshotKind,
    pub start_index: u64,
    pub end_index: u64,
    pub event_count: u64,
    pub blocked_shield_count: u64,
    pub tip_merkleroot: [u8; 32],
    pub upstream_endpoint_hash: [u8; 32],
    pub created_at_unix_seconds: i64,
    pub events_offset: u64,
    pub blocked_shields_offset: u64,
}

impl SnapshotHeader {
    #[must_use]
    pub const fn publisher_signature(&self) -> Option<[u8; 64]> {
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotEventRecord {
    pub event_index: u64,
    pub blinded_commitment: [u8; 32],
    pub signature: [u8; 64],
    pub event_type: PoiEventType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotEvent {
    pub event_index: u64,
    pub blinded_commitment: [u8; 32],
    pub signature: [u8; 64],
    pub event_type: PoiEventType,
}

impl From<SnapshotEventRecord> for SnapshotEvent {
    fn from(record: SnapshotEventRecord) -> Self {
        Self {
            event_index: record.event_index,
            blinded_commitment: record.blinded_commitment,
            signature: record.signature,
            event_type: record.event_type,
        }
    }
}

impl From<&SnapshotEventRecord> for SnapshotEvent {
    fn from(record: &SnapshotEventRecord) -> Self {
        Self {
            event_index: record.event_index,
            blinded_commitment: record.blinded_commitment,
            signature: record.signature,
            event_type: record.event_type,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotBlockedShield {
    pub commitment_hash: [u8; 32],
    pub blinded_commitment: [u8; 32],
    pub signature: [u8; 64],
    pub block_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub header: SnapshotHeader,
    pub events: Vec<SnapshotEvent>,
    pub blocked_shields: Vec<SnapshotBlockedShield>,
}

pub struct SnapshotWriter;

impl SnapshotWriter {
    pub fn write(
        header: &SnapshotHeaderInput,
        events: &[SnapshotEventRecord],
    ) -> Result<Vec<u8>, SnapshotError> {
        validate_event_range(header, events)?;
        let event_count = u64::try_from(events.len()).map_err(|_| SnapshotError::CountOverflow)?;
        let events_offset = format::HEADER_LEN_U64;
        let blocked_shields_offset = events_offset
            .checked_add(
                event_count
                    .checked_mul(format::EVENT_RECORD_BYTES_U64)
                    .ok_or(SnapshotError::CountOverflow)?,
            )
            .ok_or(SnapshotError::CountOverflow)?;

        let mut out = Vec::new();
        write_header(
            &mut out,
            header,
            event_count,
            0,
            events_offset,
            blocked_shields_offset,
        );
        debug_assert_eq!(out.len(), format::HEADER_LEN);

        for event in events {
            out.extend_from_slice(&event.blinded_commitment);
            out.extend_from_slice(&event.signature);
            out.push(event_type_discriminant(event.event_type));
        }

        Ok(out)
    }
}

pub struct SnapshotReader;

impl SnapshotReader {
    pub fn read(bytes: &[u8]) -> Result<Snapshot, SnapshotError> {
        let header = read_header(bytes)?;
        validate_header_counts(&header)?;
        validate_offsets(&header)?;
        if header.blocked_shield_count != 0 {
            return Err(SnapshotError::BlockedShieldsNotAllowed(
                header.blocked_shield_count,
            ));
        }

        let events = read_events(bytes, &header)?;
        let blocked_shields = read_blocked_shields(bytes, &header)?;

        Ok(Snapshot {
            header,
            events,
            blocked_shields,
        })
    }
}

#[derive(Debug, Error)]
pub enum SnapshotError {
    #[error("snapshot is shorter than required {needed} bytes: {actual}")]
    BufferTooShort { needed: usize, actual: usize },
    #[error("invalid snapshot magic bytes")]
    InvalidMagic,
    #[error("unsupported snapshot format version {0}")]
    UnsupportedVersion(u16),
    #[error("invalid snapshot header length {0}")]
    InvalidHeaderLength(u16),
    #[error("invalid snapshot kind {0}")]
    InvalidSnapshotKind(u8),
    #[error("invalid POI event type discriminant {0}")]
    InvalidEventType(u8),
    #[error("{field} has {actual} bytes, expected {expected}")]
    InvalidByteLen {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("event index {actual_index} does not match expected {expected_index}")]
    NonContiguousEvent {
        expected_index: u64,
        actual_index: u64,
    },
    #[error("event count does not match header range")]
    EventCountRangeMismatch,
    #[error("snapshot count or offset overflow")]
    CountOverflow,
    #[error("invalid {field} offset {actual}, expected {expected}")]
    InvalidOffset {
        field: &'static str,
        expected: u64,
        actual: u64,
    },
    #[error("block reason is too long for v1 framing")]
    BlockReasonTooLong,
    #[error("block reason is not valid utf-8")]
    BlockReasonUtf8(#[source] std::string::FromUtf8Error),
    #[error("invalid block reason presence flag {0}")]
    InvalidBlockReasonPresence(u8),
    #[error("blocked-shield records are not allowed in v2 snapshots: count={0}")]
    BlockedShieldsNotAllowed(u64),
}

fn write_header(
    out: &mut Vec<u8>,
    header: &SnapshotHeaderInput,
    event_count: u64,
    blocked_shield_count: u64,
    events_offset: u64,
    blocked_shields_offset: u64,
) {
    out.extend_from_slice(format::MAGIC);
    out.extend_from_slice(&format::FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(&format::HEADER_LEN_U16.to_le_bytes());
    out.push(header.chain_type);
    out.push(header.kind.discriminant());
    out.extend_from_slice(&[0; format::RESERVED_BYTES]);
    out.extend_from_slice(&header.list_key);
    out.extend_from_slice(&header.chain_id.to_le_bytes());
    out.extend_from_slice(&header.start_index.to_le_bytes());
    out.extend_from_slice(&header.end_index.to_le_bytes());
    out.extend_from_slice(&event_count.to_le_bytes());
    out.extend_from_slice(&blocked_shield_count.to_le_bytes());
    out.extend_from_slice(&header.tip_merkleroot);
    out.extend_from_slice(&header.upstream_endpoint_hash);
    out.extend_from_slice(&header.created_at_unix_seconds.to_le_bytes());
    out.extend_from_slice(&events_offset.to_le_bytes());
    out.extend_from_slice(&blocked_shields_offset.to_le_bytes());
}

fn read_header(bytes: &[u8]) -> Result<SnapshotHeader, SnapshotError> {
    ensure_len(bytes, format::HEADER_LEN)?;
    if read_bytes::<8>(bytes, format::MAGIC_OFFSET)? != *format::MAGIC {
        return Err(SnapshotError::InvalidMagic);
    }

    let format_version = read_u16(bytes, format::FORMAT_VERSION_OFFSET)?;
    if format_version != format::FORMAT_VERSION {
        return Err(SnapshotError::UnsupportedVersion(format_version));
    }

    let header_len = read_u16(bytes, format::HEADER_LEN_OFFSET)?;
    if header_len != format::HEADER_LEN_U16 {
        return Err(SnapshotError::InvalidHeaderLength(header_len));
    }

    let kind_discriminant = bytes[format::SNAPSHOT_KIND_OFFSET];
    let kind = SnapshotKind::from_discriminant(kind_discriminant)
        .ok_or(SnapshotError::InvalidSnapshotKind(kind_discriminant))?;

    Ok(SnapshotHeader {
        format_version,
        header_len,
        chain_type: bytes[format::CHAIN_TYPE_OFFSET],
        kind,
        list_key: read_bytes::<32>(bytes, format::LIST_KEY_OFFSET)?,
        chain_id: read_u64(bytes, format::CHAIN_ID_OFFSET)?,
        start_index: read_u64(bytes, format::START_INDEX_OFFSET)?,
        end_index: read_u64(bytes, format::END_INDEX_OFFSET)?,
        event_count: read_u64(bytes, format::EVENT_COUNT_OFFSET)?,
        blocked_shield_count: read_u64(bytes, format::BLOCKED_SHIELD_COUNT_OFFSET)?,
        tip_merkleroot: read_bytes::<32>(bytes, format::TIP_MERKLEROOT_OFFSET)?,
        upstream_endpoint_hash: read_bytes::<32>(bytes, format::UPSTREAM_ENDPOINT_HASH_OFFSET)?,
        created_at_unix_seconds: read_i64(bytes, format::CREATED_AT_OFFSET)?,
        events_offset: read_u64(bytes, format::EVENTS_OFFSET_OFFSET)?,
        blocked_shields_offset: read_u64(bytes, format::BLOCKED_SHIELDS_OFFSET_OFFSET)?,
    })
}

fn validate_event_range(
    header: &SnapshotHeaderInput,
    events: &[SnapshotEventRecord],
) -> Result<(), SnapshotError> {
    if events.is_empty() {
        return Ok(());
    }

    for (offset, event) in events.iter().enumerate() {
        let expected_index = header
            .start_index
            .checked_add(offset as u64)
            .ok_or(SnapshotError::CountOverflow)?;
        if event.event_index != expected_index {
            return Err(SnapshotError::NonContiguousEvent {
                expected_index,
                actual_index: event.event_index,
            });
        }
    }

    let expected_end = header
        .start_index
        .checked_add(u64::try_from(events.len()).map_err(|_| SnapshotError::CountOverflow)? - 1)
        .ok_or(SnapshotError::CountOverflow)?;
    if expected_end != header.end_index {
        return Err(SnapshotError::EventCountRangeMismatch);
    }

    Ok(())
}

fn validate_header_counts(header: &SnapshotHeader) -> Result<(), SnapshotError> {
    if header.event_count == 0 {
        return Ok(());
    }
    let expected_end = header
        .start_index
        .checked_add(header.event_count - 1)
        .ok_or(SnapshotError::CountOverflow)?;
    if expected_end != header.end_index {
        return Err(SnapshotError::EventCountRangeMismatch);
    }
    Ok(())
}

fn validate_offsets(header: &SnapshotHeader) -> Result<(), SnapshotError> {
    if header.events_offset != format::HEADER_LEN_U64 {
        return Err(SnapshotError::InvalidOffset {
            field: "events",
            expected: format::HEADER_LEN_U64,
            actual: header.events_offset,
        });
    }

    let expected_blocked_offset = header
        .events_offset
        .checked_add(
            header
                .event_count
                .checked_mul(format::EVENT_RECORD_BYTES_U64)
                .ok_or(SnapshotError::CountOverflow)?,
        )
        .ok_or(SnapshotError::CountOverflow)?;
    if header.blocked_shields_offset != expected_blocked_offset {
        return Err(SnapshotError::InvalidOffset {
            field: "blocked shields",
            expected: expected_blocked_offset,
            actual: header.blocked_shields_offset,
        });
    }
    Ok(())
}

fn read_events(bytes: &[u8], header: &SnapshotHeader) -> Result<Vec<SnapshotEvent>, SnapshotError> {
    let event_count =
        usize::try_from(header.event_count).map_err(|_| SnapshotError::CountOverflow)?;
    let start = usize::try_from(header.events_offset).map_err(|_| SnapshotError::CountOverflow)?;
    let event_bytes = event_count
        .checked_mul(format::EVENT_RECORD_BYTES)
        .ok_or(SnapshotError::CountOverflow)?;
    ensure_len_from(bytes, start, event_bytes)?;

    let mut events = Vec::with_capacity(event_count);
    for offset in 0..event_count {
        let record_offset = start + offset * format::EVENT_RECORD_BYTES;
        let event_type_discriminant = bytes[record_offset + format::EVENT_TYPE_OFFSET];
        let event_type = event_type_from_discriminant(event_type_discriminant)
            .ok_or(SnapshotError::InvalidEventType(event_type_discriminant))?;
        events.push(SnapshotEvent {
            event_index: header
                .start_index
                .checked_add(offset as u64)
                .ok_or(SnapshotError::CountOverflow)?,
            blinded_commitment: read_bytes::<32>(
                bytes,
                record_offset + format::EVENT_BLINDED_COMMITMENT_OFFSET,
            )?,
            signature: read_bytes::<64>(bytes, record_offset + format::EVENT_SIGNATURE_OFFSET)?,
            event_type,
        });
    }
    Ok(events)
}

fn read_blocked_shields(
    bytes: &[u8],
    header: &SnapshotHeader,
) -> Result<Vec<SnapshotBlockedShield>, SnapshotError> {
    let blocked_shield_count =
        usize::try_from(header.blocked_shield_count).map_err(|_| SnapshotError::CountOverflow)?;
    let mut offset =
        usize::try_from(header.blocked_shields_offset).map_err(|_| SnapshotError::CountOverflow)?;
    let mut records = Vec::with_capacity(blocked_shield_count);

    for _ in 0..blocked_shield_count {
        ensure_len_from(bytes, offset, format::BLOCKED_SHIELD_FIXED_RECORD_BYTES)?;
        let commitment_hash =
            read_bytes::<32>(bytes, offset + format::BLOCKED_COMMITMENT_HASH_OFFSET)?;
        let blinded_commitment =
            read_bytes::<32>(bytes, offset + format::BLOCKED_BLINDED_COMMITMENT_OFFSET)?;
        let signature = read_bytes::<64>(bytes, offset + format::BLOCKED_SIGNATURE_OFFSET)?;
        let reason_present = bytes[offset + format::BLOCKED_REASON_PRESENT_OFFSET];
        offset += format::BLOCKED_SHIELD_FIXED_RECORD_BYTES;
        let reason = match reason_present {
            format::BLOCKED_REASON_ABSENT => None,
            format::BLOCKED_REASON_PRESENT => {
                ensure_len_from(bytes, offset, format::BLOCKED_REASON_LEN_BYTES)?;
                let reason_len = usize::try_from(read_u32(bytes, offset)?)
                    .map_err(|_| SnapshotError::CountOverflow)?;
                offset += format::BLOCKED_REASON_LEN_BYTES;
                ensure_len_from(bytes, offset, reason_len)?;
                let reason = String::from_utf8(bytes[offset..offset + reason_len].to_vec())
                    .map_err(SnapshotError::BlockReasonUtf8)?;
                offset += reason_len;
                Some(reason)
            }
            other => return Err(SnapshotError::InvalidBlockReasonPresence(other)),
        };
        records.push(SnapshotBlockedShield {
            commitment_hash,
            blinded_commitment,
            signature,
            block_reason: reason,
        });
    }

    if offset != bytes.len() {
        return Err(SnapshotError::InvalidOffset {
            field: "file length",
            expected: offset as u64,
            actual: bytes.len() as u64,
        });
    }

    Ok(records)
}

const fn ensure_len(bytes: &[u8], needed: usize) -> Result<(), SnapshotError> {
    if bytes.len() < needed {
        return Err(SnapshotError::BufferTooShort {
            needed,
            actual: bytes.len(),
        });
    }
    Ok(())
}

fn ensure_len_from(bytes: &[u8], start: usize, len: usize) -> Result<(), SnapshotError> {
    let needed = start.checked_add(len).ok_or(SnapshotError::CountOverflow)?;
    ensure_len(bytes, needed)
}

fn read_bytes<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], SnapshotError> {
    ensure_len_from(bytes, offset, N)?;
    bytes[offset..offset + N]
        .try_into()
        .map_err(|_| SnapshotError::BufferTooShort {
            needed: offset + N,
            actual: bytes.len(),
        })
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, SnapshotError> {
    Ok(u16::from_le_bytes(read_bytes(bytes, offset)?))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, SnapshotError> {
    Ok(u32::from_le_bytes(read_bytes(bytes, offset)?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, SnapshotError> {
    Ok(u64::from_le_bytes(read_bytes(bytes, offset)?))
}

fn read_i64(bytes: &[u8], offset: usize) -> Result<i64, SnapshotError> {
    Ok(i64::from_le_bytes(read_bytes(bytes, offset)?))
}

const fn event_type_discriminant(event_type: PoiEventType) -> u8 {
    match event_type {
        PoiEventType::Shield => 0,
        PoiEventType::Transact => 1,
        PoiEventType::Unshield => 2,
        PoiEventType::LegacyTransact => 3,
    }
}

const fn event_type_from_discriminant(value: u8) -> Option<PoiEventType> {
    match value {
        0 => Some(PoiEventType::Shield),
        1 => Some(PoiEventType::Transact),
        2 => Some(PoiEventType::Unshield),
        3 => Some(PoiEventType::LegacyTransact),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_roundtrip_preserves_events_and_excludes_blocked_shields() {
        let header = header_input(0, 1, SnapshotKind::Base);
        let events = vec![
            event_record(0, 1, PoiEventType::Shield),
            event_record(1, 2, PoiEventType::Transact),
        ];

        let bytes = SnapshotWriter::write(&header, &events).expect("encode");
        let snapshot = SnapshotReader::read(&bytes).expect("decode");

        assert_eq!(snapshot.header.format_version, format::FORMAT_VERSION);
        assert_eq!(snapshot.header.kind, SnapshotKind::Base);
        assert_eq!(snapshot.events.len(), events.len());
        assert_eq!(snapshot.events[0].event_index, events[0].event_index);
        assert_eq!(snapshot.events[0].blinded_commitment, [1_u8; 32]);
        assert_eq!(snapshot.events[0].signature, [11_u8; 64]);
        assert_eq!(snapshot.events[0].event_type, PoiEventType::Shield);
        assert_eq!(snapshot.events[1].event_index, events[1].event_index);
        assert_eq!(snapshot.events[1].event_type, PoiEventType::Transact);
        assert!(snapshot.blocked_shields.is_empty());
    }

    #[test]
    fn snapshot_reader_rejects_corrupt_magic() {
        let events = vec![event_record(0, 1, PoiEventType::Shield)];
        let mut bytes = SnapshotWriter::write(&header_input(0, 0, SnapshotKind::Delta), &events)
            .expect("encode");
        bytes[0] = 0;

        assert!(matches!(
            SnapshotReader::read(&bytes),
            Err(SnapshotError::InvalidMagic)
        ));
    }

    #[test]
    fn snapshot_reader_rejects_corrupt_count() {
        let events = vec![event_record(0, 1, PoiEventType::Shield)];
        let mut bytes = SnapshotWriter::write(&header_input(0, 0, SnapshotKind::Delta), &events)
            .expect("encode");
        bytes[format::EVENT_COUNT_OFFSET..format::EVENT_COUNT_OFFSET + 8]
            .copy_from_slice(&2_u64.to_le_bytes());

        assert!(matches!(
            SnapshotReader::read(&bytes),
            Err(SnapshotError::EventCountRangeMismatch)
        ));
    }

    #[test]
    fn snapshot_reader_rejects_blocked_shield_records() {
        let events = vec![event_record(0, 1, PoiEventType::Shield)];
        let mut bytes = SnapshotWriter::write(&header_input(0, 0, SnapshotKind::Base), &events)
            .expect("encode");
        bytes[format::BLOCKED_SHIELD_COUNT_OFFSET..format::BLOCKED_SHIELD_COUNT_OFFSET + 8]
            .copy_from_slice(&1_u64.to_le_bytes());

        assert!(matches!(
            SnapshotReader::read(&bytes),
            Err(SnapshotError::BlockedShieldsNotAllowed(1))
        ));
    }

    #[test]
    fn v2_snapshot_header_has_no_bundle_signature() {
        let events = vec![event_record(0, 1, PoiEventType::Shield)];
        let bytes = SnapshotWriter::write(&header_input(0, 0, SnapshotKind::Base), &events)
            .expect("encode");
        let snapshot = SnapshotReader::read(&bytes).expect("decode");

        assert_eq!(snapshot.header.publisher_signature(), None);
        assert_eq!(snapshot.header.header_len, format::HEADER_LEN_U16);
    }

    fn header_input(start_index: u64, end_index: u64, kind: SnapshotKind) -> SnapshotHeaderInput {
        SnapshotHeaderInput {
            list_key: [9; 32],
            chain_id: 1,
            chain_type: 0,
            kind,
            start_index,
            end_index,
            tip_merkleroot: [8; 32],
            upstream_endpoint_hash: [7; 32],
            created_at_unix_seconds: 1_700_000_000,
        }
    }

    fn event_record(event_index: u64, byte: u8, event_type: PoiEventType) -> SnapshotEventRecord {
        SnapshotEventRecord {
            event_index,
            blinded_commitment: [byte; 32],
            signature: [byte + 10; 64],
            event_type,
        }
    }
}
