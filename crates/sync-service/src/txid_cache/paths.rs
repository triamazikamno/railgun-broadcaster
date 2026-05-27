use super::*;

pub(super) fn cache_id(key: TxidPublicCacheKey<'_>) -> String {
    format!("{}|{}|{}", key.chain_type, key.chain_id, key.txid_version)
}

pub(super) fn manifest_file_name(key: TxidPublicCacheKey<'_>) -> String {
    format!(
        "{}-{}-{}-manifest.msgpack",
        key.chain_type,
        key.chain_id,
        safe_file_component(key.txid_version)
    )
}

pub(super) fn page_file_name(key: TxidPublicCacheKey<'_>, start_index: u64) -> String {
    format!(
        "{}-{}-{}-{start_index:016}.msgpack",
        key.chain_type,
        key.chain_id,
        safe_file_component(key.txid_version)
    )
}

pub(super) fn index_shard_file_name(key: TxidPublicCacheKey<'_>, shard: u8) -> String {
    format!(
        "{}-{}-{}-tx-index-{shard:02x}.msgpack",
        key.chain_type,
        key.chain_id,
        safe_file_component(key.txid_version)
    )
}

pub(super) fn safe_file_component(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

pub(super) fn now_epoch_secs() -> Result<u64, std::io::Error> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(std::io::Error::other)?;
    Ok(now.as_secs())
}
