use super::*;

pub(super) fn write_blob_file(
    db: &DbStore,
    path: &Path,
    bytes: &[u8],
) -> Result<(), TxidPublicCacheError> {
    db.ensure_blob_dir(TXID_CACHE_BLOB_KIND)?;
    let nonce = TXID_CACHE_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temp_path = path.with_extension(format!("tmp.{}.{nonce}", std::process::id()));
    fs::write(&temp_path, bytes)?;
    fs::rename(temp_path, path)?;
    Ok(())
}

pub(super) fn read_page(
    db: &DbStore,
    page_ref: &TxidPublicCachePageRef,
) -> Result<TxidPublicCachePage, TxidPublicCacheError> {
    let bytes = fs::read(db.resolve_path(&page_ref.relative_path))?;
    let page: TxidPublicCachePage = rmp_serde::from_slice(&bytes)?;
    if page.format_version != TXID_CACHE_FORMAT_VERSION || page.start_index != page_ref.start_index
    {
        return Err(TxidPublicCacheError::MetadataMismatch(
            "page metadata mismatch".to_string(),
        ));
    }
    Ok(page)
}

pub(super) fn update_index_for_page(
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
    page: &TxidPublicCachePage,
) -> Result<(), TxidPublicCacheError> {
    let mut entries_by_shard: BTreeMap<u8, Vec<TxidPublicCacheIndexEntry>> = BTreeMap::new();
    for (row_offset, row) in page.rows.iter().enumerate() {
        entries_by_shard
            .entry(index_shard(row.transaction.transaction_hash))
            .or_default()
            .push(TxidPublicCacheIndexEntry {
                transaction_hash: row.transaction.transaction_hash,
                txid_index: row.txid_index,
                page_start_index: page.start_index,
                row_offset: row_offset as u64,
            });
    }
    let page_end = page.start_index.saturating_add(page.rows.len() as u64);
    for (shard, mut new_entries) in entries_by_shard {
        let mut index = load_index_shard(db, key, shard)?;
        index
            .entries
            .retain(|entry| entry.txid_index < page.start_index || entry.txid_index >= page_end);
        index.entries.append(&mut new_entries);
        index.entries.sort_by_key(|entry| entry.txid_index);
        write_index_shard(db, key, &index)?;
    }
    Ok(())
}

pub(super) fn rebuild_index_for_manifest(
    manifest: &TxidPublicCacheManifest,
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
) -> Result<(), TxidPublicCacheError> {
    clear_index_shards(db, key)?;
    for page_ref in &manifest.pages {
        let page = read_page(db, page_ref)?;
        update_index_for_page(db, key, &page)?;
    }
    Ok(())
}

pub(super) fn clear_index_shards(
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
) -> Result<(), TxidPublicCacheError> {
    for shard in u8::MIN..=u8::MAX {
        let path = db.blob_path(TXID_CACHE_BLOB_KIND, &index_shard_file_name(key, shard));
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
    }
    Ok(())
}

pub(super) fn index_entries_for_hash(
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
    tx_hash: FixedBytes<32>,
) -> Result<Vec<TxidPublicCacheIndexEntry>, TxidPublicCacheError> {
    let index = load_index_shard(db, key, index_shard(tx_hash))?;
    Ok(index
        .entries
        .into_iter()
        .filter(|entry| entry.transaction_hash == tx_hash)
        .collect())
}

pub(super) fn load_index_shard(
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
    shard: u8,
) -> Result<TxidPublicCacheIndexShard, TxidPublicCacheError> {
    let path = db.blob_path(TXID_CACHE_BLOB_KIND, &index_shard_file_name(key, shard));
    match fs::read(path) {
        Ok(bytes) => {
            let index: TxidPublicCacheIndexShard = rmp_serde::from_slice(&bytes)?;
            if index.format_version == TXID_CACHE_FORMAT_VERSION && index.shard == shard {
                Ok(index)
            } else {
                Ok(empty_index_shard(shard))
            }
        }
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(empty_index_shard(shard)),
        Err(err) => Err(err.into()),
    }
}

pub(super) fn write_index_shard(
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
    index: &TxidPublicCacheIndexShard,
) -> Result<(), TxidPublicCacheError> {
    let path = db.blob_path(
        TXID_CACHE_BLOB_KIND,
        &index_shard_file_name(key, index.shard),
    );
    let bytes = rmp_serde::to_vec_named(index)?;
    write_blob_file(db, &path, &bytes)
}

pub(super) const fn empty_index_shard(shard: u8) -> TxidPublicCacheIndexShard {
    TxidPublicCacheIndexShard {
        format_version: TXID_CACHE_FORMAT_VERSION,
        shard,
        entries: Vec::new(),
    }
}

pub(super) const fn index_shard(tx_hash: FixedBytes<32>) -> u8 {
    tx_hash.0[0]
}
