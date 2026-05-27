use super::*;

pub(super) fn load_or_new_manifest(
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
) -> Result<TxidPublicCacheManifest, TxidPublicCacheError> {
    if let Some(manifest) = load_manifest(db, key)? {
        match validate_manifest(&manifest, key) {
            Ok(()) => return Ok(manifest),
            Err(err) => {
                warn!(
                    ?err,
                    chain_id = key.chain_id,
                    txid_version = key.txid_version,
                    "resetting incompatible TXID public cache manifest"
                );
            }
        }
    }
    Ok(TxidPublicCacheManifest {
        format_version: TXID_CACHE_FORMAT_VERSION,
        chain_type: key.chain_type,
        chain_id: key.chain_id,
        txid_version: key.txid_version.to_string(),
        page_size: TXID_CACHE_PAGE_SIZE.get(),
        next_txid_index: 0,
        latest_validated_txid_index: None,
        latest_validated_merkleroot: None,
        validated_cached_txid_index: None,
        pages: Vec::new(),
    })
}

pub(super) fn load_manifest(
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
) -> Result<Option<TxidPublicCacheManifest>, TxidPublicCacheError> {
    let Some(meta) = db.get_blob_meta(TXID_CACHE_BLOB_KIND, &cache_id(key))? else {
        return Ok(None);
    };
    let path = db.resolve_path(&meta.relative_path);
    match fs::read(path) {
        Ok(bytes) => Ok(Some(rmp_serde::from_slice(&bytes)?)),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err.into()),
    }
}

pub(super) fn validate_manifest(
    manifest: &TxidPublicCacheManifest,
    key: TxidPublicCacheKey<'_>,
) -> Result<(), TxidPublicCacheError> {
    if manifest.format_version != TXID_CACHE_FORMAT_VERSION {
        return Err(TxidPublicCacheError::MetadataMismatch(format!(
            "unsupported format version {}",
            manifest.format_version
        )));
    }
    if manifest.chain_type != key.chain_type
        || manifest.chain_id != key.chain_id
        || manifest.txid_version != key.txid_version
    {
        return Err(TxidPublicCacheError::MetadataMismatch(
            "cache identity mismatch".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn write_manifest(
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
    manifest: &TxidPublicCacheManifest,
) -> Result<(), TxidPublicCacheError> {
    let name = manifest_file_name(key);
    let path = db.blob_path(TXID_CACHE_BLOB_KIND, &name);
    let bytes = rmp_serde::to_vec_named(manifest)?;
    write_blob_file(db, &path, &bytes)?;
    let now = now_epoch_secs()?;
    let existing = db.get_blob_meta(TXID_CACHE_BLOB_KIND, &cache_id(key))?;
    db.put_blob_meta(
        TXID_CACHE_BLOB_KIND,
        &cache_id(key),
        &BlobMeta {
            format_version: TXID_CACHE_FORMAT_VERSION,
            relative_path: DbStore::relative_blob_path(TXID_CACHE_BLOB_KIND, &name),
            content_hash: Sha256::digest(&bytes).into(),
            created_at: existing.map_or(now, |meta| meta.created_at),
            updated_at: now,
            last_block: None,
        },
    )?;
    Ok(())
}

pub(super) fn write_page(
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
    page: &TxidPublicCachePage,
) -> Result<TxidPublicCachePageRef, TxidPublicCacheError> {
    let name = page_file_name(key, page.start_index);
    let path = db.blob_path(TXID_CACHE_BLOB_KIND, &name);
    let bytes = rmp_serde::to_vec_named(page)?;
    write_blob_file(db, &path, &bytes)?;
    Ok(TxidPublicCachePageRef {
        start_index: page.start_index,
        row_count: page.rows.len() as u64,
        relative_path: DbStore::relative_blob_path(TXID_CACHE_BLOB_KIND, &name),
    })
}

pub(super) fn append_page(
    manifest: &mut TxidPublicCacheManifest,
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
    page: &TxidPublicCachePage,
) -> Result<(), TxidPublicCacheError> {
    let page_ref = write_page(db, key, page)?;
    manifest.next_txid_index = manifest
        .next_txid_index
        .max(page.start_index.saturating_add(page.rows.len() as u64));
    manifest.pages.push(page_ref);
    manifest.pages.sort_by_key(|page_ref| page_ref.start_index);
    Ok(())
}

pub(super) fn insert_or_replace_page(
    manifest: &mut TxidPublicCacheManifest,
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
    page: &TxidPublicCachePage,
) -> Result<(), TxidPublicCacheError> {
    let page_end = page.start_index.saturating_add(page.rows.len() as u64);
    let mut pages = Vec::with_capacity(manifest.pages.len() + 1);
    for page_ref in std::mem::take(&mut manifest.pages) {
        let existing_end = page_ref.start_index.saturating_add(page_ref.row_count);
        if existing_end <= page.start_index || page_ref.start_index >= page_end {
            pages.push(page_ref);
            continue;
        }

        let existing = read_page(db, &page_ref)?;
        let before_rows: Vec<_> = existing
            .rows
            .iter()
            .take_while(|row| row.txid_index < page.start_index)
            .cloned()
            .collect();
        if let Some(page_ref) = write_preserved_page_segment(db, key, before_rows)? {
            pages.push(page_ref);
        }

        let after_rows: Vec<_> = existing
            .rows
            .into_iter()
            .filter(|row| row.txid_index >= page_end)
            .collect();
        if let Some(page_ref) = write_preserved_page_segment(db, key, after_rows)? {
            pages.push(page_ref);
        }
    }

    pages.push(write_page(db, key, page)?);
    pages.sort_by_key(|page_ref| page_ref.start_index);
    manifest.next_txid_index = manifest.next_txid_index.max(page_end);
    manifest.pages = pages;
    Ok(())
}

pub(super) fn write_preserved_page_segment(
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
    rows: Vec<TxidPublicCacheRow>,
) -> Result<Option<TxidPublicCachePageRef>, TxidPublicCacheError> {
    let Some(first) = rows.first() else {
        return Ok(None);
    };
    let page = TxidPublicCachePage {
        format_version: TXID_CACHE_FORMAT_VERSION,
        start_index: first.txid_index,
        rows,
    };
    write_page(db, key, &page).map(Some)
}
