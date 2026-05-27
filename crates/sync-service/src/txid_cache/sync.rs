use super::*;

pub(super) fn txid_public_cache_page_from_rows(
    start_index: u64,
    rows: Vec<IndexedRailgunTransaction>,
) -> TxidPublicCachePage {
    TxidPublicCachePage {
        format_version: TXID_CACHE_FORMAT_VERSION,
        start_index,
        rows: rows
            .into_iter()
            .enumerate()
            .map(|(offset, transaction)| {
                let txid_index = start_index + offset as u64;
                let txid_leaf_hash =
                    FixedBytes::from(transaction.txid_leaf_hash().to_be_bytes::<32>());
                TxidPublicCacheRow {
                    txid_index,
                    txid_leaf_hash,
                    transaction: transaction.into(),
                }
            })
            .collect(),
    }
}

pub(crate) async fn sync_txid_public_cache(
    db: &DbStore,
    endpoint: &Url,
    http_client: Option<&reqwest::Client>,
    key: TxidPublicCacheKey<'_>,
    latest_validated_txid_index: u64,
    latest_validated_merkleroot: Option<FixedBytes<32>>,
) -> Result<(), TxidPublicCacheError> {
    let _guard = TXID_CACHE_SYNC_LOCK.lock().await;
    let started = std::time::Instant::now();
    let mut manifest = load_or_new_manifest(db, key)?;
    let previous_validated_txid_index = manifest.latest_validated_txid_index;
    let previous_validated_merkleroot = manifest.latest_validated_merkleroot;
    if previous_validated_txid_index.is_some_and(|index| index > latest_validated_txid_index)
        || (previous_validated_txid_index == Some(latest_validated_txid_index)
            && previous_validated_merkleroot != latest_validated_merkleroot)
    {
        manifest.validated_cached_txid_index = None;
    }
    manifest.latest_validated_txid_index = Some(latest_validated_txid_index);
    manifest.latest_validated_merkleroot = latest_validated_merkleroot;

    let client = match http_client.cloned() {
        Some(http_client) => QuickSyncClient::with_http_client(endpoint.clone(), http_client),
        None => QuickSyncClient::new(endpoint.clone()),
    };

    let mut fetched_rows = 0_u64;
    let refresh_start = manifest
        .validated_cached_txid_index
        .map_or(0, |index| index.saturating_add(1));
    let refresh_needed = refresh_start <= latest_validated_txid_index;
    if refresh_needed {
        let refresh = refresh_txid_public_cache_range(
            &mut manifest,
            db,
            &client,
            key,
            refresh_start,
            latest_validated_txid_index,
        )
        .await?;
        fetched_rows = fetched_rows.saturating_add(refresh.fetched_rows);
        if let Some(refreshed_to) = refresh.refreshed_to {
            manifest.validated_cached_txid_index = Some(refreshed_to);
        }
    }
    while !refresh_needed && manifest.next_txid_index <= latest_validated_txid_index {
        let start_index = manifest.next_txid_index;
        let rows = client
            .fetch_public_txid_page(start_index, TXID_CACHE_PAGE_SIZE)
            .await?;
        if rows.is_empty() {
            break;
        }
        let row_count = rows.len() as u64;
        let page = txid_public_cache_page_from_rows(start_index, rows);
        insert_or_replace_page(&mut manifest, db, key, &page)?;
        rebuild_index_for_manifest(&manifest, db, key)?;
        manifest.validated_cached_txid_index = Some(start_index.saturating_add(row_count - 1));
        fetched_rows = fetched_rows.saturating_add(row_count);
        debug!(
            chain_id = key.chain_id,
            start_index,
            row_count,
            next_txid_index = manifest.next_txid_index,
            "TXID public cache page synced"
        );
        if row_count < TXID_CACHE_PAGE_SIZE.get() as u64 {
            break;
        }
    }

    write_manifest(db, key, &manifest)?;
    info!(
        chain_id = key.chain_id,
        txid_version = key.txid_version,
        latest_validated_txid_index,
        next_txid_index = manifest.next_txid_index,
        fetched_rows,
        elapsed_ms = started.elapsed().as_millis(),
        "TXID public cache sync complete"
    );
    Ok(())
}

pub(crate) async fn sync_txid_public_cache_to_graph_tip(
    db: &DbStore,
    endpoint: &Url,
    http_client: Option<&reqwest::Client>,
    key: TxidPublicCacheKey<'_>,
) -> Result<u64, TxidPublicCacheError> {
    let _guard = TXID_CACHE_SYNC_LOCK.lock().await;
    let started = std::time::Instant::now();
    let mut manifest = load_or_new_manifest(db, key)?;
    let client = match http_client.cloned() {
        Some(http_client) => QuickSyncClient::with_http_client(endpoint.clone(), http_client),
        None => QuickSyncClient::new(endpoint.clone()),
    };

    let mut fetched_rows = 0_u64;
    loop {
        let start_index = manifest.next_txid_index;
        let rows = client
            .fetch_public_txid_page(start_index, TXID_CACHE_PAGE_SIZE)
            .await?;
        if rows.is_empty() {
            break;
        }
        let row_count = rows.len() as u64;
        let page = txid_public_cache_page_from_rows(start_index, rows);
        append_page(&mut manifest, db, key, &page)?;
        update_index_for_page(db, key, &page)?;
        fetched_rows = fetched_rows.saturating_add(row_count);
        debug!(
            chain_id = key.chain_id,
            start_index,
            row_count,
            next_txid_index = manifest.next_txid_index,
            "TXID public cache background page synced"
        );
        if row_count < TXID_CACHE_PAGE_SIZE.get() as u64 {
            break;
        }
    }

    write_manifest(db, key, &manifest)?;
    info!(
        chain_id = key.chain_id,
        txid_version = key.txid_version,
        next_txid_index = manifest.next_txid_index,
        fetched_rows,
        elapsed_ms = started.elapsed().as_millis(),
        "TXID public cache background sync complete"
    );
    Ok(fetched_rows)
}

pub(crate) async fn sync_txid_public_cache_until_recovered_output(
    db: &DbStore,
    endpoint: &Url,
    http_client: Option<&reqwest::Client>,
    key: TxidPublicCacheKey<'_>,
    tx_hash: FixedBytes<32>,
    output_commitment: FixedBytes<32>,
) -> Result<TxidPublicCachedTransaction, TxidPublicCacheError> {
    sync_txid_public_cache_until_recovered_output_with_page_size(
        db,
        endpoint,
        http_client,
        key,
        tx_hash,
        output_commitment,
        TXID_CACHE_PAGE_SIZE,
    )
    .await
}

pub(super) async fn sync_txid_public_cache_until_recovered_output_with_page_size(
    db: &DbStore,
    endpoint: &Url,
    http_client: Option<&reqwest::Client>,
    key: TxidPublicCacheKey<'_>,
    tx_hash: FixedBytes<32>,
    output_commitment: FixedBytes<32>,
    page_size: NonZeroUsize,
) -> Result<TxidPublicCachedTransaction, TxidPublicCacheError> {
    let _guard = TXID_CACHE_SYNC_LOCK.lock().await;
    let started = std::time::Instant::now();
    let mut manifest = load_or_new_manifest(db, key)?;
    match find_public_recovery_transaction_in_manifest(
        &manifest,
        db,
        key,
        tx_hash,
        output_commitment,
    ) {
        Ok(row) => return Ok(row.into()),
        Err(TxidPublicCacheError::MissingTarget) => {}
        Err(err) => return Err(err),
    }
    let client = match http_client.cloned() {
        Some(http_client) => QuickSyncClient::with_http_client(endpoint.clone(), http_client),
        None => QuickSyncClient::new(endpoint.clone()),
    };

    let mut next_index = manifest
        .validated_cached_txid_index
        .map_or(0, |index| index.saturating_add(1))
        .min(manifest.next_txid_index);
    let mut fetched_rows = 0_u64;
    loop {
        let start_index = next_index;
        let rows = client
            .fetch_public_txid_page(start_index, page_size)
            .await?;
        if rows.is_empty() {
            write_manifest(db, key, &manifest)?;
            return Err(TxidPublicCacheError::MissingTarget);
        }
        let row_count = rows.len() as u64;
        let page = txid_public_cache_page_from_rows(start_index, rows);
        if start_index < manifest.next_txid_index {
            insert_or_replace_page(&mut manifest, db, key, &page)?;
            rebuild_index_for_manifest(&manifest, db, key)?;
        } else {
            append_page(&mut manifest, db, key, &page)?;
            update_index_for_page(db, key, &page)?;
        }
        next_index = start_index.saturating_add(row_count);
        fetched_rows = fetched_rows.saturating_add(row_count);
        write_manifest(db, key, &manifest)?;
        debug!(
            chain_id = key.chain_id,
            start_index,
            row_count,
            next_txid_index = manifest.next_txid_index,
            "TXID public cache recovery page synced"
        );

        if let Some(row) = find_target_row_in_page(&manifest, &page, tx_hash, output_commitment)? {
            info!(
                chain_id = key.chain_id,
                txid_version = key.txid_version,
                target_txid_index = row.txid_index,
                fetched_rows,
                elapsed_ms = started.elapsed().as_millis(),
                "TXID public cache recovery target synced"
            );
            return Ok(row.into());
        }
        if row_count < page_size.get() as u64 {
            return Err(TxidPublicCacheError::MissingTarget);
        }
    }
}

pub(crate) fn txid_public_cached_latest_validated(
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
) -> Result<Option<TxidPublicLatestValidated>, TxidPublicCacheError> {
    let Some(manifest) = load_manifest(db, key)? else {
        return Ok(None);
    };
    validate_manifest(&manifest, key)?;
    Ok(manifest
        .latest_validated_txid_index
        .map(|txid_index| TxidPublicLatestValidated {
            txid_index,
            merkleroot: manifest.latest_validated_merkleroot,
        }))
}

#[cfg(test)]
pub(crate) async fn put_txid_public_latest_validated(
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
    latest: TxidPublicLatestValidated,
) -> Result<(), TxidPublicCacheError> {
    let _guard = TXID_CACHE_SYNC_LOCK.lock().await;
    let mut manifest = load_or_new_manifest(db, key)?;
    manifest.latest_validated_txid_index = Some(latest.txid_index);
    manifest.latest_validated_merkleroot = latest.merkleroot;
    write_manifest(db, key, &manifest)
}

async fn refresh_txid_public_cache_range(
    manifest: &mut TxidPublicCacheManifest,
    db: &DbStore,
    client: &QuickSyncClient,
    key: TxidPublicCacheKey<'_>,
    start_index: u64,
    end_index: u64,
) -> Result<TxidPublicCacheRefresh, TxidPublicCacheError> {
    let mut fetched_rows = 0_u64;
    let mut refreshed_to = None;
    let mut next_index = start_index;
    while next_index <= end_index {
        let remaining = end_index.saturating_sub(next_index).saturating_add(1);
        let limit = NonZeroUsize::new(remaining.min(TXID_CACHE_PAGE_SIZE.get() as u64) as usize)
            .expect("validated TXID refresh limit is non-zero");
        let rows = client.fetch_public_txid_page(next_index, limit).await?;
        if rows.is_empty() {
            break;
        }
        let row_count = rows.len() as u64;
        let page = txid_public_cache_page_from_rows(next_index, rows);
        insert_or_replace_page(manifest, db, key, &page)?;
        fetched_rows = fetched_rows.saturating_add(row_count);
        refreshed_to = Some(next_index.saturating_add(row_count - 1));
        debug!(
            chain_id = key.chain_id,
            start_index = next_index,
            row_count,
            next_txid_index = manifest.next_txid_index,
            "TXID public cache validated page refreshed"
        );
        next_index = next_index.saturating_add(row_count);
        if row_count < limit.get() as u64 {
            break;
        }
    }
    if fetched_rows > 0 {
        rebuild_index_for_manifest(manifest, db, key)?;
    }
    Ok(TxidPublicCacheRefresh {
        fetched_rows,
        refreshed_to,
    })
}
