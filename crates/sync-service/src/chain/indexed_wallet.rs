use super::*;

pub(super) struct IndexedWalletPage {
    pub(super) transact_commitments: Vec<IndexedTransactCommitmentInput>,
    pub(super) shield_commitments: Vec<IndexedShieldCommitmentInput>,
    pub(super) legacy_encrypted_commitments: Vec<IndexedLegacyEncryptedCommitmentInput>,
    pub(super) legacy_generated_commitments: Vec<IndexedLegacyGeneratedCommitmentInput>,
    pub(super) nullifiers: Vec<IndexedNullifierInput>,
    pub(super) checkpoint_block: u64,
    pub(super) transact_rows: usize,
    pub(super) shield_rows: usize,
    pub(super) legacy_encrypted_rows: usize,
    pub(super) legacy_generated_rows: usize,
    pub(super) nullifier_rows: usize,
}

pub(super) async fn fetch_indexed_wallet_page(
    client: &QuickSyncClient,
    page_kind: IndexedWalletPageKind,
    from_block: u64,
    to_block: u64,
) -> Result<IndexedWalletPage, SyncError> {
    match page_kind {
        IndexedWalletPageKind::Legacy => {
            fetch_indexed_legacy_wallet_page(client, from_block, to_block).await
        }
        IndexedWalletPageKind::Modern => {
            fetch_indexed_modern_wallet_page(client, from_block, to_block).await
        }
    }
}

pub(super) async fn fetch_indexed_modern_wallet_page(
    client: &QuickSyncClient,
    from_block: u64,
    to_block: u64,
) -> Result<IndexedWalletPage, SyncError> {
    let page = client
        .fetch_indexed_wallet_page(from_block, to_block, DEFAULT_PAGE_SIZE)
        .await?;
    let transact = page.transact_commitments;
    let shields = page.shield_commitments;
    let nullifiers = page.nullifiers;
    let page_size = DEFAULT_PAGE_SIZE.get();
    let transact_checkpoint = complete_stream_checkpoint(
        transact.len(),
        page_size,
        to_block,
        transact.iter().map(|item| item.block_number.to()),
    );
    let shield_checkpoint = complete_stream_checkpoint(
        shields.len(),
        page_size,
        to_block,
        shields.iter().map(|item| item.block_number.to()),
    );
    let nullifier_checkpoint = complete_stream_checkpoint(
        nullifiers.len(),
        page_size,
        to_block,
        nullifiers.iter().map(|item| item.block_number.to()),
    );
    let checkpoint_block = transact_checkpoint
        .min(shield_checkpoint)
        .min(nullifier_checkpoint);
    if checkpoint_block < from_block {
        return Err(SyncError::UnexpectedFormat(format!(
            "indexed wallet page is incomplete at block {from_block}; reduce page range or increase page size"
        )));
    }

    let transact_rows = transact.len();
    let shield_rows = shields.len();
    let nullifier_rows = nullifiers.len();
    let transact_commitments = transact
        .into_iter()
        .filter(|item| item.block_number.to::<u64>() <= checkpoint_block)
        .map(indexed_transact_input)
        .collect();
    let shield_commitments = shields
        .into_iter()
        .filter(|item| item.block_number.to::<u64>() <= checkpoint_block)
        .map(indexed_shield_input)
        .collect();
    let nullifiers = nullifiers
        .into_iter()
        .filter(|item| item.block_number.to::<u64>() <= checkpoint_block)
        .map(indexed_nullifier_input)
        .collect();

    Ok(IndexedWalletPage {
        transact_commitments,
        shield_commitments,
        legacy_encrypted_commitments: Vec::new(),
        legacy_generated_commitments: Vec::new(),
        nullifiers,
        checkpoint_block,
        transact_rows,
        shield_rows,
        legacy_encrypted_rows: 0,
        legacy_generated_rows: 0,
        nullifier_rows,
    })
}

pub(super) async fn fetch_indexed_legacy_wallet_page(
    client: &QuickSyncClient,
    from_block: u64,
    to_block: u64,
) -> Result<IndexedWalletPage, SyncError> {
    let page = client
        .fetch_indexed_legacy_wallet_page(from_block, to_block, DEFAULT_PAGE_SIZE)
        .await?;
    let legacy_encrypted = page.legacy_encrypted_commitments;
    let legacy_generated = page.legacy_generated_commitments;
    let nullifiers = page.nullifiers;
    let page_size = DEFAULT_PAGE_SIZE.get();
    let encrypted_checkpoint = complete_stream_checkpoint(
        legacy_encrypted.len(),
        page_size,
        to_block,
        legacy_encrypted.iter().map(|item| item.block_number.to()),
    );
    let generated_checkpoint = complete_stream_checkpoint(
        legacy_generated.len(),
        page_size,
        to_block,
        legacy_generated.iter().map(|item| item.block_number.to()),
    );
    let nullifier_checkpoint = complete_stream_checkpoint(
        nullifiers.len(),
        page_size,
        to_block,
        nullifiers.iter().map(|item| item.block_number.to()),
    );
    let checkpoint_block = encrypted_checkpoint
        .min(generated_checkpoint)
        .min(nullifier_checkpoint);
    if checkpoint_block < from_block {
        return Err(SyncError::UnexpectedFormat(format!(
            "indexed legacy wallet page is incomplete at block {from_block}; reduce page range or increase page size"
        )));
    }

    let legacy_encrypted_rows = legacy_encrypted.len();
    let legacy_generated_rows = legacy_generated.len();
    let nullifier_rows = nullifiers.len();
    let legacy_encrypted_commitments = legacy_encrypted
        .into_iter()
        .filter(|item| item.block_number.to::<u64>() <= checkpoint_block)
        .map(indexed_legacy_encrypted_input)
        .collect();
    let legacy_generated_commitments = legacy_generated
        .into_iter()
        .filter(|item| item.block_number.to::<u64>() <= checkpoint_block)
        .map(indexed_legacy_generated_input)
        .collect();
    let nullifiers = nullifiers
        .into_iter()
        .filter(|item| item.block_number.to::<u64>() <= checkpoint_block)
        .map(indexed_nullifier_input)
        .collect();

    Ok(IndexedWalletPage {
        transact_commitments: Vec::new(),
        shield_commitments: Vec::new(),
        legacy_encrypted_commitments,
        legacy_generated_commitments,
        nullifiers,
        checkpoint_block,
        transact_rows: 0,
        shield_rows: 0,
        legacy_encrypted_rows,
        legacy_generated_rows,
        nullifier_rows,
    })
}

pub(super) fn complete_stream_checkpoint<I>(
    row_count: usize,
    page_size: usize,
    target_block: u64,
    block_numbers: I,
) -> u64
where
    I: Iterator<Item = u64>,
{
    if row_count < page_size {
        return target_block;
    }
    block_numbers
        .max()
        .unwrap_or(target_block)
        .saturating_sub(1)
}

pub(super) fn indexed_source(
    tx_hash: FixedBytes<32>,
    block_number: u64,
    block_timestamp: u64,
) -> UtxoSource {
    UtxoSource {
        tx_hash,
        block_number,
        block_timestamp,
    }
}

pub(super) fn indexed_transact_input(
    item: IndexedTransactCommitment,
) -> IndexedTransactCommitmentInput {
    IndexedTransactCommitmentInput {
        tree_number: item.tree_number.to(),
        tree_position: item.tree_position.to(),
        hash: item.hash,
        ciphertext: item.ciphertext.ciphertext,
        blinded_sender_viewing_key: item.ciphertext.blinded_sender_viewing_key,
        memo: item.ciphertext.memo,
        source: indexed_source(
            item.transaction_hash,
            item.block_number.to(),
            item.block_timestamp.to(),
        ),
    }
}

pub(super) fn indexed_shield_input(item: IndexedShieldCommitment) -> IndexedShieldCommitmentInput {
    IndexedShieldCommitmentInput {
        tree_number: item.tree_number.to(),
        tree_position: item.tree_position.to(),
        preimage: item.preimage(),
        shield_ciphertext: item.shield_ciphertext(),
        source: indexed_source(
            item.transaction_hash,
            item.block_number.to(),
            item.block_timestamp.to(),
        ),
    }
}

pub(super) fn indexed_nullifier_input(item: IndexedNullifier) -> IndexedNullifierInput {
    IndexedNullifierInput {
        tree_number: item.tree_number.to(),
        nullifier: item.nullifier,
        source: indexed_source(
            item.transaction_hash,
            item.block_number.to(),
            item.block_timestamp.to(),
        ),
    }
}

pub(super) fn indexed_legacy_encrypted_input(
    item: IndexedLegacyEncryptedCommitment,
) -> IndexedLegacyEncryptedCommitmentInput {
    IndexedLegacyEncryptedCommitmentInput {
        tree_number: item.tree_number.to(),
        tree_position: item.tree_position.to(),
        hash: item.hash,
        ciphertext: item.ciphertext.ciphertext,
        ephemeral_keys: item.ciphertext.ephemeral_keys,
        memo: item.ciphertext.memo,
        source: indexed_source(
            item.transaction_hash,
            item.block_number.to(),
            item.block_timestamp.to(),
        ),
    }
}

pub(super) fn indexed_legacy_generated_input(
    item: IndexedLegacyGeneratedCommitment,
) -> IndexedLegacyGeneratedCommitmentInput {
    IndexedLegacyGeneratedCommitmentInput {
        tree_number: item.tree_number.to(),
        tree_position: item.tree_position.to(),
        preimage: item.preimage.into(),
        encrypted_random: item.encrypted_random,
        source: indexed_source(
            item.transaction_hash,
            item.block_number.to(),
            item.block_timestamp.to(),
        ),
    }
}

pub(super) fn indexed_wallet_page_kind(
    from_block: u64,
    v2_start_block: u64,
) -> IndexedWalletPageKind {
    if v2_start_block > 0 && from_block < v2_start_block {
        IndexedWalletPageKind::Legacy
    } else {
        IndexedWalletPageKind::Modern
    }
}

pub(super) fn indexed_wallet_to_block(
    from_block: u64,
    target: u64,
    v2_start_block: u64,
    indexed_wallet_block_range: u64,
) -> u64 {
    let range_end = min(
        from_block.saturating_add(indexed_wallet_block_range.saturating_sub(1)),
        target,
    );
    if v2_start_block > 0 && from_block < v2_start_block {
        range_end.min(v2_start_block.saturating_sub(1))
    } else {
        range_end
    }
}

pub(super) fn wallet_backfill_from_block(last_scanned: u64, start_block: u64) -> u64 {
    last_scanned.saturating_add(1).max(start_block)
}

pub(super) fn wallet_reorg_backfill_from_block(reset_from_block: u64, start_block: u64) -> u64 {
    reset_from_block.max(start_block)
}

pub(super) fn wallet_sync_target(safe_head: u64, sync_to_block: Option<u64>) -> u64 {
    match sync_to_block {
        Some(sync_to_block) if safe_head == 0 => sync_to_block,
        Some(sync_to_block) => sync_to_block.min(safe_head),
        None => safe_head,
    }
}

pub(super) fn forest_reorg_decision(
    last_processed: u64,
    meta_last_block: u64,
    stored_hash: [u8; 32],
    confirmed_current_hash: Option<[u8; 32]>,
) -> ForestReorgDecision {
    if stored_hash == [0u8; 32] || meta_last_block != last_processed {
        return ForestReorgDecision::Skip;
    }

    match confirmed_current_hash {
        Some(current_hash) if current_hash == stored_hash => ForestReorgDecision::Match,
        Some(_) => ForestReorgDecision::Mismatch,
        None => ForestReorgDecision::Skip,
    }
}

pub(super) fn wallet_startup_hedge_block_count(
    last_scanned: u64,
    start_block: u64,
    sync_target: u64,
) -> Option<u64> {
    if sync_target == 0 {
        return None;
    }
    let from_block = wallet_backfill_from_block(last_scanned, start_block);
    if from_block > sync_target {
        return None;
    }
    Some(sync_target.saturating_sub(from_block).saturating_add(1))
}

pub(super) fn should_hedge_wallet_startup(
    last_scanned: u64,
    start_block: u64,
    sync_target: u64,
    block_range: u64,
) -> bool {
    block_range > 0
        && wallet_startup_hedge_block_count(last_scanned, start_block, sync_target)
            .is_some_and(|block_count| block_count <= block_range)
}

pub(super) async fn wait_or_cancel<T>(
    cancel: &CancellationToken,
    future: impl Future<Output = T>,
) -> Result<T, WalletStartupSyncError> {
    tokio::select! {
        result = future => Ok(result),
        _ = cancel.cancelled() => Err(WalletStartupSyncError::Cancelled),
    }
}

pub(super) async fn send_wallet_startup_events(
    cache_key: &str,
    events: Vec<BackfillEvent>,
    sync_target: u64,
    sender: &mpsc::Sender<BackfillEvent>,
) -> bool {
    for event in events {
        if let Err(err) = sender.send(event).await {
            debug!(?err, cache_key, "failed to send wallet startup sync event");
            return false;
        }
    }
    if let Err(err) = sender
        .send(BackfillEvent::Done {
            last_block: sync_target,
        })
        .await
    {
        debug!(?err, cache_key, "failed to send wallet startup sync done");
        return false;
    }
    true
}

pub(super) fn missing_archive_for_rpc_fallback(
    chain: &ChainConfig,
    last_processed: u64,
    archive_provider: Option<&DynProvider>,
) -> Option<(u64, u64)> {
    let from_block = last_processed.saturating_add(1).max(chain.deployment_block);
    (archive_provider.is_none()
        && chain.archive_until_block > 0
        && from_block <= chain.archive_until_block)
        .then_some((from_block, chain.archive_until_block))
}

pub(super) fn indexed_catch_up_unavailable(
    chain: &ChainConfig,
    last_processed: u64,
    archive_provider: Option<&DynProvider>,
    source: impl std::fmt::Display,
) -> Option<ChainError> {
    missing_archive_for_rpc_fallback(chain, last_processed, archive_provider).map(
        |(from_block, archive_until_block)| ChainError::IndexedCatchUpUnavailable {
            from_block,
            archive_until_block,
            reason: source.to_string(),
        },
    )
}
