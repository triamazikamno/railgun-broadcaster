use super::*;

pub(crate) fn txid_public_proof_for_recovered_output(
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
    expected_leaf_hash: U256,
    output_start_global: u128,
    latest_validated_txid_index: u64,
    latest_validated_merkleroot: Option<FixedBytes<32>>,
) -> Result<TxidPublicProof, TxidPublicCacheError> {
    let manifest = load_manifest(db, key)?.ok_or(TxidPublicCacheError::CacheNotReady {
        next_index: 0,
        required_index: latest_validated_txid_index,
    })?;
    validate_manifest(&manifest, key)?;
    let expected_leaf_hash = FixedBytes::from(expected_leaf_hash.to_be_bytes::<32>());
    let target = find_target_row(&manifest, db, expected_leaf_hash, output_start_global)?;
    txid_public_proof_for_target_row(
        &manifest,
        db,
        target,
        latest_validated_txid_index,
        latest_validated_merkleroot,
    )
}

pub(crate) fn txid_public_proof_for_recovered_output_at_index(
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
    target_txid_index: u64,
    expected_leaf_hash: U256,
    output_start_global: u128,
    latest_validated_txid_index: u64,
    latest_validated_merkleroot: Option<FixedBytes<32>>,
) -> Result<TxidPublicProof, TxidPublicCacheError> {
    let manifest = load_manifest(db, key)?.ok_or(TxidPublicCacheError::CacheNotReady {
        next_index: 0,
        required_index: latest_validated_txid_index,
    })?;
    validate_manifest(&manifest, key)?;
    validated_root_txid_index(&manifest, target_txid_index, latest_validated_txid_index)?;
    let target = row_for_txid_index(&manifest, db, target_txid_index)?.ok_or(
        TxidPublicCacheError::MissingLeaf {
            index: target_txid_index,
        },
    )?;
    let expected_leaf_hash = FixedBytes::from(expected_leaf_hash.to_be_bytes::<32>());
    if target.txid_leaf_hash != expected_leaf_hash
        || target.transaction.output_start_global() != output_start_global
    {
        return Err(TxidPublicCacheError::LeafMismatch);
    }
    txid_public_proof_for_target_row(
        &manifest,
        db,
        target,
        latest_validated_txid_index,
        latest_validated_merkleroot,
    )
}

pub(super) fn txid_public_proof_for_target_row(
    manifest: &TxidPublicCacheManifest,
    db: &DbStore,
    target: TxidPublicCacheRow,
    latest_validated_txid_index: u64,
    latest_validated_merkleroot: Option<FixedBytes<32>>,
) -> Result<TxidPublicProof, TxidPublicCacheError> {
    let root_txid_index =
        validated_root_txid_index(manifest, target.txid_index, latest_validated_txid_index)?;
    let target_tree = target.txid_index / TREE_LEAF_COUNT;
    let target_index = target.txid_index % TREE_LEAF_COUNT;
    let root_index = root_txid_index % TREE_LEAF_COUNT;
    let leaf_count = root_index.saturating_add(1);
    let leaves = read_tree_leaves(manifest, db, target_tree, leaf_count)?;
    let tree = DenseMerkleTree::from_ordered_leaves(leaves, leaf_count);
    let proof = tree.prove(target_index);
    if proof.leaf != U256::from_be_bytes(target.txid_leaf_hash.0) {
        return Err(TxidPublicCacheError::LeafMismatch);
    }

    let computed_root = FixedBytes::from(proof.root.to_be_bytes::<32>());
    if root_txid_index == latest_validated_txid_index
        && latest_validated_merkleroot.is_some_and(|root| root != computed_root)
    {
        return Err(TxidPublicCacheError::RootMismatch);
    }

    Ok(TxidPublicProof {
        target_txid_index: target.txid_index,
        root_txid_index,
        proof,
    })
}

pub(super) fn validated_root_txid_index(
    manifest: &TxidPublicCacheManifest,
    target_txid_index: u64,
    latest_validated_txid_index: u64,
) -> Result<u64, TxidPublicCacheError> {
    if latest_validated_txid_index < target_txid_index {
        return Err(TxidPublicCacheError::CacheNotReady {
            next_index: manifest.next_txid_index,
            required_index: target_txid_index,
        });
    }
    let root_txid_index =
        txid_root_index_for_target(target_txid_index, latest_validated_txid_index);
    if manifest
        .validated_cached_txid_index
        .is_none_or(|index| index < root_txid_index)
    {
        return Err(TxidPublicCacheError::CacheNotReady {
            next_index: manifest
                .validated_cached_txid_index
                .map_or(0, |index| index.saturating_add(1)),
            required_index: root_txid_index,
        });
    }
    Ok(root_txid_index)
}

pub(crate) fn txid_public_transaction_for_recovered_output(
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
    tx_hash: FixedBytes<32>,
    output_commitment: FixedBytes<32>,
) -> Result<TxidPublicCachedTransaction, TxidPublicCacheError> {
    let manifest = load_manifest(db, key)?.ok_or(TxidPublicCacheError::CacheNotReady {
        next_index: 0,
        required_index: 0,
    })?;
    validate_manifest(&manifest, key)?;
    let row = find_public_recovery_transaction_in_manifest(
        &manifest,
        db,
        key,
        tx_hash,
        output_commitment,
    )?;
    Ok(row.into())
}

pub(super) fn find_public_recovery_transaction_in_manifest(
    manifest: &TxidPublicCacheManifest,
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
    tx_hash: FixedBytes<32>,
    output_commitment: FixedBytes<32>,
) -> Result<TxidPublicCacheRow, TxidPublicCacheError> {
    if let Some(row) = find_target_row_by_hash_index(manifest, db, key, tx_hash, output_commitment)?
    {
        return Ok(row);
    }
    rebuild_index_for_manifest(manifest, db, key)?;
    if let Some(row) = find_target_row_by_hash_index(manifest, db, key, tx_hash, output_commitment)?
    {
        return Ok(row);
    }
    find_target_row_by_scan(manifest, db, tx_hash, output_commitment)
}

pub(super) fn find_target_row_by_hash_index(
    manifest: &TxidPublicCacheManifest,
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
    tx_hash: FixedBytes<32>,
    output_commitment: FixedBytes<32>,
) -> Result<Option<TxidPublicCacheRow>, TxidPublicCacheError> {
    let entries = index_entries_for_hash(db, key, tx_hash)?;
    if entries.is_empty() {
        return Ok(None);
    }
    let mut found = RecoveredOutputMatch::default();
    for entry in entries {
        let Some(row) = row_for_index_entry(manifest, db, &entry)? else {
            continue;
        };
        found.remember(manifest, row, tx_hash, output_commitment)?;
    }
    Ok(found.row)
}

pub(super) fn find_target_row_by_scan(
    manifest: &TxidPublicCacheManifest,
    db: &DbStore,
    tx_hash: FixedBytes<32>,
    output_commitment: FixedBytes<32>,
) -> Result<TxidPublicCacheRow, TxidPublicCacheError> {
    let mut found = RecoveredOutputMatch::default();
    for page_ref in &manifest.pages {
        let page = read_page(db, page_ref)?;
        for row in page.rows {
            found.remember(manifest, row, tx_hash, output_commitment)?;
        }
    }
    found.row.ok_or(TxidPublicCacheError::MissingTarget)
}

pub(super) fn find_target_row_in_page(
    manifest: &TxidPublicCacheManifest,
    page: &TxidPublicCachePage,
    tx_hash: FixedBytes<32>,
    output_commitment: FixedBytes<32>,
) -> Result<Option<TxidPublicCacheRow>, TxidPublicCacheError> {
    let mut found = RecoveredOutputMatch::default();
    for row in page.rows.iter().cloned() {
        found.remember(manifest, row, tx_hash, output_commitment)?;
    }
    Ok(found.row)
}

#[derive(Default)]
pub(super) struct RecoveredOutputMatch {
    pub(super) row: Option<TxidPublicCacheRow>,
    pub(super) validated: bool,
}

impl RecoveredOutputMatch {
    fn remember(
        &mut self,
        manifest: &TxidPublicCacheManifest,
        row: TxidPublicCacheRow,
        tx_hash: FixedBytes<32>,
        output_commitment: FixedBytes<32>,
    ) -> Result<(), TxidPublicCacheError> {
        if row.transaction.transaction_hash != tx_hash
            || row.transaction.output_index(output_commitment).is_none()
        {
            return Ok(());
        }
        let validated = manifest
            .validated_cached_txid_index
            .is_some_and(|index| row.txid_index <= index);
        match (&self.row, self.validated, validated) {
            (None, _, _) => {
                self.row = Some(row);
                self.validated = validated;
            }
            (Some(_), true, false) => {}
            (Some(_), false, true) => {
                self.row = Some(row);
                self.validated = true;
            }
            (Some(_), _, _) => return Err(TxidPublicCacheError::AmbiguousTarget),
        }
        Ok(())
    }
}

fn row_for_index_entry(
    manifest: &TxidPublicCacheManifest,
    db: &DbStore,
    entry: &TxidPublicCacheIndexEntry,
) -> Result<Option<TxidPublicCacheRow>, TxidPublicCacheError> {
    let Some(page_ref) = manifest
        .pages
        .iter()
        .find(|page_ref| page_ref.start_index == entry.page_start_index)
    else {
        return Ok(None);
    };
    let page = read_page(db, page_ref)?;
    let Some(row) = page.rows.get(entry.row_offset as usize).cloned() else {
        return Ok(None);
    };
    if row.txid_index != entry.txid_index
        || row.transaction.transaction_hash != entry.transaction_hash
    {
        return Ok(None);
    }
    Ok(Some(row))
}

pub(super) fn row_for_txid_index(
    manifest: &TxidPublicCacheManifest,
    db: &DbStore,
    txid_index: u64,
) -> Result<Option<TxidPublicCacheRow>, TxidPublicCacheError> {
    let Some(page_ref) = manifest.pages.iter().find(|page_ref| {
        txid_index >= page_ref.start_index
            && txid_index < page_ref.start_index.saturating_add(page_ref.row_count)
    }) else {
        return Ok(None);
    };
    let page = read_page(db, page_ref)?;
    let offset = (txid_index - page_ref.start_index) as usize;
    let Some(row) = page.rows.get(offset).cloned() else {
        return Ok(None);
    };
    if row.txid_index == txid_index {
        Ok(Some(row))
    } else {
        Ok(None)
    }
}

pub(super) fn txid_root_index_for_target(
    target_txid_index: u64,
    latest_validated_txid_index: u64,
) -> u64 {
    let target_tree = target_txid_index / TREE_LEAF_COUNT;
    let latest_tree = latest_validated_txid_index / TREE_LEAF_COUNT;
    if latest_tree == target_tree {
        latest_validated_txid_index
    } else {
        (target_tree + 1) * TREE_LEAF_COUNT - 1
    }
}
