use super::*;

pub(super) fn find_target_row(
    manifest: &TxidPublicCacheManifest,
    db: &DbStore,
    expected_leaf_hash: FixedBytes<32>,
    output_start_global: u128,
) -> Result<TxidPublicCacheRow, TxidPublicCacheError> {
    let mut found = None;
    for page_ref in &manifest.pages {
        let page = read_page(db, page_ref)?;
        for row in page.rows {
            if row.txid_leaf_hash == expected_leaf_hash
                && row.transaction.output_start_global() == output_start_global
            {
                if found.is_some() {
                    return Err(TxidPublicCacheError::AmbiguousTarget);
                }
                found = Some(row);
            }
        }
    }
    found.ok_or(TxidPublicCacheError::MissingTarget)
}

pub(super) fn read_tree_leaves(
    manifest: &TxidPublicCacheManifest,
    db: &DbStore,
    tree: u64,
    leaf_count: u64,
) -> Result<Vec<U256>, TxidPublicCacheError> {
    let start = tree.saturating_mul(TREE_LEAF_COUNT);
    let mut leaves = vec![None; leaf_count as usize];
    for page_ref in &manifest.pages {
        let page_end = page_ref.start_index.saturating_add(page_ref.row_count);
        let range_end = start.saturating_add(leaf_count);
        if page_end <= start || page_ref.start_index >= range_end {
            continue;
        }
        let page = read_page(db, page_ref)?;
        for row in page.rows {
            if row.txid_index >= start && row.txid_index < range_end {
                let index = (row.txid_index - start) as usize;
                leaves[index] = Some(U256::from_be_bytes(row.txid_leaf_hash.0));
            }
        }
    }
    leaves
        .into_iter()
        .enumerate()
        .map(|(index, leaf)| {
            leaf.ok_or_else(|| TxidPublicCacheError::MissingLeaf {
                index: start + index as u64,
            })
        })
        .collect()
}
