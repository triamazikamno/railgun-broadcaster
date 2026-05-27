use super::*;

#[derive(Debug)]
pub(in crate::wallet) struct RecoveredOutputTxidData {
    pub(super) target_txid_index: u64,
    pub(super) poi_data: PostTransactionPoiData,
}

pub(in crate::wallet) struct PublicCacheTxidRecoveryRequest<'a> {
    pub(in crate::wallet) db: &'a DbStore,
    pub(in crate::wallet) cfg: &'a WalletConfig,
    pub(in crate::wallet) poi_client: &'a PoiRpcClient,
    pub(in crate::wallet) http_client: Option<&'a reqwest::Client>,
    pub(in crate::wallet) source_tx_hash: FixedBytes<32>,
    pub(in crate::wallet) output_commitment: FixedBytes<32>,
    pub(in crate::wallet) recovery_chunk: &'a RecoveryChunk,
    pub(in crate::wallet) started: Instant,
}

pub(super) async fn recovered_output_txid_data(
    db: &DbStore,
    cfg: &WalletConfig,
    poi_client: &PoiRpcClient,
    http_client: Option<&reqwest::Client>,
    source_tx_hash: FixedBytes<32>,
    output_commitment: FixedBytes<32>,
    recovery_chunk: &RecoveryChunk,
) -> Result<RecoveredOutputTxidData, RecoveryFailure> {
    let started = Instant::now();
    if matches!(cfg.poi_read_source, PoiReadSource::IndexedArtifacts(_)) {
        return recovered_output_txid_data_from_public_cache(PublicCacheTxidRecoveryRequest {
            db,
            cfg,
            poi_client,
            http_client,
            source_tx_hash,
            output_commitment,
            recovery_chunk,
            started,
        })
        .await;
    }

    let latest_validated_started = Instant::now();
    let latest_validated = poi_client
        .latest_validated_railgun_txid(DEFAULT_TXID_VERSION, EVM_CHAIN_TYPE, cfg.chain.chain_id)
        .await
        .map_err(|err| {
            RecoveryFailure::retryable(
                OutputPoiRecoveryStatus::MissingMerkleProof,
                format!("fetch latest validated TXID failed: {err}"),
                OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
            )
        })?;
    let latest_validated_elapsed_ms = latest_validated_started.elapsed().as_millis();

    let Some(endpoint) = cfg.quick_sync_endpoint.as_ref() else {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::TxFetchFailed,
            "no quick-sync endpoint configured for TXID proof recovery",
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    };
    let client = http_client.cloned().unwrap_or_else(reqwest::Client::new);
    let fetch_target_started = Instant::now();
    let target = fetch_recovery_graph_transaction_by_commitment(
        &client,
        endpoint,
        source_tx_hash,
        output_commitment,
    )
    .await?;
    let fetch_target_elapsed_ms = fetch_target_started.elapsed().as_millis();
    debug!(
        cache_key = %cfg.cache_key,
        source_tx_hash = %hex::encode(source_tx_hash),
        output_commitment = %hex::encode(output_commitment),
        graph_id = %target.id,
        fetch_target_elapsed_ms,
        elapsed_ms = started.elapsed().as_millis(),
        "output POI recovery target transaction fetched"
    );
    target.validate_against_recovery_chunk(recovery_chunk)?;

    let txid_index_started = Instant::now();
    let target_txid_index = fetch_recovery_graph_txid_index(&client, endpoint, &target.id).await?;
    let txid_index_elapsed_ms = txid_index_started.elapsed().as_millis();
    debug!(
        cache_key = %cfg.cache_key,
        source_tx_hash = %hex::encode(source_tx_hash),
        output_commitment = %hex::encode(output_commitment),
        graph_id = %target.id,
        target_txid_index,
        txid_index_elapsed_ms,
        elapsed_ms = started.elapsed().as_millis(),
        "output POI recovery target TXID index fetched"
    );
    let target_tree = target_txid_index / TREE_LEAF_COUNT;
    let target_index = target_txid_index % TREE_LEAF_COUNT;

    let root_txid_index = txid_root_index_for_target(target_txid_index, latest_validated)?;
    let root_tree = root_txid_index / TREE_LEAF_COUNT;
    if root_tree != target_tree {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::MissingMerkleProof,
            "latest validated TXID tree is before recovered transaction tree",
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    }
    let root_index = root_txid_index % TREE_LEAF_COUNT;
    let leaf_count = root_index.saturating_add(1);
    debug!(
        cache_key = %cfg.cache_key,
        source_tx_hash = %hex::encode(source_tx_hash),
        output_commitment = %hex::encode(output_commitment),
        target_txid_index,
        root_txid_index,
        target_tree,
        leaf_count,
        latest_validated_elapsed_ms,
        elapsed_ms = started.elapsed().as_millis(),
        "output POI recovery latest validated TXID fetched"
    );
    let tree_segment_started = Instant::now();
    let transactions =
        fetch_recovery_graph_txid_tree_segment(&client, endpoint, target_tree, leaf_count).await?;
    let tree_segment_elapsed_ms = tree_segment_started.elapsed().as_millis();
    debug!(
        cache_key = %cfg.cache_key,
        source_tx_hash = %hex::encode(source_tx_hash),
        output_commitment = %hex::encode(output_commitment),
        target_tree,
        leaf_count,
        returned = transactions.len(),
        tree_segment_elapsed_ms,
        elapsed_ms = started.elapsed().as_millis(),
        "output POI recovery TXID tree segment fetched"
    );
    if transactions.len() != leaf_count as usize {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::MissingMerkleProof,
            format!(
                "TXID graph returned {} leaves for tree {target_tree}, expected {leaf_count}",
                transactions.len()
            ),
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    }

    let txid_tree_started = Instant::now();
    let txid_tree = DenseMerkleTree::from_ordered_leaves(
        transactions
            .iter()
            .map(RecoveryGraphRailgunTransaction::txid_leaf_hash),
        leaf_count,
    );
    let proof = txid_tree.prove(target_index);
    let txid_tree_elapsed_ms = txid_tree_started.elapsed().as_millis();
    let expected_leaf = target.txid_leaf_hash();
    if proof.leaf != expected_leaf {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::MissingMerkleProof,
            "reconstructed TXID proof leaf does not match target transaction",
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    }
    let txid_merkleroot = FixedBytes::from(proof.root.to_be_bytes::<32>());
    let validate_root_started = Instant::now();
    let valid_root = poi_client
        .validate_txid_merkleroot(
            DEFAULT_TXID_VERSION,
            EVM_CHAIN_TYPE,
            cfg.chain.chain_id,
            target_tree,
            root_index,
            &txid_merkleroot,
        )
        .await
        .map_err(|err| {
            RecoveryFailure::retryable(
                OutputPoiRecoveryStatus::MissingMerkleProof,
                format!("validate recovered TXID merkleroot failed: {err}"),
                OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
            )
        })?;
    let validate_root_elapsed_ms = validate_root_started.elapsed().as_millis();
    if !valid_root {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::MissingMerkleProof,
            "POI node rejected recovered TXID merkleroot",
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    }
    debug!(
        cache_key = %cfg.cache_key,
        source_tx_hash = %hex::encode(source_tx_hash),
        output_commitment = %hex::encode(output_commitment),
        target_txid_index,
        root_txid_index,
        target_tree,
        target_index,
        leaf_count,
        txid_tree_elapsed_ms,
        validate_root_elapsed_ms,
        elapsed_ms = started.elapsed().as_millis(),
        "output POI recovery TXID data ready"
    );

    Ok(RecoveredOutputTxidData {
        target_txid_index,
        poi_data: PostTransactionPoiData {
            txid_leaf_hash: FixedBytes::from(proof.leaf.to_be_bytes::<32>()),
            txid_merkleroot,
            txid_merkleroot_index: root_txid_index,
            txid_merkle_proof_indices: U256::from(target_index),
            txid_merkle_proof_path_elements: proof.path_elements.to_vec(),
            utxo_batch_global_start_position_out: U256::from(recovery_chunk.output_start_global),
        },
    })
}

pub(in crate::wallet) async fn recovered_output_txid_data_from_public_cache(
    request: PublicCacheTxidRecoveryRequest<'_>,
) -> Result<RecoveredOutputTxidData, RecoveryFailure> {
    let PublicCacheTxidRecoveryRequest {
        db,
        cfg,
        poi_client,
        http_client,
        source_tx_hash,
        output_commitment,
        recovery_chunk,
        started,
    } = request;
    let Some(endpoint) = cfg.quick_sync_endpoint.as_ref() else {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::TxFetchFailed,
            "no quick-sync endpoint configured for TXID proof recovery",
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    };
    let cache_key = TxidPublicCacheKey {
        chain_type: EVM_CHAIN_TYPE,
        chain_id: cfg.chain.chain_id,
        txid_version: DEFAULT_TXID_VERSION,
    };
    let latest_validated_started = Instant::now();
    let required_txid_index = recovery_chunk.target_txid_index.unwrap_or(0);
    let (latest_validated_index, latest_validated_root, latest_validated_source) =
        match txid_public_cached_latest_validated(db, cache_key)
            .map_err(txid_public_cache_failure)?
        {
            Some(latest) if latest.txid_index >= required_txid_index => {
                (latest.txid_index, latest.merkleroot, "cache")
            }
            _ => {
                let latest_validated = poi_client
                    .latest_validated_railgun_txid(
                        DEFAULT_TXID_VERSION,
                        EVM_CHAIN_TYPE,
                        cfg.chain.chain_id,
                    )
                    .await
                    .map_err(|err| {
                        RecoveryFailure::retryable(
                            OutputPoiRecoveryStatus::MissingMerkleProof,
                            format!("fetch latest validated TXID failed: {err}"),
                            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
                        )
                    })?;
                let latest = TxidPublicLatestValidated {
                    txid_index: latest_validated_txid_index(&latest_validated)?,
                    merkleroot: latest_validated_txid_root(&latest_validated)?,
                };
                (latest.txid_index, latest.merkleroot, "rpc")
            }
        };
    let latest_validated_elapsed_ms = latest_validated_started.elapsed().as_millis();
    let cache_sync_started = Instant::now();
    sync_txid_public_cache(
        db,
        endpoint,
        http_client,
        cache_key,
        latest_validated_index,
        latest_validated_root,
    )
    .await
    .map_err(txid_public_cache_failure)?;
    let cache_sync_elapsed_ms = cache_sync_started.elapsed().as_millis();

    let expected_leaf = railgun_txid_leaf_hash_with_output_start(
        recovery_chunk.chunk.railgun_txid(),
        u64::from(recovery_chunk.chunk.tree_number),
        U256::from(recovery_chunk.output_start_global),
    );
    let proof_started = Instant::now();
    let cached = if let Some(target_txid_index) = recovery_chunk.target_txid_index {
        txid_public_proof_for_recovered_output_at_index(
            db,
            cache_key,
            target_txid_index,
            expected_leaf,
            recovery_chunk.output_start_global,
            latest_validated_index,
            latest_validated_root,
        )
    } else {
        txid_public_proof_for_recovered_output(
            db,
            cache_key,
            expected_leaf,
            recovery_chunk.output_start_global,
            latest_validated_index,
            latest_validated_root,
        )
    }
    .map_err(txid_public_cache_failure)?;
    let proof_elapsed_ms = proof_started.elapsed().as_millis();
    let target_tree = cached.target_txid_index / TREE_LEAF_COUNT;
    let target_index = cached.target_txid_index % TREE_LEAF_COUNT;
    let root_index = cached.root_txid_index % TREE_LEAF_COUNT;
    let txid_merkleroot = FixedBytes::from(cached.proof.root.to_be_bytes::<32>());
    let validate_root_started = Instant::now();
    let valid_root = poi_client
        .validate_txid_merkleroot(
            DEFAULT_TXID_VERSION,
            EVM_CHAIN_TYPE,
            cfg.chain.chain_id,
            target_tree,
            root_index,
            &txid_merkleroot,
        )
        .await
        .map_err(|err| {
            RecoveryFailure::retryable(
                OutputPoiRecoveryStatus::MissingMerkleProof,
                format!("validate recovered TXID merkleroot failed: {err}"),
                OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
            )
        })?;
    let validate_root_elapsed_ms = validate_root_started.elapsed().as_millis();
    if !valid_root {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::MissingMerkleProof,
            "POI node rejected recovered TXID merkleroot",
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    }
    debug!(
        cache_key = %cfg.cache_key,
        source_tx_hash = %hex::encode(source_tx_hash),
        output_commitment = %hex::encode(output_commitment),
        target_txid_index = cached.target_txid_index,
        root_txid_index = cached.root_txid_index,
        target_tree,
        target_index,
        leaf_count = root_index.saturating_add(1),
        latest_validated_elapsed_ms,
        latest_validated_source,
        cache_sync_elapsed_ms,
        txid_tree_elapsed_ms = proof_elapsed_ms,
        validate_root_elapsed_ms,
        elapsed_ms = started.elapsed().as_millis(),
        "output POI recovery TXID data ready from public cache"
    );

    Ok(RecoveredOutputTxidData {
        target_txid_index: cached.target_txid_index,
        poi_data: PostTransactionPoiData {
            txid_leaf_hash: FixedBytes::from(cached.proof.leaf.to_be_bytes::<32>()),
            txid_merkleroot,
            txid_merkleroot_index: cached.root_txid_index,
            txid_merkle_proof_indices: U256::from(target_index),
            txid_merkle_proof_path_elements: cached.proof.path_elements.to_vec(),
            utxo_batch_global_start_position_out: U256::from(recovery_chunk.output_start_global),
        },
    })
}

pub(super) fn latest_validated_txid_index(
    latest_validated: &ValidatedRailgunTxidStatus,
) -> Result<u64, RecoveryFailure> {
    latest_validated.validated_txid_index.ok_or_else(|| {
        RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::MissingMerkleProof,
            "POI node did not return a latest validated TXID index",
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        )
    })
}

pub(super) fn latest_validated_txid_root(
    latest_validated: &ValidatedRailgunTxidStatus,
) -> Result<Option<FixedBytes<32>>, RecoveryFailure> {
    let Some(root) = latest_validated.validated_merkleroot.as_deref() else {
        return Ok(None);
    };
    let root = root.strip_prefix("0x").unwrap_or(root);
    let bytes = hex::decode(root).map_err(|err| {
        RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::MissingMerkleProof,
            format!("latest validated TXID root is not hex: {err}"),
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        )
    })?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
        RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::MissingMerkleProof,
            format!(
                "latest validated TXID root has {} bytes, expected 32",
                bytes.len()
            ),
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        )
    })?;
    Ok(Some(FixedBytes::from(bytes)))
}

pub(super) fn txid_public_cache_failure(err: TxidPublicCacheError) -> RecoveryFailure {
    let status = match &err {
        TxidPublicCacheError::AmbiguousTarget => OutputPoiRecoveryStatus::UnsupportedShape,
        TxidPublicCacheError::MissingTarget
        | TxidPublicCacheError::CacheNotReady { .. }
        | TxidPublicCacheError::MissingLeaf { .. }
        | TxidPublicCacheError::LeafMismatch
        | TxidPublicCacheError::RootMismatch => OutputPoiRecoveryStatus::MissingMerkleProof,
        TxidPublicCacheError::Db(_)
        | TxidPublicCacheError::Io(_)
        | TxidPublicCacheError::Encode(_)
        | TxidPublicCacheError::Decode(_)
        | TxidPublicCacheError::Sync(_)
        | TxidPublicCacheError::MetadataMismatch(_) => OutputPoiRecoveryStatus::TxFetchFailed,
    };
    let message = format!("TXID public cache failed: {err}");
    if matches!(status, OutputPoiRecoveryStatus::UnsupportedShape) {
        RecoveryFailure::permanent(status, message)
    } else {
        RecoveryFailure::retryable(status, message, OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER)
    }
}

pub(super) fn txid_root_index_for_target(
    target_txid_index: u64,
    latest_validated: ValidatedRailgunTxidStatus,
) -> Result<u64, RecoveryFailure> {
    let Some(latest_validated_index) = latest_validated.validated_txid_index else {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::MissingMerkleProof,
            "POI node did not return a latest validated TXID index",
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    };
    if latest_validated_index < target_txid_index {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::MissingMerkleProof,
            "latest validated TXID index is before recovered transaction",
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    }

    let target_tree = target_txid_index / TREE_LEAF_COUNT;
    let latest_tree = latest_validated_index / TREE_LEAF_COUNT;
    if latest_tree == target_tree {
        Ok(latest_validated_index)
    } else {
        Ok((target_tree + 1) * TREE_LEAF_COUNT - 1)
    }
}

pub(super) async fn fetch_recovery_graph_transaction_by_commitment(
    client: &reqwest::Client,
    endpoint: &Url,
    tx_hash: FixedBytes<32>,
    commitment: FixedBytes<32>,
) -> Result<RecoveryGraphRailgunTransaction, RecoveryFailure> {
    const QUERY: &str = r#"
query RecoveryTxByCommitment($txHash: Bytes!, $commitment: Bytes!) {
  transactions(
    where: { transactionHash_eq: $txHash, commitments_containsAll: [$commitment] }
    orderBy: id_ASC
    limit: 2
  ) {
    id
    nullifiers
    commitments
    boundParamsHash
    utxoTreeIn
    utxoTreeOut
    utxoBatchStartPositionOut
  }
}
"#;
    let data: RecoveryGraphTransactionsData = post_recovery_graphql(
        client,
        endpoint,
        QUERY,
        json!({
            "txHash": hex::encode_prefixed(tx_hash),
            "commitment": hex::encode_prefixed(commitment),
        }),
    )
    .await?;
    let mut transactions = data.transactions;
    match transactions.len() {
        1 => Ok(transactions.remove(0)),
        0 => Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::TxFetchFailed,
            "indexed TXID transaction not found for recovered output",
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        )),
        _ => Err(RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::UnsupportedShape,
            "multiple indexed TXID transactions matched recovered output",
        )),
    }
}

pub(super) async fn fetch_recovery_graph_txid_index(
    client: &reqwest::Client,
    endpoint: &Url,
    graph_id: &str,
) -> Result<u64, RecoveryFailure> {
    const QUERY: &str = r#"
query RecoveryTxidIndex($id: String!) {
  transactionsConnection(orderBy: [id_ASC], where: { id_lte: $id }) {
    totalCount
  }
}
"#;
    let data: RecoveryGraphTxidIndexData =
        post_recovery_graphql(client, endpoint, QUERY, json!({ "id": graph_id })).await?;
    data.transactions_connection
        .total_count
        .checked_sub(1)
        .ok_or_else(|| {
            RecoveryFailure::retryable(
                OutputPoiRecoveryStatus::MissingMerkleProof,
                "indexed TXID transaction count is zero",
                OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
            )
        })
}

pub(super) async fn fetch_recovery_graph_txid_tree_segment(
    client: &reqwest::Client,
    endpoint: &Url,
    tree: u64,
    leaf_count: u64,
) -> Result<Vec<RecoveryGraphRailgunTransaction>, RecoveryFailure> {
    const QUERY: &str = r#"
query RecoveryTxidTreeSegment($offset: Int!, $limit: Int!) {
  transactions(orderBy: id_ASC, offset: $offset, limit: $limit) {
    id
    nullifiers
    commitments
    boundParamsHash
    utxoTreeIn
    utxoTreeOut
    utxoBatchStartPositionOut
  }
}
"#;
    let start = tree.saturating_mul(TREE_LEAF_COUNT);
    let started = Instant::now();
    let mut transactions = Vec::with_capacity(leaf_count as usize);
    while transactions.len() < leaf_count as usize {
        let remaining = leaf_count as usize - transactions.len();
        let limit = remaining.min(OUTPUT_POI_RECOVERY_TXID_GRAPH_PAGE_SIZE);
        let offset = start.saturating_add(transactions.len() as u64);
        let page_started = Instant::now();
        let data: RecoveryGraphTransactionsData = post_recovery_graphql(
            client,
            endpoint,
            QUERY,
            json!({
                "offset": offset,
                "limit": limit,
            }),
        )
        .await?;
        debug!(
            tree,
            leaf_count,
            offset,
            limit,
            returned = data.transactions.len(),
            accumulated = transactions.len() + data.transactions.len(),
            page_elapsed_ms = page_started.elapsed().as_millis(),
            elapsed_ms = started.elapsed().as_millis(),
            "output POI recovery TXID graph page fetched"
        );
        if data.transactions.is_empty() {
            break;
        }
        transactions.extend(data.transactions);
    }
    Ok(transactions)
}

pub(super) async fn post_recovery_graphql<T>(
    client: &reqwest::Client,
    endpoint: &Url,
    query: &'static str,
    variables: serde_json::Value,
) -> Result<T, RecoveryFailure>
where
    T: for<'de> Deserialize<'de>,
{
    post_graphql_data(client, endpoint, query, &variables)
        .await
        .map_err(recovery_graph_failure)
}

pub(super) fn recovery_graph_failure(error: GraphPostError) -> RecoveryFailure {
    let message = match error {
        GraphPostError::Request(error) => format!("TXID graph request failed: {error}"),
        GraphPostError::ReadBody(error) => format!("read TXID graph response failed: {error}"),
        GraphPostError::HttpStatus { status, body } => {
            format!("TXID graph request returned {status}: {body}")
        }
        GraphPostError::Json(error) => format!("decode TXID graph response failed: {error}"),
        GraphPostError::Graphql(message) => format!("TXID graph returned errors: {message}"),
        GraphPostError::MissingData => "TXID graph response missing data".to_string(),
    };
    RecoveryFailure::retryable(
        OutputPoiRecoveryStatus::TxFetchFailed,
        message,
        OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
    )
}

#[derive(Debug, Deserialize)]
pub(super) struct RecoveryGraphTransactionsData {
    pub(super) transactions: Vec<RecoveryGraphRailgunTransaction>,
}

#[derive(Debug, Deserialize)]
pub(super) struct RecoveryGraphTxidIndexData {
    #[serde(rename = "transactionsConnection")]
    pub(super) transactions_connection: RecoveryGraphConnection,
}

#[derive(Debug, Deserialize)]
pub(super) struct RecoveryGraphConnection {
    #[serde(rename = "totalCount")]
    pub(super) total_count: u64,
}

#[derive(Debug, Deserialize)]
pub(in crate::wallet) struct RecoveryGraphRailgunTransaction {
    pub(in crate::wallet) id: String,
    pub(in crate::wallet) nullifiers: Vec<U256>,
    pub(in crate::wallet) commitments: Vec<U256>,
    #[serde(rename = "boundParamsHash")]
    pub(in crate::wallet) bound_params_hash: U256,
    #[serde(rename = "utxoTreeIn")]
    pub(in crate::wallet) utxo_tree_in: U64,
    #[serde(rename = "utxoTreeOut")]
    pub(in crate::wallet) utxo_tree_out: U64,
    #[serde(rename = "utxoBatchStartPositionOut")]
    pub(in crate::wallet) utxo_batch_start_position_out: U64,
}

impl RecoveryGraphRailgunTransaction {
    pub(super) fn railgun_txid(&self) -> U256 {
        compute_railgun_txid_parts(&self.nullifiers, &self.commitments, self.bound_params_hash)
    }

    pub(super) fn txid_leaf_hash(&self) -> U256 {
        railgun_txid_leaf_hash_with_output_start(
            self.railgun_txid(),
            self.utxo_tree_in.to(),
            U256::from(self.output_start_global()),
        )
    }

    pub(in crate::wallet) fn output_start_global(&self) -> u128 {
        let output_tree = self.utxo_tree_out.to::<u128>();
        let output_position = self.utxo_batch_start_position_out.to::<u128>();
        output_tree * u128::from(TREE_LEAF_COUNT) + output_position
    }

    pub(super) fn validate_against_recovery_chunk(
        &self,
        recovery_chunk: &RecoveryChunk,
    ) -> Result<(), RecoveryFailure> {
        if self.railgun_txid() != recovery_chunk.chunk.railgun_txid() {
            return Err(RecoveryFailure::permanent(
                OutputPoiRecoveryStatus::UnsupportedShape,
                "indexed TXID transaction does not match recovered calldata transaction",
            ));
        }
        if self.output_start_global() != recovery_chunk.output_start_global {
            return Err(RecoveryFailure::permanent(
                OutputPoiRecoveryStatus::UnsupportedShape,
                "indexed TXID output position does not match recovered wallet output",
            ));
        }
        Ok(())
    }
}

pub(super) async fn resolve_cached_public_recovery_transaction(
    request: &OutputPoiRecoveryRequest<'_>,
    source_tx_hash: FixedBytes<32>,
    output_commitment: FixedBytes<32>,
) -> Result<TxidPublicCachedTransaction, RecoveryFailure> {
    let key = TxidPublicCacheKey {
        chain_type: EVM_CHAIN_TYPE,
        chain_id: request.cfg.chain.chain_id,
        txid_version: DEFAULT_TXID_VERSION,
    };
    match txid_public_transaction_for_recovered_output(
        request.db,
        key,
        source_tx_hash,
        output_commitment,
    ) {
        Ok(transaction) => return Ok(transaction),
        Err(err)
            if !matches!(
                err,
                TxidPublicCacheError::MissingTarget
                    | TxidPublicCacheError::CacheNotReady { .. }
                    | TxidPublicCacheError::MetadataMismatch(_)
            ) =>
        {
            return Err(txid_public_cache_failure(err));
        }
        Err(_) => {}
    }

    let Some(endpoint) = request.cfg.quick_sync_endpoint.as_ref() else {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::TxFetchFailed,
            "no quick-sync endpoint configured for public transaction recovery",
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    };
    sync_txid_public_cache_until_recovered_output(
        request.db,
        endpoint,
        request.http_client,
        key,
        source_tx_hash,
        output_commitment,
    )
    .await
    .map_err(txid_public_cache_failure)
}
