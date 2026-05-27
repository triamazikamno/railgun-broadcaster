use super::*;

#[derive(Clone, Copy)]
pub(super) struct RecoverySpendPublicKey {
    pub(super) spending_public_key: [U256; 2],
}

impl RailgunSpendSigner for RecoverySpendPublicKey {
    fn spending_public_key(&self) -> [U256; 2] {
        self.spending_public_key
    }

    fn sign_spend_message(&self, _msg: U256) -> [U256; 3] {
        [U256::ZERO; 3]
    }
}

pub(super) struct OutputPoiRecoveryRequest<'a> {
    pub(super) db: &'a DbStore,
    pub(super) cfg: &'a WalletConfig,
    pub(super) rpcs: &'a QueryRpcPool,
    pub(super) http_client: Option<&'a reqwest::Client>,
    pub(super) forest: &'a MerkleForest,
    pub(super) poi_client: &'a PoiRpcClient,
    pub(super) proof_source: &'a (dyn PoiMerkleProofSource + 'a),
    pub(super) local_proof_source: Option<&'a LocalPoiMerkleProofSource>,
    pub(super) submitter: &'a dyn PendingOutputPoiSubmitter,
    pub(super) active_list_keys: &'a [FixedBytes<32>],
    pub(super) wallet_utxos: &'a [WalletUtxo],
    pub(super) force_retry: bool,
}

pub(super) struct WalletNullifierIndex<'a> {
    pub(super) wallet_utxos: &'a [WalletUtxo],
    pub(super) by_tree_nullifier: HashMap<(u32, U256), usize>,
}

impl<'a> WalletNullifierIndex<'a> {
    pub(super) fn new(
        wallet_utxos: &'a [WalletUtxo],
        scan_keys: &railgun_wallet::scan::WalletScanKeys,
    ) -> Self {
        let mut by_tree_nullifier = HashMap::with_capacity(wallet_utxos.len());
        for (index, wallet_utxo) in wallet_utxos.iter().enumerate() {
            if wallet_utxo.spent.is_some() {
                by_tree_nullifier.insert(
                    (
                        wallet_utxo.utxo.tree,
                        wallet_utxo.utxo.nullifier(scan_keys.nullifying_key),
                    ),
                    index,
                );
            }
        }
        Self {
            wallet_utxos,
            by_tree_nullifier,
        }
    }

    pub(super) fn input_for(
        &self,
        input_tree: u32,
        nullifier: U256,
        source_tx_hash: FixedBytes<32>,
    ) -> Option<&'a WalletUtxo> {
        let index = self.by_tree_nullifier.get(&(input_tree, nullifier))?;
        let wallet_utxo = self.wallet_utxos.get(*index)?;
        wallet_utxo
            .spent
            .as_ref()
            .is_some_and(|spent| spent.tx_hash == source_tx_hash)
            .then_some(wallet_utxo)
    }
}

#[derive(Debug)]
pub(super) struct RecoveryChunk {
    pub(super) chunk: TransactionPlanChunk,
    pub(super) output: Utxo,
    pub(super) output_start_global: u128,
    pub(super) target_txid_index: Option<u64>,
}

#[derive(Debug, Clone)]
pub(super) struct RecoveryFailure {
    pub(super) status: OutputPoiRecoveryStatus,
    pub(super) message: String,
    pub(super) retry_after: Option<Duration>,
}

impl RecoveryFailure {
    pub(super) fn permanent(status: OutputPoiRecoveryStatus, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
            retry_after: None,
        }
    }

    pub(super) fn retryable(
        status: OutputPoiRecoveryStatus,
        message: impl Into<String>,
        retry_after: Duration,
    ) -> Self {
        Self {
            status,
            message: message.into(),
            retry_after: Some(retry_after),
        }
    }
}

#[derive(Deserialize)]
pub(super) struct JsonRpcResponse<T> {
    pub(super) result: Option<T>,
    pub(super) error: Option<JsonRpcError>,
}

#[derive(Deserialize)]
pub(super) struct JsonRpcError {
    pub(super) message: String,
}

#[derive(Deserialize)]
pub(super) struct JsonRpcTransaction {
    pub(super) input: Option<String>,
    pub(super) data: Option<String>,
}

pub(super) async fn recover_missing_output_pois(request: OutputPoiRecoveryRequest<'_>) -> usize {
    let Some(spending_public_key) = request.cfg.spending_public_key else {
        return 0;
    };
    let Some(prover) = request.cfg.poi_recovery_prover.as_ref() else {
        return 0;
    };
    if request.active_list_keys.is_empty() {
        return 0;
    }

    let started = Instant::now();
    let now = now_epoch_secs();
    let mut fetched_inputs: HashMap<FixedBytes<32>, Result<Bytes, RecoveryFailure>> =
        HashMap::new();
    let mut recovered = 0usize;
    let candidates = output_poi_recovery_candidates(request.wallet_utxos, request.active_list_keys);
    let wallet_nullifiers = WalletNullifierIndex::new(request.wallet_utxos, &request.cfg.scan_keys);
    debug!(
        cache_key = %request.cfg.cache_key,
        candidates = candidates.len(),
        force_retry = request.force_retry,
        "output POI recovery scan started"
    );

    for candidate in candidates {
        let candidate_started = Instant::now();
        let output_commitment = candidate.utxo.poi.commitment;
        let source_tx_hash = candidate.utxo.source.tx_hash;
        let existing_pending_context = request
            .db
            .get_pending_output_poi_context(request.cfg.chain.chain_id, &output_commitment)
            .ok()
            .flatten();
        if let Some(existing_pending_context) = existing_pending_context.as_ref() {
            if existing_pending_context.terminal_error.is_none()
                && pending_output_poi_context_matches_wallet_utxo(
                    request.cfg,
                    candidate,
                    existing_pending_context,
                )
            {
                if request.force_retry {
                    debug!(
                        cache_key = %request.cfg.cache_key,
                        commitment = %hex::encode(output_commitment),
                        source_tx_hash = %hex::encode(source_tx_hash),
                        "output POI recovery skipped; matching pending context exists"
                    );
                }
                continue;
            }
            if !request.force_retry {
                continue;
            }
            log_forced_output_poi_recovery_regeneration(
                request.cfg,
                candidate,
                existing_pending_context,
            );
        }

        match request.db.get_output_poi_recovery(
            request.cfg.chain.chain_id,
            &request.cfg.cache_key,
            &output_commitment,
        ) {
            Ok(Some(record)) if !record.retry_allowed(now, request.force_retry) => {
                continue;
            }
            Ok(_) => {}
            Err(err) => {
                warn!(
                    ?err,
                    cache_key = %request.cfg.cache_key,
                    commitment = %hex::encode(output_commitment),
                    "failed to load output POI recovery cache"
                );
                continue;
            }
        }

        let build_chunk_started = Instant::now();
        let recovery_chunk = if matches!(
            request.cfg.poi_read_source,
            PoiReadSource::IndexedArtifacts(_)
        ) {
            let resolve_started = Instant::now();
            let cached_transaction = match resolve_cached_public_recovery_transaction(
                &request,
                source_tx_hash,
                output_commitment,
            )
            .await
            {
                Ok(cached_transaction) => cached_transaction,
                Err(failure) => {
                    record_output_poi_recovery_failure(
                        request.db,
                        request.cfg,
                        candidate,
                        failure,
                        now,
                    );
                    continue;
                }
            };
            debug!(
                cache_key = %request.cfg.cache_key,
                commitment = %hex::encode(output_commitment),
                source_tx_hash = %hex::encode(source_tx_hash),
                txid_index = cached_transaction.txid_index,
                txid_leaf_hash = %hex::encode(cached_transaction.txid_leaf_hash),
                resolve_elapsed_ms = resolve_started.elapsed().as_millis(),
                candidate_elapsed_ms = candidate_started.elapsed().as_millis(),
                "output POI recovery public transaction resolved"
            );

            if request.local_proof_source.is_some() {
                let preflight_started = Instant::now();
                match preflight_local_output_poi_input_proofs_for_public_transaction(
                    request.local_proof_source,
                    request.cfg,
                    candidate,
                    &wallet_nullifiers,
                    &cached_transaction.transaction,
                    request.active_list_keys,
                )
                .await
                {
                    Ok(()) => {
                        debug!(
                            cache_key = %request.cfg.cache_key,
                            commitment = %hex::encode(output_commitment),
                            source_tx_hash = %hex::encode(source_tx_hash),
                            preflight_elapsed_ms = preflight_started.elapsed().as_millis(),
                            candidate_elapsed_ms = candidate_started.elapsed().as_millis(),
                            "output POI recovery local proof preflight complete"
                        );
                    }
                    Err(failure) => {
                        warn!(
                            cache_key = %request.cfg.cache_key,
                            commitment = %hex::encode(output_commitment),
                            source_tx_hash = %hex::encode(source_tx_hash),
                            preflight_elapsed_ms = preflight_started.elapsed().as_millis(),
                            candidate_elapsed_ms = candidate_started.elapsed().as_millis(),
                            error = %failure.message,
                            "output POI recovery local proof preflight failed"
                        );
                        record_output_poi_recovery_failure(
                            request.db,
                            request.cfg,
                            candidate,
                            failure,
                            now,
                        );
                        continue;
                    }
                }
            }

            match build_output_poi_recovery_chunk_from_public_transaction(
                candidate,
                &wallet_nullifiers,
                &cached_transaction,
                request.forest,
                request.active_list_keys,
                spending_public_key,
                &request.cfg.scan_keys,
            ) {
                Ok(recovery_chunk) => recovery_chunk,
                Err(failure) => {
                    record_output_poi_recovery_failure(
                        request.db,
                        request.cfg,
                        candidate,
                        failure,
                        now,
                    );
                    continue;
                }
            }
        } else {
            match build_output_poi_recovery_chunk_from_calldata(CalldataRecoveryBuildRequest {
                request: &request,
                candidate,
                source_tx_hash,
                output_commitment,
                fetched_inputs: &mut fetched_inputs,
                wallet_nullifiers: &wallet_nullifiers,
                spending_public_key,
                now,
                candidate_started,
            })
            .await
            {
                Ok(recovery_chunk) => recovery_chunk,
                Err(failure) => {
                    record_output_poi_recovery_failure(
                        request.db,
                        request.cfg,
                        candidate,
                        failure,
                        now,
                    );
                    continue;
                }
            }
        };
        let build_chunk_elapsed_ms = build_chunk_started.elapsed().as_millis();
        debug!(
            cache_key = %request.cfg.cache_key,
            commitment = %hex::encode(output_commitment),
            source_tx_hash = %hex::encode(source_tx_hash),
            inputs = recovery_chunk.chunk.inputs.len(),
            outputs = recovery_chunk.chunk.outputs.len(),
            output_start_global = recovery_chunk.output_start_global,
            build_chunk_elapsed_ms,
            candidate_elapsed_ms = candidate_started.elapsed().as_millis(),
            "output POI recovery chunk built"
        );

        let txid_data_started = Instant::now();
        let txid_data = match recovered_output_txid_data(
            request.db,
            request.cfg,
            request.poi_client,
            request.http_client,
            source_tx_hash,
            output_commitment,
            &recovery_chunk,
        )
        .await
        {
            Ok(txid_data) => txid_data,
            Err(failure) => {
                record_output_poi_recovery_failure(
                    request.db,
                    request.cfg,
                    candidate,
                    failure,
                    now,
                );
                continue;
            }
        };
        let txid_data_elapsed_ms = txid_data_started.elapsed().as_millis();
        debug!(
            cache_key = %request.cfg.cache_key,
            commitment = %hex::encode(output_commitment),
            source_tx_hash = %hex::encode(source_tx_hash),
            target_txid_index = txid_data.target_txid_index,
            txid_merkleroot_index = txid_data.poi_data.txid_merkleroot_index,
            txid_data_elapsed_ms,
            candidate_elapsed_ms = candidate_started.elapsed().as_millis(),
            "output POI recovery TXID data recovered"
        );

        let proof_generation_started = Instant::now();
        match generate_post_transaction_pois(PostTransactionPoiGenerationRequest {
            chunk: &recovery_chunk.chunk,
            txid_data: &txid_data.poi_data,
            chain_type: EVM_CHAIN_TYPE,
            chain_id: request.cfg.chain.chain_id,
            txid_version: Some(DEFAULT_TXID_VERSION),
            required_poi_list_keys: request.active_list_keys,
            proof_source: request.proof_source,
            prover,
            verify_proof: OUTPUT_POI_RECOVERY_VERIFY_PROOF,
        })
        .await
        {
            Ok(pre_transaction_pois) => {
                let proof_generation_elapsed_ms = proof_generation_started.elapsed().as_millis();
                let record = pending_output_poi_context_from_recovery(
                    request.cfg,
                    candidate,
                    &recovery_chunk,
                    txid_data.poi_data.txid_merkleroot_index,
                    pre_transaction_pois,
                    request.active_list_keys,
                    now,
                );
                if let Err(err) = request.db.put_pending_output_poi_context(&record) {
                    warn!(
                        ?err,
                        cache_key = %request.cfg.cache_key,
                        commitment = %hex::encode(output_commitment),
                        "failed to persist recovered output POI context"
                    );
                    continue;
                }
                put_output_poi_recovery_record(
                    request.db,
                    request.cfg,
                    candidate,
                    now,
                    OutputPoiRecoveryAction::Detected {
                        status: OutputPoiRecoveryStatus::Recoverable,
                        retry_after: None,
                        last_error: None,
                        increment_attempts: false,
                    },
                );
                debug!(
                    cache_key = %request.cfg.cache_key,
                    commitment = %hex::encode(output_commitment),
                    wallet_blinded_commitment = %hex::encode(candidate.utxo.poi.blinded_commitment),
                    source_tx_hash = %hex::encode(source_tx_hash),
                    txid_merkleroot_index = txid_data.poi_data.txid_merkleroot_index,
                    target_txid_index = txid_data.target_txid_index,
                    inputs = recovery_chunk.chunk.inputs.len(),
                    outputs = recovery_chunk.chunk.outputs.len(),
                    input_tree = recovery_chunk.chunk.tree_number,
                    proof_generation_elapsed_ms,
                    candidate_elapsed_ms = candidate_started.elapsed().as_millis(),
                    "reconstructed output POI context"
                );
                recovered += 1;
            }
            Err(err) => {
                let proof_generation_elapsed_ms = proof_generation_started.elapsed().as_millis();
                warn!(
                    cache_key = %request.cfg.cache_key,
                    commitment = %hex::encode(output_commitment),
                    source_tx_hash = %hex::encode(source_tx_hash),
                    proof_generation_elapsed_ms,
                    candidate_elapsed_ms = candidate_started.elapsed().as_millis(),
                    error = %err,
                    "output POI recovery proof generation failed"
                );
                let retry_after = output_poi_recovery_proof_retry_after(&err);
                record_output_poi_recovery_failure(
                    request.db,
                    request.cfg,
                    candidate,
                    RecoveryFailure::retryable(
                        OutputPoiRecoveryStatus::ProofGenerationFailed,
                        err.to_string(),
                        retry_after,
                    ),
                    now,
                );
            }
        }
        let candidate_elapsed = candidate_started.elapsed();
        if candidate_elapsed >= OUTPUT_POI_RECOVERY_SLOW_STEP_AFTER {
            warn!(
                cache_key = %request.cfg.cache_key,
                commitment = %hex::encode(output_commitment),
                source_tx_hash = %hex::encode(source_tx_hash),
                elapsed_ms = candidate_elapsed.as_millis(),
                "slow output POI recovery candidate"
            );
        } else {
            debug!(
                cache_key = %request.cfg.cache_key,
                commitment = %hex::encode(output_commitment),
                source_tx_hash = %hex::encode(source_tx_hash),
                elapsed_ms = candidate_elapsed.as_millis(),
                "output POI recovery candidate complete"
            );
        }
    }

    if recovered > 0 {
        match submit_observed_pending_output_pois(
            request.db,
            request.cfg.chain.chain_id,
            request.submitter,
            false,
        )
        .await
        {
            Ok(submitted_contexts) => {
                debug!(
                    cache_key = %request.cfg.cache_key,
                    recovered,
                    submitted_contexts,
                    elapsed_ms = started.elapsed().as_millis(),
                    "recovered missing output POI contexts"
                );
            }
            Err(err) => {
                warn!(
                    ?err,
                    cache_key = %request.cfg.cache_key,
                    recovered,
                    "failed to submit recovered output POI contexts"
                );
            }
        }
    }

    debug!(
        cache_key = %request.cfg.cache_key,
        recovered,
        elapsed_ms = started.elapsed().as_millis(),
        "output POI recovery scan complete"
    );

    recovered
}

pub(super) async fn force_resubmit_matching_pending_output_pois(
    db: &DbStore,
    cfg: &WalletConfig,
    wallet_utxos: &[WalletUtxo],
    active_list_keys: &[FixedBytes<32>],
    submitter: &dyn PendingOutputPoiSubmitter,
) -> usize {
    if active_list_keys.is_empty() {
        return 0;
    }

    let now = now_epoch_secs();
    let mut attempted_contexts = 0usize;
    for candidate in output_poi_recovery_candidates(wallet_utxos, active_list_keys) {
        let output_commitment = candidate.utxo.poi.commitment;
        let mut record =
            match db.get_pending_output_poi_context(cfg.chain.chain_id, &output_commitment) {
                Ok(Some(record)) => record,
                Ok(None) => continue,
                Err(err) => {
                    warn!(
                        ?err,
                        cache_key = %cfg.cache_key,
                        commitment = %hex::encode(output_commitment),
                        "failed to load matching pending output POI context"
                    );
                    continue;
                }
            };
        if record.terminal_error.is_some()
            || !pending_output_poi_context_matches_wallet_utxo(cfg, candidate, &record)
        {
            continue;
        }

        let mut submitted_list_keys = record.list_keys();
        submitted_list_keys.retain(|list_key| active_list_keys.contains(list_key));
        if submitted_list_keys.is_empty() {
            continue;
        }
        let pre_transaction_pois = record.retain_poi_lists(&submitted_list_keys);
        if pre_transaction_pois.len() != submitted_list_keys.len() {
            record.terminal_error =
                Some("missing pre-transaction POI for pending output".to_string());
            if let Err(err) = db.put_pending_output_poi_context(&record) {
                warn!(
                    ?err,
                    cache_key = %cfg.cache_key,
                    commitment = %hex::encode(output_commitment),
                    "failed to mark pending output POI context terminal"
                );
            }
            continue;
        }
        let Some(observation) = record.observation.clone() else {
            continue;
        };
        let Some(submit_identity) = pending_output_poi_submit_identity(&record, &observation)
        else {
            continue;
        };
        let context = SingleCommitmentProofContext {
            txid_version: record.txid_version.clone(),
            railgun_txid: record.railgun_txid,
            utxo_tree_in: record.utxo_tree_in,
            commitment: record.output_commitment,
            npk: record.output_npk,
            pre_transaction_pois_per_txid_leaf_per_list: pre_transaction_pois,
        };
        debug!(
            cache_key = %cfg.cache_key,
            commitment = %hex::encode(record.output_commitment),
            output_tree = observation.output_tree,
            output_position = observation.output_position,
            derived_blinded_commitment = %hex::encode(submit_identity.derived_blinded_commitment),
            source_tx_hash = %hex::encode(observation.tx_hash),
            list_keys = ?submitted_list_keys,
            "force-resubmitting matching pending output POI context"
        );
        attempted_contexts += 1;
        match submit_pending_output_poi_context(
            submitter,
            cfg.chain.chain_id,
            &record,
            &context,
            &observation,
            &submitted_list_keys,
        )
        .await
        {
            Ok(()) => {
                for list_key in &submitted_list_keys {
                    if !record.submitted_poi_list_keys.contains(list_key) {
                        record.submitted_poi_list_keys.push(*list_key);
                    }
                }
                if let Err(err) = db.put_pending_output_poi_context(&record) {
                    warn!(
                        ?err,
                        cache_key = %cfg.cache_key,
                        commitment = %hex::encode(output_commitment),
                        "failed to persist resubmitted pending output POI context"
                    );
                    continue;
                }
                if let Err(err) = put_pending_output_poi_recovery_record(
                    db,
                    cfg.chain.chain_id,
                    &record,
                    &observation,
                    now,
                    OutputPoiRecoveryAction::Submitted {
                        retry_after: PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER,
                    },
                ) {
                    warn!(
                        ?err,
                        cache_key = %cfg.cache_key,
                        commitment = %hex::encode(output_commitment),
                        "failed to persist resubmitted pending output POI recovery state"
                    );
                }
                if record.wallet_id != cfg.cache_key {
                    put_output_poi_recovery_record(
                        db,
                        cfg,
                        candidate,
                        now,
                        OutputPoiRecoveryAction::Submitted {
                            retry_after: OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER,
                        },
                    );
                }
            }
            Err(err) => {
                put_output_poi_recovery_record(
                    db,
                    cfg,
                    candidate,
                    now,
                    OutputPoiRecoveryAction::SubmitFailed {
                        error: err.to_string(),
                        retry_after: OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
                    },
                );
                warn!(
                    ?err,
                    cache_key = %cfg.cache_key,
                    commitment = %hex::encode(output_commitment),
                    "forced pending output POI resubmission failed"
                );
            }
        }
    }
    attempted_contexts
}

#[derive(Debug)]
pub(super) struct RecoveredOutputTxidData {
    pub(super) target_txid_index: u64,
    pub(super) poi_data: PostTransactionPoiData,
}

pub(super) struct PublicCacheTxidRecoveryRequest<'a> {
    pub(super) db: &'a DbStore,
    pub(super) cfg: &'a WalletConfig,
    pub(super) poi_client: &'a PoiRpcClient,
    pub(super) http_client: Option<&'a reqwest::Client>,
    pub(super) source_tx_hash: FixedBytes<32>,
    pub(super) output_commitment: FixedBytes<32>,
    pub(super) recovery_chunk: &'a RecoveryChunk,
    pub(super) started: Instant,
}

pub(super) struct CalldataRecoveryBuildRequest<'a> {
    pub(super) request: &'a OutputPoiRecoveryRequest<'a>,
    pub(super) candidate: &'a WalletUtxo,
    pub(super) source_tx_hash: FixedBytes<32>,
    pub(super) output_commitment: FixedBytes<32>,
    pub(super) fetched_inputs: &'a mut HashMap<FixedBytes<32>, Result<Bytes, RecoveryFailure>>,
    pub(super) wallet_nullifiers: &'a WalletNullifierIndex<'a>,
    pub(super) spending_public_key: [U256; 2],
    pub(super) now: u64,
    pub(super) candidate_started: Instant,
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

pub(super) async fn recovered_output_txid_data_from_public_cache(
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
pub(super) struct RecoveryGraphRailgunTransaction {
    pub(super) id: String,
    pub(super) nullifiers: Vec<U256>,
    pub(super) commitments: Vec<U256>,
    #[serde(rename = "boundParamsHash")]
    pub(super) bound_params_hash: U256,
    #[serde(rename = "utxoTreeIn")]
    pub(super) utxo_tree_in: U64,
    #[serde(rename = "utxoTreeOut")]
    pub(super) utxo_tree_out: U64,
    #[serde(rename = "utxoBatchStartPositionOut")]
    pub(super) utxo_batch_start_position_out: U64,
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

    pub(super) fn output_start_global(&self) -> u128 {
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

pub(super) fn output_poi_recovery_proof_retry_after(err: &PreTransactionPoiError) -> Duration {
    match err {
        PreTransactionPoiError::Prover(
            ProverError::WorkerPanic(_) | ProverError::WorkerDropped | ProverError::QueueClosed,
        ) => OUTPUT_POI_RECOVERY_PROOF_FAILURE_RETRY_AFTER,
        _ => OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
    }
}

pub(super) fn output_poi_recovery_candidates<'a>(
    wallet_utxos: &'a [WalletUtxo],
    active_list_keys: &[FixedBytes<32>],
) -> Vec<&'a WalletUtxo> {
    wallet_utxos
        .iter()
        .filter(|wallet_utxo| {
            !wallet_utxo.is_spent()
                && wallet_utxo.utxo.poi.commitment_kind == UtxoCommitmentKind::Transact
                && wallet_utxo
                    .utxo
                    .poi
                    .has_recoverable_status_for_lists(active_list_keys)
        })
        .collect()
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

pub(super) async fn build_output_poi_recovery_chunk_from_calldata(
    input: CalldataRecoveryBuildRequest<'_>,
) -> Result<RecoveryChunk, RecoveryFailure> {
    let CalldataRecoveryBuildRequest {
        request,
        candidate,
        source_tx_hash,
        output_commitment,
        fetched_inputs,
        wallet_nullifiers,
        spending_public_key,
        now,
        candidate_started,
    } = input;
    let tx_input_started = Instant::now();
    let (tx_input, tx_input_source) = if let Some(cached) = fetched_inputs.get(&source_tx_hash) {
        (cached.clone(), "memory_cache")
    } else if let Ok(Some(record)) = request.db.get_output_poi_recovery(
        request.cfg.chain.chain_id,
        &request.cfg.cache_key,
        &output_commitment,
    ) && let Some(tx_input) = record.tx_input
    {
        (Ok(Bytes::from(tx_input)), "db_cache")
    } else {
        let fetched = fetch_transaction_input(
            request.rpcs,
            request.http_client,
            request.cfg.chain.chain_id,
            source_tx_hash,
        )
        .await;
        fetched_inputs.insert(source_tx_hash, fetched.clone());
        if let Ok(tx_input) = &fetched {
            put_output_poi_recovery_tx_input(request.db, request.cfg, candidate, tx_input, now);
        }
        (fetched, "rpc")
    };
    let tx_input_elapsed_ms = tx_input_started.elapsed().as_millis();
    debug!(
        cache_key = %request.cfg.cache_key,
        commitment = %hex::encode(output_commitment),
        source_tx_hash = %hex::encode(source_tx_hash),
        tx_input_source,
        tx_input_elapsed_ms,
        candidate_elapsed_ms = candidate_started.elapsed().as_millis(),
        "output POI recovery transaction input resolved"
    );

    let tx_input = tx_input?;
    let decode_started = Instant::now();
    let decoded = decode_railgun_transactions(&tx_input)?;
    let decode_elapsed_ms = decode_started.elapsed().as_millis();
    debug!(
        cache_key = %request.cfg.cache_key,
        commitment = %hex::encode(output_commitment),
        source_tx_hash = %hex::encode(source_tx_hash),
        transactions = decoded.len(),
        decode_elapsed_ms,
        candidate_elapsed_ms = candidate_started.elapsed().as_millis(),
        "output POI recovery transaction input decoded"
    );

    if request.local_proof_source.is_some() {
        let preflight_started = Instant::now();
        match preflight_local_output_poi_input_proofs(
            request.local_proof_source,
            request.cfg,
            candidate,
            request.wallet_utxos,
            wallet_nullifiers,
            &decoded,
            request.active_list_keys,
        )
        .await
        {
            Ok(()) => {
                debug!(
                    cache_key = %request.cfg.cache_key,
                    commitment = %hex::encode(output_commitment),
                    source_tx_hash = %hex::encode(source_tx_hash),
                    preflight_elapsed_ms = preflight_started.elapsed().as_millis(),
                    candidate_elapsed_ms = candidate_started.elapsed().as_millis(),
                    "output POI recovery local proof preflight complete"
                );
            }
            Err(failure) => {
                warn!(
                    cache_key = %request.cfg.cache_key,
                    commitment = %hex::encode(output_commitment),
                    source_tx_hash = %hex::encode(source_tx_hash),
                    preflight_elapsed_ms = preflight_started.elapsed().as_millis(),
                    candidate_elapsed_ms = candidate_started.elapsed().as_millis(),
                    error = %failure.message,
                    "output POI recovery local proof preflight failed"
                );
                return Err(failure);
            }
        }
    }

    build_output_poi_recovery_chunk(
        candidate,
        wallet_nullifiers,
        &decoded,
        request.forest,
        request.active_list_keys,
        spending_public_key,
        &request.cfg.scan_keys,
    )
}

pub(super) async fn fetch_transaction_input(
    rpcs: &QueryRpcPool,
    http_client: Option<&reqwest::Client>,
    chain_id: u64,
    tx_hash: FixedBytes<32>,
) -> Result<Bytes, RecoveryFailure> {
    let Some(provider) = rpcs.random_provider() else {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::TxFetchFailed,
            "no healthy RPC available",
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    };
    let client = http_client.cloned().unwrap_or_else(reqwest::Client::new);
    let tx_hash_hex = hex::encode_prefixed(tx_hash);
    let response = client
        .post(provider.url.clone())
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_getTransactionByHash",
            "params": [tx_hash_hex],
        }))
        .send()
        .await
        .map_err(|err| {
            rpcs.mark_bad_provider(&provider);
            RecoveryFailure::retryable(
                OutputPoiRecoveryStatus::TxFetchFailed,
                format!("fetch transaction RPC failed: {err}"),
                OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
            )
        })?;
    let status = response.status();
    if !status.is_success() {
        rpcs.mark_bad_provider(&provider);
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::TxFetchFailed,
            format!("fetch transaction RPC returned HTTP {status}"),
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    }
    let response: JsonRpcResponse<JsonRpcTransaction> = response.json().await.map_err(|err| {
        rpcs.mark_bad_provider(&provider);
        RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::TxFetchFailed,
            format!("decode transaction RPC response failed: {err}"),
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        )
    })?;
    if let Some(error) = response.error {
        rpcs.mark_bad_provider(&provider);
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::TxFetchFailed,
            format!(
                "fetch transaction RPC error on chain {chain_id}: {}",
                error.message
            ),
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    }
    let Some(tx) = response.result else {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::TxFetchFailed,
            "transaction not found",
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    };
    let input = tx.input.or(tx.data).ok_or_else(|| {
        RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::DecodeFailed,
            "transaction has no input",
        )
    })?;
    let input = input.strip_prefix("0x").unwrap_or(&input);
    let bytes = hex::decode(input).map_err(|err| {
        RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::DecodeFailed,
            format!("transaction input is not hex: {err}"),
        )
    })?;
    Ok(Bytes::from(bytes))
}

pub(super) fn decode_railgun_transactions(
    calldata: &[u8],
) -> Result<Vec<Transaction>, RecoveryFailure> {
    if calldata.len() < 4 {
        return Err(RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::DecodeFailed,
            "transaction input too short",
        ));
    }
    if let Ok(call) = transactCall::abi_decode(calldata) {
        return Ok(call._transactions);
    }
    if let Ok(call) = relayCall::abi_decode(calldata) {
        if !call._actionData.calls.is_empty() {
            return Err(RecoveryFailure::permanent(
                OutputPoiRecoveryStatus::UnsupportedShape,
                "relay transaction with action data is not treated as consolidation recovery",
            ));
        }
        return Ok(call._transactions);
    }
    Err(RecoveryFailure::permanent(
        OutputPoiRecoveryStatus::UnsupportedShape,
        "transaction is not a Railgun transact or relay call",
    ))
}

pub(super) async fn preflight_local_output_poi_input_proofs(
    proof_source: Option<&LocalPoiMerkleProofSource>,
    cfg: &WalletConfig,
    candidate: &WalletUtxo,
    wallet_utxos: &[WalletUtxo],
    wallet_nullifiers: &WalletNullifierIndex<'_>,
    transactions: &[Transaction],
    active_list_keys: &[FixedBytes<32>],
) -> Result<(), RecoveryFailure> {
    let Some(proof_source) = proof_source else {
        return Ok(());
    };
    let Some(blinded_commitments) = output_poi_recovery_input_blinded_commitments(
        candidate,
        wallet_utxos,
        wallet_nullifiers,
        transactions,
        active_list_keys,
    ) else {
        return Ok(());
    };
    for list_key in active_list_keys {
        if let Err(err) = proof_source
            .check_commitments_available(
                DEFAULT_TXID_VERSION,
                EVM_CHAIN_TYPE,
                cfg.chain.chain_id,
                list_key,
                &blinded_commitments,
            )
            .await
        {
            return Err(RecoveryFailure::retryable(
                OutputPoiRecoveryStatus::ProofGenerationFailed,
                format!("local POI proof preflight failed: {err}"),
                output_poi_recovery_proof_retry_after(&err),
            ));
        }
    }
    Ok(())
}

pub(super) async fn preflight_local_output_poi_input_proofs_for_public_transaction(
    proof_source: Option<&LocalPoiMerkleProofSource>,
    cfg: &WalletConfig,
    candidate: &WalletUtxo,
    wallet_nullifiers: &WalletNullifierIndex<'_>,
    transaction: &TxidPublicCacheTransaction,
    active_list_keys: &[FixedBytes<32>],
) -> Result<(), RecoveryFailure> {
    let Some(proof_source) = proof_source else {
        return Ok(());
    };
    let inputs = wallet_inputs_for_public_transaction(candidate, wallet_nullifiers, transaction)?;
    if inputs.iter().any(|wallet_utxo| {
        active_list_keys.iter().any(|list_key| {
            wallet_utxo.utxo.poi.statuses.get(list_key) == Some(&PoiStatus::ShieldBlocked)
        })
    }) {
        return Ok(());
    }
    let blinded_commitments = inputs
        .iter()
        .map(|wallet_utxo| wallet_utxo.utxo.poi.blinded_commitment)
        .collect::<Vec<_>>();
    for list_key in active_list_keys {
        if let Err(err) = proof_source
            .check_commitments_available(
                DEFAULT_TXID_VERSION,
                EVM_CHAIN_TYPE,
                cfg.chain.chain_id,
                list_key,
                &blinded_commitments,
            )
            .await
        {
            return Err(RecoveryFailure::retryable(
                OutputPoiRecoveryStatus::ProofGenerationFailed,
                format!("local POI proof preflight failed: {err}"),
                output_poi_recovery_proof_retry_after(&err),
            ));
        }
    }
    Ok(())
}

pub(super) fn output_poi_recovery_input_blinded_commitments(
    candidate: &WalletUtxo,
    wallet_utxos: &[WalletUtxo],
    wallet_nullifiers: &WalletNullifierIndex<'_>,
    transactions: &[Transaction],
    active_list_keys: &[FixedBytes<32>],
) -> Option<Vec<FixedBytes<32>>> {
    if transactions.len() != 1 {
        return None;
    }
    let output_commitment = U256::from_be_bytes(candidate.utxo.poi.commitment.0);
    for transaction in transactions {
        let Some(output_index) = transaction
            .commitments
            .iter()
            .position(|commitment| U256::from_be_bytes(commitment.0) == output_commitment)
        else {
            continue;
        };
        if transaction.boundParams.unshield != 0 {
            return None;
        }
        let Ok(output_start_global) = output_start_global_position(&candidate.utxo, output_index)
        else {
            return None;
        };
        let output_start_tree = (output_start_global / u128::from(TREE_LEAF_COUNT)) as u32;
        let input_tree = u32::from(transaction.boundParams.treeNumber);
        if input_tree > output_start_tree {
            return None;
        }
        if wallet_outputs_for_transaction(candidate, wallet_utxos, transaction).is_err() {
            return None;
        }
        let inputs =
            wallet_inputs_for_transaction(candidate, wallet_nullifiers, transaction).ok()?;
        if inputs.iter().any(|wallet_utxo| {
            active_list_keys.iter().any(|list_key| {
                wallet_utxo.utxo.poi.statuses.get(list_key) == Some(&PoiStatus::ShieldBlocked)
            })
        }) {
            return None;
        }
        return Some(
            inputs
                .iter()
                .map(|wallet_utxo| wallet_utxo.utxo.poi.blinded_commitment)
                .collect(),
        );
    }
    None
}

pub(super) fn build_output_poi_recovery_chunk(
    candidate: &WalletUtxo,
    wallet_nullifiers: &WalletNullifierIndex<'_>,
    transactions: &[Transaction],
    forest: &MerkleForest,
    active_list_keys: &[FixedBytes<32>],
    spending_public_key: [U256; 2],
    scan_keys: &railgun_wallet::scan::WalletScanKeys,
) -> Result<RecoveryChunk, RecoveryFailure> {
    if transactions.len() != 1 {
        return Err(RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::UnsupportedShape,
            "batched transactions are not treated as consolidation recovery",
        ));
    }
    let output_commitment = U256::from_be_bytes(candidate.utxo.poi.commitment.0);
    for transaction in transactions {
        let Some(output_index) = transaction
            .commitments
            .iter()
            .position(|commitment| U256::from_be_bytes(commitment.0) == output_commitment)
        else {
            continue;
        };
        if transaction.boundParams.unshield != 0 {
            return Err(RecoveryFailure::permanent(
                OutputPoiRecoveryStatus::UnsupportedShape,
                "matched output belongs to an unshield transaction",
            ));
        }

        let output_start_global = output_start_global_position(&candidate.utxo, output_index)?;
        let output_start_tree = (output_start_global / u128::from(TREE_LEAF_COUNT)) as u32;
        let output_start_position = (output_start_global % u128::from(TREE_LEAF_COUNT)) as u64;
        let input_tree = u32::from(transaction.boundParams.treeNumber);
        let max_leaf_count = if input_tree == output_start_tree {
            output_start_position
        } else if input_tree < output_start_tree {
            TREE_LEAF_COUNT
        } else {
            return Err(RecoveryFailure::retryable(
                OutputPoiRecoveryStatus::MissingMerkleProof,
                "transaction input tree is after output tree",
                OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER,
            ));
        };

        let outputs =
            wallet_outputs_for_transaction(candidate, wallet_nullifiers.wallet_utxos, transaction)?;
        let inputs = wallet_inputs_for_transaction(candidate, wallet_nullifiers, transaction)?;
        if inputs.iter().any(|wallet_utxo| {
            active_list_keys.iter().any(|list_key| {
                wallet_utxo.utxo.poi.statuses.get(list_key) == Some(&PoiStatus::ShieldBlocked)
            })
        }) {
            return Err(RecoveryFailure::retryable(
                OutputPoiRecoveryStatus::InputPoiNotValid,
                "one or more transaction inputs are shield-blocked",
                OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER,
            ));
        }

        let merkle_root = U256::from_be_bytes(transaction.merkleRoot.0);
        let first_input = inputs.first().ok_or_else(|| {
            RecoveryFailure::permanent(
                OutputPoiRecoveryStatus::MissingWalletInputs,
                "transaction has no wallet-owned inputs",
            )
        })?;
        let input_merkle = recovery_input_merkle_tree_for_root(
            forest,
            input_tree,
            first_input,
            max_leaf_count,
            merkle_root,
        )?;
        let mut input_witnesses = Vec::with_capacity(inputs.len());
        for input in inputs {
            let proof = input_merkle.tree.prove(input.utxo.position);
            if proof.root != merkle_root || proof.leaf != input.utxo.note.commitment() {
                return Err(RecoveryFailure::retryable(
                    OutputPoiRecoveryStatus::MissingMerkleProof,
                    "reconstructed Merkle proof does not match transaction root",
                    OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER,
                ));
            }
            input_witnesses.push(InputWitness {
                utxo: input.utxo.clone(),
                merkle_proof: proof,
            });
        }

        let output_notes = outputs
            .iter()
            .map(|wallet_utxo| wallet_utxo.utxo.note.clone())
            .collect::<Vec<_>>();
        let public_inputs = PublicInputs::from_transaction(merkle_root, transaction, &output_notes);
        let signer = RecoverySpendPublicKey {
            spending_public_key,
        };
        let private_inputs = PrivateInputs::from_inputs(
            input_witnesses[0].utxo.token_address(),
            &input_witnesses,
            &output_notes,
            scan_keys,
            &signer,
        );
        return Ok(RecoveryChunk {
            chunk: TransactionPlanChunk {
                tree_number: input_tree,
                merkle_root,
                inputs: input_witnesses,
                outputs: output_notes,
                has_unshield: false,
                public_inputs,
                private_inputs,
                signature: [U256::ZERO; 3],
            },
            output: candidate.utxo.clone(),
            output_start_global,
            target_txid_index: None,
        });
    }

    Err(RecoveryFailure::permanent(
        OutputPoiRecoveryStatus::NotSelfOriginated,
        "source transaction does not contain the wallet output commitment",
    ))
}

pub(super) fn build_output_poi_recovery_chunk_from_public_transaction(
    candidate: &WalletUtxo,
    wallet_nullifiers: &WalletNullifierIndex<'_>,
    cached_transaction: &TxidPublicCachedTransaction,
    forest: &MerkleForest,
    active_list_keys: &[FixedBytes<32>],
    spending_public_key: [U256; 2],
    scan_keys: &railgun_wallet::scan::WalletScanKeys,
) -> Result<RecoveryChunk, RecoveryFailure> {
    let transaction = &cached_transaction.transaction;
    let output_commitment = candidate.utxo.poi.commitment;
    let output_index = transaction.output_index(output_commitment).ok_or_else(|| {
        RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::NotSelfOriginated,
            "source transaction does not contain the wallet output commitment",
        )
    })?;
    if transaction.has_unshield {
        return Err(RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::UnsupportedShape,
            "matched output belongs to an unshield transaction",
        ));
    }

    let output_start_global = transaction.output_start_global();
    let candidate_global = u128::from(candidate.utxo.tree) * u128::from(TREE_LEAF_COUNT)
        + u128::from(candidate.utxo.position);
    if output_start_global.checked_add(output_index as u128) != Some(candidate_global) {
        return Err(RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::UnsupportedShape,
            "indexed transaction output start does not match wallet output position",
        ));
    }

    let output_start_tree = (output_start_global / u128::from(TREE_LEAF_COUNT)) as u32;
    let output_start_position = (output_start_global % u128::from(TREE_LEAF_COUNT)) as u64;
    let input_tree = u32::try_from(transaction.utxo_tree_in).map_err(|_| {
        RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::UnsupportedShape,
            "indexed transaction input tree does not fit in u32",
        )
    })?;
    let max_leaf_count = if input_tree == output_start_tree {
        output_start_position
    } else if input_tree < output_start_tree {
        TREE_LEAF_COUNT
    } else {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::MissingMerkleProof,
            "transaction input tree is after output tree",
            OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER,
        ));
    };

    let outputs = wallet_outputs_for_public_transaction(
        candidate,
        wallet_nullifiers.wallet_utxos,
        transaction,
    )?;
    let inputs = wallet_inputs_for_public_transaction(candidate, wallet_nullifiers, transaction)?;
    if inputs.iter().any(|wallet_utxo| {
        active_list_keys.iter().any(|list_key| {
            wallet_utxo.utxo.poi.statuses.get(list_key) == Some(&PoiStatus::ShieldBlocked)
        })
    }) {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::InputPoiNotValid,
            "one or more transaction inputs are shield-blocked",
            OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER,
        ));
    }

    let merkle_root = transaction.merkle_root;
    let first_input = inputs.first().ok_or_else(|| {
        RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::MissingWalletInputs,
            "transaction has no wallet-owned inputs",
        )
    })?;
    let input_merkle = recovery_input_merkle_tree_for_root(
        forest,
        input_tree,
        first_input,
        max_leaf_count,
        merkle_root,
    )?;
    let mut input_witnesses = Vec::with_capacity(inputs.len());
    for input in inputs {
        let proof = input_merkle.tree.prove(input.utxo.position);
        if proof.root != merkle_root || proof.leaf != input.utxo.note.commitment() {
            return Err(RecoveryFailure::retryable(
                OutputPoiRecoveryStatus::MissingMerkleProof,
                "reconstructed Merkle proof does not match transaction root",
                OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER,
            ));
        }
        input_witnesses.push(InputWitness {
            utxo: input.utxo.clone(),
            merkle_proof: proof,
        });
    }

    let output_notes = outputs
        .iter()
        .map(|wallet_utxo| wallet_utxo.utxo.note.clone())
        .collect::<Vec<_>>();
    let public_inputs = PublicInputs::from_parts(
        merkle_root,
        transaction.bound_params_hash,
        transaction.nullifiers.clone(),
        &output_notes,
    );
    let signer = RecoverySpendPublicKey {
        spending_public_key,
    };
    let private_inputs = PrivateInputs::from_inputs(
        input_witnesses[0].utxo.token_address(),
        &input_witnesses,
        &output_notes,
        scan_keys,
        &signer,
    );
    Ok(RecoveryChunk {
        chunk: TransactionPlanChunk {
            tree_number: input_tree,
            merkle_root,
            inputs: input_witnesses,
            outputs: output_notes,
            has_unshield: false,
            public_inputs,
            private_inputs,
            signature: [U256::ZERO; 3],
        },
        output: candidate.utxo.clone(),
        output_start_global,
        target_txid_index: Some(cached_transaction.txid_index),
    })
}

pub(super) fn output_start_global_position(
    utxo: &Utxo,
    output_index: usize,
) -> Result<u128, RecoveryFailure> {
    let global = u128::from(utxo.tree) * u128::from(TREE_LEAF_COUNT) + u128::from(utxo.position);
    global.checked_sub(output_index as u128).ok_or_else(|| {
        RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::UnsupportedShape,
            "output index is before observed output position",
        )
    })
}

pub(super) struct RecoveryInputMerkleTree {
    pub(super) tree: DenseMerkleTree,
}

pub(super) fn recovery_input_merkle_tree_for_root(
    forest: &MerkleForest,
    input_tree: u32,
    first_input: &WalletUtxo,
    max_leaf_count: u64,
    merkle_root: U256,
) -> Result<RecoveryInputMerkleTree, RecoveryFailure> {
    let min_leaf_count = first_input.utxo.position.saturating_add(1);
    if max_leaf_count < min_leaf_count {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::MissingMerkleProof,
            "transaction root predates the first wallet input leaf",
            OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER,
        ));
    }
    let lower_bound = max_leaf_count
        .saturating_sub(OUTPUT_POI_RECOVERY_ROOT_SEARCH_LEAVES)
        .max(min_leaf_count);
    if forest
        .leaf_at(input_tree, first_input.utxo.position)
        .is_none()
    {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::MissingMerkleProof,
            "input tree missing from local Merkle forest",
            OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER,
        ));
    }
    let mut tree = DenseMerkleTree::from_forest_prefix(forest, input_tree, max_leaf_count);
    for leaf_count in (lower_bound..=max_leaf_count).rev() {
        let proof = tree.prove(first_input.utxo.position);
        if proof.leaf == first_input.utxo.note.commitment() && proof.root == merkle_root {
            return Ok(RecoveryInputMerkleTree { tree });
        }
        if leaf_count > lower_bound {
            tree.remove_leaf(leaf_count - 1);
        }
    }
    Err(RecoveryFailure::retryable(
        OutputPoiRecoveryStatus::MissingMerkleProof,
        "reconstructed Merkle proof does not match transaction root within recovery search window",
        OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER,
    ))
}

pub(super) fn wallet_outputs_for_transaction<'a>(
    candidate: &WalletUtxo,
    wallet_utxos: &'a [WalletUtxo],
    transaction: &Transaction,
) -> Result<Vec<&'a WalletUtxo>, RecoveryFailure> {
    let mut outputs = Vec::with_capacity(transaction.commitments.len());
    for commitment in &transaction.commitments {
        let commitment = FixedBytes::from(commitment.0);
        let Some(output) = wallet_utxos.iter().find(|wallet_utxo| {
            wallet_utxo.utxo.source.tx_hash == candidate.utxo.source.tx_hash
                && wallet_utxo.utxo.poi.commitment_kind == UtxoCommitmentKind::Transact
                && wallet_utxo.utxo.poi.commitment == commitment
        }) else {
            return Err(RecoveryFailure::permanent(
                OutputPoiRecoveryStatus::MissingWalletOutputs,
                "not all private transaction outputs are wallet-owned",
            ));
        };
        outputs.push(output);
    }
    if outputs.is_empty() {
        return Err(RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::UnsupportedShape,
            "transaction has no private outputs",
        ));
    }
    Ok(outputs)
}

pub(super) fn wallet_outputs_for_public_transaction<'a>(
    candidate: &WalletUtxo,
    wallet_utxos: &'a [WalletUtxo],
    transaction: &TxidPublicCacheTransaction,
) -> Result<Vec<&'a WalletUtxo>, RecoveryFailure> {
    let mut outputs = Vec::with_capacity(transaction.commitments.len());
    for commitment in &transaction.commitments {
        let commitment = FixedBytes::from(commitment.to_be_bytes::<32>());
        let Some(output) = wallet_utxos.iter().find(|wallet_utxo| {
            wallet_utxo.utxo.source.tx_hash == candidate.utxo.source.tx_hash
                && wallet_utxo.utxo.poi.commitment_kind == UtxoCommitmentKind::Transact
                && wallet_utxo.utxo.poi.commitment == commitment
        }) else {
            return Err(RecoveryFailure::permanent(
                OutputPoiRecoveryStatus::MissingWalletOutputs,
                "not all private transaction outputs are wallet-owned",
            ));
        };
        outputs.push(output);
    }
    if outputs.is_empty() {
        return Err(RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::UnsupportedShape,
            "transaction has no private outputs",
        ));
    }
    Ok(outputs)
}

pub(super) fn wallet_inputs_for_transaction<'a>(
    candidate: &WalletUtxo,
    wallet_nullifiers: &'a WalletNullifierIndex<'a>,
    transaction: &Transaction,
) -> Result<Vec<&'a WalletUtxo>, RecoveryFailure> {
    let input_tree = u32::from(transaction.boundParams.treeNumber);
    let mut inputs = Vec::with_capacity(transaction.nullifiers.len());
    for nullifier in &transaction.nullifiers {
        let nullifier = U256::from_be_bytes(nullifier.0);
        let Some(input) =
            wallet_nullifiers.input_for(input_tree, nullifier, candidate.utxo.source.tx_hash)
        else {
            return Err(RecoveryFailure::permanent(
                OutputPoiRecoveryStatus::NotSelfOriginated,
                "transaction nullifiers do not resolve to wallet-spent inputs",
            ));
        };
        inputs.push(input);
    }
    if inputs.is_empty() {
        return Err(RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::MissingWalletInputs,
            "transaction has no wallet-owned inputs",
        ));
    }
    Ok(inputs)
}

pub(super) fn wallet_inputs_for_public_transaction<'a>(
    candidate: &WalletUtxo,
    wallet_nullifiers: &'a WalletNullifierIndex<'a>,
    transaction: &TxidPublicCacheTransaction,
) -> Result<Vec<&'a WalletUtxo>, RecoveryFailure> {
    let input_tree = u32::try_from(transaction.utxo_tree_in).map_err(|_| {
        RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::UnsupportedShape,
            "indexed transaction input tree does not fit in u32",
        )
    })?;
    let mut inputs = Vec::with_capacity(transaction.nullifiers.len());
    for nullifier in &transaction.nullifiers {
        let Some(input) =
            wallet_nullifiers.input_for(input_tree, *nullifier, candidate.utxo.source.tx_hash)
        else {
            return Err(RecoveryFailure::permanent(
                OutputPoiRecoveryStatus::NotSelfOriginated,
                "transaction nullifiers do not resolve to wallet-spent inputs",
            ));
        };
        inputs.push(input);
    }
    if inputs.is_empty() {
        return Err(RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::MissingWalletInputs,
            "transaction has no wallet-owned inputs",
        ));
    }
    Ok(inputs)
}

pub(super) fn pending_output_poi_context_from_recovery(
    cfg: &WalletConfig,
    candidate: &WalletUtxo,
    recovery_chunk: &RecoveryChunk,
    txid_merkleroot_index: u64,
    pre_transaction_pois: PreTransactionPoiMap,
    active_list_keys: &[FixedBytes<32>],
    now: u64,
) -> PendingOutputPoiContextRecord {
    PendingOutputPoiContextRecord {
        chain_id: cfg.chain.chain_id,
        wallet_id: cfg.cache_key.clone(),
        txid_version: DEFAULT_TXID_VERSION.to_string(),
        output_commitment: recovery_chunk.output.poi.commitment,
        output_npk: recovery_chunk.output.poi.npk,
        utxo_tree_in: u64::from(recovery_chunk.chunk.tree_number),
        railgun_txid: recovery_chunk.chunk.railgun_txid(),
        txid_merkleroot_index: Some(txid_merkleroot_index),
        pre_transaction_pois_per_txid_leaf_per_list: pre_transaction_pois,
        required_poi_list_keys: active_list_keys.to_vec(),
        output_role: PendingOutputPoiRole::Change,
        created_at: now,
        source_operation_id: Some(format!(
            "recovered-output-poi:{}",
            hex::encode(candidate.utxo.source.tx_hash)
        )),
        observation: Some(PendingOutputPoiObservation {
            output_tree: u64::from(candidate.utxo.tree),
            output_position: candidate.utxo.position,
            tx_hash: candidate.utxo.source.tx_hash,
            block_number: candidate.utxo.source.block_number,
            block_timestamp: candidate.utxo.source.block_timestamp,
        }),
        submitted_poi_list_keys: Vec::new(),
        terminal_error: None,
    }
}

pub(super) fn log_forced_output_poi_recovery_regeneration(
    cfg: &WalletConfig,
    candidate: &WalletUtxo,
    existing_pending_context: &PendingOutputPoiContextRecord,
) {
    let stored_derived_blinded_commitment = existing_pending_context
        .observation
        .as_ref()
        .and_then(|observation| {
            pending_output_poi_submit_identity(existing_pending_context, observation)
                .map(|identity| identity.derived_blinded_commitment)
        })
        .map_or_else(|| "none".to_string(), hex::encode);
    let stored_source_tx_hash = existing_pending_context.observation.as_ref().map_or_else(
        || "none".to_string(),
        |observation| hex::encode(observation.tx_hash),
    );
    debug!(
        cache_key = %cfg.cache_key,
        commitment = %hex::encode(candidate.utxo.poi.commitment),
        wallet_blinded_commitment = %hex::encode(candidate.utxo.poi.blinded_commitment),
        stored_derived_blinded_commitment = %stored_derived_blinded_commitment,
        stored_source_tx_hash = %stored_source_tx_hash,
        source_tx_hash = %hex::encode(candidate.utxo.source.tx_hash),
        "force-regenerating recovered output POI context"
    );
}

pub(super) fn new_output_poi_recovery_record(
    cfg: &WalletConfig,
    candidate: &WalletUtxo,
    status: OutputPoiRecoveryStatus,
    now: u64,
) -> OutputPoiRecoveryRecord {
    OutputPoiRecoveryRecord {
        chain_id: cfg.chain.chain_id,
        wallet_id: cfg.cache_key.clone(),
        output_commitment: candidate.utxo.poi.commitment,
        source_tx_hash: candidate.utxo.source.tx_hash,
        tx_input: None,
        status,
        created_at: now,
        updated_at: now,
        last_detection_at: None,
        last_submission_at: None,
        next_retry_at: None,
        attempt_count: 0,
        last_error: None,
    }
}

pub(super) fn record_output_poi_recovery_failure(
    db: &DbStore,
    cfg: &WalletConfig,
    candidate: &WalletUtxo,
    failure: RecoveryFailure,
    now: u64,
) {
    let status = failure.status;
    let message = failure.message;
    put_output_poi_recovery_record(
        db,
        cfg,
        candidate,
        now,
        OutputPoiRecoveryAction::Detected {
            status,
            retry_after: failure.retry_after,
            last_error: Some(message.clone()),
            increment_attempts: true,
        },
    );
    debug!(
        cache_key = %cfg.cache_key,
        status = ?status,
        commitment = %hex::encode(candidate.utxo.poi.commitment),
        source_tx_hash = %hex::encode(candidate.utxo.source.tx_hash),
        error = %message,
        "output POI recovery skipped"
    );
}

pub(super) fn put_output_poi_recovery_tx_input(
    db: &DbStore,
    cfg: &WalletConfig,
    candidate: &WalletUtxo,
    tx_input: &Bytes,
    now: u64,
) {
    let existing = db
        .get_output_poi_recovery(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &candidate.utxo.poi.commitment,
        )
        .ok()
        .flatten();
    let mut record = existing.unwrap_or_else(|| {
        new_output_poi_recovery_record(cfg, candidate, OutputPoiRecoveryStatus::Recoverable, now)
    });
    record.apply_action(
        OutputPoiRecoveryAction::CacheTxInput {
            tx_input: tx_input.to_vec(),
        },
        now,
    );
    if let Err(err) = db.put_output_poi_recovery(&record) {
        warn!(
            ?err,
            cache_key = %cfg.cache_key,
            commitment = %hex::encode(candidate.utxo.poi.commitment),
            "failed to persist output POI recovery transaction input"
        );
    }
}

pub(super) fn put_output_poi_recovery_record(
    db: &DbStore,
    cfg: &WalletConfig,
    candidate: &WalletUtxo,
    now: u64,
    action: OutputPoiRecoveryAction,
) {
    let existing = db
        .get_output_poi_recovery(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &candidate.utxo.poi.commitment,
        )
        .ok()
        .flatten();
    let default_status = match &action {
        OutputPoiRecoveryAction::Detected { status, .. } => *status,
        OutputPoiRecoveryAction::CacheTxInput { .. } => OutputPoiRecoveryStatus::Recoverable,
        OutputPoiRecoveryAction::Submitted { .. } => OutputPoiRecoveryStatus::Submitted,
        OutputPoiRecoveryAction::SubmitFailed { .. } => OutputPoiRecoveryStatus::SubmitFailed,
        OutputPoiRecoveryAction::Valid => OutputPoiRecoveryStatus::Valid,
    };
    let mut record = existing
        .unwrap_or_else(|| new_output_poi_recovery_record(cfg, candidate, default_status, now));
    record.apply_action(action, now);
    if let Err(err) = db.put_output_poi_recovery(&record) {
        warn!(
            ?err,
            cache_key = %cfg.cache_key,
            commitment = %hex::encode(candidate.utxo.poi.commitment),
            "failed to persist output POI recovery state"
        );
    }
}

pub(super) fn mark_valid_output_poi_recoveries(
    db: &DbStore,
    cfg: &WalletConfig,
    wallet_utxos: &[WalletUtxo],
    active_list_keys: &[FixedBytes<32>],
) {
    if active_list_keys.is_empty() {
        return;
    }
    let now = now_epoch_secs();
    for wallet_utxo in wallet_utxos.iter().filter(|wallet_utxo| {
        !wallet_utxo.is_spent()
            && wallet_utxo.utxo.poi.is_valid_for_lists(active_list_keys)
            && wallet_utxo.utxo.poi.commitment_kind == UtxoCommitmentKind::Transact
    }) {
        let Ok(Some(mut record)) = db.get_output_poi_recovery(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &wallet_utxo.utxo.poi.commitment,
        ) else {
            continue;
        };
        if record.status == OutputPoiRecoveryStatus::Valid {
            continue;
        }
        record.apply_action(OutputPoiRecoveryAction::Valid, now);
        if let Err(err) = db.put_output_poi_recovery(&record) {
            warn!(?err, cache_key = %cfg.cache_key, "failed to mark output POI recovery valid");
        }
    }
}
