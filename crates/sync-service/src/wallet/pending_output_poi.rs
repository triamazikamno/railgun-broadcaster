use super::*;

pub(crate) async fn process_pending_output_poi_observations(
    db: &DbStore,
    chain_id: u64,
    observations: &[CommitmentObservation],
    submitter: Option<&dyn PendingOutputPoiSubmitter>,
) {
    process_pending_output_poi_observations_inner(db, chain_id, observations, submitter, false)
        .await;
}

pub(super) async fn process_pending_output_poi_observations_inner(
    db: &DbStore,
    chain_id: u64,
    observations: &[CommitmentObservation],
    submitter: Option<&dyn PendingOutputPoiSubmitter>,
    force_submission_retry: bool,
) {
    let started = Instant::now();
    let record_started = Instant::now();
    for observation in observations {
        if let Err(err) = record_pending_output_poi_observation(db, chain_id, observation) {
            warn!(
                ?err,
                chain_id,
                commitment = %hex::encode(FixedBytes::from(observation.commitment.to_be_bytes::<32>())),
                "failed to record pending output POI observation"
            );
        }
    }
    let record_elapsed_ms = record_started.elapsed().as_millis();

    let Some(submitter) = submitter else {
        if observations.is_empty() {
            return;
        }
        debug!(
            chain_id,
            observations = observations.len(),
            submitted = false,
            record_elapsed_ms,
            elapsed_ms = started.elapsed().as_millis(),
            "processed pending output POI observations"
        );
        return;
    };
    let submit_started = Instant::now();
    let submitted_contexts =
        match submit_observed_pending_output_pois(db, chain_id, submitter, force_submission_retry)
            .await
        {
            Ok(submitted_contexts) => submitted_contexts,
            Err(err) => {
                warn!(
                    ?err,
                    chain_id, "failed to submit observed pending output POI contexts"
                );
                0
            }
        };
    if submitted_contexts > 0 || !observations.is_empty() {
        debug!(
            chain_id,
            observations = observations.len(),
            submitted = true,
            submitted_contexts,
            record_elapsed_ms,
            submit_elapsed_ms = submit_started.elapsed().as_millis(),
            elapsed_ms = started.elapsed().as_millis(),
            "processed pending output POI observations"
        );
    }
}

pub(super) fn record_pending_output_poi_observation(
    db: &DbStore,
    chain_id: u64,
    observation: &CommitmentObservation,
) -> Result<(), local_db::DbError> {
    let output_commitment = FixedBytes::from(observation.commitment.to_be_bytes::<32>());
    let Some(mut record) = db.get_pending_output_poi_context(chain_id, &output_commitment)? else {
        return Ok(());
    };
    let observed = PendingOutputPoiObservation {
        output_tree: u64::from(observation.tree),
        output_position: observation.position,
        tx_hash: observation.source.tx_hash,
        block_number: observation.source.block_number,
        block_timestamp: observation.source.block_timestamp,
    };
    if record.observe(observed) {
        db.put_pending_output_poi_context(&record)?;
    }
    Ok(())
}

pub(super) async fn submit_observed_pending_output_pois(
    db: &DbStore,
    chain_id: u64,
    submitter: &dyn PendingOutputPoiSubmitter,
    force_submission_retry: bool,
) -> Result<usize, local_db::DbError> {
    let records = db.list_pending_output_poi_contexts(chain_id)?;
    let mut submitted_contexts = 0;
    let now = now_epoch_secs();
    for mut record in records {
        let Some(observation) = record.observation.clone() else {
            continue;
        };
        if record.terminal_error.is_some() {
            continue;
        }
        let recovery =
            db.get_output_poi_recovery(chain_id, &record.wallet_id, &record.output_commitment)?;
        let mut missing_list_keys = record.missing_list_keys();
        if missing_list_keys.is_empty()
            && recovery
                .as_ref()
                .is_some_and(|record| record.submission_retry_allowed(now, force_submission_retry))
        {
            missing_list_keys = record.list_keys();
        }
        if missing_list_keys.is_empty() {
            continue;
        }
        let pre_transaction_pois = record.retain_poi_lists(&missing_list_keys);
        if pre_transaction_pois.len() != missing_list_keys.len() {
            record.terminal_error =
                Some("missing pre-transaction POI for pending output".to_string());
            db.put_pending_output_poi_context(&record)?;
            continue;
        }
        let context = SingleCommitmentProofContext {
            txid_version: record.txid_version.clone(),
            railgun_txid: record.railgun_txid,
            utxo_tree_in: record.utxo_tree_in,
            commitment: record.output_commitment,
            npk: record.output_npk,
            pre_transaction_pois_per_txid_leaf_per_list: pre_transaction_pois,
        };
        let Some(submit_identity) = pending_output_poi_submit_identity(&record, &observation)
        else {
            warn!(
                chain_id,
                commitment = %hex::encode(record.output_commitment),
                output_tree = observation.output_tree,
                output_position = observation.output_position,
                "pending output POI context has invalid output tree"
            );
            continue;
        };
        let submitted_list_keys = missing_list_keys.clone();
        debug!(
            chain_id,
            wallet_id = %record.wallet_id,
            commitment = %hex::encode(record.output_commitment),
            npk = %hex::encode(record.output_npk),
            output_tree = observation.output_tree,
            output_position = observation.output_position,
            derived_blinded_commitment = %hex::encode(submit_identity.derived_blinded_commitment),
            railgun_txid = %hex::encode(FixedBytes::from(record.railgun_txid.to_be_bytes::<32>())),
            txid_leaf_hash = %hex::encode(submit_identity.txid_leaf_hash),
            utxo_tree_in = record.utxo_tree_in,
            source_tx_hash = %hex::encode(observation.tx_hash),
            list_keys = ?submitted_list_keys,
            pre_tx_poi_lists = context.pre_transaction_pois_per_txid_leaf_per_list.len(),
            "submitting pending output POI context"
        );
        match submit_pending_output_poi_context(
            submitter,
            chain_id,
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
                db.put_pending_output_poi_context(&record)?;
                put_pending_output_poi_recovery_record(
                    db,
                    chain_id,
                    &record,
                    &observation,
                    now,
                    OutputPoiRecoveryAction::Submitted {
                        retry_after: PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER,
                    },
                )?;
                submitted_contexts += 1;
            }
            Err(err) => {
                if let Some(mut recovery) = recovery.clone() {
                    recovery.apply_action(
                        OutputPoiRecoveryAction::SubmitFailed {
                            error: err.to_string(),
                            retry_after: OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
                        },
                        now,
                    );
                    db.put_output_poi_recovery(&recovery)?;
                }
                warn!(
                    ?err,
                    chain_id,
                    commitment = %hex::encode(record.output_commitment),
                    "pending output POI submission failed; keeping context retryable"
                );
            }
        }
    }
    Ok(submitted_contexts)
}

pub(super) fn new_pending_output_poi_recovery_record(
    chain_id: u64,
    record: &PendingOutputPoiContextRecord,
    observation: &PendingOutputPoiObservation,
    status: OutputPoiRecoveryStatus,
    now: u64,
) -> OutputPoiRecoveryRecord {
    OutputPoiRecoveryRecord {
        chain_id,
        wallet_id: record.wallet_id.clone(),
        output_commitment: record.output_commitment,
        source_tx_hash: observation.tx_hash,
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

pub(super) fn put_pending_output_poi_recovery_record(
    db: &DbStore,
    chain_id: u64,
    record: &PendingOutputPoiContextRecord,
    observation: &PendingOutputPoiObservation,
    now: u64,
    action: OutputPoiRecoveryAction,
) -> Result<(), local_db::DbError> {
    let existing =
        db.get_output_poi_recovery(chain_id, &record.wallet_id, &record.output_commitment)?;
    let default_status = match &action {
        OutputPoiRecoveryAction::Detected { status, .. } => *status,
        OutputPoiRecoveryAction::CacheTxInput { .. } => OutputPoiRecoveryStatus::Recoverable,
        OutputPoiRecoveryAction::Submitted { .. } => OutputPoiRecoveryStatus::Submitted,
        OutputPoiRecoveryAction::SubmitFailed { .. } => OutputPoiRecoveryStatus::SubmitFailed,
        OutputPoiRecoveryAction::Valid => OutputPoiRecoveryStatus::Valid,
    };
    let mut recovery = existing.unwrap_or_else(|| {
        new_pending_output_poi_recovery_record(chain_id, record, observation, default_status, now)
    });
    recovery.apply_action(action, now);
    db.put_output_poi_recovery(&recovery)
}

pub(super) fn ensure_pending_output_poi_submission_state(
    db: &DbStore,
    chain_id: u64,
    record: &PendingOutputPoiContextRecord,
    observation: &PendingOutputPoiObservation,
    now: u64,
) -> Result<(), local_db::DbError> {
    if db
        .get_output_poi_recovery(chain_id, &record.wallet_id, &record.output_commitment)?
        .is_some()
    {
        return Ok(());
    }
    put_pending_output_poi_recovery_record(
        db,
        chain_id,
        record,
        observation,
        now,
        OutputPoiRecoveryAction::Submitted {
            retry_after: PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER,
        },
    )
}

pub(super) async fn submit_pending_output_poi_context(
    submitter: &dyn PendingOutputPoiSubmitter,
    chain_id: u64,
    record: &PendingOutputPoiContextRecord,
    context: &SingleCommitmentProofContext,
    observation: &PendingOutputPoiObservation,
    submitted_list_keys: &[FixedBytes<32>],
) -> Result<(), PoiError> {
    if let Some(txid_merkleroot_index) = record.txid_merkleroot_index {
        for list_key in submitted_list_keys {
            let Some(per_leaf) = context
                .pre_transaction_pois_per_txid_leaf_per_list
                .get(list_key)
            else {
                continue;
            };
            for poi in per_leaf.values() {
                submitter
                    .submit_transact_proof(
                        &record.txid_version,
                        EVM_CHAIN_TYPE,
                        chain_id,
                        list_key,
                        txid_merkleroot_index,
                        poi,
                    )
                    .await?;
            }
        }
        Ok(())
    } else {
        submitter
            .submit_single_commitment_proofs(
                &record.txid_version,
                EVM_CHAIN_TYPE,
                chain_id,
                context,
                observation.output_tree,
                observation.output_position,
            )
            .await
    }
}

pub(super) struct PendingOutputPoiSubmitIdentity {
    pub(super) derived_blinded_commitment: FixedBytes<32>,
    pub(super) txid_leaf_hash: FixedBytes<32>,
}

pub(super) fn pending_output_poi_submit_identity(
    record: &PendingOutputPoiContextRecord,
    observation: &PendingOutputPoiObservation,
) -> Option<PendingOutputPoiSubmitIdentity> {
    let output_tree = u32::try_from(observation.output_tree).ok()?;
    let txid_leaf_hash = record.txid_leaf_hash()?;
    Some(PendingOutputPoiSubmitIdentity {
        derived_blinded_commitment: UtxoPoiMetadata::blinded_commitment_for(
            record.output_commitment,
            record.output_npk,
            output_tree,
            observation.output_position,
        ),
        txid_leaf_hash,
    })
}

pub(super) fn pending_output_poi_context_matches_wallet_utxo(
    cfg: &WalletConfig,
    wallet_utxo: &WalletUtxo,
    record: &PendingOutputPoiContextRecord,
) -> bool {
    if record.chain_id != cfg.chain.chain_id
        || record.output_commitment != wallet_utxo.utxo.poi.commitment
    {
        return false;
    }
    let Some(observation) = record.observation.as_ref() else {
        return false;
    };
    if observation.output_tree != u64::from(wallet_utxo.utxo.tree)
        || observation.output_position != wallet_utxo.utxo.position
        || observation.tx_hash != wallet_utxo.utxo.source.tx_hash
    {
        return false;
    }
    pending_output_poi_submit_identity(record, observation).is_some_and(|identity| {
        identity.derived_blinded_commitment == wallet_utxo.utxo.poi.blinded_commitment
    })
}

#[derive(Default)]
pub(super) struct PendingOutputPoiVerificationOutcome {
    pub(super) completed: usize,
    pub(super) pending: usize,
    pub(super) errors: usize,
}

pub(super) async fn verify_submitted_pending_output_pois_with_config(
    remote_client: &PoiRpcClient,
    cfg: &WalletConfig,
    db: &DbStore,
    active_list_keys: &[FixedBytes<32>],
) -> PendingOutputPoiVerificationOutcome {
    match &cfg.poi_read_source {
        PoiReadSource::IndexedArtifacts(_) => {
            let local_caches = cfg.local_poi_caches.as_ref().cloned().unwrap_or_else(|| {
                warn!(
                    cache_key = %cfg.cache_key,
                    chain_id = cfg.chain.chain_id,
                    "artifact POI read source missing local cache handle"
                );
                Arc::new(RwLock::new(BTreeMap::new()))
            });
            let reader = LocalPoiStatusReader::new(local_caches);
            verify_submitted_pending_output_pois(&reader, db, cfg.chain.chain_id, active_list_keys)
                .await
        }
        PoiReadSource::PoiProxy => {
            verify_submitted_pending_output_pois(
                remote_client,
                db,
                cfg.chain.chain_id,
                active_list_keys,
            )
            .await
        }
    }
}

pub(super) async fn verify_submitted_pending_output_pois(
    status_reader: &dyn PoiStatusReader,
    db: &DbStore,
    chain_id: u64,
    active_list_keys: &[FixedBytes<32>],
) -> PendingOutputPoiVerificationOutcome {
    let records = match db.list_pending_output_poi_contexts(chain_id) {
        Ok(records) => records,
        Err(err) => {
            warn!(?err, chain_id, "failed to list pending output POI contexts");
            return PendingOutputPoiVerificationOutcome {
                errors: 1,
                ..PendingOutputPoiVerificationOutcome::default()
            };
        }
    };
    let now = now_epoch_secs();
    let mut outcome = PendingOutputPoiVerificationOutcome::default();
    for record in records {
        if record.terminal_error.is_some() || record.submitted_poi_list_keys.is_empty() {
            continue;
        }
        let Some(observation) = record.observation.as_ref() else {
            continue;
        };
        let required_list_keys = record
            .list_keys()
            .into_iter()
            .filter(|list_key| active_list_keys.contains(list_key))
            .collect::<Vec<_>>();
        if required_list_keys.is_empty()
            || required_list_keys
                .iter()
                .any(|list_key| !record.submitted_poi_list_keys.contains(list_key))
        {
            continue;
        }
        let Some(identity) = pending_output_poi_submit_identity(&record, observation) else {
            continue;
        };
        let statuses = match status_reader
            .pois_per_list(
                &record.txid_version,
                EVM_CHAIN_TYPE,
                chain_id,
                &required_list_keys,
                &[BlindedCommitmentData::transact(
                    identity.derived_blinded_commitment,
                )],
            )
            .await
        {
            Ok(mut statuses) => statuses
                .remove(&identity.derived_blinded_commitment)
                .unwrap_or_default(),
            Err(err) => {
                outcome.errors += 1;
                warn!(
                    ?err,
                    chain_id,
                    wallet_id = %record.wallet_id,
                    commitment = %hex::encode(record.output_commitment),
                    "failed to verify submitted pending output POI status"
                );
                continue;
            }
        };
        let all_valid = required_list_keys
            .iter()
            .all(|list_key| statuses.get(list_key) == Some(&PoiStatus::Valid));
        if all_valid {
            if let Err(err) =
                db.delete_pending_output_poi_context(chain_id, &record.output_commitment)
            {
                outcome.errors += 1;
                warn!(
                    ?err,
                    chain_id,
                    wallet_id = %record.wallet_id,
                    commitment = %hex::encode(record.output_commitment),
                    "failed to delete verified pending output POI context"
                );
                continue;
            }
            if let Ok(Some(mut recovery)) =
                db.get_output_poi_recovery(chain_id, &record.wallet_id, &record.output_commitment)
            {
                recovery.apply_action(OutputPoiRecoveryAction::Valid, now);
                if let Err(err) = db.put_output_poi_recovery(&recovery) {
                    warn!(
                        ?err,
                        chain_id,
                        wallet_id = %record.wallet_id,
                        commitment = %hex::encode(record.output_commitment),
                        "failed to mark pending output POI recovery valid"
                    );
                }
            }
            outcome.completed += 1;
            debug!(
                chain_id,
                wallet_id = %record.wallet_id,
                output_role = ?record.output_role,
                commitment = %hex::encode(record.output_commitment),
                derived_blinded_commitment = %hex::encode(identity.derived_blinded_commitment),
                list_keys = ?required_list_keys,
                "verified pending output POI context"
            );
        } else {
            if let Err(err) =
                ensure_pending_output_poi_submission_state(db, chain_id, &record, observation, now)
            {
                outcome.errors += 1;
                warn!(
                    ?err,
                    chain_id,
                    wallet_id = %record.wallet_id,
                    commitment = %hex::encode(record.output_commitment),
                    "failed to persist pending output POI submission state"
                );
            }
            outcome.pending += 1;
        }
    }
    if outcome.completed > 0 || outcome.pending > 0 || outcome.errors > 0 {
        debug!(
            chain_id,
            completed = outcome.completed,
            pending = outcome.pending,
            errors = outcome.errors,
            "verified submitted pending output POI contexts"
        );
    }
    outcome
}
