use super::*;

pub(super) async fn apply_wallet_logs(
    db: &DbStore,
    poi_submitter: Option<&dyn PendingOutputPoiSubmitter>,
    cfg: &WalletConfig,
    wallet_utxos: &Arc<RwLock<Vec<WalletUtxo>>>,
    batch: &SharedLogBatch,
    last_scanned: u64,
) -> Result<(u64, bool), WalletScanError> {
    let started = Instant::now();
    let filter_started = Instant::now();
    let filtered_logs: Vec<_> = batch
        .logs
        .iter()
        .filter(|log| log.block_number.unwrap_or_default() > last_scanned)
        .cloned()
        .collect();
    let filter_elapsed_ms = filter_started.elapsed().as_millis();

    let parse_started = Instant::now();
    let WalletLogDelta {
        utxos: new_utxos,
        nullifiers,
        commitment_observations,
    } = if filtered_logs.is_empty() {
        WalletLogDelta {
            utxos: Vec::new(),
            nullifiers: Vec::new(),
            commitment_observations: Vec::new(),
        }
    } else {
        parse_wallet_delta_from_logs(&filtered_logs, &batch.block_timestamps, &cfg.scan_keys)?
    };
    let parse_elapsed_ms = parse_started.elapsed().as_millis();
    let delta_utxos = new_utxos.len();
    let delta_nullifiers = nullifiers.len();
    let commitment_observation_count = commitment_observations.len();

    let poi_submitter = if commitment_observation_count > 0 {
        poi_submitter
    } else {
        None
    };
    let poi_observation_started = Instant::now();
    process_pending_output_poi_observations(
        db,
        cfg.chain.chain_id,
        &commitment_observations,
        poi_submitter,
    )
    .await;
    let poi_observation_elapsed_ms = poi_observation_started.elapsed().as_millis();

    let apply_started = Instant::now();
    let outcome = apply_wallet_delta_with_outcome(
        cfg,
        wallet_utxos,
        WalletLogDelta {
            utxos: new_utxos,
            nullifiers,
            commitment_observations,
        },
    )
    .await;
    let apply_elapsed_ms = apply_started.elapsed().as_millis();
    discard_pending_output_poi_contexts_for_spent_outputs(
        db,
        cfg.chain.chain_id,
        &outcome.spent_output_commitments,
    );
    let changed = outcome.changed;

    debug!(
        cache_key = %cfg.cache_key,
        chain_id = cfg.chain.chain_id,
        from_block = batch.from_block,
        to_block = batch.to_block,
        logs = batch.logs.len(),
        filtered_logs = filtered_logs.len(),
        delta_utxos,
        delta_nullifiers,
        commitment_observations = commitment_observation_count,
        poi_submission_enabled = poi_submitter.is_some(),
        changed,
        filter_elapsed_ms,
        parse_elapsed_ms,
        poi_observation_elapsed_ms,
        apply_elapsed_ms,
        elapsed_ms = started.elapsed().as_millis(),
        "applied wallet log delta"
    );

    Ok((batch.to_block, changed))
}

pub(super) async fn apply_wallet_delta_with_outcome(
    cfg: &WalletConfig,
    wallet_utxos: &Arc<RwLock<Vec<WalletUtxo>>>,
    delta: WalletLogDelta,
) -> WalletDeltaApplyOutcome {
    let started = Instant::now();
    let lock_wait_started = Instant::now();
    let mut locked = wallet_utxos.write().await;
    let lock_wait_elapsed_ms = lock_wait_started.elapsed().as_millis();
    let rows_before = locked.len();
    let outcome = apply_wallet_delta_to_vec_with_outcome(cfg, &mut locked, delta);
    debug!(
        cache_key = %cfg.cache_key,
        rows_before,
        rows_after = locked.len(),
        changed = outcome.changed,
        spent_outputs = outcome.spent_output_commitments.len(),
        lock_wait_elapsed_ms,
        elapsed_ms = started.elapsed().as_millis(),
        "applied wallet delta to cache"
    );
    outcome
}

pub(crate) fn apply_wallet_delta_to_vec(
    cfg: &WalletConfig,
    wallet_utxos: &mut Vec<WalletUtxo>,
    delta: WalletLogDelta,
) -> bool {
    apply_wallet_delta_to_vec_with_outcome(cfg, wallet_utxos, delta).changed
}

pub(crate) fn pending_overlay_from_delta(
    cfg: &WalletConfig,
    wallet_utxos: &[WalletUtxo],
    delta: WalletLogDelta,
) -> WalletPendingOverlay {
    let WalletLogDelta {
        utxos: delta_utxos,
        nullifiers,
        ..
    } = delta;
    let nullifier_sources: HashMap<_, _> = nullifiers
        .into_iter()
        .map(|spent| ((spent.tree, spent.nullifier), spent.source))
        .collect();

    let mut pending_spent = wallet_utxos
        .iter()
        .filter(|entry| !entry.is_spent())
        .filter_map(|entry| {
            spent_source_for_utxo(
                &entry.utxo,
                cfg.scan_keys.nullifying_key,
                &nullifier_sources,
            )
            .map(|source| WalletPendingSpent::from_source(&entry.utxo, source))
        })
        .collect::<Vec<_>>();
    pending_spent.sort_by_key(WalletPendingSpent::key);

    let mut existing: HashSet<_> = wallet_utxos
        .iter()
        .map(|wallet_utxo| (wallet_utxo.utxo.tree, wallet_utxo.utxo.position))
        .collect();
    let mut new_utxos = Vec::new();
    for utxo in delta_utxos {
        if existing.insert((utxo.tree, utxo.position)) {
            let spent =
                spent_source_for_utxo(&utxo, cfg.scan_keys.nullifying_key, &nullifier_sources);
            new_utxos.push(WalletUtxo { utxo, spent });
        }
    }
    new_utxos.sort_by_key(|wallet_utxo| (wallet_utxo.utxo.tree, wallet_utxo.utxo.position));

    WalletPendingOverlay {
        new_utxos,
        pending_spent,
        local_pending_spent: Vec::new(),
    }
}

pub(super) fn apply_wallet_delta_to_vec_with_outcome(
    cfg: &WalletConfig,
    wallet_utxos: &mut Vec<WalletUtxo>,
    delta: WalletLogDelta,
) -> WalletDeltaApplyOutcome {
    let WalletLogDelta {
        utxos: new_utxos,
        nullifiers,
        ..
    } = delta;
    let nullifier_sources: HashMap<_, _> = nullifiers
        .into_iter()
        .map(|spent| ((spent.tree, spent.nullifier), spent.source))
        .collect();
    let mut changed = false;
    let mut spent_output_commitments = Vec::new();
    if !nullifier_sources.is_empty() {
        for wallet_utxo in wallet_utxos.iter_mut().filter(|entry| !entry.is_spent()) {
            if let Some(source) = spent_source_for_utxo(
                &wallet_utxo.utxo,
                cfg.scan_keys.nullifying_key,
                &nullifier_sources,
            ) {
                wallet_utxo.spent = Some(source);
                spent_output_commitments.push(wallet_utxo.utxo.poi.commitment);
                changed = true;
            }
        }
    }

    let mut existing: HashSet<_> = wallet_utxos
        .iter()
        .map(|wallet_utxo| (wallet_utxo.utxo.tree, wallet_utxo.utxo.position))
        .collect();
    for utxo in new_utxos {
        if existing.insert((utxo.tree, utxo.position)) {
            let spent =
                spent_source_for_utxo(&utxo, cfg.scan_keys.nullifying_key, &nullifier_sources);
            if spent.is_some() {
                spent_output_commitments.push(utxo.poi.commitment);
            }
            wallet_utxos.push(WalletUtxo { utxo, spent });
            changed = true;
        }
    }

    let before_dedupe = wallet_utxos.len();
    super::worker::dedupe_wallet_utxos(wallet_utxos);
    WalletDeltaApplyOutcome {
        changed: changed || wallet_utxos.len() != before_dedupe,
        spent_output_commitments,
    }
}

pub(crate) fn rewind_wallet_utxos(wallet_utxos: &mut Vec<WalletUtxo>, from_block: u64) -> bool {
    let before_len = wallet_utxos.len();
    wallet_utxos.retain(|wallet_utxo| wallet_utxo.utxo.source.block_number < from_block);
    let mut changed = wallet_utxos.len() != before_len;

    for wallet_utxo in wallet_utxos {
        if wallet_utxo
            .spent
            .as_ref()
            .is_some_and(|spent| spent.block_number >= from_block)
        {
            wallet_utxo.spent = None;
            changed = true;
        }
    }

    changed
}

#[derive(Debug, Default)]
pub(super) struct WalletDeltaApplyOutcome {
    pub(super) changed: bool,
    pub(super) spent_output_commitments: Vec<FixedBytes<32>>,
}

pub(super) fn discard_pending_output_poi_contexts_for_spent_outputs(
    db: &DbStore,
    chain_id: u64,
    spent_output_commitments: &[FixedBytes<32>],
) {
    for output_commitment in spent_output_commitments {
        if let Err(err) = db.delete_pending_output_poi_context(chain_id, output_commitment) {
            warn!(
                ?err,
                chain_id,
                commitment = %hex::encode(output_commitment),
                "failed to delete pending output POI context for spent output"
            );
        }
    }
}

pub(super) fn spent_source_for_utxo(
    utxo: &Utxo,
    nullifying_key: U256,
    nullifier_sources: &HashMap<(u32, U256), UtxoSource>,
) -> Option<UtxoSource> {
    nullifier_sources
        .get(&(utxo.tree, utxo.nullifier(nullifying_key)))
        .cloned()
}

pub(super) fn chain_pending_overlay_matches(
    current: &WalletPendingOverlay,
    next: &WalletPendingOverlay,
) -> bool {
    current.pending_spent == next.pending_spent
        && wallet_utxo_keys_match(&current.new_utxos, &next.new_utxos)
}

pub(super) fn wallet_utxo_keys_match(left: &[WalletUtxo], right: &[WalletUtxo]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(left, right)| {
            left.utxo.tree == right.utxo.tree
                && left.utxo.position == right.utxo.position
                && left.utxo.poi.commitment == right.utxo.poi.commitment
                && left.spent.as_ref().map(|source| source.tx_hash)
                    == right.spent.as_ref().map(|source| source.tx_hash)
                && left.spent.as_ref().map(|source| source.block_number)
                    == right.spent.as_ref().map(|source| source.block_number)
        })
}
