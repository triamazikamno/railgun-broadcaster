use super::*;

pub(super) async fn refresh_wallet_poi_statuses_selected(
    client: &dyn PoiStatusReader,
    chain_id: u64,
    active_list_keys: &[FixedBytes<32>],
    wallet_utxos: &mut [WalletUtxo],
    selection: WalletPoiRefreshSelection,
) -> bool {
    if active_list_keys.is_empty() {
        return false;
    }

    let started = Instant::now();
    let selection_label = selection.as_str();
    let unspent: Vec<_> = wallet_utxos
        .iter()
        .enumerate()
        .filter(|(_, wallet_utxo)| {
            !wallet_utxo.is_spent() && selection.matches_wallet_utxo(wallet_utxo, active_list_keys)
        })
        .map(|(index, wallet_utxo)| {
            (
                index,
                BlindedCommitmentData::new(
                    wallet_utxo.utxo.poi.blinded_commitment,
                    blinded_commitment_type(wallet_utxo.utxo.poi.commitment_kind),
                ),
            )
        })
        .collect();

    debug!(
        chain_id,
        selection = selection_label,
        list_keys = active_list_keys.len(),
        commitments = unspent.len(),
        batch_size = WALLET_POI_STATUS_BATCH_SIZE,
        "wallet POI status refresh started"
    );
    let mut status_changes = 0usize;
    for (chunk_index, chunk) in unspent.chunks(WALLET_POI_STATUS_BATCH_SIZE).enumerate() {
        let request_data: Vec<_> = chunk.iter().map(|(_, data)| *data).collect();
        let chunk_started = Instant::now();
        match client
            .pois_per_list(
                DEFAULT_TXID_VERSION,
                EVM_CHAIN_TYPE,
                chain_id,
                active_list_keys,
                &request_data,
            )
            .await
        {
            Ok(statuses_by_blinded_commitment) => {
                let chunk_elapsed_ms = chunk_started.elapsed().as_millis();
                let refreshed_at = now_epoch_secs();
                for (index, data) in chunk {
                    let Some(wallet_utxo) = wallet_utxos.get_mut(*index) else {
                        continue;
                    };
                    status_changes += wallet_utxo.utxo.poi.apply_status_refresh(
                        active_list_keys,
                        statuses_by_blinded_commitment.get(&data.blinded_commitment),
                        refreshed_at,
                    );
                }
                debug!(
                    chain_id,
                    selection = selection_label,
                    chunk_index,
                    commitments = chunk.len(),
                    returned_commitments = statuses_by_blinded_commitment.len(),
                    elapsed_ms = chunk_elapsed_ms,
                    "wallet POI status chunk complete"
                );
            }
            Err(error) => {
                let chunk_elapsed_ms = chunk_started.elapsed().as_millis();
                warn!(
                    ?error,
                    chain_id,
                    commitments = chunk.len(),
                    chunk_index,
                    elapsed_ms = chunk_elapsed_ms,
                    "wallet POI status chunk failed; leaving statuses unknown"
                );
                for (index, _) in chunk {
                    let Some(wallet_utxo) = wallet_utxos.get_mut(*index) else {
                        continue;
                    };
                    status_changes += wallet_utxo
                        .utxo
                        .poi
                        .mark_statuses_unknown_for_lists(active_list_keys);
                }
            }
        }
    }
    let changed = status_changes > 0;
    debug!(
        chain_id,
        selection = selection_label,
        commitments = unspent.len(),
        status_changes,
        changed,
        elapsed_ms = started.elapsed().as_millis(),
        "wallet POI status refresh complete"
    );
    changed
}

#[derive(Debug, Default)]
pub(crate) struct LivePoiTailOutcome {
    pub(crate) events: usize,
    pub(crate) pages: usize,
    pub(crate) start_index: u64,
    pub(crate) next_event_index: u64,
}

#[derive(Debug, Error)]
pub(crate) enum LivePoiTailError {
    #[error("live POI tail request failed")]
    Rpc(#[from] PoiRpcError),
    #[error("live POI event signature verification failed")]
    Verify(#[from] poi::artifacts::VerifyError),
    #[error("live POI cache update failed")]
    Cache(#[from] PoiCacheError),
    #[error("live POI event index mismatch: expected {expected}, got {actual}")]
    EventIndexMismatch { expected: u64, actual: u64 },
    #[error("live POI event range overflow")]
    RangeOverflow,
    #[error("invalid hex in {field}: {value}")]
    InvalidHex { field: &'static str, value: String },
    #[error("{field} has {actual} bytes, expected {expected}")]
    InvalidByteLen {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("live POI root missing for tree {tree_number}")]
    MissingRoot { tree_number: u32 },
    #[error("live POI root mismatch for tree {tree_number}: expected {expected}, got {actual}")]
    RootMismatch {
        tree_number: u32,
        expected: String,
        actual: String,
    },
}

pub(crate) async fn sync_live_poi_event_tail(
    client: &PoiRpcClient,
    cache: &mut PoiCache,
) -> Result<LivePoiTailOutcome, LivePoiTailError> {
    let identity = cache.identity().clone();
    let mut outcome = LivePoiTailOutcome {
        start_index: cache.progress().next_event_index,
        next_event_index: cache.progress().next_event_index,
        ..LivePoiTailOutcome::default()
    };
    if outcome.next_event_index == 0 {
        return Ok(outcome);
    }

    loop {
        let start_index = outcome.next_event_index;
        let end_index = start_index
            .checked_add(POI_EVENTS_PAGE_SIZE - 1)
            .ok_or(LivePoiTailError::RangeOverflow)?;
        let events = client
            .poi_events(
                &identity.txid_version,
                identity.chain_type,
                identity.chain_id,
                &identity.list_key,
                start_index,
                end_index,
            )
            .await?;
        if events.is_empty() {
            break;
        }
        let returned = events.len();
        apply_live_poi_events(cache, &identity.list_key, start_index, &events)?;
        outcome.events += returned;
        outcome.pages += 1;
        outcome.next_event_index = cache.progress().next_event_index;
        if returned < POI_EVENTS_PAGE_SIZE as usize {
            break;
        }
    }

    Ok(outcome)
}

pub(super) fn apply_live_poi_events(
    cache: &mut PoiCache,
    list_key: &FixedBytes<32>,
    start_index: u64,
    events: &[PoiSyncedListEvent],
) -> Result<(), LivePoiTailError> {
    let mut expected_index = start_index;
    let mut snapshot_events = Vec::with_capacity(events.len());
    let mut expected_roots = BTreeMap::new();
    let list_key_bytes = fixed_bytes(list_key);
    for event in events {
        if event.signed_poi_event.index != expected_index {
            return Err(LivePoiTailError::EventIndexMismatch {
                expected: expected_index,
                actual: event.signed_poi_event.index,
            });
        }
        verify_poi_event(&event.signed_poi_event, &list_key_bytes)?;
        let blinded_commitment = decode_hex_array::<32>(
            "signedPOIEvent.blindedCommitment",
            &event.signed_poi_event.blinded_commitment,
        )?;
        let signature = decode_hex_array::<64>(
            "signedPOIEvent.signature",
            &event.signed_poi_event.signature,
        )?;
        let (tree_number, _) = normalize_tree_position(0, event.signed_poi_event.index);
        expected_roots.insert(
            tree_number,
            decode_hex_array::<32>("validatedMerkleroot", &event.validated_merkleroot)?,
        );
        snapshot_events.push(SnapshotEvent {
            event_index: event.signed_poi_event.index,
            blinded_commitment,
            signature,
            event_type: event.signed_poi_event.event_type,
        });
        expected_index = expected_index
            .checked_add(1)
            .ok_or(LivePoiTailError::RangeOverflow)?;
    }
    cache.apply_verified_artifact_events(&snapshot_events)?;
    let actual_roots = cache.current_roots();
    for (tree_number, expected_root) in expected_roots {
        let actual_root = actual_roots
            .get(&tree_number)
            .ok_or(LivePoiTailError::MissingRoot { tree_number })?;
        if *actual_root != expected_root {
            return Err(LivePoiTailError::RootMismatch {
                tree_number,
                expected: hex::encode_prefixed(expected_root),
                actual: hex::encode_prefixed(actual_root),
            });
        }
    }
    cache.accept_current_roots();
    Ok(())
}

pub(super) fn decode_hex_array<const N: usize>(
    field: &'static str,
    value: &str,
) -> Result<[u8; N], LivePoiTailError> {
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value)).map_err(|_| {
        LivePoiTailError::InvalidHex {
            field,
            value: value.to_string(),
        }
    })?;
    let actual = bytes.len();
    bytes
        .try_into()
        .map_err(|_| LivePoiTailError::InvalidByteLen {
            field,
            expected: N,
            actual,
        })
}

pub(super) fn fixed_bytes<const N: usize>(value: &FixedBytes<N>) -> [u8; N] {
    let mut bytes = [0_u8; N];
    bytes.copy_from_slice(value.as_slice());
    bytes
}
