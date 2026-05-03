use super::*;

pub(crate) struct PublicBroadcasterPreTransactionPois {
    pub(crate) request_pois: PreTransactionPoiMap,
    pub(crate) pending_poi_list_keys: Vec<FixedBytes<32>>,
    pub(crate) pending_pois: PreTransactionPoiMap,
}

pub(crate) async fn public_broadcaster_pre_transaction_pois(
    chunks: &[TransactionPlanChunk],
    broadcaster: &PublicBroadcasterCandidate,
    chain_id: u64,
    prover: &ProverService,
    verify_proof: bool,
    http: &HttpContext,
) -> Result<PublicBroadcasterPreTransactionPois> {
    let required_poi_list_keys = parse_required_poi_list_keys(broadcaster)?;
    let pending_poi_list_keys: Vec<FixedBytes<32>> = default_active_poi_list_keys();
    let all_poi_list_keys = combined_poi_list_keys(&required_poi_list_keys, &pending_poi_list_keys);
    let poi_started = Instant::now();
    let all_pois = generate_pre_transaction_pois_for_lists(
        chunks,
        chain_id,
        prover,
        verify_proof,
        http,
        &all_poi_list_keys,
        "generate public broadcaster pre-transaction POI",
    )
    .await?;
    tracing::info!(
        chain_id,
        chunks = chunks.len(),
        required_list_keys = required_poi_list_keys.len(),
        pending_list_keys = pending_poi_list_keys.len(),
        total_list_keys = all_poi_list_keys.len(),
        elapsed_ms = poi_started.elapsed().as_millis(),
        "generated public broadcaster pre-transaction POIs"
    );
    let pending_pois = retain_pre_transaction_poi_lists(&all_pois, &pending_poi_list_keys);
    Ok(PublicBroadcasterPreTransactionPois {
        request_pois: retain_pre_transaction_poi_lists(&all_pois, &required_poi_list_keys),
        pending_poi_list_keys,
        pending_pois,
    })
}

pub(crate) async fn active_list_pre_transaction_pois(
    chunks: &[TransactionPlanChunk],
    chain_id: u64,
    prover: &ProverService,
    verify_proof: bool,
    http: &HttpContext,
    context: &'static str,
) -> Result<(Vec<FixedBytes<32>>, PreTransactionPoiMap)> {
    let poi_list_keys = default_active_poi_list_keys();
    let pois = generate_pre_transaction_pois_for_lists(
        chunks,
        chain_id,
        prover,
        verify_proof,
        http,
        &poi_list_keys,
        context,
    )
    .await?;
    Ok((poi_list_keys, pois))
}

async fn generate_pre_transaction_pois_for_lists(
    chunks: &[TransactionPlanChunk],
    chain_id: u64,
    prover: &ProverService,
    verify_proof: bool,
    http: &HttpContext,
    poi_list_keys: &[FixedBytes<32>],
    context: &'static str,
) -> Result<PreTransactionPoiMap> {
    if poi_list_keys.is_empty() {
        return Ok(BTreeMap::new());
    }
    let poi_rpc_url =
        Url::parse(DEFAULT_WALLET_POI_RPC_URL).wrap_err("parse default POI RPC URL")?;
    let poi_client = PoiRpcClient::with_http_client(poi_rpc_url, http.client.clone());
    generate_pre_transaction_pois(PreTransactionPoiGenerationRequest {
        chunks,
        chain_type: 0,
        chain_id,
        txid_version: Some(DEFAULT_TXID_VERSION),
        required_poi_list_keys: poi_list_keys,
        poi_client: &poi_client,
        prover,
        verify_proof,
    })
    .await
    .wrap_err(context)
}

fn combined_poi_list_keys(
    first: &[FixedBytes<32>],
    second: &[FixedBytes<32>],
) -> Vec<FixedBytes<32>> {
    let mut out = Vec::with_capacity(first.len() + second.len());
    for key in first.iter().chain(second.iter()) {
        if !out.contains(key) {
            out.push(*key);
        }
    }
    out
}

fn retain_pre_transaction_poi_lists(
    pois: &PreTransactionPoiMap,
    list_keys: &[FixedBytes<32>],
) -> PreTransactionPoiMap {
    list_keys
        .iter()
        .filter_map(|list_key| {
            pois.get(list_key)
                .cloned()
                .map(|per_leaf| (*list_key, per_leaf))
        })
        .collect()
}

#[derive(Clone, Copy)]
pub(crate) struct PendingOutputPoiRolePlan {
    role: PendingOutputPoiRole,
    first_chunk_only: bool,
    required: bool,
    missing_output: &'static str,
}

pub(crate) fn pending_send_output_role_plans(
    include_broadcaster_fee: bool,
) -> Vec<PendingOutputPoiRolePlan> {
    let mut plans = Vec::with_capacity(3);
    if include_broadcaster_fee {
        plans.push(PendingOutputPoiRolePlan {
            role: PendingOutputPoiRole::BroadcasterFee,
            first_chunk_only: true,
            required: true,
            missing_output: "missing public broadcaster send fee output for pending POI",
        });
    }
    plans.push(PendingOutputPoiRolePlan {
        role: PendingOutputPoiRole::Recipient,
        first_chunk_only: false,
        required: true,
        missing_output: "missing send recipient output for pending POI",
    });
    plans.push(PendingOutputPoiRolePlan {
        role: PendingOutputPoiRole::Change,
        first_chunk_only: false,
        required: false,
        missing_output: "missing send change output for pending POI",
    });
    plans
}

pub(crate) fn pending_unshield_output_role_plans(
    include_broadcaster_fee: bool,
) -> Vec<PendingOutputPoiRolePlan> {
    let mut plans = Vec::with_capacity(2);
    if include_broadcaster_fee {
        plans.push(PendingOutputPoiRolePlan {
            role: PendingOutputPoiRole::BroadcasterFee,
            first_chunk_only: true,
            required: true,
            missing_output: "missing public broadcaster unshield fee output for pending POI",
        });
    }
    plans.push(PendingOutputPoiRolePlan {
        role: PendingOutputPoiRole::Change,
        first_chunk_only: false,
        required: false,
        missing_output: "missing unshield change output for pending POI",
    });
    plans
}

pub(crate) fn persist_pending_send_output_poi_contexts(
    db: &DbStore,
    chain_id: u64,
    wallet_id: &str,
    chunks: &[TransactionPlanChunk],
    pre_transaction_pois: &PreTransactionPoiMap,
    poi_list_keys: &[FixedBytes<32>],
    include_broadcaster_fee: bool,
) -> Result<usize> {
    let created_at = now_epoch_secs()?;
    let records = build_pending_output_poi_context_records(
        chain_id,
        wallet_id,
        created_at,
        chunks,
        pre_transaction_pois,
        poi_list_keys,
        &pending_send_output_role_plans(include_broadcaster_fee),
    )?;
    persist_pending_output_poi_context_records(db, &records)
}

pub(crate) fn persist_pending_unshield_output_poi_contexts(
    db: &DbStore,
    chain_id: u64,
    wallet_id: &str,
    chunks: &[TransactionPlanChunk],
    pre_transaction_pois: &PreTransactionPoiMap,
    poi_list_keys: &[FixedBytes<32>],
    include_broadcaster_fee: bool,
) -> Result<usize> {
    let created_at = now_epoch_secs()?;
    let records = build_pending_output_poi_context_records(
        chain_id,
        wallet_id,
        created_at,
        chunks,
        pre_transaction_pois,
        poi_list_keys,
        &pending_unshield_output_role_plans(include_broadcaster_fee),
    )?;
    persist_pending_output_poi_context_records(db, &records)
}

pub(crate) fn build_pending_output_poi_context_records(
    chain_id: u64,
    wallet_id: &str,
    created_at: u64,
    chunks: &[TransactionPlanChunk],
    pre_transaction_pois: &PreTransactionPoiMap,
    poi_list_keys: &[FixedBytes<32>],
    role_plans: &[PendingOutputPoiRolePlan],
) -> Result<Vec<PendingOutputPoiContextRecord>> {
    let mut records = Vec::new();
    for (chunk_index, chunk) in chunks.iter().enumerate() {
        let chunk_context = pending_chunk_context(chunk, pre_transaction_pois, poi_list_keys)?;
        let private_output_count = pending_private_output_count(chunk)?;
        let mut output_index = 0;

        for role_plan in role_plans {
            if role_plan.first_chunk_only && chunk_index != 0 {
                continue;
            }
            if output_index >= private_output_count {
                if role_plan.required {
                    return Err(eyre!(role_plan.missing_output));
                }
                continue;
            }
            let note = chunk
                .outputs
                .get(output_index)
                .ok_or_else(|| eyre!(role_plan.missing_output))?;
            records.push(pending_output_poi_context_record(
                chain_id,
                wallet_id,
                created_at,
                &chunk_context,
                note,
                role_plan.role,
            ));
            output_index += 1;
        }
    }
    Ok(records)
}

struct PendingOutputPoiChunkContext {
    utxo_tree_in: u64,
    railgun_txid: U256,
    pre_transaction_pois: PreTransactionPoiMap,
    poi_list_keys: Vec<FixedBytes<32>>,
}

fn pending_chunk_context(
    chunk: &TransactionPlanChunk,
    pre_transaction_pois: &PreTransactionPoiMap,
    poi_list_keys: &[FixedBytes<32>],
) -> Result<PendingOutputPoiChunkContext> {
    let railgun_txid = chunk.railgun_txid();
    let utxo_tree_in = u64::from(chunk.tree_number);
    let txid_leaf_hash =
        FixedBytes::from(railgun_txid_leaf_hash(railgun_txid, utxo_tree_in).to_be_bytes::<32>());
    let pre_transaction_pois = pre_transaction_pois
        .iter()
        .filter_map(|(list_key, per_leaf)| {
            per_leaf
                .get(&txid_leaf_hash)
                .cloned()
                .map(|poi| (*list_key, BTreeMap::from([(txid_leaf_hash, poi)])))
        })
        .collect::<PreTransactionPoiMap>();

    for list_key in poi_list_keys {
        let has_poi = pre_transaction_pois
            .get(list_key)
            .is_some_and(|per_leaf| per_leaf.contains_key(&txid_leaf_hash));
        if !has_poi {
            return Err(eyre!(
                "missing pending output pre-transaction POI for list key {}",
                hex::encode(list_key)
            ));
        }
    }

    Ok(PendingOutputPoiChunkContext {
        utxo_tree_in,
        railgun_txid,
        pre_transaction_pois,
        poi_list_keys: poi_list_keys.to_vec(),
    })
}

fn pending_private_output_count(chunk: &TransactionPlanChunk) -> Result<usize> {
    if chunk.has_unshield {
        chunk
            .outputs
            .len()
            .checked_sub(1)
            .ok_or_else(|| eyre!("unshield chunk is missing public output"))
    } else {
        Ok(chunk.outputs.len())
    }
}

fn pending_output_poi_context_record(
    chain_id: u64,
    wallet_id: &str,
    created_at: u64,
    chunk_context: &PendingOutputPoiChunkContext,
    note: &Note,
    output_role: PendingOutputPoiRole,
) -> PendingOutputPoiContextRecord {
    PendingOutputPoiContextRecord {
        chain_id,
        wallet_id: wallet_id.to_string(),
        txid_version: DEFAULT_TXID_VERSION.to_string(),
        output_commitment: FixedBytes::from(note.commitment().to_be_bytes::<32>()),
        output_npk: FixedBytes::from(note.npk.to_be_bytes::<32>()),
        utxo_tree_in: chunk_context.utxo_tree_in,
        railgun_txid: chunk_context.railgun_txid,
        txid_merkleroot_index: None,
        pre_transaction_pois_per_txid_leaf_per_list: chunk_context.pre_transaction_pois.clone(),
        required_poi_list_keys: chunk_context.poi_list_keys.clone(),
        output_role,
        created_at,
        source_operation_id: None,
        observation: None,
        submitted_poi_list_keys: Vec::new(),
        terminal_error: None,
    }
}

fn persist_pending_output_poi_context_records(
    db: &DbStore,
    records: &[PendingOutputPoiContextRecord],
) -> Result<usize> {
    for record in records {
        db.put_pending_output_poi_context(record)
            .wrap_err("persist pending output POI context")?;
    }
    Ok(records.len())
}

fn now_epoch_secs() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .wrap_err("system clock is before unix epoch")?
        .as_secs())
}
