use super::*;

pub(super) async fn fetch_logs_for_range_with_provider(
    provider: &DynProvider,
    contract: Address,
    from_block: u64,
    to_block: u64,
    v2_start_block: u64,
    legacy_shield_block: u64,
) -> Result<Vec<Log>, ChainError> {
    if from_block > to_block {
        return Ok(Vec::new());
    }

    if let Some(event_signatures) = combined_log_event_signatures_for_range(
        from_block,
        to_block,
        v2_start_block,
        legacy_shield_block,
    ) {
        let filter = Filter::new()
            .select(from_block..=to_block)
            .address(contract)
            .event_signature(event_signatures);
        return Ok(provider.get_logs(&filter).await?);
    }

    let mut logs = Vec::new();

    if from_block <= v2_start_block {
        let legacy_end = to_block.min(v2_start_block);
        let legacy_filter = Filter::new()
            .select(from_block..=legacy_end)
            .address(contract)
            .event_signature(vec![
                CommitmentBatch::SIGNATURE_HASH,
                GeneratedCommitmentBatch::SIGNATURE_HASH,
            ]);
        let legacy_logs = provider.get_logs(&legacy_filter).await?;
        logs.extend(legacy_logs);
    }

    if to_block >= v2_start_block {
        let v2_start = from_block.max(v2_start_block);
        let transact_filter = Filter::new()
            .select(v2_start..=to_block)
            .address(contract)
            .event_signature(Transact::SIGNATURE_HASH);
        let transact_logs = provider.get_logs(&transact_filter).await?;
        logs.extend(transact_logs);

        if v2_start <= legacy_shield_block {
            let legacy_shield_end = to_block.min(legacy_shield_block);
            let legacy_shield_filter = Filter::new()
                .select(v2_start..=legacy_shield_end)
                .address(contract)
                .event_signature(ShieldLegacyPreMar23::SIGNATURE_HASH);
            let legacy_shield_logs = provider.get_logs(&legacy_shield_filter).await?;
            logs.extend(legacy_shield_logs);
        }

        if to_block > legacy_shield_block {
            let modern_start = v2_start.max(legacy_shield_block.saturating_add(1));
            let modern_shield_filter = Filter::new()
                .select(modern_start..=to_block)
                .address(contract)
                .event_signature(Shield::SIGNATURE_HASH);
            let modern_shield_logs = provider.get_logs(&modern_shield_filter).await?;
            logs.extend(modern_shield_logs);
        }
    }

    let nullifier_filter = Filter::new()
        .select(from_block..=to_block)
        .address(contract)
        .event_signature(vec![Nullifiers::SIGNATURE_HASH, Nullified::SIGNATURE_HASH]);
    let nullifier_logs = provider.get_logs(&nullifier_filter).await?;
    logs.extend(nullifier_logs);

    Ok(logs)
}

pub(super) fn combined_log_event_signatures_for_range(
    from_block: u64,
    to_block: u64,
    v2_start_block: u64,
    legacy_shield_block: u64,
) -> Option<Vec<FixedBytes<32>>> {
    if v2_start_block > 0 && to_block < v2_start_block {
        return Some(vec![
            CommitmentBatch::SIGNATURE_HASH,
            GeneratedCommitmentBatch::SIGNATURE_HASH,
            Nullifiers::SIGNATURE_HASH,
            Nullified::SIGNATURE_HASH,
        ]);
    }

    if from_block < v2_start_block {
        return None;
    }

    if to_block <= legacy_shield_block {
        return Some(vec![
            Transact::SIGNATURE_HASH,
            ShieldLegacyPreMar23::SIGNATURE_HASH,
            Nullifiers::SIGNATURE_HASH,
            Nullified::SIGNATURE_HASH,
        ]);
    }

    if from_block > legacy_shield_block {
        return Some(vec![
            Transact::SIGNATURE_HASH,
            Shield::SIGNATURE_HASH,
            Nullifiers::SIGNATURE_HASH,
            Nullified::SIGNATURE_HASH,
        ]);
    }

    None
}

pub(super) fn sort_logs(logs: &mut [Log]) {
    logs.sort_by_key(|log| {
        (
            log.block_number.unwrap_or_default(),
            log.log_index.unwrap_or_default(),
        )
    });
}

pub(super) fn anchor_file_name(chain_id: u64, contract: Address, block: u64) -> String {
    format!("forest-{chain_id}-{contract}-anchor-{block}.msgpack")
}

pub(super) fn parse_anchor_block(chain_id: u64, contract: Address, name: &str) -> Option<u64> {
    let prefix = format!("forest-{chain_id}-{contract}-anchor-");
    let suffix = ".msgpack";
    if !name.starts_with(&prefix) || !name.ends_with(suffix) {
        return None;
    }
    let start = prefix.len();
    let end = name.len().saturating_sub(suffix.len());
    name.get(start..end)?.parse::<u64>().ok()
}
