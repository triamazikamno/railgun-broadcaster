use super::*;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct UtxoOutput {
    pub tree: u32,
    pub position: u64,
    pub token: String,
    pub value: String,
    pub commitment_kind: String,
    pub commitment: String,
    pub npk: String,
    pub blinded_commitment: String,
    pub poi_statuses: BTreeMap<String, String>,
    pub poi_spendable: bool,
    pub source_tx_hash: String,
    pub source_block_number: u64,
    pub source_block_timestamp: u64,
    pub is_spent: bool,
    pub spent_tx_hash: Option<String>,
    pub spent_block_number: Option<u64>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TokenTotal {
    pub token: String,
    pub total: String,
    pub poi_verified_total: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ListUtxosOutput {
    pub chain_id: u64,
    pub cache_key: String,
    pub utxo_count: usize,
    pub unspent_count: usize,
    pub spent_count: usize,
    pub utxos: Vec<UtxoOutput>,
    pub totals: Vec<TokenTotal>,
}

#[must_use]
pub fn max_unshield_amount_from_outputs(utxos: &[UtxoOutput], token: Address) -> U256 {
    let planner_utxos = planner_utxos_from_outputs(utxos, token);
    max_unshield_spendable(&planner_utxos, token)
}

#[must_use]
pub fn max_send_amount_from_outputs(utxos: &[UtxoOutput], token: Address) -> U256 {
    let planner_utxos = planner_utxos_from_outputs(utxos, token);
    max_send_spendable(&planner_utxos, token)
}

fn planner_utxos_from_outputs(utxos: &[UtxoOutput], token: Address) -> Vec<Utxo> {
    utxos
        .iter()
        .filter(|row| !row.is_spent)
        .filter(|row| row.poi_spendable)
        .filter_map(|row| {
            let row_token = row.token.parse::<Address>().ok()?;
            if row_token != token {
                return None;
            }
            let value = U256::from_str_radix(&row.value, 10).ok()?;
            if value.is_zero() {
                return None;
            }
            Some(Utxo::new(
                Note::new_unshield(Address::ZERO, token, value),
                row.tree,
                row.position,
                UtxoSource {
                    tx_hash: FixedBytes::ZERO,
                    block_number: row.source_block_number,
                    block_timestamp: row.source_block_timestamp,
                },
                UtxoCommitmentKind::Transact,
            ))
        })
        .collect()
}

#[must_use]
pub(crate) fn utxo_outputs_from_utxos(
    mut utxos: Vec<WalletUtxo>,
) -> (Vec<UtxoOutput>, Vec<TokenTotal>) {
    utxos.sort_by(|a, b| match a.utxo.tree.cmp(&b.utxo.tree) {
        std::cmp::Ordering::Equal => a.utxo.position.cmp(&b.utxo.position),
        other => other,
    });

    let active_poi_list_keys = default_active_poi_list_keys();
    let mut totals_map: BTreeMap<Address, U256> = BTreeMap::new();
    let mut poi_verified_totals_map: BTreeMap<Address, U256> = BTreeMap::new();
    let utxo_outputs = utxos
        .into_iter()
        .map(|wallet_utxo| {
            let utxo = wallet_utxo.utxo;
            let token_addr = utxo.token_address();
            let poi_spendable =
                wallet_utxo.spent.is_none() && utxo.poi.is_valid_for_lists(&active_poi_list_keys);
            if wallet_utxo.spent.is_none() {
                *totals_map.entry(token_addr).or_default() += utxo.note.value;
            }
            if poi_spendable {
                *poi_verified_totals_map.entry(token_addr).or_default() += utxo.note.value;
            }
            let source = &utxo.source;
            let spent = wallet_utxo.spent.as_ref();
            let poi_statuses = poi_statuses_for_output(&utxo, &active_poi_list_keys);

            UtxoOutput {
                tree: utxo.tree,
                position: utxo.position,
                token: token_addr.to_checksum(None),
                value: utxo.note.value.to_string(),
                commitment_kind: commitment_kind_label(utxo.poi.commitment_kind).to_string(),
                commitment: hex::encode_prefixed(utxo.poi.commitment),
                npk: hex::encode_prefixed(utxo.poi.npk),
                blinded_commitment: hex::encode_prefixed(utxo.poi.blinded_commitment),
                poi_statuses,
                poi_spendable,
                source_tx_hash: hex::encode_prefixed(source.tx_hash),
                source_block_number: source.block_number,
                source_block_timestamp: source.block_timestamp,
                is_spent: wallet_utxo.spent.is_some(),
                spent_tx_hash: spent.map(|source| hex::encode_prefixed(source.tx_hash)),
                spent_block_number: spent.map(|source| source.block_number),
            }
        })
        .collect();

    let totals = totals_map
        .into_iter()
        .map(|(addr, total)| TokenTotal {
            token: addr.to_checksum(None),
            total: total.to_string(),
            poi_verified_total: poi_verified_totals_map
                .remove(&addr)
                .unwrap_or_default()
                .to_string(),
        })
        .collect();

    (utxo_outputs, totals)
}

const fn commitment_kind_label(kind: UtxoCommitmentKind) -> &'static str {
    match kind {
        UtxoCommitmentKind::Shield => "Shield",
        UtxoCommitmentKind::Transact => "Transact",
    }
}

const fn poi_status_label(status: PoiStatus) -> &'static str {
    match status {
        PoiStatus::Valid => "Valid",
        PoiStatus::ShieldBlocked => "ShieldBlocked",
        PoiStatus::ProofSubmitted => "ProofSubmitted",
        PoiStatus::Missing => "Missing",
        PoiStatus::Unknown => "Unknown",
    }
}

fn poi_statuses_for_output(
    utxo: &Utxo,
    active_poi_list_keys: &[FixedBytes<32>],
) -> BTreeMap<String, String> {
    let mut statuses = utxo.poi.statuses.clone();
    for list_key in active_poi_list_keys {
        statuses.entry(*list_key).or_insert(PoiStatus::Unknown);
    }
    statuses
        .into_iter()
        .map(|(list_key, status)| (hex::encode(list_key), poi_status_label(status).to_string()))
        .collect()
}
