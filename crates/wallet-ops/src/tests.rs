use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use alloy::hex;
use alloy::primitives::{Address, Bytes, FixedBytes, TxHash, U256};
use alloy::uint;
use broadcaster_core::crypto::railgun::{Address as RailgunAddress, AddressData, ViewingKeyData};
use broadcaster_core::notes::Note;
use broadcaster_core::transact::{
    EncryptedTransactRequest, PreTxPoi, SnarkJsProof, railgun_txid_leaf_hash,
    try_decrypt_transact_request,
};
use broadcaster_core::transact_response::DecryptedTransactResponse;
use broadcaster_core::tree::TREE_DEPTH;
use broadcaster_monitor::FeeRow;
use local_db::{DbConfig, DbStore, PendingOutputPoiRole};
use merkletree::tree::MerkleProof;
use poi::poi::default_active_poi_list_keys;
use railgun_wallet::tx::{
    BuildError, InputWitness, PrivateInputs, PublicInputs, TransactionCall, TransactionPlanChunk,
    UnshieldPlan, UnshieldSelectionInfo,
};
use railgun_wallet::{PoiStatus, Utxo, UtxoCommitmentKind, UtxoSource, WalletKeys, WalletUtxo};
use serde_json::json;
use sync_service::ChainConfigDefaults;

use super::hardware::{HardwareDerivationDescriptor, HardwareWalletSyncIntent, parse_bip32_path};
use super::signer::{EvmMessageSigner, EvmTransactionSigner, SoftwareEvmSigner};
use super::{
    ApproximateTransactionShape, BlockedShieldRescueUtxoId, BroadcasterFeePolicy,
    BroadcasterFeePolicyStatus, DesktopWalletChainStart, DesktopWalletSyncStartPolicy,
    FeeHandlingMode, ListUtxosOutput, PublicBroadcasterCandidate, PublicBroadcasterFeeMargin,
    PublicBroadcasterResultKind, PublicBroadcasterSelection, PublicBroadcasterTrustFilter,
    RAILGUN_UNSHIELD_PROTOCOL_FEE_BPS, SelfBroadcastFeeSample, SelfBroadcastGasFeeQuote,
    SelfBroadcastGasFeeSelection, SelfBroadcastTipFallback, TokenTotal, UtxoOutput,
    WalletPendingOverlay, WalletPendingSpent, apply_pending_overlay_to_outputs,
    approximate_public_broadcaster_cost, approximate_public_broadcaster_gas,
    broadcaster_fee_amount, broadcaster_fee_covers, buffered_public_broadcaster_fee,
    decode_public_broadcaster_response, eligible_public_broadcasters,
    fee_policy_eligible_public_broadcasters, filter_public_broadcasters_by_trust,
    fixed_token_anchor_rate, initial_separate_token_public_broadcaster_fee,
    is_self_broadcast_insufficient_native_gas_error, is_self_broadcast_tx_already_known_message,
    is_wrapped_native_token, max_broadcaster_fee_token_amount_from_outputs,
    max_send_amount_from_outputs, max_unshield_amount_from_outputs, parse_railgun_recipient,
    parse_send_amount, parse_submitted_tx_hash, parse_unshield_amount,
    public_broadcaster_amount_split, public_broadcaster_amount_split_for_tokens,
    public_broadcaster_amount_split_for_tokens_and_protocol,
    public_broadcaster_anchor_rate_for_policy, public_broadcaster_build_error,
    public_broadcaster_candidates, public_broadcaster_fee_breakdown,
    public_broadcaster_gas_limit_with_buffer, public_broadcaster_max_entered_amount,
    public_broadcaster_max_entered_amount_for_tokens,
    public_broadcaster_max_entered_amount_for_tokens_and_protocol,
    public_broadcaster_republish_loop, public_broadcaster_transact_params,
    resolve_desktop_wallet_chain_start, resolve_self_broadcast_gas_fee, select_public_broadcaster,
    select_public_broadcaster_with_policy, select_public_broadcaster_with_policy_and_trust,
    self_broadcast_gas_limit_with_buffer, self_broadcast_insufficient_native_gas_error,
    self_broadcast_native_gas_cost, self_broadcast_quote_from_fee_samples,
    self_broadcast_quote_from_fee_samples_with_tip_fallback, self_broadcast_transaction_request,
    send_approximate_shape, sort_specific_public_broadcasters, transact_topic,
    unshield_approximate_shape, utxo_outputs_from_utxos, validate_self_broadcast_gas_fee, vault,
    wrapped_native_token_for_chain,
};

static TEMP_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

fn address(byte: u8) -> Address {
    Address::from_slice(&[byte; 20])
}

fn temp_db_root() -> PathBuf {
    let dir = std::env::temp_dir().join("railgun-broadcaster-wallet-ops-tests");
    fs::create_dir_all(&dir).expect("create temp db dir");
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let counter = TEMP_DB_COUNTER.fetch_add(1, Ordering::Relaxed);
    dir.join(format!("db-{pid}-{nanos}-{counter}"))
}

fn source(byte: u8) -> UtxoSource {
    UtxoSource {
        tx_hash: FixedBytes::from([byte; 32]),
        block_number: u64::from(byte),
        block_timestamp: 1_700_000_000 + u64::from(byte),
    }
}

fn hardware_wallet_metadata(sync_intent: HardwareWalletSyncIntent) -> vault::WalletMetadataBundle {
    let descriptor = HardwareDerivationDescriptor::ledger_eip1024_v1(
        parse_bip32_path("m/44'/60'/0'/0/0").expect("valid path"),
        0,
        "ledger:evm:0x1111111111111111111111111111111111111111".to_string(),
        sync_intent,
    );
    vault::WalletMetadataBundle {
        wallet_uuid: "hardware-wallet".to_string(),
        label: "Hardware wallet".to_string(),
        derivation_index: descriptor.account_index,
        source: vault::WalletSource::LedgerDerived,
        status: vault::WalletStatus::Active,
        display_order: 0,
        hardware_descriptor: Some(descriptor),
        hardware_account: None,
    }
}

fn selection_info(
    total: U256,
    input_count: usize,
    transaction_count: usize,
    private_output_count: usize,
    public_output_count: usize,
    max_spendable: U256,
) -> UnshieldSelectionInfo {
    UnshieldSelectionInfo {
        total,
        input_count,
        transaction_count,
        private_output_count,
        public_output_count,
        max_spendable,
    }
}

fn sample_railgun_address(seed: u8) -> String {
    let viewing = ViewingKeyData::from_spending_public_key(
        [seed; 32],
        [U256::from(seed), U256::from(seed + 1)],
    );
    viewing
        .derive_address(None)
        .expect("derive railgun address")
        .to_string()
}

fn sample_public_broadcaster_candidate(seed: u8) -> (PublicBroadcasterCandidate, ViewingKeyData) {
    let viewing = ViewingKeyData::from_spending_public_key(
        [seed; 32],
        [U256::from(seed), U256::from(seed + 1)],
    );
    let railgun_address = viewing.derive_address(None).expect("derive address");
    let address_data = AddressData::try_from(&RailgunAddress::from(railgun_address.as_ref()))
        .expect("address data");
    (
        PublicBroadcasterCandidate {
            chain_id: 1,
            railgun_address: railgun_address.to_string(),
            identifier: None,
            token: address(0x33),
            fee: uint!(10_U256),
            fees_id: "fees-id".to_string(),
            fee_expiration: SystemTime::now() + Duration::from_mins(1),
            reliability: 0.9,
            available_wallets: 1,
            version: "8.2.3".to_string(),
            relay_adapt: address(0x44),
            relay_adapt_7702: None,
            required_poi_list_keys: Vec::new(),
            viewing_public_key: address_data.viewing_public_key,
            address_data,
            fee_policy_status: BroadcasterFeePolicyStatus::UnknownAnchor,
        },
        viewing,
    )
}

fn sample_pre_tx_poi(byte: u8) -> PreTxPoi {
    PreTxPoi {
        snark_proof: SnarkJsProof {
            pi_a: [U256::from(byte), U256::from(byte + 1)],
            pi_b: [
                [U256::from(byte + 2), U256::from(byte + 3)],
                [U256::from(byte + 4), U256::from(byte + 5)],
            ],
            pi_c: [U256::from(byte + 6), U256::from(byte + 7)],
        },
        txid_merkleroot: FixedBytes::from([byte; 32]),
        poi_merkleroots: vec![FixedBytes::from([byte + 1; 32])],
        blinded_commitments_out: vec![FixedBytes::from([byte + 2; 32])],
        railgun_txid_if_has_unshield: Bytes::copy_from_slice(&[0_u8]),
    }
}

#[test]
fn desktop_wallet_start_policy_generated_uses_safe_head_no_backfill() {
    let resolved = resolve_desktop_wallet_chain_start(
        DesktopWalletSyncStartPolicy::CurrentSafeHeadNoBackfill,
        None,
        None,
        100,
        Some(250),
        false,
    )
    .expect("resolve generated start");

    assert_eq!(
        resolved,
        DesktopWalletChainStart {
            start_block: 251,
            last_scanned_block: 250,
        }
    );
}

#[test]
fn desktop_wallet_start_policy_imported_uses_deployment_block() {
    let resolved = resolve_desktop_wallet_chain_start(
        DesktopWalletSyncStartPolicy::ImportedHistoricalBackfill,
        None,
        None,
        100,
        Some(250),
        false,
    )
    .expect("resolve imported start");

    assert_eq!(
        resolved,
        DesktopWalletChainStart {
            start_block: 100,
            last_scanned_block: 99,
        }
    );
}

#[test]
fn desktop_wallet_start_policy_new_hardware_uses_safe_head_no_backfill() {
    let metadata = hardware_wallet_metadata(HardwareWalletSyncIntent::CreateNew);
    assert_eq!(
        DesktopWalletSyncStartPolicy::from(&metadata),
        DesktopWalletSyncStartPolicy::CurrentSafeHeadNoBackfill
    );

    let resolved = resolve_desktop_wallet_chain_start(
        DesktopWalletSyncStartPolicy::from(&metadata),
        None,
        None,
        100,
        Some(250),
        false,
    )
    .expect("resolve new hardware start");

    assert_eq!(
        resolved,
        DesktopWalletChainStart {
            start_block: 251,
            last_scanned_block: 250,
        }
    );
}

#[test]
fn desktop_wallet_start_policy_recovered_hardware_uses_deployment_block() {
    let metadata = hardware_wallet_metadata(HardwareWalletSyncIntent::RecoverExisting);
    assert_eq!(
        DesktopWalletSyncStartPolicy::from(&metadata),
        DesktopWalletSyncStartPolicy::ImportedHistoricalBackfill
    );

    let resolved = resolve_desktop_wallet_chain_start(
        DesktopWalletSyncStartPolicy::from(&metadata),
        None,
        None,
        100,
        Some(250),
        false,
    )
    .expect("resolve recovered hardware start");

    assert_eq!(
        resolved,
        DesktopWalletChainStart {
            start_block: 100,
            last_scanned_block: 99,
        }
    );
}

#[test]
fn chain_config_uses_effective_rpc_pool_and_sync_tuning() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build runtime");
    let root_dir = temp_db_root();
    let http = runtime
        .block_on(super::build_wallet_network_context(
            super::WalletNetworkConfig {
                network_mode: Some(super::WalletNetworkMode::Direct),
                proxy: None,
                data_dir: &root_dir,
            },
        ))
        .expect("direct HTTP context");
    let defaults = ChainConfigDefaults::for_chain(1).expect("ethereum defaults");
    let effective = super::settings::EffectiveChainConfig {
        chain_id: 1,
        enabled: true,
        rpc_endpoints: vec![
            "https://rpc-a.example".to_string(),
            "https://rpc-b.example".to_string(),
        ],
        archive_rpc_url: Some("https://archive.example".to_string()),
        quick_sync_enabled: false,
        quick_sync_endpoint: Some("https://quick.example/graphql".to_string()),
        indexed_wallet_block_range: 12_345,
        deployment_block: 12_000,
        v2_start_block: 13_000,
        legacy_shield_block: 14_000,
        archive_until_block: 12_500,
        railgun_contract: defaults.contract.to_string(),
        relay_adapt_contract: defaults.relay_adapt_contract.to_string(),
        relay_adapt_7702_contract: defaults.relay_adapt_7702_contract.to_string(),
        wrapped_native_token: wrapped_native_token_for_chain(1).map(|token| token.to_string()),
        multicall_contract: defaults.multicall_contract.to_string(),
        finality_depth: 99,
        block_range: Some(2_000),
        poll_interval_secs: Some(30),
        gas: super::settings::EffectiveChainGasSettings {
            gas_limit_buffer: 250_000,
            gas_price_buffer_numerator: 110,
            gas_price_buffer_denominator: 100,
        },
    };

    let cfg = super::chain_config(
        &defaults,
        Some(reqwest::Url::parse("https://ignored.example").expect("url")),
        Some(&effective),
        &http,
        None,
    )
    .expect("chain config");

    assert_eq!(cfg.quick_sync_endpoint, None);
    assert_eq!(cfg.indexed_wallet_block_range, 12_345);
    assert_eq!(cfg.finality_depth, 99);
    assert_eq!(cfg.block_range, 2_000);
    assert_eq!(cfg.poll_interval, Duration::from_secs(30));
    assert_eq!(
        cfg.archive_rpc_url.as_ref().map(reqwest::Url::as_str),
        Some("https://archive.example/")
    );
    assert_eq!(cfg.deployment_block, 12_000);
    assert_eq!(cfg.v2_start_block, 13_000);
    assert_eq!(cfg.legacy_shield_block, 14_000);
    assert_eq!(cfg.archive_until_block, 12_500);

    let first = cfg.rpcs.random_provider().expect("first provider");
    cfg.rpcs.mark_bad_provider(&first);
    let second = cfg.rpcs.random_provider().expect("fallback provider");
    assert_ne!(first.url, second.url);

    drop(http);
    let _ = fs::remove_dir_all(root_dir);
}

#[test]
fn desktop_wallet_start_policy_reuses_existing_metadata() {
    let existing = super::vault::WalletChainMetadataBundle {
        wallet_chain_uuid: "wallet-chain".to_string(),
        wallet_uuid: "wallet".to_string(),
        chain_type: 0,
        chain_id: 1,
        contract: "0x1111111111111111111111111111111111111111".to_string(),
        start_block: 251,
        last_scanned_block: 300,
        last_scanned_block_hash: None,
        poi_read_source: None,
    };

    let resolved = resolve_desktop_wallet_chain_start(
        DesktopWalletSyncStartPolicy::CurrentSafeHeadNoBackfill,
        Some(&existing),
        None,
        100,
        None,
        false,
    )
    .expect("resolve existing start");

    assert_eq!(
        resolved,
        DesktopWalletChainStart {
            start_block: 251,
            last_scanned_block: 300,
        }
    );
}

#[test]
fn desktop_wallet_start_policy_generated_requires_safe_head() {
    let error = resolve_desktop_wallet_chain_start(
        DesktopWalletSyncStartPolicy::CurrentSafeHeadNoBackfill,
        None,
        None,
        100,
        None,
        false,
    )
    .expect_err("safe head required");

    assert!(error.to_string().contains("safe head unavailable"));
}

#[test]
fn desktop_wallet_rewind_uses_explicit_init_block() {
    let existing = super::vault::WalletChainMetadataBundle {
        wallet_chain_uuid: "wallet-chain".to_string(),
        wallet_uuid: "wallet".to_string(),
        chain_type: 0,
        chain_id: 1,
        contract: "0x1111111111111111111111111111111111111111".to_string(),
        start_block: 251,
        last_scanned_block: 300,
        last_scanned_block_hash: None,
        poi_read_source: None,
    };

    let resolved = resolve_desktop_wallet_chain_start(
        DesktopWalletSyncStartPolicy::CurrentSafeHeadNoBackfill,
        Some(&existing),
        Some(existing.start_block),
        100,
        None,
        true,
    )
    .expect("resolve explicit rewind start");

    assert_eq!(
        resolved,
        DesktopWalletChainStart {
            start_block: existing.start_block,
            last_scanned_block: existing.start_block.saturating_sub(1),
        }
    );
}

fn sample_poi_map(
    list_keys: &[FixedBytes<32>],
    txid_leaf_hashes: &[FixedBytes<32>],
) -> BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PreTxPoi>> {
    list_keys
        .iter()
        .enumerate()
        .map(|(list_index, list_key)| {
            let per_leaf = txid_leaf_hashes
                .iter()
                .enumerate()
                .map(|(leaf_index, leaf)| {
                    (
                        *leaf,
                        sample_pre_tx_poi(10 + (list_index * 4 + leaf_index) as u8),
                    )
                })
                .collect();
            (*list_key, per_leaf)
        })
        .collect()
}

fn sample_note(seed: u8, token: Address, value: u64) -> Note {
    Note::new_change(U256::from(seed), token, U256::from(value), [seed; 16])
}

fn sample_chunk(
    tree_number: u32,
    bound_seed: u8,
    outputs: Vec<Note>,
    has_unshield: bool,
) -> TransactionPlanChunk {
    TransactionPlanChunk {
        tree_number,
        merkle_root: U256::from(bound_seed),
        inputs: Vec::new(),
        public_inputs: PublicInputs {
            merkle_root: U256::from(bound_seed),
            bound_params_hash: U256::from(bound_seed + 1),
            nullifiers: Vec::new(),
            commitments_out: outputs.iter().map(Note::commitment).collect(),
        },
        private_inputs: PrivateInputs {
            token_address: U256::from(bound_seed + 2),
            random_in: Vec::new(),
            value_in: Vec::new(),
            path_elements: Vec::new(),
            leaves_indices: Vec::new(),
            value_out: outputs.iter().map(|note| note.value).collect(),
            public_key: [U256::from(bound_seed + 3), U256::from(bound_seed + 4)],
            npk_out: outputs.iter().map(|note| note.npk).collect(),
            nullifying_key: U256::from(bound_seed + 5),
        },
        outputs,
        has_unshield,
        signature: [U256::ZERO; 3],
    }
}

fn poi_map_for_chunks(
    list_keys: &[FixedBytes<32>],
    chunks: &[TransactionPlanChunk],
) -> BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PreTxPoi>> {
    let leaves = chunks
        .iter()
        .map(|chunk| {
            FixedBytes::from(
                railgun_txid_leaf_hash(chunk.railgun_txid(), u64::from(chunk.tree_number))
                    .to_be_bytes::<32>(),
            )
        })
        .collect::<Vec<_>>();
    sample_poi_map(list_keys, &leaves)
}

fn fee_row(chain_id: u64, token: Address, fee: u64, reliability: f64, fees_id: &str) -> FeeRow {
    fee_row_with_broadcaster_seed(chain_id, token, fee, reliability, fees_id, 7)
}

fn fee_row_with_broadcaster_seed(
    chain_id: u64,
    token: Address,
    fee: u64,
    reliability: f64,
    fees_id: &str,
    broadcaster_seed: u8,
) -> FeeRow {
    FeeRow {
        chain_id,
        railgun_address: Arc::from(sample_railgun_address(broadcaster_seed)),
        token_address: token,
        fee: U256::from(fee),
        signature_valid: true,
        fees_id: Arc::from(fees_id),
        fee_expiration: SystemTime::now() + Duration::from_mins(1),
        available_wallets: 1,
        version: Arc::from("8.2.3"),
        relay_adapt: address(0x44),
        relay_adapt_7702: None,
        required_poi_list_keys: Vec::new(),
        identifier: None,
        last_seen: SystemTime::now(),
        reliability,
    }
}

fn broadcaster_preference_entry(seed: u8) -> vault::BroadcasterPreferenceEntry {
    vault::BroadcasterPreferenceEntry {
        address: sample_railgun_address(seed),
    }
}

fn utxo_with_kind(
    token: Address,
    value: u64,
    tree: u32,
    position: u64,
    commitment_kind: UtxoCommitmentKind,
) -> WalletUtxo {
    let mut wallet_utxo = WalletUtxo::new(Utxo::new(
        Note::new_unshield(Address::ZERO, token, U256::from(value)),
        tree,
        position,
        source(position as u8 + 1),
        commitment_kind,
    ));
    for list_key in default_active_poi_list_keys() {
        wallet_utxo
            .utxo
            .poi
            .statuses
            .insert(list_key, PoiStatus::Valid);
    }
    wallet_utxo
}

fn utxo(token: Address, value: u64, tree: u32, position: u64) -> WalletUtxo {
    utxo_with_kind(token, value, tree, position, UtxoCommitmentKind::Transact)
}

fn blocked_shield_utxo(token: Address, value: u64, tree: u32, position: u64) -> WalletUtxo {
    let mut wallet_utxo = utxo_with_kind(token, value, tree, position, UtxoCommitmentKind::Shield);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(default_active_poi_list_keys()[0], PoiStatus::ShieldBlocked);
    wallet_utxo
}

fn rescue_utxo_id(wallet_utxo: &WalletUtxo) -> BlockedShieldRescueUtxoId {
    BlockedShieldRescueUtxoId {
        tree: wallet_utxo.utxo.tree,
        position: wallet_utxo.utxo.position,
        commitment: wallet_utxo.utxo.poi.commitment,
        blinded_commitment: wallet_utxo.utxo.poi.blinded_commitment,
    }
}

fn public_account(
    uuid: &str,
    address: Address,
    status: super::vault::PublicAccountStatus,
) -> super::vault::PublicAccountMetadata {
    super::vault::PublicAccountMetadata {
        public_account_uuid: uuid.to_string(),
        address,
        label: Some(format!("Account {uuid}")),
        source: super::vault::PublicAccountSource::Imported,
        scope: super::vault::PublicAccountScope::Global,
        derivation_index: None,
        hardware_descriptor: None,
        status,
        display_order: 0,
    }
}

fn rescue_plan_for_test(
    utxo: &Utxo,
    token: Address,
    amount: U256,
    origin: Address,
    extra_input: Option<Utxo>,
    change_value: Option<U256>,
) -> UnshieldPlan {
    let mut inputs = vec![InputWitness {
        utxo: utxo.clone(),
        merkle_proof: MerkleProof {
            root: U256::ZERO,
            leaf: U256::ZERO,
            leaf_index: utxo.position,
            path_elements: [U256::ZERO; TREE_DEPTH],
            path_indices: [0; TREE_DEPTH],
        },
    }];
    if let Some(extra) = extra_input {
        inputs.push(InputWitness {
            utxo: extra,
            merkle_proof: MerkleProof {
                root: U256::ZERO,
                leaf: U256::ZERO,
                leaf_index: 0,
                path_elements: [U256::ZERO; TREE_DEPTH],
                path_indices: [0; TREE_DEPTH],
            },
        });
    }

    let unshield_note = Note::new_unshield(origin, token, amount);
    let change_note = change_value.map(|value| Note::new_change(U256::ZERO, token, value, [1; 16]));
    let mut outputs = Vec::new();
    if let Some(change) = change_note.clone() {
        outputs.push(change);
    }
    outputs.push(unshield_note.clone());
    let public_inputs = PublicInputs {
        merkle_root: U256::ZERO,
        bound_params_hash: U256::ZERO,
        nullifiers: Vec::new(),
        commitments_out: outputs.iter().map(Note::commitment).collect(),
    };
    let private_inputs = PrivateInputs {
        token_address: U256::from_be_slice(token.as_slice()),
        random_in: Vec::new(),
        value_in: Vec::new(),
        path_elements: Vec::new(),
        leaves_indices: Vec::new(),
        value_out: outputs.iter().map(|note| note.value).collect(),
        public_key: [U256::ZERO; 2],
        npk_out: outputs.iter().map(|note| note.npk).collect(),
        nullifying_key: U256::ZERO,
    };
    let chunk = TransactionPlanChunk {
        tree_number: utxo.tree,
        merkle_root: U256::ZERO,
        inputs: inputs.clone(),
        outputs: outputs.clone(),
        has_unshield: true,
        public_inputs: public_inputs.clone(),
        private_inputs: private_inputs.clone(),
        signature: [U256::ZERO; 3],
    };
    UnshieldPlan {
        call: TransactionCall {
            to: Address::ZERO,
            data: Bytes::new(),
        },
        tree_number: utxo.tree,
        merkle_root: U256::ZERO,
        inputs,
        outputs,
        chunks: vec![chunk],
        broadcaster_fee_note: None,
        unshield_note,
        unshield_notes: vec![Note::new_unshield(origin, token, amount)],
        change_note,
        public_inputs,
        private_inputs,
        signature: [U256::ZERO; 3],
    }
}

fn spent_utxo(token: Address, value: u64, tree: u32, position: u64) -> WalletUtxo {
    let mut wallet_utxo = utxo(token, value, tree, position);
    wallet_utxo.spent = Some(source(9));
    wallet_utxo
}

#[test]
fn poi_verified_unspent_utxos_filter_planner_inputs() {
    let token = address(0x11);
    let valid = utxo(token, 5, 0, 1);
    let mut unknown = utxo(token, 100, 0, 2);
    unknown.utxo.poi.statuses.clear();
    let mut blocked = utxo(token, 7, 0, 3);
    blocked
        .utxo
        .poi
        .statuses
        .insert(default_active_poi_list_keys()[0], PoiStatus::ShieldBlocked);
    let spent = spent_utxo(token, 9, 0, 4);

    let selected = super::poi_verified_unspent_utxos_from_records(
        &[valid, unknown, blocked, spent],
        &WalletPendingOverlay::default(),
    );

    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].note.value, uint!(5_U256));
}

#[test]
fn pending_spent_utxos_filter_planner_inputs() {
    let token = address(0x11);
    let valid = utxo(token, 5, 0, 1);
    let pending = WalletPendingOverlay {
        pending_spent: vec![WalletPendingSpent {
            tree: 0,
            position: 1,
            tx_hash: Some(FixedBytes::from([0x99; 32])),
            block_number: Some(20),
            block_timestamp: Some(1_700_000_020),
        }],
        ..WalletPendingOverlay::default()
    };

    let selected = super::poi_verified_unspent_utxos_from_records(&[valid], &pending);

    assert!(selected.is_empty());
}

#[test]
fn blocked_shield_rescue_eligibility_accepts_matched_origin_account() {
    let token = address(0x11);
    let origin = address(0xaa);
    let blocked = blocked_shield_utxo(token, 5, 0, 1);
    let id = rescue_utxo_id(&blocked);
    let candidate = super::blocked_shield_rescue_candidate_from_records(
        &[blocked],
        &WalletPendingOverlay::default(),
        &id,
    );
    let eligibility = super::blocked_shield_rescue_eligibility_for_origin(
        Some(origin),
        &[public_account(
            "pub-1",
            origin,
            super::vault::PublicAccountStatus::Active,
        )],
    );

    assert!(candidate.is_some());
    assert!(eligibility.eligible);
    assert_eq!(eligibility.origin_address, Some(origin));
    assert_eq!(eligibility.public_account_uuid.as_deref(), Some("pub-1"));
    assert!(eligibility.disabled_reason.is_none());
}

#[test]
fn blocked_shield_rescue_eligibility_requires_origin_account() {
    let origin = address(0xaa);

    let missing = super::blocked_shield_rescue_eligibility_for_origin(Some(origin), &[]);
    let inactive = super::blocked_shield_rescue_eligibility_for_origin(
        Some(origin),
        &[public_account(
            "pub-1",
            origin,
            super::vault::PublicAccountStatus::Inactive,
        )],
    );

    assert!(!missing.eligible);
    assert_eq!(missing.origin_address, Some(origin));
    assert_eq!(
        missing.disabled_reason.as_deref(),
        Some("The Shield origin Public account must be added or activated before refund.")
    );
    assert!(!inactive.eligible);
}

#[test]
fn blocked_shield_rescue_eligibility_reports_unresolved_origin() {
    let eligibility = super::blocked_shield_rescue_eligibility_for_origin(None, &[]);

    assert!(!eligibility.eligible);
    assert_eq!(eligibility.origin_address, None);
    assert_eq!(
        eligibility.disabled_reason.as_deref(),
        Some(
            "Source transaction origin could not be resolved. Retry after checking RPC connectivity."
        )
    );
}

#[test]
fn blocked_shield_rescue_candidate_rejects_ineligible_utxos() {
    let token = address(0x11);
    let blocked = blocked_shield_utxo(token, 5, 0, 1);
    let blocked_id = rescue_utxo_id(&blocked);
    let transact = utxo(token, 5, 0, 2);
    let transact_id = rescue_utxo_id(&transact);
    let shield = utxo_with_kind(token, 5, 0, 3, UtxoCommitmentKind::Shield);
    let shield_id = rescue_utxo_id(&shield);
    let mut spent = blocked_shield_utxo(token, 5, 0, 4);
    let spent_id = rescue_utxo_id(&spent);
    spent.spent = Some(source(9));
    let pending_overlay = WalletPendingOverlay {
        pending_spent: vec![WalletPendingSpent {
            tree: blocked.utxo.tree,
            position: blocked.utxo.position,
            tx_hash: Some(FixedBytes::from([0x99; 32])),
            block_number: Some(20),
            block_timestamp: Some(1_700_000_020),
        }],
        ..WalletPendingOverlay::default()
    };

    assert!(
        super::blocked_shield_rescue_candidate_from_records(
            std::slice::from_ref(&blocked),
            &WalletPendingOverlay::default(),
            &blocked_id,
        )
        .is_some()
    );
    assert!(
        super::blocked_shield_rescue_candidate_from_records(
            &[blocked],
            &pending_overlay,
            &blocked_id,
        )
        .is_none()
    );
    assert!(
        super::blocked_shield_rescue_candidate_from_records(
            &[transact],
            &WalletPendingOverlay::default(),
            &transact_id,
        )
        .is_none()
    );
    assert!(
        super::blocked_shield_rescue_candidate_from_records(
            &[shield],
            &WalletPendingOverlay::default(),
            &shield_id,
        )
        .is_none()
    );
    assert!(
        super::blocked_shield_rescue_candidate_from_records(
            &[spent],
            &WalletPendingOverlay::default(),
            &spent_id,
        )
        .is_none()
    );
}

#[test]
fn blocked_shield_rescue_plan_accepts_exact_single_utxo_unshield() {
    let token = address(0x11);
    let origin = address(0xaa);
    let blocked = blocked_shield_utxo(token, 5, 0, 1);
    let id = rescue_utxo_id(&blocked);
    let plan = rescue_plan_for_test(&blocked.utxo, token, uint!(5_U256), origin, None, None);

    super::validate_blocked_shield_rescue_plan(&plan, &id, token, uint!(5_U256), origin)
        .expect("valid rescue plan");
}

#[test]
fn blocked_shield_rescue_plan_rejects_additional_private_inputs() {
    let token = address(0x11);
    let origin = address(0xaa);
    let blocked = blocked_shield_utxo(token, 5, 0, 1);
    let extra = blocked_shield_utxo(token, 1, 0, 2);
    let id = rescue_utxo_id(&blocked);
    let plan = rescue_plan_for_test(
        &blocked.utxo,
        token,
        uint!(5_U256),
        origin,
        Some(extra.utxo),
        None,
    );

    assert!(
        super::validate_blocked_shield_rescue_plan(&plan, &id, token, uint!(5_U256), origin)
            .is_err()
    );
}

#[test]
fn blocked_shield_rescue_plan_rejects_partial_amount() {
    let token = address(0x11);
    let origin = address(0xaa);
    let blocked = blocked_shield_utxo(token, 5, 0, 1);
    let id = rescue_utxo_id(&blocked);
    let plan = rescue_plan_for_test(&blocked.utxo, token, uint!(4_U256), origin, None, None);

    assert!(
        super::validate_blocked_shield_rescue_plan(&plan, &id, token, uint!(5_U256), origin)
            .is_err()
    );
}

#[test]
fn blocked_shield_rescue_plan_rejects_private_change_outputs() {
    let token = address(0x11);
    let origin = address(0xaa);
    let blocked = blocked_shield_utxo(token, 5, 0, 1);
    let id = rescue_utxo_id(&blocked);
    let plan = rescue_plan_for_test(
        &blocked.utxo,
        token,
        uint!(5_U256),
        origin,
        None,
        Some(uint!(1_U256)),
    );

    assert!(
        super::validate_blocked_shield_rescue_plan(&plan, &id, token, uint!(5_U256), origin)
            .is_err()
    );
}

#[test]
fn blocked_shield_rescue_rejects_mismatched_gas_payer() {
    assert_eq!(
        super::matched_blocked_shield_rescue_public_account_uuid(Some("origin"), None)
            .expect("matched account"),
        "origin"
    );
    assert_eq!(
        super::matched_blocked_shield_rescue_public_account_uuid(Some("origin"), Some("origin"))
            .expect("matched account"),
        "origin"
    );
    assert!(
        super::matched_blocked_shield_rescue_public_account_uuid(Some("origin"), Some("other"))
            .is_err()
    );
}

#[test]
fn normal_spend_selection_excludes_shield_blocked_utxos() {
    let token = address(0x11);
    let blocked = blocked_shield_utxo(token, 5, 0, 1);
    let selected = super::poi_verified_unspent_utxos_from_records(
        std::slice::from_ref(&blocked),
        &WalletPendingOverlay::default(),
    );
    let (outputs, _) = utxo_outputs_from_utxos(vec![blocked]);

    assert!(selected.is_empty());
    assert_eq!(max_send_amount_from_outputs(&outputs, token), U256::ZERO);
    assert_eq!(
        max_unshield_amount_from_outputs(&outputs, token),
        U256::ZERO
    );
}

#[test]
fn pending_overlay_rows_are_not_spendable() {
    let token = address(0x11);
    let confirmed = utxo(token, 5, 0, 1);
    let pending_new = utxo(token, 7, 0, 2);
    let mut pending_spent_overlay = WalletPendingOverlay {
        pending_spent: vec![WalletPendingSpent {
            tree: 0,
            position: 1,
            tx_hash: Some(FixedBytes::from([0x99; 32])),
            block_number: Some(20),
            block_timestamp: Some(1_700_000_020),
        }],
        ..WalletPendingOverlay::default()
    };
    pending_spent_overlay.new_utxos.push(pending_new);
    let (mut outputs, _) = utxo_outputs_from_utxos(vec![confirmed.clone()]);

    apply_pending_overlay_to_outputs(&[confirmed], pending_spent_overlay, &mut outputs);

    assert_eq!(outputs.len(), 2);
    assert!(outputs.iter().any(|output| output.pending_spent));
    assert!(outputs.iter().any(|output| output.pending_new));
    assert_eq!(max_send_amount_from_outputs(&outputs, token), U256::ZERO);
    assert_eq!(
        max_unshield_amount_from_outputs(&outputs, token),
        U256::ZERO
    );
}

#[test]
fn local_pending_spent_rows_are_not_spendable() {
    let token = address(0x11);
    let confirmed = utxo(token, 5, 0, 1);
    let local_pending_overlay = WalletPendingOverlay {
        local_pending_spent: vec![WalletPendingSpent {
            tree: 0,
            position: 1,
            tx_hash: Some(FixedBytes::from([0x99; 32])),
            block_number: None,
            block_timestamp: Some(1_700_000_020),
        }],
        ..WalletPendingOverlay::default()
    };
    let (mut outputs, _) = utxo_outputs_from_utxos(vec![confirmed.clone()]);

    apply_pending_overlay_to_outputs(&[confirmed], local_pending_overlay, &mut outputs);

    assert_eq!(outputs.len(), 1);
    assert!(outputs[0].local_pending_spent);
    assert!(!outputs[0].pending_spent);
    assert_eq!(max_send_amount_from_outputs(&outputs, token), U256::ZERO);
    assert_eq!(
        max_unshield_amount_from_outputs(&outputs, token),
        U256::ZERO
    );
}

#[test]
fn self_broadcast_transaction_request_sets_outer_evm_fields() {
    let from = address(0x11);
    let to = address(0x22);
    let calldata = Bytes::from_static(&[0xaa, 0xbb, 0xcc]);

    let tx_req = self_broadcast_transaction_request(5, from, to, calldata.clone(), 42, 0, 7);

    assert_eq!(tx_req.chain_id, Some(5));
    assert_eq!(tx_req.from, Some(from));
    assert_eq!(tx_req.to, Some(to.into()));
    assert_eq!(tx_req.max_fee_per_gas, Some(42));
    assert_eq!(tx_req.max_priority_fee_per_gas, Some(0));
    assert_eq!(tx_req.nonce, Some(7));
    assert_eq!(
        tx_req.input.input().expect("self-broadcast input"),
        calldata.as_ref()
    );
}

#[test]
fn self_broadcast_auto_gas_fee_uses_rpc_gas_price_with_min_tip() {
    let quote = SelfBroadcastGasFeeQuote::from_rpc_gas_price(100);
    let resolved = resolve_self_broadcast_gas_fee(SelfBroadcastGasFeeSelection::Auto, quote)
        .expect("resolve auto gas fee");

    assert_eq!(quote.suggested_max_fee_per_gas, 120);
    assert_eq!(quote.suggested_max_priority_fee_per_gas, 1);
    assert_eq!(resolved.rpc_gas_price, 100);
    assert_eq!(resolved.max_fee_per_gas, 120);
    assert_eq!(resolved.max_priority_fee_per_gas, 1);
}

#[test]
fn self_broadcast_fee_samples_ignore_zero_tips_when_non_zero_exists() {
    let samples = [
        SelfBroadcastFeeSample {
            rpc_gas_price: Some(100),
            max_priority_fee_per_gas: Some(0),
            next_base_fee_per_gas: Some(80),
            priority_fee_rewards: vec![0, 0, 0],
        },
        SelfBroadcastFeeSample {
            rpc_gas_price: Some(110),
            max_priority_fee_per_gas: Some(0),
            next_base_fee_per_gas: Some(90),
            priority_fee_rewards: vec![0, 5, 7],
        },
    ];

    let quote = self_broadcast_quote_from_fee_samples(&samples).expect("fee quote");

    assert_eq!(quote.suggested_max_priority_fee_per_gas, 7);
    assert_eq!(quote.rpc_gas_price, 110);
    assert_eq!(quote.suggested_max_fee_per_gas, 132);
}

#[test]
fn self_broadcast_fee_samples_can_use_rpc_gas_price_as_tip_fallback() {
    let samples = [SelfBroadcastFeeSample {
        rpc_gas_price: Some(100),
        max_priority_fee_per_gas: Some(0),
        next_base_fee_per_gas: None,
        priority_fee_rewards: vec![0],
    }];

    let default_quote = self_broadcast_quote_from_fee_samples(&samples).expect("fee quote");
    let rpc_fallback_quote = self_broadcast_quote_from_fee_samples_with_tip_fallback(
        &samples,
        SelfBroadcastTipFallback::RpcGasPrice,
    )
    .expect("fee quote with rpc gas price fallback");

    assert_eq!(default_quote.suggested_max_priority_fee_per_gas, 1);
    assert_eq!(rpc_fallback_quote.suggested_max_fee_per_gas, 120);
    assert_eq!(rpc_fallback_quote.suggested_max_priority_fee_per_gas, 100);
}

#[test]
fn self_broadcast_fee_samples_prefer_non_zero_tip_over_rpc_gas_price_fallback() {
    let samples = [SelfBroadcastFeeSample {
        rpc_gas_price: Some(100),
        max_priority_fee_per_gas: Some(5),
        next_base_fee_per_gas: None,
        priority_fee_rewards: vec![0],
    }];

    let quote = self_broadcast_quote_from_fee_samples_with_tip_fallback(
        &samples,
        SelfBroadcastTipFallback::RpcGasPrice,
    )
    .expect("fee quote");

    assert_eq!(quote.suggested_max_fee_per_gas, 120);
    assert_eq!(quote.suggested_max_priority_fee_per_gas, 5);
}

#[test]
fn self_broadcast_fee_samples_include_fee_history_base_fee_cap() {
    let samples = [SelfBroadcastFeeSample {
        rpc_gas_price: Some(100),
        max_priority_fee_per_gas: Some(1),
        next_base_fee_per_gas: Some(200),
        priority_fee_rewards: vec![10],
    }];

    let quote = self_broadcast_quote_from_fee_samples(&samples).expect("fee quote");

    assert_eq!(quote.suggested_max_priority_fee_per_gas, 10);
    assert_eq!(quote.suggested_max_fee_per_gas, 250);
}

#[test]
fn self_broadcast_already_known_classifier_excludes_nonce_errors() {
    for message in [
        "already known",
        "already in mempool",
        "known transaction: 0xabc",
        "transaction already imported",
        "Transaction already exists",
    ] {
        assert!(
            is_self_broadcast_tx_already_known_message(message),
            "expected {message:?} to be classified as already known"
        );
    }

    for message in [
        "nonce too low",
        "replacement transaction underpriced",
        "transaction gas price below minimum",
    ] {
        assert!(
            !is_self_broadcast_tx_already_known_message(message),
            "expected {message:?} to remain retryable"
        );
    }
}

#[test]
fn self_broadcast_custom_gas_fee_validates_caps() {
    assert!(validate_self_broadcast_gas_fee(1, 0).is_ok());
    assert!(validate_self_broadcast_gas_fee(1, 1).is_ok());
    assert!(validate_self_broadcast_gas_fee(0, 0).is_err());
    assert!(validate_self_broadcast_gas_fee(1, 2).is_err());
}

#[test]
fn self_broadcast_replacement_bump_uses_ceil_twelve_point_five_percent() {
    assert_eq!(super::self_broadcast_replacement_bumped_fee(0), 0);
    assert_eq!(super::self_broadcast_replacement_bumped_fee(1), 2);
    assert_eq!(super::self_broadcast_replacement_bumped_fee(8), 9);
    assert_eq!(super::self_broadcast_replacement_bumped_fee(100), 113);
}

#[test]
fn self_broadcast_gas_cost_uses_max_fee_cap() {
    assert_eq!(self_broadcast_gas_limit_with_buffer(21_000, 5_000), 26_000);
    assert_eq!(self_broadcast_gas_limit_with_buffer(u64::MAX, 1), u64::MAX);
    assert_eq!(
        self_broadcast_native_gas_cost(26_000, 2_000_000_000),
        U256::from(52_000_000_000_000_u128)
    );
}

#[test]
fn self_broadcast_insufficient_gas_error_is_terminal_and_formatted() {
    let error = self_broadcast_insufficient_native_gas_error(U256::from(7_u64), U256::from(9_u64));

    assert!(is_self_broadcast_insufficient_native_gas_error(&error));
    assert_eq!(
        error.to_string(),
        "insufficient native gas for self-broadcast: live balance 7, estimated cost 9"
    );
}

#[test]
fn self_broadcast_pending_spent_hash_parsing_accepts_submitted_tx_hash() {
    let hash = "0x1111111111111111111111111111111111111111111111111111111111111111";

    assert_eq!(
        parse_submitted_tx_hash(hash),
        Some(FixedBytes::from([0x11; 32]))
    );
    assert_eq!(parse_submitted_tx_hash("not-a-hash"), None);
}

#[test]
fn manual_send_pending_output_contexts_persist_without_tx_hash() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let token = address(0x33);
    let recipient_note = sample_note(1, token, 5);
    let change_note = sample_note(2, token, 3);
    let chunk = sample_chunk(
        4,
        0x20,
        vec![recipient_note.clone(), change_note.clone()],
        false,
    );
    let poi_list_keys = default_active_poi_list_keys();
    let pre_transaction_pois = poi_map_for_chunks(&poi_list_keys, std::slice::from_ref(&chunk));

    let count = super::persist_pending_send_output_poi_contexts(
        &store,
        1,
        "wallet-1",
        &[chunk],
        &pre_transaction_pois,
        &poi_list_keys,
        false,
        false,
    )
    .expect("persist pending send output contexts");

    assert_eq!(count, 2);
    let records = store
        .list_pending_output_poi_contexts(1)
        .expect("list pending output POI contexts");
    assert_eq!(records.len(), 2);
    let recipient = records
        .iter()
        .find(|record| record.output_role == PendingOutputPoiRole::Recipient)
        .expect("recipient context");
    assert_eq!(recipient.wallet_id, "wallet-1");
    assert_eq!(
        recipient.output_commitment,
        FixedBytes::from(recipient_note.commitment().to_be_bytes::<32>())
    );
    assert!(recipient.source_operation_id.is_none());
    assert!(recipient.observation.is_none());
    assert_eq!(recipient.required_poi_list_keys, poi_list_keys);
    let change = records
        .iter()
        .find(|record| record.output_role == PendingOutputPoiRole::Change)
        .expect("change context");
    assert_eq!(
        change.output_commitment,
        FixedBytes::from(change_note.commitment().to_be_bytes::<32>())
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn manual_unshield_pending_output_contexts_skip_public_output_without_tx_hash() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let token = address(0x34);
    let change_note = sample_note(3, token, 7);
    let unshield_note = Note::new_unshield(address(0xaa), token, uint!(5_U256));
    let chunk = sample_chunk(
        5,
        0x30,
        vec![change_note.clone(), unshield_note.clone()],
        true,
    );
    let poi_list_keys = default_active_poi_list_keys();
    let pre_transaction_pois = poi_map_for_chunks(&poi_list_keys, std::slice::from_ref(&chunk));

    let count = super::persist_pending_unshield_output_poi_contexts(
        &store,
        1,
        "wallet-1",
        &[chunk],
        &pre_transaction_pois,
        &poi_list_keys,
        false,
        false,
    )
    .expect("persist pending unshield output contexts");

    assert_eq!(count, 1);
    let records = store
        .list_pending_output_poi_contexts(1)
        .expect("list pending output POI contexts");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].output_role, PendingOutputPoiRole::Change);
    assert_eq!(
        records[0].output_commitment,
        FixedBytes::from(change_note.commitment().to_be_bytes::<32>())
    );
    assert_ne!(
        records[0].output_commitment,
        FixedBytes::from(unshield_note.commitment().to_be_bytes::<32>())
    );
    assert!(records[0].source_operation_id.is_none());
    assert!(records[0].observation.is_none());

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn public_broadcaster_pending_output_contexts_include_fee_outputs() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let token = address(0x35);
    let fee_note = sample_note(4, token, 1);
    let recipient_note = sample_note(5, token, 8);
    let change_note = sample_note(6, token, 2);
    let chunk = sample_chunk(
        6,
        0x40,
        vec![fee_note.clone(), recipient_note, change_note],
        false,
    );
    let poi_list_keys = default_active_poi_list_keys();
    let pre_transaction_pois = poi_map_for_chunks(&poi_list_keys, std::slice::from_ref(&chunk));

    let count = super::persist_pending_send_output_poi_contexts(
        &store,
        1,
        "wallet-1",
        &[chunk],
        &pre_transaction_pois,
        &poi_list_keys,
        true,
        false,
    )
    .expect("persist public broadcaster send output contexts");

    assert_eq!(count, 3);
    let records = store
        .list_pending_output_poi_contexts(1)
        .expect("list pending output POI contexts");
    assert_eq!(records.len(), 3);
    assert!(records.iter().any(|record| record.output_role
        == PendingOutputPoiRole::BroadcasterFee
        && record.output_commitment
            == FixedBytes::from(fee_note.commitment().to_be_bytes::<32>())));

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn public_broadcaster_unshield_pending_output_contexts_skip_public_output() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let token = address(0x36);
    let fee_note = sample_note(7, token, 1);
    let change_note = sample_note(8, token, 4);
    let unshield_note = Note::new_unshield(address(0xbb), token, uint!(6_U256));
    let chunk = sample_chunk(
        7,
        0x50,
        vec![fee_note, change_note, unshield_note.clone()],
        true,
    );
    let poi_list_keys = default_active_poi_list_keys();
    let pre_transaction_pois = poi_map_for_chunks(&poi_list_keys, std::slice::from_ref(&chunk));

    let count = super::persist_pending_unshield_output_poi_contexts(
        &store,
        1,
        "wallet-1",
        &[chunk],
        &pre_transaction_pois,
        &poi_list_keys,
        true,
        false,
    )
    .expect("persist public broadcaster unshield output contexts");

    assert_eq!(count, 2);
    let records = store
        .list_pending_output_poi_contexts(1)
        .expect("list pending output POI contexts");
    assert_eq!(records.len(), 2);
    assert!(
        records
            .iter()
            .any(|record| record.output_role == PendingOutputPoiRole::BroadcasterFee)
    );
    assert!(
        records
            .iter()
            .any(|record| record.output_role == PendingOutputPoiRole::Change)
    );
    assert!(records.iter().all(|record| record.output_commitment
        != FixedBytes::from(unshield_note.commitment().to_be_bytes::<32>())));

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn separate_fee_token_send_pending_output_contexts_keep_fee_change_role() {
    let fee_token = address(0x39);
    let action_token = address(0x3a);
    let fee_note = sample_note(11, fee_token, 1);
    let fee_change_note = sample_note(12, fee_token, 4);
    let recipient_note = sample_note(13, action_token, 8);
    let action_change_note = sample_note(14, action_token, 2);
    let chunks = vec![
        sample_chunk(
            10,
            0x80,
            vec![fee_note.clone(), fee_change_note.clone()],
            false,
        ),
        sample_chunk(
            11,
            0x81,
            vec![recipient_note.clone(), action_change_note.clone()],
            false,
        ),
    ];
    let poi_list_keys = default_active_poi_list_keys();
    let pre_transaction_pois = poi_map_for_chunks(&poi_list_keys, &chunks);

    let records = super::build_pending_output_poi_context_records(
        1,
        "wallet-1",
        123,
        &chunks,
        &pre_transaction_pois,
        &poi_list_keys,
        &super::pending_send_output_role_plans(true, true),
    )
    .expect("build separate fee send records");

    assert_eq!(records.len(), 4);
    assert!(records.iter().any(|record| record.output_role
        == PendingOutputPoiRole::BroadcasterFee
        && record.output_commitment
            == FixedBytes::from(fee_note.commitment().to_be_bytes::<32>())));
    assert!(
        records
            .iter()
            .any(|record| record.output_role == PendingOutputPoiRole::Change
                && record.output_commitment
                    == FixedBytes::from(fee_change_note.commitment().to_be_bytes::<32>()))
    );
    assert!(records.iter().any(
        |record| record.output_role == PendingOutputPoiRole::Recipient
            && record.output_commitment
                == FixedBytes::from(recipient_note.commitment().to_be_bytes::<32>())
    ));
    assert!(
        records
            .iter()
            .any(|record| record.output_role == PendingOutputPoiRole::Change
                && record.output_commitment
                    == FixedBytes::from(action_change_note.commitment().to_be_bytes::<32>()))
    );
}

#[test]
fn separate_fee_token_unshield_pending_output_contexts_skip_action_public_output() {
    let fee_token = address(0x3b);
    let action_token = address(0x3c);
    let fee_note = sample_note(15, fee_token, 1);
    let fee_change_note = sample_note(16, fee_token, 4);
    let action_change_note = sample_note(17, action_token, 2);
    let unshield_note = Note::new_unshield(address(0xdd), action_token, uint!(6_U256));
    let chunks = vec![
        sample_chunk(
            12,
            0x82,
            vec![fee_note.clone(), fee_change_note.clone()],
            false,
        ),
        sample_chunk(
            13,
            0x83,
            vec![action_change_note.clone(), unshield_note.clone()],
            true,
        ),
    ];
    let poi_list_keys = default_active_poi_list_keys();
    let pre_transaction_pois = poi_map_for_chunks(&poi_list_keys, &chunks);

    let records = super::build_pending_output_poi_context_records(
        1,
        "wallet-1",
        123,
        &chunks,
        &pre_transaction_pois,
        &poi_list_keys,
        &super::pending_unshield_output_role_plans(true, true),
    )
    .expect("build separate fee unshield records");

    assert_eq!(records.len(), 3);
    assert!(records.iter().any(|record| record.output_role
        == PendingOutputPoiRole::BroadcasterFee
        && record.output_commitment
            == FixedBytes::from(fee_note.commitment().to_be_bytes::<32>())));
    assert!(
        records
            .iter()
            .any(|record| record.output_role == PendingOutputPoiRole::Change
                && record.output_commitment
                    == FixedBytes::from(fee_change_note.commitment().to_be_bytes::<32>()))
    );
    assert!(
        records
            .iter()
            .any(|record| record.output_role == PendingOutputPoiRole::Change
                && record.output_commitment
                    == FixedBytes::from(action_change_note.commitment().to_be_bytes::<32>()))
    );
    assert!(records.iter().all(|record| record.output_commitment
        != FixedBytes::from(unshield_note.commitment().to_be_bytes::<32>())));
}

#[test]
fn send_pending_output_role_plan_omits_absent_change() {
    let token = address(0x37);
    let recipient_note = sample_note(9, token, 11);
    let chunk = sample_chunk(8, 0x60, vec![recipient_note.clone()], false);
    let poi_list_keys = default_active_poi_list_keys();
    let pre_transaction_pois = poi_map_for_chunks(&poi_list_keys, std::slice::from_ref(&chunk));

    let records = super::build_pending_output_poi_context_records(
        1,
        "wallet-1",
        123,
        &[chunk],
        &pre_transaction_pois,
        &poi_list_keys,
        &super::pending_send_output_role_plans(false, false),
    )
    .expect("build pending send records");

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].output_role, PendingOutputPoiRole::Recipient);
    assert_eq!(
        records[0].output_commitment,
        FixedBytes::from(recipient_note.commitment().to_be_bytes::<32>())
    );
}

#[test]
fn unshield_pending_output_role_plan_skips_public_output_without_change() {
    let token = address(0x38);
    let fee_note = sample_note(10, token, 2);
    let unshield_note = Note::new_unshield(address(0xcc), token, uint!(9_U256));
    let chunk = sample_chunk(9, 0x70, vec![fee_note.clone(), unshield_note.clone()], true);
    let poi_list_keys = default_active_poi_list_keys();
    let pre_transaction_pois = poi_map_for_chunks(&poi_list_keys, std::slice::from_ref(&chunk));

    let records = super::build_pending_output_poi_context_records(
        1,
        "wallet-1",
        123,
        &[chunk],
        &pre_transaction_pois,
        &poi_list_keys,
        &super::pending_unshield_output_role_plans(true, false),
    )
    .expect("build pending unshield records");

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].output_role, PendingOutputPoiRole::BroadcasterFee);
    assert_eq!(
        records[0].output_commitment,
        FixedBytes::from(fee_note.commitment().to_be_bytes::<32>())
    );
    assert_ne!(
        records[0].output_commitment,
        FixedBytes::from(unshield_note.commitment().to_be_bytes::<32>())
    );
}

#[test]
fn self_broadcast_unshield_pending_pois_only_when_private_outputs_exist() {
    let token = address(0x3d);
    let unshield_note = Note::new_unshield(address(0xde), token, uint!(9_U256));
    let no_change_chunk = sample_chunk(14, 0x84, vec![unshield_note.clone()], true);

    assert!(!super::unshield_chunks_require_pending_output_pois(
        std::slice::from_ref(&no_change_chunk)
    ));

    let change_note = sample_note(18, token, 1);
    let change_chunk = sample_chunk(15, 0x85, vec![change_note, unshield_note], true);

    assert!(super::unshield_chunks_require_pending_output_pois(
        std::slice::from_ref(&change_chunk)
    ));
}

#[test]
fn self_broadcast_unshield_pending_pois_are_required_for_malformed_chunks() {
    let malformed_chunk = sample_chunk(16, 0x86, Vec::new(), true);

    assert!(super::unshield_chunks_require_pending_output_pois(
        std::slice::from_ref(&malformed_chunk)
    ));
}

#[test]
fn utxo_outputs_are_sorted_by_tree_then_position() {
    let token = address(0x11);
    let (outputs, _) = utxo_outputs_from_utxos(vec![
        utxo(token, 1, 2, 1),
        utxo(token, 1, 1, 2),
        utxo(token, 1, 1, 1),
    ]);

    let positions: Vec<(u32, u64)> = outputs
        .into_iter()
        .map(|output| (output.tree, output.position))
        .collect();
    assert_eq!(positions, vec![(1, 1), (1, 2), (2, 1)]);
}

#[test]
fn fee_token_amount_from_outputs_matches_single_fee_transaction_limit() {
    let token = address(0x12);
    let (outputs, _) = utxo_outputs_from_utxos(
        (0..20)
            .map(|position| utxo(token, 1, 0, position))
            .collect(),
    );

    assert_eq!(
        max_broadcaster_fee_token_amount_from_outputs(&outputs, token),
        uint!(13_U256)
    );
}

#[test]
fn token_totals_are_accumulated_by_token_address() {
    let token_a = address(0x11);
    let token_b = address(0x22);
    let (_, totals) = utxo_outputs_from_utxos(vec![
        utxo(token_b, 7, 0, 0),
        utxo(token_a, 3, 0, 1),
        utxo(token_a, 4, 0, 2),
        spent_utxo(token_a, 100, 0, 3),
    ]);

    assert_eq!(
        totals,
        vec![
            TokenTotal {
                token: token_a.to_checksum(None),
                total: "7".to_string(),
                poi_verified_total: "7".to_string(),
            },
            TokenTotal {
                token: token_b.to_checksum(None),
                total: "7".to_string(),
                poi_verified_total: "7".to_string(),
            },
        ]
    );
}

#[test]
fn token_totals_include_poi_verified_balance() {
    let token = address(0x11);
    let active_list_key = default_active_poi_list_keys()[0];
    let mut valid = utxo(token, 5, 0, 1);
    valid
        .utxo
        .poi
        .statuses
        .insert(active_list_key, PoiStatus::Valid);
    let mut missing = utxo(token, 7, 0, 2);
    missing.utxo.poi.statuses.clear();

    let (outputs, totals) = utxo_outputs_from_utxos(vec![valid, missing]);

    assert!(outputs[0].poi_spendable);
    assert_eq!(
        outputs[0].poi_statuses[&hex::encode(active_list_key)],
        "Valid"
    );
    assert!(!outputs[1].poi_spendable);
    assert_eq!(
        outputs[1].poi_statuses[&hex::encode(active_list_key)],
        "Unknown"
    );
    assert_eq!(totals[0].total, "12");
    assert_eq!(totals[0].poi_verified_total, "5");
}

#[test]
fn utxo_outputs_classify_activity_rows() {
    let token = address(0x11);
    let active_list_key = default_active_poi_list_keys()[0];
    let shield = utxo_with_kind(token, 5, 0, 1, UtxoCommitmentKind::Shield);
    let mut blocked_shield = utxo_with_kind(token, 7, 0, 2, UtxoCommitmentKind::Shield);
    blocked_shield
        .utxo
        .poi
        .statuses
        .insert(active_list_key, PoiStatus::ShieldBlocked);
    let transact = utxo(token, 9, 0, 3);

    let (outputs, _) = utxo_outputs_from_utxos(vec![shield, blocked_shield, transact]);

    assert_eq!(outputs[0].activity_classification, "Shield");
    assert!(outputs[0].blocked_shield_rescue.is_none());
    assert_eq!(outputs[1].activity_classification, "Blocked Shield");
    assert!(!outputs[1].poi_spendable);
    assert_eq!(
        outputs[1]
            .blocked_shield_rescue
            .as_ref()
            .and_then(|rescue| rescue.disabled_reason.as_deref()),
        Some("Source transaction origin has not been resolved yet.")
    );
    assert_eq!(outputs[2].activity_classification, "Private Output");
    assert!(outputs[2].blocked_shield_rescue.is_none());
}

#[test]
fn max_amount_from_outputs_uses_planner_batched_selection() {
    let token = address(0x11);
    let other = address(0x22);
    let mut wallet_utxos = (0..20)
        .map(|position| utxo(token, 1, 0, position))
        .collect::<Vec<_>>();
    wallet_utxos.extend((0..5).map(|position| utxo(token, 3, 1, position)));
    wallet_utxos.push(utxo(other, 100, 1, 99));
    wallet_utxos.push(spent_utxo(token, 100, 2, 0));
    let (outputs, _) = utxo_outputs_from_utxos(wallet_utxos);

    assert_eq!(
        max_unshield_amount_from_outputs(&outputs, token),
        uint!(35_U256)
    );
    assert_eq!(
        max_send_amount_from_outputs(&outputs, token),
        uint!(35_U256)
    );
}

#[test]
fn max_amount_from_outputs_excludes_non_poi_verified_utxos() {
    let token = address(0x11);
    let mut valid = utxo(token, 5, 0, 1);
    let mut unknown = utxo(token, 100, 0, 2);
    unknown.utxo.poi.statuses.clear();
    let (outputs, _) = utxo_outputs_from_utxos(vec![valid.clone(), unknown]);

    assert_eq!(max_send_amount_from_outputs(&outputs, token), uint!(5_U256));
    assert_eq!(
        max_unshield_amount_from_outputs(&outputs, token),
        uint!(5_U256)
    );

    valid.spent = Some(source(9));
    let (outputs, _) = utxo_outputs_from_utxos(vec![valid]);
    assert_eq!(max_send_amount_from_outputs(&outputs, token), U256::ZERO);
    assert_eq!(
        max_unshield_amount_from_outputs(&outputs, token),
        U256::ZERO
    );
}

#[test]
fn utxo_outputs_include_generation_timestamp() {
    let token = address(0x11);
    let (outputs, _) = utxo_outputs_from_utxos(vec![utxo(token, 1, 0, 7)]);

    assert_eq!(outputs[0].source_block_timestamp, 1_700_000_008);
}

#[test]
fn list_utxos_output_serializes_existing_field_names() {
    let output = ListUtxosOutput {
        chain_id: 1,
        cache_key: "cache".to_string(),
        utxo_count: 1,
        unspent_count: 0,
        spent_count: 1,
        local_pending_spent_count: 0,
        utxos: vec![UtxoOutput {
            tree: 2,
            position: 3,
            token: "0x0000000000000000000000000000000000000001".to_string(),
            value: "4".to_string(),
            commitment_kind: "Transact".to_string(),
            activity_classification: "Private Output".to_string(),
            blocked_shield_rescue: None,
            commitment: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            npk: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            blinded_commitment:
                "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
            poi_statuses: BTreeMap::from([(
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string(),
                "Unknown".to_string(),
            )]),
            poi_spendable: false,
            source_tx_hash: "0x1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            source_block_number: 11,
            source_block_timestamp: 1_700_000_011,
            is_spent: true,
            pending_new: false,
            pending_spent: false,
            local_pending_spent: false,
            spent_tx_hash: Some(
                "0x2222222222222222222222222222222222222222222222222222222222222222".to_string(),
            ),
            spent_block_number: Some(21),
        }],
        totals: vec![TokenTotal {
            token: "0x0000000000000000000000000000000000000001".to_string(),
            total: "4".to_string(),
            poi_verified_total: "0".to_string(),
        }],
    };

    assert_eq!(
        serde_json::to_value(output).expect("serialize output"),
        json!({
            "chain_id": 1,
            "cache_key": "cache",
            "utxo_count": 1,
            "unspent_count": 0,
            "spent_count": 1,
            "local_pending_spent_count": 0,
            "utxos": [{
                "tree": 2,
                "position": 3,
                "token": "0x0000000000000000000000000000000000000001",
                "value": "4",
                "commitment_kind": "Transact",
                "activity_classification": "Private Output",
                "blocked_shield_rescue": null,
                "commitment": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "npk": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "blinded_commitment": "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "poi_statuses": {
                    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd": "Unknown",
                },
                "poi_spendable": false,
                "source_tx_hash": "0x1111111111111111111111111111111111111111111111111111111111111111",
                "source_block_number": 11,
                "source_block_timestamp": 1_700_000_011,
                "is_spent": true,
                "pending_new": false,
                "pending_spent": false,
                "local_pending_spent": false,
                "spent_tx_hash": "0x2222222222222222222222222222222222222222222222222222222222222222",
                "spent_block_number": 21,
            }],
            "totals": [{
                "token": "0x0000000000000000000000000000000000000001",
                "total": "4",
                "poi_verified_total": "0",
            }],
        })
    );
}

#[test]
fn software_evm_signer_uses_separate_transaction_and_message_boundaries() {
    fn exercise_boundaries(signer: &(impl EvmTransactionSigner + EvmMessageSigner)) {
        let address = signer.address();
        let shield_key = signer
            .derive_shield_private_key()
            .expect("derive shield key through EVM message boundary");
        let _wallet = signer.ethereum_wallet();

        assert_ne!(address, Address::ZERO);
        assert_ne!(shield_key, [0u8; 32]);
    }

    let signer = SoftwareEvmSigner::from_private_key([1; 32]).expect("software EVM signer");

    exercise_boundaries(&signer);
}

#[test]
fn parse_unshield_amount_scales_known_token_decimals() {
    assert_eq!(
        parse_unshield_amount("1.23", Some(6)).expect("parsed amount"),
        uint!(1_230_000_U256)
    );
    assert_eq!(
        parse_unshield_amount(".5", Some(18)).expect("parsed amount"),
        uint!(5_U256) * uint!(10_U256).pow(uint!(17_U256))
    );
}

#[test]
fn parse_unshield_amount_rejects_too_much_precision() {
    assert!(parse_unshield_amount("1.2345678", Some(6)).is_err());
}

#[test]
fn parse_unshield_amount_requires_raw_units_for_unknown_tokens() {
    assert_eq!(
        parse_unshield_amount("123", None).expect("parsed raw amount"),
        uint!(123_U256)
    );
    assert!(parse_unshield_amount("1.23", None).is_err());
}

#[test]
fn parse_send_amount_reuses_token_aware_amount_parsing() {
    assert_eq!(
        parse_send_amount("1.23", Some(6)).expect("parsed amount"),
        uint!(1_230_000_U256)
    );
    assert_eq!(
        parse_send_amount("123", None).expect("parsed raw amount"),
        uint!(123_U256)
    );
    assert!(parse_send_amount("1.23", None).is_err());
}

#[test]
fn parse_railgun_recipient_accepts_valid_0zk_address() {
    let wallet = WalletKeys::from_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        0,
    )
    .expect("derive wallet");
    let address = wallet
        .viewing
        .derive_address(None)
        .expect("derive all-chain address")
        .to_string();

    let recipient = parse_railgun_recipient(&address).expect("valid 0zk recipient");

    assert_eq!(
        recipient.master_public_key,
        wallet.viewing.master_public_key
    );
    assert_eq!(
        recipient.viewing_public_key,
        wallet.viewing.viewing_public_key
    );
}

#[test]
fn parse_railgun_recipient_rejects_invalid_address() {
    assert!(parse_railgun_recipient("0x0000000000000000000000000000000000000000").is_err());
    assert!(parse_railgun_recipient("").is_err());
}

#[test]
fn public_broadcaster_candidates_filter_unsupported_rows_but_allow_poi_required_temporarily() {
    let token = address(0x21);
    let relay_adapt = address(0x44);
    let mut rows = vec![fee_row(1, token, 10, 0.9, "ok")];

    let mut invalid_signature = fee_row(1, token, 10, 0.9, "invalid-signature");
    invalid_signature.signature_valid = false;
    rows.push(invalid_signature);

    let mut expired = fee_row(1, token, 10, 0.9, "expired");
    expired.fee_expiration = SystemTime::now() - Duration::from_secs(1);
    rows.push(expired);

    let mut unavailable = fee_row(1, token, 10, 0.9, "unavailable");
    unavailable.available_wallets = 0;
    rows.push(unavailable);

    let mut unsupported_version = fee_row(1, token, 10, 0.9, "version");
    unsupported_version.version = Arc::from("9.0.0");
    rows.push(unsupported_version);

    let mut poi_required = fee_row(1, token, 10, 0.9, "poi");
    poi_required.required_poi_list_keys = vec![Arc::from("poi-list")];
    rows.push(poi_required);

    rows.push(fee_row(2, token, 10, 0.9, "chain"));
    rows.push(fee_row(1, address(0x22), 10, 0.9, "token"));

    let mut relay_mismatch = fee_row(1, token, 10, 0.9, "relay");
    relay_mismatch.relay_adapt = address(0x55);
    rows.push(relay_mismatch);

    let candidates =
        eligible_public_broadcasters(&rows, 1, token, Some(relay_adapt), SystemTime::now());

    assert_eq!(candidates.len(), 2);
    assert_eq!(candidates[0].fees_id, "ok");
    assert_eq!(candidates[1].fees_id, "poi");
}

#[test]
fn public_broadcaster_candidates_are_keyed_by_selected_fee_token() {
    let action_token = address(0x43);
    let fee_token = address(0x44);
    let candidates = public_broadcaster_candidates(
        &[
            fee_row(1, action_token, 10, 0.9, "action-token"),
            fee_row(1, fee_token, 11, 0.9, "fee-token"),
        ],
        1,
        fee_token,
        None,
        SystemTime::now(),
        BroadcasterFeePolicy::default(),
        None,
    );

    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].fees_id, "fee-token");
    assert_eq!(candidates[0].token, fee_token);
}

#[test]
fn specific_public_broadcaster_fails_when_not_available_for_fee_token() {
    let action_token = address(0x45);
    let fee_token = address(0x46);
    let railgun_address = sample_railgun_address(51);
    let candidates = public_broadcaster_candidates(
        &[fee_row_with_broadcaster_seed(
            1,
            action_token,
            10,
            0.9,
            "action-only",
            51,
        )],
        1,
        fee_token,
        None,
        SystemTime::now(),
        BroadcasterFeePolicy::default(),
        None,
    );

    let error = select_public_broadcaster_with_policy(
        &candidates,
        &PublicBroadcasterSelection::Specific { railgun_address },
        BroadcasterFeePolicy::default(),
    )
    .expect_err("specific broadcaster should not match action-token row");

    assert!(error.to_string().contains("no longer eligible"));
}

#[test]
fn public_broadcaster_selection_sorts_by_fee_then_reliability() {
    let token = address(0x23);
    let candidates = eligible_public_broadcasters(
        &[
            fee_row_with_broadcaster_seed(1, token, 20, 0.99, "expensive", 11),
            fee_row_with_broadcaster_seed(1, token, 10, 0.50, "cheap-low-rel", 12),
            fee_row_with_broadcaster_seed(1, token, 10, 0.90, "cheap-high-rel", 13),
        ],
        1,
        token,
        None,
        SystemTime::now(),
    );

    let sorted = sort_specific_public_broadcasters(candidates.clone());
    let ids: Vec<_> = sorted
        .iter()
        .map(|candidate| candidate.fees_id.as_str())
        .collect();
    assert_eq!(ids, vec!["cheap-high-rel", "cheap-low-rel", "expensive"]);
    let cheap_low_rel_address = candidates
        .iter()
        .find(|candidate| candidate.fees_id == "cheap-low-rel")
        .expect("cheap-low-rel candidate")
        .railgun_address
        .clone();

    let selected = select_public_broadcaster(
        &candidates,
        &PublicBroadcasterSelection::Specific {
            railgun_address: cheap_low_rel_address,
        },
    )
    .expect("specific candidate");
    assert_eq!(selected.fees_id, "cheap-low-rel");
    assert!(select_public_broadcaster(&candidates, &PublicBroadcasterSelection::Random).is_ok());
}

#[test]
fn random_public_broadcaster_selection_prefers_non_poi_required_candidate() {
    let token = address(0x27);
    let mut poi_required = fee_row_with_broadcaster_seed(1, token, 10, 0.9, "poi", 31);
    poi_required.required_poi_list_keys = vec![Arc::from("poi-list")];
    let candidates = eligible_public_broadcasters(
        &[
            poi_required,
            fee_row_with_broadcaster_seed(1, token, 10, 0.9, "supported", 32),
        ],
        1,
        token,
        None,
        SystemTime::now(),
    );

    let selected = select_public_broadcaster(&candidates, &PublicBroadcasterSelection::Random)
        .expect("random supported candidate");

    assert_eq!(selected.fees_id, "supported");
    assert!(selected.required_poi_list_keys.is_empty());
}

#[test]
fn public_broadcaster_specific_selection_survives_fees_id_refresh() {
    let token = address(0x24);
    let railgun_address = sample_railgun_address(21);
    let candidates = eligible_public_broadcasters(
        &[fee_row_with_broadcaster_seed(
            1,
            token,
            10,
            0.9,
            "fresh-fees-id",
            21,
        )],
        1,
        token,
        None,
        SystemTime::now(),
    );

    let selected = select_public_broadcaster(
        &candidates,
        &PublicBroadcasterSelection::Specific { railgun_address },
    )
    .expect("specific candidate by stable address");

    assert_eq!(selected.fees_id, "fresh-fees-id");
}

#[test]
fn public_broadcaster_trust_filter_gives_banned_precedence() {
    let token = address(0x47);
    let candidates = public_broadcaster_candidates(
        &[
            fee_row_with_broadcaster_seed(1, token, 10, 0.9, "favorite-and-banned", 61),
            fee_row_with_broadcaster_seed(1, token, 11, 0.9, "neutral", 62),
        ],
        1,
        token,
        None,
        SystemTime::now(),
        BroadcasterFeePolicy::default(),
        None,
    );
    let trust_filter = PublicBroadcasterTrustFilter {
        preferences: vault::BroadcasterPreferences {
            favorites: vec![broadcaster_preference_entry(61)],
            banned: vec![broadcaster_preference_entry(61)],
        },
        favorites_only: false,
    };

    let trusted = filter_public_broadcasters_by_trust(&candidates, &trust_filter);

    assert_eq!(trusted.len(), 1);
    assert_eq!(trusted[0].fees_id, "neutral");
}

#[test]
fn public_broadcaster_trust_filter_supports_favorites_only_selection() {
    let token = address(0x48);
    let candidates = public_broadcaster_candidates(
        &[
            fee_row_with_broadcaster_seed(1, token, 10, 0.9, "favorite", 63),
            fee_row_with_broadcaster_seed(1, token, 11, 0.9, "neutral", 64),
        ],
        1,
        token,
        None,
        SystemTime::now(),
        BroadcasterFeePolicy::default(),
        None,
    );
    let favorite_address = sample_railgun_address(63);
    let neutral_address = sample_railgun_address(64);
    let trust_filter = PublicBroadcasterTrustFilter {
        preferences: vault::BroadcasterPreferences {
            favorites: vec![broadcaster_preference_entry(63)],
            banned: Vec::new(),
        },
        favorites_only: true,
    };

    let favorite = select_public_broadcaster_with_policy_and_trust(
        &candidates,
        &PublicBroadcasterSelection::Specific {
            railgun_address: favorite_address,
        },
        BroadcasterFeePolicy::default(),
        &trust_filter,
    )
    .expect("favorite broadcaster remains selectable");
    let error = select_public_broadcaster_with_policy_and_trust(
        &candidates,
        &PublicBroadcasterSelection::Specific {
            railgun_address: neutral_address,
        },
        BroadcasterFeePolicy::default(),
        &trust_filter,
    )
    .expect_err("non-favorite should be rejected");

    assert_eq!(favorite.fees_id, "favorite");
    assert!(error.to_string().contains("preferences"));
}

#[test]
fn public_broadcaster_trust_filter_rejects_stale_estimated_broadcaster() {
    let token = address(0x49);
    let railgun_address = sample_railgun_address(65);
    let candidates = public_broadcaster_candidates(
        &[fee_row_with_broadcaster_seed(
            1, token, 10, 0.9, "stale", 65,
        )],
        1,
        token,
        None,
        SystemTime::now(),
        BroadcasterFeePolicy::default(),
        None,
    );
    let trust_filter = PublicBroadcasterTrustFilter {
        preferences: vault::BroadcasterPreferences {
            favorites: Vec::new(),
            banned: vec![broadcaster_preference_entry(65)],
        },
        favorites_only: false,
    };

    let error = select_public_broadcaster_with_policy_and_trust(
        &candidates,
        &PublicBroadcasterSelection::Specific { railgun_address },
        BroadcasterFeePolicy::default(),
        &trust_filter,
    )
    .expect_err("banned estimated broadcaster should be rejected");

    assert!(error.to_string().contains("preferences"));
}

#[test]
fn public_broadcaster_fee_policy_classifies_anchor_bounds() {
    let token = address(0x28);
    let policy = BroadcasterFeePolicy::default();
    let candidates = public_broadcaster_candidates(
        &[
            fee_row(1, token, 89, 0.9, "below"),
            fee_row(1, token, 90, 0.9, "lower-bound"),
            fee_row(1, token, 150, 0.9, "upper-bound"),
            fee_row(1, token, 151, 0.9, "above"),
        ],
        1,
        token,
        None,
        SystemTime::now(),
        policy,
        Some(uint!(100_U256)),
    );

    let eligible_ids = fee_policy_eligible_public_broadcasters(&candidates, policy)
        .into_iter()
        .map(|candidate| candidate.fees_id)
        .collect::<Vec<_>>();
    assert_eq!(eligible_ids, vec!["lower-bound", "upper-bound"]);
    assert!(
        candidates
            .iter()
            .any(|candidate| candidate.fees_id == "below"
                && matches!(
                    candidate.fee_policy_status,
                    BroadcasterFeePolicyStatus::Suspicious {
                        premium_bps: Some(-1100),
                        ..
                    }
                ))
    );
    assert!(
        candidates
            .iter()
            .any(|candidate| candidate.fees_id == "above"
                && matches!(
                    candidate.fee_policy_status,
                    BroadcasterFeePolicyStatus::Suspicious {
                        premium_bps: Some(5100),
                        ..
                    }
                ))
    );
}

#[test]
fn public_broadcaster_fee_policy_allows_unknown_anchor_rows() {
    let token = address(0x29);
    let policy = BroadcasterFeePolicy::default();
    let candidates = public_broadcaster_candidates(
        &[fee_row(1, token, 1_000_000, 0.9, "raw")],
        1,
        token,
        None,
        SystemTime::now(),
        policy,
        None,
    );

    assert_eq!(candidates.len(), 1);
    assert_eq!(
        candidates[0].fee_policy_status,
        BroadcasterFeePolicyStatus::UnknownAnchor
    );
    assert_eq!(
        fee_policy_eligible_public_broadcasters(&candidates, policy).len(),
        1
    );
}

#[test]
fn public_broadcaster_policy_uses_fixed_anchor_without_cache() {
    let weth = wrapped_native_token_for_chain(1).expect("ethereum wrapped native");

    assert_eq!(
        fixed_token_anchor_rate(1, weth),
        Some(uint!(1_000_000_000_000_000_000_U256))
    );
    assert_eq!(
        public_broadcaster_anchor_rate_for_policy(None, 1, weth),
        Some(uint!(1_000_000_000_000_000_000_U256))
    );
}

#[test]
fn public_broadcaster_fee_breakdown_splits_gas_and_margin() {
    let breakdown = public_broadcaster_fee_breakdown(
        uint!(2_500_U256),
        10,
        100,
        Some(uint!(2_000_000_000_000_000_000_U256)),
    );

    assert_eq!(breakdown.native_gas_cost, uint!(1_010_U256));
    assert_eq!(breakdown.fee_token_gas_cost, Some(uint!(2_020_U256)));
    assert_eq!(
        breakdown.broadcaster_fee,
        Some(PublicBroadcasterFeeMargin::Positive(uint!(480_U256)))
    );
}

#[test]
fn public_broadcaster_fee_breakdown_handles_negative_and_missing_anchor() {
    let negative = public_broadcaster_fee_breakdown(
        uint!(1_000_U256),
        10,
        100,
        Some(uint!(2_000_000_000_000_000_000_U256)),
    );
    let missing = public_broadcaster_fee_breakdown(uint!(1_000_U256), 10, 100, None);

    assert_eq!(
        negative.broadcaster_fee,
        Some(PublicBroadcasterFeeMargin::Negative(uint!(1_020_U256)))
    );
    assert_eq!(missing.native_gas_cost, uint!(1_010_U256));
    assert_eq!(missing.fee_token_gas_cost, None);
    assert_eq!(missing.broadcaster_fee, None);
}

#[test]
fn public_broadcaster_fee_policy_override_includes_suspicious_rows() {
    let token = address(0x2a);
    let policy = BroadcasterFeePolicy::default();
    let allow_policy = policy.with_allow_suspicious_broadcasters(true);
    let candidates = public_broadcaster_candidates(
        &[fee_row(1, token, 151, 0.9, "above")],
        1,
        token,
        None,
        SystemTime::now(),
        policy,
        Some(uint!(100_U256)),
    );

    assert!(
        select_public_broadcaster_with_policy(
            &candidates,
            &PublicBroadcasterSelection::Random,
            policy
        )
        .is_err()
    );
    assert!(
        select_public_broadcaster_with_policy(
            &candidates,
            &PublicBroadcasterSelection::Random,
            allow_policy
        )
        .is_ok()
    );
}

#[test]
fn specific_public_broadcaster_drift_rechecks_latest_fee_policy() {
    let token = address(0x2b);
    let railgun_address = sample_railgun_address(41);
    let policy = BroadcasterFeePolicy::default();
    let initial = public_broadcaster_candidates(
        &[fee_row_with_broadcaster_seed(
            1, token, 100, 0.9, "initial", 41,
        )],
        1,
        token,
        None,
        SystemTime::now(),
        policy,
        Some(uint!(100_U256)),
    );
    let selection = PublicBroadcasterSelection::Specific { railgun_address };
    assert!(select_public_broadcaster_with_policy(&initial, &selection, policy).is_ok());

    let drifted = public_broadcaster_candidates(
        &[fee_row_with_broadcaster_seed(
            1, token, 151, 0.9, "drifted", 41,
        )],
        1,
        token,
        None,
        SystemTime::now(),
        policy,
        Some(uint!(100_U256)),
    );
    let error = select_public_broadcaster_with_policy(&drifted, &selection, policy)
        .expect_err("drifted broadcaster should be blocked");
    assert!(error.to_string().contains("outside the allowed range"));
    assert!(
        select_public_broadcaster_with_policy(
            &drifted,
            &selection,
            policy.with_allow_suspicious_broadcasters(true)
        )
        .is_ok()
    );
}

#[test]
fn broadcaster_fee_amount_uses_same_token_fee_rate() {
    let fee = broadcaster_fee_amount(
        uint!(2_000_000_000_000_000_000_U256),
        150_000,
        20_000_000_000,
    );

    assert_eq!(fee, uint!(6_000_000_000_000_000_U256));
}

#[test]
fn railgun_protocol_fee_uses_hardcoded_unshield_bps() {
    let amount = uint!(1_000_000_U256);

    assert_eq!(
        super::railgun_protocol_fee_amount(amount, RAILGUN_UNSHIELD_PROTOCOL_FEE_BPS),
        uint!(2_500_U256)
    );
    assert_eq!(
        super::railgun_protocol_fee_amount(amount, U256::ZERO),
        U256::ZERO
    );
}

#[test]
fn unshield_fee_handling_handles_protocol_fee_for_same_and_different_fee_tokens() {
    let entered = uint!(1_000_000_U256);
    let broadcaster_fee = uint!(400_U256);
    let gross = super::railgun_protocol_gross_amount_for_recipient(
        entered,
        RAILGUN_UNSHIELD_PROTOCOL_FEE_BPS,
    )
    .expect("gross protocol amount");
    let protocol_fee = super::railgun_protocol_fee_amount(gross, RAILGUN_UNSHIELD_PROTOCOL_FEE_BPS);

    assert_eq!(gross, uint!(1_002_506_U256));
    assert_eq!(gross - protocol_fee, entered);
    assert_eq!(
        super::unshield_receiver_amount_for_fee_mode(entered, FeeHandlingMode::DeductFromAmount)
            .expect("deduct unshield receiver amount"),
        entered
    );
    assert_eq!(
        super::unshield_receiver_amount_for_fee_mode(entered, FeeHandlingMode::AddToAmount)
            .expect("add unshield receiver amount"),
        gross
    );

    let same_token_add = public_broadcaster_amount_split_for_tokens_and_protocol(
        entered,
        broadcaster_fee,
        FeeHandlingMode::AddToAmount,
        true,
        RAILGUN_UNSHIELD_PROTOCOL_FEE_BPS,
    )
    .expect("same-token add split");
    assert_eq!(same_token_add.receiver_amount, gross);
    assert_eq!(same_token_add.total_private_spend, gross + broadcaster_fee);
    assert_eq!(same_token_add.fee_mode, FeeHandlingMode::AddToAmount);

    let same_token_deduct = public_broadcaster_amount_split_for_tokens_and_protocol(
        entered,
        broadcaster_fee,
        FeeHandlingMode::DeductFromAmount,
        true,
        RAILGUN_UNSHIELD_PROTOCOL_FEE_BPS,
    )
    .expect("same-token deduct split");
    assert_eq!(same_token_deduct.receiver_amount, entered - broadcaster_fee);
    assert_eq!(same_token_deduct.total_private_spend, entered);
    assert_eq!(
        same_token_deduct.fee_mode,
        FeeHandlingMode::DeductFromAmount
    );

    let different_token_add = public_broadcaster_amount_split_for_tokens_and_protocol(
        entered,
        broadcaster_fee,
        FeeHandlingMode::AddToAmount,
        false,
        RAILGUN_UNSHIELD_PROTOCOL_FEE_BPS,
    )
    .expect("different-token add split");
    assert_eq!(different_token_add.receiver_amount, gross);
    assert_eq!(different_token_add.total_private_spend, gross);
    assert_eq!(different_token_add.fee_mode, FeeHandlingMode::AddToAmount);

    let different_token_deduct = public_broadcaster_amount_split_for_tokens_and_protocol(
        entered,
        broadcaster_fee,
        FeeHandlingMode::DeductFromAmount,
        false,
        RAILGUN_UNSHIELD_PROTOCOL_FEE_BPS,
    )
    .expect("different-token deduct split");
    assert_eq!(different_token_deduct.receiver_amount, entered);
    assert_eq!(different_token_deduct.total_private_spend, entered);
    assert_eq!(
        different_token_deduct.fee_mode,
        FeeHandlingMode::DeductFromAmount
    );

    let max_receiver = uint!(2_000_000_U256);
    assert_eq!(
        public_broadcaster_max_entered_amount_for_tokens_and_protocol(
            max_receiver,
            broadcaster_fee,
            FeeHandlingMode::AddToAmount,
            true,
            RAILGUN_UNSHIELD_PROTOCOL_FEE_BPS,
        ),
        uint!(1_995_000_U256)
    );
    assert_eq!(
        public_broadcaster_max_entered_amount_for_tokens_and_protocol(
            max_receiver,
            broadcaster_fee,
            FeeHandlingMode::DeductFromAmount,
            true,
            RAILGUN_UNSHIELD_PROTOCOL_FEE_BPS,
        ),
        max_receiver + broadcaster_fee
    );
    assert_eq!(
        public_broadcaster_max_entered_amount_for_tokens_and_protocol(
            max_receiver,
            broadcaster_fee,
            FeeHandlingMode::DeductFromAmount,
            false,
            RAILGUN_UNSHIELD_PROTOCOL_FEE_BPS,
        ),
        max_receiver
    );
}

#[test]
fn public_broadcaster_fee_stabilization_accepts_covering_fee() {
    let required = uint!(1_000_U256);

    assert!(broadcaster_fee_covers(required, required));
    assert!(broadcaster_fee_covers(required + uint!(1_U256), required));
    assert!(!broadcaster_fee_covers(required - uint!(1_U256), required));
}

#[test]
fn public_broadcaster_fee_stabilization_buffers_retries() {
    assert_eq!(
        buffered_public_broadcaster_fee(uint!(10_000_U256)),
        uint!(10_100_U256)
    );
    assert_eq!(
        buffered_public_broadcaster_fee(uint!(1_U256)),
        uint!(2_U256)
    );
}

#[test]
fn fee_handling_mode_deducts_or_adds_fee() {
    let entered = uint!(100_U256);
    let fee = uint!(7_U256);

    let deducted = public_broadcaster_amount_split(entered, fee, FeeHandlingMode::DeductFromAmount)
        .expect("deduct split");
    assert_eq!(deducted.receiver_amount, uint!(93_U256));
    assert_eq!(deducted.total_private_spend, entered);

    let added = public_broadcaster_amount_split(entered, fee, FeeHandlingMode::AddToAmount)
        .expect("add split");
    assert_eq!(added.receiver_amount, entered);
    assert_eq!(added.total_private_spend, uint!(107_U256));
}

#[test]
fn different_token_fee_handling_preserves_selected_mode() {
    let entered = uint!(100_U256);
    let fee = uint!(7_U256);

    let deducted = public_broadcaster_amount_split_for_tokens(
        entered,
        fee,
        FeeHandlingMode::DeductFromAmount,
        false,
    )
    .expect("different-token split");

    assert_eq!(deducted.entered_amount, entered);
    assert_eq!(deducted.receiver_amount, entered);
    assert_eq!(deducted.total_private_spend, entered);
    assert_eq!(deducted.fee_amount, fee);
    assert_eq!(deducted.fee_mode, FeeHandlingMode::DeductFromAmount);

    let added = public_broadcaster_amount_split_for_tokens(
        entered,
        fee,
        FeeHandlingMode::AddToAmount,
        false,
    )
    .expect("different-token add split");

    assert_eq!(added.entered_amount, entered);
    assert_eq!(added.receiver_amount, entered);
    assert_eq!(added.total_private_spend, entered);
    assert_eq!(added.fee_amount, fee);
    assert_eq!(added.fee_mode, FeeHandlingMode::AddToAmount);
    assert_eq!(
        public_broadcaster_max_entered_amount_for_tokens(
            uint!(123_U256),
            fee,
            FeeHandlingMode::DeductFromAmount,
            false,
        ),
        uint!(123_U256)
    );
}

#[test]
fn public_broadcaster_build_error_distinguishes_fee_token_balance() {
    let report = public_broadcaster_build_error(
        BuildError::InsufficientFeeTokenBalance(uint!(123_U256)),
        uint!(7_U256),
        FeeHandlingMode::AddToAmount,
        false,
        U256::ZERO,
    );

    assert_eq!(
        report.to_string(),
        "public broadcaster fee-token max spendable: 123; required fee: 7"
    );
}

#[test]
fn fee_handling_mode_rejects_deducting_full_amount() {
    assert!(
        public_broadcaster_amount_split(
            uint!(7_U256),
            uint!(7_U256),
            FeeHandlingMode::DeductFromAmount,
        )
        .is_err()
    );
}

#[test]
fn public_broadcaster_max_entered_amount_depends_on_fee_handling() {
    let max_receiver_amount = uint!(100_U256);
    let fee = uint!(7_U256);

    assert_eq!(
        public_broadcaster_max_entered_amount(
            max_receiver_amount,
            fee,
            FeeHandlingMode::DeductFromAmount,
        ),
        uint!(107_U256)
    );
    assert_eq!(
        public_broadcaster_max_entered_amount(
            max_receiver_amount,
            fee,
            FeeHandlingMode::AddToAmount,
        ),
        max_receiver_amount
    );
}

#[test]
fn public_broadcaster_estimate_preserves_fee_handling_amount_split() {
    let token = address(0x25);
    let broadcaster = eligible_public_broadcasters(
        &[fee_row(
            1,
            token,
            1_000_000_000_000_000_000,
            0.9,
            "fee-mode",
        )],
        1,
        token,
        None,
        SystemTime::now(),
    )
    .into_iter()
    .next()
    .expect("candidate");
    let entered = uint!(1_000_000_000_U256);
    let selected_total = uint!(2_000_000_000_U256);

    let deducted = approximate_public_broadcaster_cost(
        broadcaster.clone(),
        token,
        token,
        entered,
        FeeHandlingMode::DeductFromAmount,
        U256::ZERO,
        100,
        U256::ZERO,
        |_split| {
            let selection = selection_info(selected_total, 1, 1, 2, 0, selected_total);
            Ok(send_approximate_shape(&selection, selected_total))
        },
    )
    .expect("deduct estimate");
    assert_eq!(deducted.entered_amount, entered);
    assert_eq!(deducted.total_private_spend, entered);
    assert_eq!(deducted.receiver_amount + deducted.fee_amount, entered);
    assert_eq!(deducted.protocol_fee_amount, U256::ZERO);
    assert_eq!(deducted.recipient_amount, deducted.receiver_amount);
    assert_eq!(deducted.fee_mode, FeeHandlingMode::DeductFromAmount);

    let added = approximate_public_broadcaster_cost(
        broadcaster,
        token,
        token,
        entered,
        FeeHandlingMode::AddToAmount,
        U256::ZERO,
        100,
        U256::ZERO,
        |_split| {
            let selection = selection_info(selected_total, 1, 1, 2, 0, selected_total);
            Ok(send_approximate_shape(&selection, selected_total))
        },
    )
    .expect("add estimate");
    assert_eq!(added.entered_amount, entered);
    assert_eq!(added.receiver_amount, entered);
    assert_eq!(added.total_private_spend, entered + added.fee_amount);
    assert_eq!(added.protocol_fee_amount, U256::ZERO);
    assert_eq!(added.recipient_amount, added.receiver_amount);
    assert_eq!(added.fee_mode, FeeHandlingMode::AddToAmount);
}

#[test]
fn public_broadcaster_estimate_reports_separate_fee_token_amounts() {
    let action_token = address(0x41);
    let fee_token = address(0x42);
    let broadcaster = eligible_public_broadcasters(
        &[fee_row(
            1,
            fee_token,
            1_000_000_000_000_000_000,
            0.9,
            "separate-fee",
        )],
        1,
        fee_token,
        None,
        SystemTime::now(),
    )
    .into_iter()
    .next()
    .expect("candidate");
    let entered = uint!(1_000_000_000_U256);
    let max_receiver = uint!(2_000_000_000_U256);
    let seed_shape = ApproximateTransactionShape {
        transaction_count: 2,
        input_count: 2,
        private_output_count: 3,
        public_output_count: 0,
        max_receiver_amount: max_receiver,
        unwrap: false,
        send: true,
    };
    let initial_fee_amount =
        initial_separate_token_public_broadcaster_fee(&broadcaster, 100, seed_shape);
    let mut observed_fee_amounts = Vec::new();

    let estimate = approximate_public_broadcaster_cost(
        broadcaster,
        action_token,
        fee_token,
        entered,
        FeeHandlingMode::DeductFromAmount,
        U256::ZERO,
        100,
        initial_fee_amount,
        |split| {
            observed_fee_amounts.push(split.fee_amount);
            let selection = selection_info(max_receiver, 2, 2, 3, 0, max_receiver);
            Ok(send_approximate_shape(&selection, max_receiver))
        },
    )
    .expect("separate-token estimate");

    assert_eq!(estimate.action_token, action_token);
    assert_eq!(estimate.fee_token, fee_token);
    assert_eq!(estimate.entered_amount, entered);
    assert_eq!(estimate.receiver_amount, entered);
    assert_eq!(estimate.total_private_spend, entered);
    assert_eq!(estimate.recipient_amount, entered);
    assert_eq!(estimate.fee_mode, FeeHandlingMode::DeductFromAmount);
    assert_eq!(estimate.max_receiver_amount, max_receiver);
    assert_eq!(estimate.max_entered_amount, max_receiver);
    assert_eq!(estimate.transaction_count, 2);
    assert!(!initial_fee_amount.is_zero());
    assert_eq!(observed_fee_amounts.first(), Some(&initial_fee_amount));
    assert!(observed_fee_amounts.iter().all(|fee| !fee.is_zero()));
}

#[test]
fn public_broadcaster_unshield_estimate_includes_protocol_fee() {
    let token = address(0x26);
    let broadcaster = eligible_public_broadcasters(
        &[fee_row(
            1,
            token,
            1_000_000_000_000_000_000,
            0.9,
            "unshield-fee",
        )],
        1,
        token,
        None,
        SystemTime::now(),
    )
    .into_iter()
    .next()
    .expect("candidate");
    let entered = uint!(1_000_000_U256);
    let selected_total = uint!(2_000_000_U256);

    let estimate = approximate_public_broadcaster_cost(
        broadcaster,
        token,
        token,
        entered,
        FeeHandlingMode::AddToAmount,
        RAILGUN_UNSHIELD_PROTOCOL_FEE_BPS,
        100,
        U256::ZERO,
        |_split| {
            let selection = selection_info(selected_total, 1, 1, 1, 1, selected_total);
            Ok(unshield_approximate_shape(
                &selection,
                selected_total,
                false,
            ))
        },
    )
    .expect("unshield estimate");

    let expected_fee = estimate.receiver_amount * uint!(25_U256) / uint!(10_000_U256);
    assert_eq!(estimate.protocol_fee_bps, RAILGUN_UNSHIELD_PROTOCOL_FEE_BPS);
    assert_eq!(estimate.receiver_amount, uint!(1_002_506_U256));
    assert_eq!(estimate.protocol_fee_amount, expected_fee);
    assert_eq!(estimate.recipient_amount, entered);
    assert_eq!(
        estimate.total_private_spend,
        estimate.receiver_amount + estimate.fee_amount
    );
}

#[test]
fn approximate_public_broadcaster_gas_tracks_transaction_shape() {
    let base = approximate_public_broadcaster_gas(ApproximateTransactionShape {
        transaction_count: 1,
        input_count: 1,
        private_output_count: 2,
        public_output_count: 0,
        max_receiver_amount: U256::ZERO,
        unwrap: false,
        send: true,
    });
    let larger = approximate_public_broadcaster_gas(ApproximateTransactionShape {
        transaction_count: 2,
        input_count: 2,
        private_output_count: 3,
        public_output_count: 1,
        max_receiver_amount: U256::ZERO,
        unwrap: true,
        send: false,
    });

    assert!(larger > base);
}

#[test]
fn approximate_public_broadcaster_gas_applies_safety_uplift() {
    let gas = approximate_public_broadcaster_gas(ApproximateTransactionShape {
        transaction_count: 2,
        input_count: 2,
        private_output_count: 4,
        public_output_count: 0,
        max_receiver_amount: U256::ZERO,
        unwrap: false,
        send: true,
    });

    assert_eq!(gas, 1_803_200);
}

#[test]
fn public_broadcaster_gas_limit_uses_configured_buffer() {
    assert_eq!(
        public_broadcaster_gas_limit_with_buffer(210_000, 250_000),
        460_000
    );
}

#[test]
fn approximate_shapes_include_broadcaster_fee_output_and_change() {
    let send_selection = selection_info(uint!(15_U256), 2, 1, 3, 0, uint!(13_U256));
    let send = send_approximate_shape(&send_selection, uint!(13_U256));
    assert_eq!(send.input_count, 2);
    assert_eq!(send.transaction_count, 1);
    assert_eq!(send.private_output_count, 3);
    assert_eq!(send.public_output_count, 0);

    let unshield_selection = selection_info(uint!(12_U256), 1, 1, 1, 1, uint!(10_U256));
    let unshield = unshield_approximate_shape(&unshield_selection, uint!(10_U256), true);
    assert_eq!(unshield.input_count, 1);
    assert_eq!(unshield.transaction_count, 1);
    assert_eq!(unshield.private_output_count, 1);
    assert_eq!(unshield.public_output_count, 1);
    assert!(unshield.unwrap);
}

#[test]
fn public_broadcaster_transact_envelope_roundtrips() {
    let (candidate, broadcaster) = sample_public_broadcaster_candidate(9);
    let params = public_broadcaster_transact_params(
        &candidate,
        address(0x33),
        Bytes::from(vec![1, 2, 3, 4]),
        20_000_000_000,
        BTreeMap::new(),
    );

    let encrypted = EncryptedTransactRequest::encrypt_with_seed(
        candidate.viewing_public_key,
        &params,
        [8u8; 32],
    )
    .expect("encrypt request");
    let payload = encrypted.to_transact_payload().expect("serialize envelope");
    let value: serde_json::Value = serde_json::from_slice(&payload).expect("json envelope");
    assert_eq!(value["method"], "transact");
    assert!(value["params"]["encryptedData"].is_array());
    assert_eq!(transact_topic(1), "/railgun/v2/0-1-transact/json");

    let decrypted = try_decrypt_transact_request(
        &broadcaster.viewing_private_key,
        encrypted.pubkey,
        &encrypted.encrypted_data,
    )
    .expect("decrypt request")
    .expect("request for broadcaster");
    assert_eq!(decrypted.params.fees_id.as_deref(), Some("fees-id"));
    assert_eq!(
        decrypted.params.min_gas_price,
        Some(uint!(20_000_000_000_U256))
    );
    assert!(
        decrypted
            .params
            .pre_transaction_pois_per_txid_leaf_per_list
            .is_empty()
    );
}

#[test]
fn public_broadcaster_transact_payload_includes_single_chunk_poi() {
    let (mut candidate, broadcaster) = sample_public_broadcaster_candidate(10);
    let list_key = FixedBytes::from([0x88; 32]);
    let txid_leaf = FixedBytes::from([0x99; 32]);
    candidate.required_poi_list_keys = vec![hex::encode(list_key)];
    let required_keys = candidate
        .parsed_required_poi_list_keys()
        .expect("required list keys");
    let params = public_broadcaster_transact_params(
        &candidate,
        address(0x33),
        Bytes::from(vec![1, 2, 3, 4]),
        20_000_000_000,
        sample_poi_map(&required_keys, &[txid_leaf]),
    );

    let encrypted = EncryptedTransactRequest::encrypt_with_seed(
        candidate.viewing_public_key,
        &params,
        [8u8; 32],
    )
    .expect("encrypt request");
    let decrypted = try_decrypt_transact_request(
        &broadcaster.viewing_private_key,
        encrypted.pubkey,
        &encrypted.encrypted_data,
    )
    .expect("decrypt request")
    .expect("request for broadcaster");

    let per_leaf = decrypted
        .params
        .pre_transaction_pois_per_txid_leaf_per_list
        .get(&list_key)
        .expect("list key");
    assert_eq!(per_leaf.len(), 1);
    assert!(per_leaf.contains_key(&txid_leaf));
}

#[test]
fn public_broadcaster_transact_payload_includes_batched_poi() {
    let (mut candidate, broadcaster) = sample_public_broadcaster_candidate(11);
    let list_keys = [FixedBytes::from([0x81; 32]), FixedBytes::from([0x82; 32])];
    let leaves = [FixedBytes::from([0x91; 32]), FixedBytes::from([0x92; 32])];
    candidate.required_poi_list_keys = list_keys.iter().map(hex::encode).collect();
    let required_keys = candidate
        .parsed_required_poi_list_keys()
        .expect("required list keys");
    let params = public_broadcaster_transact_params(
        &candidate,
        address(0x33),
        Bytes::from(vec![1, 2, 3, 4]),
        20_000_000_000,
        sample_poi_map(&required_keys, &leaves),
    );

    let encrypted = EncryptedTransactRequest::encrypt_with_seed(
        candidate.viewing_public_key,
        &params,
        [8u8; 32],
    )
    .expect("encrypt request");
    let decrypted = try_decrypt_transact_request(
        &broadcaster.viewing_private_key,
        encrypted.pubkey,
        &encrypted.encrypted_data,
    )
    .expect("decrypt request")
    .expect("request for broadcaster");

    let poi_map = decrypted.params.pre_transaction_pois_per_txid_leaf_per_list;
    assert_eq!(poi_map.len(), 2);
    for list_key in list_keys {
        let per_leaf = poi_map.get(&list_key).expect("list key");
        assert_eq!(per_leaf.len(), 2);
        for leaf in leaves {
            assert!(per_leaf.contains_key(&leaf));
        }
    }
}

#[test]
fn public_broadcaster_invalid_poi_list_key_fails_preparation() {
    let (mut candidate, _) = sample_public_broadcaster_candidate(12);
    candidate.required_poi_list_keys = vec!["poi-list".to_string()];

    let error = candidate
        .parsed_required_poi_list_keys()
        .expect_err("invalid POI list key should fail");

    assert!(error.to_string().contains("invalid required POI list key"));
}

#[test]
fn public_broadcaster_response_decodes_tx_hash() {
    let shared_key = [7u8; 32];
    let tx_hash = TxHash::from([3u8; 32]);
    let response = DecryptedTransactResponse::encrypted_tx_hash_message(None, &shared_key, tx_hash)
        .expect("response payload");

    let decoded = decode_public_broadcaster_response(&shared_key, &response)
        .expect("decode response")
        .expect("decryptable response");

    assert_eq!(
        decoded,
        PublicBroadcasterResultKind::Submitted {
            tx_hash: tx_hash.to_string()
        }
    );
}

#[test]
fn public_broadcaster_republish_loop_retries_until_stopped() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("build runtime");

    runtime.block_on(async {
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let (attempt_tx, mut attempt_rx) = tokio::sync::mpsc::unbounded_channel();
        let handle = tokio::spawn(public_broadcaster_republish_loop(
            stop_rx,
            Duration::from_millis(10),
            move |attempt| {
                let attempt_tx = attempt_tx.clone();
                async move {
                    attempt_tx.send(attempt).expect("record attempt");
                    Ok(())
                }
            },
        ));

        let first = tokio::time::timeout(Duration::from_secs(1), attempt_rx.recv())
            .await
            .expect("first retry timed out")
            .expect("first retry attempt");
        let second = tokio::time::timeout(Duration::from_secs(1), attempt_rx.recv())
            .await
            .expect("second retry timed out")
            .expect("second retry attempt");
        let _ = stop_tx.send(());
        handle.await.expect("republish loop joined");

        assert_eq!(first, 2);
        assert_eq!(second, 3);
    });
}

#[test]
fn public_broadcaster_republish_loop_stops_before_first_retry() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("build runtime");

    runtime.block_on(async {
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let (attempt_tx, mut attempt_rx) = tokio::sync::mpsc::unbounded_channel();
        let handle = tokio::spawn(public_broadcaster_republish_loop(
            stop_rx,
            Duration::from_millis(50),
            move |attempt| {
                let attempt_tx = attempt_tx.clone();
                async move {
                    attempt_tx.send(attempt).expect("record attempt");
                    Ok(())
                }
            },
        ));
        let _ = stop_tx.send(());
        handle.await.expect("republish loop joined");

        assert!(attempt_rx.try_recv().is_err());
    });
}

#[test]
fn wrapped_native_detection_matches_supported_chains() {
    let weth = wrapped_native_token_for_chain(1).expect("ethereum wrapped native");
    assert!(is_wrapped_native_token(1, weth));
    assert!(!is_wrapped_native_token(1, address(0x11)));
    assert!(wrapped_native_token_for_chain(999_999).is_none());
}
