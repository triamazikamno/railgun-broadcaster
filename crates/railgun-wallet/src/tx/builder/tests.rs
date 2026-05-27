use std::cell::Cell;
use std::sync::Mutex;

use super::*;
use crate::artifacts::ArtifactSource;
use async_trait::async_trait;
use broadcaster_core::utxo::{UtxoCommitmentKind, UtxoSource};

struct MockSpendSigner {
    signed_msg: Cell<Option<U256>>,
}

impl RailgunSpendSigner for MockSpendSigner {
    fn spending_public_key(&self) -> [U256; 2] {
        [uint!(11_U256), uint!(12_U256)]
    }

    fn sign_spend_message(&self, msg: U256) -> [U256; 3] {
        self.signed_msg.set(Some(msg));
        [uint!(1_U256), uint!(2_U256), uint!(3_U256)]
    }
}

#[derive(Default)]
struct FailingLocalPoiProofSource {
    calls: Mutex<usize>,
    commitment_counts: Mutex<Vec<usize>>,
}

impl FailingLocalPoiProofSource {
    fn calls(&self) -> usize {
        *self.calls.lock().expect("calls")
    }

    fn commitment_counts(&self) -> Vec<usize> {
        self.commitment_counts
            .lock()
            .expect("commitment counts")
            .clone()
    }
}

#[async_trait]
impl PoiMerkleProofSource for FailingLocalPoiProofSource {
    async fn poi_merkle_proofs(
        &self,
        _txid_version: &str,
        _chain_type: u8,
        _chain_id: u64,
        _list_key: &FixedBytes<32>,
        blinded_commitments: &[FixedBytes<32>],
    ) -> Result<Vec<PoiMerkleProof>, PreTransactionPoiError> {
        *self.calls.lock().expect("calls") += 1;
        self.commitment_counts
            .lock()
            .expect("commitment counts")
            .push(blinded_commitments.len());
        Err(PreTransactionPoiError::ProofSource(
            "local cache unavailable".to_string(),
        ))
    }
}

fn test_utxo(token: Address, value: u64, tree: u32, position: u64) -> Utxo {
    Utxo::new(
        Note::new_unshield(Address::ZERO, token, U256::from(value)),
        tree,
        position,
        UtxoSource {
            tx_hash: FixedBytes::ZERO,
            block_number: 1,
            block_timestamp: 1,
        },
        UtxoCommitmentKind::Transact,
    )
}

fn selected_positions(selection: &[Utxo]) -> Vec<u64> {
    selection.iter().map(|utxo| utxo.position).collect()
}

fn dummy_merkle_proof(leaf: U256, leaf_index: u64) -> MerkleProof {
    MerkleProof {
        root: U256::ZERO,
        leaf,
        leaf_index,
        path_elements: [U256::ZERO; TREE_DEPTH],
        path_indices: [0u8; TREE_DEPTH],
    }
}

fn sample_chunk(
    seed: u8,
    input_count: usize,
    private_output_count: usize,
    has_unshield: bool,
) -> TransactionPlanChunk {
    let token = Address::from([seed; 20]);
    let inputs = (0..input_count)
        .map(|index| {
            let utxo = test_utxo(
                token,
                u64::try_from(index + 1).unwrap(),
                seed.into(),
                index as u64,
            );
            InputWitness {
                merkle_proof: dummy_merkle_proof(utxo.note.commitment(), index as u64),
                utxo,
            }
        })
        .collect::<Vec<_>>();
    let mut outputs = (0..private_output_count)
        .map(|index| {
            Note::new_change(
                U256::from(1_000_u64 + u64::from(seed) + index as u64),
                token,
                U256::from(10_u64 + index as u64),
                [seed.saturating_add(index as u8); 16],
            )
        })
        .collect::<Vec<_>>();
    if has_unshield {
        outputs.push(Note::new_unshield(
            Address::from([seed.saturating_add(1); 20]),
            token,
            uint!(5_U256),
        ));
    }

    let public_inputs = PublicInputs {
        merkle_root: uint!(7_U256),
        bound_params_hash: U256::from(2_000_u64 + u64::from(seed)),
        nullifiers: (0..input_count)
            .map(|index| U256::from(3_000_u64 + u64::from(seed) + index as u64))
            .collect(),
        commitments_out: outputs.iter().map(Note::commitment).collect(),
    };
    let private_inputs = PrivateInputs {
        token_address: U256::from_be_slice(token.as_slice()),
        random_in: inputs
            .iter()
            .map(|input| U256::from_be_slice(&input.utxo.note.random))
            .collect(),
        value_in: inputs.iter().map(|input| input.utxo.note.value).collect(),
        path_elements: vec![U256::ZERO; input_count * TREE_DEPTH],
        leaves_indices: inputs
            .iter()
            .map(|input| U256::from(input.utxo.position))
            .collect(),
        value_out: outputs.iter().map(|note| note.value).collect(),
        public_key: [uint!(11_U256), uint!(12_U256)],
        npk_out: outputs.iter().map(|note| note.npk).collect(),
        nullifying_key: uint!(13_U256),
    };

    TransactionPlanChunk {
        tree_number: seed.into(),
        merkle_root: uint!(7_U256),
        inputs,
        outputs,
        has_unshield,
        public_inputs,
        private_inputs,
        signature: [uint!(1_U256), uint!(2_U256), uint!(3_U256)],
    }
}

fn sample_poi_merkle_proofs(blinded_commitments: &[FixedBytes<32>]) -> Vec<PoiMerkleProof> {
    blinded_commitments
        .iter()
        .enumerate()
        .map(|(index, blinded_commitment)| PoiMerkleProof {
            leaf: hex::encode_prefixed(blinded_commitment),
            elements: (0..TREE_DEPTH)
                .map(|level| format!("0x{:064x}", index + level + 1))
                .collect(),
            indices: format!("0x{index:064x}"),
            root: format!("0x{:064x}", 100 + index),
        })
        .collect()
}

fn sample_pre_tx_poi() -> PreTxPoi {
    PreTxPoi {
        snark_proof: SnarkJsProof::zero(),
        txid_merkleroot: FixedBytes::ZERO,
        poi_merkleroots: vec![FixedBytes::ZERO],
        blinded_commitments_out: vec![FixedBytes::ZERO],
        railgun_txid_if_has_unshield: Bytes::copy_from_slice(&[0_u8]),
    }
}

fn sample_post_txid_data(
    chunk: &TransactionPlanChunk,
    utxo_batch_global_start_position_out: U256,
) -> PostTransactionPoiData {
    let railgun_txid = compute_railgun_txid_from_public_inputs(&chunk.public_inputs);
    let txid_leaf_hash = poseidon(vec![
        railgun_txid,
        U256::from(chunk.tree_number),
        utxo_batch_global_start_position_out,
    ]);

    PostTransactionPoiData {
        txid_leaf_hash: FixedBytes::from(txid_leaf_hash.to_be_bytes::<32>()),
        txid_merkleroot: FixedBytes::from([0x77; 32]),
        txid_merkleroot_index: 123,
        txid_merkle_proof_indices: uint!(9_U256),
        txid_merkle_proof_path_elements: vec![uint!(8_U256); TREE_DEPTH],
        utxo_batch_global_start_position_out,
    }
}

fn sample_address_data(seed: u8) -> ViewingKeyData {
    ViewingKeyData::from_spending_public_key([seed; 32], [U256::from(seed), U256::from(seed + 1)])
}

#[tokio::test]
async fn pre_transaction_poi_generation_uses_configured_proof_source() {
    let chunk = sample_chunk(11, 1, 1, false);
    let source = FailingLocalPoiProofSource::default();
    let prover = ProverService::with_capacity_db(ArtifactSource::default(), 1, None);
    let err = generate_pre_transaction_pois(PreTransactionPoiGenerationRequest {
        chunks: &[chunk],
        chain_type: 0,
        chain_id: 1,
        txid_version: Some(DEFAULT_TXID_VERSION),
        required_poi_list_keys: &[FixedBytes::from([0x11; 32])],
        proof_source: &source,
        prover: &prover,
        verify_proof: false,
    })
    .await
    .expect_err("local proof source error should fail generation");

    assert!(matches!(err, PreTransactionPoiError::ProofSource(_)));
    assert_eq!(source.calls(), 1);
}

#[tokio::test]
async fn pre_transaction_poi_generation_batches_merkle_proof_source_by_list() {
    let chunks = [sample_chunk(11, 1, 1, false), sample_chunk(12, 1, 1, false)];
    let source = FailingLocalPoiProofSource::default();
    let prover = ProverService::with_capacity_db(ArtifactSource::default(), 1, None);
    let err = generate_pre_transaction_pois(PreTransactionPoiGenerationRequest {
        chunks: &chunks,
        chain_type: 0,
        chain_id: 1,
        txid_version: Some(DEFAULT_TXID_VERSION),
        required_poi_list_keys: &[FixedBytes::from([0x11; 32])],
        proof_source: &source,
        prover: &prover,
        verify_proof: false,
    })
    .await
    .expect_err("local proof source error should fail generation");

    assert!(matches!(err, PreTransactionPoiError::ProofSource(_)));
    assert_eq!(source.calls(), 1);
    assert_eq!(source.commitment_counts(), vec![2]);
}

#[tokio::test]
async fn post_transaction_poi_generation_uses_configured_proof_source() {
    let chunk = sample_chunk(12, 1, 1, false);
    let txid_data = sample_post_txid_data(&chunk, uint!(5_U256));
    let source = FailingLocalPoiProofSource::default();
    let prover = ProverService::with_capacity_db(ArtifactSource::default(), 1, None);
    let err = generate_post_transaction_pois(PostTransactionPoiGenerationRequest {
        chunk: &chunk,
        txid_data: &txid_data,
        chain_type: 0,
        chain_id: 1,
        txid_version: Some(DEFAULT_TXID_VERSION),
        required_poi_list_keys: &[FixedBytes::from([0x11; 32])],
        proof_source: &source,
        prover: &prover,
        verify_proof: false,
    })
    .await
    .expect_err("local proof source error should fail generation");

    assert!(matches!(err, PreTransactionPoiError::ProofSource(_)));
    assert_eq!(source.calls(), 1);
}

#[test]
fn unproven_send_uses_proof_root_from_dirty_forest() {
    let token = Address::from([0xaa; 20]);
    let input = test_utxo(token, 10, 0, 0);
    let mut forest = MerkleForest::new();
    forest
        .insert_leaf(merkletree::tree::MerkleTreeUpdate {
            tree_number: input.tree,
            tree_position: input.position,
            hash: input.note.commitment(),
        })
        .expect("insert leaf");
    assert_eq!(forest.roots().get(&input.tree), Some(&U256::ZERO));

    let sender = sample_address_data(21);
    let recipient = sample_address_data(22).address_data();
    let outputs = build_send_outputs(
        token,
        uint!(4_U256),
        uint!(6_U256),
        &sender.address_data(),
        &recipient,
        None,
        &sender.viewing_private_key,
    )
    .expect("send outputs");
    let builder = TransactionBuilder {
        chain_type: 0,
        chain_id: 1,
        railgun_contract: Address::ZERO,
        relay_adapt_contract: Address::ZERO,
    };
    let signer = MockSpendSigner {
        signed_msg: Cell::new(None),
    };
    let prover = ProverService::with_capacity_db(ArtifactSource::default(), 1, None);
    let plan_builder = TransactionPlanBuilder::new(
        &builder,
        &sender,
        &signer,
        &forest,
        &prover,
        vec![input.clone()],
        token,
    )
    .expect("plan builder");

    let plan = plan_builder
        .build_unproven_send(
            SendRequest {
                token_address: token,
                amount: uint!(4_U256),
                recipient,
                verify_proof: false,
                spend_up_to: false,
                broadcaster_fee: None,
                min_gas_price: 0,
            },
            outputs.outputs,
            outputs.commitment_ciphertext,
            None,
        )
        .expect("unproven send");
    let expected_root = forest
        .prove(input.tree, input.position)
        .expect("proof")
        .root;

    assert_ne!(expected_root, U256::ZERO);
    assert_eq!(plan.merkle_root, expected_root);
    assert_eq!(plan.inputs[0].merkle_proof.root, expected_root);
    assert_eq!(
        plan.transaction.merkleRoot,
        FixedBytes::from(expected_root.to_be_bytes::<32>())
    );
}

#[test]
fn poi_circuit_variant_selects_smallest_supported_variant() {
    assert_eq!(
        poi_circuit_variant(3, 3),
        PoiCircuitVariant {
            max_inputs: 3,
            max_outputs: 3,
        }
    );
    assert_eq!(
        poi_circuit_variant(4, 3),
        PoiCircuitVariant {
            max_inputs: 13,
            max_outputs: 13,
        }
    );
    assert_eq!(
        poi_circuit_variant(3, 4),
        PoiCircuitVariant {
            max_inputs: 13,
            max_outputs: 13,
        }
    );
}

#[test]
fn pre_transaction_poi_inputs_exclude_unshield_output_from_blinded_outputs() {
    let chunk = sample_chunk(31, 2, 2, true);

    let chunk_inputs = chunk.pre_transaction_poi_inputs().expect("chunk inputs");
    let proof_inputs = chunk_inputs
        .proof_inputs(&sample_poi_merkle_proofs(
            &chunk_inputs.blinded_commitments_in,
        ))
        .expect("proof inputs");

    assert_eq!(chunk_inputs.blinded_commitments_in.len(), 2);
    assert_eq!(chunk_inputs.blinded_commitments_out.len(), 2);
    assert_eq!(chunk_inputs.railgun_txid_if_has_unshield.len(), 32);
    assert_eq!(proof_inputs.commitments_out.len(), 3);
    assert_eq!(proof_inputs.npks_out.len(), 2);
    assert_eq!(proof_inputs.values_out.len(), 2);
    assert_ne!(proof_inputs.railgun_txid_if_has_unshield, U256::ZERO);
    assert_eq!(proof_inputs.poi_merkleroots.len(), 2);
    assert_eq!(proof_inputs.poi_in_merkle_proof_path_elements[0].len(), 16);
}

#[test]
fn pre_transaction_poi_map_shape_single_chunk_send() {
    let chunk = sample_chunk(41, 1, 1, false);
    let chunk_inputs = chunk.pre_transaction_poi_inputs().expect("chunk inputs");
    let list_key = FixedBytes::from([0x11; 32]);
    let mut map = BTreeMap::new();

    insert_pre_transaction_poi(
        &mut map,
        list_key,
        chunk_inputs.txid_leaf_hash,
        sample_pre_tx_poi(),
    );

    assert_eq!(map.len(), 1);
    assert!(
        map.get(&list_key)
            .is_some_and(|per_leaf| per_leaf.contains_key(&chunk_inputs.txid_leaf_hash))
    );
    assert_eq!(
        chunk_inputs.railgun_txid_if_has_unshield,
        Bytes::copy_from_slice(&[0_u8])
    );
}

#[test]
fn pre_transaction_poi_map_shape_multi_chunk_unshield() {
    let chunks = [sample_chunk(51, 2, 1, true), sample_chunk(52, 3, 1, true)];
    let list_keys = [FixedBytes::from([0x21; 32]), FixedBytes::from([0x22; 32])];
    let mut map = BTreeMap::new();
    let chunk_inputs = chunks
        .iter()
        .map(TransactionPlanChunk::pre_transaction_poi_inputs)
        .collect::<Result<Vec<_>, _>>()
        .expect("chunk inputs");

    for list_key in list_keys {
        for inputs in &chunk_inputs {
            insert_pre_transaction_poi(
                &mut map,
                list_key,
                inputs.txid_leaf_hash,
                sample_pre_tx_poi(),
            );
        }
    }

    assert_eq!(map.len(), 2);
    for list_key in list_keys {
        let per_leaf = map.get(&list_key).expect("list key");
        assert_eq!(per_leaf.len(), 2);
        for inputs in &chunk_inputs {
            assert!(per_leaf.contains_key(&inputs.txid_leaf_hash));
        }
    }
    assert_ne!(
        chunk_inputs[0].txid_leaf_hash,
        chunk_inputs[1].txid_leaf_hash
    );
}

#[test]
fn post_transaction_poi_inputs_use_included_txid_leaf_and_global_output_positions() {
    let chunk = sample_chunk(61, 2, 2, false);
    let output_start = uint!(65_540_U256);
    let txid_data = sample_post_txid_data(&chunk, output_start);

    let chunk_inputs = chunk
        .post_transaction_poi_inputs(&txid_data)
        .expect("chunk inputs");
    let proof_inputs = chunk_inputs
        .proof_inputs(&sample_poi_merkle_proofs(
            &chunk_inputs.blinded_commitments_in,
        ))
        .expect("proof inputs");

    assert_eq!(chunk_inputs.txid_leaf_hash, txid_data.txid_leaf_hash);
    assert_eq!(chunk_inputs.txid_merkleroot, txid_data.txid_merkleroot);
    assert_eq!(
        proof_inputs.utxo_batch_global_start_position_out,
        output_start
    );
    assert_eq!(
        proof_inputs.railgun_txid_merkle_proof_indices,
        uint!(9_U256)
    );
    assert_eq!(
        proof_inputs.railgun_txid_merkle_proof_path_elements.len(),
        16
    );
    for (index, blinded_commitment) in chunk_inputs.blinded_commitments_out.iter().enumerate() {
        let expected = poseidon(vec![
            chunk.public_inputs.commitments_out[index],
            chunk.private_inputs.npk_out[index],
            output_start + U256::from(index),
        ]);
        assert_eq!(
            *blinded_commitment,
            FixedBytes::from(expected.to_be_bytes::<32>())
        );
    }
}

#[test]
fn post_transaction_poi_zero_value_outputs_use_zero_blinded_commitment() {
    let mut chunk = sample_chunk(63, 1, 2, false);
    chunk.private_inputs.value_out[1] = U256::ZERO;
    let txid_data = sample_post_txid_data(&chunk, uint!(987_654_U256));

    let chunk_inputs = chunk
        .post_transaction_poi_inputs(&txid_data)
        .expect("chunk inputs");

    assert_ne!(chunk.public_inputs.commitments_out[1], U256::ZERO);
    assert_ne!(chunk.private_inputs.npk_out[1], U256::ZERO);
    assert_eq!(chunk_inputs.blinded_commitments_out[1], FixedBytes::ZERO);
    assert_ne!(chunk_inputs.blinded_commitments_out[0], FixedBytes::ZERO);
}

#[test]
fn post_transaction_poi_from_public_signals_uses_canonical_public_outputs() {
    let chunk = sample_chunk(62, 1, 1, false);
    let txid_data = sample_post_txid_data(&chunk, uint!(123_456_U256));
    let chunk_inputs = chunk
        .post_transaction_poi_inputs(&txid_data)
        .expect("chunk inputs");
    let proof_inputs = chunk_inputs
        .proof_inputs(&sample_poi_merkle_proofs(
            &chunk_inputs.blinded_commitments_in,
        ))
        .expect("proof inputs");
    let variant = poi_circuit_variant(
        chunk.public_inputs.nullifiers.len(),
        chunk.public_inputs.commitments_out.len(),
    );
    let mut public_signals = vec![U256::ZERO; variant.max_outputs + 2 + variant.max_inputs];
    public_signals[0] = U256::from_be_bytes(chunk_inputs.blinded_commitments_out[0].0);
    public_signals[variant.max_outputs] = U256::from_be_bytes(txid_data.txid_merkleroot.0);
    public_signals[variant.max_outputs + 1] = U256::ZERO;
    public_signals[variant.max_outputs + 2] = proof_inputs.poi_merkleroots[0];
    public_signals[variant.max_outputs + 3] = MERKLE_ZERO_VALUE;
    public_signals[variant.max_outputs + 4] = MERKLE_ZERO_VALUE;

    let poi = chunk_inputs
        .post_tx_poi_from_public_signals(
            sample_pre_tx_poi().snark_proof,
            &proof_inputs,
            &public_signals,
            variant,
        )
        .expect("post tx poi");

    assert_eq!(poi.txid_merkleroot, txid_data.txid_merkleroot);
    assert_eq!(
        poi.blinded_commitments_out,
        chunk_inputs.blinded_commitments_out
    );
    assert_eq!(poi.poi_merkleroots.len(), 1);
    assert_eq!(
        poi.poi_merkleroots[0],
        FixedBytes::from(proof_inputs.poi_merkleroots[0].to_be_bytes::<32>())
    );
    assert_eq!(
        poi.railgun_txid_if_has_unshield,
        Bytes::copy_from_slice(&[0_u8])
    );

    public_signals[variant.max_outputs + 3] = U256::ZERO;
    let err = chunk_inputs
        .post_tx_poi_from_public_signals(
            sample_pre_tx_poi().snark_proof,
            &proof_inputs,
            &public_signals,
            variant,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        PreTransactionPoiError::PublicSignalMismatch {
            field: "poiMerkleroots",
            ..
        }
    ));
}

#[test]
fn public_inputs_signature_uses_spend_signer_boundary() {
    let public_inputs = PublicInputs {
        merkle_root: uint!(1_U256),
        bound_params_hash: uint!(2_U256),
        nullifiers: vec![uint!(3_U256)],
        commitments_out: vec![uint!(4_U256)],
    };
    let signer = MockSpendSigner {
        signed_msg: Cell::new(None),
    };

    let signature = public_inputs.signature(&signer);

    assert_eq!(signature, [uint!(1_U256), uint!(2_U256), uint!(3_U256)]);
    assert_eq!(
        signer.signed_msg.get(),
        Some(poseidon(public_inputs.signature_message()))
    );
}

#[test]
fn bound_params_min_gas_price_defaults_to_zero_and_accepts_nonzero() {
    let params =
        BoundParams::new_transact(0, 0, 1, Vec::new(), Address::ZERO, UNRELAYED_ADAPT_PARAMS)
            .with_min_gas_price(0)
            .expect("zero min gas price");
    assert_eq!(params.minGasPrice, Uint::<72, 2>::ZERO);

    let params =
        BoundParams::new_transact(0, 0, 1, Vec::new(), Address::ZERO, UNRELAYED_ADAPT_PARAMS)
            .with_min_gas_price(123)
            .expect("nonzero min gas price");
    assert_eq!(params.minGasPrice, Uint::<72, 2>::from(123_u128));
}

#[test]
fn unshield_selection_prefers_fewest_inputs() {
    let token = Address::from([1_u8; 20]);
    let utxos = vec![
        test_utxo(token, 40, 0, 1),
        test_utxo(token, 30, 0, 2),
        test_utxo(token, 5, 0, 3),
    ];

    let (selected, total) = select_utxos(&utxos, token, uint!(35_U256), false, 1).unwrap();

    assert_eq!(total, uint!(40_U256));
    assert_eq!(selected_positions(&selected), vec![1]);
}

#[test]
fn unshield_selection_prefers_exact_match_with_same_input_count() {
    let token = Address::from([2_u8; 20]);
    let utxos = vec![
        test_utxo(token, 12, 0, 1),
        test_utxo(token, 10, 0, 2),
        test_utxo(token, 6, 0, 3),
        test_utxo(token, 5, 0, 4),
    ];

    let (selected, total) = select_utxos(&utxos, token, uint!(16_U256), false, 1).unwrap();

    assert_eq!(total, uint!(16_U256));
    assert_eq!(selected_positions(&selected), vec![2, 3]);
}

#[test]
fn unshield_selection_minimizes_change_with_same_input_count() {
    let token = Address::from([3_u8; 20]);
    let utxos = vec![
        test_utxo(token, 10, 0, 1),
        test_utxo(token, 7, 0, 2),
        test_utxo(token, 6, 0, 3),
    ];

    let (selected, total) = select_utxos(&utxos, token, uint!(12_U256), false, 1).unwrap();

    assert_eq!(total, uint!(13_U256));
    assert_eq!(selected_positions(&selected), vec![2, 3]);
}

#[test]
fn partial_unshield_uses_at_most_twelve_inputs_when_change_is_needed() {
    let token = Address::from([4_u8; 20]);
    let utxos = (0..13)
        .map(|position| test_utxo(token, 2, 0, position))
        .collect::<Vec<_>>();

    let (selected, total) = select_utxos(&utxos, token, uint!(23_U256), false, 1).unwrap();

    assert_eq!(selected.len(), 12);
    assert_eq!(total, uint!(24_U256));
}

#[test]
fn exact_unshield_can_use_thirteen_inputs() {
    let token = Address::from([5_u8; 20]);
    let utxos = (0..13)
        .map(|position| test_utxo(token, 2, 0, position))
        .collect::<Vec<_>>();

    let (selected, total) = select_utxos(&utxos, token, uint!(26_U256), false, 1).unwrap();

    assert_eq!(selected.len(), 13);
    assert_eq!(total, uint!(26_U256));
}

#[test]
fn max_unshield_spendable_uses_eight_batched_chunks() {
    let token = Address::from([6_u8; 20]);
    let mut utxos = (0..20)
        .map(|position| test_utxo(token, 1, 0, position))
        .collect::<Vec<_>>();
    utxos.extend((0..5).map(|position| test_utxo(token, 3, 1, position)));

    assert_eq!(max_unshield_spendable(&utxos, token), uint!(35_U256));
}

#[test]
fn unshield_selection_error_reports_max_single_transaction_amount() {
    let token = Address::from([7_u8; 20]);
    let utxos = (0..13)
        .map(|position| test_utxo(token, 1, 0, position))
        .collect::<Vec<_>>();

    let error = select_utxos(&utxos, token, uint!(14_U256), false, 1).unwrap_err();

    assert!(matches!(error, BuildError::InsufficientBalance(max) if max == uint!(13_U256)));
}

#[test]
fn send_outputs_create_recipient_and_change_notes() {
    let token = Address::from([8_u8; 20]);
    let sender_viewing = sample_address_data(10);
    let sender = sender_viewing.address_data();
    let recipient = sample_address_data(20).address_data();

    let outputs = build_send_outputs(
        token,
        uint!(7_U256),
        uint!(3_U256),
        &sender,
        &recipient,
        None,
        &sender_viewing.viewing_private_key,
    )
    .expect("send outputs");

    assert_eq!(outputs.outputs.len(), 2);
    assert_eq!(outputs.recipient_note.value, uint!(7_U256));
    assert_eq!(
        outputs.recipient_note.npk,
        Note::npk_for(recipient.master_public_key, outputs.recipient_note.random)
    );
    let change_note = outputs.change_note.expect("change note");
    assert_eq!(change_note.value, uint!(3_U256));
    assert_eq!(
        change_note.npk,
        Note::npk_for(sender.master_public_key, change_note.random)
    );
}

#[test]
fn send_outputs_omit_change_for_exact_send() {
    let token = Address::from([9_u8; 20]);
    let sender_viewing = sample_address_data(11);
    let sender = sender_viewing.address_data();
    let recipient = sample_address_data(21).address_data();

    let outputs = build_send_outputs(
        token,
        uint!(7_U256),
        U256::ZERO,
        &sender,
        &recipient,
        None,
        &sender_viewing.viewing_private_key,
    )
    .expect("send outputs");

    assert_eq!(outputs.outputs.len(), 1);
    assert!(outputs.change_note.is_none());
}

#[test]
fn send_outputs_put_broadcaster_fee_note_first() {
    let token = Address::from([14_u8; 20]);
    let sender_viewing = sample_address_data(12);
    let sender = sender_viewing.address_data();
    let recipient = sample_address_data(22).address_data();
    let broadcaster = sample_address_data(32).address_data();

    let outputs = build_send_outputs(
        token,
        uint!(7_U256),
        uint!(3_U256),
        &sender,
        &recipient,
        Some(BroadcasterFeeOutput {
            recipient: broadcaster,
            token_address: token,
            amount: uint!(2_U256),
        }),
        &sender_viewing.viewing_private_key,
    )
    .expect("send outputs");

    assert_eq!(outputs.outputs.len(), 3);
    let fee_note = outputs.broadcaster_fee_note.expect("fee note");
    assert_eq!(outputs.outputs[0].value, uint!(2_U256));
    assert_eq!(fee_note.value, uint!(2_U256));
    assert_eq!(
        outputs.outputs[0].npk,
        Note::npk_for(broadcaster.master_public_key, outputs.outputs[0].random)
    );
    assert_eq!(outputs.outputs[1].value, uint!(7_U256));
    assert_eq!(outputs.outputs[2].value, uint!(3_U256));
}

#[test]
fn unshield_outputs_put_broadcaster_fee_note_first() {
    let token = Address::from([15_u8; 20]);
    let receiver_viewing = sample_address_data(13);
    let receiver = receiver_viewing.address_data();
    let broadcaster = sample_address_data(33).address_data();
    let unshield_to = Address::from([16_u8; 20]);

    let outputs = build_unshield_outputs(
        token,
        uint!(7_U256),
        unshield_to,
        uint!(3_U256),
        &receiver,
        Some(BroadcasterFeeOutput {
            recipient: broadcaster,
            token_address: token,
            amount: uint!(2_U256),
        }),
        &receiver_viewing.viewing_private_key,
    )
    .expect("unshield outputs");

    assert_eq!(outputs.outputs.len(), 3);
    assert_eq!(outputs.commitment_ciphertext.len(), 2);
    let fee_note = outputs.broadcaster_fee_note.expect("fee note");
    assert_eq!(outputs.outputs[0].value, uint!(2_U256));
    assert_eq!(fee_note.value, uint!(2_U256));
    assert_eq!(outputs.outputs[1].value, uint!(3_U256));
    assert_eq!(outputs.outputs[2].value, uint!(7_U256));
    assert_eq!(
        outputs.unshield_note.npk,
        U256::from_be_slice(unshield_to.as_slice())
    );
}

#[test]
fn send_selection_prefers_fewest_inputs() {
    let token = Address::from([10_u8; 20]);
    let utxos = vec![
        test_utxo(token, 40, 0, 1),
        test_utxo(token, 30, 0, 2),
        test_utxo(token, 5, 0, 3),
    ];

    let (selected, total) = select_utxos(&utxos, token, uint!(35_U256), false, 1).unwrap();

    assert_eq!(total, uint!(40_U256));
    assert_eq!(selected_positions(&selected), vec![1]);
}

#[test]
fn partial_send_uses_at_most_twelve_inputs_when_change_is_needed() {
    let token = Address::from([11_u8; 20]);
    let utxos = (0..13)
        .map(|position| test_utxo(token, 2, 0, position))
        .collect::<Vec<_>>();

    let info = send_selection_info(&utxos, token, uint!(23_U256), false).unwrap();

    assert_eq!(info.input_count, 12);
    assert_eq!(info.total, uint!(24_U256));
}

#[test]
fn exact_send_can_use_thirteen_inputs() {
    let token = Address::from([12_u8; 20]);
    let utxos = (0..13)
        .map(|position| test_utxo(token, 2, 0, position))
        .collect::<Vec<_>>();

    let info = send_selection_info(&utxos, token, uint!(26_U256), false).unwrap();

    assert_eq!(info.input_count, 13);
    assert_eq!(info.total, uint!(26_U256));
}

#[test]
fn broadcaster_fee_selection_batches_when_fee_output_reduces_first_chunk() {
    let token = Address::from([17_u8; 20]);
    let utxos = (0..13)
        .map(|position| test_utxo(token, 2, 0, position))
        .collect::<Vec<_>>();

    let info = send_selection_info_with_broadcaster_fee(
        &utxos,
        token,
        uint!(23_U256),
        uint!(3_U256),
        false,
    )
    .unwrap();

    assert_eq!(info.total, uint!(26_U256));
    assert_eq!(info.input_count, 13);
    assert_eq!(info.transaction_count, 2);
    assert_eq!(info.private_output_count, 3);
    assert_eq!(info.public_output_count, 0);
    assert_eq!(info.max_spendable, uint!(23_U256));
}

#[test]
fn same_token_fee_token_selection_preserves_existing_shape() {
    let token = Address::from([23_u8; 20]);
    let utxos = (0..13)
        .map(|position| test_utxo(token, 2, 0, position))
        .collect::<Vec<_>>();

    let existing = send_selection_info_with_broadcaster_fee(
        &utxos,
        token,
        uint!(23_U256),
        uint!(3_U256),
        false,
    )
    .expect("same-token existing selection");
    let selected_fee_token = send_selection_info_with_broadcaster_fee_token(
        &utxos,
        token,
        token,
        uint!(23_U256),
        uint!(3_U256),
        false,
    )
    .expect("same-token fee-token selection");

    assert_eq!(selected_fee_token, existing);
}

#[test]
fn different_token_fee_shape_includes_fee_transaction_first() {
    let action_token = Address::from([24_u8; 20]);
    let fee_token = Address::from([25_u8; 20]);
    let utxos = vec![
        test_utxo(fee_token, 5, 0, 0),
        test_utxo(action_token, 10, 0, 1),
    ];

    let info = send_selection_info_with_broadcaster_fee_token(
        &utxos,
        action_token,
        fee_token,
        uint!(7_U256),
        uint!(3_U256),
        false,
    )
    .expect("different-token selection");

    assert_eq!(info.transaction_count, 2);
    assert_eq!(info.input_count, 2);
    assert_eq!(info.private_output_count, 4);
    assert_eq!(info.public_output_count, 0);
    assert_eq!(info.total, uint!(10_U256));
}

#[test]
fn fee_only_outputs_use_fee_token_and_private_change() {
    let fee_token = Address::from([26_u8; 20]);
    let sender_viewing = sample_address_data(14);
    let sender = sender_viewing.address_data();
    let broadcaster = sample_address_data(34).address_data();

    let outputs = build_fee_only_outputs(
        BroadcasterFeeOutput {
            recipient: broadcaster,
            token_address: fee_token,
            amount: uint!(3_U256),
        },
        uint!(2_U256),
        &sender,
        &sender_viewing.viewing_private_key,
    )
    .expect("fee-only outputs");

    assert_eq!(outputs.outputs.len(), 2);
    assert_eq!(outputs.outputs[0].value, uint!(3_U256));
    assert_eq!(
        outputs.outputs[0].token_hash,
        U256::from_be_slice(fee_token.as_slice())
    );
    assert_eq!(
        outputs.outputs[0].npk,
        Note::npk_for(broadcaster.master_public_key, outputs.outputs[0].random)
    );
    let change = outputs.change_note.expect("fee-token change");
    assert_eq!(outputs.outputs[1].value, uint!(2_U256));
    assert_eq!(
        outputs.outputs[1].token_hash,
        U256::from_be_slice(fee_token.as_slice())
    );
    assert_eq!(change.value, uint!(2_U256));
}

#[test]
fn different_token_fee_selection_reports_fee_token_balance() {
    let action_token = Address::from([27_u8; 20]);
    let fee_token = Address::from([28_u8; 20]);
    let utxos = vec![test_utxo(action_token, 10, 0, 1)];

    let error = send_selection_info_with_broadcaster_fee_token(
        &utxos,
        action_token,
        fee_token,
        uint!(7_U256),
        uint!(3_U256),
        false,
    )
    .expect_err("missing fee token should fail");

    assert!(matches!(error, BuildError::InsufficientFeeTokenBalance(max) if max == U256::ZERO));
}

#[test]
fn fee_token_max_spendable_matches_single_fee_transaction_limit() {
    let fee_token = Address::from([31_u8; 20]);
    let utxos: Vec<_> = (0..20)
        .map(|position| test_utxo(fee_token, 1, 0, position))
        .collect();

    assert_eq!(
        max_broadcaster_fee_token_spendable(&utxos, fee_token),
        U256::from(MAX_CIRCUIT_INPUTS)
    );
}

#[test]
fn separate_fee_seed_selection_reserves_fee_transaction_without_fee_amount() {
    let action_token = Address::from([32_u8; 20]);
    let fee_token = Address::from([33_u8; 20]);
    let utxos = vec![
        test_utxo(fee_token, 1, 0, 100),
        test_utxo(action_token, 10, 0, 1),
    ];

    let info = send_selection_info_with_separate_broadcaster_fee_seed(
        &utxos,
        action_token,
        fee_token,
        uint!(7_U256),
        false,
    )
    .expect("seed selection");

    assert_eq!(info.transaction_count, 2);
    assert_eq!(info.input_count, 2);
    assert_eq!(info.private_output_count, 4);
    assert_eq!(info.max_spendable, uint!(10_U256));
}

#[test]
fn different_token_fee_selection_reserves_one_batch_slot() {
    let action_token = Address::from([29_u8; 20]);
    let fee_token = Address::from([30_u8; 20]);
    let mut utxos = vec![test_utxo(fee_token, 1, 0, 100)];
    utxos.extend(
        (0..8).flat_map(|tree| {
            (0..13).map(move |position| test_utxo(action_token, 1, tree, position))
        }),
    );

    let error = send_selection_info_with_broadcaster_fee_token(
        &utxos,
        action_token,
        fee_token,
        uint!(92_U256),
        uint!(1_U256),
        false,
    )
    .expect_err("fee transaction should reduce action batch capacity");

    assert!(matches!(error, BuildError::InsufficientBalance(max) if max == uint!(91_U256)));
}

#[test]
fn batched_selection_can_use_smaller_first_chunk_for_satisfiable_remainder() {
    let token = Address::from([19_u8; 20]);
    let mut utxos = (0..13)
        .map(|position| test_utxo(token, 2, 0, position))
        .collect::<Vec<_>>();
    utxos.push(test_utxo(token, 1, 1, 0));

    let info = send_selection_info(&utxos, token, uint!(25_U256), false).unwrap();

    assert_eq!(info.total, uint!(25_U256));
    assert_eq!(info.input_count, 13);
    assert_eq!(info.transaction_count, 2);
    assert_eq!(info.private_output_count, 2);
    assert_eq!(info.public_output_count, 0);
}

#[test]
fn max_send_spendable_uses_eight_batched_chunks() {
    let token = Address::from([13_u8; 20]);
    let mut utxos = (0..20)
        .map(|position| test_utxo(token, 1, 0, position))
        .collect::<Vec<_>>();
    utxos.extend((0..5).map(|position| test_utxo(token, 3, 1, position)));

    assert_eq!(max_send_spendable(&utxos, token), uint!(35_U256));
}

#[test]
fn batched_selection_reports_eight_chunk_cap() {
    let token = Address::from([18_u8; 20]);
    let utxos = (0..9)
        .flat_map(|tree| (0..13).map(move |position| test_utxo(token, 1, tree, position)))
        .collect::<Vec<_>>();

    let error = send_selection_info(&utxos, token, uint!(105_U256), false).unwrap_err();

    assert!(matches!(error, BuildError::InsufficientBalance(max) if max == uint!(104_U256)));
}
