use super::*;

#[async_trait]
pub trait PoiMerkleProofSource: Send + Sync {
    async fn poi_merkle_proofs(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_key: &FixedBytes<32>,
        blinded_commitments: &[FixedBytes<32>],
    ) -> Result<Vec<PoiMerkleProof>, PreTransactionPoiError>;
}

#[async_trait]
impl PoiMerkleProofSource for PoiRpcClient {
    async fn poi_merkle_proofs(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_key: &FixedBytes<32>,
        blinded_commitments: &[FixedBytes<32>],
    ) -> Result<Vec<PoiMerkleProof>, PreTransactionPoiError> {
        Ok(PoiRpcClient::poi_merkle_proofs(
            self,
            txid_version,
            chain_type,
            chain_id,
            list_key,
            blinded_commitments,
        )
        .await?)
    }
}

pub type PreTransactionPoiMap = BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PreTxPoi>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoiCircuitVariant {
    pub max_inputs: usize,
    pub max_outputs: usize,
}

#[must_use]
pub const fn poi_circuit_variant(nullifiers: usize, commitments_out: usize) -> PoiCircuitVariant {
    if nullifiers <= 3 && commitments_out <= 3 {
        PoiCircuitVariant {
            max_inputs: 3,
            max_outputs: 3,
        }
    } else {
        PoiCircuitVariant {
            max_inputs: 13,
            max_outputs: 13,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PoiProofInputs {
    pub any_railgun_txid_merkleroot_after_transaction: U256,
    pub bound_params_hash: U256,
    pub nullifiers: Vec<U256>,
    pub commitments_out: Vec<U256>,
    pub spending_public_key: [U256; 2],
    pub nullifying_key: U256,
    pub token: U256,
    pub randoms_in: Vec<U256>,
    pub values_in: Vec<U256>,
    pub utxo_positions_in: Vec<U256>,
    pub utxo_tree_in: U256,
    pub npks_out: Vec<U256>,
    pub values_out: Vec<U256>,
    pub utxo_batch_global_start_position_out: U256,
    pub railgun_txid_if_has_unshield: U256,
    pub railgun_txid_merkle_proof_indices: U256,
    pub railgun_txid_merkle_proof_path_elements: Vec<U256>,
    pub poi_merkleroots: Vec<U256>,
    pub poi_in_merkle_proof_indices: Vec<U256>,
    pub poi_in_merkle_proof_path_elements: Vec<Vec<U256>>,
}

#[derive(Debug, Clone)]
pub struct PreTransactionPoiChunkInputs {
    pub txid_leaf_hash: FixedBytes<32>,
    pub txid_merkleroot: FixedBytes<32>,
    pub blinded_commitments_in: Vec<FixedBytes<32>>,
    pub blinded_commitments_out: Vec<FixedBytes<32>>,
    pub railgun_txid_if_has_unshield: Bytes,
    proof_base_inputs: PoiProofBaseInputs,
}

#[derive(Debug, Clone)]
pub struct PostTransactionPoiData {
    pub txid_leaf_hash: FixedBytes<32>,
    pub txid_merkleroot: FixedBytes<32>,
    pub txid_merkleroot_index: u64,
    pub txid_merkle_proof_indices: U256,
    pub txid_merkle_proof_path_elements: Vec<U256>,
    pub utxo_batch_global_start_position_out: U256,
}

#[derive(Debug, Clone)]
struct PoiProofBaseInputs {
    any_railgun_txid_merkleroot_after_transaction: U256,
    bound_params_hash: U256,
    nullifiers: Vec<U256>,
    commitments_out: Vec<U256>,
    spending_public_key: [U256; 2],
    nullifying_key: U256,
    token: U256,
    randoms_in: Vec<U256>,
    values_in: Vec<U256>,
    utxo_positions_in: Vec<U256>,
    utxo_tree_in: U256,
    npks_out: Vec<U256>,
    values_out: Vec<U256>,
    utxo_batch_global_start_position_out: U256,
    railgun_txid_if_has_unshield: U256,
    railgun_txid_merkle_proof_indices: U256,
    railgun_txid_merkle_proof_path_elements: Vec<U256>,
}

impl PreTransactionPoiChunkInputs {
    pub fn proof_inputs(
        &self,
        merkle_proofs: &[PoiMerkleProof],
    ) -> Result<PoiProofInputs, PreTransactionPoiError> {
        if merkle_proofs.len() != self.blinded_commitments_in.len() {
            return Err(PreTransactionPoiError::MerkleProofCountMismatch {
                expected: self.blinded_commitments_in.len(),
                got: merkle_proofs.len(),
            });
        }

        let mut poi_merkleroots = Vec::with_capacity(merkle_proofs.len());
        let mut poi_in_merkle_proof_indices = Vec::with_capacity(merkle_proofs.len());
        let mut poi_in_merkle_proof_path_elements = Vec::with_capacity(merkle_proofs.len());

        for (index, proof) in merkle_proofs.iter().enumerate() {
            let leaf = parse_fixed_hex(&proof.leaf, "leaf")?;
            let expected = self.blinded_commitments_in[index];
            if leaf != expected {
                return Err(PreTransactionPoiError::MerkleProofLeafMismatch {
                    index,
                    expected,
                    actual: leaf,
                });
            }
            if proof.elements.len() != TREE_DEPTH {
                return Err(PreTransactionPoiError::MerkleProofPathLengthMismatch {
                    index,
                    expected: TREE_DEPTH,
                    got: proof.elements.len(),
                });
            }
            poi_merkleroots.push(parse_u256_hex(&proof.root, "root")?);
            poi_in_merkle_proof_indices.push(parse_u256_hex(&proof.indices, "indices")?);
            poi_in_merkle_proof_path_elements.push(
                proof
                    .elements
                    .iter()
                    .map(|element| parse_u256_hex(element, "elements"))
                    .collect::<Result<Vec<_>, _>>()?,
            );
        }

        Ok(PoiProofInputs {
            any_railgun_txid_merkleroot_after_transaction: self
                .proof_base_inputs
                .any_railgun_txid_merkleroot_after_transaction,
            bound_params_hash: self.proof_base_inputs.bound_params_hash,
            nullifiers: self.proof_base_inputs.nullifiers.clone(),
            commitments_out: self.proof_base_inputs.commitments_out.clone(),
            spending_public_key: self.proof_base_inputs.spending_public_key,
            nullifying_key: self.proof_base_inputs.nullifying_key,
            token: self.proof_base_inputs.token,
            randoms_in: self.proof_base_inputs.randoms_in.clone(),
            values_in: self.proof_base_inputs.values_in.clone(),
            utxo_positions_in: self.proof_base_inputs.utxo_positions_in.clone(),
            utxo_tree_in: self.proof_base_inputs.utxo_tree_in,
            npks_out: self.proof_base_inputs.npks_out.clone(),
            values_out: self.proof_base_inputs.values_out.clone(),
            utxo_batch_global_start_position_out: self
                .proof_base_inputs
                .utxo_batch_global_start_position_out,
            railgun_txid_if_has_unshield: self.proof_base_inputs.railgun_txid_if_has_unshield,
            railgun_txid_merkle_proof_indices: self
                .proof_base_inputs
                .railgun_txid_merkle_proof_indices,
            railgun_txid_merkle_proof_path_elements: self
                .proof_base_inputs
                .railgun_txid_merkle_proof_path_elements
                .clone(),
            poi_merkleroots,
            poi_in_merkle_proof_indices,
            poi_in_merkle_proof_path_elements,
        })
    }

    #[must_use]
    pub fn pre_tx_poi(&self, snark_proof: SnarkJsProof, proof_inputs: &PoiProofInputs) -> PreTxPoi {
        PreTxPoi {
            snark_proof,
            txid_merkleroot: self.txid_merkleroot,
            poi_merkleroots: proof_inputs
                .poi_merkleroots
                .iter()
                .copied()
                .map(|value| FixedBytes::from(value.to_be_bytes::<32>()))
                .collect(),
            blinded_commitments_out: self.blinded_commitments_out.clone(),
            railgun_txid_if_has_unshield: self.railgun_txid_if_has_unshield.clone(),
        }
    }

    pub fn post_tx_poi_from_public_signals(
        &self,
        snark_proof: SnarkJsProof,
        proof_inputs: &PoiProofInputs,
        public_signals: &[U256],
        variant: PoiCircuitVariant,
    ) -> Result<PreTxPoi, PreTransactionPoiError> {
        let expected_len = variant.max_outputs + 2 + variant.max_inputs;
        if public_signals.len() != expected_len {
            return Err(PreTransactionPoiError::PublicSignalCountMismatch {
                expected: expected_len,
                got: public_signals.len(),
            });
        }

        let mut expected_blinded_commitments_out = self.blinded_commitments_out.clone();
        expected_blinded_commitments_out.resize(variant.max_outputs, FixedBytes::ZERO);
        for (index, expected) in expected_blinded_commitments_out.iter().enumerate() {
            validate_public_signal(
                "blindedCommitmentsOut",
                FixedBytes::from(public_signals[index].to_be_bytes::<32>()),
                *expected,
            )?;
        }

        let txid_merkleroot =
            FixedBytes::from(public_signals[variant.max_outputs].to_be_bytes::<32>());
        let expected_txid_merkleroot = FixedBytes::from(
            self.proof_base_inputs
                .any_railgun_txid_merkleroot_after_transaction
                .to_be_bytes::<32>(),
        );
        validate_public_signal("txidMerkleroot", txid_merkleroot, expected_txid_merkleroot)?;

        let railgun_txid_if_has_unshield = public_signals[variant.max_outputs + 1];
        validate_public_signal(
            "railgunTxidIfHasUnshield",
            FixedBytes::from(railgun_txid_if_has_unshield.to_be_bytes::<32>()),
            FixedBytes::from(
                self.proof_base_inputs
                    .railgun_txid_if_has_unshield
                    .to_be_bytes::<32>(),
            ),
        )?;

        let poi_merkleroots_start = variant.max_outputs + 2;
        let mut expected_poi_merkleroots = proof_inputs.poi_merkleroots.clone();
        expected_poi_merkleroots.resize(variant.max_inputs, MERKLE_ZERO_VALUE);
        for (index, expected) in expected_poi_merkleroots.iter().enumerate() {
            let actual = public_signals[poi_merkleroots_start + index];
            validate_public_signal(
                "poiMerkleroots",
                FixedBytes::from(actual.to_be_bytes::<32>()),
                FixedBytes::from(expected.to_be_bytes::<32>()),
            )?;
        }

        let railgun_txid_if_has_unshield = if railgun_txid_if_has_unshield == U256::ZERO {
            Bytes::copy_from_slice(&[0_u8])
        } else {
            Bytes::copy_from_slice(&railgun_txid_if_has_unshield.to_be_bytes::<32>())
        };

        Ok(PreTxPoi {
            snark_proof,
            txid_merkleroot,
            poi_merkleroots: proof_inputs
                .poi_merkleroots
                .iter()
                .copied()
                .map(|value| FixedBytes::from(value.to_be_bytes::<32>()))
                .collect(),
            blinded_commitments_out: public_signals[..self.blinded_commitments_out.len()]
                .iter()
                .copied()
                .map(|value| FixedBytes::from(value.to_be_bytes::<32>()))
                .collect(),
            railgun_txid_if_has_unshield,
        })
    }
}

impl TransactionPlanChunk {
    pub fn pre_transaction_poi_inputs(
        &self,
    ) -> Result<PreTransactionPoiChunkInputs, PreTransactionPoiError> {
        validate_poi_input_count(self)?;
        let private_output_count = self.private_output_count_for_poi()?;

        let railgun_txid = compute_railgun_txid_from_public_inputs(&self.public_inputs);
        let txid_leaf = railgun_txid_leaf_hash(railgun_txid, u64::from(self.tree_number));
        let txid_merkleroot = dummy_txid_root(txid_leaf);
        let railgun_txid_if_has_unshield = railgun_txid_if_has_unshield_bytes(self, railgun_txid);
        let railgun_txid_if_has_unshield_value =
            railgun_txid_if_has_unshield_value(self, railgun_txid);

        Ok(PreTransactionPoiChunkInputs {
            txid_leaf_hash: FixedBytes::from(txid_leaf.to_be_bytes::<32>()),
            txid_merkleroot: FixedBytes::from(txid_merkleroot.to_be_bytes::<32>()),
            blinded_commitments_in: blinded_commitments_in(self),
            blinded_commitments_out: pre_transaction_blinded_commitments_out(
                self,
                private_output_count,
            ),
            railgun_txid_if_has_unshield,
            proof_base_inputs: poi_proof_base_inputs(
                self,
                private_output_count,
                PoiProofBaseContext {
                    any_railgun_txid_merkleroot_after_transaction: txid_merkleroot,
                    utxo_batch_global_start_position_out: pre_transaction_output_global_position(),
                    railgun_txid_if_has_unshield: railgun_txid_if_has_unshield_value,
                    railgun_txid_merkle_proof_indices: U256::ZERO,
                    railgun_txid_merkle_proof_path_elements: vec![U256::ZERO; TREE_DEPTH],
                },
            ),
        })
    }
}

fn validate_poi_input_count(chunk: &TransactionPlanChunk) -> Result<(), PreTransactionPoiError> {
    if chunk.inputs.len() != chunk.public_inputs.nullifiers.len() {
        return Err(PreTransactionPoiError::InputCountMismatch {
            expected: chunk.public_inputs.nullifiers.len(),
            got: chunk.inputs.len(),
        });
    }
    Ok(())
}

fn railgun_txid_if_has_unshield_bytes(chunk: &TransactionPlanChunk, railgun_txid: U256) -> Bytes {
    if chunk.has_unshield {
        Bytes::copy_from_slice(&railgun_txid.to_be_bytes::<32>())
    } else {
        Bytes::copy_from_slice(&[0_u8])
    }
}

fn railgun_txid_if_has_unshield_value(chunk: &TransactionPlanChunk, railgun_txid: U256) -> U256 {
    if chunk.has_unshield {
        railgun_txid
    } else {
        U256::ZERO
    }
}

fn blinded_commitments_in(chunk: &TransactionPlanChunk) -> Vec<FixedBytes<32>> {
    chunk
        .inputs
        .iter()
        .map(|input| input.utxo.poi.blinded_commitment)
        .collect()
}

fn pre_transaction_blinded_commitments_out(
    chunk: &TransactionPlanChunk,
    private_output_count: usize,
) -> Vec<FixedBytes<32>> {
    chunk
        .public_inputs
        .commitments_out
        .iter()
        .take(private_output_count)
        .zip(
            chunk
                .private_inputs
                .npk_out
                .iter()
                .take(private_output_count),
        )
        .enumerate()
        .map(|(index, (commitment, npk))| {
            let global_position = pre_transaction_output_global_position() + U256::from(index);
            poseidon(vec![*commitment, *npk, global_position]).into()
        })
        .collect()
}

fn post_transaction_blinded_commitments_out(
    chunk: &TransactionPlanChunk,
    private_output_count: usize,
    utxo_batch_global_start_position_out: U256,
) -> Vec<FixedBytes<32>> {
    chunk
        .public_inputs
        .commitments_out
        .iter()
        .take(private_output_count)
        .zip(
            chunk
                .private_inputs
                .npk_out
                .iter()
                .take(private_output_count),
        )
        .zip(
            chunk
                .private_inputs
                .value_out
                .iter()
                .take(private_output_count),
        )
        .enumerate()
        .map(|(index, ((commitment, npk), value))| {
            // The post-transaction POI circuit emits zero for zero-value private
            // outputs, not the Poseidon commitment preimage used by non-zero notes.
            if *value == U256::ZERO {
                FixedBytes::ZERO
            } else {
                let global_position = utxo_batch_global_start_position_out + U256::from(index);
                poseidon(vec![*commitment, *npk, global_position]).into()
            }
        })
        .collect()
}

struct PoiProofBaseContext {
    any_railgun_txid_merkleroot_after_transaction: U256,
    utxo_batch_global_start_position_out: U256,
    railgun_txid_if_has_unshield: U256,
    railgun_txid_merkle_proof_indices: U256,
    railgun_txid_merkle_proof_path_elements: Vec<U256>,
}

fn poi_proof_base_inputs(
    chunk: &TransactionPlanChunk,
    private_output_count: usize,
    context: PoiProofBaseContext,
) -> PoiProofBaseInputs {
    PoiProofBaseInputs {
        any_railgun_txid_merkleroot_after_transaction: context
            .any_railgun_txid_merkleroot_after_transaction,
        bound_params_hash: chunk.public_inputs.bound_params_hash,
        nullifiers: chunk.public_inputs.nullifiers.clone(),
        commitments_out: chunk.public_inputs.commitments_out.clone(),
        spending_public_key: chunk.private_inputs.public_key,
        nullifying_key: chunk.private_inputs.nullifying_key,
        token: chunk.private_inputs.token_address,
        randoms_in: chunk.private_inputs.random_in.clone(),
        values_in: chunk.private_inputs.value_in.clone(),
        utxo_positions_in: chunk.private_inputs.leaves_indices.clone(),
        utxo_tree_in: U256::from(chunk.tree_number),
        npks_out: chunk
            .private_inputs
            .npk_out
            .iter()
            .take(private_output_count)
            .copied()
            .collect(),
        values_out: chunk
            .private_inputs
            .value_out
            .iter()
            .take(private_output_count)
            .copied()
            .collect(),
        utxo_batch_global_start_position_out: context.utxo_batch_global_start_position_out,
        railgun_txid_if_has_unshield: context.railgun_txid_if_has_unshield,
        railgun_txid_merkle_proof_indices: context.railgun_txid_merkle_proof_indices,
        railgun_txid_merkle_proof_path_elements: context.railgun_txid_merkle_proof_path_elements,
    }
}

impl TransactionPlanChunk {
    pub fn post_transaction_poi_inputs(
        &self,
        txid_data: &PostTransactionPoiData,
    ) -> Result<PreTransactionPoiChunkInputs, PreTransactionPoiError> {
        validate_poi_input_count(self)?;
        if txid_data.txid_merkle_proof_path_elements.len() != TREE_DEPTH {
            return Err(PreTransactionPoiError::TxidMerkleProofPathLengthMismatch {
                expected: TREE_DEPTH,
                got: txid_data.txid_merkle_proof_path_elements.len(),
            });
        }
        let private_output_count = self.private_output_count_for_poi()?;

        let railgun_txid = compute_railgun_txid_from_public_inputs(&self.public_inputs);
        let expected_txid_leaf = railgun_txid_leaf_hash_with_output_start(
            railgun_txid,
            u64::from(self.tree_number),
            txid_data.utxo_batch_global_start_position_out,
        );
        let expected_txid_leaf_hash = FixedBytes::from(expected_txid_leaf.to_be_bytes::<32>());
        if expected_txid_leaf_hash != txid_data.txid_leaf_hash {
            return Err(PreTransactionPoiError::TxidLeafHashMismatch {
                expected: expected_txid_leaf_hash,
                actual: txid_data.txid_leaf_hash,
            });
        }

        let railgun_txid_if_has_unshield = railgun_txid_if_has_unshield_bytes(self, railgun_txid);
        let railgun_txid_if_has_unshield_value =
            railgun_txid_if_has_unshield_value(self, railgun_txid);

        Ok(PreTransactionPoiChunkInputs {
            txid_leaf_hash: txid_data.txid_leaf_hash,
            txid_merkleroot: txid_data.txid_merkleroot,
            blinded_commitments_in: blinded_commitments_in(self),
            blinded_commitments_out: post_transaction_blinded_commitments_out(
                self,
                private_output_count,
                txid_data.utxo_batch_global_start_position_out,
            ),
            railgun_txid_if_has_unshield,
            proof_base_inputs: poi_proof_base_inputs(
                self,
                private_output_count,
                PoiProofBaseContext {
                    any_railgun_txid_merkleroot_after_transaction: U256::from_be_bytes(
                        txid_data.txid_merkleroot.0,
                    ),
                    utxo_batch_global_start_position_out: txid_data
                        .utxo_batch_global_start_position_out,
                    railgun_txid_if_has_unshield: railgun_txid_if_has_unshield_value,
                    railgun_txid_merkle_proof_indices: txid_data.txid_merkle_proof_indices,
                    railgun_txid_merkle_proof_path_elements: txid_data
                        .txid_merkle_proof_path_elements
                        .clone(),
                },
            ),
        })
    }
}

pub struct PreTransactionPoiGenerationRequest<'a> {
    pub chunks: &'a [TransactionPlanChunk],
    pub chain_type: u8,
    pub chain_id: u64,
    pub txid_version: Option<&'a str>,
    pub required_poi_list_keys: &'a [FixedBytes<32>],
    pub proof_source: &'a (dyn PoiMerkleProofSource + 'a),
    pub prover: &'a ProverService,
    pub verify_proof: bool,
}

pub async fn generate_pre_transaction_pois(
    request: PreTransactionPoiGenerationRequest<'_>,
) -> Result<PreTransactionPoiMap, PreTransactionPoiError> {
    let mut map = BTreeMap::new();
    if request.required_poi_list_keys.is_empty() {
        return Ok(map);
    }
    let txid_version = request.txid_version.unwrap_or(DEFAULT_TXID_VERSION);
    let chunk_inputs = request
        .chunks
        .iter()
        .map(|chunk| {
            chunk
                .pre_transaction_poi_inputs()
                .map(|inputs| (chunk, inputs))
        })
        .collect::<Result<Vec<_>, _>>()?;
    for list_key in request.required_poi_list_keys {
        let blinded_commitments_in = chunk_inputs
            .iter()
            .flat_map(|(_, inputs)| inputs.blinded_commitments_in.iter().copied())
            .collect::<Vec<_>>();
        let merkle_started = Instant::now();
        let all_merkle_proofs = if blinded_commitments_in.is_empty() {
            Vec::new()
        } else {
            request
                .proof_source
                .poi_merkle_proofs(
                    txid_version,
                    request.chain_type,
                    request.chain_id,
                    list_key,
                    &blinded_commitments_in,
                )
                .await?
        };
        let merkle_elapsed_ms = merkle_started.elapsed().as_millis();
        let mut proof_jobs = Vec::with_capacity(chunk_inputs.len());
        let mut proof_offset = 0_usize;
        for (index, (chunk, chunk_inputs)) in chunk_inputs.iter().enumerate() {
            let proof_count = chunk_inputs.blinded_commitments_in.len();
            let proof_end = proof_offset.saturating_add(proof_count);
            let Some(merkle_proofs) = all_merkle_proofs.get(proof_offset..proof_end) else {
                return Err(PreTransactionPoiError::MerkleProofCountMismatch {
                    expected: blinded_commitments_in.len(),
                    got: all_merkle_proofs.len(),
                });
            };
            let proof_inputs = chunk_inputs.proof_inputs(merkle_proofs)?;
            proof_jobs.push((
                index,
                chunk.tree_number,
                chunk.inputs.len(),
                chunk.outputs.len(),
                chunk.has_unshield,
                chunk_inputs.clone(),
                proof_inputs,
            ));
            proof_offset = proof_end;
        }
        if proof_offset != all_merkle_proofs.len() {
            return Err(PreTransactionPoiError::MerkleProofCountMismatch {
                expected: blinded_commitments_in.len(),
                got: all_merkle_proofs.len(),
            });
        }

        let mut handles = Vec::with_capacity(proof_jobs.len());
        for (
            index,
            tree_number,
            input_count,
            output_count,
            has_unshield,
            chunk_inputs,
            proof_inputs,
        ) in proof_jobs
        {
            let prover = request.prover.clone();
            let chain_type = request.chain_type;
            let chain_id = request.chain_id;
            let list_key = *list_key;
            let batched_merkle_commitments = blinded_commitments_in.len();
            let verify_proof = request.verify_proof;
            handles.push(tokio::spawn(async move {
                let prove_started = Instant::now();
                let snark_proof = prover.prove_poi(&proof_inputs, verify_proof).await?;
                let prove_elapsed_ms = prove_started.elapsed().as_millis();
                tracing::debug!(
                    chain_type,
                    chain_id,
                    tree_number,
                    input_count,
                    output_count,
                    has_unshield,
                    list_key = %hex::encode(list_key),
                    batched_merkle_commitments,
                    merkle_elapsed_ms,
                    prove_elapsed_ms,
                    "generated pre-transaction POI proof"
                );
                let txid_leaf_hash = chunk_inputs.txid_leaf_hash;
                let pre_tx_poi = chunk_inputs.pre_tx_poi(snark_proof, &proof_inputs);
                Ok::<_, PreTransactionPoiError>((index, list_key, txid_leaf_hash, pre_tx_poi))
            }));
        }

        let mut proof_results: Vec<Option<(FixedBytes<32>, FixedBytes<32>, PreTxPoi)>> =
            std::iter::repeat_with(|| None)
                .take(handles.len())
                .collect();
        for handle in handles {
            let (index, list_key, txid_leaf_hash, pre_tx_poi) =
                handle.await.map_err(join_error_to_prover_error)??;
            proof_results[index] = Some((list_key, txid_leaf_hash, pre_tx_poi));
        }
        for result in proof_results {
            let (list_key, txid_leaf_hash, pre_tx_poi) = result.expect("all POI proofs generated");
            insert_pre_transaction_poi(&mut map, list_key, txid_leaf_hash, pre_tx_poi);
        }
    }
    Ok(map)
}

pub struct PostTransactionPoiGenerationRequest<'a> {
    pub chunk: &'a TransactionPlanChunk,
    pub txid_data: &'a PostTransactionPoiData,
    pub chain_type: u8,
    pub chain_id: u64,
    pub txid_version: Option<&'a str>,
    pub required_poi_list_keys: &'a [FixedBytes<32>],
    pub proof_source: &'a (dyn PoiMerkleProofSource + 'a),
    pub prover: &'a ProverService,
    pub verify_proof: bool,
}

pub async fn generate_post_transaction_pois(
    request: PostTransactionPoiGenerationRequest<'_>,
) -> Result<PreTransactionPoiMap, PreTransactionPoiError> {
    let mut map = BTreeMap::new();
    if request.required_poi_list_keys.is_empty() {
        return Ok(map);
    }
    let txid_version = request.txid_version.unwrap_or(DEFAULT_TXID_VERSION);
    let chunk_inputs = request
        .chunk
        .post_transaction_poi_inputs(request.txid_data)?;
    for list_key in request.required_poi_list_keys {
        let merkle_started = Instant::now();
        let merkle_proofs = request
            .proof_source
            .poi_merkle_proofs(
                txid_version,
                request.chain_type,
                request.chain_id,
                list_key,
                &chunk_inputs.blinded_commitments_in,
            )
            .await?;
        let merkle_elapsed_ms = merkle_started.elapsed().as_millis();
        let proof_inputs = chunk_inputs.proof_inputs(&merkle_proofs)?;
        let variant = poi_circuit_variant(
            request.chunk.public_inputs.nullifiers.len(),
            request.chunk.public_inputs.commitments_out.len(),
        );
        let prove_started = Instant::now();
        let proof_result = request
            .prover
            .prove_poi_with_public_signals(&proof_inputs, request.verify_proof)
            .await?;
        let prove_elapsed_ms = prove_started.elapsed().as_millis();
        tracing::debug!(
            chain_type = request.chain_type,
            chain_id = request.chain_id,
            tree_number = request.chunk.tree_number,
            input_count = request.chunk.inputs.len(),
            output_count = request.chunk.outputs.len(),
            has_unshield = request.chunk.has_unshield,
            list_key = %hex::encode(list_key),
            txid_merkleroot_index = request.txid_data.txid_merkleroot_index,
            merkle_elapsed_ms,
            prove_elapsed_ms,
            "generated post-transaction POI proof"
        );
        let pre_tx_poi = chunk_inputs.post_tx_poi_from_public_signals(
            proof_result.snark_proof,
            &proof_inputs,
            &proof_result.public_signals,
            variant,
        )?;
        insert_pre_transaction_poi(&mut map, *list_key, chunk_inputs.txid_leaf_hash, pre_tx_poi);
    }
    Ok(map)
}

pub fn insert_pre_transaction_poi(
    map: &mut PreTransactionPoiMap,
    list_key: FixedBytes<32>,
    txid_leaf_hash: FixedBytes<32>,
    pre_tx_poi: PreTxPoi,
) {
    map.entry(list_key)
        .or_default()
        .insert(txid_leaf_hash, pre_tx_poi);
}

pub fn compute_railgun_txid_from_public_inputs(public_inputs: &PublicInputs) -> U256 {
    compute_railgun_txid_parts(
        &public_inputs.nullifiers,
        &public_inputs.commitments_out,
        public_inputs.bound_params_hash,
    )
}

fn validate_public_signal(
    field: &'static str,
    actual: FixedBytes<32>,
    expected: FixedBytes<32>,
) -> Result<(), PreTransactionPoiError> {
    if actual != expected {
        return Err(PreTransactionPoiError::PublicSignalMismatch {
            field,
            expected,
            actual,
        });
    }
    Ok(())
}

fn parse_fixed_hex(
    value: &str,
    field: &'static str,
) -> Result<FixedBytes<32>, PreTransactionPoiError> {
    parse_u256_hex(value, field).map(|value| FixedBytes::from(value.to_be_bytes::<32>()))
}

fn parse_u256_hex(value: &str, field: &'static str) -> Result<U256, PreTransactionPoiError> {
    let value_without_prefix = value.strip_prefix("0x").unwrap_or(value);
    if value_without_prefix.len() > 64 {
        return Err(PreTransactionPoiError::InvalidHex {
            field,
            value: value.to_string(),
        });
    }
    if value_without_prefix.is_empty() {
        return Ok(U256::ZERO);
    }
    U256::from_str_radix(value_without_prefix, 16).map_err(|_| PreTransactionPoiError::InvalidHex {
        field,
        value: value.to_string(),
    })
}
