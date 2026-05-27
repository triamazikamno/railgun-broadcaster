use super::*;

#[async_trait]
pub(crate) trait PoiStatusReader: Send + Sync {
    async fn pois_per_list(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_keys: &[FixedBytes<32>],
        blinded_commitment_datas: &[BlindedCommitmentData],
    ) -> Result<BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PoiStatus>>, PoiError>;
}

#[async_trait]
impl PoiStatusReader for PoiRpcClient {
    async fn pois_per_list(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_keys: &[FixedBytes<32>],
        blinded_commitment_datas: &[BlindedCommitmentData],
    ) -> Result<BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PoiStatus>>, PoiError> {
        PoiRpcClient::pois_per_list(
            self,
            txid_version,
            chain_type,
            chain_id,
            list_keys,
            blinded_commitment_datas,
        )
        .await
    }
}

#[derive(Clone)]
pub(crate) struct LocalPoiStatusReader {
    caches: WalletLocalPoiCaches,
}

impl LocalPoiStatusReader {
    pub(crate) fn new(caches: WalletLocalPoiCaches) -> Self {
        Self { caches }
    }
}

#[async_trait]
impl PoiStatusReader for LocalPoiStatusReader {
    async fn pois_per_list(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_keys: &[FixedBytes<32>],
        blinded_commitment_datas: &[BlindedCommitmentData],
    ) -> Result<BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PoiStatus>>, PoiError> {
        let started = Instant::now();
        let lock_started = Instant::now();
        let caches = self.caches.read().await;
        let lock_wait_elapsed_ms = lock_started.elapsed().as_millis();
        let statuses = blinded_commitment_datas
            .iter()
            .map(|data| {
                let per_list = list_keys
                    .iter()
                    .copied()
                    .map(|list_key| {
                        let status = caches
                            .get(&list_key)
                            .filter(|cache| {
                                cache.identity().chain_type == chain_type
                                    && cache.identity().chain_id == chain_id
                                    && cache.identity().txid_version == txid_version
                            })
                            .map_or(PoiStatus::Unknown, |cache| cache.status_for_data(data));
                        (list_key, status)
                    })
                    .collect();
                (data.blinded_commitment, per_list)
            })
            .collect();
        debug!(
            chain_type,
            chain_id,
            list_keys = list_keys.len(),
            commitments = blinded_commitment_datas.len(),
            lock_wait_elapsed_ms,
            elapsed_ms = started.elapsed().as_millis(),
            "local POI status read complete"
        );
        Ok(statuses)
    }
}

#[derive(Clone)]
pub struct LocalPoiMerkleProofSource {
    caches: WalletLocalPoiCaches,
}

impl LocalPoiMerkleProofSource {
    #[must_use]
    pub const fn new(caches: WalletLocalPoiCaches) -> Self {
        Self { caches }
    }

    pub(super) async fn check_commitments_available(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_key: &FixedBytes<32>,
        blinded_commitments: &[FixedBytes<32>],
    ) -> Result<(), PreTransactionPoiError> {
        let started = Instant::now();
        let lock_started = Instant::now();
        let caches = self.caches.read().await;
        let lock_wait_elapsed_ms = lock_started.elapsed().as_millis();
        let Some(cache) = caches.get(list_key).filter(|cache| {
            cache.identity().chain_type == chain_type
                && cache.identity().chain_id == chain_id
                && cache.identity().txid_version == txid_version
        }) else {
            return Err(PreTransactionPoiError::ProofSource(format!(
                "local POI cache unavailable for listKey={}",
                hex::encode(list_key)
            )));
        };
        for blinded_commitment in blinded_commitments {
            if cache.position(blinded_commitment).is_none() {
                return Err(PreTransactionPoiError::ProofSource(format!(
                    "missing POI cache proof data for blinded commitment {blinded_commitment}"
                )));
            }
        }
        debug!(
            chain_type,
            chain_id,
            list_key = %hex::encode(list_key),
            commitments = blinded_commitments.len(),
            lock_wait_elapsed_ms,
            elapsed_ms = started.elapsed().as_millis(),
            "local POI proof preflight complete"
        );
        Ok(())
    }
}

#[async_trait]
impl PoiMerkleProofSource for LocalPoiMerkleProofSource {
    async fn poi_merkle_proofs(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_key: &FixedBytes<32>,
        blinded_commitments: &[FixedBytes<32>],
    ) -> Result<Vec<PoiMerkleProof>, PreTransactionPoiError> {
        let started = Instant::now();
        let lock_started = Instant::now();
        let caches = self.caches.read().await;
        let lock_wait_elapsed_ms = lock_started.elapsed().as_millis();
        let Some(cache) = caches.get(list_key).filter(|cache| {
            cache.identity().chain_type == chain_type
                && cache.identity().chain_id == chain_id
                && cache.identity().txid_version == txid_version
        }) else {
            return Err(PreTransactionPoiError::ProofSource(format!(
                "local POI cache unavailable for listKey={}",
                hex::encode(list_key)
            )));
        };
        let positions = cache.positions_for_blinded_commitments(blinded_commitments);
        let proof_global_indices = positions
            .iter()
            .map(|position| position.map(|position| position.global_index))
            .collect::<Vec<_>>();
        let proof_tree_numbers = positions
            .iter()
            .map(|position| position.map(|position| position.tree_number))
            .collect::<Vec<_>>();
        let proof_tree_positions = positions
            .iter()
            .map(|position| position.map(|position| position.tree_position))
            .collect::<Vec<_>>();
        let proof_started = Instant::now();
        let proofs = cache
            .poi_merkle_proofs(blinded_commitments)
            .map_err(|err| PreTransactionPoiError::ProofSource(err.to_string()))?;
        debug!(
            chain_type,
            chain_id,
            list_key = %hex::encode(list_key),
            commitments = blinded_commitments.len(),
            proofs = proofs.len(),
            ?proof_global_indices,
            ?proof_tree_numbers,
            ?proof_tree_positions,
            lock_wait_elapsed_ms,
            proof_elapsed_ms = proof_started.elapsed().as_millis(),
            elapsed_ms = started.elapsed().as_millis(),
            "local POI merkle proofs complete"
        );
        Ok(proofs)
    }
}

#[async_trait]
pub(crate) trait PendingOutputPoiSubmitter: Send + Sync {
    async fn submit_single_commitment_proofs(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        context: &SingleCommitmentProofContext,
        utxo_tree_out: u64,
        utxo_position_out: u64,
    ) -> Result<(), PoiError>;

    async fn submit_transact_proof(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_key: &FixedBytes<32>,
        txid_merkleroot_index: u64,
        poi: &broadcaster_core::transact::PreTxPoi,
    ) -> Result<(), PoiError>;
}

#[async_trait]
impl PendingOutputPoiSubmitter for PoiRpcClient {
    async fn submit_single_commitment_proofs(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        context: &SingleCommitmentProofContext,
        utxo_tree_out: u64,
        utxo_position_out: u64,
    ) -> Result<(), PoiError> {
        PoiRpcClient::submit_single_commitment_proofs(
            self,
            txid_version,
            chain_type,
            chain_id,
            context,
            utxo_tree_out,
            utxo_position_out,
        )
        .await?;
        Ok(())
    }

    async fn submit_transact_proof(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_key: &FixedBytes<32>,
        txid_merkleroot_index: u64,
        poi: &broadcaster_core::transact::PreTxPoi,
    ) -> Result<(), PoiError> {
        PoiRpcClient::submit_transact_proof(
            self,
            txid_version,
            chain_type,
            chain_id,
            list_key,
            txid_merkleroot_index,
            poi,
        )
        .await?;
        Ok(())
    }
}
