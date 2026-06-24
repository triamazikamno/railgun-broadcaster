use alloy::hex;
use alloy::primitives::FixedBytes;
use broadcaster_core::crypto::snark_proof::Prover;
use broadcaster_core::transact::{
    BroadcasterRawParamsTransact, DEFAULT_TXID_VERSION, ParsedTransactCalldata,
    ParsedTransactTransaction, PreTxPoi, dummy_txid_root, railgun_txid_leaf_hash,
    txid_version_or_default,
};
use poi::cache::{PoiCache, PoiCacheRootValidation};
use poi::error::PoiError;
use poi::poi::{Poi, PoiRpcClient, PoiStatus, default_active_poi_list_keys};
use std::collections::BTreeMap;
use std::sync::Arc;
use sync_service::LocalPoiCaches;
use tracing::debug;

const EVM_CHAIN_TYPE: u8 = 0;

pub struct BroadcasterPoiValidator {
    proxy: Arc<Poi>,
    rpc_client: PoiRpcClient,
    snark_prover: Arc<Prover>,
    required_poi_list: Vec<FixedBytes<32>>,
    default_list_keys: Vec<FixedBytes<32>>,
    local_poi_caches: Option<LocalPoiCaches>,
}

impl BroadcasterPoiValidator {
    #[must_use]
    pub fn new(
        proxy: Arc<Poi>,
        rpc_client: PoiRpcClient,
        snark_prover: Arc<Prover>,
        required_poi_list: Vec<FixedBytes<32>>,
        local_poi_caches: Option<LocalPoiCaches>,
    ) -> Self {
        Self {
            proxy,
            rpc_client,
            snark_prover,
            required_poi_list,
            default_list_keys: default_active_poi_list_keys(),
            local_poi_caches,
        }
    }

    pub async fn validate_all(
        &self,
        parsed_calldata: &ParsedTransactCalldata,
        params: &BroadcasterRawParamsTransact,
    ) -> Result<(), PoiError> {
        for list_key in &self.required_poi_list {
            for transaction in &parsed_calldata.transactions {
                self.validate_transaction(transaction, params, list_key)
                    .await
                    .map_err(|source| PoiError::ValidateList {
                        list_key: *list_key,
                        source: Box::new(source),
                    })?;
            }
        }
        Ok(())
    }

    pub async fn fee_note_statuses_for_blinded_commitment(
        &self,
        chain_type: u8,
        chain_id: u64,
        txid_version: &str,
        required_poi_list_keys: &[FixedBytes<32>],
        blinded_commitment: &FixedBytes<32>,
    ) -> Result<BTreeMap<FixedBytes<32>, PoiStatus>, PoiError> {
        match local_fee_note_status_outcome(
            self.local_poi_caches.as_ref(),
            &self.default_list_keys,
            chain_type,
            chain_id,
            txid_version,
            required_poi_list_keys,
            blinded_commitment,
        )
        .await
        {
            FeeNoteStatusOutcome::LocalValid(statuses) => {
                debug!(
                    chain_type,
                    chain_id,
                    fee_blinded_commitment = %hex::encode_prefixed(blinded_commitment),
                    list_count = required_poi_list_keys.len(),
                    "broadcaster POI artifact cache fee-note status hit"
                );
                Ok(statuses)
            }
            FeeNoteStatusOutcome::ProxyFallback { list_key, reason } => {
                if self.local_poi_caches.is_some() {
                    log_proxy_fallback(
                        chain_type,
                        chain_id,
                        list_key.as_ref(),
                        reason,
                        "broadcaster POI artifact cache fee-note status miss; falling back to proxy",
                    );
                }
                self.proxy
                    .fee_note_statuses_for_blinded_commitment(
                        chain_type,
                        chain_id,
                        txid_version,
                        required_poi_list_keys,
                        blinded_commitment,
                    )
                    .await
            }
        }
    }

    pub async fn submit_fee_note_single_commitment(
        &self,
        chain_type: u8,
        chain_id: u64,
        context: &broadcaster_core::transact::FeeNoteAssuranceContext,
        utxo_tree_out: u64,
        utxo_position_out: u64,
    ) -> Result<(), PoiError> {
        self.proxy
            .submit_fee_note_single_commitment(
                chain_type,
                chain_id,
                context,
                utxo_tree_out,
                utxo_position_out,
            )
            .await
    }

    async fn validate_transaction(
        &self,
        transaction: &ParsedTransactTransaction,
        params: &BroadcasterRawParamsTransact,
        required_list_key: &FixedBytes<32>,
    ) -> Result<(), PoiError> {
        let poi = transaction_poi_for_validation(transaction, params, required_list_key)?;
        let txid_version = txid_version_or_default(params.txid_version.as_deref());
        self.validate_roots(
            txid_version,
            params.chain_type as u8,
            params.chain_id,
            required_list_key,
            &poi.poi_merkleroots,
        )
        .await?;

        let snark_ok = self.snark_prover.verify(
            transaction.tx_nullifiers_len,
            transaction.tx_commitments_out_len,
            poi,
        )?;
        snark_validation_result(snark_ok)
    }

    async fn validate_roots(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_key: &FixedBytes<32>,
        poi_merkleroots: &[FixedBytes<32>],
    ) -> Result<(), PoiError> {
        match local_root_validation_outcome(
            self.local_poi_caches.as_ref(),
            &self.default_list_keys,
            chain_type,
            chain_id,
            txid_version,
            list_key,
            poi_merkleroots,
        )
        .await
        {
            RootValidationOutcome::LocalHit => {
                debug!(
                    chain_type,
                    chain_id,
                    list_key = %hex::encode(list_key),
                    root_count = poi_merkleroots.len(),
                    "broadcaster POI artifact cache root validation hit"
                );
                Ok(())
            }
            RootValidationOutcome::ProxyFallback(reason) => {
                if self.local_poi_caches.is_some() {
                    log_proxy_fallback(
                        chain_type,
                        chain_id,
                        Some(list_key),
                        reason,
                        "broadcaster POI artifact cache root validation miss; falling back to proxy",
                    );
                }
                let ok = self
                    .rpc_client
                    .validate_poi_merkleroots(
                        txid_version,
                        chain_type,
                        chain_id,
                        list_key,
                        &poi_merkleroots.iter().map(hex::encode).collect::<Vec<_>>(),
                    )
                    .await?;

                if ok {
                    Ok(())
                } else {
                    Err(PoiError::MerkleRootsRejected)
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalPoiFallbackReason {
    ArtifactModeDisabled,
    NonDefaultListKey,
    UnsupportedChainType,
    UnsupportedTxidVersion,
    CacheUnavailable,
    CacheIdentityMismatch,
    AcceptedRootsUnavailable,
    SubmittedRootsEmpty,
    SubmittedRootAbsent,
    RequiredListsEmpty,
    StatusUnresolved,
}

impl LocalPoiFallbackReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ArtifactModeDisabled => "artifact_mode_disabled",
            Self::NonDefaultListKey => "non_default_list_key",
            Self::UnsupportedChainType => "unsupported_chain_type",
            Self::UnsupportedTxidVersion => "unsupported_txid_version",
            Self::CacheUnavailable => "cache_unavailable",
            Self::CacheIdentityMismatch => "cache_identity_mismatch",
            Self::AcceptedRootsUnavailable => "accepted_roots_unavailable",
            Self::SubmittedRootsEmpty => "submitted_roots_empty",
            Self::SubmittedRootAbsent => "submitted_root_absent",
            Self::RequiredListsEmpty => "required_lists_empty",
            Self::StatusUnresolved => "status_unresolved",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RootValidationOutcome {
    LocalHit,
    ProxyFallback(LocalPoiFallbackReason),
}

enum FeeNoteStatusOutcome {
    LocalValid(BTreeMap<FixedBytes<32>, PoiStatus>),
    ProxyFallback {
        list_key: Option<FixedBytes<32>>,
        reason: LocalPoiFallbackReason,
    },
}

fn log_proxy_fallback(
    chain_type: u8,
    chain_id: u64,
    list_key: Option<&FixedBytes<32>>,
    reason: LocalPoiFallbackReason,
    message: &'static str,
) {
    debug!(
        chain_type,
        chain_id,
        list_key = list_key.map(hex::encode),
        fallback_reason = reason.as_str(),
        "{}",
        message
    );
}

fn transaction_poi_for_validation<'a>(
    transaction: &ParsedTransactTransaction,
    params: &'a BroadcasterRawParamsTransact,
    required_list_key: &FixedBytes<32>,
) -> Result<&'a PreTxPoi, PoiError> {
    let leaf = railgun_txid_leaf_hash(transaction.railgun_txid, transaction.utxo_tree_in);
    let leaf_hex: FixedBytes<32> = leaf.into();

    let per_list = params
        .pre_transaction_pois_per_txid_leaf_per_list
        .get(required_list_key)
        .ok_or(PoiError::MissingListKey)?;

    let poi = per_list
        .get(&leaf_hex)
        .ok_or(PoiError::MissingProof { leaf_hex })?;

    let expected_root = FixedBytes::from(dummy_txid_root(leaf).to_be_bytes::<32>());
    if expected_root != poi.txid_merkleroot {
        return Err(PoiError::TxidMerklerootMismatch {
            expected: expected_root,
            actual: poi.txid_merkleroot,
        });
    }

    Ok(poi)
}

const fn snark_validation_result(snark_ok: bool) -> Result<(), PoiError> {
    if snark_ok {
        Ok(())
    } else {
        Err(PoiError::InvalidSnarkProof)
    }
}

async fn local_root_validation_outcome(
    local_poi_caches: Option<&LocalPoiCaches>,
    default_list_keys: &[FixedBytes<32>],
    chain_type: u8,
    chain_id: u64,
    txid_version: &str,
    list_key: &FixedBytes<32>,
    poi_merkleroots: &[FixedBytes<32>],
) -> RootValidationOutcome {
    if !default_list_keys.contains(list_key) {
        return RootValidationOutcome::ProxyFallback(LocalPoiFallbackReason::NonDefaultListKey);
    }
    let Some(local_poi_caches) = local_poi_caches else {
        return RootValidationOutcome::ProxyFallback(LocalPoiFallbackReason::ArtifactModeDisabled);
    };
    if chain_type != EVM_CHAIN_TYPE {
        return RootValidationOutcome::ProxyFallback(LocalPoiFallbackReason::UnsupportedChainType);
    }
    if txid_version != DEFAULT_TXID_VERSION {
        return RootValidationOutcome::ProxyFallback(
            LocalPoiFallbackReason::UnsupportedTxidVersion,
        );
    }
    if poi_merkleroots.is_empty() {
        return RootValidationOutcome::ProxyFallback(LocalPoiFallbackReason::SubmittedRootsEmpty);
    }

    let caches = local_poi_caches.read().await;
    let Some(cache) = caches.get(list_key) else {
        return RootValidationOutcome::ProxyFallback(LocalPoiFallbackReason::CacheUnavailable);
    };
    if !cache_identity_matches(cache, chain_type, chain_id, txid_version, list_key) {
        return RootValidationOutcome::ProxyFallback(LocalPoiFallbackReason::CacheIdentityMismatch);
    }
    local_accepted_root_check(cache, poi_merkleroots)
}

async fn local_fee_note_status_outcome(
    local_poi_caches: Option<&LocalPoiCaches>,
    default_list_keys: &[FixedBytes<32>],
    chain_type: u8,
    chain_id: u64,
    txid_version: &str,
    required_poi_list_keys: &[FixedBytes<32>],
    blinded_commitment: &FixedBytes<32>,
) -> FeeNoteStatusOutcome {
    if required_poi_list_keys.is_empty() {
        return FeeNoteStatusOutcome::ProxyFallback {
            list_key: None,
            reason: LocalPoiFallbackReason::RequiredListsEmpty,
        };
    }
    if let Some(non_default_list_key) = required_poi_list_keys
        .iter()
        .find(|list_key| !default_list_keys.contains(list_key))
    {
        return FeeNoteStatusOutcome::ProxyFallback {
            list_key: Some(*non_default_list_key),
            reason: LocalPoiFallbackReason::NonDefaultListKey,
        };
    }
    let Some(local_poi_caches) = local_poi_caches else {
        return FeeNoteStatusOutcome::ProxyFallback {
            list_key: required_poi_list_keys.first().copied(),
            reason: LocalPoiFallbackReason::ArtifactModeDisabled,
        };
    };
    if chain_type != EVM_CHAIN_TYPE {
        return FeeNoteStatusOutcome::ProxyFallback {
            list_key: required_poi_list_keys.first().copied(),
            reason: LocalPoiFallbackReason::UnsupportedChainType,
        };
    }
    if txid_version != DEFAULT_TXID_VERSION {
        return FeeNoteStatusOutcome::ProxyFallback {
            list_key: required_poi_list_keys.first().copied(),
            reason: LocalPoiFallbackReason::UnsupportedTxidVersion,
        };
    }

    let caches = local_poi_caches.read().await;
    let mut statuses = BTreeMap::new();
    for list_key in required_poi_list_keys {
        let Some(cache) = caches.get(list_key) else {
            return FeeNoteStatusOutcome::ProxyFallback {
                list_key: Some(*list_key),
                reason: LocalPoiFallbackReason::CacheUnavailable,
            };
        };
        if !cache_identity_matches(cache, chain_type, chain_id, txid_version, list_key) {
            return FeeNoteStatusOutcome::ProxyFallback {
                list_key: Some(*list_key),
                reason: LocalPoiFallbackReason::CacheIdentityMismatch,
            };
        }
        if !has_accepted_roots(cache) || cache.status(blinded_commitment) != PoiStatus::Valid {
            return FeeNoteStatusOutcome::ProxyFallback {
                list_key: Some(*list_key),
                reason: LocalPoiFallbackReason::StatusUnresolved,
            };
        }
        statuses.insert(*list_key, PoiStatus::Valid);
    }

    FeeNoteStatusOutcome::LocalValid(statuses)
}

fn local_accepted_root_check(
    cache: &PoiCache,
    poi_merkleroots: &[FixedBytes<32>],
) -> RootValidationOutcome {
    let PoiCacheRootValidation::Validated { roots } = &cache.progress().root_validation else {
        return RootValidationOutcome::ProxyFallback(
            LocalPoiFallbackReason::AcceptedRootsUnavailable,
        );
    };
    if roots.is_empty() {
        return RootValidationOutcome::ProxyFallback(
            LocalPoiFallbackReason::AcceptedRootsUnavailable,
        );
    }
    if poi_merkleroots
        .iter()
        .all(|submitted| roots.values().any(|accepted| accepted == submitted))
    {
        RootValidationOutcome::LocalHit
    } else {
        RootValidationOutcome::ProxyFallback(LocalPoiFallbackReason::SubmittedRootAbsent)
    }
}

fn has_accepted_roots(cache: &PoiCache) -> bool {
    matches!(
        &cache.progress().root_validation,
        PoiCacheRootValidation::Validated { roots } if !roots.is_empty()
    )
}

fn cache_identity_matches(
    cache: &PoiCache,
    chain_type: u8,
    chain_id: u64,
    txid_version: &str,
    list_key: &FixedBytes<32>,
) -> bool {
    let identity = cache.identity();
    identity.chain_type == chain_type
        && identity.chain_id == chain_id
        && identity.txid_version == txid_version
        && identity.list_key == *list_key
}

#[cfg(test)]
mod tests {
    use super::{
        EVM_CHAIN_TYPE, FeeNoteStatusOutcome, LocalPoiFallbackReason, RootValidationOutcome,
        local_fee_note_status_outcome, local_root_validation_outcome, snark_validation_result,
        transaction_poi_for_validation,
    };
    use alloy::primitives::{Address, Bytes, FixedBytes, U256};
    use broadcaster_core::transact::{
        BroadcasterRawParamsTransact, DEFAULT_TXID_VERSION, ParsedTransactTransaction,
    };
    use poi::cache::{PoiCache, PoiCacheIdentity};
    use poi::error::PoiError;
    use poi::poi::default_active_poi_list_key;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use sync_service::LocalPoiCaches;
    use tokio::sync::RwLock;

    const CHAIN_ID: u64 = 1;

    fn transaction() -> ParsedTransactTransaction {
        ParsedTransactTransaction {
            railgun_txid: U256::from(5_u8),
            utxo_tree_in: 7,
            tx_nullifiers_len: 1,
            tx_commitments_out_len: 2,
            has_unshield: false,
        }
    }

    fn params_with_poi_map(
        pre_transaction_pois_per_txid_leaf_per_list: BTreeMap<
            FixedBytes<32>,
            BTreeMap<FixedBytes<32>, broadcaster_core::transact::PreTxPoi>,
        >,
    ) -> BroadcasterRawParamsTransact {
        BroadcasterRawParamsTransact {
            chain_type: u64::from(EVM_CHAIN_TYPE),
            chain_id: CHAIN_ID,
            transact_type: None,
            min_gas_price: None,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            authorization: None,
            fees_id: None,
            to: Address::ZERO,
            data: Bytes::new(),
            broadcaster_viewing_key: FixedBytes::ZERO,
            txid_version: None,
            pre_transaction_pois_per_txid_leaf_per_list,
        }
    }

    fn accepted_cache(list_key: FixedBytes<32>, commitment: FixedBytes<32>) -> PoiCache {
        let mut cache = PoiCache::new(PoiCacheIdentity::new(
            EVM_CHAIN_TYPE,
            CHAIN_ID,
            DEFAULT_TXID_VERSION,
            list_key,
        ));
        cache
            .apply_poi_leaves(0, &[alloy::hex::encode_prefixed(commitment)])
            .expect("apply POI leaf");
        cache.accept_current_roots();
        cache
    }

    fn caches_with(list_key: FixedBytes<32>, cache: PoiCache) -> LocalPoiCaches {
        Arc::new(RwLock::new(BTreeMap::from([(list_key, cache)])))
    }

    #[tokio::test]
    async fn default_list_local_root_hit_uses_artifact_cache() {
        let list_key = default_active_poi_list_key();
        let cache = accepted_cache(list_key, FixedBytes::from([0x11; 32]));
        let accepted_root = cache
            .progress()
            .root_validation
            .clone()
            .validated_roots()
            .values()
            .next()
            .copied()
            .expect("accepted root");
        let caches = caches_with(list_key, cache);

        assert_eq!(
            local_root_validation_outcome(
                Some(&caches),
                &[list_key],
                EVM_CHAIN_TYPE,
                CHAIN_ID,
                DEFAULT_TXID_VERSION,
                &list_key,
                &[accepted_root],
            )
            .await,
            RootValidationOutcome::LocalHit
        );
    }

    #[tokio::test]
    async fn default_list_local_root_miss_falls_back_to_proxy() {
        let list_key = default_active_poi_list_key();
        let cache = accepted_cache(list_key, FixedBytes::from([0x11; 32]));
        let caches = caches_with(list_key, cache);

        assert_eq!(
            local_root_validation_outcome(
                Some(&caches),
                &[list_key],
                EVM_CHAIN_TYPE,
                CHAIN_ID,
                DEFAULT_TXID_VERSION,
                &list_key,
                &[FixedBytes::from([0x99; 32])],
            )
            .await,
            RootValidationOutcome::ProxyFallback(LocalPoiFallbackReason::SubmittedRootAbsent)
        );
    }

    #[tokio::test]
    async fn non_default_list_uses_proxy_without_local_cache() {
        let default_list_key = default_active_poi_list_key();
        let non_default_list_key = FixedBytes::from([0x22; 32]);
        let cache = accepted_cache(default_list_key, FixedBytes::from([0x11; 32]));
        let caches = caches_with(default_list_key, cache);

        assert_eq!(
            local_root_validation_outcome(
                Some(&caches),
                &[default_list_key],
                EVM_CHAIN_TYPE,
                CHAIN_ID,
                DEFAULT_TXID_VERSION,
                &non_default_list_key,
                &[FixedBytes::from([0x99; 32])],
            )
            .await,
            RootValidationOutcome::ProxyFallback(LocalPoiFallbackReason::NonDefaultListKey)
        );
    }

    #[test]
    fn missing_poi_proof_is_rejected_before_root_fallback() {
        let list_key = default_active_poi_list_key();
        let params = params_with_poi_map(BTreeMap::from([(list_key, BTreeMap::new())]));
        let error = transaction_poi_for_validation(&transaction(), &params, &list_key)
            .expect_err("missing proof should reject");

        assert!(matches!(error, PoiError::MissingProof { .. }));
    }

    #[test]
    fn invalid_snark_result_is_rejected_without_proxy_retry() {
        assert!(matches!(
            snark_validation_result(false),
            Err(PoiError::InvalidSnarkProof)
        ));
    }

    #[tokio::test]
    async fn fee_note_local_valid_status_completes_from_artifact_cache() {
        let list_key = default_active_poi_list_key();
        let fee_blinded_commitment = FixedBytes::from([0x33; 32]);
        let cache = accepted_cache(list_key, fee_blinded_commitment);
        let caches = caches_with(list_key, cache);

        match local_fee_note_status_outcome(
            Some(&caches),
            &[list_key],
            EVM_CHAIN_TYPE,
            CHAIN_ID,
            DEFAULT_TXID_VERSION,
            &[list_key],
            &fee_blinded_commitment,
        )
        .await
        {
            FeeNoteStatusOutcome::LocalValid(statuses) => {
                assert_eq!(statuses.get(&list_key), Some(&poi::poi::PoiStatus::Valid));
            }
            FeeNoteStatusOutcome::ProxyFallback { reason, .. } => {
                panic!("expected local valid status, got fallback reason {reason:?}");
            }
        }
    }

    #[tokio::test]
    async fn fee_note_unresolved_status_falls_back_to_proxy() {
        let list_key = default_active_poi_list_key();
        let cache = accepted_cache(list_key, FixedBytes::from([0x11; 32]));
        let caches = caches_with(list_key, cache);

        match local_fee_note_status_outcome(
            Some(&caches),
            &[list_key],
            EVM_CHAIN_TYPE,
            CHAIN_ID,
            DEFAULT_TXID_VERSION,
            &[list_key],
            &FixedBytes::from([0x44; 32]),
        )
        .await
        {
            FeeNoteStatusOutcome::LocalValid(_) => panic!("expected proxy fallback"),
            FeeNoteStatusOutcome::ProxyFallback { reason, .. } => {
                assert_eq!(reason, LocalPoiFallbackReason::StatusUnresolved);
            }
        }
    }

    #[tokio::test]
    async fn fee_note_non_default_list_falls_back_to_proxy() {
        let default_list_key = default_active_poi_list_key();
        let non_default_list_key = FixedBytes::from([0x22; 32]);
        let cache = accepted_cache(default_list_key, FixedBytes::from([0x11; 32]));
        let caches = caches_with(default_list_key, cache);

        match local_fee_note_status_outcome(
            Some(&caches),
            &[default_list_key],
            EVM_CHAIN_TYPE,
            CHAIN_ID,
            DEFAULT_TXID_VERSION,
            &[non_default_list_key],
            &FixedBytes::from([0x44; 32]),
        )
        .await
        {
            FeeNoteStatusOutcome::LocalValid(_) => panic!("expected proxy fallback"),
            FeeNoteStatusOutcome::ProxyFallback { reason, .. } => {
                assert_eq!(reason, LocalPoiFallbackReason::NonDefaultListKey);
            }
        }
    }

    trait ValidatedRootsExt {
        fn validated_roots(&self) -> &BTreeMap<u32, FixedBytes<32>>;
    }

    impl ValidatedRootsExt for poi::cache::PoiCacheRootValidation {
        fn validated_roots(&self) -> &BTreeMap<u32, FixedBytes<32>> {
            match self {
                Self::Validated { roots } => roots,
                _ => panic!("expected validated roots"),
            }
        }
    }
}
