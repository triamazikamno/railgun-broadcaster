use std::collections::HashMap;

use alloy::primitives::{Bytes, FixedBytes, U256};
use alloy::sol_types::{Error as SolError, SolEvent};
use alloy_rpc_types_eth::Log;
use thiserror::Error;

use broadcaster_core::crypto::railgun::ViewingKeyData;
use broadcaster_core::crypto::shared_key::{shared_symmetric_key, shared_symmetric_key_legacy};
use broadcaster_core::notes::{
    Note, decrypt_legacy_random, decrypt_shield_random, note_public_key,
};
use broadcaster_core::utxo::{Utxo, UtxoSource};

use crate::errors::SyncError;
use crate::slow::types::{
    CommitmentBatch, CommitmentPreimage, GeneratedCommitmentBatch, IntoCommitmentUpdates,
    LegacyCommitmentPreimage, Nullified, Nullifiers, Shield, ShieldCiphertext,
    ShieldLegacyPreMar23, Transact,
};
use crate::tree::{MerkleForest, normalize_tree_position};

#[derive(Debug, Error)]
pub enum WalletScanError {
    #[error("decode log: {0}")]
    Decode(#[from] SolError),
    #[error("apply commitment updates: {0}")]
    Update(#[from] SyncError),
    #[error("log missing required metadata: {0}")]
    MissingLogMetadata(&'static str),
}

pub type WalletScanKeys = ViewingKeyData;

#[derive(Debug)]
pub struct WalletLogDelta {
    pub utxos: Vec<Utxo>,
    pub nullifiers: Vec<SpentNullifier>,
}

#[derive(Debug, Clone)]
pub struct SpentNullifier {
    pub tree: u32,
    pub nullifier: U256,
    pub source: UtxoSource,
}

#[derive(Clone)]
pub struct IndexedTransactCommitmentInput {
    pub tree_number: u32,
    pub tree_position: u64,
    pub hash: U256,
    pub ciphertext: [FixedBytes<32>; 4],
    pub blinded_sender_viewing_key: FixedBytes<32>,
    pub memo: Bytes,
    pub source: UtxoSource,
}

#[derive(Clone)]
pub struct IndexedShieldCommitmentInput {
    pub tree_number: u32,
    pub tree_position: u64,
    pub preimage: CommitmentPreimage,
    pub shield_ciphertext: ShieldCiphertext,
    pub source: UtxoSource,
}

#[derive(Clone)]
pub struct IndexedNullifierInput {
    pub tree_number: u32,
    pub nullifier: U256,
    pub source: UtxoSource,
}

#[derive(Clone)]
pub struct IndexedLegacyEncryptedCommitmentInput {
    pub tree_number: u32,
    pub tree_position: u64,
    pub hash: U256,
    pub ciphertext: [FixedBytes<32>; 4],
    pub ephemeral_keys: [FixedBytes<32>; 2],
    pub memo: Vec<FixedBytes<32>>,
    pub source: UtxoSource,
}

#[derive(Clone)]
pub struct IndexedLegacyGeneratedCommitmentInput {
    pub tree_number: u32,
    pub tree_position: u64,
    pub preimage: LegacyCommitmentPreimage,
    pub encrypted_random: (FixedBytes<32>, FixedBytes<16>),
    pub source: UtxoSource,
}

pub fn parse_wallet_delta_from_logs(
    logs: &[Log],
    keys: &WalletScanKeys,
) -> Result<WalletLogDelta, WalletScanError> {
    let mut utxos = Vec::new();
    let mut nullifiers = HashMap::new();

    for raw_log in logs {
        let topic0 = raw_log.inner.topics().first().copied().unwrap_or_default();
        if topic0 == Transact::SIGNATURE_HASH {
            let event = Transact::decode_log(&raw_log.inner)?.data;

            let tree_number: u32 = event.treeNumber.to();
            let start_pos: u64 = event.startPosition.to();
            let commitment_hashes = &event.hash;
            let source = source_from_log(raw_log)?;
            for (index, ciphertext) in event.ciphertext.iter().enumerate() {
                let position = start_pos + index as u64;
                if let Some(expected_hash) = commitment_hashes
                    .get(index)
                    .map(|hash| U256::from_be_bytes(hash.0))
                    && let Some(utxo) = scan_transact_commitment(
                        tree_number,
                        position,
                        expected_hash,
                        &ciphertext.ciphertext,
                        &ciphertext.blindedSenderViewingKey,
                        ciphertext.memo.as_ref(),
                        source.clone(),
                        keys,
                    )
                {
                    utxos.push(utxo);
                }
            }
        } else if topic0 == Shield::SIGNATURE_HASH {
            let event = Shield::decode_log(&raw_log.inner)?.data;

            let tree_number: u32 = event.treeNumber.to();
            let start_pos: u64 = event.startPosition.to();
            let source = source_from_log(raw_log)?;
            for (index, preimage) in event.commitments.iter().enumerate() {
                let position = start_pos + index as u64;
                if let Some(ciphertext) = event.shieldCiphertext.get(index)
                    && let Some(utxo) = scan_shield_commitment(
                        tree_number,
                        position,
                        preimage,
                        ciphertext,
                        source.clone(),
                        keys,
                    )
                {
                    utxos.push(utxo);
                }
            }
        } else if topic0 == ShieldLegacyPreMar23::SIGNATURE_HASH {
            let event = ShieldLegacyPreMar23::decode_log(&raw_log.inner)?.data;

            let tree_number: u32 = event.treeNumber.to();
            let start_pos: u64 = event.startPosition.to();
            let source = source_from_log(raw_log)?;
            for (index, preimage) in event.commitments.iter().enumerate() {
                let position = start_pos + index as u64;
                if let Some(ciphertext) = event.shieldCiphertext.get(index)
                    && let Some(utxo) = scan_shield_commitment(
                        tree_number,
                        position,
                        preimage,
                        ciphertext,
                        source.clone(),
                        keys,
                    )
                {
                    utxos.push(utxo);
                }
            }
        } else if topic0 == Nullifiers::SIGNATURE_HASH {
            let event = Nullifiers::decode_log(&raw_log.inner)?.data;
            let tree_number: u32 = event.treeNumber.to();
            let source = source_from_log(raw_log)?;
            for nullifier in event.nullifier {
                nullifiers
                    .entry((tree_number, nullifier))
                    .or_insert_with(|| source.clone());
            }
        } else if topic0 == Nullified::SIGNATURE_HASH {
            let event = Nullified::decode_log(&raw_log.inner)?.data;
            let tree_number: u32 = event.treeNumber.into();
            let source = source_from_log(raw_log)?;
            for nullifier in event.nullifier {
                nullifiers
                    .entry((tree_number, U256::from_be_bytes(nullifier.0)))
                    .or_insert_with(|| source.clone());
            }
        } else if topic0 == CommitmentBatch::SIGNATURE_HASH {
            let event = CommitmentBatch::decode_log(&raw_log.inner)?.data;

            let tree_number: u32 = event.treeNumber.to();
            let start_pos: u64 = event.startPosition.to();
            let source = source_from_log(raw_log)?;
            for (index, ciphertext) in event.ciphertext.iter().enumerate() {
                let Some(expected_hash) = event.hash.get(index).copied() else {
                    continue;
                };
                let position = start_pos + index as u64;
                let input = IndexedLegacyEncryptedCommitmentInput {
                    tree_number,
                    tree_position: position,
                    hash: expected_hash,
                    ciphertext: ciphertext.ciphertext.map(u256_to_fixed_bytes),
                    ephemeral_keys: ciphertext.ephemeralKeys.map(u256_to_fixed_bytes),
                    memo: ciphertext
                        .memo
                        .iter()
                        .copied()
                        .map(u256_to_fixed_bytes)
                        .collect(),
                    source: source.clone(),
                };
                if let Some(utxo) = scan_legacy_encrypted_commitment(&input, keys) {
                    utxos.push(utxo);
                }
            }
        } else if topic0 == GeneratedCommitmentBatch::SIGNATURE_HASH {
            let event = GeneratedCommitmentBatch::decode_log(&raw_log.inner)?.data;

            let tree_number: u32 = event.treeNumber.to();
            let start_pos: u64 = event.startPosition.to();
            let source = source_from_log(raw_log)?;
            for (index, preimage) in event.commitments.iter().enumerate() {
                let Some(encrypted_random) = event.encryptedRandom.get(index) else {
                    continue;
                };
                let position = start_pos + index as u64;
                let input = IndexedLegacyGeneratedCommitmentInput {
                    tree_number,
                    tree_position: position,
                    preimage: preimage.clone(),
                    encrypted_random: encrypted_random_from_u256(*encrypted_random),
                    source: source.clone(),
                };
                if let Some(utxo) = scan_legacy_generated_commitment(&input, keys) {
                    utxos.push(utxo);
                }
            }
        }
    }

    Ok(WalletLogDelta {
        utxos,
        nullifiers: nullifiers
            .into_iter()
            .map(|((tree, nullifier), source)| SpentNullifier {
                tree,
                nullifier,
                source,
            })
            .collect(),
    })
}

pub fn parse_indexed_wallet_delta(
    transact_commitments: &[IndexedTransactCommitmentInput],
    shield_commitments: &[IndexedShieldCommitmentInput],
    legacy_encrypted_commitments: &[IndexedLegacyEncryptedCommitmentInput],
    legacy_generated_commitments: &[IndexedLegacyGeneratedCommitmentInput],
    indexed_nullifiers: &[IndexedNullifierInput],
    keys: &WalletScanKeys,
) -> WalletLogDelta {
    let mut utxos = Vec::new();
    let mut nullifiers = HashMap::new();

    for commitment in transact_commitments {
        if let Some(utxo) = scan_transact_commitment(
            commitment.tree_number,
            commitment.tree_position,
            commitment.hash,
            &commitment.ciphertext,
            &commitment.blinded_sender_viewing_key,
            commitment.memo.as_ref(),
            commitment.source.clone(),
            keys,
        ) {
            utxos.push(utxo);
        }
    }

    for commitment in shield_commitments {
        if let Some(utxo) = scan_shield_commitment(
            commitment.tree_number,
            commitment.tree_position,
            &commitment.preimage,
            &commitment.shield_ciphertext,
            commitment.source.clone(),
            keys,
        ) {
            utxos.push(utxo);
        }
    }

    for commitment in legacy_encrypted_commitments {
        if let Some(utxo) = scan_legacy_encrypted_commitment(commitment, keys) {
            utxos.push(utxo);
        }
    }

    for commitment in legacy_generated_commitments {
        if let Some(utxo) = scan_legacy_generated_commitment(commitment, keys) {
            utxos.push(utxo);
        }
    }

    for nullifier in indexed_nullifiers {
        nullifiers
            .entry((nullifier.tree_number, nullifier.nullifier))
            .or_insert_with(|| nullifier.source.clone());
    }

    WalletLogDelta {
        utxos,
        nullifiers: nullifiers
            .into_iter()
            .map(|((tree, nullifier), source)| SpentNullifier {
                tree,
                nullifier,
                source,
            })
            .collect(),
    }
}

fn scan_legacy_encrypted_commitment(
    commitment: &IndexedLegacyEncryptedCommitmentInput,
    keys: &WalletScanKeys,
) -> Option<Utxo> {
    let memo = commitment
        .memo
        .iter()
        .skip(2)
        .flat_map(|chunk| chunk.0)
        .collect::<Vec<_>>();
    let shared_key =
        shared_symmetric_key_legacy(&keys.viewing_private_key, &commitment.ephemeral_keys[0].0)
            .ok()?;
    let (tree, position) =
        normalize_tree_position(commitment.tree_number, commitment.tree_position);
    let note = Note::decrypt_v2(
        &commitment.ciphertext,
        &memo,
        &shared_key,
        keys.master_public_key,
    )
    .ok()?;
    if note.commitment() != commitment.hash {
        return None;
    }
    Some(Utxo {
        note,
        tree,
        position,
        source: commitment.source.clone(),
    })
}

fn scan_legacy_generated_commitment(
    commitment: &IndexedLegacyGeneratedCommitmentInput,
    keys: &WalletScanKeys,
) -> Option<Utxo> {
    let random = decrypt_legacy_random(
        commitment.encrypted_random.0,
        commitment.encrypted_random.1,
        &keys.viewing_private_key,
    )
    .ok()?;
    let npk = note_public_key(keys.master_public_key, random);
    if npk != commitment.preimage.npk {
        return None;
    }
    let (tree, position) =
        normalize_tree_position(commitment.tree_number, commitment.tree_position);
    Some(Utxo {
        note: Note {
            token_hash: commitment.preimage.token.id(),
            value: U256::from(commitment.preimage.value.to::<u128>()),
            random,
            npk: commitment.preimage.npk,
        },
        tree,
        position,
        source: commitment.source.clone(),
    })
}

fn scan_transact_commitment(
    tree_number: u32,
    tree_position: u64,
    expected_hash: U256,
    ciphertext: &[FixedBytes<32>; 4],
    blinded_sender_viewing_key: &FixedBytes<32>,
    memo: &[u8],
    source: UtxoSource,
    keys: &WalletScanKeys,
) -> Option<Utxo> {
    let (tree, position) = normalize_tree_position(tree_number, tree_position);
    let shared_key =
        shared_symmetric_key(&keys.viewing_private_key, &blinded_sender_viewing_key.0).ok()?;
    let note = Note::decrypt_v2(ciphertext, memo, &shared_key, keys.master_public_key).ok()?;
    if note.commitment() != expected_hash {
        return None;
    }
    Some(Utxo {
        note,
        tree,
        position,
        source,
    })
}

fn u256_to_fixed_bytes(value: U256) -> FixedBytes<32> {
    FixedBytes::from(value.to_be_bytes::<32>())
}

fn encrypted_random_from_u256(value: [U256; 2]) -> (FixedBytes<32>, FixedBytes<16>) {
    let data = value[1].to_be_bytes::<32>();
    let mut data16 = [0u8; 16];
    data16.copy_from_slice(&data[16..]);
    (u256_to_fixed_bytes(value[0]), FixedBytes::from(data16))
}

fn scan_shield_commitment(
    tree_number: u32,
    tree_position: u64,
    preimage: &CommitmentPreimage,
    ciphertext: &ShieldCiphertext,
    source: UtxoSource,
    keys: &WalletScanKeys,
) -> Option<Utxo> {
    let (tree, position) = normalize_tree_position(tree_number, tree_position);
    let shared_key =
        shared_symmetric_key(&keys.viewing_private_key, &ciphertext.shieldKey.0).ok()?;
    let random = decrypt_shield_random(&ciphertext.encryptedBundle, &shared_key).ok()?;
    Some(Utxo {
        note: preimage.note_with_random(random),
        tree,
        position,
        source,
    })
}

fn source_from_log(log: &Log) -> Result<UtxoSource, WalletScanError> {
    Ok(UtxoSource {
        tx_hash: log
            .transaction_hash
            .ok_or(WalletScanError::MissingLogMetadata("transaction_hash"))?,
        block_number: log
            .block_number
            .ok_or(WalletScanError::MissingLogMetadata("block_number"))?,
    })
}

pub fn apply_commitment_updates_from_logs(
    forest: &mut MerkleForest,
    logs: &[Log],
) -> Result<(), WalletScanError> {
    for raw_log in logs {
        let topic0 = raw_log.inner.topics().first().copied().unwrap_or_default();
        if topic0 == Transact::SIGNATURE_HASH {
            let event = Transact::decode_log(&raw_log.inner)?.data;
            forest.insert_updates(event.commitment_updates())?;
        } else if topic0 == Shield::SIGNATURE_HASH {
            let event = Shield::decode_log(&raw_log.inner)?.data;
            forest.insert_updates(event.commitment_updates())?;
        } else if topic0 == ShieldLegacyPreMar23::SIGNATURE_HASH {
            let event = ShieldLegacyPreMar23::decode_log(&raw_log.inner)?.data;
            forest.insert_updates(event.commitment_updates())?;
        } else if topic0 == CommitmentBatch::SIGNATURE_HASH {
            let event = CommitmentBatch::decode_log(&raw_log.inner)?.data;
            forest.insert_updates(event.commitment_updates())?;
        } else if topic0 == GeneratedCommitmentBatch::SIGNATURE_HASH {
            let event = GeneratedCommitmentBatch::decode_log(&raw_log.inner)?.data;
            forest.insert_updates(event.commitment_updates())?;
        }
    }
    Ok(())
}
