use std::collections::HashMap;

use alloy::primitives::{Bytes, FixedBytes, U256};
use alloy::sol_types::{Error as SolError, SolEvent};
use alloy_rpc_types_eth::Log;
use thiserror::Error;

use broadcaster_core::contracts::railgun::{
    CommitmentBatch, CommitmentPreimage, GeneratedCommitmentBatch, LegacyCommitmentPreimage,
    Nullified, Nullifiers, Shield, ShieldCiphertext, ShieldLegacyPreMar23, Transact,
};
use broadcaster_core::crypto::railgun::ViewingKeyData;
use broadcaster_core::crypto::shared_key::{shared_symmetric_key, shared_symmetric_key_legacy};
use broadcaster_core::notes::{
    Note, decrypt_legacy_random, decrypt_shield_random, note_public_key,
};
use broadcaster_core::tree::normalize_tree_position;
use broadcaster_core::utxo::{Utxo, UtxoCommitmentKind, UtxoSource};

#[derive(Debug, Error)]
pub enum WalletScanError {
    #[error("decode log: {0}")]
    Decode(#[from] SolError),
    #[error("log missing required metadata: {0}")]
    MissingLogMetadata(&'static str),
}

pub type WalletScanKeys = ViewingKeyData;

#[derive(Debug, Clone)]
pub struct WalletLogDelta {
    pub utxos: Vec<Utxo>,
    pub nullifiers: Vec<SpentNullifier>,
    pub commitment_observations: Vec<CommitmentObservation>,
}

#[derive(Debug, Clone)]
pub struct CommitmentObservation {
    pub tree: u32,
    pub position: u64,
    pub commitment: U256,
    pub source: UtxoSource,
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
    block_timestamps: &HashMap<u64, u64>,
    keys: &WalletScanKeys,
) -> Result<WalletLogDelta, WalletScanError> {
    let mut utxos = Vec::new();
    let mut nullifiers = HashMap::new();
    let mut commitment_observations = Vec::new();

    for raw_log in logs {
        let topic0 = raw_log.inner.topics().first().copied().unwrap_or_default();
        if topic0 == Transact::SIGNATURE_HASH {
            let event = Transact::decode_log(&raw_log.inner)?.data;

            let tree_number: u32 = event.treeNumber.to();
            let start_pos: u64 = event.startPosition.to();
            let commitment_hashes = &event.hash;
            let source = source_from_log(raw_log, block_timestamps)?;
            for (index, ciphertext) in event.ciphertext.iter().enumerate() {
                let position = start_pos + index as u64;
                if let Some(expected_hash) = commitment_hashes
                    .get(index)
                    .map(|hash| U256::from_be_bytes(hash.0))
                {
                    let input = IndexedTransactCommitmentInput {
                        tree_number,
                        tree_position: position,
                        hash: expected_hash,
                        ciphertext: ciphertext.ciphertext,
                        blinded_sender_viewing_key: ciphertext.blindedSenderViewingKey,
                        memo: ciphertext.memo.clone(),
                        source: source.clone(),
                    };
                    commitment_observations.push(commitment_observation(
                        tree_number,
                        position,
                        expected_hash,
                        source.clone(),
                    ));
                    if let Some(utxo) = scan_transact_commitment(&input, keys) {
                        utxos.push(utxo);
                    }
                }
            }
        } else if topic0 == Shield::SIGNATURE_HASH {
            let event = Shield::decode_log(&raw_log.inner)?.data;

            let tree_number: u32 = event.treeNumber.to();
            let start_pos: u64 = event.startPosition.to();
            let source = source_from_log(raw_log, block_timestamps)?;
            let mut output = WalletScanOutput {
                utxos: &mut utxos,
                commitment_observations: &mut commitment_observations,
            };
            scan_shield_event_commitments(
                tree_number,
                start_pos,
                &event.commitments,
                &event.shieldCiphertext,
                &source,
                keys,
                &mut output,
            );
        } else if topic0 == ShieldLegacyPreMar23::SIGNATURE_HASH {
            let event = ShieldLegacyPreMar23::decode_log(&raw_log.inner)?.data;

            let tree_number: u32 = event.treeNumber.to();
            let start_pos: u64 = event.startPosition.to();
            let source = source_from_log(raw_log, block_timestamps)?;
            let mut output = WalletScanOutput {
                utxos: &mut utxos,
                commitment_observations: &mut commitment_observations,
            };
            scan_shield_event_commitments(
                tree_number,
                start_pos,
                &event.commitments,
                &event.shieldCiphertext,
                &source,
                keys,
                &mut output,
            );
        } else if topic0 == Nullifiers::SIGNATURE_HASH {
            let event = Nullifiers::decode_log(&raw_log.inner)?.data;
            let tree_number: u32 = event.treeNumber.to();
            let source = source_from_log(raw_log, block_timestamps)?;
            for nullifier in event.nullifier {
                nullifiers
                    .entry((tree_number, nullifier))
                    .or_insert_with(|| source.clone());
            }
        } else if topic0 == Nullified::SIGNATURE_HASH {
            let event = Nullified::decode_log(&raw_log.inner)?.data;
            let tree_number: u32 = event.treeNumber.into();
            let source = source_from_log(raw_log, block_timestamps)?;
            for nullifier in event.nullifier {
                nullifiers
                    .entry((tree_number, U256::from_be_bytes(nullifier.0)))
                    .or_insert_with(|| source.clone());
            }
        } else if topic0 == CommitmentBatch::SIGNATURE_HASH {
            let event = CommitmentBatch::decode_log(&raw_log.inner)?.data;

            let tree_number: u32 = event.treeNumber.to();
            let start_pos: u64 = event.startPosition.to();
            let source = source_from_log(raw_log, block_timestamps)?;
            for (index, ciphertext) in event.ciphertext.iter().enumerate() {
                let Some(expected_hash) = event.hash.get(index).copied() else {
                    continue;
                };
                let position = start_pos + index as u64;
                let input = IndexedLegacyEncryptedCommitmentInput {
                    tree_number,
                    tree_position: position,
                    hash: expected_hash,
                    ciphertext: ciphertext
                        .ciphertext
                        .map(|value| FixedBytes::from(value.to_be_bytes::<32>())),
                    ephemeral_keys: ciphertext
                        .ephemeralKeys
                        .map(|value| FixedBytes::from(value.to_be_bytes::<32>())),
                    memo: ciphertext
                        .memo
                        .iter()
                        .copied()
                        .map(|value| FixedBytes::from(value.to_be_bytes::<32>()))
                        .collect(),
                    source: source.clone(),
                };
                commitment_observations.push(commitment_observation(
                    tree_number,
                    position,
                    expected_hash,
                    source.clone(),
                ));
                if let Some(utxo) = scan_legacy_encrypted_commitment(&input, keys) {
                    utxos.push(utxo);
                }
            }
        } else if topic0 == GeneratedCommitmentBatch::SIGNATURE_HASH {
            let event = GeneratedCommitmentBatch::decode_log(&raw_log.inner)?.data;

            let tree_number: u32 = event.treeNumber.to();
            let start_pos: u64 = event.startPosition.to();
            let source = source_from_log(raw_log, block_timestamps)?;
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
                commitment_observations.push(commitment_observation(
                    tree_number,
                    position,
                    preimage.hash(),
                    source.clone(),
                ));
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
        commitment_observations,
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
    let mut commitment_observations = Vec::new();

    for commitment in transact_commitments {
        commitment_observations.push(commitment_observation(
            commitment.tree_number,
            commitment.tree_position,
            commitment.hash,
            commitment.source.clone(),
        ));
        if let Some(utxo) = scan_transact_commitment(commitment, keys) {
            utxos.push(utxo);
        }
    }

    for commitment in shield_commitments {
        commitment_observations.push(commitment_observation(
            commitment.tree_number,
            commitment.tree_position,
            commitment.preimage.hash(),
            commitment.source.clone(),
        ));
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
        commitment_observations.push(commitment_observation(
            commitment.tree_number,
            commitment.tree_position,
            commitment.hash,
            commitment.source.clone(),
        ));
        if let Some(utxo) = scan_legacy_encrypted_commitment(commitment, keys) {
            utxos.push(utxo);
        }
    }

    for commitment in legacy_generated_commitments {
        commitment_observations.push(commitment_observation(
            commitment.tree_number,
            commitment.tree_position,
            commitment.preimage.hash(),
            commitment.source.clone(),
        ));
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
        commitment_observations,
    }
}

const fn commitment_observation(
    tree_number: u32,
    tree_position: u64,
    commitment: U256,
    source: UtxoSource,
) -> CommitmentObservation {
    let (tree, position) = normalize_tree_position(tree_number, tree_position);
    CommitmentObservation {
        tree,
        position,
        commitment,
        source,
    }
}

struct WalletScanOutput<'a> {
    utxos: &'a mut Vec<Utxo>,
    commitment_observations: &'a mut Vec<CommitmentObservation>,
}

fn scan_shield_event_commitments(
    tree_number: u32,
    start_pos: u64,
    commitments: &[CommitmentPreimage],
    shield_ciphertext: &[ShieldCiphertext],
    source: &UtxoSource,
    keys: &WalletScanKeys,
    output: &mut WalletScanOutput<'_>,
) {
    for (index, preimage) in commitments.iter().enumerate() {
        let position = start_pos + index as u64;
        output.commitment_observations.push(commitment_observation(
            tree_number,
            position,
            preimage.hash(),
            source.clone(),
        ));
        if let Some(ciphertext) = shield_ciphertext.get(index)
            && let Some(utxo) = scan_shield_commitment(
                tree_number,
                position,
                preimage,
                ciphertext,
                source.clone(),
                keys,
            )
        {
            output.utxos.push(utxo);
        }
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
    Some(Utxo::new(
        note,
        tree,
        position,
        commitment.source.clone(),
        UtxoCommitmentKind::Transact,
    ))
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
    let note = Note {
        token_hash: commitment.preimage.token.id(),
        value: U256::from(commitment.preimage.value.to::<u128>()),
        random,
        npk: commitment.preimage.npk,
    };
    Some(Utxo::new(
        note,
        tree,
        position,
        commitment.source.clone(),
        UtxoCommitmentKind::Shield,
    ))
}

fn scan_transact_commitment(
    commitment: &IndexedTransactCommitmentInput,
    keys: &WalletScanKeys,
) -> Option<Utxo> {
    let (tree, position) =
        normalize_tree_position(commitment.tree_number, commitment.tree_position);
    let shared_key = shared_symmetric_key(
        &keys.viewing_private_key,
        &commitment.blinded_sender_viewing_key.0,
    )
    .ok()?;
    let note = Note::decrypt_v2(
        &commitment.ciphertext,
        commitment.memo.as_ref(),
        &shared_key,
        keys.master_public_key,
    )
    .ok()?;
    if note.commitment() != commitment.hash {
        return None;
    }
    Some(Utxo::new(
        note,
        tree,
        position,
        commitment.source.clone(),
        UtxoCommitmentKind::Transact,
    ))
}

fn encrypted_random_from_u256(value: [U256; 2]) -> (FixedBytes<32>, FixedBytes<16>) {
    let data = value[1].to_be_bytes::<32>();
    let mut data16 = [0u8; 16];
    data16.copy_from_slice(&data[16..]);
    (
        FixedBytes::from(value[0].to_be_bytes::<32>()),
        FixedBytes::from(data16),
    )
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
    Some(Utxo::new(
        preimage.note_with_random(random),
        tree,
        position,
        source,
        UtxoCommitmentKind::Shield,
    ))
}

fn source_from_log(
    log: &Log,
    block_timestamps: &HashMap<u64, u64>,
) -> Result<UtxoSource, WalletScanError> {
    let block_number = log
        .block_number
        .ok_or(WalletScanError::MissingLogMetadata("block_number"))?;
    let block_timestamp = block_timestamps
        .get(&block_number)
        .copied()
        .ok_or(WalletScanError::MissingLogMetadata("block_timestamp"))?;

    Ok(UtxoSource {
        tx_hash: log
            .transaction_hash
            .ok_or(WalletScanError::MissingLogMetadata("transaction_hash"))?,
        block_number,
        block_timestamp,
    })
}
