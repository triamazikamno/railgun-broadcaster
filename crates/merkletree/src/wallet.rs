use std::collections::HashSet;

use alloy::primitives::U256;
use alloy::sol_types::{Error as SolError, SolEvent};
use alloy_rpc_types_eth::Log;
use thiserror::Error;

use broadcaster_core::crypto::railgun::ViewingKeyData;
use broadcaster_core::crypto::shared_key::shared_symmetric_key;
use broadcaster_core::notes::{Note, decrypt_shield_random};
use broadcaster_core::utxo::Utxo;

use crate::errors::SyncError;
use crate::slow::types::{
    CommitmentBatch, GeneratedCommitmentBatch, IntoCommitmentUpdates, Nullified, Nullifiers,
    Shield, ShieldLegacyPreMar23, Transact,
};
use crate::tree::{MerkleForest, normalize_tree_position};

#[derive(Debug, Error)]
pub enum WalletScanError {
    #[error("decode log: {0}")]
    Decode(#[from] SolError),
    #[error("apply commitment updates: {0}")]
    Update(#[from] SyncError),
}

pub type WalletScanKeys = ViewingKeyData;

#[derive(Debug)]
pub struct WalletLogDelta {
    pub utxos: Vec<Utxo>,
    pub nullifiers: Vec<U256>,
}

pub fn parse_wallet_delta_from_logs(
    logs: &[Log],
    keys: &WalletScanKeys,
) -> Result<WalletLogDelta, WalletScanError> {
    let mut utxos = Vec::new();
    let mut nullifiers = HashSet::new();

    for raw_log in logs {
        let topic0 = raw_log.inner.topics().first().copied().unwrap_or_default();
        if topic0 == Transact::SIGNATURE_HASH {
            let event = Transact::decode_log(&raw_log.inner)?.data;

            let tree_number: u32 = event.treeNumber.to();
            let start_pos: u64 = event.startPosition.to();
            let commitment_hashes = &event.hash;
            for (index, ciphertext) in event.ciphertext.iter().enumerate() {
                let position = start_pos + index as u64;
                let (tree_number, tree_position) = normalize_tree_position(tree_number, position);

                let shared_key = shared_symmetric_key(
                    &keys.viewing_private_key,
                    &ciphertext.blindedSenderViewingKey.0,
                );
                let Ok(shared_key) = shared_key else {
                    continue;
                };

                let note = Note::decrypt_v2(
                    &ciphertext.ciphertext,
                    ciphertext.memo.as_ref(),
                    &shared_key,
                    keys.master_public_key,
                );
                if let Ok(note) = note {
                    let commitment = note.commitment();
                    let expected = commitment_hashes
                        .get(index)
                        .map(|h| U256::from_be_bytes(h.0));
                    if expected.is_some_and(|hash| hash == commitment) {
                        utxos.push(Utxo {
                            note,
                            tree: tree_number,
                            position: tree_position,
                        });
                    }
                }
            }
        } else if topic0 == Shield::SIGNATURE_HASH {
            let event = Shield::decode_log(&raw_log.inner)?.data;

            let tree_number: u32 = event.treeNumber.to();
            let start_pos: u64 = event.startPosition.to();
            for (index, preimage) in event.commitments.iter().enumerate() {
                let position = start_pos + index as u64;
                let (tree_number, tree_position) = normalize_tree_position(tree_number, position);

                if let Some(ciphertext) = event.shieldCiphertext.get(index) {
                    let shared_key =
                        shared_symmetric_key(&keys.viewing_private_key, &ciphertext.shieldKey.0);
                    let Ok(shared_key) = shared_key else {
                        continue;
                    };
                    let random = decrypt_shield_random(&ciphertext.encryptedBundle, &shared_key);
                    let Ok(random) = random else {
                        continue;
                    };
                    let note = preimage.note_with_random(random);
                    utxos.push(Utxo {
                        note,
                        tree: tree_number,
                        position: tree_position,
                    });
                }
            }
        } else if topic0 == Nullifiers::SIGNATURE_HASH {
            let event = Nullifiers::decode_log(&raw_log.inner)?.data;
            for nullifier in event.nullifier {
                nullifiers.insert(nullifier);
            }
        } else if topic0 == Nullified::SIGNATURE_HASH {
            let event = Nullified::decode_log(&raw_log.inner)?.data;
            for nullifier in event.nullifier {
                nullifiers.insert(U256::from_be_bytes(nullifier.0));
            }
        }
    }

    Ok(WalletLogDelta {
        utxos,
        nullifiers: nullifiers.into_iter().collect(),
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
