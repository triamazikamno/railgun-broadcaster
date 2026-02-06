use alloy::primitives::{Address, FixedBytes, U256};
use thiserror::Error;

use crate::crypto::aes_gcm::{AesGcmError, decrypt_in_place_16b_iv, split_iv_tag};
use crate::crypto::poseidon::poseidon;

#[derive(Debug, Error)]
pub enum NoteError {
    #[error("ciphertext too short")]
    CiphertextTooShort,
    #[error("invalid iv/tag length")]
    InvalidIvTag,
    #[error("invalid key")]
    InvalidKey,
    #[error("encrypt failed")]
    EncryptFailed,
    #[error("decrypt failed")]
    DecryptFailed,
    #[error(transparent)]
    AesGcm(#[from] AesGcmError),
    #[error("invalid viewing key")]
    InvalidViewingKey,
}

#[derive(Debug, Clone)]
pub struct Note {
    pub token_hash: U256,
    pub value: U256,
    pub random: [u8; 16],
    pub npk: U256,
}

impl Note {
    #[must_use]
    pub fn new_unshield(to: Address, token_address: Address, value: U256) -> Self {
        let token_hash = U256::from_be_slice(token_address.as_slice());
        let npk = U256::from_be_slice(to.as_slice());
        Self {
            token_hash,
            value,
            random: [0u8; 16],
            npk,
        }
    }

    #[must_use]
    pub fn new_change(
        master_public_key: U256,
        token_address: Address,
        value: U256,
        random: [u8; 16],
    ) -> Self {
        let token_hash = U256::from_be_slice(token_address.as_slice());
        let npk = note_public_key(master_public_key, random);
        Self {
            token_hash,
            value,
            random,
            npk,
        }
    }

    #[must_use]
    pub fn commitment(&self) -> U256 {
        poseidon(vec![self.npk, self.token_hash, self.value])
    }

    pub fn decrypt_v2(
        ciphertext: &[FixedBytes<32>; 4],
        memo: &[u8],
        shared_key: &[u8; 32],
        receiver_mpk: U256,
    ) -> Result<Self, NoteError> {
        let (iv, tag) = split_iv_tag(ciphertext[0].0);
        let mut ct = Vec::with_capacity(32 * 3 + memo.len());
        ct.extend_from_slice(&ciphertext[1].0);
        ct.extend_from_slice(&ciphertext[2].0);
        ct.extend_from_slice(&ciphertext[3].0);
        ct.extend_from_slice(memo);

        let mut pt = ct;
        decrypt_in_place_16b_iv(shared_key, &iv, &tag, &mut pt)?;
        if pt.len() < 96 {
            return Err(NoteError::CiphertextTooShort);
        }

        let mut encoded_mpk = [0u8; 32];
        encoded_mpk.copy_from_slice(&pt[..32]);
        let mut token_hash = [0u8; 32];
        token_hash.copy_from_slice(&pt[32..64]);
        let mut random = [0u8; 16];
        random.copy_from_slice(&pt[64..80]);
        let mut value_bytes = [0u8; 16];
        value_bytes.copy_from_slice(&pt[80..96]);

        let token_hash = U256::from_be_bytes(token_hash);
        let value = U256::from_be_slice(&value_bytes);
        let npk = note_public_key(receiver_mpk, random);
        Ok(Self {
            token_hash,
            value,
            random,
            npk,
        })
    }
}

#[must_use]
pub fn note_public_key(master_public_key: U256, random: [u8; 16]) -> U256 {
    let random_value = U256::from_be_slice(&random);
    poseidon(vec![master_public_key, random_value])
}

pub fn decrypt_shield_random(
    encrypted_bundle: &[FixedBytes<32>; 3],
    shared_key: &[u8; 32],
) -> Result<[u8; 16], NoteError> {
    let (iv, tag) = split_iv_tag(encrypted_bundle[0].0);
    let mut ct = Vec::with_capacity(32);
    ct.extend_from_slice(&encrypted_bundle[1].0[..16]);

    let mut pt = ct;
    decrypt_in_place_16b_iv(shared_key, &iv, &tag, &mut pt)?;
    if pt.len() < 16 {
        return Err(NoteError::CiphertextTooShort);
    }
    let mut random = [0u8; 16];
    random.copy_from_slice(&pt[..16]);
    Ok(random)
}
