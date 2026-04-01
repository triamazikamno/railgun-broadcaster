use alloy::primitives::{Address, FixedBytes, U256, Uint, keccak256};
use alloy::sol_types::SolCall;

use crate::contracts::railgun::{
    CommitmentPreimage, ShieldCiphertext, ShieldRequest, TokenData, approveCall, shieldCall,
};
use crate::crypto::aes_gcm::{AesGcmError, encrypt_in_place_16b_iv};
use crate::crypto::shared_key::{SharedKeyError, shared_symmetric_key};
use crate::notes::note_public_key;

use ed25519_dalek::SigningKey;
use getrandom::fill;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ShieldError {
    #[error("random generation failed")]
    RandomFailed,
    #[error("shared key derivation failed: {0}")]
    SharedKey(#[from] SharedKeyError),
    #[error("encryption failed: {0}")]
    Encrypt(#[from] AesGcmError),
    #[error("invalid EVM private key")]
    InvalidPrivateKey,
    #[error("ECDSA signing failed")]
    SigningFailed,
}

/// Build ABI-encoded calldata for `shield(ShieldRequest[])`.
///
/// `shield_private_key` is the 32-byte key derived from `keccak256(evm_sign("RAILGUN_SHIELD"))`.
pub fn build_shield_calldata(
    master_public_key: U256,
    viewing_public_key: &[u8; 32],
    token_address: Address,
    amount: U256,
    shield_private_key: &[u8; 32],
) -> Result<Vec<u8>, ShieldError> {
    let mut random = [0u8; 16];
    fill(&mut random).map_err(|_| ShieldError::RandomFailed)?;

    let npk = note_public_key(master_public_key, random);

    let preimage = CommitmentPreimage {
        npk: FixedBytes::from(npk.to_be_bytes::<32>()),
        token: TokenData {
            tokenType: 0,
            tokenAddress: token_address,
            tokenSubID: U256::ZERO,
        },
        value: Uint::<120, 2>::from(amount),
    };

    let ciphertext = encrypt_shield_random(random, shield_private_key, viewing_public_key)?;

    let request = ShieldRequest {
        preimage,
        ciphertext,
    };

    Ok(shieldCall {
        _shieldRequests: vec![request],
    }
    .abi_encode())
}

/// Build ABI-encoded calldata for ERC-20 `approve(spender, amount)`.
#[must_use]
pub fn build_approve_calldata(spender: Address, amount: U256) -> Vec<u8> {
    approveCall { spender, amount }.abi_encode()
}

/// Derive `shieldPrivateKey` from an EVM private key.
///
/// Signs the fixed message `"RAILGUN_SHIELD"` using EIP-191 personal sign,
/// then returns `keccak256(signature)`.
pub fn derive_shield_private_key(evm_private_key: &[u8; 32]) -> Result<[u8; 32], ShieldError> {
    let msg = b"RAILGUN_SHIELD";

    // EIP-191 personal sign hash: keccak256("\x19Ethereum Signed Message:\n" + len + msg)
    let prefix = format!("\x19Ethereum Signed Message:\n{}", msg.len());
    let mut hash_input = Vec::with_capacity(prefix.len() + msg.len());
    hash_input.extend_from_slice(prefix.as_bytes());
    hash_input.extend_from_slice(msg);
    let msg_hash = keccak256(&hash_input);

    // secp256k1 ECDSA sign
    let signing_key = k256::ecdsa::SigningKey::from_bytes(evm_private_key.into())
        .map_err(|_| ShieldError::InvalidPrivateKey)?;
    let (signature, recovery_id) = signing_key
        .sign_prehash_recoverable(msg_hash.as_ref())
        .map_err(|_| ShieldError::SigningFailed)?;

    // 65-byte signature: r (32) + s (32) + v (1)
    let mut sig_bytes = [0u8; 65];
    sig_bytes[..64].copy_from_slice(&signature.to_bytes());
    sig_bytes[64] = recovery_id.to_byte() + 27;

    Ok(keccak256(sig_bytes).0)
}

fn encrypt_shield_random(
    random: [u8; 16],
    shield_private_key: &[u8; 32],
    viewing_public_key: &[u8; 32],
) -> Result<ShieldCiphertext, ShieldError> {
    // Derive the ed25519 public key from shield_private_key to use as shieldKey
    let shield_public_key = SigningKey::from_bytes(shield_private_key)
        .verifying_key()
        .to_bytes();

    // Compute shared symmetric key via ECDH
    let shared_key = shared_symmetric_key(shield_private_key, viewing_public_key)?;

    // Encrypt the 16-byte random
    let mut buffer = random;
    let iv_tag = encrypt_in_place_16b_iv(&shared_key, &mut buffer)?;

    // Pack into ShieldCiphertext: encryptedBundle[0] = iv||tag, encryptedBundle[1] = encrypted random (padded), encryptedBundle[2] = zeros
    let mut bundle = [FixedBytes::<32>::ZERO; 3];
    bundle[0] = FixedBytes::from(iv_tag);
    let mut padded_ct = [0u8; 32];
    padded_ct[..16].copy_from_slice(&buffer);
    bundle[1] = FixedBytes::from(padded_ct);
    // bundle[2] stays zero

    Ok(ShieldCiphertext {
        encryptedBundle: bundle,
        shieldKey: FixedBytes::from(shield_public_key),
    })
}
