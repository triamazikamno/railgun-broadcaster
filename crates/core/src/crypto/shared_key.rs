use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SharedKeyError {
    #[error("ed25519 pubkey invalid")]
    InvalidEd25519Pubkey,
}

pub fn shared_symmetric_key(
    viewing_private_key: &[u8; 32],
    blinded_public_key: &[u8; 32],
) -> Result<[u8; 32], SharedKeyError> {
    let comp = CompressedEdwardsY(*blinded_public_key);
    let point = comp
        .decompress()
        .ok_or(SharedKeyError::InvalidEd25519Pubkey)?;

    let scalar = ed25519_private_scalar(viewing_private_key);
    let shared_point = (point * scalar).compress().to_bytes();
    let digest = Sha256::digest(shared_point);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    Ok(out)
}

pub fn shared_symmetric_key_legacy(
    viewing_private_key: &[u8; 32],
    blinded_public_key: &[u8; 32],
) -> Result<[u8; 32], SharedKeyError> {
    let comp = CompressedEdwardsY(*blinded_public_key);
    let point = comp
        .decompress()
        .ok_or(SharedKeyError::InvalidEd25519Pubkey)?;

    let scalar = ed25519_private_scalar(viewing_private_key);
    Ok((point * scalar).compress().to_bytes())
}

pub(crate) fn ed25519_private_scalar_bytes(seed32: &[u8; 32]) -> [u8; 32] {
    let hash = Sha512::digest(seed32);
    clamp25519(hash[..32].try_into().expect("sha512 output is 512 bits"))
}

fn ed25519_private_scalar(seed32: &[u8; 32]) -> Scalar {
    Scalar::from_bytes_mod_order(ed25519_private_scalar_bytes(seed32))
}

const fn clamp25519(mut bytes: [u8; 32]) -> [u8; 32] {
    bytes[0] &= 0b1111_1000;
    bytes[31] &= 0b0111_1111;
    bytes[31] |= 0b0100_0000;
    bytes
}
