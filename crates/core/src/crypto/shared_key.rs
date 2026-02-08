use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha256};
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

fn ed25519_private_scalar(seed32: &[u8; 32]) -> Scalar {
    let hash = sha2::Sha512::digest(seed32);
    let mut head = [0u8; 32];
    head.copy_from_slice(&hash[..32]);
    head[0] &= 248;
    head[31] &= 127;
    head[31] |= 64;
    Scalar::from_bytes_mod_order(head)
}
