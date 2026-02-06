use aes_gcm::aead::AeadInPlace;
use aes_gcm::{AesGcm, KeyInit, Nonce, Tag};
use getrandom::fill;

#[derive(Debug, thiserror::Error)]
pub enum AesGcmError {
    #[error("invalid key")]
    InvalidKey,
    #[error("random generation failed")]
    RandomFailed,
    #[error("encrypt failed")]
    EncryptFailed,
    #[error("decrypt failed")]
    DecryptFailed,
}

type Aes256Gcm16 = AesGcm<aes::Aes256, typenum::U16>;

pub fn decrypt_in_place_16b_iv(
    key: &[u8; 32],
    iv: &[u8; 16],
    tag: &[u8; 16],
    buffer: &mut [u8],
) -> Result<(), AesGcmError> {
    let cipher = Aes256Gcm16::new_from_slice(key).map_err(|_| AesGcmError::InvalidKey)?;
    #[allow(deprecated)]
    let nonce = Nonce::from_slice(iv);
    #[allow(deprecated)]
    let tag = Tag::from_slice(tag);
    cipher
        .decrypt_in_place_detached(nonce, b"", buffer, tag)
        .map_err(|_| AesGcmError::DecryptFailed)
}

pub fn encrypt_in_place_16b_iv(key: &[u8; 32], buffer: &mut [u8]) -> Result<[u8; 32], AesGcmError> {
    let mut iv = [0u8; 16];
    fill(&mut iv).map_err(|_| AesGcmError::RandomFailed)?;
    let cipher = Aes256Gcm16::new_from_slice(key).map_err(|_| AesGcmError::InvalidKey)?;
    #[allow(deprecated)]
    let nonce = Nonce::from_slice(&iv);
    let tag = cipher
        .encrypt_in_place_detached(nonce, b"", buffer)
        .map_err(|_| AesGcmError::EncryptFailed)?;

    let mut iv_tag = [0u8; 32];
    iv_tag[..16].copy_from_slice(&iv);
    iv_tag[16..].copy_from_slice(&tag);
    Ok(iv_tag)
}

#[must_use]
pub fn split_iv_tag(iv_tag: [u8; 32]) -> ([u8; 16], [u8; 16]) {
    let mut iv = [0u8; 16];
    let mut tag = [0u8; 16];
    iv.copy_from_slice(&iv_tag[..16]);
    tag.copy_from_slice(&iv_tag[16..]);
    (iv, tag)
}
