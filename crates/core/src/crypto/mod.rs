use alloy::primitives::U256;
use alloy::primitives::keccak256;
use ruint::uint;

pub mod aes_gcm;
pub mod ark_utils;
pub mod poseidon;
pub mod railgun;
pub mod shared_key;
pub mod snark_proof;

pub const SCALAR_FIELD: U256 =
    uint!(21888242871839275222246405745257275088548364400416034343698204186575808495617_U256);

#[must_use]
pub fn hash_to_scalar(encoded: impl AsRef<[u8]>) -> U256 {
    let hash = keccak256(encoded.as_ref());
    let value = U256::from_be_bytes(hash.0);
    value % SCALAR_FIELD
}
