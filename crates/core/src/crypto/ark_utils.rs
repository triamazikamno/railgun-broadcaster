use alloy::primitives::U256;
use ark_ff::{BigInteger, PrimeField};

#[must_use]
pub fn prime_field_to_u256<F: PrimeField>(value: F) -> U256 {
    let bytes = value.into_bigint().to_bytes_be();
    if bytes.is_empty() {
        U256::ZERO
    } else {
        U256::from_be_slice(&bytes)
    }
}
