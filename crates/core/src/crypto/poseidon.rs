use alloy::primitives::U256;
use rs_poseidon::poseidon::hash;

use crate::crypto::SCALAR_FIELD;

#[must_use]
pub fn poseidon(inputs: Vec<U256>) -> U256 {
    let mut inputs = inputs;
    for input in &mut inputs {
        if *input >= SCALAR_FIELD {
            *input %= SCALAR_FIELD;
        }
    }

    hash(&inputs)
}
