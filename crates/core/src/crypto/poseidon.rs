use alloy::primitives::U256;
use rs_poseidon::poseidon::hash;
use ruint::uint;

const SCALAR_FIELD: U256 =
    uint!(21888242871839275222246405745257275088548364400416034343698204186575808495617_U256);

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
