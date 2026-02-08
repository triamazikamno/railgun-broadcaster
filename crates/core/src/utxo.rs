use alloy::primitives::U256;

use crate::crypto::poseidon::poseidon;
use crate::notes::Note;

#[derive(Debug, Clone)]
pub struct Utxo {
    pub note: Note,
    pub tree: u32,
    pub position: u64,
}

impl Utxo {
    #[must_use]
    pub fn nullifier(&self, nullifying_key: U256) -> U256 {
        poseidon(vec![nullifying_key, U256::from(self.position)])
    }
}
