use alloy::primitives::{FixedBytes, U256};

use crate::crypto::poseidon::poseidon;
use crate::notes::Note;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtxoSource {
    pub tx_hash: FixedBytes<32>,
    pub block_number: u64,
}

#[derive(Debug, Clone)]
pub struct Utxo {
    pub note: Note,
    pub tree: u32,
    pub position: u64,
    pub source: UtxoSource,
}

impl Utxo {
    #[must_use]
    pub fn nullifier(&self, nullifying_key: U256) -> U256 {
        poseidon(vec![nullifying_key, U256::from(self.position)])
    }
}

#[derive(Debug, Clone)]
pub struct WalletUtxo {
    pub utxo: Utxo,
    pub spent: Option<UtxoSource>,
}

impl WalletUtxo {
    #[must_use]
    pub const fn new(utxo: Utxo) -> Self {
        Self { utxo, spent: None }
    }

    #[must_use]
    pub const fn is_spent(&self) -> bool {
        self.spent.is_some()
    }
}
