use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::Address as ContractAddress;
use alloy::primitives::U256;
use broadcaster_core::notes::Note;
use broadcaster_core::utxo::Utxo;
use local_db::{DbError, DbStore, WalletMeta};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WalletCacheError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("db error: {0}")]
    Db(#[from] DbError),
    #[error("encode error: {0}")]
    Encode(#[from] rmp_serde::encode::Error),
    #[error("decode error: {0}")]
    Decode(#[from] rmp_serde::decode::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedNote {
    token_hash: U256,
    value: U256,
    random: [u8; 16],
    npk: U256,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedUtxo {
    note: CachedNote,
    tree: u32,
    position: u64,
}

impl From<&Utxo> for CachedUtxo {
    fn from(utxo: &Utxo) -> Self {
        Self {
            note: CachedNote {
                token_hash: utxo.note.token_hash,
                value: utxo.note.value,
                random: utxo.note.random,
                npk: utxo.note.npk,
            },
            tree: utxo.tree,
            position: utxo.position,
        }
    }
}

impl CachedUtxo {
    fn into_utxo(self) -> Utxo {
        Utxo {
            note: Note {
                token_hash: self.note.token_hash,
                value: self.note.value,
                random: self.note.random,
                npk: self.note.npk,
            },
            tree: self.tree,
            position: self.position,
        }
    }

    fn utxo_id(&self) -> String {
        format!("{}:{}", self.tree, self.position)
    }
}

pub fn wallet_cache_key(
    wallet_id: &str,
    chain_id: u64,
    contract_address: ContractAddress,
) -> String {
    format!("{wallet_id}|{chain_id}|{contract_address}")
}

pub trait WalletCacheDbExt {
    fn store_unspent_utxos(
        &self,
        wallet_id: &str,
        utxos: &[Utxo],
        last_scanned_block: Option<u64>,
        last_scanned_block_hash: Option<[u8; 32]>,
    ) -> Result<(), WalletCacheError>;

    fn load_unspent_utxos(&self, wallet_id: &str) -> Result<Vec<Utxo>, WalletCacheError>;
}

impl WalletCacheDbExt for DbStore {
    fn store_unspent_utxos(
        &self,
        wallet_id: &str,
        utxos: &[Utxo],
        last_scanned_block: Option<u64>,
        last_scanned_block_hash: Option<[u8; 32]>,
    ) -> Result<(), WalletCacheError> {
        self.clear_wallet_unspent(wallet_id)?;
        for utxo in utxos {
            let cached = CachedUtxo::from(utxo);
            let payload = rmp_serde::to_vec_named(&cached)?;
            self.put_wallet_unspent(wallet_id, &cached.utxo_id(), &payload)?;
        }

        if let Some(last_scanned_block) = last_scanned_block {
            let meta = WalletMeta {
                last_scanned_block,
                updated_at: now_epoch_secs()?,
                last_scanned_block_hash,
            };
            self.put_wallet_meta(wallet_id, &meta)?;
        }

        Ok(())
    }

    fn load_unspent_utxos(&self, wallet_id: &str) -> Result<Vec<Utxo>, WalletCacheError> {
        let entries = self.list_wallet_unspent(wallet_id)?;
        let mut out = Vec::with_capacity(entries.len());
        for entry in entries {
            let cached: CachedUtxo = rmp_serde::from_slice(&entry.payload)?;
            out.push(cached.into_utxo());
        }
        Ok(out)
    }
}

fn now_epoch_secs() -> Result<u64, std::io::Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(std::io::Error::other)
}
