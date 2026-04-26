use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::Address as ContractAddress;
use alloy::primitives::{FixedBytes, U256};
use broadcaster_core::notes::Note;
use broadcaster_core::utxo::{Utxo, UtxoSource, WalletUtxo};
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
    #[error("encrypted wallet cache failed")]
    Crypto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedNote {
    token_hash: U256,
    value: U256,
    random: [u8; 16],
    npk: U256,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedUtxoSource {
    tx_hash: [u8; 32],
    block_number: u64,
}

impl From<&UtxoSource> for CachedUtxoSource {
    fn from(source: &UtxoSource) -> Self {
        Self {
            tx_hash: source.tx_hash.0,
            block_number: source.block_number,
        }
    }
}

impl CachedUtxoSource {
    fn into_source(self) -> UtxoSource {
        UtxoSource {
            tx_hash: FixedBytes::from(self.tx_hash),
            block_number: self.block_number,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedWalletUtxo {
    note: CachedNote,
    tree: u32,
    position: u64,
    source: CachedUtxoSource,
    spent: Option<CachedUtxoSource>,
}

impl From<&WalletUtxo> for CachedWalletUtxo {
    fn from(wallet_utxo: &WalletUtxo) -> Self {
        let utxo = &wallet_utxo.utxo;
        Self {
            note: CachedNote {
                token_hash: utxo.note.token_hash,
                value: utxo.note.value,
                random: utxo.note.random,
                npk: utxo.note.npk,
            },
            tree: utxo.tree,
            position: utxo.position,
            source: CachedUtxoSource::from(&utxo.source),
            spent: wallet_utxo.spent.as_ref().map(CachedUtxoSource::from),
        }
    }
}

impl CachedWalletUtxo {
    fn into_wallet_utxo(self) -> WalletUtxo {
        let utxo = Utxo {
            note: Note {
                token_hash: self.note.token_hash,
                value: self.note.value,
                random: self.note.random,
                npk: self.note.npk,
            },
            tree: self.tree,
            position: self.position,
            source: self.source.into_source(),
        };
        WalletUtxo {
            utxo,
            spent: self.spent.map(CachedUtxoSource::into_source),
        }
    }

    fn utxo_id(&self) -> String {
        format!("{}:{}", self.tree, self.position)
    }
}

pub fn serialize_wallet_utxo(utxo: &WalletUtxo) -> Result<Vec<u8>, WalletCacheError> {
    Ok(rmp_serde::to_vec_named(&CachedWalletUtxo::from(utxo))?)
}

pub fn deserialize_wallet_utxo(payload: &[u8]) -> Result<WalletUtxo, WalletCacheError> {
    let cached: CachedWalletUtxo = rmp_serde::from_slice(payload)?;
    Ok(cached.into_wallet_utxo())
}

#[must_use]
pub fn wallet_utxo_stable_identity(utxo: &WalletUtxo) -> Vec<u8> {
    let note = &utxo.utxo.note;
    let source = &utxo.utxo.source;
    let mut out = Vec::with_capacity(32 + 32 + 32 + 16 + 32);
    out.extend_from_slice(source.tx_hash.as_slice());
    out.extend_from_slice(&note.token_hash.to_be_bytes::<32>());
    out.extend_from_slice(&note.value.to_be_bytes::<32>());
    out.extend_from_slice(&note.random);
    out.extend_from_slice(&note.npk.to_be_bytes::<32>());
    out
}

pub fn wallet_cache_key(
    wallet_id: &str,
    chain_id: u64,
    contract_address: ContractAddress,
) -> String {
    format!("{wallet_id}|{chain_id}|{contract_address}")
}

pub trait WalletCacheDbExt {
    fn store_wallet_utxos(
        &self,
        wallet_id: &str,
        utxos: &[WalletUtxo],
        last_scanned_block: Option<u64>,
        last_scanned_block_hash: Option<[u8; 32]>,
    ) -> Result<(), WalletCacheError>;

    fn load_wallet_utxos(&self, wallet_id: &str) -> Result<Vec<WalletUtxo>, WalletCacheError>;
}

impl WalletCacheDbExt for DbStore {
    fn store_wallet_utxos(
        &self,
        wallet_id: &str,
        utxos: &[WalletUtxo],
        last_scanned_block: Option<u64>,
        last_scanned_block_hash: Option<[u8; 32]>,
    ) -> Result<(), WalletCacheError> {
        let utxo_entries: Vec<(String, Vec<u8>)> = utxos
            .iter()
            .map(|utxo| {
                let cached = CachedWalletUtxo::from(utxo);
                let payload = serialize_wallet_utxo(utxo)?;
                Ok((cached.utxo_id(), payload))
            })
            .collect::<Result<_, WalletCacheError>>()?;

        let meta = last_scanned_block
            .map(|block| {
                Ok::<_, WalletCacheError>(WalletMeta {
                    last_scanned_block: block,
                    updated_at: now_epoch_secs()?,
                    last_scanned_block_hash,
                })
            })
            .transpose()?;

        self.batch_store_wallet_utxos(wallet_id, &utxo_entries, meta.as_ref())?;
        Ok(())
    }

    fn load_wallet_utxos(&self, wallet_id: &str) -> Result<Vec<WalletUtxo>, WalletCacheError> {
        let entries = self.list_wallet_utxos(wallet_id)?;
        let mut out = Vec::with_capacity(entries.len());
        for entry in entries {
            out.push(deserialize_wallet_utxo(&entry.payload)?);
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
