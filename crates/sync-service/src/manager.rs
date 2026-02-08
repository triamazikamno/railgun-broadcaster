use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use local_db::DbStore;

use crate::chain::ChainHandle;
use crate::chain::{ChainError, ChainService};
use crate::types::{ChainConfig, ChainKey, WalletConfig};
use crate::wallet::WalletHandle;

#[derive(Debug, thiserror::Error)]
pub enum SyncManagerError {
    #[error("chain not found")]
    ChainNotFound,
    #[error("wallet not found")]
    WalletNotFound,
    #[error("chain error: {0}")]
    Chain(#[from] ChainError),
}

pub struct SyncManager {
    db: Arc<DbStore>,
    chains: RwLock<HashMap<ChainKey, Arc<ChainService>>>,
}

impl SyncManager {
    pub fn new(db: Arc<DbStore>) -> Self {
        Self {
            db,
            chains: RwLock::new(HashMap::new()),
        }
    }

    pub async fn add_chain(&self, cfg: ChainConfig) -> Result<Arc<ChainService>, SyncManagerError> {
        let key = ChainKey {
            chain_id: cfg.chain_id,
            contract: cfg.contract,
        };
        if let Some(existing) = self.chains.read().await.get(&key) {
            return Ok(Arc::clone(existing));
        }

        let service = ChainService::start(Arc::clone(&self.db), cfg).await?;
        self.chains.write().await.insert(key, Arc::clone(&service));
        Ok(service)
    }

    pub async fn remove_chain(&self, key: &ChainKey) {
        if let Some((_key, service)) = self.chains.write().await.remove_entry(key) {
            service.shutdown();
        }
    }

    pub async fn add_wallet(&self, cfg: WalletConfig) -> Result<WalletHandle, SyncManagerError> {
        let chain = self
            .chains
            .read()
            .await
            .get(&cfg.chain)
            .cloned()
            .ok_or(SyncManagerError::ChainNotFound)?;
        Ok(chain.register_wallet(cfg).await)
    }

    pub async fn chain_handle(&self, chain: &ChainKey) -> Option<ChainHandle> {
        self.chains
            .read()
            .await
            .get(chain)
            .map(|service| service.handle())
    }

    pub async fn wallet_handle(&self, chain: &ChainKey, cache_key: &str) -> Option<WalletHandle> {
        let chain = self.chains.read().await.get(chain).cloned()?;
        chain.wallet_handle(cache_key).await
    }

    pub async fn remove_wallet(
        &self,
        chain: &ChainKey,
        cache_key: &str,
    ) -> Result<(), SyncManagerError> {
        let chain = self
            .chains
            .read()
            .await
            .get(chain)
            .cloned()
            .ok_or(SyncManagerError::ChainNotFound)?;
        chain.unregister_wallet(cache_key).await;
        Ok(())
    }

    pub async fn reset_wallet(
        &self,
        cache_key: &str,
        from_block: Option<u64>,
    ) -> Result<(), SyncManagerError> {
        let chains = self.chains.read().await;
        for service in chains.values() {
            match service.reset_wallet(cache_key, from_block).await {
                Ok(()) => return Ok(()),
                Err(ChainError::WalletNotFound) => continue,
                Err(err) => return Err(SyncManagerError::Chain(err)),
            }
        }
        Err(SyncManagerError::WalletNotFound)
    }
}
