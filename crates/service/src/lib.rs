mod auto_refill;
mod evm_tx;
#[cfg(test)]
mod executor_tests;
mod fee_note_assurance;
mod fee_note_store;
mod fee_note_worker;
mod fees_publisher;
mod manager;
mod poi_validation;
mod service_init;
#[cfg(test)]
mod shutdown_tests;
mod transact_submitter;
mod utxo_consolidation;

use alloy::network::EthereumWallet;
use alloy::primitives::{Address, Bytes, ChainId, FixedBytes, U256};
use alloy::signers::k256::ecdsa::SigningKey;
use alloy::signers::local::{LocalSigner, LocalSignerError};
use alloy::transports::TransportErrorKind;
use alloy::{sol, uint};
use broadcaster_core::crypto::railgun::{Address as RailgunAddress, RailgunError};
use broadcaster_core::query_rpc_pool::QueryRpcPool;
use broadcaster_core::transact::{
    DecryptedTransact, ParsedTransactCalldata, TransactError, parse_transact_calldata,
    try_decrypt_transact_request,
};
use fees::{FeesError, Manager as FeesManager};
use local_db::DbStore;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::time::Duration;
use thiserror::Error;
use tracing::{info, warn};
use tx_submit::TxBroadcaster;
use waku_relay::client::Client;

pub use crate::evm_tx::SubmitTxError;
use crate::fee_note_assurance::FeeNoteAssuranceSubmissionTracker;
use crate::fee_note_worker::FeeNoteAssuranceFallback;
pub use crate::manager::BroadcasterManager;
pub use crate::poi_validation::BroadcasterPoiValidator;
pub use crate::service_init::BroadcasterServiceDeps;
use poi::error::PoiError;
use railgun_wallet::Utxo;
use sync_service::SyncManagerError;

async fn unspent_utxos(wallet_handle: &sync_service::WalletHandle) -> Vec<Utxo> {
    let Some(snapshot) = wallet_handle.current_snapshot() else {
        return Vec::new();
    };
    snapshot
        .utxos
        .iter()
        .filter(|entry| {
            !entry.is_spent()
                && !snapshot
                    .pending_overlay
                    .pending_spent
                    .iter()
                    .any(|spent| spent.key() == (entry.utxo.tree, entry.utxo.position))
                && !snapshot
                    .pending_overlay
                    .local_pending_spent
                    .iter()
                    .any(|spent| spent.matches_local_utxo(entry))
        })
        .map(|entry| entry.utxo.clone())
        .collect()
}

sol! {
    function balanceOf(address account) external view returns (uint256);
    struct Call {
        address to;
        bytes data;
        uint256 value;
    }
    function multicall(bool _requireSuccess, Call[] calldata _calls) external payable;
    function transfer(address recipient, uint256 amount) external;
}

pub const API_VERSION: &str = "8.3.0";

const WAD: U256 = uint!(1_000_000_000_000_000_000_U256);

#[derive(Debug, Error)]
pub enum HandleTransactError {
    #[error("failed to decrypt transact request: {0}")]
    Decrypt(#[from] TransactError),
    #[error("transact is not for us")]
    NotForUs,
    #[error("failed to parse transact calldata: {0}")]
    Parse(#[source] TransactError),
    #[error("validate pre tx poi: {0}")]
    Poi(#[from] PoiError),
    #[error("enqueue tx for submission: {0}")]
    Enqueue(#[from] kanal::SendError),
}

#[derive(Debug, Error)]
pub enum BroadcasterServiceError {
    #[error("local db failed: {0}")]
    Db(#[from] local_db::DbError),
    #[error("derive railgun address failed: {0}")]
    DeriveAddress(#[from] RailgunError),
    #[error("sync manager failed: {0}")]
    SyncManager(#[from] SyncManagerError),
    #[error("invalid viewing privkey")]
    InvalidViewingPrivkey,
    #[error("init tx broadcaster failed: {0}")]
    InitBroadcaster(#[from] tx_submit::BroadcasterInitError),
    #[error("missing multicall_contract")]
    MissingMulticallContract,
    #[error("missing query_rpc endpoints")]
    MissingQueryRpc,
    #[error("simulation failed: {0}")]
    SimulationFailed(#[from] alloy::transports::RpcError<TransportErrorKind>),
    #[error("failed to decode EVM private key: {0}")]
    DecodePrivateKey(#[from] alloy::signers::k256::ecdsa::signature::Error),
    #[error("mnemonic signer failed: {0}")]
    MnemonicSigner(#[from] LocalSignerError),
    #[error("failed to derive keys: {0}")]
    DeriveKeys(#[from] railgun_wallet::keys::KeyError),
    #[error("railgun_contract is not defined for this chain")]
    RailgunContractMissing,
    #[error("finality_depth is not defined for this chain")]
    FinalityDepthMissing,
    #[error("block_time is not defined for this chain")]
    BlockTimeMissing,
    #[error("anchor_interval is not defined for this chain")]
    AnchorIntervalMissing,
    #[error("archive_until_block is not defined for this chain")]
    ArchiveUntilBlockMissing,
    #[error("v2_start_block is not defined for this chain")]
    V2StartBlockMissing,
    #[error("legacy_shield_block is not defined for this chain")]
    LegacyShieldBlockMissing,
    #[error("deployment_block is not defined for this chain")]
    DeploymentBlockMissing,
    #[error("auto_refill requires relay_adapt_contract, which is not defined for this chain")]
    AutoRefillRequiresRelayAdapt,
}

#[derive(Debug, Error)]
pub enum BroadcasterManagerError {
    #[error("waku subscribe failed: {0}")]
    Subscribe(#[from] waku_relay::ClientError),
}

type ResponseSender = kanal::AsyncSender<(DecryptedTransact, ParsedTransactCalldata)>;
type ResponseReceiver = kanal::AsyncReceiver<(DecryptedTransact, ParsedTransactCalldata)>;

pub struct BroadcasterService {
    chain_id: ChainId,
    db: Arc<DbStore>,
    pending_fee_note_assurance_fallback: Arc<FeeNoteAssuranceFallback>,
    fee_note_assurance_submission_tracker: Arc<FeeNoteAssuranceSubmissionTracker>,
    key: [u8; 32],
    master_public_key: U256,
    addr: RailgunAddress,
    advertised_addr: RailgunAddress,
    tx: ResponseSender,
    rx: ResponseReceiver,
    broadcaster: Arc<TxBroadcaster>,
    fees_manager: Arc<FeesManager>,
    evm_wallets: Vec<(EthereumWallet, LocalSigner<SigningKey>)>,
    count_transact_requests: Arc<AtomicU32>,
    count_txs_landed: Arc<AtomicU32>,
    client: Arc<Client>,
    poi: Option<Arc<BroadcasterPoiValidator>>,
    required_poi_list: Vec<FixedBytes<32>>,
    query_rpc_pool: Arc<QueryRpcPool>,
    railgun_contract: Option<Address>,
    finality_depth: Option<u64>,
    receipt_poll_interval: Duration,
    relay_adapt_contract: Option<Address>,
    relay_adapt_7702_contract: Option<Address>,
    identifier: Option<String>,
    fees_refresh_interval: Duration,
    fees_ttl: Duration,
}

impl BroadcasterService {
    #[must_use]
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    #[must_use]
    pub const fn addr(&self) -> &RailgunAddress {
        &self.addr
    }

    #[must_use]
    pub const fn advertised_addr(&self) -> &RailgunAddress {
        &self.advertised_addr
    }

    pub async fn update_prices(&self) -> Result<(), FeesError> {
        self.fees_manager.update_prices().await
    }

    pub async fn handle_transact_request(
        &self,
        pubkey: [u8; 32],
        encrypted_data: &[Bytes; 2],
    ) -> Result<(), HandleTransactError> {
        let req = try_decrypt_transact_request(&self.key, pubkey, encrypted_data)?
            .ok_or(HandleTransactError::NotForUs)?;

        let mut parsed_transact = parse_transact_calldata(
            req.params.data.as_ref(),
            &self.key,
            self.master_public_key,
            req.params.txid_version.as_deref(),
        )
        .inspect_err(|error| {
            warn!(?error, "failed to parse decoded transact request");
        })
        .map_err(HandleTransactError::Parse)?;

        info!(
            fee_token = ?parsed_transact.fee_token,
            fee_amount = ?parsed_transact.fee_amount,
            railgun_txid = ?parsed_transact.railgun_txid,
            utxo_tree_in = parsed_transact.utxo_tree_in,
            "parsed transact calldata"
        );

        if let Some(poi) = self.poi.as_ref() {
            poi.validate_all(&parsed_transact, &req.params).await?;
            parsed_transact
                .attach_fee_note_assurance_context(&req.params, &self.required_poi_list)
                .map_err(HandleTransactError::Parse)?;
        }

        self.tx.send((req, parsed_transact)).await?;
        Ok(())
    }

    pub async fn handle_trusted_signer_fees(
        &self,
        railgun_address: String,
        fees: HashMap<Address, U256>,
    ) {
        self.fees_manager
            .handle_trusted_signer_fees(railgun_address, fees)
            .await;
    }
}

fn pretty_number(num: &U256, decimals: usize) -> String {
    let div = uint!(10_U256).pow(U256::from(decimals));
    let q = num / div;
    let mut r = num % div;

    let mut frac = Vec::with_capacity(decimals);
    for _ in 0..decimals {
        let digit = (r * uint!(10_U256)) / div;
        r = (r * uint!(10_U256)) % div;
        frac.push((digit.to::<u8>() + b'0') as char);
    }

    while frac.len() > 2 && frac.last() == Some(&'0') {
        frac.pop();
    }

    format!("{q}.{}", frac.iter().collect::<String>())
}
