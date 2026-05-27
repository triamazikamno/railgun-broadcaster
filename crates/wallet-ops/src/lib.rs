use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant, SystemTime};

use alloy::eips::BlockNumberOrTag;
use alloy::eips::Encodable2718;
use alloy::hex;
use alloy::network::{
    EthereumWallet, NetworkTransactionBuilder, TransactionBuilder as _, TransactionResponse,
};
use alloy::primitives::{Address, Bytes, FixedBytes, U256, address, keccak256};
use alloy::providers::Provider;
use alloy::rpc::types::{FeeHistory, TransactionReceipt, TransactionRequest};
use alloy::signers::k256::ecdsa::SigningKey;
use alloy::signers::local::PrivateKeySigner;
use alloy::uint;
use broadcaster_core::contracts::shield::derive_shield_private_key;
use broadcaster_core::crypto::railgun::{Address as RailgunAddress, AddressData};
use broadcaster_core::query_rpc_pool::{ProviderHandle, QueryRpcPool};
use broadcaster_core::transact::{
    BroadcasterRawParamsTransact, DEFAULT_TXID_VERSION, EncryptedTransactRequest,
    railgun_txid_leaf_hash,
};
use broadcaster_core::transact_response::DecryptedTransactResponse;
use broadcaster_monitor::FeeRow;
use eyre::{Report, Result, WrapErr, eyre};
use local_db::{DbConfig, DbStore, PendingOutputPoiContextRecord, PendingOutputPoiRole};
use merkletree::tree::MerkleForest;
use poi::poi::{DEFAULT_WALLET_POI_RPC_URL, PoiRpcClient, default_active_poi_list_keys};
use railgun_wallet::artifacts::ArtifactSource;
use railgun_wallet::prover::build_prover_cache_with_progress;
pub use railgun_wallet::prover::{
    ProverCacheBuildProgress, ProverCacheBuildReport, ProverCacheBuildStage,
};
use railgun_wallet::tx::{
    BroadcasterFeeOutput, BuildError, PoiMerkleProofSource, PreTransactionPoiGenerationRequest,
    PreTransactionPoiMap, SendPlan, SendRequest as RailgunSendRequest, TransactionPlanChunk,
    UnshieldMode, UnshieldPlan, UnshieldRequest as RailgunUnshieldRequest,
    generate_pre_transaction_pois, max_broadcaster_fee_token_spendable, max_send_spendable,
    max_unshield_spendable, send_selection_info, send_selection_info_with_broadcaster_fee_token,
    send_selection_info_with_separate_broadcaster_fee_seed, unshield_selection_info,
    unshield_selection_info_with_broadcaster_fee_token,
    unshield_selection_info_with_separate_broadcaster_fee_seed,
};
use railgun_wallet::{
    Note, PoiStatus, ProverService, TransactionBuilder, Utxo, UtxoCommitmentKind, UtxoPoiMetadata,
    UtxoSource, WalletUtxo,
};
use rand::seq::IndexedRandom;
use reqwest::Url;
use serde::Serialize;
use sync_service::{
    ChainConfig, ChainConfigDefaults, ChainKey, LocalPoiMerkleProofSource, SyncManager,
    SyncProgressSender, WalletConfig, WalletHandle, WalletLocalPoiCaches, WalletPendingOverlay,
    WalletPendingSpent,
};
pub use sync_service::{
    PoiArtifactManifestSource, PoiArtifactSourceConfig, PoiCacheService, PoiReadSource,
    SyncProgressStage, SyncProgressUpdate,
};
use tokio::sync::{RwLock, mpsc, oneshot, watch};
use tokio::task::JoinSet;
use waku_relay::client::Client as WakuClient;
use waku_relay::msg::ContentTopic;
use zeroize::{Zeroize, Zeroizing};

pub use local_db::DbStore as WalletDbStore;
pub use waku_relay::client::Client as PublicBroadcasterWakuClient;

static ACTIVE_PROVER_CACHE_BUILDS: LazyLock<
    Mutex<HashMap<PathBuf, watch::Sender<Option<ProverCacheBuildProgress>>>>,
> = LazyLock::new(|| Mutex::new(HashMap::new()));

mod amounts;
mod anchors;
mod desktop;
mod http;
mod poi_contexts;
mod public_wallet;
mod signer;
mod utxos;

pub mod settings;
pub mod vault;

pub use amounts::{
    is_wrapped_native_token, parse_railgun_recipient, parse_send_amount, parse_unshield_amount,
};
pub use anchors::{
    BroadcasterFeePolicy, BroadcasterFeePolicyStatus, TokenAnchorRateCache,
    TokenAnchorRefreshHandle, average_non_outlier_anchor_rates, fixed_token_anchor_rate,
    known_token_anchor_sources, oracle_answer_to_anchor_rate, refresh_token_anchor_rates,
    spawn_token_anchor_refresh_worker,
};
pub use desktop::*;
pub use http::{
    HttpContext, WalletNetworkConfig, WalletNetworkHealth, WalletNetworkHealthState,
    WalletNetworkMode, WalletNetworkProgress, WalletNetworkProgressStage, WalletTorClient,
    WalletTorClientProvider, build_http_client, build_wallet_network_context,
    build_wallet_network_context_with_progress, request_tor_state_reset,
    resolve_wallet_network_mode,
};
use public_wallet::vaulted_public_signer;
pub use public_wallet::{
    PublicAccountBalance, PublicActionAttemptInfo, PublicActionCommand, PublicActionCommandKind,
    PublicActionCommandReceiver, PublicActionCommandSender, PublicActionGasFeeQuote,
    PublicActionGasFeeSelection, PublicActionProgressStatus, PublicActionProgressStep,
    PublicActionProgressUpdate, PublicActionSessionEvent, PublicActionSessionEventSender,
    PublicAssetId, PublicBalanceAmount, PublicBalanceAsset, PublicBalanceEntry,
    PublicBalanceRefreshCoordinator, PublicBalanceSnapshot, PublicSendRequest, PublicSendResult,
    PublicShieldRequest, estimate_public_native_action_gas_reserve,
    public_action_replacement_bumped_fee, public_balance_assets_for_chain,
    public_balance_refresh_interval_secs, public_native_action_gas_reserve,
    public_native_action_gas_units, quote_public_action_gas_fee, refresh_public_balances,
    submit_public_send, submit_public_send_with_progress, submit_public_shield,
    submit_public_shield_with_progress,
};
use signer::EvmTransactionSigner;
use utxos::apply_pending_overlay_to_outputs;
pub use utxos::{
    ActivityUtxoClassification, BlockedShieldRescueInfo, ListUtxosOutput, TokenTotal, UtxoOutput,
    max_broadcaster_fee_token_amount_from_outputs, max_send_amount_from_outputs,
    max_unshield_amount_from_outputs,
};

#[cfg(test)]
mod tests;
