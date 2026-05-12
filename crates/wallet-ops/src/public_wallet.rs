use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;

use alloy::network::{EthereumWallet, TransactionBuilder as _};
use alloy::primitives::{Address, U256};
use alloy::providers::{CallItem, Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::sol;
use alloy::sol_types::SolCall;
use eyre::{Result, WrapErr, eyre};
use railgun_ui::{chain_name, known_tokens_for_chain};
use sync_service::ChainConfigDefaults;
use zeroize::Zeroizing;

use crate::amounts::wrapped_native_token_for_chain;
use crate::signer::{EvmMessageSigner, EvmTransactionSigner, SoftwareEvmSigner};
use crate::vault::{DesktopVaultStore, DesktopViewSession, PublicAccountMetadata};
use crate::{
    GAS_LIMIT_BUFFER, HttpContext, ShieldSendOutput, TxReceiptOutput, WETH_DEPOSIT_SELECTOR,
    buffered_gas_price, chain_defaults_for_chain, sign_send_wait_with_sent,
};

sol! {
    interface PublicErc20 {
        function balanceOf(address account) external view returns (uint256);
        function transfer(address recipient, uint256 amount) external returns (bool);
    }

    interface Multicall3Balance {
        function getEthBalance(address addr) external view returns (uint256);
    }
}

const PUBLIC_BALANCE_REFRESH_INTERVAL_SECS: u64 = 60;
const PUBLIC_NATIVE_SEND_GAS_UNITS: u64 = 21_000;
const PUBLIC_NATIVE_WRAP_GAS_UNITS: u64 = 50_000;
const PUBLIC_NATIVE_APPROVE_GAS_UNITS: u64 = 65_000;
const PUBLIC_NATIVE_SHIELD_GAS_UNITS: u64 = 650_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PublicAssetId {
    Native,
    Erc20(Address),
}

impl PublicAssetId {
    #[must_use]
    pub const fn token_address(self) -> Option<Address> {
        match self {
            Self::Native => None,
            Self::Erc20(token) => Some(token),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicBalanceAsset {
    pub id: PublicAssetId,
    pub symbol: &'static str,
    pub decimals: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicBalanceAmount {
    Available(U256),
    Unavailable,
}

impl PublicBalanceAmount {
    #[must_use]
    pub const fn amount(&self) -> Option<U256> {
        match self {
            Self::Available(amount) => Some(*amount),
            Self::Unavailable => None,
        }
    }

    #[must_use]
    pub fn is_zero(&self) -> bool {
        matches!(self, Self::Available(amount) if amount.is_zero())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicBalanceEntry {
    pub asset: PublicBalanceAsset,
    pub amount: PublicBalanceAmount,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicAccountBalance {
    pub account: PublicAccountMetadata,
    pub balances: Vec<PublicBalanceEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicBalanceSnapshot {
    pub chain_id: u64,
    pub refreshed_at: SystemTime,
    pub accounts: Vec<PublicAccountBalance>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlannedPublicBalanceCall {
    pub(crate) public_account_uuid: String,
    pub(crate) account: Address,
    pub(crate) asset: PublicBalanceAsset,
    pub(crate) target: Address,
    pub(crate) data: Vec<u8>,
}

#[derive(Default)]
pub struct PublicBalanceRefreshCoordinator {
    refreshing: Arc<AtomicBool>,
}

pub struct PublicBalanceRefreshGuard {
    refreshing: Arc<AtomicBool>,
}

impl PublicBalanceRefreshCoordinator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn try_begin(&self) -> Option<PublicBalanceRefreshGuard> {
        self.refreshing
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| PublicBalanceRefreshGuard {
                refreshing: Arc::clone(&self.refreshing),
            })
    }

    #[must_use]
    pub fn is_refreshing(&self) -> bool {
        self.refreshing.load(Ordering::Acquire)
    }
}

impl Drop for PublicBalanceRefreshGuard {
    fn drop(&mut self) {
        self.refreshing.store(false, Ordering::Release);
    }
}

pub struct PublicSendRequest {
    pub chain_id: u64,
    pub view_session: Arc<DesktopViewSession>,
    pub vault_store: Arc<DesktopVaultStore>,
    pub vault_password: Zeroizing<String>,
    pub public_account_uuid: String,
    pub asset: PublicAssetId,
    pub amount: U256,
    pub recipient: Address,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicSendResult {
    pub tx: TxReceiptOutput,
}

pub struct PublicShieldRequest {
    pub chain_id: u64,
    pub view_session: Arc<DesktopViewSession>,
    pub vault_store: Arc<DesktopVaultStore>,
    pub vault_password: Zeroizing<String>,
    pub public_account_uuid: String,
    pub asset: PublicAssetId,
    pub amount: U256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PublicActionProgressStep {
    Send,
    Wrap,
    Approve,
    Shield,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicActionProgressStatus {
    Pending,
    Done,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicActionProgressUpdate {
    pub step: PublicActionProgressStep,
    pub status: PublicActionProgressStatus,
    pub tx_hash: Option<String>,
    pub message: Option<String>,
}

#[must_use]
pub const fn public_balance_refresh_interval_secs() -> u64 {
    PUBLIC_BALANCE_REFRESH_INTERVAL_SECS
}

#[must_use]
pub fn public_balance_assets_for_chain(chain_id: u64) -> Vec<PublicBalanceAsset> {
    let mut assets = Vec::new();
    if let Some(native) = native_asset_for_chain(chain_id) {
        assets.push(native);
    }
    assets.extend(
        known_tokens_for_chain(chain_id).map(|token| PublicBalanceAsset {
            id: PublicAssetId::Erc20(token.token),
            symbol: token.symbol,
            decimals: token.decimals,
        }),
    );
    assets
}

#[must_use]
pub fn public_native_action_gas_units(steps: &[PublicActionProgressStep]) -> u64 {
    steps.iter().fold(0_u64, |total, step| {
        total.saturating_add(public_native_step_gas_units(*step) + GAS_LIMIT_BUFFER)
    })
}

#[must_use]
pub fn public_native_action_gas_reserve(
    gas_price: u128,
    steps: &[PublicActionProgressStep],
) -> U256 {
    U256::from(public_native_action_gas_units(steps)) * U256::from(gas_price)
}

pub async fn estimate_public_native_action_gas_reserve(
    chain_id: u64,
    steps: &[PublicActionProgressStep],
    http: &HttpContext,
) -> Result<U256> {
    let defaults = chain_defaults_for_public_chain(chain_id)?;
    let provider = ProviderBuilder::new()
        .connect_reqwest(http.client.clone(), defaults.rpc_url)
        .erased();
    let gas_price = buffered_gas_price(&provider).await?;
    Ok(public_native_action_gas_reserve(gas_price, steps))
}

const fn public_native_step_gas_units(step: PublicActionProgressStep) -> u64 {
    match step {
        PublicActionProgressStep::Send => PUBLIC_NATIVE_SEND_GAS_UNITS,
        PublicActionProgressStep::Wrap => PUBLIC_NATIVE_WRAP_GAS_UNITS,
        PublicActionProgressStep::Approve => PUBLIC_NATIVE_APPROVE_GAS_UNITS,
        PublicActionProgressStep::Shield => PUBLIC_NATIVE_SHIELD_GAS_UNITS,
    }
}

pub(crate) fn plan_public_balance_calls(
    chain_id: u64,
    multicall_addr: Address,
    accounts: &[PublicAccountMetadata],
) -> Vec<PlannedPublicBalanceCall> {
    let assets = public_balance_assets_for_chain(chain_id);
    let mut calls = Vec::with_capacity(accounts.len().saturating_mul(assets.len()));
    for account in accounts {
        for asset in &assets {
            let (target, data) = match asset.id {
                PublicAssetId::Native => (
                    multicall_addr,
                    Multicall3Balance::getEthBalanceCall {
                        addr: account.address,
                    }
                    .abi_encode(),
                ),
                PublicAssetId::Erc20(token) => (
                    token,
                    PublicErc20::balanceOfCall {
                        account: account.address,
                    }
                    .abi_encode(),
                ),
            };
            calls.push(PlannedPublicBalanceCall {
                public_account_uuid: account.public_account_uuid.clone(),
                account: account.address,
                asset: asset.clone(),
                target,
                data,
            });
        }
    }
    calls
}

pub async fn refresh_public_balances(
    chain_id: u64,
    accounts: &[PublicAccountMetadata],
    http: &HttpContext,
) -> Result<PublicBalanceSnapshot> {
    let defaults = chain_defaults_for_public_chain(chain_id)?;
    let chain_label =
        chain_name(chain_id).map_or_else(|| format!("chain {chain_id}"), str::to_string);
    let multicall_contract = defaults.multicall_contract;
    let rpc_url = defaults.rpc_url.clone();
    let rpc_host = rpc_url
        .host_str()
        .map_or_else(|| "configured RPC".to_string(), str::to_string);
    let planned_calls = plan_public_balance_calls(chain_id, multicall_contract, accounts);
    if planned_calls.is_empty() {
        return Ok(empty_public_balance_snapshot(chain_id, accounts));
    }

    let provider = ProviderBuilder::new()
        .connect_reqwest(http.client.clone(), rpc_url)
        .erased();
    let mut multicall = provider
        .multicall()
        .dynamic::<PublicErc20::balanceOfCall>()
        .address(multicall_contract);
    for call in &planned_calls {
        multicall =
            multicall.add_call_dynamic(CallItem::new(call.target, call.data.clone().into()));
    }

    let results = multicall
        .try_aggregate(false)
        .await
        .wrap_err_with(|| {
            let account_suffix = if accounts.len() == 1 { "" } else { "s" };
            let call_suffix = if planned_calls.len() == 1 { "" } else { "s" };
            format!(
                "could not refresh public balances on {chain_label}: Multicall3 request to {rpc_host} ({multicall_contract:#x}) failed for {} account{account_suffix} and {} balance call{call_suffix}",
                accounts.len(),
                planned_calls.len(),
            )
        })?;
    Ok(public_balance_snapshot_from_results(
        chain_id,
        accounts,
        &planned_calls,
        results.into_iter().map(std::result::Result::ok).collect(),
    ))
}

pub async fn submit_public_send(
    request: PublicSendRequest,
    http: &HttpContext,
) -> Result<PublicSendResult> {
    submit_public_send_with_progress(request, http, |_| {}).await
}

pub async fn submit_public_send_with_progress(
    request: PublicSendRequest,
    http: &HttpContext,
    mut progress: impl FnMut(PublicActionProgressUpdate) + Send,
) -> Result<PublicSendResult> {
    if request.amount.is_zero() {
        return Err(eyre!("amount is required"));
    }
    let defaults = chain_defaults_for_public_chain(request.chain_id)?;
    let signer = vaulted_public_signer(
        &request.vault_store,
        &request.view_session,
        &request.vault_password,
        &request.public_account_uuid,
    )?;
    let from_address = signer.address();
    let wallet = signer.ethereum_wallet();
    let provider = ProviderBuilder::new()
        .connect_reqwest(http.client.clone(), defaults.rpc_url)
        .erased();
    let gas_price = buffered_gas_price(&provider).await?;
    let nonce = provider
        .get_transaction_count(from_address)
        .await
        .wrap_err("fetch public send nonce")?;
    let tx_req = public_send_transaction_request(
        request.chain_id,
        from_address,
        request.asset,
        request.amount,
        request.recipient,
        gas_price,
        nonce,
    );
    let tx = sign_public_action_step(
        PublicActionProgressStep::Send,
        &provider,
        &wallet,
        tx_req,
        "public-send",
        &mut progress,
    )
    .await?;
    if !tx.status {
        return Err(eyre!("public send transaction reverted ({})", tx.tx_hash));
    }
    Ok(PublicSendResult { tx })
}

pub async fn submit_public_shield(
    request: PublicShieldRequest,
    http: &HttpContext,
) -> Result<ShieldSendOutput> {
    submit_public_shield_with_progress(request, http, |_| {}).await
}

pub async fn submit_public_shield_with_progress(
    request: PublicShieldRequest,
    http: &HttpContext,
    mut progress: impl FnMut(PublicActionProgressUpdate) + Send,
) -> Result<ShieldSendOutput> {
    if request.amount.is_zero() {
        return Err(eyre!("amount is required"));
    }
    let defaults = chain_defaults_for_public_chain(request.chain_id)?;
    let token = public_shield_token(request.chain_id, request.asset)?;
    let recipient = request
        .view_session
        .receive_address()
        .wrap_err("derive selected private wallet receive address")?;
    let railgun_addr = broadcaster_core::crypto::railgun::Address::from(recipient.as_str());
    let addr_data = broadcaster_core::crypto::railgun::AddressData::try_from(&railgun_addr)
        .wrap_err("invalid selected private wallet receive address")?;
    let signer = vaulted_public_signer(
        &request.vault_store,
        &request.view_session,
        &request.vault_password,
        &request.public_account_uuid,
    )?;
    let shield_private_key = signer.derive_shield_private_key()?;
    let approve_data = broadcaster_core::contracts::shield::build_approve_calldata(
        defaults.contract,
        request.amount,
    );
    let shield_data = broadcaster_core::contracts::shield::build_shield_calldata(
        addr_data.master_public_key,
        &addr_data.viewing_public_key,
        token,
        request.amount,
        &shield_private_key,
    )
    .wrap_err("build public shield calldata")?;

    let from_address = signer.address();
    let wallet = signer.ethereum_wallet();
    let provider = ProviderBuilder::new()
        .connect_reqwest(http.client.clone(), defaults.rpc_url)
        .erased();
    let gas_price = buffered_gas_price(&provider).await?;
    let mut nonce = provider
        .get_transaction_count(from_address)
        .await
        .wrap_err("fetch public shield nonce")?;

    let wrap_receipt = if request.asset == PublicAssetId::Native {
        let tx_req = TransactionRequest::default()
            .with_chain_id(request.chain_id)
            .with_from(from_address)
            .with_to(token)
            .with_input(WETH_DEPOSIT_SELECTOR.to_vec())
            .with_value(request.amount)
            .with_gas_price(gas_price)
            .with_nonce(nonce);
        let receipt = sign_public_action_step(
            PublicActionProgressStep::Wrap,
            &provider,
            &wallet,
            tx_req,
            "public-shield-wrap",
            &mut progress,
        )
        .await?;
        if !receipt.status {
            return Err(eyre!(
                "public shield wrap transaction reverted ({})",
                receipt.tx_hash
            ));
        }
        nonce += 1;
        Some(receipt)
    } else {
        None
    };

    let approve_tx = TransactionRequest::default()
        .with_chain_id(request.chain_id)
        .with_from(from_address)
        .with_to(token)
        .with_input(approve_data)
        .with_gas_price(gas_price)
        .with_nonce(nonce);
    let approve_receipt = sign_public_action_step(
        PublicActionProgressStep::Approve,
        &provider,
        &wallet,
        approve_tx,
        "public-shield-approve",
        &mut progress,
    )
    .await?;
    if !approve_receipt.status {
        return Err(eyre!(
            "public shield approve transaction reverted ({})",
            approve_receipt.tx_hash
        ));
    }
    nonce += 1;

    let shield_tx = TransactionRequest::default()
        .with_chain_id(request.chain_id)
        .with_from(from_address)
        .with_to(defaults.contract)
        .with_input(shield_data)
        .with_gas_price(gas_price)
        .with_nonce(nonce);
    let shield_receipt = sign_public_action_step(
        PublicActionProgressStep::Shield,
        &provider,
        &wallet,
        shield_tx,
        "public-shield",
        &mut progress,
    )
    .await?;
    if !shield_receipt.status {
        return Err(eyre!(
            "public shield transaction reverted ({})",
            shield_receipt.tx_hash
        ));
    }

    Ok(ShieldSendOutput {
        wrap: wrap_receipt,
        approve: approve_receipt,
        shield: shield_receipt,
    })
}

async fn sign_public_action_step(
    step: PublicActionProgressStep,
    provider: &(impl Provider + Clone),
    wallet: &EthereumWallet,
    tx_req: TransactionRequest,
    label: &str,
    progress: &mut (impl FnMut(PublicActionProgressUpdate) + Send),
) -> Result<TxReceiptOutput> {
    progress(public_action_progress_update(
        step,
        PublicActionProgressStatus::Pending,
        None,
        None,
    ));
    let mut sent_hash = None;
    let receipt = match sign_send_wait_with_sent(provider, wallet, tx_req, label, |tx_hash| {
        sent_hash = Some(tx_hash.clone());
        progress(public_action_progress_update(
            step,
            PublicActionProgressStatus::Pending,
            Some(tx_hash),
            None,
        ));
    })
    .await
    {
        Ok(receipt) => receipt,
        Err(error) => {
            let message = format_report_chain(&error);
            progress(public_action_progress_update(
                step,
                PublicActionProgressStatus::Error,
                sent_hash,
                Some(message),
            ));
            return Err(error);
        }
    };
    if receipt.status {
        progress(public_action_progress_update(
            step,
            PublicActionProgressStatus::Done,
            Some(receipt.tx_hash.clone()),
            None,
        ));
    } else {
        progress(public_action_progress_update(
            step,
            PublicActionProgressStatus::Error,
            Some(receipt.tx_hash.clone()),
            Some("Transaction reverted".to_string()),
        ));
    }
    Ok(receipt)
}

const fn public_action_progress_update(
    step: PublicActionProgressStep,
    status: PublicActionProgressStatus,
    tx_hash: Option<String>,
    message: Option<String>,
) -> PublicActionProgressUpdate {
    PublicActionProgressUpdate {
        step,
        status,
        tx_hash,
        message,
    }
}

fn format_report_chain(error: &eyre::Report) -> String {
    let mut parts = error.chain().map(ToString::to_string);
    let Some(mut message) = parts.next() else {
        return error.to_string();
    };
    for part in parts {
        if message.ends_with(&part) {
            continue;
        }
        message.push_str(": ");
        message.push_str(&part);
    }
    message
}

fn public_balance_snapshot_from_results(
    chain_id: u64,
    accounts: &[PublicAccountMetadata],
    planned_calls: &[PlannedPublicBalanceCall],
    results: Vec<Option<U256>>,
) -> PublicBalanceSnapshot {
    let mut by_account: BTreeMap<String, Vec<PublicBalanceEntry>> = BTreeMap::new();
    for (call, result) in planned_calls.iter().zip(results) {
        by_account
            .entry(call.public_account_uuid.clone())
            .or_default()
            .push(PublicBalanceEntry {
                asset: call.asset.clone(),
                amount: result.map_or(
                    PublicBalanceAmount::Unavailable,
                    PublicBalanceAmount::Available,
                ),
            });
    }

    PublicBalanceSnapshot {
        chain_id,
        refreshed_at: SystemTime::now(),
        accounts: accounts
            .iter()
            .cloned()
            .map(|account| PublicAccountBalance {
                balances: by_account
                    .remove(&account.public_account_uuid)
                    .unwrap_or_default(),
                account,
            })
            .collect(),
    }
}

fn empty_public_balance_snapshot(
    chain_id: u64,
    accounts: &[PublicAccountMetadata],
) -> PublicBalanceSnapshot {
    PublicBalanceSnapshot {
        chain_id,
        refreshed_at: SystemTime::now(),
        accounts: accounts
            .iter()
            .cloned()
            .map(|account| PublicAccountBalance {
                account,
                balances: Vec::new(),
            })
            .collect(),
    }
}

const fn native_asset_for_chain(chain_id: u64) -> Option<PublicBalanceAsset> {
    let symbol = match chain_id {
        1 | 42161 => "ETH",
        56 => "BNB",
        137 => "MATIC",
        _ => return None,
    };
    Some(PublicBalanceAsset {
        id: PublicAssetId::Native,
        symbol,
        decimals: 18,
    })
}

fn public_shield_token(chain_id: u64, asset: PublicAssetId) -> Result<Address> {
    match asset {
        PublicAssetId::Native => wrapped_native_token_for_chain(chain_id)
            .ok_or_else(|| eyre!("selected chain does not support native shielding")),
        PublicAssetId::Erc20(token) => Ok(token),
    }
}

fn vaulted_public_signer(
    vault_store: &DesktopVaultStore,
    view_session: &DesktopViewSession,
    vault_password: &str,
    public_account_uuid: &str,
) -> Result<SoftwareEvmSigner> {
    let mut grant = vault_store
        .create_spend_grant(vault_password)
        .wrap_err("authorize public account spend")?;
    let private_key = vault_store
        .public_account_signing_key(&mut grant, view_session, public_account_uuid)
        .wrap_err("load public account signing key")?;
    SoftwareEvmSigner::from_private_key(*private_key).wrap_err("create public account signer")
}

fn public_send_transaction_request(
    chain_id: u64,
    from: Address,
    asset: PublicAssetId,
    amount: U256,
    recipient: Address,
    gas_price: u128,
    nonce: u64,
) -> TransactionRequest {
    let mut tx_req = TransactionRequest::default()
        .with_chain_id(chain_id)
        .with_from(from)
        .with_gas_price(gas_price)
        .with_nonce(nonce);
    match asset {
        PublicAssetId::Native => {
            tx_req = tx_req.with_to(recipient).with_value(amount);
        }
        PublicAssetId::Erc20(token) => {
            tx_req = tx_req
                .with_to(token)
                .with_input(PublicErc20::transferCall { recipient, amount }.abi_encode());
        }
    }
    tx_req
}

fn chain_defaults_for_public_chain(chain_id: u64) -> Result<ChainConfigDefaults> {
    chain_defaults_for_chain(chain_id, crate::UnsupportedChainMessage::Generic)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use alloy::primitives::address;
    use alloy::sol_types::SolCall;
    use local_db::{DbConfig, DbStore};

    use super::*;
    use crate::vault::{
        KdfParams, PublicAccountScope, PublicAccountSource, PublicAccountStatus, WalletSource,
    };

    const TEST_PASSWORD: &str = "correct horse battery staple";
    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    static TEMP_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_kdf() -> KdfParams {
        KdfParams::new(1024, 1, 1)
    }

    fn temp_db_root() -> PathBuf {
        let dir = std::env::temp_dir().join("railgun-broadcaster-public-wallet-tests");
        fs::create_dir_all(&dir).expect("create temp db dir");
        let pid = std::process::id();
        let nanos = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let counter = TEMP_DB_COUNTER.fetch_add(1, Ordering::Relaxed);
        dir.join(format!("db-{pid}-{nanos}-{counter}"))
    }

    fn public_action_request_parts() -> (
        PathBuf,
        Arc<DbStore>,
        Arc<DesktopVaultStore>,
        Arc<DesktopViewSession>,
    ) {
        let root_dir = temp_db_root();
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let store = Arc::new(DesktopVaultStore::from_db(Arc::clone(&db)));
        let _created = store
            .create_vault_with_params(TEST_PASSWORD, test_kdf())
            .expect("create vault");
        let wallet_id = "public-action-wallet";
        let metadata = store
            .new_wallet_metadata(
                TEST_PASSWORD,
                wallet_id,
                0,
                WalletSource::Imported,
                "Public action",
            )
            .expect("wallet metadata");
        store
            .import_wallet_mnemonic_with_metadata(
                TEST_PASSWORD,
                wallet_id,
                0,
                "english",
                TEST_MNEMONIC,
                &metadata,
            )
            .expect("import wallet");
        let view_session = Arc::new(
            store
                .load_view_session(TEST_PASSWORD, wallet_id)
                .expect("view session"),
        );
        (root_dir, db, store, view_session)
    }

    #[test]
    fn balance_plan_batches_native_and_known_tokens_per_account() {
        let account = PublicAccountMetadata {
            public_account_uuid: "public-1".to_string(),
            address: address!("0x1111111111111111111111111111111111111111"),
            label: None,
            source: PublicAccountSource::Derived,
            scope: PublicAccountScope::PrivateWallet {
                wallet_uuid: "wallet-1".to_string(),
            },
            derivation_index: Some(0),
            status: PublicAccountStatus::Active,
            display_order: 0,
        };
        let multicall = address!("0xcA11bde05977b3631167028862bE2a173976CA11");
        let calls = plan_public_balance_calls(1, multicall, &[account]);

        assert_eq!(calls.first().expect("native call").target, multicall);
        assert_eq!(
            calls.first().expect("native call").asset.id,
            PublicAssetId::Native
        );
        assert!(
            calls
                .iter()
                .any(|call| matches!(call.asset.id, PublicAssetId::Erc20(_)))
        );
    }

    #[test]
    fn balance_snapshot_preserves_partial_success() {
        let account = PublicAccountMetadata {
            public_account_uuid: "public-1".to_string(),
            address: address!("0x1111111111111111111111111111111111111111"),
            label: None,
            source: PublicAccountSource::Derived,
            scope: PublicAccountScope::PrivateWallet {
                wallet_uuid: "wallet-1".to_string(),
            },
            derivation_index: Some(0),
            status: PublicAccountStatus::Active,
            display_order: 0,
        };
        let planned = vec![
            PlannedPublicBalanceCall {
                public_account_uuid: account.public_account_uuid.clone(),
                account: account.address,
                asset: PublicBalanceAsset {
                    id: PublicAssetId::Native,
                    symbol: "ETH",
                    decimals: 18,
                },
                target: address!("0xcA11bde05977b3631167028862bE2a173976CA11"),
                data: Vec::new(),
            },
            PlannedPublicBalanceCall {
                public_account_uuid: account.public_account_uuid.clone(),
                account: account.address,
                asset: PublicBalanceAsset {
                    id: PublicAssetId::Erc20(address!(
                        "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
                    )),
                    symbol: "WETH",
                    decimals: 18,
                },
                target: address!("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"),
                data: Vec::new(),
            },
        ];

        let snapshot = public_balance_snapshot_from_results(
            1,
            &[account],
            &planned,
            vec![Some(U256::from(7_u64)), None],
        );

        let balances = &snapshot.accounts[0].balances;
        assert_eq!(balances[0].amount.amount(), Some(U256::from(7_u64)));
        assert!(matches!(
            balances[1].amount,
            PublicBalanceAmount::Unavailable
        ));
    }

    #[test]
    fn refresh_coordinator_prevents_overlap_and_releases() {
        let coordinator = PublicBalanceRefreshCoordinator::new();
        let guard = coordinator.try_begin().expect("first refresh guard");

        assert!(coordinator.is_refreshing());
        assert!(coordinator.try_begin().is_none());
        drop(guard);
        assert!(!coordinator.is_refreshing());
        assert!(coordinator.try_begin().is_some());
    }

    #[test]
    fn public_native_action_gas_reserve_uses_buffered_units() {
        let send_steps = [PublicActionProgressStep::Send];
        assert_eq!(
            public_native_action_gas_units(&send_steps),
            PUBLIC_NATIVE_SEND_GAS_UNITS + GAS_LIMIT_BUFFER,
        );
        assert_eq!(
            public_native_action_gas_reserve(2, &send_steps),
            U256::from((PUBLIC_NATIVE_SEND_GAS_UNITS + GAS_LIMIT_BUFFER) * 2),
        );

        let shield_steps = [
            PublicActionProgressStep::Wrap,
            PublicActionProgressStep::Approve,
            PublicActionProgressStep::Shield,
        ];
        assert_eq!(
            public_native_action_gas_units(&shield_steps),
            PUBLIC_NATIVE_WRAP_GAS_UNITS
                + PUBLIC_NATIVE_APPROVE_GAS_UNITS
                + PUBLIC_NATIVE_SHIELD_GAS_UNITS
                + (3 * GAS_LIMIT_BUFFER),
        );
    }

    #[test]
    fn public_send_request_uses_native_value_or_erc20_transfer() {
        let from = address!("0x1111111111111111111111111111111111111111");
        let recipient = address!("0x2222222222222222222222222222222222222222");
        let token = address!("0x3333333333333333333333333333333333333333");
        let amount = U256::from(5_u64);

        let native = public_send_transaction_request(
            1,
            from,
            PublicAssetId::Native,
            amount,
            recipient,
            10,
            3,
        );
        assert_eq!(native.to, Some(recipient.into()));
        assert_eq!(native.value, Some(amount));

        let erc20 = public_send_transaction_request(
            1,
            from,
            PublicAssetId::Erc20(token),
            amount,
            recipient,
            10,
            3,
        );
        assert_eq!(erc20.to, Some(token.into()));
        let expected_transfer = PublicErc20::transferCall { recipient, amount }.abi_encode();
        assert_eq!(
            erc20.input.input().expect("transfer input").as_ref(),
            expected_transfer.as_slice()
        );
    }

    #[test]
    fn public_actions_reject_zero_amount_before_signing() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build runtime");
        let (root_dir, db, store, view_session) = public_action_request_parts();
        let http = HttpContext {
            client: reqwest::Client::new(),
            proxy_url: None,
        };
        let recipient = address!("0x2222222222222222222222222222222222222222");

        let send_result = runtime.block_on(submit_public_send(
            PublicSendRequest {
                chain_id: 1,
                view_session: Arc::clone(&view_session),
                vault_store: Arc::clone(&store),
                vault_password: Zeroizing::new(TEST_PASSWORD.to_string()),
                public_account_uuid: "unused".to_string(),
                asset: PublicAssetId::Native,
                amount: U256::ZERO,
                recipient,
            },
            &http,
        ));
        match send_result {
            Ok(_) => panic!("zero-value public send unexpectedly succeeded"),
            Err(error) => assert!(error.to_string().contains("amount is required")),
        }

        let shield_result = runtime.block_on(submit_public_shield(
            PublicShieldRequest {
                chain_id: 1,
                view_session,
                vault_store: store,
                vault_password: Zeroizing::new(TEST_PASSWORD.to_string()),
                public_account_uuid: "unused".to_string(),
                asset: PublicAssetId::Native,
                amount: U256::ZERO,
            },
            &http,
        ));
        match shield_result {
            Ok(_) => panic!("zero-value public shield unexpectedly succeeded"),
            Err(error) => assert!(error.to_string().contains("amount is required")),
        }

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }
}
