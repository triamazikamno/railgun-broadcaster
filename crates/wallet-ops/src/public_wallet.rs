use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use alloy::consensus::SignableTransaction;
use alloy::eips::Encodable2718;
use alloy::network::{NetworkTransactionBuilder, TransactionBuilder as _};
use alloy::primitives::{Address, FixedBytes, Signature, U256, keccak256};
use alloy::providers::{CallItem, Provider};
use alloy::rpc::types::TransactionRequest;
use alloy::sol;
use alloy::sol_types::SolCall;
use broadcaster_core::query_rpc_pool::{ProviderHandle, QueryRpcPool};
use eyre::{Result, WrapErr, eyre};
use railgun_ui::{chain_name, known_tokens_for_chain};
use reqwest::Url;
use sync_service::ChainConfigDefaults;
use zeroize::Zeroizing;

use crate::amounts::wrapped_native_token_for_chain;
use crate::hardware::HardwarePublicAccountDescriptor;
#[cfg(feature = "hardware")]
use crate::hardware::{DEFAULT_HARDWARE_DERIVATION_PATH, parse_bip32_path};
use crate::settings::{EffectiveChainConfig, EffectiveChainGasSettings, EffectiveTokenRegistry};
use crate::signer::{EvmMessageSigner, EvmTransactionSigner, SoftwareEvmSigner};
use crate::vault::{
    DesktopVaultStore, DesktopViewSession, HardwareProfileSession, PublicAccountMetadata,
};
use crate::{
    GAS_LIMIT_BUFFER, HttpContext, SelfBroadcastTipFallback, ShieldSendOutput, TxReceiptOutput,
    WETH_DEPOSIT_SELECTOR, chain_defaults_for_chain, effective_rpc_urls_for_chain,
    query_rpc_pool_with_http_client, report_chain_string, resolve_self_broadcast_gas_fee,
    self_broadcast_gas_fee_quote_from_rpc_pool_with_tip_fallback,
    self_broadcast_replacement_bumped_fee, self_broadcast_send_raw_transaction_to_rpc_pool,
    tx_receipt_output,
};

pub type PublicActionGasFeeQuote = crate::SelfBroadcastGasFeeQuote;
pub type PublicActionGasFeeSelection = crate::SelfBroadcastGasFeeSelection;
pub type PublicActionCommandKind = crate::SelfBroadcastCommandKind;
pub type PublicActionCommand = crate::SelfBroadcastCommand;
pub type PublicActionCommandSender = tokio::sync::mpsc::UnboundedSender<PublicActionCommand>;
pub type PublicActionCommandReceiver = tokio::sync::mpsc::UnboundedReceiver<PublicActionCommand>;
pub type PublicActionAttemptInfo = crate::SelfBroadcastAttemptInfo;
pub type PublicActionSessionEventSender =
    tokio::sync::mpsc::UnboundedSender<PublicActionSessionEvent>;
#[cfg(feature = "hardware")]
pub type HardwareTrezorPinMatrixProvider = crate::hardware::trezor::TrezorPinMatrixProvider;
#[cfg(not(feature = "hardware"))]
pub type HardwareTrezorPinMatrixProvider = ();

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
const PUBLIC_ACTION_BNB_CHAIN_ID: u64 = 56;

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
    pub symbol: String,
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
    pub effective_chain: Option<EffectiveChainConfig>,
    pub view_session: Arc<DesktopViewSession>,
    pub vault_store: Arc<DesktopVaultStore>,
    pub vault_password: Zeroizing<String>,
    pub trezor_app_passphrase: Option<Zeroizing<String>>,
    pub trezor_pin_matrix_provider: Option<HardwareTrezorPinMatrixProvider>,
    pub public_account_uuid: String,
    pub asset: PublicAssetId,
    pub amount: U256,
    pub recipient: Address,
    pub gas_fee: PublicActionGasFeeSelection,
    pub command_rx: Option<PublicActionCommandReceiver>,
    pub event_tx: Option<PublicActionSessionEventSender>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicSendResult {
    pub tx: TxReceiptOutput,
}

pub struct PublicShieldRequest {
    pub chain_id: u64,
    pub effective_chain: Option<EffectiveChainConfig>,
    pub view_session: Arc<DesktopViewSession>,
    pub vault_store: Arc<DesktopVaultStore>,
    pub vault_password: Zeroizing<String>,
    pub trezor_app_passphrase: Option<Zeroizing<String>>,
    pub trezor_pin_matrix_provider: Option<HardwareTrezorPinMatrixProvider>,
    pub public_account_uuid: String,
    pub asset: PublicAssetId,
    pub amount: U256,
    pub gas_fee: PublicActionGasFeeSelection,
    pub command_rx: Option<PublicActionCommandReceiver>,
    pub event_tx: Option<PublicActionSessionEventSender>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PublicActionProgressStep {
    ShieldKey,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicActionSessionEvent {
    StepFailed {
        step: PublicActionProgressStep,
        message: String,
    },
    AttemptHandoff {
        step: PublicActionProgressStep,
    },
    AttemptSubmitted {
        step: PublicActionProgressStep,
        attempt: PublicActionAttemptInfo,
    },
    AttemptRejected {
        step: PublicActionProgressStep,
        message: String,
    },
    HardwareProfileSessionRefreshed {
        session: HardwareProfileSession,
    },
}

#[must_use]
pub const fn public_balance_refresh_interval_secs() -> u64 {
    PUBLIC_BALANCE_REFRESH_INTERVAL_SECS
}

#[must_use]
pub fn public_balance_assets_for_chain(chain_id: u64) -> Vec<PublicBalanceAsset> {
    public_balance_assets_for_chain_with_registry(chain_id, None)
}

#[must_use]
pub(crate) fn public_balance_assets_for_chain_with_registry(
    chain_id: u64,
    token_registry: Option<&EffectiveTokenRegistry>,
) -> Vec<PublicBalanceAsset> {
    let mut assets = Vec::new();
    if let Some(native) = native_asset_for_chain(chain_id) {
        assets.push(native);
    }
    if let Some(token_registry) = token_registry {
        assets.extend(
            token_registry
                .tokens
                .values()
                .filter(|token| token.chain_id == chain_id)
                .filter_map(|token| {
                    Address::from_str(&token.token_address)
                        .ok()
                        .map(|address| PublicBalanceAsset {
                            id: PublicAssetId::Erc20(address),
                            symbol: token.symbol.clone(),
                            decimals: token.decimals,
                        })
                }),
        );
    } else {
        assets.extend(
            known_tokens_for_chain(chain_id).map(|token| PublicBalanceAsset {
                id: PublicAssetId::Erc20(token.token),
                symbol: token.symbol.to_string(),
                decimals: token.decimals,
            }),
        );
    }
    assets
}

#[must_use]
pub fn public_native_action_gas_units(steps: &[PublicActionProgressStep]) -> u64 {
    public_native_action_gas_units_with_buffer(steps, GAS_LIMIT_BUFFER)
}

#[must_use]
fn public_native_action_gas_units_with_buffer(
    steps: &[PublicActionProgressStep],
    gas_limit_buffer: u64,
) -> u64 {
    steps.iter().fold(0_u64, |total, step| {
        let gas_units = public_native_step_gas_units(*step);
        if gas_units == 0 {
            total
        } else {
            total.saturating_add(gas_units + gas_limit_buffer)
        }
    })
}

#[must_use]
pub fn public_native_action_gas_reserve(
    max_fee_per_gas: u128,
    steps: &[PublicActionProgressStep],
) -> U256 {
    public_native_action_gas_reserve_with_buffer(max_fee_per_gas, steps, GAS_LIMIT_BUFFER)
}

#[must_use]
fn public_native_action_gas_reserve_with_buffer(
    max_fee_per_gas: u128,
    steps: &[PublicActionProgressStep],
    gas_limit_buffer: u64,
) -> U256 {
    U256::from(public_native_action_gas_units_with_buffer(
        steps,
        gas_limit_buffer,
    )) * U256::from(max_fee_per_gas)
}

pub async fn quote_public_action_gas_fee(
    chain_id: u64,
    effective_chain: Option<&EffectiveChainConfig>,
    http: &HttpContext,
) -> Result<PublicActionGasFeeQuote> {
    let chain = public_chain_runtime_config(chain_id, effective_chain)?;
    let query_rpc_pool = query_rpc_pool_with_http_client(chain.rpc_urls, http);
    public_action_gas_fee_quote_from_rpc_pool(&query_rpc_pool, http.network_mode(), chain_id).await
}

pub async fn estimate_public_native_action_gas_reserve(
    chain_id: u64,
    steps: &[PublicActionProgressStep],
    effective_chain: Option<&EffectiveChainConfig>,
    gas_fee: PublicActionGasFeeSelection,
    http: &HttpContext,
) -> Result<U256> {
    let chain = public_chain_runtime_config(chain_id, effective_chain)?;
    let query_rpc_pool = query_rpc_pool_with_http_client(chain.rpc_urls, http);
    let quote =
        public_action_gas_fee_quote_from_rpc_pool(&query_rpc_pool, http.network_mode(), chain_id)
            .await
            .wrap_err("fetch public action gas price")?;
    let gas = resolve_self_broadcast_gas_fee(gas_fee, quote)?;
    Ok(public_native_action_gas_reserve_with_buffer(
        gas.max_fee_per_gas,
        steps,
        chain.gas.gas_limit_buffer,
    ))
}

async fn public_action_gas_fee_quote_from_rpc_pool(
    query_rpc_pool: &QueryRpcPool,
    network_mode: crate::WalletNetworkMode,
    chain_id: u64,
) -> Result<PublicActionGasFeeQuote> {
    self_broadcast_gas_fee_quote_from_rpc_pool_with_tip_fallback(
        query_rpc_pool,
        network_mode,
        public_action_tip_fallback(chain_id),
    )
    .await
}

const fn public_action_tip_fallback(chain_id: u64) -> SelfBroadcastTipFallback {
    if chain_id == PUBLIC_ACTION_BNB_CHAIN_ID {
        SelfBroadcastTipFallback::RpcGasPrice
    } else {
        SelfBroadcastTipFallback::Minimum
    }
}

const fn public_native_step_gas_units(step: PublicActionProgressStep) -> u64 {
    match step {
        PublicActionProgressStep::ShieldKey => 0,
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
    token_registry: Option<&EffectiveTokenRegistry>,
) -> Vec<PlannedPublicBalanceCall> {
    let assets = public_balance_assets_for_chain_with_registry(chain_id, token_registry);
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
    effective_chain: Option<&EffectiveChainConfig>,
    token_registry: Option<&EffectiveTokenRegistry>,
    http: &HttpContext,
) -> Result<PublicBalanceSnapshot> {
    let chain = public_chain_runtime_config(chain_id, effective_chain)?;
    let chain_label =
        chain_name(chain_id).map_or_else(|| format!("chain {chain_id}"), str::to_string);
    let multicall_contract = chain.multicall_contract;
    let planned_calls =
        plan_public_balance_calls(chain_id, multicall_contract, accounts, token_registry);
    if planned_calls.is_empty() {
        return Ok(empty_public_balance_snapshot(chain_id, accounts));
    }

    let query_rpc_pool = query_rpc_pool_with_http_client(chain.rpc_urls, http);
    let mut last_error = None;
    let mut results = None;
    for _ in 0..query_rpc_pool.len() {
        let Some(provider_handle) = query_rpc_pool.random_provider() else {
            break;
        };
        let mut multicall = provider_handle
            .provider
            .multicall()
            .dynamic::<PublicErc20::balanceOfCall>()
            .address(multicall_contract);
        for call in &planned_calls {
            multicall =
                multicall.add_call_dynamic(CallItem::new(call.target, call.data.clone().into()));
        }

        match multicall.try_aggregate(false).await {
            Ok(values) => {
                results = Some(values);
                break;
            }
            Err(error) => {
                tracing::warn!(%error, rpc = %provider_handle.url, "refresh public balances multicall failed");
                query_rpc_pool.mark_bad_provider(&provider_handle);
                last_error = Some(eyre!("{error}"));
            }
        }
    }
    let results = results.ok_or_else(|| {
        let account_suffix = if accounts.len() == 1 { "" } else { "s" };
        let call_suffix = if planned_calls.len() == 1 { "" } else { "s" };
        let detail = last_error.map_or_else(
            || "no healthy query RPC available".to_string(),
            |error| error.to_string(),
        );
        eyre!(
            "could not refresh public balances on {chain_label}: Multicall3 request to configured RPCs ({multicall_contract:#x}) failed for {} account{account_suffix} and {} balance call{call_suffix}: {detail}",
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
    let chain = public_chain_runtime_config(request.chain_id, request.effective_chain.as_ref())?;
    let signer = vaulted_public_signer(
        &request.vault_store,
        &request.view_session,
        Some(request.vault_password.as_str()),
        &request.public_account_uuid,
        request.trezor_app_passphrase,
        request.trezor_pin_matrix_provider,
    )?;
    let from_address = signer.address();
    let query_rpc_pool = query_rpc_pool_with_http_client(chain.rpc_urls, http);
    let tx_req = public_send_transaction_request(
        request.chain_id,
        from_address,
        request.asset,
        request.amount,
        request.recipient,
    );
    let mut command_rx = request.command_rx;
    let tx = submit_public_action_step_session(
        PublicActionProgressStep::Send,
        tx_req,
        &signer,
        "public-send",
        &query_rpc_pool,
        http.network_mode(),
        request.chain_id,
        from_address,
        &chain.gas,
        None,
        request.gas_fee,
        &mut command_rx,
        request.event_tx.as_ref(),
        &mut progress,
    )
    .await?
    .receipt;
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
    let chain = public_chain_runtime_config(request.chain_id, request.effective_chain.as_ref())?;
    let token = public_shield_token(request.asset, &chain)?;
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
        Some(request.vault_password.as_str()),
        &request.public_account_uuid,
        request.trezor_app_passphrase,
        request.trezor_pin_matrix_provider,
    )?;
    let mut nonce = None;
    let mut gas_fee = request.gas_fee;
    let mut command_rx = request.command_rx;
    let event_tx = request.event_tx;
    let shield_private_key = if signer.requires_device_approval() {
        loop {
            progress(public_action_progress_update(
                PublicActionProgressStep::ShieldKey,
                PublicActionProgressStatus::Pending,
                None,
                None,
            ));
            match signer.derive_shield_private_key().await {
                Ok(shield_private_key) => {
                    progress(public_action_progress_update(
                        PublicActionProgressStep::ShieldKey,
                        PublicActionProgressStatus::Done,
                        None,
                        None,
                    ));
                    break shield_private_key;
                }
                Err(error) => {
                    let message = report_chain_string(&error);
                    progress(public_action_progress_update(
                        PublicActionProgressStep::ShieldKey,
                        PublicActionProgressStatus::Error,
                        None,
                        Some(message.clone()),
                    ));
                    emit_public_action_event(
                        event_tx.as_ref(),
                        PublicActionSessionEvent::StepFailed {
                            step: PublicActionProgressStep::ShieldKey,
                            message,
                        },
                    );
                    let Some(command) = recv_public_action_command(&mut command_rx).await else {
                        return Err(error);
                    };
                    gas_fee = command.gas_fee;
                }
            }
        }
    } else {
        signer.derive_shield_private_key().await?
    };
    emit_refreshed_public_action_hardware_session(event_tx.as_ref(), &signer);
    let approve_data = broadcaster_core::contracts::shield::build_approve_calldata(
        chain.railgun_contract,
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
    let query_rpc_pool = query_rpc_pool_with_http_client(chain.rpc_urls, http);

    let wrap_receipt = if request.asset == PublicAssetId::Native {
        let tx_req = TransactionRequest::default()
            .with_chain_id(request.chain_id)
            .with_from(from_address)
            .with_to(token)
            .with_input(WETH_DEPOSIT_SELECTOR.to_vec())
            .with_value(request.amount)
            .with_nonce(0);
        let outcome = submit_public_action_step_session(
            PublicActionProgressStep::Wrap,
            tx_req,
            &signer,
            "public-shield-wrap",
            &query_rpc_pool,
            http.network_mode(),
            request.chain_id,
            from_address,
            &chain.gas,
            nonce,
            gas_fee,
            &mut command_rx,
            event_tx.as_ref(),
            &mut progress,
        )
        .await?;
        let receipt = outcome.receipt;
        if !receipt.status {
            return Err(eyre!(
                "public shield wrap transaction reverted ({})",
                receipt.tx_hash
            ));
        }
        nonce = Some(outcome.next_nonce);
        gas_fee = outcome.gas_fee;
        Some(receipt)
    } else {
        None
    };

    let approve_tx = TransactionRequest::default()
        .with_chain_id(request.chain_id)
        .with_from(from_address)
        .with_to(token)
        .with_input(approve_data)
        .with_nonce(0);
    let approve_outcome = submit_public_action_step_session(
        PublicActionProgressStep::Approve,
        approve_tx,
        &signer,
        "public-shield-approve",
        &query_rpc_pool,
        http.network_mode(),
        request.chain_id,
        from_address,
        &chain.gas,
        nonce,
        gas_fee,
        &mut command_rx,
        event_tx.as_ref(),
        &mut progress,
    )
    .await?;
    let approve_receipt = approve_outcome.receipt;
    if !approve_receipt.status {
        return Err(eyre!(
            "public shield approve transaction reverted ({})",
            approve_receipt.tx_hash
        ));
    }
    nonce = Some(approve_outcome.next_nonce);
    gas_fee = approve_outcome.gas_fee;

    let shield_tx = TransactionRequest::default()
        .with_chain_id(request.chain_id)
        .with_from(from_address)
        .with_to(chain.railgun_contract)
        .with_input(shield_data)
        .with_nonce(0);
    let shield_receipt = submit_public_action_step_session(
        PublicActionProgressStep::Shield,
        shield_tx,
        &signer,
        "public-shield",
        &query_rpc_pool,
        http.network_mode(),
        request.chain_id,
        from_address,
        &chain.gas,
        nonce,
        gas_fee,
        &mut command_rx,
        event_tx.as_ref(),
        &mut progress,
    )
    .await?
    .receipt;
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

struct PublicActionStepOutcome {
    receipt: TxReceiptOutput,
    next_nonce: u64,
    gas_fee: PublicActionGasFeeSelection,
}

struct PublicActionPreflight {
    tx_req: TransactionRequest,
    nonce: u64,
    gas_limit: u64,
    rpc_gas_price: u128,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
    estimated_native_gas_cost: U256,
    live_native_balance: U256,
}

struct SubmittedPublicActionAttempt {
    provider_handles: Vec<ProviderHandle>,
    tx_hash: FixedBytes<32>,
    info: PublicActionAttemptInfo,
    rpc_gas_price: u128,
    estimated_native_gas_cost: U256,
    live_native_balance: U256,
}

struct PublicActionSentTx {
    tx_hash: FixedBytes<32>,
    tx_hash_string: String,
    provider_handles: Vec<ProviderHandle>,
}

pub(crate) enum VaultedPublicSigner {
    Software(SoftwareEvmSigner),
    Hardware(HardwarePublicEvmSigner),
}

pub(crate) struct HardwarePublicEvmSigner {
    address: Address,
    descriptor: HardwarePublicAccountDescriptor,
    hardware_session: Mutex<HardwareProfileSession>,
    trezor_app_passphrase: Mutex<Option<Zeroizing<String>>>,
    trezor_pin_matrix_provider: Option<HardwareTrezorPinMatrixProvider>,
}

impl VaultedPublicSigner {
    pub(crate) fn address(&self) -> Address {
        match self {
            Self::Software(signer) => signer.address(),
            Self::Hardware(signer) => signer.address,
        }
    }

    pub(crate) const fn requires_device_approval(&self) -> bool {
        matches!(self, Self::Hardware(_))
    }

    pub(crate) async fn sign_transaction_request(
        &self,
        tx_req: TransactionRequest,
        label: &str,
    ) -> Result<Vec<u8>> {
        match self {
            Self::Software(signer) => {
                let wallet = signer.ethereum_wallet();
                Ok(tx_req
                    .build(&wallet)
                    .await
                    .wrap_err_with(|| format!("{label}: sign"))?
                    .encoded_2718())
            }
            Self::Hardware(signer) => signer.sign_transaction_request(tx_req, label).await,
        }
    }

    pub(crate) async fn derive_shield_private_key(&self) -> Result<Zeroizing<[u8; 32]>> {
        match self {
            Self::Software(signer) => Ok(Zeroizing::new(signer.derive_shield_private_key()?)),
            Self::Hardware(signer) => signer.derive_shield_private_key().await,
        }
    }

    pub(crate) fn refreshed_trezor_hardware_session(
        &self,
    ) -> Result<Option<HardwareProfileSession>> {
        match self {
            Self::Software(_) => Ok(None),
            Self::Hardware(signer) => signer.refreshed_trezor_hardware_session(),
        }
    }
}

impl HardwarePublicEvmSigner {
    async fn sign_transaction_request(
        &self,
        tx_req: TransactionRequest,
        label: &str,
    ) -> Result<Vec<u8>> {
        let tx = tx_req
            .build_consensus_tx()
            .map_err(|error| eyre!(error.error))
            .wrap_err_with(|| format!("{label}: build hardware transaction"))?;
        let signature = self
            .sign_transaction(&tx)
            .await
            .wrap_err_with(|| format!("{label}: hardware sign"))?;
        let signing_hash = tx.signature_hash();
        let recovered = signature
            .recover_address_from_prehash(&signing_hash)
            .wrap_err_with(|| format!("{label}: recover hardware signature"))?;
        if recovered != self.address {
            return Err(eyre!(
                "hardware public signer address mismatch: expected {}, got {}",
                self.address,
                recovered
            ));
        }
        Ok(tx.into_envelope(signature).encoded_2718())
    }

    async fn derive_shield_private_key(&self) -> Result<Zeroizing<[u8; 32]>> {
        const SHIELD_MESSAGE: &[u8] = b"RAILGUN_SHIELD";
        let signature = self
            .sign_message(SHIELD_MESSAGE)
            .await
            .wrap_err("hardware sign shield key message")?;
        let recovered = signature
            .recover_address_from_msg(SHIELD_MESSAGE)
            .wrap_err("recover hardware shield key signature")?;
        if recovered != self.address {
            return Err(eyre!(
                "hardware public signer address mismatch: expected {}, got {}",
                self.address,
                recovered
            ));
        }
        let signature_bytes = Zeroizing::new(signature.as_bytes());
        Ok(Zeroizing::new(keccak256(*signature_bytes).0))
    }

    async fn sign_transaction(&self, tx: &dyn SignableTransaction<Signature>) -> Result<Signature> {
        let hardware_session = self.hardware_session()?;
        let (signature, trezor_session_id) = sign_hardware_public_transaction(
            &self.descriptor,
            &hardware_session,
            self.take_trezor_app_passphrase(),
            self.trezor_pin_matrix_provider.clone(),
            self.address,
            tx,
        )
        .await?;
        self.replace_trezor_session_id_if_trezor(trezor_session_id)?;
        Ok(signature)
    }

    async fn sign_message(&self, message: &[u8]) -> Result<Signature> {
        let hardware_session = self.hardware_session()?;
        let (signature, trezor_session_id) = sign_hardware_public_message(
            &self.descriptor,
            &hardware_session,
            self.take_trezor_app_passphrase(),
            self.trezor_pin_matrix_provider.clone(),
            self.address,
            message,
        )
        .await?;
        self.replace_trezor_session_id_if_trezor(trezor_session_id)?;
        Ok(signature)
    }

    fn hardware_session(&self) -> Result<HardwareProfileSession> {
        let session = self
            .hardware_session
            .lock()
            .map_err(|_| eyre!("hardware public signer session lock poisoned"))?;
        Ok(session.clone())
    }

    fn replace_trezor_session_id_if_trezor(&self, session_id: Option<Vec<u8>>) -> Result<()> {
        if self.descriptor.device_kind != crate::hardware::HardwareDeviceKind::Trezor {
            return Ok(());
        }
        let mut session = self
            .hardware_session
            .lock()
            .map_err(|_| eyre!("hardware public signer session lock poisoned"))?;
        session.trezor_session_id = session_id;
        Ok(())
    }

    fn refreshed_trezor_hardware_session(&self) -> Result<Option<HardwareProfileSession>> {
        if self.descriptor.device_kind != crate::hardware::HardwareDeviceKind::Trezor {
            return Ok(None);
        }
        self.hardware_session().map(Some)
    }

    fn take_trezor_app_passphrase(&self) -> Option<Zeroizing<String>> {
        self.trezor_app_passphrase
            .lock()
            .ok()
            .and_then(|mut passphrase| passphrase.take())
    }
}

#[cfg(feature = "hardware")]
async fn sign_hardware_public_transaction(
    descriptor: &HardwarePublicAccountDescriptor,
    hardware_session: &HardwareProfileSession,
    trezor_app_passphrase: Option<Zeroizing<String>>,
    trezor_pin_matrix_provider: Option<HardwareTrezorPinMatrixProvider>,
    expected_address: Address,
    tx: &dyn SignableTransaction<Signature>,
) -> Result<(Signature, Option<Vec<u8>>)> {
    match descriptor.device_kind {
        crate::hardware::HardwareDeviceKind::Ledger => {
            let client = crate::hardware::ledger::LedgerHardwareDerivationClient::connect()
                .await
                .wrap_err("connect Ledger for public transaction signing")?;
            let profile_path = parse_bip32_path(DEFAULT_HARDWARE_DERIVATION_PATH)
                .wrap_err("parse hardware profile path")?;
            let active = client
                .active_profile_session(&profile_path)
                .await
                .wrap_err("verify Ledger hardware profile")?;
            ensure_hardware_public_profile_session(hardware_session, &active)?;
            let address = client
                .public_ethereum_address(descriptor)
                .await
                .wrap_err("verify Ledger public account address")?;
            ensure_hardware_public_address(expected_address, address)?;
            let signature = client
                .sign_transaction_rlp(descriptor, &tx.encoded_for_signing())
                .await
                .wrap_err("sign public transaction on Ledger")?;
            Ok((signature, None))
        }
        crate::hardware::HardwareDeviceKind::Trezor => {
            let mut client =
                crate::hardware::trezor::TrezorHardwareDerivationClient::connect_with_session(
                    hardware_session.trezor_session_id.clone(),
                )
                .wrap_err("connect Trezor for public transaction signing")?;
            client.set_passphrase_mode(hardware_session.trezor_passphrase_mode());
            if let Some(passphrase) = trezor_app_passphrase {
                client.set_app_passphrase_zeroizing(passphrase);
            }
            if let Some(provider) = trezor_pin_matrix_provider {
                client.set_pin_matrix_provider(provider);
            }
            let profile_path = parse_bip32_path(DEFAULT_HARDWARE_DERIVATION_PATH)
                .wrap_err("parse hardware profile path")?;
            let active = client
                .active_profile_session(&profile_path)
                .wrap_err("verify Trezor hardware profile")?;
            let trezor_session_id = active.trezor_session_id.clone();
            ensure_hardware_public_profile_session(hardware_session, &active)?;
            let address = client
                .public_ethereum_address(descriptor)
                .wrap_err("verify Trezor public account address")?;
            ensure_hardware_public_address(expected_address, address)?;
            let signature = client
                .sign_transaction(descriptor, tx)
                .wrap_err("sign public transaction on Trezor")?;
            Ok((signature, trezor_session_id))
        }
    }
}

#[cfg(not(feature = "hardware"))]
#[allow(clippy::unused_async)]
async fn sign_hardware_public_transaction(
    _descriptor: &HardwarePublicAccountDescriptor,
    _hardware_session: &HardwareProfileSession,
    _trezor_app_passphrase: Option<Zeroizing<String>>,
    _trezor_pin_matrix_provider: Option<HardwareTrezorPinMatrixProvider>,
    _expected_address: Address,
    _tx: &dyn SignableTransaction<Signature>,
) -> Result<(Signature, Option<Vec<u8>>)> {
    Err(eyre!(
        "hardware public signing is not enabled in this build"
    ))
}

#[cfg(feature = "hardware")]
async fn sign_hardware_public_message(
    descriptor: &HardwarePublicAccountDescriptor,
    hardware_session: &HardwareProfileSession,
    trezor_app_passphrase: Option<Zeroizing<String>>,
    trezor_pin_matrix_provider: Option<HardwareTrezorPinMatrixProvider>,
    expected_address: Address,
    message: &[u8],
) -> Result<(Signature, Option<Vec<u8>>)> {
    match descriptor.device_kind {
        crate::hardware::HardwareDeviceKind::Ledger => {
            let client = crate::hardware::ledger::LedgerHardwareDerivationClient::connect()
                .await
                .wrap_err("connect Ledger for public message signing")?;
            let profile_path = parse_bip32_path(DEFAULT_HARDWARE_DERIVATION_PATH)
                .wrap_err("parse hardware profile path")?;
            let active = client
                .active_profile_session(&profile_path)
                .await
                .wrap_err("verify Ledger hardware profile")?;
            ensure_hardware_public_profile_session(hardware_session, &active)?;
            let address = client
                .public_ethereum_address(descriptor)
                .await
                .wrap_err("verify Ledger public account address")?;
            ensure_hardware_public_address(expected_address, address)?;
            let signature = client
                .sign_message(descriptor, message)
                .await
                .wrap_err("sign public message on Ledger")?;
            Ok((signature, None))
        }
        crate::hardware::HardwareDeviceKind::Trezor => {
            let mut client =
                crate::hardware::trezor::TrezorHardwareDerivationClient::connect_with_session(
                    hardware_session.trezor_session_id.clone(),
                )
                .wrap_err("connect Trezor for public message signing")?;
            client.set_passphrase_mode(hardware_session.trezor_passphrase_mode());
            if let Some(passphrase) = trezor_app_passphrase {
                client.set_app_passphrase_zeroizing(passphrase);
            }
            if let Some(provider) = trezor_pin_matrix_provider {
                client.set_pin_matrix_provider(provider);
            }
            let profile_path = parse_bip32_path(DEFAULT_HARDWARE_DERIVATION_PATH)
                .wrap_err("parse hardware profile path")?;
            let active = client
                .active_profile_session(&profile_path)
                .wrap_err("verify Trezor hardware profile")?;
            let trezor_session_id = active.trezor_session_id.clone();
            ensure_hardware_public_profile_session(hardware_session, &active)?;
            let address = client
                .public_ethereum_address(descriptor)
                .wrap_err("verify Trezor public account address")?;
            ensure_hardware_public_address(expected_address, address)?;
            let signature = client
                .sign_message(descriptor, message)
                .wrap_err("sign public message on Trezor")?;
            Ok((signature, trezor_session_id))
        }
    }
}

#[cfg(not(feature = "hardware"))]
#[allow(clippy::unused_async)]
async fn sign_hardware_public_message(
    _descriptor: &HardwarePublicAccountDescriptor,
    _hardware_session: &HardwareProfileSession,
    _trezor_app_passphrase: Option<Zeroizing<String>>,
    _trezor_pin_matrix_provider: Option<HardwareTrezorPinMatrixProvider>,
    _expected_address: Address,
    _message: &[u8],
) -> Result<(Signature, Option<Vec<u8>>)> {
    Err(eyre!(
        "hardware public signing is not enabled in this build"
    ))
}

#[cfg_attr(not(feature = "hardware"), allow(dead_code))]
fn ensure_hardware_public_profile_session(
    expected: &HardwareProfileSession,
    actual: &HardwareProfileSession,
) -> Result<()> {
    if expected.device_kind == actual.device_kind && expected.binding == actual.binding {
        Ok(())
    } else {
        Err(eyre!(
            "hardware public signer profile mismatch: wrong device or passphrase context is active"
        ))
    }
}

#[cfg_attr(not(feature = "hardware"), allow(dead_code))]
fn ensure_hardware_public_address(expected: Address, actual: Address) -> Result<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(eyre!(
            "hardware public account identity mismatch: expected {}, got {}",
            expected,
            actual
        ))
    }
}

async fn submit_public_action_step_session(
    step: PublicActionProgressStep,
    base_tx_req: TransactionRequest,
    signer: &VaultedPublicSigner,
    label: &str,
    query_rpc_pool: &QueryRpcPool,
    network_mode: crate::WalletNetworkMode,
    chain_id: u64,
    from_address: Address,
    gas: &EffectiveChainGasSettings,
    mut nonce: Option<u64>,
    gas_fee: PublicActionGasFeeSelection,
    command_rx: &mut Option<PublicActionCommandReceiver>,
    event_tx: Option<&PublicActionSessionEventSender>,
    progress: &mut (impl FnMut(PublicActionProgressUpdate) + Send),
) -> Result<PublicActionStepOutcome> {
    let mut next_gas_fee = gas_fee;
    let mut submitted_attempts = Vec::new();

    loop {
        progress(public_action_progress_update(
            step,
            PublicActionProgressStatus::Pending,
            None,
            None,
        ));

        let preflight = match public_action_preflight_from_rpc_pool(
            query_rpc_pool,
            network_mode,
            chain_id,
            from_address,
            base_tx_req.clone(),
            next_gas_fee,
            gas,
            nonce,
            None,
        )
        .await
        {
            Ok(preflight) => preflight,
            Err(error) => {
                let message = report_chain_string(&error);
                progress(public_action_progress_update(
                    step,
                    PublicActionProgressStatus::Error,
                    None,
                    Some(message.clone()),
                ));
                emit_public_action_event(
                    event_tx,
                    PublicActionSessionEvent::StepFailed { step, message },
                );
                let Some(command) = recv_public_action_command(command_rx).await else {
                    return Err(error);
                };
                next_gas_fee = command.gas_fee;
                continue;
            }
        };
        nonce = Some(preflight.nonce);

        emit_public_action_event(event_tx, PublicActionSessionEvent::AttemptHandoff { step });
        let attempt = match submit_public_action_attempt(
            step,
            preflight,
            query_rpc_pool,
            network_mode,
            signer,
            label,
            event_tx,
        )
        .await
        {
            Ok(attempt) => attempt,
            Err(
                PublicActionAttemptError::Signing(error) | PublicActionAttemptError::Sending(error),
            ) => {
                let message = report_chain_string(&error);
                progress(public_action_progress_update(
                    step,
                    PublicActionProgressStatus::Error,
                    None,
                    Some(message.clone()),
                ));
                emit_public_action_event(
                    event_tx,
                    PublicActionSessionEvent::StepFailed { step, message },
                );
                let Some(command) = recv_public_action_command(command_rx).await else {
                    return Err(error);
                };
                next_gas_fee = command.gas_fee;
                continue;
            }
        };
        progress(public_action_progress_update(
            step,
            PublicActionProgressStatus::Pending,
            Some(attempt.info.tx_hash.clone()),
            None,
        ));
        submitted_attempts.push(attempt);

        loop {
            let receipt = if command_rx.is_some() {
                tokio::select! {
                    () = tokio::time::sleep(Duration::from_secs(3)) => {
                        poll_public_action_attempt_receipts(&submitted_attempts).await?
                    }
                    command = recv_public_action_command(command_rx) => {
                        let Some(command) = command else {
                            *command_rx = None;
                            continue;
                        };
                        let Some(nonce) = nonce else {
                            next_gas_fee = command.gas_fee;
                            break;
                        };
                        let gas_limit = submitted_attempts
                            .last()
                            .map_or(0, |attempt| attempt.info.gas_limit);
                        let replacement = match public_action_preflight_from_rpc_pool(
                            query_rpc_pool,
                            network_mode,
                            chain_id,
                            from_address,
                            base_tx_req.clone(),
                            command.gas_fee,
                            gas,
                            Some(nonce),
                            Some(gas_limit),
                        )
                        .await
                        {
                            Ok(preflight) => preflight,
                            Err(error) => {
                                emit_public_action_event(
                                    event_tx,
                                    PublicActionSessionEvent::AttemptRejected {
                                        step,
                                        message: report_chain_string(&error),
                                    },
                                );
                                continue;
                            }
                        };
                        emit_public_action_event(
                            event_tx,
                            PublicActionSessionEvent::AttemptHandoff { step },
                        );
                        match submit_public_action_attempt(
                            step,
                            replacement,
                            query_rpc_pool,
                            network_mode,
                            signer,
                            label,
                            event_tx,
                        )
                        .await
                        {
                            Ok(attempt) => {
                                progress(public_action_progress_update(
                                    step,
                                    PublicActionProgressStatus::Pending,
                                    Some(attempt.info.tx_hash.clone()),
                                    None,
                                ));
                                submitted_attempts.push(attempt);
                            }
                            Err(error) => emit_public_action_event(
                                event_tx,
                                PublicActionSessionEvent::AttemptRejected {
                                    step,
                                    message: error.message(),
                                },
                            ),
                        }
                        continue;
                    }
                }
            } else {
                tokio::time::sleep(Duration::from_secs(3)).await;
                poll_public_action_attempt_receipts(&submitted_attempts).await?
            };

            if let Some((winner_index, receipt)) = receipt {
                let winner = &submitted_attempts[winner_index];
                tracing::info!(
                    step = ?step,
                    tx_hash = %receipt.tx_hash,
                    rpc_gas_price = winner.rpc_gas_price,
                    estimated_native_gas_cost = %winner.estimated_native_gas_cost,
                    live_native_balance = %winner.live_native_balance,
                    "public action receipt confirmed from submitted attempts"
                );
                if receipt.status {
                    progress(public_action_progress_update(
                        step,
                        PublicActionProgressStatus::Done,
                        Some(receipt.tx_hash.clone()),
                        None,
                    ));
                } else {
                    let message = "Transaction reverted".to_string();
                    progress(public_action_progress_update(
                        step,
                        PublicActionProgressStatus::Error,
                        Some(receipt.tx_hash.clone()),
                        Some(message.clone()),
                    ));
                    emit_public_action_event(
                        event_tx,
                        PublicActionSessionEvent::StepFailed { step, message },
                    );
                    let gas_fee = PublicActionGasFeeSelection::Custom {
                        max_fee_per_gas: winner.info.max_fee_per_gas,
                        max_priority_fee_per_gas: winner.info.max_priority_fee_per_gas,
                    };
                    let Some(command) = recv_public_action_command(command_rx).await else {
                        return Ok(PublicActionStepOutcome {
                            receipt,
                            next_nonce: winner.info.nonce.saturating_add(1),
                            gas_fee,
                        });
                    };
                    nonce = Some(winner.info.nonce.saturating_add(1));
                    next_gas_fee = command.gas_fee;
                    submitted_attempts.clear();
                    break;
                }
                let gas_fee = PublicActionGasFeeSelection::Custom {
                    max_fee_per_gas: winner.info.max_fee_per_gas,
                    max_priority_fee_per_gas: winner.info.max_priority_fee_per_gas,
                };
                return Ok(PublicActionStepOutcome {
                    receipt,
                    next_nonce: winner.info.nonce.saturating_add(1),
                    gas_fee,
                });
            }
        }
    }
}

async fn submit_public_action_attempt(
    step: PublicActionProgressStep,
    preflight: PublicActionPreflight,
    query_rpc_pool: &QueryRpcPool,
    network_mode: crate::WalletNetworkMode,
    signer: &VaultedPublicSigner,
    label: &str,
    event_tx: Option<&PublicActionSessionEventSender>,
) -> Result<SubmittedPublicActionAttempt, PublicActionAttemptError> {
    let sent = sign_send_public_action_transaction(
        query_rpc_pool,
        network_mode,
        signer,
        preflight.tx_req,
        label,
        event_tx,
    )
    .await?;
    let info = PublicActionAttemptInfo {
        tx_hash: sent.tx_hash_string,
        nonce: preflight.nonce,
        gas_limit: preflight.gas_limit,
        max_fee_per_gas: preflight.max_fee_per_gas,
        max_priority_fee_per_gas: preflight.max_priority_fee_per_gas,
    };
    emit_public_action_event(
        event_tx,
        PublicActionSessionEvent::AttemptSubmitted {
            step,
            attempt: info.clone(),
        },
    );
    Ok(SubmittedPublicActionAttempt {
        provider_handles: sent.provider_handles,
        tx_hash: sent.tx_hash,
        info,
        rpc_gas_price: preflight.rpc_gas_price,
        estimated_native_gas_cost: preflight.estimated_native_gas_cost,
        live_native_balance: preflight.live_native_balance,
    })
}

enum PublicActionAttemptError {
    Signing(eyre::Report),
    Sending(eyre::Report),
}

impl PublicActionAttemptError {
    fn message(&self) -> String {
        match self {
            Self::Signing(error) | Self::Sending(error) => report_chain_string(error),
        }
    }
}

async fn public_action_preflight_from_rpc_pool(
    query_rpc_pool: &QueryRpcPool,
    network_mode: crate::WalletNetworkMode,
    chain_id: u64,
    from: Address,
    base_tx_req: TransactionRequest,
    gas_fee: PublicActionGasFeeSelection,
    gas: &EffectiveChainGasSettings,
    nonce: Option<u64>,
    gas_limit: Option<u64>,
) -> Result<PublicActionPreflight> {
    let quote = public_action_gas_fee_quote_from_rpc_pool(query_rpc_pool, network_mode, chain_id)
        .await
        .wrap_err("fetch public action gas price")?;
    let mut last_error = None;
    for _ in 0..query_rpc_pool.len() {
        let Some(provider_handle) = query_rpc_pool.random_provider() else {
            break;
        };
        match public_action_preflight(
            provider_handle,
            chain_id,
            from,
            base_tx_req.clone(),
            gas_fee,
            quote,
            gas,
            nonce,
            gas_limit,
        )
        .await
        {
            Ok(preflight) => return Ok(preflight),
            Err(error) => {
                tracing::warn!(%error, "public action preflight failed");
                last_error = Some(error);
            }
        }
    }
    if let Some(error) = last_error {
        Err(error).wrap_err("all public action query RPC attempts failed")
    } else {
        Err(eyre!("no healthy query RPC available"))
    }
}

async fn public_action_preflight(
    provider_handle: ProviderHandle,
    chain_id: u64,
    from: Address,
    base_tx_req: TransactionRequest,
    gas_fee: PublicActionGasFeeSelection,
    quote: PublicActionGasFeeQuote,
    gas: &EffectiveChainGasSettings,
    nonce: Option<u64>,
    gas_limit: Option<u64>,
) -> Result<PublicActionPreflight> {
    let provider = &provider_handle.provider;
    let resolved = resolve_self_broadcast_gas_fee(gas_fee, quote)?;
    let nonce = if let Some(nonce) = nonce {
        nonce
    } else {
        provider
            .get_transaction_count(from)
            .await
            .wrap_err("fetch public action nonce")?
    };
    let tx_req = public_action_eip1559_transaction_request(
        base_tx_req,
        chain_id,
        from,
        resolved.max_fee_per_gas,
        resolved.max_priority_fee_per_gas,
        nonce,
    );
    let gas_limit = if let Some(gas_limit) = gas_limit {
        gas_limit
    } else {
        provider
            .estimate_gas(tx_req.clone())
            .await
            .wrap_err("estimate public action gas")?
            .saturating_add(gas.gas_limit_buffer)
    };
    let estimated_native_gas_cost = public_action_native_gas_cost(
        tx_req.value.unwrap_or_default(),
        gas_limit,
        resolved.max_fee_per_gas,
    );
    let live_native_balance = provider
        .get_balance(from)
        .await
        .wrap_err("fetch public action native balance")?;
    if live_native_balance < estimated_native_gas_cost {
        return Err(eyre!(
            "insufficient native gas for public action: live balance {live_native_balance}, estimated max cost {estimated_native_gas_cost}"
        ));
    }
    Ok(PublicActionPreflight {
        tx_req: tx_req.with_gas_limit(gas_limit),
        nonce,
        gas_limit,
        rpc_gas_price: resolved.rpc_gas_price,
        max_fee_per_gas: resolved.max_fee_per_gas,
        max_priority_fee_per_gas: resolved.max_priority_fee_per_gas,
        estimated_native_gas_cost,
        live_native_balance,
    })
}

fn public_action_eip1559_transaction_request(
    tx_req: TransactionRequest,
    chain_id: u64,
    from: Address,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
    nonce: u64,
) -> TransactionRequest {
    tx_req
        .with_chain_id(chain_id)
        .with_from(from)
        .with_max_fee_per_gas(max_fee_per_gas)
        .with_max_priority_fee_per_gas(max_priority_fee_per_gas)
        .with_nonce(nonce)
}

fn public_action_native_gas_cost(value: U256, gas_limit: u64, max_fee_per_gas: u128) -> U256 {
    value + (U256::from(gas_limit) * U256::from(max_fee_per_gas))
}

async fn sign_send_public_action_transaction(
    query_rpc_pool: &QueryRpcPool,
    network_mode: crate::WalletNetworkMode,
    signer: &VaultedPublicSigner,
    tx_req: TransactionRequest,
    label: &str,
    event_tx: Option<&PublicActionSessionEventSender>,
) -> Result<PublicActionSentTx, PublicActionAttemptError> {
    tracing::info!(
        from = %tx_req.from.unwrap_or_default(),
        to = ?tx_req.to,
        gas = ?tx_req.gas,
        label,
        "signing and sending public action transaction",
    );
    let signed_tx = signer
        .sign_transaction_request(tx_req, label)
        .await
        .map_err(PublicActionAttemptError::Signing)?;
    emit_refreshed_public_action_hardware_session(event_tx, signer);
    // Stop/abort requested during synchronous hardware approval is observed here before RPC broadcast.
    public_action_before_raw_broadcast_checkpoint().await;
    let tx_hash = keccak256(&signed_tx);
    let provider_handles = self_broadcast_send_raw_transaction_to_rpc_pool(
        query_rpc_pool,
        network_mode,
        signed_tx,
        tx_hash,
    )
    .await
    .wrap_err_with(|| format!("{label}: send"))
    .map_err(PublicActionAttemptError::Sending)?;
    let tx_hash_string = alloy::hex::encode_prefixed(tx_hash);
    tracing::info!(%tx_hash, providers = provider_handles.len(), label, "sent public action transaction");
    Ok(PublicActionSentTx {
        tx_hash,
        tx_hash_string,
        provider_handles,
    })
}

async fn public_action_before_raw_broadcast_checkpoint() {
    tokio::task::yield_now().await;
}

async fn poll_public_action_attempt_receipts(
    attempts: &[SubmittedPublicActionAttempt],
) -> Result<Option<(usize, TxReceiptOutput)>> {
    let mut queried_provider_count = 0;
    let mut pending_response_count = 0;
    let mut last_error = None;
    for (index, attempt) in attempts.iter().enumerate() {
        for provider_handle in &attempt.provider_handles {
            match provider_handle
                .provider
                .get_transaction_receipt(attempt.tx_hash)
                .await
            {
                Ok(Some(receipt)) => {
                    return Ok(Some((index, tx_receipt_output(attempt.tx_hash, &receipt))));
                }
                Ok(None) => {
                    queried_provider_count += 1;
                    pending_response_count += 1;
                }
                Err(error) => {
                    queried_provider_count += 1;
                    last_error = Some(format!("{}: {error}", provider_handle.url));
                    tracing::warn!(
                        url = %provider_handle.url,
                        %error,
                        "public action receipt fetch failed"
                    );
                }
            }
        }
    }
    if let Some(message) = public_action_receipt_poll_error_message(
        queried_provider_count,
        pending_response_count,
        last_error,
    ) {
        return Err(eyre!("{message}"));
    }
    Ok(None)
}

#[must_use]
fn public_action_receipt_poll_error_message(
    queried_provider_count: usize,
    pending_response_count: usize,
    last_error: Option<String>,
) -> Option<String> {
    if queried_provider_count == 0 || pending_response_count > 0 {
        return None;
    }
    last_error.map(|error| {
        format!(
            "public action receipt fetch failed for all accepted RPC providers ({queried_provider_count} checked): {error}"
        )
    })
}

fn emit_public_action_event(
    event_tx: Option<&PublicActionSessionEventSender>,
    event: PublicActionSessionEvent,
) {
    if let Some(event_tx) = event_tx {
        let _ = event_tx.send(event);
    }
}

fn emit_refreshed_public_action_hardware_session(
    event_tx: Option<&PublicActionSessionEventSender>,
    signer: &VaultedPublicSigner,
) {
    match signer.refreshed_trezor_hardware_session() {
        Ok(Some(session)) => emit_public_action_event(
            event_tx,
            PublicActionSessionEvent::HardwareProfileSessionRefreshed { session },
        ),
        Ok(None) => {}
        Err(error) => {
            tracing::warn!(%error, "failed to read refreshed hardware public signer session")
        }
    }
}

async fn recv_public_action_command(
    command_rx: &mut Option<PublicActionCommandReceiver>,
) -> Option<PublicActionCommand> {
    let command_rx = command_rx.as_mut()?;
    command_rx.recv().await
}

#[must_use]
pub const fn public_action_replacement_bumped_fee(value: u128) -> u128 {
    self_broadcast_replacement_bumped_fee(value)
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

fn native_asset_for_chain(chain_id: u64) -> Option<PublicBalanceAsset> {
    let symbol = match chain_id {
        1 | 42161 => "ETH",
        56 => "BNB",
        137 => "MATIC",
        _ => return None,
    };
    Some(PublicBalanceAsset {
        id: PublicAssetId::Native,
        symbol: symbol.to_string(),
        decimals: 18,
    })
}

fn public_shield_token(asset: PublicAssetId, chain: &PublicChainRuntimeConfig) -> Result<Address> {
    match asset {
        PublicAssetId::Native => chain
            .wrapped_native_token
            .ok_or_else(|| eyre!("selected chain does not support native shielding")),
        PublicAssetId::Erc20(token) => Ok(token),
    }
}

struct PublicChainRuntimeConfig {
    rpc_urls: Vec<Url>,
    railgun_contract: Address,
    wrapped_native_token: Option<Address>,
    multicall_contract: Address,
    gas: EffectiveChainGasSettings,
}

fn public_chain_runtime_config(
    chain_id: u64,
    effective_chain: Option<&EffectiveChainConfig>,
) -> Result<PublicChainRuntimeConfig> {
    let defaults = chain_defaults_for_public_chain(chain_id)?;
    let Some(effective_chain) = effective_chain else {
        return Ok(PublicChainRuntimeConfig {
            rpc_urls: defaults.rpc_urls,
            railgun_contract: defaults.contract,
            wrapped_native_token: wrapped_native_token_for_chain(chain_id),
            multicall_contract: defaults.multicall_contract,
            gas: EffectiveChainGasSettings {
                gas_limit_buffer: GAS_LIMIT_BUFFER,
                gas_price_buffer_numerator: crate::GAS_PRICE_BUFFER_NUMERATOR as u64,
                gas_price_buffer_denominator: crate::GAS_PRICE_BUFFER_DENOMINATOR as u64,
            },
        });
    };
    if effective_chain.chain_id != chain_id {
        return Err(eyre!(
            "effective chain config is for chain {}, not {chain_id}",
            effective_chain.chain_id
        ));
    }
    let rpc_urls = effective_rpc_urls_for_chain(&defaults, Some(effective_chain))?;
    let railgun_contract =
        parse_effective_address("railgun contract", &effective_chain.railgun_contract)?;
    let wrapped_native_token = effective_chain
        .wrapped_native_token
        .as_deref()
        .map(|value| parse_effective_address("wrapped native token", value))
        .transpose()?
        .or_else(|| wrapped_native_token_for_chain(chain_id));
    let multicall_contract =
        parse_effective_address("multicall contract", &effective_chain.multicall_contract)?;
    Ok(PublicChainRuntimeConfig {
        rpc_urls,
        railgun_contract,
        wrapped_native_token,
        multicall_contract,
        gas: effective_chain.gas.clone(),
    })
}

fn parse_effective_address(label: &str, value: &str) -> Result<Address> {
    Address::from_str(value).wrap_err_with(|| format!("parse effective {label} address"))
}

pub(crate) fn vaulted_public_signer(
    vault_store: &DesktopVaultStore,
    view_session: &DesktopViewSession,
    vault_password: Option<&str>,
    public_account_uuid: &str,
    trezor_app_passphrase: Option<Zeroizing<String>>,
    trezor_pin_matrix_provider: Option<HardwareTrezorPinMatrixProvider>,
) -> Result<VaultedPublicSigner> {
    let accounts = vault_store
        .list_public_accounts_for_session(view_session, true)
        .wrap_err("load public account metadata")?;
    let account = accounts
        .iter()
        .find(|account| account.public_account_uuid == public_account_uuid)
        .ok_or_else(|| eyre!("public account not found"))?;
    if account.source == crate::vault::PublicAccountSource::HardwareDerived {
        let descriptor = account
            .hardware_descriptor
            .clone()
            .ok_or_else(|| eyre!("hardware public account descriptor missing"))?;
        descriptor
            .validate()
            .map_err(|error| eyre!(error))
            .wrap_err("validate hardware public account descriptor")?;
        return Ok(VaultedPublicSigner::Hardware(HardwarePublicEvmSigner {
            address: account.address,
            descriptor,
            hardware_session: Mutex::new(
                view_session
                    .hardware_profile_session()
                    .cloned()
                    .ok_or_else(|| eyre!("hardware profile session required for public signer"))?,
            ),
            trezor_app_passphrase: Mutex::new(trezor_app_passphrase),
            trezor_pin_matrix_provider,
        }));
    }

    let vault_password = vault_password
        .ok_or_else(|| eyre!("vault password required for software public account signer"))?;
    let mut grant = vault_store
        .create_spend_grant(vault_password)
        .wrap_err("authorize public account spend")?;
    let private_key = vault_store
        .public_account_signing_key(&mut grant, view_session, public_account_uuid)
        .wrap_err("load public account signing key")?;
    let signer = SoftwareEvmSigner::from_private_key(*private_key)
        .wrap_err("create public account signer")?;
    Ok(VaultedPublicSigner::Software(signer))
}

fn public_send_transaction_request(
    chain_id: u64,
    from: Address,
    asset: PublicAssetId,
    amount: U256,
    recipient: Address,
) -> TransactionRequest {
    let mut tx_req = TransactionRequest::default()
        .with_chain_id(chain_id)
        .with_from(from);
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
    chain_defaults_for_chain(chain_id)
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
    use crate::hardware::{
        ConfirmedHardwarePublicAccount, HardwareDerivationDescriptor, HardwareDeviceKind,
        HardwareOperationOutput, HardwarePublicAccountDescriptor, HardwareWalletSyncIntent,
        hardware_view_access_key_from_hardware_output, parse_bip32_path,
        synthetic_entropy_from_hardware_output,
    };
    use crate::vault::{
        HardwareProfileBinding, KdfParams, PublicAccountScope, PublicAccountSource,
        PublicAccountStatus, TrezorPassphraseMode, VaultError, WalletSource,
    };

    const TEST_PASSWORD: &str = "correct horse battery staple";
    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const TEST_IMPORTED_PRIVATE_KEY: &str =
        "0x59c6995e998f97a5a0044966f0945387e7d5e4a4dbd4b3f1b530b87d9b4a5c2f";
    static TEMP_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn public_action_attempt_errors_distinguish_signing_from_retryable_sending() {
        let signing = PublicActionAttemptError::Signing(eyre!("user rejected on device"));
        let sending = PublicActionAttemptError::Sending(eyre!("rpc rejected transaction"));

        assert!(matches!(signing, PublicActionAttemptError::Signing(_)));
        assert!(matches!(sending, PublicActionAttemptError::Sending(_)));
    }

    #[test]
    fn public_action_pre_broadcast_checkpoint_yields_for_abort() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build runtime");

        runtime.block_on(async {
            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
            let task = tokio::spawn(async move {
                let _ = ready_tx.send(());
                public_action_before_raw_broadcast_checkpoint().await;
                true
            });

            ready_rx.await.expect("checkpoint task started");
            task.abort();
            let error = task.await.expect_err("checkpoint task should abort");
            assert!(error.is_cancelled());
        });
    }

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
            hardware_descriptor: None,
            status: PublicAccountStatus::Active,
            display_order: 0,
        };
        let multicall = address!("0xcA11bde05977b3631167028862bE2a173976CA11");
        let calls = plan_public_balance_calls(1, multicall, &[account], None);

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
    fn balance_assets_use_effective_token_registry_overlays() {
        let mut settings = crate::settings::WalletSettings::default();
        settings
            .tokens
            .built_in_tombstones
            .push(crate::settings::TokenKey {
                chain_id: 1,
                token_address: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".to_string(),
            });
        settings
            .tokens
            .custom_tokens
            .push(crate::settings::CustomTokenSettings {
                chain_id: 1,
                token_address: "0x0000000000000000000000000000000000000002".to_string(),
                symbol: "CSTM".to_string(),
                decimals: 9,
                icon_path: None,
                price_anchor: None,
            });
        let registry = crate::settings::build_effective_token_registry(&settings)
            .expect("effective token registry");

        let assets = public_balance_assets_for_chain_with_registry(1, Some(&registry));

        assert!(assets.iter().any(|asset| asset.id == PublicAssetId::Native));
        assert!(!assets.iter().any(|asset| {
            asset.id == PublicAssetId::Erc20(address!("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"))
        }));
        let custom = assets
            .iter()
            .find(|asset| {
                asset.id
                    == PublicAssetId::Erc20(address!("0x0000000000000000000000000000000000000002"))
            })
            .expect("custom token asset");
        assert_eq!(custom.symbol, "CSTM");
        assert_eq!(custom.decimals, 9);
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
            hardware_descriptor: None,
            status: PublicAccountStatus::Active,
            display_order: 0,
        };
        let planned = vec![
            PlannedPublicBalanceCall {
                public_account_uuid: account.public_account_uuid.clone(),
                account: account.address,
                asset: PublicBalanceAsset {
                    id: PublicAssetId::Native,
                    symbol: "ETH".to_string(),
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
                    symbol: "WETH".to_string(),
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
            PublicActionProgressStep::ShieldKey,
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
        assert_eq!(
            public_native_action_gas_units_with_buffer(&send_steps, 7),
            PUBLIC_NATIVE_SEND_GAS_UNITS + 7,
        );
    }

    #[test]
    fn effective_public_chain_config_uses_settings_overrides() {
        let defaults = chain_defaults_for_public_chain(1).expect("ethereum defaults");
        let effective = EffectiveChainConfig {
            chain_id: 1,
            enabled: true,
            rpc_endpoints: vec!["https://rpc.example".to_string()],
            archive_rpc_url: None,
            quick_sync_enabled: true,
            quick_sync_endpoint: defaults.quick_sync_endpoint.map(|url| url.to_string()),
            indexed_wallet_block_range: defaults.indexed_wallet_block_range,
            deployment_block: defaults.deployment_block,
            v2_start_block: defaults.v2_start_block,
            legacy_shield_block: defaults.legacy_shield_block,
            archive_until_block: defaults.archive_until_block,
            railgun_contract: "0x0000000000000000000000000000000000000001".to_string(),
            relay_adapt_contract: defaults.relay_adapt_contract.to_string(),
            relay_adapt_7702_contract: defaults.relay_adapt_7702_contract.to_string(),
            wrapped_native_token: Some("0x0000000000000000000000000000000000000002".to_string()),
            multicall_contract: "0x0000000000000000000000000000000000000003".to_string(),
            finality_depth: defaults.finality_depth,
            block_range: None,
            poll_interval_secs: None,
            gas: EffectiveChainGasSettings {
                gas_limit_buffer: 42,
                gas_price_buffer_numerator: 111,
                gas_price_buffer_denominator: 100,
            },
        };

        let config = public_chain_runtime_config(1, Some(&effective)).expect("effective config");

        assert_eq!(config.rpc_urls.len(), 1);
        assert_eq!(config.rpc_urls[0].as_str(), "https://rpc.example/");
        assert_eq!(
            config.railgun_contract,
            address!("0x0000000000000000000000000000000000000001")
        );
        assert_eq!(
            config.wrapped_native_token,
            Some(address!("0x0000000000000000000000000000000000000002"))
        );
        assert_eq!(
            config.multicall_contract,
            address!("0x0000000000000000000000000000000000000003")
        );
        assert_eq!(config.gas.gas_limit_buffer, 42);
    }

    #[test]
    fn effective_public_chain_config_uses_default_rpc_fallbacks() {
        let defaults = chain_defaults_for_public_chain(1).expect("ethereum defaults");
        let config = public_chain_runtime_config(1, None).expect("default config");

        assert_eq!(config.rpc_urls, defaults.rpc_urls);
        assert!(config.rpc_urls.len() > 1);
    }

    #[test]
    fn public_send_request_uses_native_value_or_erc20_transfer() {
        let from = address!("0x1111111111111111111111111111111111111111");
        let recipient = address!("0x2222222222222222222222222222222222222222");
        let token = address!("0x3333333333333333333333333333333333333333");
        let amount = U256::from(5_u64);

        let native =
            public_send_transaction_request(1, from, PublicAssetId::Native, amount, recipient);
        assert_eq!(native.to, Some(recipient.into()));
        assert_eq!(native.value, Some(amount));

        let erc20 = public_send_transaction_request(
            1,
            from,
            PublicAssetId::Erc20(token),
            amount,
            recipient,
        );
        assert_eq!(erc20.to, Some(token.into()));
        let expected_transfer = PublicErc20::transferCall { recipient, amount }.abi_encode();
        assert_eq!(
            erc20.input.input().expect("transfer input").as_ref(),
            expected_transfer.as_slice()
        );
    }

    #[test]
    fn public_action_eip1559_request_sets_fee_caps_and_nonce() {
        let from = address!("0x1111111111111111111111111111111111111111");
        let recipient = address!("0x2222222222222222222222222222222222222222");
        let base = public_send_transaction_request(
            1,
            from,
            PublicAssetId::Native,
            U256::from(5_u64),
            recipient,
        );

        let tx = public_action_eip1559_transaction_request(base, 1, from, 42, 3, 9);

        assert_eq!(tx.chain_id, Some(1));
        assert_eq!(tx.from, Some(from));
        assert_eq!(tx.to, Some(recipient.into()));
        assert_eq!(tx.max_fee_per_gas, Some(42));
        assert_eq!(tx.max_priority_fee_per_gas, Some(3));
        assert_eq!(tx.nonce, Some(9));
    }

    #[test]
    fn public_action_replacement_bump_reuses_self_broadcast_policy() {
        assert_eq!(public_action_replacement_bumped_fee(8), 9);
        assert_eq!(public_action_replacement_bumped_fee(9), 11);
    }

    #[test]
    fn public_action_tip_fallback_uses_rpc_gas_price_only_for_bnb() {
        assert_eq!(
            public_action_tip_fallback(56),
            SelfBroadcastTipFallback::RpcGasPrice,
        );
        assert_eq!(
            public_action_tip_fallback(1),
            SelfBroadcastTipFallback::Minimum,
        );
    }

    #[test]
    fn public_action_receipt_poll_error_message_requires_all_checked_providers_to_fail() {
        assert!(public_action_receipt_poll_error_message(0, 0, None).is_none());
        assert!(
            public_action_receipt_poll_error_message(
                2,
                1,
                Some("https://rpc.example: rate limited".to_string()),
            )
            .is_none()
        );

        let message = public_action_receipt_poll_error_message(
            2,
            0,
            Some("https://rpc.example: rate limited".to_string()),
        )
        .expect("all checked providers failed");

        assert!(message.contains("all accepted RPC providers"));
        assert!(message.contains("2 checked"));
        assert!(message.contains("rate limited"));
    }

    #[test]
    fn public_actions_reject_zero_amount_before_signing() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build runtime");
        let (root_dir, db, store, view_session) = public_action_request_parts();
        let http = HttpContext::direct_for_tests();
        let recipient = address!("0x2222222222222222222222222222222222222222");

        let send_result = runtime.block_on(submit_public_send(
            PublicSendRequest {
                chain_id: 1,
                effective_chain: None,
                view_session: Arc::clone(&view_session),
                vault_store: Arc::clone(&store),
                vault_password: Zeroizing::new(TEST_PASSWORD.to_string()),
                trezor_app_passphrase: None,
                trezor_pin_matrix_provider: None,
                public_account_uuid: "unused".to_string(),
                asset: PublicAssetId::Native,
                amount: U256::ZERO,
                recipient,
                gas_fee: PublicActionGasFeeSelection::Auto,
                command_rx: None,
                event_tx: None,
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
                effective_chain: None,
                view_session,
                vault_store: store,
                vault_password: Zeroizing::new(TEST_PASSWORD.to_string()),
                trezor_app_passphrase: None,
                trezor_pin_matrix_provider: None,
                public_account_uuid: "unused".to_string(),
                asset: PublicAssetId::Native,
                amount: U256::ZERO,
                gas_fee: PublicActionGasFeeSelection::Auto,
                command_rx: None,
                event_tx: None,
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

    #[test]
    fn vaulted_public_signer_resolves_private_self_broadcast_gas_payers() {
        let (root_dir, db, store, view_session) = public_action_request_parts();
        let derived = store
            .list_active_public_accounts_for_session(&view_session)
            .expect("active accounts")
            .into_iter()
            .find(|account| account.source == PublicAccountSource::Derived)
            .expect("derived account");
        let derived_secret_key = format!("public-account-secret|{}", derived.public_account_uuid);
        assert!(
            db.get_desktop_wallet_vault_record(&derived_secret_key)
                .expect("load derived secret record")
                .is_none()
        );

        let derived_signer = vaulted_public_signer(
            &store,
            &view_session,
            Some(TEST_PASSWORD),
            &derived.public_account_uuid,
            None,
            None,
        )
        .expect("derived signer");
        assert_eq!(derived_signer.address(), derived.address);
        let Err(missing_password) = vaulted_public_signer(
            &store,
            &view_session,
            None,
            &derived.public_account_uuid,
            None,
            None,
        ) else {
            panic!("software public signer without password unexpectedly succeeded");
        };
        assert!(
            missing_password
                .to_string()
                .contains("vault password required for software public account signer")
        );

        let hardware_index = store
            .next_derived_public_account_index_for_session(&view_session)
            .expect("next hardware public index");
        let hardware_descriptor = HardwarePublicAccountDescriptor::for_wallet_public_index(
            HardwareDeviceKind::Ledger,
            view_session.derivation_index(),
            hardware_index,
        )
        .expect("hardware descriptor");
        let hardware_address = address!("0x2222222222222222222222222222222222222222");
        let confirmed =
            ConfirmedHardwarePublicAccount::new_for_tests(hardware_descriptor, hardware_address);
        assert!(matches!(
            store.add_hardware_public_account(&view_session, confirmed, Some("Ledger Gas")),
            Err(VaultError::HardwareWalletViewRequiresDevice)
        ));

        let hardware_wallet_id = "hardware-public-action-wallet";
        let hardware_private_descriptor = HardwareDerivationDescriptor::ledger_eip1024_v1(
            parse_bip32_path("m/44'/60'/0'/0/0").expect("hardware path"),
            0,
            "ledger:evm:0x1111111111111111111111111111111111111111".to_string(),
            HardwareWalletSyncIntent::CreateNew,
        );
        let output = HardwareOperationOutput::new([42; 32]);
        let view_access_key =
            hardware_view_access_key_from_hardware_output(&hardware_private_descriptor, &output)
                .expect("hardware view key");
        let entropy = synthetic_entropy_from_hardware_output(&hardware_private_descriptor, output)
            .expect("hardware entropy");
        let hardware_metadata = store
            .new_hardware_wallet_metadata(
                TEST_PASSWORD,
                hardware_wallet_id,
                "Hardware public action",
                hardware_private_descriptor.clone(),
            )
            .expect("hardware wallet metadata");
        store
            .store_hardware_derived_wallet_from_entropy_with_metadata(
                TEST_PASSWORD,
                hardware_wallet_id,
                hardware_private_descriptor.account_index,
                entropy.expose_secret(),
                &hardware_metadata,
                &view_access_key,
            )
            .expect("store hardware wallet");
        let hardware_session = store
            .hardware_profile_session_for_fingerprint(
                TEST_PASSWORD,
                HardwareDeviceKind::Ledger,
                &hardware_private_descriptor.profile_fingerprint,
                None,
            )
            .expect("hardware profile session");
        let hardware_view_session = store
            .load_hardware_view_session(
                TEST_PASSWORD,
                &hardware_session,
                hardware_wallet_id,
                &view_access_key,
            )
            .expect("hardware view session");
        let hardware_public_descriptor = HardwarePublicAccountDescriptor::for_wallet_public_index(
            HardwareDeviceKind::Ledger,
            hardware_view_session.derivation_index(),
            0,
        )
        .expect("hardware public descriptor");
        let hardware_public = store
            .add_hardware_public_account(
                &hardware_view_session,
                ConfirmedHardwarePublicAccount::new_for_tests(
                    hardware_public_descriptor,
                    address!("0x3333333333333333333333333333333333333333"),
                ),
                Some("Hardware Ledger Gas"),
            )
            .expect("hardware public account under hardware view");
        let hardware_signer = vaulted_public_signer(
            &store,
            &hardware_view_session,
            None,
            &hardware_public.public_account_uuid,
            None,
            None,
        )
        .expect("hardware signer with profile session");
        assert_eq!(hardware_signer.address(), hardware_public.address);
        assert!(hardware_signer.requires_device_approval());

        let imported = store
            .import_public_account(
                TEST_PASSWORD,
                &view_session,
                TEST_IMPORTED_PRIVATE_KEY,
                Some("Imported"),
                false,
            )
            .expect("import public account");
        let imported_signer = vaulted_public_signer(
            &store,
            &view_session,
            Some(TEST_PASSWORD),
            &imported.public_account_uuid,
            None,
            None,
        )
        .expect("imported signer");
        assert_eq!(imported_signer.address(), imported.address);

        drop(store);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[test]
    fn hardware_public_signer_consumes_trezor_app_passphrase_once() {
        let mut hardware_session = HardwareProfileSession::unmatched(
            HardwareDeviceKind::Trezor,
            HardwareProfileBinding::evm_address_fingerprint(
                "trezor:evm:0x1111111111111111111111111111111111111111",
            ),
            Some(vec![1, 2, 3]),
        );
        hardware_session.set_trezor_passphrase_mode(TrezorPassphraseMode::EnterInApp);
        let signer = HardwarePublicEvmSigner {
            address: address!("0x1111111111111111111111111111111111111111"),
            descriptor: HardwarePublicAccountDescriptor::for_wallet_public_index(
                HardwareDeviceKind::Trezor,
                0,
                0,
            )
            .expect("trezor descriptor"),
            hardware_session: std::sync::Mutex::new(hardware_session),
            trezor_app_passphrase: std::sync::Mutex::new(Some(Zeroizing::new(
                "app secret".to_owned(),
            ))),
            trezor_pin_matrix_provider: None,
        };

        let passphrase = signer
            .take_trezor_app_passphrase()
            .expect("first passphrase take");
        assert_eq!(passphrase.as_str(), "app secret");
        assert!(signer.take_trezor_app_passphrase().is_none());
    }

    #[test]
    fn hardware_public_signer_updates_in_memory_trezor_session_id() {
        let mut hardware_session = HardwareProfileSession::unmatched(
            HardwareDeviceKind::Trezor,
            HardwareProfileBinding::evm_address_fingerprint(
                "trezor:evm:0x1111111111111111111111111111111111111111",
            ),
            Some(vec![1, 2, 3]),
        );
        hardware_session.set_trezor_passphrase_mode(TrezorPassphraseMode::EnterInApp);
        let signer = HardwarePublicEvmSigner {
            address: address!("0x1111111111111111111111111111111111111111"),
            descriptor: HardwarePublicAccountDescriptor::for_wallet_public_index(
                HardwareDeviceKind::Trezor,
                0,
                0,
            )
            .expect("trezor descriptor"),
            hardware_session: std::sync::Mutex::new(hardware_session),
            trezor_app_passphrase: std::sync::Mutex::new(None),
            trezor_pin_matrix_provider: None,
        };

        signer
            .replace_trezor_session_id_if_trezor(Some(vec![4, 5, 6]))
            .expect("replace Trezor session id");
        assert_eq!(
            signer
                .hardware_session()
                .expect("hardware session")
                .trezor_session_id,
            Some(vec![4, 5, 6])
        );
        signer
            .replace_trezor_session_id_if_trezor(None)
            .expect("clear Trezor session id");
        assert_eq!(
            signer
                .hardware_session()
                .expect("hardware session")
                .trezor_session_id,
            None
        );
    }
}
