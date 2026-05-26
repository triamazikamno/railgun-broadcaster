use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use alloy::primitives::{Address, U256};
use alloy::providers::{CallItem, Provider};
use alloy::sol;
use alloy::sol_types::SolCall;
use broadcaster_core::query_rpc_pool::QueryRpcPool;
use eyre::{Result, WrapErr};
use railgun_ui::{
    NativeUsdAnchorInfo, TokenAnchorInfo, TokenAnchorSource, lookup_token,
    native_usd_anchor_entries, native_usd_micro_value, token_anchor_entries, token_usd_micro_value,
};
use sync_service::ChainConfigDefaults;
use tokio::runtime::Handle;
use tokio::sync::watch;
use tokio::task::AbortHandle;
use tokio::time::{Instant, MissedTickBehavior, interval};

use crate::settings::{EffectiveChainConfig, EffectiveTokenRegistry, PriceAnchorSettings};
use crate::{HttpContext, effective_rpc_urls_for_chain, query_rpc_pool_with_http_client};

const ANCHOR_OUTLIER_THRESHOLD_BPS: U256 = alloy::uint!(5_000_U256);
const BPS_DENOMINATOR: U256 = alloy::uint!(10_000_U256);
const TOKEN_ANCHOR_REFRESH_INTERVAL: Duration = Duration::from_secs(300);
const TOKEN_ANCHOR_WAKE_REFRESH_MIN_INTERVAL: Duration = Duration::from_secs(30);

sol! {
    interface AggregatorInterface {
        function latestAnswer() external view returns (int256);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BroadcasterFeePolicyStatus {
    Normal {
        anchor_rate: U256,
        premium_bps: i128,
    },
    Suspicious {
        anchor_rate: U256,
        premium_bps: Option<i128>,
    },
    UnknownAnchor,
}

impl BroadcasterFeePolicyStatus {
    #[must_use]
    pub const fn is_suspicious(self) -> bool {
        matches!(self, Self::Suspicious { .. })
    }

    #[must_use]
    pub const fn premium_bps(self) -> Option<i128> {
        match self {
            Self::Normal { premium_bps, .. } => Some(premium_bps),
            Self::Suspicious { premium_bps, .. } => premium_bps,
            Self::UnknownAnchor => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BroadcasterFeePolicy {
    pub min_anchor_bps: u64,
    pub max_anchor_bps: u64,
    pub allow_suspicious_broadcasters: bool,
}

impl Default for BroadcasterFeePolicy {
    fn default() -> Self {
        Self {
            min_anchor_bps: 9_000,
            max_anchor_bps: 15_000,
            allow_suspicious_broadcasters: false,
        }
    }
}

impl BroadcasterFeePolicy {
    #[must_use]
    pub const fn with_allow_suspicious_broadcasters(
        mut self,
        allow_suspicious_broadcasters: bool,
    ) -> Self {
        self.allow_suspicious_broadcasters = allow_suspicious_broadcasters;
        self
    }

    #[must_use]
    pub const fn allows_status(self, status: BroadcasterFeePolicyStatus) -> bool {
        !status.is_suspicious() || self.allow_suspicious_broadcasters
    }

    #[must_use]
    pub fn classify_fee(self, fee: U256, anchor_rate: Option<U256>) -> BroadcasterFeePolicyStatus {
        let Some(anchor_rate) = anchor_rate.filter(|rate| !rate.is_zero()) else {
            return BroadcasterFeePolicyStatus::UnknownAnchor;
        };
        let Some(fee_bps) = fee
            .checked_mul(BPS_DENOMINATOR)
            .and_then(|scaled| scaled.checked_div(anchor_rate))
        else {
            return BroadcasterFeePolicyStatus::Suspicious {
                anchor_rate,
                premium_bps: None,
            };
        };
        let min_bps = U256::from(self.min_anchor_bps);
        let max_bps = U256::from(self.max_anchor_bps);
        let premium_bps = i128::try_from(fee_bps).ok().map(|bps| bps - 10_000);
        if fee_bps < min_bps || fee_bps > max_bps {
            return BroadcasterFeePolicyStatus::Suspicious {
                anchor_rate,
                premium_bps,
            };
        }
        BroadcasterFeePolicyStatus::Normal {
            anchor_rate,
            premium_bps: premium_bps.unwrap_or_default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct TokenAnchorKey {
    chain_id: u64,
    token: Address,
}

#[derive(Debug, Clone)]
struct RuntimeTokenAnchorInfo {
    chain_id: u64,
    token: Address,
    anchor_sources: Vec<RuntimeTokenAnchorSource>,
}

#[derive(Debug, Clone)]
struct RuntimeNativeUsdAnchorInfo {
    chain_id: u64,
    anchor_sources: Vec<RuntimeTokenAnchorSource>,
}

#[derive(Debug, Clone)]
enum RuntimeTokenAnchorSource {
    Fixed {
        token_fee_per_unit_gas: U256,
    },
    ChainlinkOracle {
        chain_id: u64,
        addr: Address,
        token_decimals: u8,
        oracle_decimals: u8,
        is_inversed: bool,
    },
    Product {
        sources: Vec<Self>,
        scale_decimals: u8,
    },
}

impl TokenAnchorKey {
    const fn new(chain_id: u64, token: Address) -> Self {
        Self { chain_id, token }
    }
}

#[derive(Debug)]
pub struct TokenAnchorRateCache {
    rates: RwLock<BTreeMap<TokenAnchorKey, U256>>,
    native_usd_rates: RwLock<BTreeMap<u64, U256>>,
    refresh_tx: watch::Sender<u64>,
}

impl Default for TokenAnchorRateCache {
    fn default() -> Self {
        let (refresh_tx, _refresh_rx) = watch::channel(0_u64);
        Self {
            rates: RwLock::new(BTreeMap::new()),
            native_usd_rates: RwLock::new(BTreeMap::new()),
            refresh_tx,
        }
    }
}

impl TokenAnchorRateCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn cached_rate(&self, chain_id: u64, token: Address) -> Option<U256> {
        self.rates
            .read()
            .ok()
            .and_then(|rates| rates.get(&TokenAnchorKey::new(chain_id, token)).copied())
    }

    pub fn store_rate(&self, chain_id: u64, token: Address, rate: U256) {
        if rate.is_zero() {
            return;
        }
        if let Ok(mut rates) = self.rates.write() {
            rates.insert(TokenAnchorKey::new(chain_id, token), rate);
        }
    }

    #[must_use]
    pub fn cached_native_usd_rate(&self, chain_id: u64) -> Option<U256> {
        self.native_usd_rates
            .read()
            .ok()
            .and_then(|rates| rates.get(&chain_id).copied())
    }

    pub fn store_native_usd_rate(&self, chain_id: u64, rate: U256) {
        if rate.is_zero() {
            return;
        }
        if let Ok(mut rates) = self.native_usd_rates.write() {
            rates.insert(chain_id, rate);
        }
    }

    #[must_use]
    pub fn cached_token_usd_micro_value(
        &self,
        chain_id: u64,
        token: Address,
        amount: U256,
    ) -> Option<U256> {
        let token_anchor_rate = self
            .cached_rate(chain_id, token)
            .or_else(|| fixed_token_anchor_rate(chain_id, token))?;
        let native_usd_rate = self.cached_native_usd_rate(chain_id)?;
        token_usd_micro_value(amount, token_anchor_rate, native_usd_rate)
    }

    #[must_use]
    pub fn cached_native_usd_micro_value(&self, chain_id: u64, amount: U256) -> Option<U256> {
        native_usd_micro_value(amount, self.cached_native_usd_rate(chain_id)?)
    }

    #[must_use]
    pub fn subscribe_refreshes(&self) -> watch::Receiver<u64> {
        self.refresh_tx.subscribe()
    }

    fn notify_refreshed(&self) {
        let current = *self.refresh_tx.borrow();
        let _ = self.refresh_tx.send(current.wrapping_add(1));
    }
}

#[derive(Debug)]
pub struct TokenAnchorRefreshHandle {
    wake_tx: watch::Sender<u64>,
    abort_handle: AbortHandle,
}

impl TokenAnchorRefreshHandle {
    pub fn wake(&self) {
        let current = *self.wake_tx.borrow();
        let _ = self.wake_tx.send(current.wrapping_add(1));
    }
}

impl Drop for TokenAnchorRefreshHandle {
    fn drop(&mut self) {
        self.abort_handle.abort();
    }
}

#[must_use]
pub fn spawn_token_anchor_refresh_worker(
    runtime: &Handle,
    cache: Arc<TokenAnchorRateCache>,
    chain_ids: Vec<u64>,
    effective_chains: BTreeMap<u64, EffectiveChainConfig>,
    token_registry: EffectiveTokenRegistry,
    http: HttpContext,
) -> TokenAnchorRefreshHandle {
    let (wake_tx, wake_rx) = watch::channel(0_u64);
    let task = runtime.spawn(run_token_anchor_refresh_worker(
        cache,
        chain_ids,
        effective_chains,
        token_registry,
        http,
        wake_rx,
    ));
    TokenAnchorRefreshHandle {
        wake_tx,
        abort_handle: task.abort_handle(),
    }
}

async fn run_token_anchor_refresh_worker(
    cache: Arc<TokenAnchorRateCache>,
    chain_ids: Vec<u64>,
    effective_chains: BTreeMap<u64, EffectiveChainConfig>,
    token_registry: EffectiveTokenRegistry,
    http: HttpContext,
    mut wake_rx: watch::Receiver<u64>,
) {
    refresh_token_anchor_rates(
        &cache,
        &chain_ids,
        &effective_chains,
        &token_registry,
        &http,
    )
    .await;
    let mut last_refresh = Instant::now();

    let mut refresh_interval = interval(TOKEN_ANCHOR_REFRESH_INTERVAL);
    refresh_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    refresh_interval.tick().await;
    loop {
        tokio::select! {
            _ = refresh_interval.tick() => {
                refresh_token_anchor_rates(&cache, &chain_ids, &effective_chains, &token_registry, &http).await;
                last_refresh = Instant::now();
            }
            changed = wake_rx.changed() => {
                if changed.is_err() {
                    break;
                }
                if last_refresh.elapsed() >= TOKEN_ANCHOR_WAKE_REFRESH_MIN_INTERVAL {
                    refresh_token_anchor_rates(&cache, &chain_ids, &effective_chains, &token_registry, &http).await;
                    last_refresh = Instant::now();
                }
            }
        }
    }
}

pub async fn refresh_token_anchor_rates(
    cache: &TokenAnchorRateCache,
    chain_ids: &[u64],
    effective_chains: &BTreeMap<u64, EffectiveChainConfig>,
    token_registry: &EffectiveTokenRegistry,
    http: &HttpContext,
) {
    let mut entries_by_chain: BTreeMap<u64, Vec<RuntimeTokenAnchorInfo>> = BTreeMap::new();
    for entry in token_anchor_entries_for_chains(chain_ids, token_registry) {
        entries_by_chain
            .entry(entry.chain_id)
            .or_default()
            .push(entry);
    }
    let mut native_entries_by_chain: BTreeMap<u64, Vec<RuntimeNativeUsdAnchorInfo>> =
        BTreeMap::new();
    for entry in native_usd_anchor_entries_for_chains(chain_ids) {
        native_entries_by_chain
            .entry(entry.chain_id)
            .or_default()
            .push(entry);
    }

    let refresh_chain_ids = entries_by_chain
        .keys()
        .chain(native_entries_by_chain.keys())
        .copied()
        .collect::<BTreeSet<_>>();
    for chain_id in refresh_chain_ids {
        let entries = entries_by_chain.remove(&chain_id).unwrap_or_default();
        let native_entries = native_entries_by_chain
            .remove(&chain_id)
            .unwrap_or_default();
        refresh_token_anchor_rates_for_chain(
            cache,
            chain_id,
            &entries,
            &native_entries,
            effective_chains,
            http,
        )
        .await;
    }
    cache.notify_refreshed();
}

async fn refresh_token_anchor_rates_for_chain(
    cache: &TokenAnchorRateCache,
    chain_id: u64,
    entries: &[RuntimeTokenAnchorInfo],
    native_entries: &[RuntimeNativeUsdAnchorInfo],
    effective_chains: &BTreeMap<u64, EffectiveChainConfig>,
    http: &HttpContext,
) {
    let oracle_addresses_by_chain =
        oracle_addresses_for_token_and_native_entries(entries, native_entries);
    let mut oracle_answers = BTreeMap::new();
    for (oracle_chain_id, oracle_addresses) in oracle_addresses_by_chain {
        match fetch_oracle_answers_for_chain(
            oracle_chain_id,
            &oracle_addresses,
            effective_chains,
            http,
        )
        .await
        {
            Ok(answers) => {
                for (oracle_address, answer) in answers {
                    oracle_answers.insert((oracle_chain_id, oracle_address), answer);
                }
            }
            Err(error) => {
                tracing::warn!(chain_id, oracle_chain_id, %error, "failed to refresh token anchor oracles");
            }
        }
    }
    store_anchor_rates_from_entries(cache, entries, &oracle_answers);
    store_native_usd_rates_from_entries(cache, native_entries, &oracle_answers);
}

async fn fetch_oracle_answers_for_chain(
    chain_id: u64,
    oracle_addresses: &[Address],
    effective_chains: &BTreeMap<u64, EffectiveChainConfig>,
    http: &HttpContext,
) -> Result<BTreeMap<Address, U256>> {
    let (query_rpc_pool, multicall_addr) = provider_for_chain(chain_id, effective_chains, http)?;
    let mut last_error = None;
    let mut results = None;
    for _ in 0..query_rpc_pool.len() {
        let Some(provider_handle) = query_rpc_pool.random_provider() else {
            break;
        };
        let mut multicall = provider_handle
            .provider
            .multicall()
            .dynamic::<AggregatorInterface::latestAnswerCall>()
            .address(multicall_addr);
        for oracle_address in oracle_addresses {
            multicall = multicall.add_call_dynamic(CallItem::new(
                *oracle_address,
                AggregatorInterface::latestAnswerCall {}.abi_encode().into(),
            ));
        }

        match multicall.try_aggregate(false).await {
            Ok(values) => {
                results = Some(values);
                break;
            }
            Err(error) => {
                tracing::warn!(chain_id, %error, rpc = %provider_handle.url, "multicall anchor oracle answers failed");
                query_rpc_pool.mark_bad_provider(&provider_handle);
                last_error = Some(eyre::eyre!("{error}"));
            }
        }
    }
    let results = results.ok_or_else(|| {
        last_error.map_or_else(
            || eyre::eyre!("no healthy query RPC available for chain {chain_id}"),
            |error| error.wrap_err("multicall anchor oracle answers"),
        )
    })?;
    let mut answers = BTreeMap::new();
    for (oracle_address, result) in oracle_addresses.iter().copied().zip(results) {
        match result {
            Ok(answer) => match U256::try_from(answer) {
                Ok(price) if !price.is_zero() => {
                    answers.insert(oracle_address, price);
                }
                Ok(_) => {}
                Err(_) => {
                    tracing::warn!(chain_id, ?oracle_address, %answer, "discarding negative anchor oracle answer");
                }
            },
            Err(error) => {
                tracing::warn!(chain_id, ?oracle_address, %error, "discarding failed anchor oracle call");
            }
        }
    }
    Ok(answers)
}

fn provider_for_chain(
    chain_id: u64,
    effective_chains: &BTreeMap<u64, EffectiveChainConfig>,
    http: &HttpContext,
) -> Result<(Arc<QueryRpcPool>, Address)> {
    let defaults = ChainConfigDefaults::for_chain(chain_id)
        .ok_or_else(|| eyre::eyre!("unsupported chain id {chain_id}"))?;
    let effective_chain = effective_chains.get(&chain_id);
    let rpc_urls = effective_rpc_urls_for_chain(&defaults, effective_chain)?;
    let multicall_contract = if let Some(effective_chain) = effective_chain {
        Address::from_str(&effective_chain.multicall_contract)
            .wrap_err("parse effective multicall contract")?
    } else {
        defaults.multicall_contract
    };
    Ok((
        query_rpc_pool_with_http_client(rpc_urls, http),
        multicall_contract,
    ))
}

fn token_anchor_entries_for_chains(
    chain_ids: &[u64],
    token_registry: &EffectiveTokenRegistry,
) -> Vec<RuntimeTokenAnchorInfo> {
    let chain_ids = chain_ids.iter().copied().collect::<BTreeSet<_>>();
    let registry_tokens = token_registry
        .tokens
        .values()
        .filter(|token| chain_ids.contains(&token.chain_id))
        .filter_map(|token| {
            Address::from_str(&token.token_address)
                .ok()
                .map(|address| ((token.chain_id, address), token.price_anchor.as_ref()))
        })
        .collect::<BTreeMap<_, _>>();
    let mut entries = token_anchor_entries()
        .filter(|entry| chain_ids.contains(&entry.chain_id))
        .filter(|entry| registry_tokens.contains_key(&(entry.chain_id, entry.token)))
        .map(static_anchor_entry_to_runtime)
        .collect::<BTreeMap<_, _>>();
    for ((chain_id, token), anchor) in registry_tokens {
        if let Some(anchor) = anchor.and_then(price_anchor_to_runtime_sources) {
            entries.insert(
                (chain_id, token),
                RuntimeTokenAnchorInfo {
                    chain_id,
                    token,
                    anchor_sources: anchor,
                },
            );
        }
    }
    entries.into_values().collect()
}

fn static_anchor_entry_to_runtime(
    entry: TokenAnchorInfo,
) -> ((u64, Address), RuntimeTokenAnchorInfo) {
    (
        (entry.chain_id, entry.token),
        RuntimeTokenAnchorInfo {
            chain_id: entry.chain_id,
            token: entry.token,
            anchor_sources: entry
                .anchor_sources
                .iter()
                .map(|source| static_anchor_source_to_runtime(entry.chain_id, source))
                .collect(),
        },
    )
}

fn native_usd_anchor_entries_for_chains(chain_ids: &[u64]) -> Vec<RuntimeNativeUsdAnchorInfo> {
    let chain_ids = chain_ids.iter().copied().collect::<BTreeSet<_>>();
    native_usd_anchor_entries()
        .filter(|entry| chain_ids.contains(&entry.chain_id))
        .map(static_native_usd_entry_to_runtime)
        .collect()
}

fn static_native_usd_entry_to_runtime(entry: NativeUsdAnchorInfo) -> RuntimeNativeUsdAnchorInfo {
    RuntimeNativeUsdAnchorInfo {
        chain_id: entry.chain_id,
        anchor_sources: entry
            .anchor_sources
            .iter()
            .map(|source| static_anchor_source_to_runtime(entry.chain_id, source))
            .collect(),
    }
}

fn static_anchor_source_to_runtime(
    chain_id: u64,
    source: &TokenAnchorSource,
) -> RuntimeTokenAnchorSource {
    match source {
        TokenAnchorSource::Fixed {
            token_fee_per_unit_gas,
        } => RuntimeTokenAnchorSource::Fixed {
            token_fee_per_unit_gas: *token_fee_per_unit_gas,
        },
        TokenAnchorSource::ChainlinkOracle {
            addr,
            token_decimals,
            oracle_decimals,
            is_inversed,
        } => RuntimeTokenAnchorSource::ChainlinkOracle {
            chain_id,
            addr: *addr,
            token_decimals: *token_decimals,
            oracle_decimals: *oracle_decimals,
            is_inversed: *is_inversed,
        },
        TokenAnchorSource::Product {
            sources,
            scale_decimals,
        } => RuntimeTokenAnchorSource::Product {
            sources: sources
                .iter()
                .map(|source| static_anchor_source_to_runtime(chain_id, source))
                .collect(),
            scale_decimals: *scale_decimals,
        },
    }
}

fn price_anchor_to_runtime_sources(
    anchor: &PriceAnchorSettings,
) -> Option<Vec<RuntimeTokenAnchorSource>> {
    Some(vec![price_anchor_to_runtime_source(anchor)?])
}

fn price_anchor_to_runtime_source(
    anchor: &PriceAnchorSettings,
) -> Option<RuntimeTokenAnchorSource> {
    match anchor {
        PriceAnchorSettings::Fixed { rate } => Some(RuntimeTokenAnchorSource::Fixed {
            token_fee_per_unit_gas: U256::from_str_radix(rate, 10).ok()?,
        }),
        PriceAnchorSettings::Oracle {
            chain_id,
            oracle_address,
            token_decimals,
            oracle_decimals,
            is_inversed,
        } => Some(RuntimeTokenAnchorSource::ChainlinkOracle {
            chain_id: *chain_id,
            addr: Address::from_str(oracle_address).ok()?,
            token_decimals: *token_decimals,
            oracle_decimals: *oracle_decimals,
            is_inversed: *is_inversed,
        }),
        PriceAnchorSettings::Product {
            components,
            scale_decimals,
        } => Some(RuntimeTokenAnchorSource::Product {
            sources: components
                .iter()
                .map(price_anchor_to_runtime_source)
                .collect::<Option<Vec<_>>>()?,
            scale_decimals: *scale_decimals,
        }),
    }
}

#[cfg(test)]
fn oracle_addresses_for_entries(entries: &[RuntimeTokenAnchorInfo]) -> BTreeMap<u64, Vec<Address>> {
    let mut addresses: BTreeMap<u64, BTreeSet<Address>> = BTreeMap::new();
    for entry in entries {
        for source in &entry.anchor_sources {
            collect_oracle_addresses_from_source(source, &mut addresses);
        }
    }
    addresses
        .into_iter()
        .map(|(chain_id, addresses)| (chain_id, addresses.into_iter().collect()))
        .collect()
}

fn oracle_addresses_for_token_and_native_entries(
    entries: &[RuntimeTokenAnchorInfo],
    native_entries: &[RuntimeNativeUsdAnchorInfo],
) -> BTreeMap<u64, Vec<Address>> {
    let mut addresses: BTreeMap<u64, BTreeSet<Address>> = BTreeMap::new();
    for entry in entries {
        for source in &entry.anchor_sources {
            collect_oracle_addresses_from_source(source, &mut addresses);
        }
    }
    for entry in native_entries {
        for source in &entry.anchor_sources {
            collect_oracle_addresses_from_source(source, &mut addresses);
        }
    }
    addresses
        .into_iter()
        .map(|(chain_id, addresses)| (chain_id, addresses.into_iter().collect()))
        .collect()
}

fn collect_oracle_addresses_from_source(
    source: &RuntimeTokenAnchorSource,
    addresses: &mut BTreeMap<u64, BTreeSet<Address>>,
) {
    match source {
        RuntimeTokenAnchorSource::Fixed { .. } => {}
        RuntimeTokenAnchorSource::ChainlinkOracle { chain_id, addr, .. } => {
            addresses.entry(*chain_id).or_default().insert(*addr);
        }
        RuntimeTokenAnchorSource::Product { sources, .. } => {
            for source in sources {
                collect_oracle_addresses_from_source(source, addresses);
            }
        }
    }
}

fn store_anchor_rates_from_entries(
    cache: &TokenAnchorRateCache,
    entries: &[RuntimeTokenAnchorInfo],
    oracle_answers: &BTreeMap<(u64, Address), U256>,
) {
    for entry in entries {
        let rates = anchor_rates_from_sources(&entry.anchor_sources, oracle_answers);
        if let Some(rate) = average_non_outlier_anchor_rates(&rates) {
            cache.store_rate(entry.chain_id, entry.token, rate);
        }
    }
}

fn store_native_usd_rates_from_entries(
    cache: &TokenAnchorRateCache,
    entries: &[RuntimeNativeUsdAnchorInfo],
    oracle_answers: &BTreeMap<(u64, Address), U256>,
) {
    for entry in entries {
        let rates = anchor_rates_from_sources(&entry.anchor_sources, oracle_answers);
        if let Some(rate) = average_non_outlier_anchor_rates(&rates) {
            cache.store_native_usd_rate(entry.chain_id, rate);
        }
    }
}

fn anchor_rates_from_sources(
    sources: &[RuntimeTokenAnchorSource],
    oracle_answers: &BTreeMap<(u64, Address), U256>,
) -> Vec<U256> {
    sources
        .iter()
        .filter_map(|source| anchor_rate_from_source(source, oracle_answers))
        .collect()
}

fn anchor_rate_from_source(
    source: &RuntimeTokenAnchorSource,
    oracle_answers: &BTreeMap<(u64, Address), U256>,
) -> Option<U256> {
    match source {
        RuntimeTokenAnchorSource::Fixed {
            token_fee_per_unit_gas,
        } => non_zero_rate(*token_fee_per_unit_gas),
        RuntimeTokenAnchorSource::ChainlinkOracle {
            chain_id,
            addr,
            token_decimals,
            oracle_decimals,
            is_inversed,
        } => oracle_answers.get(&(*chain_id, *addr)).and_then(|price| {
            oracle_answer_to_anchor_rate(*price, *token_decimals, *oracle_decimals, *is_inversed)
        }),
        RuntimeTokenAnchorSource::Product {
            sources,
            scale_decimals,
        } => product_anchor_rate(sources, *scale_decimals, oracle_answers),
    }
}

fn product_anchor_rate(
    sources: &[RuntimeTokenAnchorSource],
    scale_decimals: u8,
    oracle_answers: &BTreeMap<(u64, Address), U256>,
) -> Option<U256> {
    let scale = checked_pow10(scale_decimals)?;
    let mut rates = sources
        .iter()
        .map(|source| anchor_rate_from_source(source, oracle_answers));
    let mut product = rates.next()??;
    for rate in rates {
        product = product.checked_mul(rate?)?.checked_div(scale)?;
    }
    non_zero_rate(product)
}

#[must_use]
pub fn known_token_anchor_sources(
    chain_id: u64,
    token: Address,
) -> Option<&'static [TokenAnchorSource]> {
    lookup_token(chain_id, &token).map(|info| info.anchor_sources)
}

#[must_use]
pub fn fixed_token_anchor_rate(chain_id: u64, token: Address) -> Option<U256> {
    known_token_anchor_sources(chain_id, token)?
        .iter()
        .find_map(|source| match source {
            TokenAnchorSource::Fixed {
                token_fee_per_unit_gas,
            } => Some(*token_fee_per_unit_gas),
            TokenAnchorSource::ChainlinkOracle { .. } | TokenAnchorSource::Product { .. } => None,
        })
}

#[must_use]
pub fn oracle_answer_to_anchor_rate(
    price: U256,
    token_decimals: u8,
    oracle_decimals: u8,
    is_inversed: bool,
) -> Option<U256> {
    if price.is_zero() {
        return None;
    }
    let token_scale = checked_pow10(token_decimals)?;
    let oracle_scale = checked_pow10(oracle_decimals)?;
    let rate = if is_inversed {
        token_scale.checked_mul(oracle_scale)?.checked_div(price)?
    } else {
        price.checked_mul(token_scale)?.checked_div(oracle_scale)?
    };
    non_zero_rate(rate)
}

#[must_use]
pub fn average_non_outlier_anchor_rates(rates: &[U256]) -> Option<U256> {
    let mut sorted = rates
        .iter()
        .copied()
        .filter(|rate| !rate.is_zero())
        .collect::<Vec<_>>();
    if sorted.is_empty() {
        return None;
    }
    sorted.sort_unstable();
    let median = median_rate(&sorted)?;
    if median.is_zero() {
        return None;
    }
    let survivors = sorted
        .into_iter()
        .filter(|rate| within_outlier_threshold(*rate, median))
        .collect::<Vec<_>>();
    checked_average(&survivors)
}

fn median_rate(sorted: &[U256]) -> Option<U256> {
    match sorted.len() {
        0 => None,
        len if len % 2 == 1 => Some(sorted[len / 2]),
        len => Some(checked_average_pair(sorted[len / 2 - 1], sorted[len / 2])),
    }
}

fn checked_average_pair(a: U256, b: U256) -> U256 {
    let half = a / U256::from(2) + b / U256::from(2);
    half + U256::from(u8::from(
        a % U256::from(2) + b % U256::from(2) >= U256::from(2),
    ))
}

fn within_outlier_threshold(rate: U256, median: U256) -> bool {
    let diff = match rate.cmp(&median) {
        Ordering::Less => median - rate,
        Ordering::Equal => return true,
        Ordering::Greater => rate - median,
    };
    let Some(scaled_diff) = diff.checked_mul(BPS_DENOMINATOR) else {
        return false;
    };
    let Some(threshold) = median.checked_mul(ANCHOR_OUTLIER_THRESHOLD_BPS) else {
        return false;
    };
    scaled_diff <= threshold
}

fn checked_average(rates: &[U256]) -> Option<U256> {
    if rates.is_empty() {
        return None;
    }
    let total = rates
        .iter()
        .copied()
        .try_fold(U256::ZERO, U256::checked_add)?;
    non_zero_rate(total / U256::from(rates.len()))
}

fn checked_pow10(exp: u8) -> Option<U256> {
    U256::from(10).checked_pow(U256::from(exp))
}

fn non_zero_rate(rate: U256) -> Option<U256> {
    if rate.is_zero() { None } else { Some(rate) }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::address;
    use alloy::uint;
    use railgun_ui::WRAPPED_NATIVE_FEE_RATE;

    use super::*;

    const SHARED_ORACLE_SOURCE_6: &[TokenAnchorSource] = &[TokenAnchorSource::ChainlinkOracle {
        addr: address!("0x0000000000000000000000000000000000000100"),
        token_decimals: 6,
        oracle_decimals: 8,
        is_inversed: false,
    }];
    const SHARED_ORACLE_SOURCE_18: &[TokenAnchorSource] = &[TokenAnchorSource::ChainlinkOracle {
        addr: address!("0x0000000000000000000000000000000000000100"),
        token_decimals: 18,
        oracle_decimals: 8,
        is_inversed: false,
    }];
    const ETH_USD_18_SOURCE: TokenAnchorSource = TokenAnchorSource::ChainlinkOracle {
        addr: address!("0x0000000000000000000000000000000000000200"),
        token_decimals: 18,
        oracle_decimals: 8,
        is_inversed: false,
    };
    const ARB_USD_INVERSE_18_SOURCE: TokenAnchorSource = TokenAnchorSource::ChainlinkOracle {
        addr: address!("0x0000000000000000000000000000000000000300"),
        token_decimals: 18,
        oracle_decimals: 8,
        is_inversed: true,
    };
    const ARB_PER_ETH_PRODUCT_SOURCES: &[TokenAnchorSource] =
        &[ETH_USD_18_SOURCE, ARB_USD_INVERSE_18_SOURCE];
    const ARB_PER_ETH_ANCHOR_SOURCE: &[TokenAnchorSource] = &[TokenAnchorSource::Product {
        sources: ARB_PER_ETH_PRODUCT_SOURCES,
        scale_decimals: 18,
    }];

    fn runtime_sources(sources: &[TokenAnchorSource]) -> Vec<RuntimeTokenAnchorSource> {
        sources
            .iter()
            .map(|source| static_anchor_source_to_runtime(1, source))
            .collect()
    }

    #[test]
    fn fixed_anchor_source_uses_wrapped_native_rate() {
        assert_eq!(
            non_zero_rate(WRAPPED_NATIVE_FEE_RATE),
            Some(uint!(1_000_000_000_000_000_000_U256))
        );
    }

    #[test]
    fn oracle_answer_to_anchor_rate_handles_non_inverted_feed() {
        let rate =
            oracle_answer_to_anchor_rate(uint!(3_000_00000000_U256), 6, 8, false).expect("rate");

        assert_eq!(rate, uint!(3_000_000_000_U256));
    }

    #[test]
    fn oracle_answer_to_anchor_rate_handles_inverted_feed() {
        let rate =
            oracle_answer_to_anchor_rate(uint!(15_000_000_000_000_000_000_U256), 8, 18, true)
                .expect("rate");

        assert_eq!(rate, uint!(6_666_666_U256));
    }

    #[test]
    fn oracle_answer_discards_non_sensible_values() {
        assert_eq!(oracle_answer_to_anchor_rate(U256::ZERO, 6, 8, false), None);
        assert_eq!(oracle_answer_to_anchor_rate(U256::ONE, 0, 8, false), None);
        assert_eq!(oracle_answer_to_anchor_rate(U256::MAX, 18, 0, false), None);
    }

    #[test]
    fn average_non_outlier_anchor_rates_averages_agreeing_sources() {
        let rates = [uint!(100_U256), uint!(110_U256), uint!(105_U256)];

        assert_eq!(
            average_non_outlier_anchor_rates(&rates),
            Some(uint!(105_U256))
        );
    }

    #[test]
    fn average_non_outlier_anchor_rates_rejects_large_outlier() {
        let rates = [uint!(100_U256), uint!(105_U256), uint!(1_000_U256)];

        assert_eq!(
            average_non_outlier_anchor_rates(&rates),
            Some(uint!(102_U256))
        );
    }

    #[test]
    fn average_non_outlier_anchor_rates_returns_none_without_survivors() {
        let rates = [uint!(100_U256), uint!(1_000_U256)];

        assert_eq!(average_non_outlier_anchor_rates(&rates), None);
    }

    #[test]
    fn cache_keeps_stale_rate_when_refresh_has_no_usable_value() {
        let cache = TokenAnchorRateCache::new();
        let token = address!("0x0000000000000000000000000000000000000001");
        let entry = RuntimeTokenAnchorInfo {
            chain_id: 1,
            token,
            anchor_sources: runtime_sources(SHARED_ORACLE_SOURCE_6),
        };
        cache.store_rate(1, token, uint!(123_U256));

        store_anchor_rates_from_entries(&cache, &[entry], &BTreeMap::new());

        assert_eq!(cache.cached_rate(1, token), Some(uint!(123_U256)));
        assert_eq!(
            cache.cached_rate(1, address!("0x0000000000000000000000000000000000000002")),
            None
        );
    }

    #[test]
    fn cache_stores_native_usd_rates_by_chain() {
        let cache = TokenAnchorRateCache::new();

        cache.store_native_usd_rate(1, U256::ZERO);
        assert_eq!(cache.cached_native_usd_rate(1), None);

        cache.store_native_usd_rate(1, uint!(3_000_000_000_U256));

        assert_eq!(
            cache.cached_native_usd_rate(1),
            Some(uint!(3_000_000_000_U256))
        );
        assert_eq!(cache.cached_native_usd_rate(56), None);
    }

    #[test]
    fn native_usd_rates_store_from_oracle_answers() {
        let cache = TokenAnchorRateCache::new();
        let entry = RuntimeNativeUsdAnchorInfo {
            chain_id: 1,
            anchor_sources: runtime_sources(SHARED_ORACLE_SOURCE_6),
        };
        let mut answers = BTreeMap::new();
        answers.insert(
            (1, address!("0x0000000000000000000000000000000000000100")),
            uint!(3_000_00000000_U256),
        );

        store_native_usd_rates_from_entries(&cache, &[entry], &answers);

        assert_eq!(
            cache.cached_native_usd_rate(1),
            Some(uint!(3_000_000_000_U256))
        );
    }

    #[test]
    fn cache_refresh_notifications_increment_generation() {
        let cache = TokenAnchorRateCache::new();
        let mut refresh_rx = cache.subscribe_refreshes();

        assert_eq!(*refresh_rx.borrow_and_update(), 0);

        cache.notify_refreshed();

        assert!(refresh_rx.has_changed().expect("watch channel open"));
        assert_eq!(*refresh_rx.borrow_and_update(), 1);
    }

    #[test]
    fn oracle_addresses_for_entries_deduplicates_shared_sources() {
        let entries = [
            RuntimeTokenAnchorInfo {
                chain_id: 1,
                token: address!("0x0000000000000000000000000000000000000001"),
                anchor_sources: runtime_sources(SHARED_ORACLE_SOURCE_6),
            },
            RuntimeTokenAnchorInfo {
                chain_id: 1,
                token: address!("0x0000000000000000000000000000000000000002"),
                anchor_sources: runtime_sources(SHARED_ORACLE_SOURCE_18),
            },
            RuntimeTokenAnchorInfo {
                chain_id: 1,
                token: address!("0x0000000000000000000000000000000000000003"),
                anchor_sources: runtime_sources(ARB_PER_ETH_ANCHOR_SOURCE),
            },
        ];

        assert_eq!(
            oracle_addresses_for_entries(&entries),
            BTreeMap::from([(
                1,
                vec![
                    address!("0x0000000000000000000000000000000000000100"),
                    address!("0x0000000000000000000000000000000000000200"),
                    address!("0x0000000000000000000000000000000000000300"),
                ],
            )])
        );
    }

    #[test]
    fn token_anchor_entries_apply_effective_registry_overrides() {
        let mut settings = crate::settings::WalletSettings::default();
        let weth = address!("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2");
        let custom = address!("0x0000000000000000000000000000000000000002");
        settings
            .tokens
            .built_in_tombstones
            .push(crate::settings::TokenKey {
                chain_id: 1,
                token_address: weth.to_string(),
            });
        settings
            .tokens
            .custom_tokens
            .push(crate::settings::CustomTokenSettings {
                chain_id: 1,
                token_address: custom.to_string(),
                symbol: "CSTM".to_string(),
                decimals: 18,
                icon_path: None,
                price_anchor: Some(crate::settings::PriceAnchorSettings::Oracle {
                    chain_id: 42161,
                    oracle_address: "0x0000000000000000000000000000000000000100".to_string(),
                    token_decimals: 18,
                    oracle_decimals: 8,
                    is_inversed: false,
                }),
            });
        let registry = crate::settings::build_effective_token_registry(&settings)
            .expect("effective token registry");

        let entries = token_anchor_entries_for_chains(&[1], &registry);

        assert!(!entries.iter().any(|entry| entry.token == weth));
        let custom_entry = entries
            .iter()
            .find(|entry| entry.token == custom)
            .expect("custom anchor entry");
        let oracle_addresses = oracle_addresses_for_entries(std::slice::from_ref(custom_entry));
        assert_eq!(
            oracle_addresses,
            BTreeMap::from([(
                42161,
                vec![address!("0x0000000000000000000000000000000000000100")],
            )])
        );
    }

    #[test]
    fn anchor_rates_from_sources_reuses_oracle_answer() {
        let mut answers = BTreeMap::new();
        answers.insert(
            (1, address!("0x0000000000000000000000000000000000000100")),
            uint!(3_000_00000000_U256),
        );

        assert_eq!(
            anchor_rates_from_sources(&runtime_sources(SHARED_ORACLE_SOURCE_6), &answers),
            vec![uint!(3_000_000_000_U256)]
        );
        assert_eq!(
            anchor_rates_from_sources(&runtime_sources(SHARED_ORACLE_SOURCE_18), &answers),
            vec![uint!(3_000_000_000_000_000_000_000_U256)]
        );
    }

    #[test]
    fn anchor_rates_from_sources_composes_arb_per_eth_anchor() {
        let mut answers = BTreeMap::new();
        answers.insert(
            (1, address!("0x0000000000000000000000000000000000000200")),
            uint!(3_000_00000000_U256),
        );
        answers.insert(
            (1, address!("0x0000000000000000000000000000000000000300")),
            uint!(70_000000_U256),
        );

        assert_eq!(
            anchor_rates_from_sources(&runtime_sources(ARB_PER_ETH_ANCHOR_SOURCE), &answers),
            vec![uint!(4_285_714_285_714_285_713_000_U256)]
        );
    }

    #[test]
    fn anchor_rates_from_sources_discards_composite_with_missing_component() {
        let mut answers = BTreeMap::new();
        answers.insert(
            (1, address!("0x0000000000000000000000000000000000000200")),
            uint!(3_000_00000000_U256),
        );

        assert!(
            anchor_rates_from_sources(&runtime_sources(ARB_PER_ETH_ANCHOR_SOURCE), &answers)
                .is_empty()
        );
    }

    #[test]
    fn policy_classifies_cache_miss_as_allowed_unknown_anchor() {
        let policy = BroadcasterFeePolicy::default();
        let status = policy.classify_fee(uint!(1_501_U256), None);

        assert_eq!(status, BroadcasterFeePolicyStatus::UnknownAnchor);
        assert!(policy.allows_status(status));
    }

    #[test]
    fn policy_classifies_fee_bounds_and_unknown_anchor() {
        let policy = BroadcasterFeePolicy::default();
        let anchor = uint!(1_000_U256);

        assert!(
            policy
                .classify_fee(uint!(899_U256), Some(anchor))
                .is_suspicious()
        );
        assert!(
            !policy
                .classify_fee(uint!(900_U256), Some(anchor))
                .is_suspicious()
        );
        assert!(
            !policy
                .classify_fee(uint!(1_500_U256), Some(anchor))
                .is_suspicious()
        );
        assert!(
            policy
                .classify_fee(uint!(1_501_U256), Some(anchor))
                .is_suspicious()
        );
        assert_eq!(
            policy.classify_fee(uint!(1_501_U256), None),
            BroadcasterFeePolicyStatus::UnknownAnchor
        );
    }
}
