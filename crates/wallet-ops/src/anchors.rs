use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use alloy::primitives::{Address, U256};
use alloy::providers::{CallItem, Provider, ProviderBuilder};
use alloy::sol;
use alloy::sol_types::SolCall;
use alloy_provider::DynProvider;
use eyre::{Result, WrapErr};
use railgun_ui::{TokenAnchorInfo, TokenAnchorSource, lookup_token, token_anchor_entries};
use sync_service::ChainConfigDefaults;
use tokio::runtime::Handle;
use tokio::sync::watch;
use tokio::time::{Instant, MissedTickBehavior, interval};

use crate::HttpContext;

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

impl TokenAnchorKey {
    const fn new(chain_id: u64, token: Address) -> Self {
        Self { chain_id, token }
    }
}

#[derive(Debug, Default)]
pub struct TokenAnchorRateCache {
    rates: RwLock<BTreeMap<TokenAnchorKey, U256>>,
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
}

#[derive(Debug, Clone)]
pub struct TokenAnchorRefreshHandle {
    wake_tx: watch::Sender<u64>,
}

impl TokenAnchorRefreshHandle {
    pub fn wake(&self) {
        let current = *self.wake_tx.borrow();
        let _ = self.wake_tx.send(current.wrapping_add(1));
    }
}

#[must_use]
pub fn spawn_token_anchor_refresh_worker(
    runtime: &Handle,
    cache: Arc<TokenAnchorRateCache>,
    chain_ids: Vec<u64>,
    http: HttpContext,
) -> TokenAnchorRefreshHandle {
    let (wake_tx, wake_rx) = watch::channel(0_u64);
    runtime.spawn(run_token_anchor_refresh_worker(
        cache, chain_ids, http, wake_rx,
    ));
    TokenAnchorRefreshHandle { wake_tx }
}

async fn run_token_anchor_refresh_worker(
    cache: Arc<TokenAnchorRateCache>,
    chain_ids: Vec<u64>,
    http: HttpContext,
    mut wake_rx: watch::Receiver<u64>,
) {
    refresh_token_anchor_rates(&cache, &chain_ids, &http).await;
    let mut last_refresh = Instant::now();

    let mut refresh_interval = interval(TOKEN_ANCHOR_REFRESH_INTERVAL);
    refresh_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    refresh_interval.tick().await;
    loop {
        tokio::select! {
            _ = refresh_interval.tick() => {
                refresh_token_anchor_rates(&cache, &chain_ids, &http).await;
                last_refresh = Instant::now();
            }
            changed = wake_rx.changed() => {
                if changed.is_err() {
                    break;
                }
                if last_refresh.elapsed() >= TOKEN_ANCHOR_WAKE_REFRESH_MIN_INTERVAL {
                    refresh_token_anchor_rates(&cache, &chain_ids, &http).await;
                    last_refresh = Instant::now();
                }
            }
        }
    }
}

pub async fn refresh_token_anchor_rates(
    cache: &TokenAnchorRateCache,
    chain_ids: &[u64],
    http: &HttpContext,
) {
    let mut entries_by_chain: BTreeMap<u64, Vec<TokenAnchorInfo>> = BTreeMap::new();
    for entry in token_anchor_entries_for_chains(chain_ids) {
        entries_by_chain
            .entry(entry.chain_id)
            .or_default()
            .push(entry);
    }

    for (chain_id, entries) in entries_by_chain {
        refresh_token_anchor_rates_for_chain(cache, chain_id, &entries, http).await;
    }
}

async fn refresh_token_anchor_rates_for_chain(
    cache: &TokenAnchorRateCache,
    chain_id: u64,
    entries: &[TokenAnchorInfo],
    http: &HttpContext,
) {
    let oracle_addresses = oracle_addresses_for_entries(entries);
    let oracle_answers = if oracle_addresses.is_empty() {
        BTreeMap::new()
    } else {
        match fetch_oracle_answers_for_chain(chain_id, &oracle_addresses, http).await {
            Ok(answers) => answers,
            Err(error) => {
                tracing::warn!(chain_id, %error, "failed to refresh token anchor oracles");
                BTreeMap::new()
            }
        }
    };
    store_anchor_rates_from_entries(cache, entries, &oracle_answers);
}

async fn fetch_oracle_answers_for_chain(
    chain_id: u64,
    oracle_addresses: &[Address],
    http: &HttpContext,
) -> Result<BTreeMap<Address, U256>> {
    let (provider, multicall_addr) = provider_for_chain(chain_id, http)?;
    let mut multicall = provider
        .multicall()
        .dynamic::<AggregatorInterface::latestAnswerCall>()
        .address(multicall_addr);
    for oracle_address in oracle_addresses {
        multicall = multicall.add_call_dynamic(CallItem::new(
            *oracle_address,
            AggregatorInterface::latestAnswerCall {}.abi_encode().into(),
        ));
    }

    let results = multicall
        .try_aggregate(false)
        .await
        .wrap_err("multicall anchor oracle answers")?;
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

fn provider_for_chain(chain_id: u64, http: &HttpContext) -> Result<(DynProvider, Address)> {
    let defaults = ChainConfigDefaults::for_chain(chain_id)
        .ok_or_else(|| eyre::eyre!("unsupported chain id {chain_id}"))?;
    let provider = ProviderBuilder::new()
        .connect_reqwest(http.client.clone(), defaults.rpc_url)
        .erased();
    Ok((provider, defaults.multicall_contract))
}

fn token_anchor_entries_for_chains(chain_ids: &[u64]) -> Vec<TokenAnchorInfo> {
    let chain_ids = chain_ids.iter().copied().collect::<BTreeSet<_>>();
    token_anchor_entries()
        .filter(|entry| chain_ids.contains(&entry.chain_id))
        .collect()
}

fn oracle_addresses_for_entries(entries: &[TokenAnchorInfo]) -> Vec<Address> {
    let mut addresses = BTreeSet::new();
    for entry in entries {
        for source in entry.anchor_sources {
            collect_oracle_addresses_from_source(source, &mut addresses);
        }
    }
    addresses.into_iter().collect()
}

fn collect_oracle_addresses_from_source(
    source: &TokenAnchorSource,
    addresses: &mut BTreeSet<Address>,
) {
    match source {
        TokenAnchorSource::Fixed { .. } => {}
        TokenAnchorSource::ChainlinkOracle { addr, .. } => {
            addresses.insert(*addr);
        }
        TokenAnchorSource::Product { sources, .. } => {
            for source in *sources {
                collect_oracle_addresses_from_source(source, addresses);
            }
        }
    }
}

fn store_anchor_rates_from_entries(
    cache: &TokenAnchorRateCache,
    entries: &[TokenAnchorInfo],
    oracle_answers: &BTreeMap<Address, U256>,
) {
    for entry in entries {
        let rates = anchor_rates_from_sources(entry.anchor_sources, oracle_answers);
        if let Some(rate) = average_non_outlier_anchor_rates(&rates) {
            cache.store_rate(entry.chain_id, entry.token, rate);
        }
    }
}

fn anchor_rates_from_sources(
    sources: &[TokenAnchorSource],
    oracle_answers: &BTreeMap<Address, U256>,
) -> Vec<U256> {
    sources
        .iter()
        .filter_map(|source| anchor_rate_from_source(source, oracle_answers))
        .collect()
}

fn anchor_rate_from_source(
    source: &TokenAnchorSource,
    oracle_answers: &BTreeMap<Address, U256>,
) -> Option<U256> {
    match *source {
        TokenAnchorSource::Fixed {
            token_fee_per_unit_gas,
        } => non_zero_rate(token_fee_per_unit_gas),
        TokenAnchorSource::ChainlinkOracle {
            addr,
            token_decimals,
            oracle_decimals,
            is_inversed,
        } => oracle_answers.get(&addr).and_then(|price| {
            oracle_answer_to_anchor_rate(*price, token_decimals, oracle_decimals, is_inversed)
        }),
        TokenAnchorSource::Product {
            sources,
            scale_decimals,
        } => product_anchor_rate(sources, scale_decimals, oracle_answers),
    }
}

fn product_anchor_rate(
    sources: &[TokenAnchorSource],
    scale_decimals: u8,
    oracle_answers: &BTreeMap<Address, U256>,
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
        let entry = TokenAnchorInfo {
            chain_id: 1,
            token,
            anchor_sources: SHARED_ORACLE_SOURCE_6,
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
    fn oracle_addresses_for_entries_deduplicates_shared_sources() {
        let entries = [
            TokenAnchorInfo {
                chain_id: 1,
                token: address!("0x0000000000000000000000000000000000000001"),
                anchor_sources: SHARED_ORACLE_SOURCE_6,
            },
            TokenAnchorInfo {
                chain_id: 1,
                token: address!("0x0000000000000000000000000000000000000002"),
                anchor_sources: SHARED_ORACLE_SOURCE_18,
            },
            TokenAnchorInfo {
                chain_id: 1,
                token: address!("0x0000000000000000000000000000000000000003"),
                anchor_sources: ARB_PER_ETH_ANCHOR_SOURCE,
            },
        ];

        assert_eq!(
            oracle_addresses_for_entries(&entries),
            vec![
                address!("0x0000000000000000000000000000000000000100"),
                address!("0x0000000000000000000000000000000000000200"),
                address!("0x0000000000000000000000000000000000000300"),
            ]
        );
    }

    #[test]
    fn anchor_rates_from_sources_reuses_oracle_answer() {
        let mut answers = BTreeMap::new();
        answers.insert(
            address!("0x0000000000000000000000000000000000000100"),
            uint!(3_000_00000000_U256),
        );

        assert_eq!(
            anchor_rates_from_sources(SHARED_ORACLE_SOURCE_6, &answers),
            vec![uint!(3_000_000_000_U256)]
        );
        assert_eq!(
            anchor_rates_from_sources(SHARED_ORACLE_SOURCE_18, &answers),
            vec![uint!(3_000_000_000_000_000_000_000_U256)]
        );
    }

    #[test]
    fn anchor_rates_from_sources_composes_arb_per_eth_anchor() {
        let mut answers = BTreeMap::new();
        answers.insert(
            address!("0x0000000000000000000000000000000000000200"),
            uint!(3_000_00000000_U256),
        );
        answers.insert(
            address!("0x0000000000000000000000000000000000000300"),
            uint!(70_000000_U256),
        );

        assert_eq!(
            anchor_rates_from_sources(ARB_PER_ETH_ANCHOR_SOURCE, &answers),
            vec![uint!(4_285_714_285_714_285_713_000_U256)]
        );
    }

    #[test]
    fn anchor_rates_from_sources_discards_composite_with_missing_component() {
        let mut answers = BTreeMap::new();
        answers.insert(
            address!("0x0000000000000000000000000000000000000200"),
            uint!(3_000_00000000_U256),
        );

        assert!(anchor_rates_from_sources(ARB_PER_ETH_ANCHOR_SOURCE, &answers).is_empty());
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
