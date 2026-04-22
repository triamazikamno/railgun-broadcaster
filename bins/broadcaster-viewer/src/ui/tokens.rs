//! Static registry of the tokens the broadcaster accepts fees in, plus
//! the display helpers the fees pane uses to render them.
//!
//! The table is mirrored verbatim from `config.example.yaml` `chains[].fees`
//! — `!Oracle` entries copy `token_decimals` exactly, `!Fixed` entries
//! default to 18 (all wrapped-native tokens). When operators run with a
//! different config we fall through to the raw-address / raw-integer
//! display, which is the signal to extend this list.

use alloy::primitives::{Address, address};
use ruint::aliases::U256;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct TokenInfo {
    pub(crate) symbol: &'static str,
    pub(crate) decimals: u8,
}

#[rustfmt::skip]
const TOKENS: &[(u64, Address, &str, u8)] = &[
    // Ethereum (1)
    (1, address!("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"), "WETH", 18),
    (1, address!("0xdAC17F958D2ee523a2206206994597C13D831ec7"), "USDT", 6),
    (1, address!("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"), "USDC", 6),
    (1, address!("0x6b175474e89094c44da98b954eedeac495271d0f"), "DAI", 18),
    (1, address!("0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599"), "WBTC", 8),
    (1, address!("0x1aBaEA1f7C830bD89Acc67eC4af516284b1bC33c"), "EURC", 6),
    (1, address!("0x6f40d4a6237c257fff2db00fa0510deeecd303eb"), "FLUID", 18),
    (1, address!("0xe76C6c83af64e4C60245D8C7dE953DF673a7A33D"), "RAIL", 18),
    (1, address!("0x03ab458634910aad20ef5f1c8ee96f1d6ac54919"), "RAI", 18),
    (1, address!("0x853d955aCEf822Db058eb8505911ED77F175b99e"), "FRAX", 18),
    (1, address!("0x956f47f50a910163d8bf957cf5846d573e7f87ca"), "FEI", 18),
    (1, address!("0xeb4c2781e4eba804ce9a9803c67d0893436bb27d"), "renBTC", 8),
    (1, address!("0x085780639CC2cACd35E474e71f4d000e2405d8f6"), "fxUSD", 18),
    // BSC (56)
    (56, address!("0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c"), "BNB", 18),
    (56, address!("0x55d398326f99059ff775485246999027b3197955"), "BSC-USD", 18),
    (56, address!("0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d"), "USDC", 18),
    (56, address!("0xe9e7cea3dedca5984780bafc599bd69add087d56"), "BUSD", 18),
    (56, address!("0x1af3f329e8be154074d8769d1ffa4ee058b1dbc3"), "DAI", 18),
    (56, address!("0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82"), "CAKE", 18),
    (56, address!("0x2170Ed0880ac9A755fd29B2688956BD959F933F8"), "ETH", 18),
    // Polygon (137)
    (137, address!("0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270"), "WMATIC", 18),
    (137, address!("0xc2132d05d31c914a87c6611c10748aeb04b58e8f"), "USDT", 6),
    (137, address!("0x2791bca1f2de4661ed88a30c99a7a9449aa84174"), "USDC.e", 6),
    (137, address!("0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359"), "USDC", 6),
    (137, address!("0x8f3cf7ad23cd3cadbd9735aff958023239c6a063"), "DAI", 18),
    (137, address!("0x1BFD67037B42Cf73acF2047067bd4F2C47D9BfD6"), "WBTC", 8),
    (137, address!("0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619"), "WETH", 18),
    // Arbitrum (42161)
    (42161, address!("0x82af49447d8a07e3bd95bd0d56f35241523fbab1"), "WETH", 18),
    (42161, address!("0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9"), "USDT", 6),
    (42161, address!("0xff970a61a04b1ca14834a43f5de4533ebddb5cc8"), "USDC.e", 6),
    (42161, address!("0xaf88d065e77c8cc2239327c5edb3a432268e5831"), "USDC", 6),
    (42161, address!("0xda10009cbd5d07dd0cecc66161fc93d7c9000da1"), "DAI", 18),
    (42161, address!("0x2f2a2543b76a4166549f7aab2e75bef0aefc5b0f"), "WBTC", 8),
    (42161, address!("0x912ce59144191c1204e64559fe8253a0e49e6548"), "ARB", 18),
    (42161, address!("0xFa7F8980b0f1E64A2062791cc3b0871572f1F7f0"), "UNI", 18),
    (42161, address!("0x17FC002b466eEc40DaE837Fc4bE5c67993ddBd6F"), "FRAX", 18),
    (42161, address!("0x4D15a3A2286D883AF0AA1B3f21367843FAc63E07"), "TUSD", 18),
];

pub(crate) fn lookup_token(chain_id: u64, addr: &Address) -> Option<TokenInfo> {
    TOKENS
        .iter()
        .find(|(c, a, _, _)| *c == chain_id && a == addr)
        .map(|(_, _, symbol, decimals)| TokenInfo {
            symbol,
            decimals: *decimals,
        })
}

/// Format a raw integer amount as a decimal string scaled by `decimals`,
/// trimming trailing zeros in the fractional part. No truncation — a 1
/// wei fee with 18 decimals renders as `"0.000000000000000001"`, so
/// operators can always spot dust without being misled by rounding.
pub(crate) fn format_token_amount(amount: U256, decimals: u8) -> String {
    if decimals == 0 {
        return amount.to_string();
    }
    let divisor = U256::from(10u8).pow(U256::from(decimals));
    let whole = amount / divisor;
    let frac = amount % divisor;
    let frac_str = frac.to_string();
    let padded = format!("{frac_str:0>width$}", width = decimals as usize);
    let trimmed = padded.trim_end_matches('0');
    if trimmed.is_empty() {
        whole.to_string()
    } else {
        format!("{whole}.{trimmed}")
    }
}

/// Shorten an address for the fallback display on unknown tokens.
/// Produces `"0xc02a…6cc2"` — 4 hex chars on each side, enough to
/// distinguish tokens without burning a full 42-char column.
pub(crate) fn short_address(addr: &Address) -> String {
    let hex = format!("{addr:#x}");
    format!("{}…{}", &hex[..6], &hex[38..])
}

/// Human-readable name for a chain id. Returns `None` for any chain outside
/// the default broadcaster set so callers can decide whether to fall back to
/// the numeric id.
#[must_use]
pub(crate) const fn chain_name(chain_id: u64) -> Option<&'static str> {
    match chain_id {
        1 => Some("Ethereum"),
        56 => Some("BSC"),
        137 => Some("Polygon"),
        42161 => Some("Arbitrum"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_handles_zero_decimals() {
        assert_eq!(format_token_amount(U256::from(123u64), 0), "123");
    }

    #[test]
    fn format_whole_number_trims_fraction() {
        // 1_000_000 with 6 decimals == 1.0 → "1"
        assert_eq!(format_token_amount(U256::from(1_000_000u64), 6), "1");
    }

    #[test]
    fn format_fractional_trims_trailing_zeros() {
        // 1_500_000 with 6 decimals == 1.5 → "1.5" (not "1.500000")
        assert_eq!(format_token_amount(U256::from(1_500_000u64), 6), "1.5");
    }

    #[test]
    fn format_zero_whole_pads_leading_fraction_zeros() {
        // 12_345 with 6 decimals == 0.012345
        assert_eq!(format_token_amount(U256::from(12_345u64), 6), "0.012345");
    }

    #[test]
    fn format_single_wei_at_18_decimals() {
        assert_eq!(
            format_token_amount(U256::from(1u64), 18),
            "0.000000000000000001"
        );
    }

    #[test]
    fn format_zero_amount() {
        assert_eq!(format_token_amount(U256::ZERO, 18), "0");
        assert_eq!(format_token_amount(U256::ZERO, 0), "0");
    }

    #[test]
    fn lookup_hits_ethereum_weth() {
        let addr = address!("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2");
        let info = lookup_token(1, &addr).expect("WETH on Ethereum should be known");
        assert_eq!(info.symbol, "WETH");
        assert_eq!(info.decimals, 18);
    }

    #[test]
    fn lookup_disambiguates_native_usdc_across_chains() {
        // The YAML lists native USDC on Arbitrum with 18 decimals — unusual
        // but that's what the broadcaster parses, so the viewer mirrors it.
        let arb_usdc = address!("0xaf88d065e77c8cc2239327c5edb3a432268e5831");
        let info = lookup_token(42161, &arb_usdc).expect("Arbitrum USDC present");
        assert_eq!(info.symbol, "USDC");
        assert_eq!(info.decimals, 6);

        // Same chain_id with a different address should miss.
        let bogus = address!("0x0000000000000000000000000000000000000001");
        assert!(lookup_token(42161, &bogus).is_none());
    }

    #[test]
    fn lookup_misses_unknown_chain() {
        let weth = address!("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2");
        // Optimism (10) isn't in the registry.
        assert!(lookup_token(10, &weth).is_none());
    }

    #[test]
    fn short_address_preserves_prefix_and_suffix() {
        let weth = address!("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2");
        assert_eq!(short_address(&weth), "0xc02a…6cc2");
    }

    #[test]
    fn chain_name_covers_default_set_and_misses_others() {
        assert_eq!(chain_name(1), Some("Ethereum"));
        assert_eq!(chain_name(56), Some("BSC"));
        assert_eq!(chain_name(137), Some("Polygon"));
        assert_eq!(chain_name(42161), Some("Arbitrum"));
        assert_eq!(chain_name(10), None);
        assert_eq!(chain_name(0), None);
    }
}
