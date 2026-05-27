use super::*;

#[test]
fn effective_token_registry_formats_private_and_public_assets() {
    let token = Address::from([0x88; 20]);
    let icon = "/tmp/custom-token.png";
    let mut settings = WalletSettings::default();
    settings.tokens.custom_tokens.push(CustomTokenSettings {
        chain_id: 1,
        token_address: token.to_string(),
        symbol: "TST".to_string(),
        decimals: 4,
        icon_path: Some(icon.to_string()),
        price_anchor: None,
    });
    let registry = build_effective_token_registry(&settings).expect("effective registry");
    let totals = [wallet_ops::TokenTotal {
        token: token.to_checksum(None),
        total: "12345".to_string(),
        poi_verified_total: "12345".to_string(),
    }];

    let rows = format_private_asset_rows(1, &totals, Some(&registry), None);

    assert_eq!(rows[0].label, "TST");
    assert_eq!(rows[0].amount, "1.23");
    assert_eq!(rows[0].decimals, Some(4));
    assert_eq!(
        rows[0]
            .icon_path
            .as_ref()
            .and_then(|path| path.as_file_path()),
        Some(std::path::Path::new(icon))
    );
    assert_eq!(
        public_asset_label(1, PublicAssetId::Erc20(token), Some(&registry)),
        "TST"
    );
    assert_eq!(
        public_asset_decimals(1, PublicAssetId::Erc20(token), Some(&registry)),
        Some(4)
    );
    assert_eq!(
        public_asset_icon_path(1, PublicAssetId::Erc20(token), Some(&registry))
            .as_ref()
            .and_then(|path| path.as_file_path()),
        Some(std::path::Path::new(icon))
    );
}

#[test]
fn private_asset_rows_use_totals_formatting() {
    let totals = [wallet_ops::TokenTotal {
        token: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
        total: "1234567".to_string(),
        poi_verified_total: "1000000".to_string(),
    }];

    let rows = format_private_asset_rows(1, &totals, None, None);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].label, "USDC");
    assert_eq!(rows[0].amount, "1.23");
    assert_eq!(rows[0].pending_poi_amount, "0.23457");
    assert_eq!(rows[0].pending_poi_total, Some(uint!(234_567_U256)));
    assert!(should_show_pending_poi_amount(rows[0].pending_poi_total));
    assert!(rows[0].icon_path.is_some());
}

#[test]
fn private_asset_rows_include_usd_when_cache_has_rates() {
    let usdc = address!("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
    let weth = address!("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2");
    let cache = TokenAnchorRateCache::new();
    cache.store_native_usd_rate(1, uint!(3_000_000_000_U256));
    cache.store_rate(1, usdc, uint!(3_000_000_000_U256));
    let totals = [
        wallet_ops::TokenTotal {
            token: usdc.to_checksum(None),
            total: "1234567".to_string(),
            poi_verified_total: "1234567".to_string(),
        },
        wallet_ops::TokenTotal {
            token: weth.to_checksum(None),
            total: "500000000000000000".to_string(),
            poi_verified_total: "500000000000000000".to_string(),
        },
    ];

    let rows = format_private_asset_rows(1, &totals, None, Some(&cache));

    assert_eq!(rows[0].usd_amount.as_deref(), Some("$1.23"));
    assert_eq!(rows[1].usd_amount.as_deref(), Some("$1,500.00"));
}

#[test]
fn private_asset_rows_from_snapshot_sort_by_usd_descending() {
    let rail = address!("0xe76C6c83af64e4C60245D8C7dE953DF673a7A33D");
    let usdc = address!("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
    let weth = address!("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2");
    let cache = TokenAnchorRateCache::new();
    cache.store_native_usd_rate(1, uint!(3_000_000_000_U256));
    cache.store_rate(1, usdc, uint!(3_000_000_000_U256));
    let snapshot = ListUtxosOutput {
        chain_id: 1,
        cache_key: "cache".to_string(),
        utxo_count: 0,
        unspent_count: 0,
        spent_count: 0,
        local_pending_spent_count: 0,
        utxos: Vec::new(),
        totals: vec![
            wallet_ops::TokenTotal {
                token: rail.to_checksum(None),
                total: "1000000000000000000".to_string(),
                poi_verified_total: "1000000000000000000".to_string(),
            },
            wallet_ops::TokenTotal {
                token: usdc.to_checksum(None),
                total: "1234567".to_string(),
                poi_verified_total: "1234567".to_string(),
            },
            wallet_ops::TokenTotal {
                token: weth.to_checksum(None),
                total: "500000000000000000".to_string(),
                poi_verified_total: "500000000000000000".to_string(),
            },
        ],
    };

    let rows = format_private_asset_rows_from_snapshot(&snapshot, None, Some(&cache));

    assert_eq!(
        rows.iter()
            .map(|row| row.label.as_str())
            .collect::<Vec<_>>(),
        ["WETH", "USDC", "RAIL"]
    );
    assert_eq!(rows[0].usd_amount.as_deref(), Some("$1,500.00"));
    assert_eq!(rows[1].usd_amount.as_deref(), Some("$1.23"));
    assert_eq!(rows[2].usd_amount, None);
}

#[test]
fn private_asset_rows_from_snapshot_preserve_equal_and_unpriced_order() {
    let usdc = address!("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
    let weth = address!("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2");
    let rail = address!("0xe76C6c83af64e4C60245D8C7dE953DF673a7A33D");
    let unknown = Address::from([0x99; 20]);
    let cache = TokenAnchorRateCache::new();
    cache.store_native_usd_rate(1, uint!(3_000_000_000_U256));
    cache.store_rate(1, usdc, uint!(3_000_000_000_U256));
    let snapshot = ListUtxosOutput {
        chain_id: 1,
        cache_key: "cache".to_string(),
        utxo_count: 0,
        unspent_count: 0,
        spent_count: 0,
        local_pending_spent_count: 0,
        utxos: Vec::new(),
        totals: vec![
            wallet_ops::TokenTotal {
                token: usdc.to_checksum(None),
                total: "1500000000".to_string(),
                poi_verified_total: "1500000000".to_string(),
            },
            wallet_ops::TokenTotal {
                token: weth.to_checksum(None),
                total: "500000000000000000".to_string(),
                poi_verified_total: "500000000000000000".to_string(),
            },
            wallet_ops::TokenTotal {
                token: rail.to_checksum(None),
                total: "1000000000000000000".to_string(),
                poi_verified_total: "1000000000000000000".to_string(),
            },
            wallet_ops::TokenTotal {
                token: unknown.to_checksum(None),
                total: "1".to_string(),
                poi_verified_total: "1".to_string(),
            },
        ],
    };

    let rows = format_private_asset_rows_from_snapshot(&snapshot, None, Some(&cache));

    assert_eq!(
        rows.iter()
            .map(|row| row.label.as_str())
            .collect::<Vec<_>>(),
        ["USDC", "WETH", "RAIL", "0x9999…9999"]
    );
    assert_eq!(rows[0].usd_amount.as_deref(), Some("$1,500.00"));
    assert_eq!(rows[1].usd_amount.as_deref(), Some("$1,500.00"));
    assert_eq!(rows[2].usd_amount, None);
    assert_eq!(rows[3].usd_amount, None);
}

#[test]
fn private_total_balance_sums_priced_assets() {
    let rail = address!("0xe76C6c83af64e4C60245D8C7dE953DF673a7A33D");
    let usdc = address!("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
    let weth = address!("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2");
    let cache = TokenAnchorRateCache::new();
    cache.store_native_usd_rate(1, uint!(3_000_000_000_U256));
    cache.store_rate(1, usdc, uint!(3_000_000_000_U256));
    let snapshot = ListUtxosOutput {
        chain_id: 1,
        cache_key: "cache".to_string(),
        utxo_count: 0,
        unspent_count: 0,
        spent_count: 0,
        local_pending_spent_count: 0,
        utxos: Vec::new(),
        totals: vec![
            wallet_ops::TokenTotal {
                token: usdc.to_checksum(None),
                total: "1234567".to_string(),
                poi_verified_total: "1234567".to_string(),
            },
            wallet_ops::TokenTotal {
                token: weth.to_checksum(None),
                total: "500000000000000000".to_string(),
                poi_verified_total: "500000000000000000".to_string(),
            },
            wallet_ops::TokenTotal {
                token: rail.to_checksum(None),
                total: "1000000000000000000".to_string(),
                poi_verified_total: "1000000000000000000".to_string(),
            },
        ],
    };

    let rows = format_private_asset_rows_from_snapshot(&snapshot, None, Some(&cache));

    assert_eq!(
        total_private_balance_usd_amount(&rows).as_deref(),
        Some("$1,501.23")
    );
}

#[test]
fn private_total_balance_absent_without_priced_assets() {
    let rail = address!("0xe76C6c83af64e4C60245D8C7dE953DF673a7A33D");
    let rows = format_private_asset_rows(
        1,
        &[wallet_ops::TokenTotal {
            token: rail.to_checksum(None),
            total: "1000000000000000000".to_string(),
            poi_verified_total: "1000000000000000000".to_string(),
        }],
        None,
        None,
    );

    assert_eq!(total_private_balance_usd_amount(&rows), None);
}

#[test]
fn private_asset_display_amounts_prioritize_usd_when_available() {
    let usdc = address!("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
    let cache = TokenAnchorRateCache::new();
    cache.store_native_usd_rate(1, uint!(3_000_000_000_U256));
    cache.store_rate(1, usdc, uint!(3_000_000_000_U256));
    let totals = [wallet_ops::TokenTotal {
        token: usdc.to_checksum(None),
        total: "1234567".to_string(),
        poi_verified_total: "1234567".to_string(),
    }];
    let rows = format_private_asset_rows(1, &totals, None, Some(&cache));

    assert_eq!(
        private_asset_display_amounts(&rows[0]),
        ("$1.23".to_string(), Some("1.23 USDC".to_string()))
    );
}

#[test]
fn private_asset_display_amounts_keep_token_primary_when_unpriced() {
    let totals = [wallet_ops::TokenTotal {
        token: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
        total: "1234567".to_string(),
        poi_verified_total: "1234567".to_string(),
    }];
    let rows = format_private_asset_rows(1, &totals, None, None);

    assert_eq!(
        private_asset_display_amounts(&rows[0]),
        ("1.23".to_string(), None)
    );
}

#[test]
fn private_asset_rows_omit_usd_without_required_pricing() {
    let rail = address!("0xe76C6c83af64e4C60245D8C7dE953DF673a7A33D");
    let usdc = address!("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
    let unknown = Address::from([0x99; 20]);
    let cache = TokenAnchorRateCache::new();
    cache.store_native_usd_rate(1, uint!(3_000_000_000_U256));
    let totals = [
        wallet_ops::TokenTotal {
            token: rail.to_checksum(None),
            total: "1000000000000000000".to_string(),
            poi_verified_total: "1000000000000000000".to_string(),
        },
        wallet_ops::TokenTotal {
            token: usdc.to_checksum(None),
            total: "1234567".to_string(),
            poi_verified_total: "1234567".to_string(),
        },
        wallet_ops::TokenTotal {
            token: unknown.to_checksum(None),
            total: "1234567".to_string(),
            poi_verified_total: "1234567".to_string(),
        },
    ];

    let rows = format_private_asset_rows(1, &totals, None, Some(&cache));

    assert_eq!(rows[0].label, "RAIL");
    assert_eq!(rows[0].usd_amount, None);
    assert_eq!(rows[1].label, "USDC");
    assert_eq!(rows[1].usd_amount, None);
    assert_eq!(rows[2].token, Some(unknown));
    assert_eq!(rows[2].usd_amount, None);
}

#[test]
fn private_asset_rows_hide_zero_pending_poi() {
    let totals = [wallet_ops::TokenTotal {
        token: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
        total: "1234567".to_string(),
        poi_verified_total: "1234567".to_string(),
    }];

    let rows = format_private_asset_rows(1, &totals, None, None);

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].pending_poi_amount, "0");
    assert_eq!(rows[0].pending_poi_total, Some(U256::ZERO));
    assert!(!should_show_pending_poi_amount(rows[0].pending_poi_total));
}

#[test]
fn private_asset_rows_show_separate_pending_amounts() {
    let token = Address::from([0x11; 20]);
    let mut pending_in = unshield_utxo_output(token, 7, 0, 2);
    pending_in.pending_new = true;
    pending_in.poi_spendable = false;
    let mut pending_out = unshield_utxo_output(token, 5, 0, 1);
    pending_out.pending_spent = true;
    pending_out.poi_spendable = false;
    let snapshot = ListUtxosOutput {
        chain_id: 1,
        cache_key: "cache".to_string(),
        utxo_count: 2,
        unspent_count: 2,
        spent_count: 0,
        local_pending_spent_count: 0,
        utxos: vec![pending_out, pending_in],
        totals: vec![wallet_ops::TokenTotal {
            token: token.to_checksum(None),
            total: "5".to_string(),
            poi_verified_total: "5".to_string(),
        }],
    };

    let rows = format_private_asset_rows_from_snapshot(&snapshot, None, None);

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].total, Some(uint!(5_U256)));
    assert_eq!(rows[0].pending_incoming_total, Some(uint!(7_U256)));
    assert_eq!(rows[0].pending_outgoing_total, Some(uint!(5_U256)));
    assert!(should_show_pending_amount(rows[0].pending_incoming_total));
    assert!(should_show_pending_amount(rows[0].pending_outgoing_total));
}

#[test]
fn private_asset_rows_include_local_pending_outgoing_amount() {
    let token = Address::from([0x11; 20]);
    let mut local_pending_out = unshield_utxo_output(token, 5, 0, 1);
    local_pending_out.local_pending_spent = true;
    local_pending_out.poi_spendable = false;
    let snapshot = ListUtxosOutput {
        chain_id: 1,
        cache_key: "cache".to_string(),
        utxo_count: 1,
        unspent_count: 1,
        spent_count: 0,
        local_pending_spent_count: 1,
        utxos: vec![local_pending_out],
        totals: vec![wallet_ops::TokenTotal {
            token: token.to_checksum(None),
            total: "5".to_string(),
            poi_verified_total: "5".to_string(),
        }],
    };

    let rows = format_private_asset_rows_from_snapshot(&snapshot, None, None);

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].pending_outgoing_total, Some(uint!(5_U256)));
    assert!(should_show_pending_amount(rows[0].pending_outgoing_total));
}

#[test]
fn unshield_amount_input_formats_exact_token_units() {
    assert_eq!(
        format_unshield_amount_input(uint!(1_230_000_U256), Some(6)),
        "1.23"
    );
    assert_eq!(
        format_unshield_amount_input(uint!(1_000_000_U256), Some(6)),
        "1"
    );
    assert_eq!(format_unshield_amount_input(uint!(42_U256), None), "42");
}

#[test]
fn send_amount_input_formats_exact_token_units() {
    assert_eq!(
        format_send_amount_input(uint!(1_230_000_U256), Some(6)),
        "1.23"
    );
    assert_eq!(
        format_send_amount_input(uint!(1_000_000_U256), Some(6)),
        "1"
    );
    assert_eq!(format_send_amount_input(uint!(42_U256), None), "42");
}

#[test]
fn transaction_generation_stage_text_is_specific() {
    assert_eq!(
        TransactionGenerationStage::SelectingPrivateNotes.label(),
        "Selecting private notes"
    );
    assert_eq!(
        TransactionGenerationStage::ProvingTransaction.detail(),
        "Generating the zero-knowledge proof. This is usually the slowest step."
    );
    assert_eq!(
        TransactionGenerationStage::PublishingToBroadcaster.label(),
        "Publishing to broadcaster"
    );
    assert_eq!(
        TransactionGenerationStage::WaitingForBroadcasterResponse.detail(),
        "Waiting for the selected broadcaster to respond."
    );
}
