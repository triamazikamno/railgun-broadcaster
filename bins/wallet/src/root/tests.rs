use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use alloy::primitives::{Address, U256};
use alloy::uint;
use broadcaster_monitor::FeeRow;
use broadcaster_monitor_waku::{DEFAULT_DOH_ENDPOINT, DEFAULT_TOR_DOH_ENDPOINT};
use gpui_component::select::SelectItem;
use wallet_ops::{
    BroadcasterFeePolicy, ListUtxosOutput, PublicAccountBalance, PublicActionProgressStep,
    PublicAssetId, PublicBalanceAmount, PublicBalanceAsset, PublicBalanceEntry,
    PublicBalanceSnapshot, PublicBroadcasterCandidate, PublicBroadcasterCostEstimate,
    PublicBroadcasterFeeMargin, PublicBroadcasterFeeMode, PublicBroadcasterResultKind,
    PublicBroadcasterSelection, SyncProgressStage, SyncProgressUpdate, TransactionGenerationStage,
    UtxoOutput,
    settings::{
        BuiltInTokenOverride, CustomTokenSettings, NetworkModeSetting, PoiReadSourceSetting,
        PriceAnchorSettings, TokenKey, TokenPriceAnchorOverride, WALLET_SETTINGS_KEY,
        WakuDirectPeerSetting, WalletSettings, build_effective_chain_configs,
        build_effective_token_registry, default_chain_contract_settings,
        default_chain_quick_sync_endpoint, default_chain_rpc_endpoints, default_waku_direct_peers,
        default_waku_dns_enr_trees, encode_wallet_settings,
    },
    vault::{
        DesktopVaultStore, PublicAccountMetadata, PublicAccountScope, PublicAccountSource,
        PublicAccountStatus, WalletMetadataBundle, WalletSource, WalletStatus,
    },
};

use super::private_assets::{
    build_send_asset, build_unshield_asset, format_private_asset_rows_from_snapshot,
    should_show_pending_amount, should_show_pending_poi_amount,
};
use super::private_broadcaster::private_broadcaster_closed_active_stage;
use super::public_action::{public_action_asset_label, public_action_max_label};
use super::public_broadcaster_cost::public_broadcaster_cost_status;
use super::{
    Activity, BroadcasterChoice, ChainUtxoState, CostEstimateStatus, DeliveryFormKind,
    DeliveryMode, PUBLIC_ACCOUNT_IDENTICON_CELL_COUNT, PUBLIC_ACCOUNT_IDENTICON_GRID_SIZE,
    PUBLIC_ADDRESS_QR_QUIET_ZONE_MODULES, PriceAnchorComponentDialogValues,
    PriceAnchorDialogValues, PrivateActionMetric, PrivateBroadcasterProgressState,
    PublicActionMode, PublicActionStepStatus, PublicBroadcasterFeeTokenOption, SECONDS_PER_DAY,
    SECONDS_PER_HOUR, SECONDS_PER_MINUTE, SECONDS_PER_MONTH, SECONDS_PER_YEAR,
    SEND_AUTHORIZATION_FAILED_ERROR, SEND_MISSING_PASSWORD_ERROR, SettingsApplyMode,
    UNSHIELD_AUTHORIZATION_FAILED_ERROR, UNSHIELD_MISSING_PASSWORD_ERROR, UnshieldAsset,
    UnshieldAssetKey, VaultState, WalletAppOptions, WalletRoot, WalletSelectItem, WalletTab,
    add_chain_rpc_endpoint, add_poi_gateway_url, add_waku_direct_peer, add_waku_dns_enr_tree,
    add_waku_doh_fallback_endpoint, adjusted_amount_for_max_change,
    apply_private_broadcaster_progress_stage, broadcaster_choice_supported_by_candidates,
    classify_settings_apply_mode, display_chain_contract_settings,
    display_chain_quick_sync_endpoint, display_chain_rpc_endpoints, display_price_anchor_entries,
    display_rows_from_output, display_token_entries, display_waku_direct_peers,
    display_waku_dns_enr_trees, display_waku_doh_endpoint, display_waku_doh_fallback_endpoints,
    effective_public_broadcaster_fee_mode, ethereum_weth_public_broadcaster_count,
    fail_private_broadcaster_progress_steps_at_stage, fee_token_option_has_eligible_broadcaster,
    finish_private_broadcaster_progress_steps, finish_private_broadcaster_progress_steps_at_stage,
    form_error_clears_public_broadcaster_cost_estimate, format_anchor_bps_exact_range,
    format_anchor_bps_percent, format_anchor_bps_percent_range, format_anchor_premium_range,
    format_compact_age, format_exact_asset_amount_for_display, format_form_error_for_asset,
    format_native_token_amount_for_display, format_private_asset_rows,
    format_public_broadcaster_fee_margin, format_report_chain, format_send_amount_input,
    format_total, format_unshield_amount_input, is_effective_wrapped_native_token,
    load_validated_startup_settings, loading_summary, max_send_amount_from_snapshot,
    max_unshield_amount_from_snapshot, merge_public_balance_snapshot, native_token_display_label,
    native_wrapped_output_labels, next_public_account_label_number, parse_repair_cache_block,
    price_anchor_dialog_values_from_entry, price_anchor_override_from_dialog_values,
    price_anchor_token_primary_label, private_action_metrics, private_broadcaster_progress_steps,
    progress_detail, public_account_identicon_color, public_account_identicon_pattern,
    public_account_matches_search, public_account_visible_balances_for_chain,
    public_action_error_copy_value, public_action_error_details, public_action_error_summary,
    public_action_max_amount_after_reserve, public_action_progress_steps,
    public_address_qr_module_range, public_address_qr_payload, public_asset_decimals,
    public_asset_icon_path, public_asset_label, public_balance_entry_for_chain,
    public_broadcaster_candidates_for_asset, public_broadcaster_cost_status_text,
    public_broadcaster_fee_token_options_from_snapshot, public_broadcaster_fee_token_warning,
    public_broadcaster_submit_disabled_for_fee_token_options, refresh_form_asset_from_snapshot,
    remove_chain_rpc_endpoint, remove_poi_gateway_url, remove_waku_direct_peer,
    remove_waku_dns_enr_tree, remove_waku_doh_fallback_endpoint, repair_cache_help_text,
    required_relay_adapt_for_unwrap, resolve_selected_public_broadcaster_fee_token,
    send_asset_key_from_formatted, send_element_id, send_key_matches_asset,
    send_public_broadcaster_estimate_input_error, set_chain_rpc_endpoint, set_poi_gateway_url,
    set_price_anchor_override, set_waku_direct_peer, set_waku_dns_enr_tree,
    set_waku_doh_fallback_endpoint, settings_draft_after_discard, settings_restart_action_enabled,
    settings_restart_reuses_active_network, settings_save_action_enabled,
    should_clear_private_action_error_on_password_change, should_focus_utxo_table,
    should_preserve_estimate_after_broadcaster_policy_change,
    should_render_public_broadcaster_cost_preview, should_show_broadcaster_fee_mode_toggle,
    should_show_distinct_amount, should_show_pre_unlock_settings_action,
    should_show_proxy_url_setting, should_show_proxy_waku_disclaimer,
    sidebar_primary_activity_order, startup_settings_action_state,
    unshield_asset_key_from_formatted, unshield_element_id, unshield_key_matches_asset,
    unshield_public_broadcaster_estimate_input_error, wallet_generation_matches,
    wallet_options_from_metadata,
};

fn utxo_output(token: &str, value: &str, is_spent: bool) -> UtxoOutput {
    const SOURCE_TX_HASH: &str =
        "0x1111111111111111111111111111111111111111111111111111111111111111";
    const SPENT_TX_HASH: &str =
        "0x2222222222222222222222222222222222222222222222222222222222222222";

    utxo_output_with_hashes(
        token,
        value,
        is_spent,
        SOURCE_TX_HASH,
        is_spent.then_some(SPENT_TX_HASH),
    )
}

fn utxo_output_with_hashes(
    token: &str,
    value: &str,
    is_spent: bool,
    source_tx_hash: &str,
    spent_tx_hash: Option<&str>,
) -> UtxoOutput {
    UtxoOutput {
        tree: 0,
        position: 7,
        token: token.to_string(),
        value: value.to_string(),
        commitment_kind: "Transact".to_string(),
        commitment: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .to_string(),
        npk: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        blinded_commitment: "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            .to_string(),
        poi_statuses: BTreeMap::from([(
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string(),
            if is_spent { "Unknown" } else { "Valid" }.to_string(),
        )]),
        poi_spendable: !is_spent,
        source_tx_hash: source_tx_hash.to_string(),
        source_block_number: 11,
        source_block_timestamp: 1_700_000_011,
        is_spent,
        pending_new: false,
        pending_spent: false,
        local_pending_spent: false,
        spent_tx_hash: spent_tx_hash.map(str::to_string),
        spent_block_number: spent_tx_hash.map(|_| 21),
    }
}

fn unshield_utxo_output(token: Address, value: u64, tree: u32, position: u64) -> UtxoOutput {
    UtxoOutput {
        tree,
        position,
        token: token.to_checksum(None),
        value: value.to_string(),
        commitment_kind: "Transact".to_string(),
        commitment: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .to_string(),
        npk: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        blinded_commitment: "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            .to_string(),
        poi_statuses: BTreeMap::from([(
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string(),
            "Valid".to_string(),
        )]),
        poi_spendable: true,
        source_tx_hash: "0x1111111111111111111111111111111111111111111111111111111111111111"
            .to_string(),
        source_block_number: 11,
        source_block_timestamp: 1_700_000_011,
        is_spent: false,
        pending_new: false,
        pending_spent: false,
        local_pending_spent: false,
        spent_tx_hash: None,
        spent_block_number: None,
    }
}

fn temp_wallet_db_root(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    std::env::temp_dir().join(format!(
        "railgun-broadcaster-wallet-root-tests-{name}-{}-{nanos}",
        std::process::id()
    ))
}

fn fee_row(chain_id: u64, token: Address, fees_id: &str) -> FeeRow {
    const RAILGUN_ADDRESS: &str = "0zk1qy4v02p5zkq0zfpaxhz79j5tslrv8c44d80d8jr2fuecrtxlp8lemrv7j6fe3z53ll0jm7u592n0hr8elesd0xzv6y9jpdvsyln80m95jcxhvnmagfqg5p6e9mp";

    FeeRow {
        chain_id,
        railgun_address: Arc::from(RAILGUN_ADDRESS),
        token_address: token,
        fee: uint!(10_U256),
        signature_valid: true,
        fees_id: Arc::from(fees_id),
        fee_expiration: SystemTime::now() + Duration::from_secs(60),
        available_wallets: 1,
        version: Arc::from("8.2.3"),
        relay_adapt: Address::ZERO,
        relay_adapt_7702: None,
        required_poi_list_keys: Vec::new(),
        identifier: Some(Arc::from(fees_id)),
        last_seen: SystemTime::now(),
        reliability: 0.9,
    }
}

fn public_broadcaster_cost_estimate(
    candidate: PublicBroadcasterCandidate,
) -> PublicBroadcasterCostEstimate {
    PublicBroadcasterCostEstimate {
        broadcaster: candidate,
        action_token: Address::from([0x41; 20]),
        fee_token: Address::from([0x42; 20]),
        entered_amount: U256::from(1),
        receiver_amount: U256::from(1),
        recipient_amount: U256::from(1),
        total_private_spend: U256::from(1),
        fee_amount: U256::from(1),
        protocol_fee_amount: U256::ZERO,
        protocol_fee_bps: U256::ZERO,
        fee_mode: PublicBroadcasterFeeMode::AddToAmount,
        max_receiver_amount: U256::from(1),
        max_entered_amount: U256::from(1),
        gas_limit: 1,
        min_gas_price: 1,
        native_gas_cost: U256::from(1),
        transaction_count: 1,
        input_count: 1,
        private_output_count: 2,
        public_output_count: 0,
    }
}

fn wallet_metadata(
    wallet_uuid: &str,
    label: &str,
    source: WalletSource,
    status: WalletStatus,
    display_order: u32,
) -> WalletMetadataBundle {
    WalletMetadataBundle {
        wallet_uuid: wallet_uuid.to_string(),
        label: label.to_string(),
        derivation_index: 0,
        source,
        status,
        display_order,
    }
}

#[test]
fn wallet_options_hide_inactive_and_sort_active_metadata() {
    let options = wallet_options_from_metadata(vec![
        wallet_metadata(
            "wallet-b",
            "Beta",
            WalletSource::Imported,
            WalletStatus::Active,
            2,
        ),
        wallet_metadata(
            "wallet-hidden",
            "Hidden",
            WalletSource::Imported,
            WalletStatus::Inactive,
            0,
        ),
        wallet_metadata(
            "wallet-a",
            "Alpha",
            WalletSource::Generated,
            WalletStatus::Active,
            1,
        ),
    ]);

    assert_eq!(options.len(), 2);
    assert_eq!(options[0].wallet_id.as_ref(), "wallet-a");
    assert_eq!(options[0].label.as_ref(), "Alpha");
    assert_eq!(options[0].source, WalletSource::Generated);
    assert_eq!(options[1].wallet_id.as_ref(), "wallet-b");
}

#[test]
fn wallet_select_item_matches_label_and_wallet_id() {
    let wallet = WalletSelectItem {
        wallet_id: "wallet-a".into(),
        label: "Alpha".into(),
    };

    assert!(wallet.matches("alpha"));
    assert!(wallet.matches("wallet-a"));
    assert!(!wallet.matches("add"));
}

#[test]
fn wallet_generation_guard_rejects_stale_async_results() {
    assert!(wallet_generation_matches(
        Some("wallet-a"),
        2,
        "wallet-a",
        2
    ));
    assert!(!wallet_generation_matches(
        Some("wallet-b"),
        2,
        "wallet-a",
        2
    ));
    assert!(!wallet_generation_matches(
        Some("wallet-a"),
        3,
        "wallet-a",
        2
    ));
    assert!(!wallet_generation_matches(None, 2, "wallet-a", 2));
}

#[test]
fn display_rows_use_known_token_metadata() {
    let output = ListUtxosOutput {
        chain_id: 1,
        cache_key: "cache".to_string(),
        utxo_count: 1,
        unspent_count: 1,
        spent_count: 0,
        local_pending_spent_count: 0,
        utxos: vec![utxo_output(
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            "1234567",
            false,
        )],
        totals: Vec::new(),
    };

    let rows = display_rows_from_output(&output, "", true);
    assert_eq!(rows[0].token, "USDC");
    assert_eq!(rows[0].amount, "1.23");
    assert_eq!(rows[0].tree_position, "0/7");
    assert_eq!(rows[0].poi_status, "Valid");
    assert!(rows[0].poi_spendable);
    assert_eq!(rows[0].source_block_timestamp, 1_700_000_011);
    assert!(rows[0].token_icon_path.is_some());
    assert!(!rows[0].is_spent);
}

#[test]
fn compact_age_uses_expected_thresholds() {
    const M: u64 = SECONDS_PER_MINUTE;
    const H: u64 = SECONDS_PER_HOUR;
    const D: u64 = SECONDS_PER_DAY;
    const MO: u64 = SECONDS_PER_MONTH;
    const Y: u64 = SECONDS_PER_YEAR;

    assert_eq!(format_compact_age(0), "0s");
    assert_eq!(format_compact_age(59), "59s");
    assert_eq!(format_compact_age(M), "1m");
    assert_eq!(format_compact_age(59 * M + 59), "59m");
    assert_eq!(format_compact_age(H), "1h");
    assert_eq!(format_compact_age(2 * H + 14 * M), "2h 14m");
    assert_eq!(format_compact_age(3 * H), "3h");
    assert_eq!(format_compact_age(23 * H + 59 * M), "23h");
    assert_eq!(format_compact_age(D), "1d");
    assert_eq!(format_compact_age(2 * D + 3 * H), "2d 3h");
    assert_eq!(format_compact_age(3 * D), "3d");
    assert_eq!(format_compact_age(29 * D), "29d");
    assert_eq!(format_compact_age(30 * D), "1mo");
    assert_eq!(format_compact_age(2 * MO + 4 * D), "2mo 4d");
    assert_eq!(format_compact_age(3 * MO), "3mo");
    assert_eq!(format_compact_age(11 * MO), "11mo");
    assert_eq!(format_compact_age(Y), "1y");
    assert_eq!(format_compact_age(2 * Y + 3 * MO), "2y 3mo");
    assert_eq!(format_compact_age(3 * Y), "3y");
}

#[test]
fn display_rows_fall_back_for_unknown_token_metadata() {
    let output = ListUtxosOutput {
        chain_id: 1,
        cache_key: "cache".to_string(),
        utxo_count: 1,
        unspent_count: 1,
        spent_count: 0,
        local_pending_spent_count: 0,
        utxos: vec![utxo_output(
            "0x1111111111111111111111111111111111111111",
            "42",
            false,
        )],
        totals: Vec::new(),
    };

    let rows = display_rows_from_output(&output, "", true);
    assert_eq!(rows[0].amount, "42");
    assert_eq!(
        rows[0].token_address,
        "0x1111111111111111111111111111111111111111"
    );
    assert_eq!(rows[0].token_icon_path, None);
}

#[test]
fn totals_format_known_token_amount() {
    let total = wallet_ops::TokenTotal {
        token: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
        total: "1234567".to_string(),
        poi_verified_total: "1234567".to_string(),
    };

    assert_eq!(format_total(1, &total), "USDC 1.23");
}

#[test]
fn form_error_formats_broadcaster_max_in_token_units() {
    let asset = UnshieldAsset {
        chain_id: 1,
        token: Address::ZERO,
        label: "USDC".to_string(),
        decimals: Some(6),
        total: U256::ZERO,
        poi_verified_total: U256::ZERO,
        max_batched: U256::ZERO,
        icon_path: None,
    };

    let formatted = format_form_error_for_asset(
        "build public broadcaster send proof: public broadcaster max entered amount: 388585770",
        &asset,
        asset.token,
        None,
    );

    assert_eq!(
        formatted,
        "Max POI-verified entered amount for public broadcaster: 388.58577 USDC. Try a smaller amount or switch fee mode."
    );
}

#[test]
fn report_chain_preserves_wrapped_public_broadcaster_error() {
    let asset = UnshieldAsset {
        chain_id: 1,
        token: Address::ZERO,
        label: "USDC".to_string(),
        decimals: Some(6),
        total: U256::ZERO,
        poi_verified_total: U256::ZERO,
        max_batched: U256::ZERO,
        icon_path: None,
    };
    let error = eyre::eyre!("public broadcaster max entered amount: 388585770")
        .wrap_err("build public broadcaster send proof");

    let chain = format_report_chain(&error);

    assert_eq!(
        chain,
        "build public broadcaster send proof: public broadcaster max entered amount: 388585770"
    );
    assert_eq!(
        format_form_error_for_asset(chain.as_str(), &asset, asset.token, None),
        "Max POI-verified entered amount for public broadcaster: 388.58577 USDC. Try a smaller amount or switch fee mode."
    );
}

#[test]
fn form_error_formats_fee_token_balance_in_selected_fee_token_units() {
    let weth = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
        .parse::<Address>()
        .expect("weth address");
    let usdc = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
        .parse::<Address>()
        .expect("usdc address");
    let asset = UnshieldAsset {
        chain_id: 1,
        token: weth,
        label: "WETH".to_string(),
        decimals: Some(18),
        total: U256::ZERO,
        poi_verified_total: U256::ZERO,
        max_batched: U256::ZERO,
        icon_path: None,
    };

    let formatted = format_form_error_for_asset(
        "build public broadcaster unshield proof: public broadcaster fee-token max spendable: 388585770",
        &asset,
        usdc,
        None,
    );

    assert_eq!(
        formatted,
        "Broadcaster fee exceeds available fee-token balance: 388.58577 USDC. Choose a fee token with more spendable balance or a lower-fee broadcaster."
    );
}

#[test]
fn public_broadcaster_amount_display_is_exact() {
    let asset = UnshieldAsset {
        chain_id: 1,
        token: Address::ZERO,
        label: "USDC".to_string(),
        decimals: Some(6),
        total: U256::ZERO,
        poi_verified_total: U256::ZERO,
        max_batched: U256::ZERO,
        icon_path: None,
    };

    assert_eq!(
        format_exact_asset_amount_for_display(uint!(388_429_885_U256), &asset),
        "388.429885 USDC"
    );
    assert_eq!(
        format_exact_asset_amount_for_display(uint!(14_390_115_U256), &asset),
        "14.390115 USDC"
    );
}

#[test]
fn public_broadcaster_estimate_hides_duplicate_amount_rows() {
    let entered = uint!(388_429_885_U256);

    assert!(!should_show_distinct_amount(entered, entered));
    assert!(should_show_distinct_amount(
        entered,
        entered + uint!(1_U256)
    ));
}

#[test]
fn public_broadcaster_cost_preview_hides_on_form_error() {
    assert!(should_render_public_broadcaster_cost_preview(
        DeliveryMode::PublicBroadcaster,
        false,
        false,
    ));
    assert!(!should_render_public_broadcaster_cost_preview(
        DeliveryMode::PublicBroadcaster,
        false,
        true,
    ));
    assert!(!should_render_public_broadcaster_cost_preview(
        DeliveryMode::PublicBroadcaster,
        true,
        false,
    ));
    assert!(!should_render_public_broadcaster_cost_preview(
        DeliveryMode::ManualCalldata,
        false,
        false,
    ));
}

#[test]
fn public_broadcaster_missing_password_errors_preserve_estimate() {
    assert!(!form_error_clears_public_broadcaster_cost_estimate(
        DeliveryFormKind::Send,
        SEND_MISSING_PASSWORD_ERROR,
    ));
    assert!(!form_error_clears_public_broadcaster_cost_estimate(
        DeliveryFormKind::Unshield,
        UNSHIELD_MISSING_PASSWORD_ERROR,
    ));
    assert!(!form_error_clears_public_broadcaster_cost_estimate(
        DeliveryFormKind::Send,
        SEND_AUTHORIZATION_FAILED_ERROR,
    ));
    assert!(!form_error_clears_public_broadcaster_cost_estimate(
        DeliveryFormKind::Unshield,
        UNSHIELD_AUTHORIZATION_FAILED_ERROR,
    ));
    assert!(form_error_clears_public_broadcaster_cost_estimate(
        DeliveryFormKind::Send,
        "invalid recipient 0zk address",
    ));
    assert!(form_error_clears_public_broadcaster_cost_estimate(
        DeliveryFormKind::Unshield,
        SEND_MISSING_PASSWORD_ERROR,
    ));
}

#[test]
fn password_change_only_clears_missing_password_errors() {
    assert!(should_clear_private_action_error_on_password_change(
        DeliveryFormKind::Send,
        SEND_MISSING_PASSWORD_ERROR,
    ));
    assert!(should_clear_private_action_error_on_password_change(
        DeliveryFormKind::Unshield,
        UNSHIELD_MISSING_PASSWORD_ERROR,
    ));
    assert!(should_clear_private_action_error_on_password_change(
        DeliveryFormKind::Send,
        SEND_AUTHORIZATION_FAILED_ERROR,
    ));
    assert!(should_clear_private_action_error_on_password_change(
        DeliveryFormKind::Unshield,
        UNSHIELD_AUTHORIZATION_FAILED_ERROR,
    ));
    assert!(!should_clear_private_action_error_on_password_change(
        DeliveryFormKind::Send,
        "invalid recipient 0zk address",
    ));
    assert!(!should_clear_private_action_error_on_password_change(
        DeliveryFormKind::Unshield,
        SEND_MISSING_PASSWORD_ERROR,
    ));
}

#[test]
fn public_broadcaster_estimate_validation_reports_invalid_send_recipient() {
    let asset = UnshieldAsset {
        chain_id: 1,
        token: Address::ZERO,
        label: "DAI".to_string(),
        decimals: Some(18),
        total: uint!(10_000_000_000_000_000_000_U256),
        poi_verified_total: uint!(10_000_000_000_000_000_000_U256),
        max_batched: uint!(10_000_000_000_000_000_000_U256),
        icon_path: None,
    };

    let error = send_public_broadcaster_estimate_input_error("not-0zk", "1", &asset)
        .expect("invalid recipient should be reported");

    assert!(error.contains("invalid recipient 0zk address"));
}

#[test]
fn public_broadcaster_estimate_validation_reports_invalid_unshield_recipient() {
    let asset = UnshieldAsset {
        chain_id: 1,
        token: Address::ZERO,
        label: "DAI".to_string(),
        decimals: Some(18),
        total: uint!(10_000_000_000_000_000_000_U256),
        poi_verified_total: uint!(10_000_000_000_000_000_000_U256),
        max_batched: uint!(10_000_000_000_000_000_000_U256),
        icon_path: None,
    };

    assert_eq!(
        unshield_public_broadcaster_estimate_input_error("not-0x", "1", &asset),
        Some("Enter a valid public EVM recipient address".to_string())
    );
}

#[test]
fn public_broadcaster_estimate_validation_allows_empty_recipient_prompt_state() {
    let asset = UnshieldAsset {
        chain_id: 1,
        token: Address::ZERO,
        label: "DAI".to_string(),
        decimals: Some(18),
        total: uint!(10_000_000_000_000_000_000_U256),
        poi_verified_total: uint!(10_000_000_000_000_000_000_U256),
        max_batched: uint!(10_000_000_000_000_000_000_U256),
        icon_path: None,
    };

    assert_eq!(
        send_public_broadcaster_estimate_input_error("", "1", &asset),
        None
    );
    assert_eq!(
        unshield_public_broadcaster_estimate_input_error("", "1", &asset),
        None
    );
}

#[test]
fn public_broadcaster_cost_status_separates_pending_from_estimating() {
    assert_eq!(public_broadcaster_cost_status(true, false), None);
    assert_eq!(
        public_broadcaster_cost_status(false, true),
        Some(CostEstimateStatus::Estimating)
    );
    assert_eq!(public_broadcaster_cost_status(true, true), None);
    assert_eq!(public_broadcaster_cost_status(false, false), None);
    assert_eq!(
        public_broadcaster_cost_status_text(CostEstimateStatus::Estimating).0,
        "Estimating public broadcaster cost..."
    );
}

#[test]
fn fee_token_options_use_poi_spendable_balances_and_broadcaster_counts() {
    let token_a = Address::from([0x11; 20]);
    let token_b = Address::from([0x22; 20]);
    let token_c = Address::from([0x33; 20]);
    let snapshot = ListUtxosOutput {
        chain_id: 1,
        cache_key: "cache".to_string(),
        utxo_count: 2,
        unspent_count: 2,
        spent_count: 0,
        local_pending_spent_count: 0,
        utxos: vec![
            unshield_utxo_output(token_a, 5, 0, 1),
            unshield_utxo_output(token_b, 7, 0, 2),
        ],
        totals: vec![
            wallet_ops::TokenTotal {
                token: token_a.to_checksum(None),
                total: "5".to_string(),
                poi_verified_total: "5".to_string(),
            },
            wallet_ops::TokenTotal {
                token: token_b.to_checksum(None),
                total: "7".to_string(),
                poi_verified_total: "7".to_string(),
            },
            wallet_ops::TokenTotal {
                token: token_c.to_checksum(None),
                total: "9".to_string(),
                poi_verified_total: "0".to_string(),
            },
        ],
    };
    let fee_rows = vec![fee_row(1, token_a, "token-a")];

    let options = public_broadcaster_fee_token_options_from_snapshot(
        &snapshot,
        &fee_rows,
        None,
        BroadcasterFeePolicy::default(),
        None,
        |_| None,
    );

    assert_eq!(options.len(), 2);
    let option_a = options
        .iter()
        .find(|option| option.token == token_a)
        .expect("token a option");
    assert_eq!(option_a.max_spendable, uint!(5_U256));
    assert_eq!(option_a.eligible_broadcaster_count, 1);
    let option_b = options
        .iter()
        .find(|option| option.token == token_b)
        .expect("token b option");
    assert_eq!(option_b.max_spendable, uint!(7_U256));
    assert_eq!(option_b.eligible_broadcaster_count, 0);
    assert!(!options.iter().any(|option| option.token == token_c));
}

#[test]
fn fee_token_options_use_fee_only_transaction_spend_limit() {
    let token = Address::from([0x34; 20]);
    let snapshot = ListUtxosOutput {
        chain_id: 1,
        cache_key: "cache".to_string(),
        utxo_count: 20,
        unspent_count: 20,
        spent_count: 0,
        local_pending_spent_count: 0,
        utxos: (0..20)
            .map(|position| unshield_utxo_output(token, 1, 0, position))
            .collect(),
        totals: vec![wallet_ops::TokenTotal {
            token: token.to_checksum(None),
            total: "20".to_string(),
            poi_verified_total: "20".to_string(),
        }],
    };
    let fee_rows = vec![fee_row(1, token, "token")];

    let options = public_broadcaster_fee_token_options_from_snapshot(
        &snapshot,
        &fee_rows,
        None,
        BroadcasterFeePolicy::default(),
        None,
        |_| None,
    );

    assert_eq!(options.len(), 1);
    assert_eq!(options[0].max_spendable, uint!(13_U256));
}

#[test]
fn fee_token_options_include_known_token_icons() {
    let token = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
        .parse::<Address>()
        .expect("usdc address");
    let snapshot = ListUtxosOutput {
        chain_id: 1,
        cache_key: "cache".to_string(),
        utxo_count: 1,
        unspent_count: 1,
        spent_count: 0,
        local_pending_spent_count: 0,
        utxos: vec![unshield_utxo_output(token, 1, 0, 1)],
        totals: vec![wallet_ops::TokenTotal {
            token: token.to_checksum(None),
            total: "1".to_string(),
            poi_verified_total: "1".to_string(),
        }],
    };
    let fee_rows = vec![fee_row(1, token, "usdc")];

    let options = public_broadcaster_fee_token_options_from_snapshot(
        &snapshot,
        &fee_rows,
        None,
        BroadcasterFeePolicy::default(),
        None,
        |_| None,
    );

    assert_eq!(options.len(), 1);
    assert!(options[0].icon_path.is_some());
}

#[test]
fn ethereum_weth_public_broadcaster_count_filters_available_broadcasters() {
    let weth = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
        .parse::<Address>()
        .expect("weth address");
    let other_token = Address::from([0x77; 20]);
    let mut unavailable = fee_row(1, weth, "unavailable");
    unavailable.available_wallets = 0;
    let mut expired = fee_row(1, weth, "expired");
    expired.fee_expiration = SystemTime::now() - Duration::from_secs(1);
    let mut invalid_signature = fee_row(1, weth, "invalid-signature");
    invalid_signature.signature_valid = false;
    let rows = vec![
        fee_row(1, weth, "available-weth"),
        fee_row(42161, weth, "wrong-chain"),
        fee_row(1, other_token, "wrong-token"),
        unavailable,
        expired,
        invalid_signature,
    ];

    assert_eq!(ethereum_weth_public_broadcaster_count(&rows), 1);
}

#[test]
fn ethereum_weth_public_broadcaster_count_is_zero_without_available_broadcasters() {
    let weth = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
        .parse::<Address>()
        .expect("weth address");
    let mut unavailable = fee_row(1, weth, "unavailable");
    unavailable.available_wallets = 0;

    assert_eq!(ethereum_weth_public_broadcaster_count(&[]), 0);
    assert_eq!(ethereum_weth_public_broadcaster_count(&[unavailable]), 0);
}

#[test]
fn fee_token_options_filter_unwrap_by_effective_relay_adapter() {
    let token = Address::from([0x39; 20]);
    let required_relay = Address::from([0x40; 20]);
    let other_relay = Address::from([0x41; 20]);
    let snapshot = ListUtxosOutput {
        chain_id: 1,
        cache_key: "cache".to_string(),
        utxo_count: 20,
        unspent_count: 20,
        spent_count: 0,
        local_pending_spent_count: 0,
        utxos: (0..20)
            .map(|position| unshield_utxo_output(token, 1, 0, position))
            .collect(),
        totals: vec![wallet_ops::TokenTotal {
            token: token.to_checksum(None),
            total: "20".to_string(),
            poi_verified_total: "20".to_string(),
        }],
    };
    let mut row = fee_row(1, token, "custom-relay");
    row.relay_adapt = required_relay;

    let matching = public_broadcaster_fee_token_options_from_snapshot(
        &snapshot,
        &[row.clone()],
        Some(required_relay),
        BroadcasterFeePolicy::default(),
        None,
        |_| None,
    );
    let mismatched = public_broadcaster_fee_token_options_from_snapshot(
        &snapshot,
        &[row],
        Some(other_relay),
        BroadcasterFeePolicy::default(),
        None,
        |_| None,
    );

    assert_eq!(matching[0].eligible_broadcaster_count, 1);
    assert_eq!(mismatched[0].eligible_broadcaster_count, 0);
}

#[test]
fn effective_chain_overrides_drive_unwrap_ui_filters() {
    let relay = Address::from([0x42; 20]);
    let wrapped = Address::from([0x43; 20]);
    let other = Address::from([0x44; 20]);
    let mut settings = WalletSettings::default();
    let chain = settings.chains.per_chain.entry(1).or_default();
    chain.contracts.relay_adapt_contract = Some(relay.to_string());
    chain.contracts.wrapped_native_token = Some(wrapped.to_string());
    let configs = build_effective_chain_configs(&settings).expect("effective chains");

    assert_eq!(
        required_relay_adapt_for_unwrap(&configs, 1, true),
        Some(relay)
    );
    assert_eq!(required_relay_adapt_for_unwrap(&configs, 1, false), None);
    assert!(is_effective_wrapped_native_token(&configs, 1, wrapped));
    assert!(!is_effective_wrapped_native_token(&configs, 1, other));
}

#[test]
fn fee_token_resolution_prefers_current_then_action_then_first_eligible() {
    let action = Address::from([0x44; 20]);
    let current = Address::from([0x45; 20]);
    let fallback = Address::from([0x46; 20]);
    let option = |token, count| PublicBroadcasterFeeTokenOption {
        token,
        label: format!("token-{count}"),
        decimals: None,
        max_spendable: U256::from(1),
        eligible_broadcaster_count: count,
        icon_path: None,
    };

    assert_eq!(
        resolve_selected_public_broadcaster_fee_token(
            current,
            action,
            &[option(current, 1), option(action, 1)],
        ),
        current
    );
    assert_eq!(
        resolve_selected_public_broadcaster_fee_token(
            current,
            action,
            &[option(current, 0), option(action, 1), option(fallback, 1)],
        ),
        action
    );
    assert_eq!(
        resolve_selected_public_broadcaster_fee_token(
            current,
            action,
            &[option(current, 0), option(action, 0), option(fallback, 1)],
        ),
        fallback
    );
}

#[test]
fn fee_token_submit_state_requires_selected_token_broadcaster_count() {
    let selected = Address::from([0x51; 20]);
    let other = Address::from([0x52; 20]);
    let options = vec![
        PublicBroadcasterFeeTokenOption {
            token: selected,
            label: "selected".to_string(),
            decimals: None,
            max_spendable: U256::from(1),
            eligible_broadcaster_count: 0,
            icon_path: None,
        },
        PublicBroadcasterFeeTokenOption {
            token: other,
            label: "other".to_string(),
            decimals: None,
            max_spendable: U256::from(1),
            eligible_broadcaster_count: 1,
            icon_path: None,
        },
    ];

    assert!(!fee_token_option_has_eligible_broadcaster(
        &options, selected
    ));
    assert!(fee_token_option_has_eligible_broadcaster(&options, other));
    assert!(public_broadcaster_submit_disabled_for_fee_token_options(
        &options, selected
    ));
    assert!(!public_broadcaster_submit_disabled_for_fee_token_options(
        &options, other
    ));
}

#[test]
fn fee_token_warning_distinguishes_empty_broadcaster_monitor() {
    let selected = Address::from([0x51; 20]);
    let options = vec![PublicBroadcasterFeeTokenOption {
        token: selected,
        label: "selected".to_string(),
        decimals: None,
        max_spendable: U256::from(1),
        eligible_broadcaster_count: 0,
        icon_path: None,
    }];

    assert_eq!(
        public_broadcaster_fee_token_warning(&[], 1, &options, selected),
        Some("Searching for public broadcasters")
    );
}

#[test]
fn fee_token_warning_reports_no_supporting_broadcaster() {
    let selected = Address::from([0x51; 20]);
    let unsupported = Address::from([0x52; 20]);
    let row = fee_row(1, unsupported, "unsupported");
    let options = vec![PublicBroadcasterFeeTokenOption {
        token: selected,
        label: "selected".to_string(),
        decimals: None,
        max_spendable: U256::from(1),
        eligible_broadcaster_count: 0,
        icon_path: None,
    }];

    assert_eq!(
        public_broadcaster_fee_token_warning(&[row], 1, &options, selected),
        Some("No detected public broadcaster supports your spendable fee tokens")
    );
}

#[test]
fn fee_token_warning_reports_selected_token_without_broadcaster() {
    let selected = Address::from([0x51; 20]);
    let other = Address::from([0x52; 20]);
    let row = fee_row(1, other, "supported-other");
    let options = vec![
        PublicBroadcasterFeeTokenOption {
            token: selected,
            label: "selected".to_string(),
            decimals: None,
            max_spendable: U256::from(1),
            eligible_broadcaster_count: 0,
            icon_path: None,
        },
        PublicBroadcasterFeeTokenOption {
            token: other,
            label: "other".to_string(),
            decimals: None,
            max_spendable: U256::from(1),
            eligible_broadcaster_count: 1,
            icon_path: None,
        },
    ];

    assert_eq!(
        public_broadcaster_fee_token_warning(&[row], 1, &options, selected),
        Some("Choose a fee token with at least one eligible public broadcaster before submitting.")
    );
    assert_eq!(
        public_broadcaster_fee_token_warning(&[], 1, &options, other),
        None
    );
}

#[test]
fn unsupported_specific_broadcaster_is_detected_for_fee_token_change() {
    let token = Address::from([0x61; 20]);
    let other = Address::from([0x62; 20]);
    let policy = BroadcasterFeePolicy::default();
    let row = fee_row(1, token, "supported");
    let candidates = public_broadcaster_candidates_for_asset(&[row], 1, token, None, policy, None)
        .expect("candidates");
    let choice = BroadcasterChoice::Specific {
        railgun_address: candidates[0].railgun_address.clone(),
    };
    let unsupported = public_broadcaster_candidates_for_asset(&[], 1, other, None, policy, None)
        .expect("empty candidates");

    assert!(broadcaster_choice_supported_by_candidates(
        &choice,
        &candidates,
        policy
    ));
    assert!(!broadcaster_choice_supported_by_candidates(
        &choice,
        &unsupported,
        policy
    ));
    assert!(should_preserve_estimate_after_broadcaster_policy_change(
        &choice,
        &candidates,
        policy
    ));
    assert!(!should_preserve_estimate_after_broadcaster_policy_change(
        &BroadcasterChoice::Random,
        &candidates,
        policy
    ));
    assert!(!should_preserve_estimate_after_broadcaster_policy_change(
        &choice,
        &unsupported,
        policy
    ));
}

#[test]
fn random_submission_selection_uses_estimated_broadcaster() {
    let token = Address::from([0x63; 20]);
    let policy = BroadcasterFeePolicy::default();
    let candidates = public_broadcaster_candidates_for_asset(
        &[fee_row(1, token, "estimated")],
        1,
        token,
        None,
        policy,
        None,
    )
    .expect("candidates");
    let candidate = candidates[0].clone();
    let estimate = public_broadcaster_cost_estimate(candidate.clone());

    assert_eq!(
        WalletRoot::public_broadcaster_submission_selection(
            &BroadcasterChoice::Random,
            Some(&estimate),
        ),
        PublicBroadcasterSelection::Specific {
            railgun_address: candidate.railgun_address
        }
    );
}

#[test]
fn random_submission_selection_remains_random_without_estimate() {
    assert_eq!(
        WalletRoot::public_broadcaster_submission_selection(&BroadcasterChoice::Random, None),
        PublicBroadcasterSelection::Random
    );
}

#[test]
fn specific_submission_selection_ignores_estimate() {
    let token = Address::from([0x64; 20]);
    let policy = BroadcasterFeePolicy::default();
    let candidates = public_broadcaster_candidates_for_asset(
        &[fee_row(1, token, "estimated")],
        1,
        token,
        None,
        policy,
        None,
    )
    .expect("candidates");
    let estimate = public_broadcaster_cost_estimate(candidates[0].clone());
    let choice = BroadcasterChoice::Specific {
        railgun_address: "0zk-specific".to_string(),
    };

    assert_eq!(
        WalletRoot::public_broadcaster_submission_selection(&choice, Some(&estimate)),
        PublicBroadcasterSelection::Specific {
            railgun_address: "0zk-specific".to_string()
        }
    );
}

#[test]
fn different_fee_token_forces_add_mode_and_hides_toggle() {
    let action = Address::from([0x71; 20]);
    let fee = Address::from([0x72; 20]);

    assert_eq!(
        effective_public_broadcaster_fee_mode(
            action,
            fee,
            PublicBroadcasterFeeMode::DeductFromAmount,
        ),
        PublicBroadcasterFeeMode::AddToAmount
    );
    assert_eq!(
        effective_public_broadcaster_fee_mode(
            action,
            action,
            PublicBroadcasterFeeMode::DeductFromAmount,
        ),
        PublicBroadcasterFeeMode::DeductFromAmount
    );
    assert!(!should_show_broadcaster_fee_mode_toggle(action, fee));
    assert!(should_show_broadcaster_fee_mode_toggle(action, action));
}

#[test]
fn amount_adjustment_clamps_or_raises_only_at_mode_max() {
    assert_eq!(
        adjusted_amount_for_max_change(uint!(120_U256), Some(uint!(120_U256)), uint!(100_U256),),
        Some(uint!(100_U256))
    );
    assert_eq!(
        adjusted_amount_for_max_change(uint!(100_U256), Some(uint!(100_U256)), uint!(120_U256),),
        Some(uint!(120_U256))
    );
    assert_eq!(
        adjusted_amount_for_max_change(uint!(90_U256), Some(uint!(100_U256)), uint!(120_U256),),
        None
    );
}

#[test]
fn private_tab_is_default_wallet_tab() {
    assert_eq!(WalletTab::default(), WalletTab::Private);
}

#[test]
fn utxo_table_focus_is_activity_scoped() {
    let state = ChainUtxoState::Loading { progress: None };

    assert!(!should_focus_utxo_table(
        Activity::Wallet,
        WalletTab::Private,
        Some(&state)
    ));
    assert!(!should_focus_utxo_table(
        Activity::Broadcaster,
        WalletTab::Activity,
        Some(&state)
    ));
    assert!(should_focus_utxo_table(
        Activity::Wallet,
        WalletTab::Activity,
        Some(&state)
    ));
}

#[test]
fn startup_settings_load_defaults_without_persisting() {
    let root = temp_wallet_db_root("startup-defaults");
    let store = DesktopVaultStore::open(root.clone()).expect("open wallet store");

    let settings = load_validated_startup_settings(&store).expect("load startup settings");

    assert_eq!(
        settings.poi.read_source,
        PoiReadSourceSetting::IndexedArtifacts
    );
    assert!(
        store
            .db()
            .get_app_settings_record(WALLET_SETTINGS_KEY)
            .expect("read settings record")
            .is_none()
    );

    drop(store);
    fs::remove_dir_all(root).expect("remove temp wallet db");
}

#[test]
fn startup_settings_invalid_record_is_recoverable_error() {
    let root = temp_wallet_db_root("startup-invalid");
    let store = DesktopVaultStore::open(root.clone()).expect("open wallet store");
    let mut settings = WalletSettings::default();
    for chain in settings.chains.per_chain.values_mut() {
        chain.enabled = false;
    }
    let payload = encode_wallet_settings(&settings).expect("encode invalid settings");
    store
        .db()
        .put_app_settings_record(WALLET_SETTINGS_KEY, &payload)
        .expect("write invalid settings");

    let error = load_validated_startup_settings(&store).expect_err("settings should fail");
    let message = error.to_string();

    assert!(message.contains("wallet settings are invalid"));
    assert!(message.contains("at least one supported chain enabled"));

    drop(store);
    fs::remove_dir_all(root).expect("remove temp wallet db");
}

#[test]
fn wallet_app_options_preserve_cli_db_path() {
    let db_path = PathBuf::from("custom-wallet-db");
    let options = WalletAppOptions::try_from(crate::cli::Options {
        db_path: Some(db_path.clone()),
    })
    .expect("options");

    assert_eq!(options.db_path, db_path);
}

#[test]
fn settings_sidebar_order_places_settings_after_broadcasters() {
    assert_eq!(
        sidebar_primary_activity_order(),
        [Activity::Wallet, Activity::Broadcaster, Activity::Settings]
    );
}

#[test]
fn locked_vault_screen_exposes_pre_unlock_settings_action() {
    assert!(should_show_pre_unlock_settings_action(
        &VaultState::CreateVault
    ));
    assert!(should_show_pre_unlock_settings_action(
        &VaultState::UnlockVault
    ));
    assert!(should_show_pre_unlock_settings_action(
        &VaultState::SetupWallet
    ));
    assert!(!should_show_pre_unlock_settings_action(
        &VaultState::ViewUnlocked
    ));
}

#[test]
fn startup_pre_unlock_state_exposes_settings_and_error_recovery() {
    assert_eq!(
        startup_settings_action_state(true),
        super::StartupSettingsActionState {
            settings: true,
            reset: true,
            retry: true,
        }
    );
    assert_eq!(
        startup_settings_action_state(false),
        super::StartupSettingsActionState {
            settings: true,
            reset: false,
            retry: false,
        }
    );
}

#[test]
fn settings_apply_classifier_tracks_restart_and_request_changes() {
    let saved = WalletSettings::default();
    assert_eq!(
        classify_settings_apply_mode(&saved, &saved),
        SettingsApplyMode::Clean
    );

    let mut network_draft = saved.clone();
    network_draft.network.mode = NetworkModeSetting::Direct;
    assert_eq!(
        classify_settings_apply_mode(&saved, &network_draft),
        SettingsApplyMode::NetworkingRestart
    );

    let mut request_draft = saved.clone();
    request_draft.broadcaster.response_timeout_secs += 1;
    assert_eq!(
        classify_settings_apply_mode(&saved, &request_draft),
        SettingsApplyMode::NewRequests
    );

    let mut session_draft = saved.clone();
    session_draft.runtime.public_balance_refresh_interval_secs += 1;
    assert_eq!(
        classify_settings_apply_mode(&saved, &session_draft),
        SettingsApplyMode::FutureSessions
    );
}

#[test]
fn settings_save_action_requires_restart_for_networking_changes() {
    let saved = WalletSettings::default();
    let mut network_draft = saved.clone();
    network_draft.network.mode = NetworkModeSetting::Direct;
    assert!(!settings_save_action_enabled(&saved, &network_draft, false));
    assert!(settings_restart_action_enabled(
        &saved,
        &network_draft,
        false
    ));

    let mut request_draft = saved.clone();
    request_draft.broadcaster.response_timeout_secs += 1;
    assert!(settings_save_action_enabled(&saved, &request_draft, false));
    assert!(settings_restart_action_enabled(
        &saved,
        &request_draft,
        false
    ));

    assert!(!settings_save_action_enabled(&saved, &request_draft, true));
    assert!(!settings_restart_action_enabled(
        &saved,
        &request_draft,
        true
    ));
}

#[test]
fn anchor_bps_formatting_shows_percent_and_exact_bps() {
    assert_eq!(format_anchor_bps_percent(9_000), "90%");
    assert_eq!(format_anchor_bps_percent(9_050), "90.5%");
    assert_eq!(format_anchor_bps_percent(9_055), "90.55%");
    assert_eq!(
        format_anchor_bps_percent_range(9_000, 15_000),
        "90% - 150% of price anchor"
    );
    assert_eq!(
        format_anchor_premium_range(9_000, 15_000),
        "Allows -10% to +50% vs anchor"
    );
    assert_eq!(
        format_anchor_bps_exact_range(9_000, 15_000),
        "9,000 - 15,000 bps"
    );
}

#[test]
fn settings_restart_reuses_network_only_when_network_settings_are_unchanged() {
    let saved = WalletSettings::default();

    let mut waku_draft = saved.clone();
    waku_draft.waku.max_peers += 1;
    assert!(settings_restart_reuses_active_network(&saved, &waku_draft));

    let mut poi_draft = saved.clone();
    poi_draft.poi.read_source = PoiReadSourceSetting::PoiProxy;
    assert!(settings_restart_reuses_active_network(&saved, &poi_draft));

    let mut network_draft = saved.clone();
    network_draft.network.mode = NetworkModeSetting::Direct;
    assert!(!settings_restart_reuses_active_network(
        &saved,
        &network_draft
    ));
}

#[test]
fn proxy_url_setting_only_shows_for_proxy_mode() {
    assert!(!should_show_proxy_url_setting(NetworkModeSetting::Tor));
    assert!(should_show_proxy_url_setting(NetworkModeSetting::Proxy));
    assert!(!should_show_proxy_url_setting(NetworkModeSetting::Direct));
}

#[test]
fn proxy_waku_disclaimer_only_shows_for_proxy_mode() {
    assert!(!should_show_proxy_waku_disclaimer(NetworkModeSetting::Tor));
    assert!(should_show_proxy_waku_disclaimer(NetworkModeSetting::Proxy));
    assert!(!should_show_proxy_waku_disclaimer(
        NetworkModeSetting::Direct
    ));
}

#[test]
fn waku_doh_settings_display_presets_until_customized() {
    let settings = WalletSettings::default();

    assert_eq!(
        display_waku_doh_endpoint(&settings),
        DEFAULT_TOR_DOH_ENDPOINT
    );
    assert_eq!(
        display_waku_doh_fallback_endpoints(&settings),
        vec![DEFAULT_DOH_ENDPOINT.to_string()]
    );
    assert!(settings.waku.doh_endpoint.is_none());
    assert!(settings.waku.doh_fallback_endpoints.is_none());

    let mut direct = settings.clone();
    direct.network.mode = NetworkModeSetting::Direct;
    assert_eq!(display_waku_doh_endpoint(&direct), DEFAULT_DOH_ENDPOINT);
    assert!(display_waku_doh_fallback_endpoints(&direct).is_empty());

    let mut proxy = settings.clone();
    proxy.network.mode = NetworkModeSetting::Proxy;
    proxy.network.proxy_url = Some("socks5h://127.0.0.1:9050".to_string());
    assert_eq!(display_waku_doh_endpoint(&proxy), DEFAULT_DOH_ENDPOINT);
    assert!(display_waku_doh_fallback_endpoints(&proxy).is_empty());

    let mut custom = settings;
    custom.waku.doh_endpoint = Some("https://doh.example.invalid/dns-query".to_string());
    assert_eq!(
        display_waku_doh_endpoint(&custom),
        "https://doh.example.invalid/dns-query"
    );
    assert_eq!(
        display_waku_doh_fallback_endpoints(&custom),
        vec![DEFAULT_DOH_ENDPOINT.to_string()]
    );
}

#[test]
fn waku_doh_fallback_mutations_materialize_presets() {
    let mut settings = WalletSettings::default();

    remove_waku_doh_fallback_endpoint(&mut settings, 0);
    assert_eq!(settings.waku.doh_fallback_endpoints, Some(Vec::new()));
    assert!(display_waku_doh_fallback_endpoints(&settings).is_empty());

    add_waku_doh_fallback_endpoint(&mut settings, " https://fallback.example/dns-query ");
    assert_eq!(
        settings.waku.doh_fallback_endpoints.as_deref(),
        Some(["https://fallback.example/dns-query".to_string()].as_slice())
    );

    set_waku_doh_fallback_endpoint(&mut settings, 0, " https://edited.example/dns-query ");
    assert_eq!(
        settings.waku.doh_fallback_endpoints.as_deref(),
        Some(["https://edited.example/dns-query".to_string()].as_slice())
    );
}

#[test]
fn waku_dns_enr_tree_settings_display_presets_until_customized() {
    let mut settings = WalletSettings::default();

    assert_eq!(
        display_waku_dns_enr_trees(&settings),
        default_waku_dns_enr_trees()
    );
    assert!(settings.waku.dns_enr_trees.is_none());

    remove_waku_dns_enr_tree(&mut settings, 0);
    assert_eq!(settings.waku.dns_enr_trees, Some(Vec::new()));
    assert!(display_waku_dns_enr_trees(&settings).is_empty());

    add_waku_dns_enr_tree(&mut settings, " enrtree://custom@example.invalid ");
    assert_eq!(
        settings.waku.dns_enr_trees.as_deref(),
        Some(["enrtree://custom@example.invalid".to_string()].as_slice())
    );

    set_waku_dns_enr_tree(&mut settings, 0, " enrtree://edited@example.invalid ");
    assert_eq!(
        settings.waku.dns_enr_trees.as_deref(),
        Some(["enrtree://edited@example.invalid".to_string()].as_slice())
    );
}

#[test]
fn waku_direct_peer_settings_mutations_update_rows() {
    let mut settings = WalletSettings::default();
    assert_eq!(
        display_waku_direct_peers(&settings),
        default_waku_direct_peers()
    );
    assert!(settings.waku.direct_peers.is_none());

    remove_waku_direct_peer(&mut settings, 0);
    assert_eq!(settings.waku.direct_peers, Some(Vec::new()));
    assert!(display_waku_direct_peers(&settings).is_empty());

    let first = WakuDirectPeerSetting {
        peer_id: "16Uiu2HAkwNeQVY32bUrL1eM68ryMa48PXY5Bhfxfg9e2byYcc46m".to_string(),
        addr: "/dns4/prod.rootedinprivacy.com/tcp/30304/p2p/16Uiu2HAkwNeQVY32bUrL1eM68ryMa48PXY5Bhfxfg9e2byYcc46m".to_string(),
    };
    let edited = WakuDirectPeerSetting {
        peer_id: first.peer_id.clone(),
        addr: "/dns4/prod.rootedinprivacy.com/tcp/8000/wss/p2p/16Uiu2HAkwNeQVY32bUrL1eM68ryMa48PXY5Bhfxfg9e2byYcc46m".to_string(),
    };

    add_waku_direct_peer(&mut settings, first);
    assert_eq!(display_waku_direct_peers(&settings).len(), 1);

    set_waku_direct_peer(&mut settings, 0, edited.clone());
    assert_eq!(settings.waku.direct_peers, Some(vec![edited]));

    remove_waku_direct_peer(&mut settings, 0);
    assert_eq!(settings.waku.direct_peers, Some(Vec::new()));
}

#[test]
fn chain_rpc_settings_display_presets_until_customized() {
    let settings = WalletSettings::default();
    for chain_id in railgun_ui::DEFAULT_CHAINS {
        assert_eq!(
            display_chain_rpc_endpoints(&settings, *chain_id),
            default_chain_rpc_endpoints(*chain_id).expect("supported chain preset")
        );
        assert!(
            settings
                .chains
                .per_chain
                .get(chain_id)
                .is_some_and(|chain| chain.rpc_endpoints.is_empty())
        );
    }

    let mut custom = settings;
    custom.chains.per_chain.entry(1).or_default().rpc_endpoints = vec![
        "https://rpc-one.example".to_string(),
        "https://rpc-two.example".to_string(),
    ];

    assert_eq!(
        display_chain_rpc_endpoints(&custom, 1),
        vec![
            "https://rpc-one.example".to_string(),
            "https://rpc-two.example".to_string()
        ]
    );
}

#[test]
fn chain_rpc_settings_mutations_materialize_presets() {
    let mut settings = WalletSettings::default();
    let defaults = default_chain_rpc_endpoints(1).expect("supported chain preset");

    set_chain_rpc_endpoint(&mut settings, 1, 0, " https://custom-rpc.example ");
    let endpoints = &settings
        .chains
        .per_chain
        .get(&1)
        .expect("chain settings")
        .rpc_endpoints;
    assert_eq!(endpoints.len(), defaults.len());
    assert_eq!(endpoints[0], "https://custom-rpc.example");

    add_chain_rpc_endpoint(&mut settings, 1, " https://added-rpc.example ");
    let endpoints = &settings
        .chains
        .per_chain
        .get(&1)
        .expect("chain settings")
        .rpc_endpoints;
    assert_eq!(endpoints.len(), defaults.len() + 1);
    assert_eq!(endpoints.last().unwrap(), "https://added-rpc.example");

    remove_chain_rpc_endpoint(&mut settings, 1, 1);
    assert_eq!(
        settings
            .chains
            .per_chain
            .get(&1)
            .expect("chain settings")
            .rpc_endpoints
            .len(),
        defaults.len()
    );
}

#[test]
fn chain_rpc_settings_remove_default_creates_custom_override() {
    let mut settings = WalletSettings::default();
    let defaults = default_chain_rpc_endpoints(1).expect("supported chain preset");

    remove_chain_rpc_endpoint(&mut settings, 1, 0);

    let expected = defaults.into_iter().skip(1).collect::<Vec<_>>();
    assert_eq!(display_chain_rpc_endpoints(&settings, 1), expected);
}

#[test]
fn poi_gateway_settings_mutations_update_direct_list() {
    let mut settings = WalletSettings::default();
    settings.poi.artifact.gateway_urls = vec![
        "https://gateway-one.example".to_string(),
        "https://gateway-two.example".to_string(),
    ];

    set_poi_gateway_url(&mut settings, 0, " https://edited-gateway.example ");
    add_poi_gateway_url(&mut settings, " https://added-gateway.example ");
    remove_poi_gateway_url(&mut settings, 1);
    remove_poi_gateway_url(&mut settings, 10);

    assert_eq!(
        settings.poi.artifact.gateway_urls,
        vec![
            "https://edited-gateway.example".to_string(),
            "https://added-gateway.example".to_string(),
        ]
    );
}

#[test]
fn chain_quick_sync_setting_displays_preset_until_customized() {
    let settings = WalletSettings::default();
    for chain_id in railgun_ui::DEFAULT_CHAINS {
        assert_eq!(
            display_chain_quick_sync_endpoint(&settings, *chain_id),
            default_chain_quick_sync_endpoint(*chain_id).unwrap_or_default()
        );
    }

    let mut custom = settings;
    custom
        .chains
        .per_chain
        .entry(1)
        .or_default()
        .quick_sync
        .endpoint = Some("https://quick.example/graphql".to_string());

    assert_eq!(
        display_chain_quick_sync_endpoint(&custom, 1),
        "https://quick.example/graphql"
    );
}

#[test]
fn chain_contract_settings_display_presets_until_customized() {
    let settings = WalletSettings::default();
    for chain_id in railgun_ui::DEFAULT_CHAINS {
        assert_eq!(
            display_chain_contract_settings(&settings, *chain_id),
            default_chain_contract_settings(*chain_id).expect("supported chain preset")
        );
        assert!(
            settings
                .chains
                .per_chain
                .get(chain_id)
                .is_some_and(|chain| chain.contracts.railgun_contract.is_none())
        );
    }

    let mut custom = settings;
    custom
        .chains
        .per_chain
        .entry(1)
        .or_default()
        .contracts
        .multicall_contract = Some("0x0000000000000000000000000000000000000001".to_string());

    let displayed = display_chain_contract_settings(&custom, 1);
    let defaults = default_chain_contract_settings(1).expect("ethereum preset");
    assert_eq!(displayed.railgun_contract, defaults.railgun_contract);
    assert_eq!(
        displayed.multicall_contract.as_deref(),
        Some("0x0000000000000000000000000000000000000001")
    );
}

#[test]
fn settings_discard_reverts_relay_adapter_7702_display_value() {
    let saved = WalletSettings::default();
    let mut draft = saved.clone();
    draft
        .chains
        .per_chain
        .entry(1)
        .or_default()
        .contracts
        .relay_adapt_7702_contract = Some("0x0000000000000000000000000000000000000001".to_string());
    assert_eq!(
        display_chain_contract_settings(&draft, 1)
            .relay_adapt_7702_contract
            .as_deref(),
        Some("0x0000000000000000000000000000000000000001")
    );

    let discarded = settings_draft_after_discard(&saved);
    assert_eq!(
        display_chain_contract_settings(&discarded, 1).relay_adapt_7702_contract,
        default_chain_contract_settings(1)
            .expect("ethereum preset")
            .relay_adapt_7702_contract
    );
}

#[test]
fn settings_discard_restores_saved_snapshot() {
    let mut saved = WalletSettings::default();
    saved.network.mode = NetworkModeSetting::Direct;
    let mut draft = saved.clone();
    draft.broadcaster.response_timeout_secs += 1;

    assert_ne!(draft, saved);
    assert_eq!(settings_draft_after_discard(&saved), saved);
}

#[test]
fn token_settings_display_includes_built_in_defaults() {
    let settings = WalletSettings::default();
    let entries = display_token_entries(&settings);

    let weth = entries
        .iter()
        .find(|entry| {
            entry.chain_id == 1
                && entry
                    .token_address
                    .eq_ignore_ascii_case("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
        })
        .expect("ethereum WETH default token");
    assert!(weth.built_in);
    assert_eq!(weth.symbol, "WETH");
    assert_eq!(weth.decimals, 18);
}

#[test]
fn price_anchor_settings_display_includes_built_in_defaults() {
    let settings = WalletSettings::default();
    let entries = display_price_anchor_entries(&settings);

    let weth = entries
        .iter()
        .find(|entry| {
            entry.key.chain_id == 1
                && entry
                    .key
                    .token_address
                    .eq_ignore_ascii_case("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
        })
        .expect("ethereum WETH default price anchor");
    assert!(weth.built_in_default);
    assert_eq!(
        weth.price_anchor,
        PriceAnchorSettings::Fixed {
            rate: "1000000000000000000".to_string(),
        }
    );
    assert!(settings.tokens.price_anchors.is_empty());
}

#[test]
fn price_anchor_settings_display_overrides_built_in_defaults() {
    let mut settings = WalletSettings::default();
    settings
        .tokens
        .price_anchors
        .push(TokenPriceAnchorOverride {
            key: TokenKey {
                chain_id: 1,
                token_address: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".to_string(),
            },
            price_anchor: PriceAnchorSettings::Fixed {
                rate: "2000000000000000000".to_string(),
            },
        });

    let entries = display_price_anchor_entries(&settings);
    let weth = entries
        .iter()
        .find(|entry| {
            entry.key.chain_id == 1
                && entry
                    .key
                    .token_address
                    .eq_ignore_ascii_case("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
        })
        .expect("ethereum WETH price anchor");

    assert!(!weth.built_in_default);
    assert_eq!(
        weth.price_anchor,
        PriceAnchorSettings::Fixed {
            rate: "2000000000000000000".to_string(),
        }
    );

    settings.tokens.price_anchors.clear();
    let entries = display_price_anchor_entries(&settings);
    let weth = entries
        .iter()
        .find(|entry| {
            entry.key.chain_id == 1
                && entry
                    .key
                    .token_address
                    .eq_ignore_ascii_case("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
        })
        .expect("ethereum WETH default price anchor");
    assert!(weth.built_in_default);
}

#[test]
fn price_anchor_view_uses_token_symbol_when_available() {
    let settings = WalletSettings::default();
    let entries = display_price_anchor_entries(&settings);

    let weth = entries
        .iter()
        .find(|entry| {
            entry.key.chain_id == 1
                && entry
                    .key
                    .token_address
                    .eq_ignore_ascii_case("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
        })
        .expect("ethereum WETH default price anchor");

    assert_eq!(weth.token_symbol.as_deref(), Some("WETH"));
    assert_eq!(price_anchor_token_primary_label(weth), "WETH");
}

#[test]
fn price_anchor_view_falls_back_to_short_address_without_symbol() {
    let token = Address::from([0x22; 20]);
    let mut settings = WalletSettings::default();
    settings
        .tokens
        .price_anchors
        .push(TokenPriceAnchorOverride {
            key: TokenKey {
                chain_id: 1,
                token_address: token.to_string(),
            },
            price_anchor: PriceAnchorSettings::Fixed {
                rate: "1".to_string(),
            },
        });

    let entries = display_price_anchor_entries(&settings);
    let entry = entries
        .iter()
        .find(|entry| {
            entry
                .key
                .token_address
                .eq_ignore_ascii_case(&token.to_string())
        })
        .expect("unknown token price anchor");

    assert_eq!(entry.token_symbol, None);
    assert_eq!(
        price_anchor_token_primary_label(entry),
        railgun_ui::short_address(&token)
    );
}

#[test]
fn price_anchor_edit_prefills_dialog_values() {
    let settings = WalletSettings::default();
    let entries = display_price_anchor_entries(&settings);
    let weth = entries
        .iter()
        .find(|entry| {
            entry.key.chain_id == 1
                && entry
                    .key
                    .token_address
                    .eq_ignore_ascii_case("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
        })
        .expect("ethereum WETH default price anchor");

    let values = price_anchor_dialog_values_from_entry(weth);

    assert_eq!(values.chain_id, 1);
    assert_eq!(values.token_address, weth.key.token_address);
    assert_eq!(values.anchor_type, "fixed");
    assert_eq!(values.fixed_rate, "1000000000000000000");
}

#[test]
fn price_anchor_edit_builtin_default_creates_sparse_override() {
    let mut settings = WalletSettings::default();
    let entry = display_price_anchor_entries(&settings)
        .into_iter()
        .find(|entry| {
            entry.key.chain_id == 1
                && entry
                    .key
                    .token_address
                    .eq_ignore_ascii_case("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
        })
        .expect("ethereum WETH default price anchor");
    let edited = TokenPriceAnchorOverride {
        key: entry.key.clone(),
        price_anchor: PriceAnchorSettings::Fixed {
            rate: "3000000000000000000".to_string(),
        },
    };

    set_price_anchor_override(&mut settings, &entry, edited);

    assert_eq!(settings.tokens.price_anchors.len(), 1);
    let updated = display_price_anchor_entries(&settings)
        .into_iter()
        .find(|entry| {
            entry.key.chain_id == 1
                && entry
                    .key
                    .token_address
                    .eq_ignore_ascii_case("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
        })
        .expect("ethereum WETH edited price anchor");
    assert!(!updated.built_in_default);
    assert_eq!(
        updated.price_anchor,
        PriceAnchorSettings::Fixed {
            rate: "3000000000000000000".to_string(),
        }
    );
}

#[test]
fn price_anchor_edit_override_replaces_existing_override() {
    let mut settings = WalletSettings::default();
    settings
        .tokens
        .price_anchors
        .push(TokenPriceAnchorOverride {
            key: TokenKey {
                chain_id: 1,
                token_address: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".to_string(),
            },
            price_anchor: PriceAnchorSettings::Fixed {
                rate: "2000000000000000000".to_string(),
            },
        });
    let entry = display_price_anchor_entries(&settings)
        .into_iter()
        .find(|entry| {
            entry.key.chain_id == 1
                && entry
                    .key
                    .token_address
                    .eq_ignore_ascii_case("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
        })
        .expect("ethereum WETH override price anchor");

    set_price_anchor_override(
        &mut settings,
        &entry,
        TokenPriceAnchorOverride {
            key: entry.key.clone(),
            price_anchor: PriceAnchorSettings::Fixed {
                rate: "4000000000000000000".to_string(),
            },
        },
    );

    assert_eq!(settings.tokens.price_anchors.len(), 1);
    assert_eq!(
        settings.tokens.price_anchors[0].price_anchor,
        PriceAnchorSettings::Fixed {
            rate: "4000000000000000000".to_string(),
        }
    );
}

#[test]
fn price_anchor_add_dialog_values_create_override_without_mutating_settings() {
    let settings = WalletSettings::default();

    let anchor = price_anchor_override_from_dialog_values(&PriceAnchorDialogValues {
        chain_id: 42161,
        token_address: " 0x0000000000000000000000000000000000000002 ".to_string(),
        anchor_type: "oracle",
        fixed_rate: "1000000000000000000".to_string(),
        oracle_chain_id: 1,
        oracle_address: " 0x0000000000000000000000000000000000000003 ".to_string(),
        oracle_token_decimals: "6".to_string(),
        oracle_decimals: "8".to_string(),
        oracle_is_inversed: true,
        product_scale_decimals: "18".to_string(),
        product_components: test_product_anchor_components(),
    })
    .expect("valid add price anchor dialog values");

    assert!(settings.tokens.price_anchors.is_empty());
    assert_eq!(anchor.key.chain_id, 42161);
    assert_eq!(
        anchor.key.token_address,
        "0x0000000000000000000000000000000000000002"
    );
    assert!(matches!(
        anchor.price_anchor,
        PriceAnchorSettings::Oracle {
            chain_id: 1,
            token_decimals: 6,
            oracle_decimals: 8,
            is_inversed: true,
            ref oracle_address,
            ..
        } if oracle_address == "0x0000000000000000000000000000000000000003"
    ));
}

#[test]
fn price_anchor_add_dialog_values_create_product_override() {
    let anchor = price_anchor_override_from_dialog_values(&PriceAnchorDialogValues {
        chain_id: 1,
        token_address: "0x0000000000000000000000000000000000000002".to_string(),
        anchor_type: "product",
        fixed_rate: "1000000000000000000".to_string(),
        oracle_chain_id: 1,
        oracle_address: "0x0000000000000000000000000000000000000003".to_string(),
        oracle_token_decimals: "18".to_string(),
        oracle_decimals: "8".to_string(),
        oracle_is_inversed: false,
        product_scale_decimals: "12".to_string(),
        product_components: vec![
            PriceAnchorComponentDialogValues {
                anchor_type: "oracle",
                fixed_rate: "1000000000000000000".to_string(),
                oracle_chain_id: 42161,
                oracle_address: "0x0000000000000000000000000000000000000004".to_string(),
                oracle_token_decimals: "18".to_string(),
                oracle_decimals: "8".to_string(),
                oracle_is_inversed: false,
            },
            PriceAnchorComponentDialogValues {
                anchor_type: "oracle",
                fixed_rate: "1000000000000000000".to_string(),
                oracle_chain_id: 42161,
                oracle_address: "0x0000000000000000000000000000000000000005".to_string(),
                oracle_token_decimals: "18".to_string(),
                oracle_decimals: "8".to_string(),
                oracle_is_inversed: true,
            },
        ],
    })
    .expect("valid product price anchor dialog values");

    assert!(matches!(
        anchor.price_anchor,
        PriceAnchorSettings::Product {
            scale_decimals: 12,
            ref components,
        } if matches!(
            components.as_slice(),
            [
                PriceAnchorSettings::Oracle {
                    chain_id: 42161,
                    oracle_decimals: 8,
                    is_inversed: false,
                    ..
                },
                PriceAnchorSettings::Oracle {
                    chain_id: 42161,
                    oracle_decimals: 8,
                    is_inversed: true,
                    ..
                },
            ]
        )
    ));
}

#[test]
fn price_anchor_add_dialog_values_reject_invalid_anchor_type() {
    let err = price_anchor_override_from_dialog_values(&PriceAnchorDialogValues {
        chain_id: 1,
        token_address: "0x0000000000000000000000000000000000000002".to_string(),
        anchor_type: "bad",
        fixed_rate: "1000000000000000000".to_string(),
        oracle_chain_id: 1,
        oracle_address: "0x0000000000000000000000000000000000000003".to_string(),
        oracle_token_decimals: "18".to_string(),
        oracle_decimals: "8".to_string(),
        oracle_is_inversed: false,
        product_scale_decimals: "18".to_string(),
        product_components: test_product_anchor_components(),
    })
    .expect_err("bad anchor type rejected");

    assert!(err.contains("fixed, oracle, or product"));
}

fn test_product_anchor_components() -> Vec<PriceAnchorComponentDialogValues> {
    vec![
        PriceAnchorComponentDialogValues {
            anchor_type: "oracle",
            fixed_rate: "1000000000000000000".to_string(),
            oracle_chain_id: 1,
            oracle_address: "0x0000000000000000000000000000000000000003".to_string(),
            oracle_token_decimals: "18".to_string(),
            oracle_decimals: "8".to_string(),
            oracle_is_inversed: false,
        },
        PriceAnchorComponentDialogValues {
            anchor_type: "oracle",
            fixed_rate: "1000000000000000000".to_string(),
            oracle_chain_id: 1,
            oracle_address: "0x0000000000000000000000000000000000000004".to_string(),
            oracle_token_decimals: "18".to_string(),
            oracle_decimals: "8".to_string(),
            oracle_is_inversed: true,
        },
    ]
}

#[test]
fn token_settings_display_applies_builtin_overrides_and_custom_tokens() {
    let custom = Address::from([0x77; 20]);
    let mut settings = WalletSettings::default();
    settings
        .tokens
        .built_in_overrides
        .push(BuiltInTokenOverride {
            key: TokenKey {
                chain_id: 1,
                token_address: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".to_string(),
            },
            symbol: Some("WETHx".to_string()),
            decimals: Some(17),
            icon_path: None,
            price_anchor: None,
        });
    settings.tokens.custom_tokens.push(CustomTokenSettings {
        chain_id: 1,
        token_address: custom.to_string(),
        symbol: "TST".to_string(),
        decimals: 4,
        icon_path: None,
        price_anchor: None,
    });

    let entries = display_token_entries(&settings);

    let overridden = entries
        .iter()
        .find(|entry| entry.chain_id == 1 && entry.symbol == "WETHx")
        .expect("overridden built-in token");
    assert!(overridden.built_in);
    assert_eq!(overridden.decimals, 17);

    let custom = entries
        .iter()
        .find(|entry| entry.chain_id == 1 && entry.symbol == "TST")
        .expect("custom token");
    assert!(!custom.built_in);
    assert_eq!(custom.decimals, 4);
}

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

    let rows = format_private_asset_rows(1, &totals, Some(&registry));

    assert_eq!(rows[0].label, "TST");
    assert_eq!(rows[0].amount, "1.23");
    assert_eq!(rows[0].decimals, Some(4));
    assert_eq!(
        rows[0].icon_path.as_deref(),
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
        public_asset_icon_path(1, PublicAssetId::Erc20(token), Some(&registry)).as_deref(),
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

    let rows = format_private_asset_rows(1, &totals, None);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].label, "USDC");
    assert_eq!(rows[0].amount, "1.23");
    assert_eq!(rows[0].pending_poi_amount, "0.23457");
    assert_eq!(rows[0].pending_poi_total, Some(uint!(234_567_U256)));
    assert!(should_show_pending_poi_amount(rows[0].pending_poi_total));
    assert!(rows[0].icon_path.is_some());
}

#[test]
fn private_asset_rows_hide_zero_pending_poi() {
    let totals = [wallet_ops::TokenTotal {
        token: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
        total: "1234567".to_string(),
        poi_verified_total: "1234567".to_string(),
    }];

    let rows = format_private_asset_rows(1, &totals, None);

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

    let rows = format_private_asset_rows_from_snapshot(&snapshot, None);

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

    let rows = format_private_asset_rows_from_snapshot(&snapshot, None);

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

#[test]
fn private_broadcaster_progress_stage_marks_prior_steps_done() {
    let mut steps = private_broadcaster_progress_steps();

    apply_private_broadcaster_progress_stage(
        &mut steps,
        TransactionGenerationStage::EstimatingBroadcasterFee,
    );

    let statuses = steps.iter().map(|step| step.status).collect::<Vec<_>>();
    assert_eq!(
        statuses,
        vec![
            PublicActionStepStatus::Done,
            PublicActionStepStatus::Done,
            PublicActionStepStatus::Pending,
            PublicActionStepStatus::NotStarted,
            PublicActionStepStatus::NotStarted,
            PublicActionStepStatus::NotStarted,
        ]
    );
}

#[test]
fn private_broadcaster_progress_submitted_marks_all_steps_done() {
    let mut steps = private_broadcaster_progress_steps();
    apply_private_broadcaster_progress_stage(
        &mut steps,
        TransactionGenerationStage::WaitingForBroadcasterResponse,
    );

    finish_private_broadcaster_progress_steps(
        &mut steps,
        &PublicBroadcasterResultKind::Submitted {
            tx_hash: "0xabc".to_string(),
        },
    );

    assert!(
        steps
            .iter()
            .all(|step| step.status == PublicActionStepStatus::Done)
    );
}

#[test]
fn private_broadcaster_progress_timeout_marks_waiting_step_error() {
    let mut steps = private_broadcaster_progress_steps();
    apply_private_broadcaster_progress_stage(
        &mut steps,
        TransactionGenerationStage::WaitingForBroadcasterResponse,
    );

    finish_private_broadcaster_progress_steps(&mut steps, &PublicBroadcasterResultKind::TimedOut);

    assert_eq!(
        steps.last().map(|step| step.status),
        Some(PublicActionStepStatus::Error)
    );
    assert!(
        steps
            .last()
            .and_then(|step| step.message.as_ref())
            .is_some()
    );
}

#[test]
fn private_broadcaster_terminal_failure_applies_latest_stage() {
    let mut steps = private_broadcaster_progress_steps();

    fail_private_broadcaster_progress_steps_at_stage(
        &mut steps,
        TransactionGenerationStage::PublishingToBroadcaster,
        "publish failed",
    );

    let statuses = steps.iter().map(|step| step.status).collect::<Vec<_>>();
    assert_eq!(
        statuses,
        vec![
            PublicActionStepStatus::Done,
            PublicActionStepStatus::Done,
            PublicActionStepStatus::Done,
            PublicActionStepStatus::Done,
            PublicActionStepStatus::Error,
            PublicActionStepStatus::NotStarted,
        ]
    );
    assert_eq!(steps[4].message.as_deref(), Some("publish failed"));
}

#[test]
fn private_broadcaster_terminal_result_applies_latest_stage_before_timeout() {
    let mut steps = private_broadcaster_progress_steps();

    finish_private_broadcaster_progress_steps_at_stage(
        &mut steps,
        TransactionGenerationStage::WaitingForBroadcasterResponse,
        &PublicBroadcasterResultKind::TimedOut,
    );

    assert_eq!(
        steps.last().map(|step| step.status),
        Some(PublicActionStepStatus::Error)
    );
    assert!(
        steps[..steps.len() - 1]
            .iter()
            .all(|step| step.status == PublicActionStepStatus::Done)
    );
}

#[test]
fn closed_private_broadcaster_progress_exposes_active_stage() {
    let key = UnshieldAssetKey::new(1, Address::from([0x11; 20]));
    let mut progress = PrivateBroadcasterProgressState {
        kind: DeliveryFormKind::Send,
        key,
        generation_id: 7,
        asset_label: Arc::from("ETH"),
        icon_path: None,
        recipient: Arc::from("0zk"),
        steps: private_broadcaster_progress_steps(),
        estimate: None,
        result: None,
        error: None,
        dialog_open: false,
        stage_seen: false,
    };
    assert_eq!(
        private_broadcaster_closed_active_stage(Some(&progress), DeliveryFormKind::Send, key, 7,),
        None
    );
    apply_private_broadcaster_progress_stage(
        &mut progress.steps,
        TransactionGenerationStage::PublishingToBroadcaster,
    );
    progress.stage_seen = true;

    assert_eq!(
        private_broadcaster_closed_active_stage(Some(&progress), DeliveryFormKind::Send, key, 7,),
        Some(TransactionGenerationStage::PublishingToBroadcaster)
    );

    progress.dialog_open = true;
    assert_eq!(
        private_broadcaster_closed_active_stage(Some(&progress), DeliveryFormKind::Send, key, 7,),
        None
    );

    progress.dialog_open = false;
    progress.error = Some(Arc::from("failed"));
    assert_eq!(
        private_broadcaster_closed_active_stage(Some(&progress), DeliveryFormKind::Send, key, 7,),
        None
    );
}

#[test]
fn private_action_metrics_hide_values_matching_total() {
    let token = Address::from([0x11; 20]);
    let mut asset = UnshieldAsset {
        chain_id: 1,
        token,
        label: "WETH".to_string(),
        decimals: Some(18),
        total: uint!(10_U256),
        poi_verified_total: uint!(10_U256),
        max_batched: uint!(10_U256),
        icon_path: None,
    };

    assert_eq!(
        private_action_metrics(&asset),
        vec![PrivateActionMetric {
            label: "Total private balance",
            amount: uint!(10_U256),
        }]
    );

    asset.poi_verified_total = uint!(7_U256);
    assert_eq!(
        private_action_metrics(&asset),
        vec![
            PrivateActionMetric {
                label: "Total private balance",
                amount: uint!(10_U256),
            },
            PrivateActionMetric {
                label: "POI-verified balance",
                amount: uint!(7_U256),
            },
        ]
    );

    asset.poi_verified_total = asset.total;
    asset.max_batched = uint!(8_U256);
    assert_eq!(
        private_action_metrics(&asset),
        vec![
            PrivateActionMetric {
                label: "Total private balance",
                amount: uint!(10_U256),
            },
            PrivateActionMetric {
                label: "Max batched transaction",
                amount: uint!(8_U256),
            },
        ]
    );
}

#[test]
fn native_wrapped_output_labels_are_chain_specific() {
    assert_eq!(native_wrapped_output_labels(1), Some(("ETH", "WETH")));
    assert_eq!(native_wrapped_output_labels(56), Some(("BNB", "WBNB")));
    assert_eq!(native_wrapped_output_labels(137), Some(("MATIC", "WMATIC")));
    assert_eq!(native_wrapped_output_labels(42161), Some(("ETH", "WETH")));
    assert_eq!(native_wrapped_output_labels(999_999), None);
}

#[test]
fn native_gas_cost_display_uses_base_token_label() {
    assert_eq!(native_token_display_label(1), "ETH");
    assert_eq!(native_token_display_label(999_999), "base token");
    assert_eq!(
        format_native_token_amount_for_display(1, uint!(1_500_000_000_000_000_U256)),
        "0.0015 ETH"
    );
}

#[test]
fn public_account_default_label_number_uses_account_count() {
    assert_eq!(next_public_account_label_number(0), 1);
    assert_eq!(next_public_account_label_number(2), 3);
    assert_eq!(next_public_account_label_number(usize::MAX), u32::MAX);
}

#[test]
fn public_broadcaster_fee_margin_display_is_signed_fee_token_amount() {
    let usdc = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
        .parse::<Address>()
        .expect("usdc address");

    assert_eq!(
        format_public_broadcaster_fee_margin(
            1,
            usdc,
            PublicBroadcasterFeeMargin::Positive(uint!(123_456_U256)),
            None,
        ),
        "0.123456 USDC"
    );
    assert_eq!(
        format_public_broadcaster_fee_margin(
            1,
            usdc,
            PublicBroadcasterFeeMargin::Negative(uint!(42_U256)),
            None,
        ),
        "-0.000042 USDC"
    );
    assert_eq!(
        format_public_broadcaster_fee_margin(1, usdc, PublicBroadcasterFeeMargin::Zero, None),
        "0 USDC"
    );
}

#[test]
fn max_unshield_amount_from_snapshot_uses_batched_top_chunks() {
    let token = Address::from([0x11; 20]);
    let other = Address::from([0x22; 20]);
    let mut utxos = (0..20)
        .map(|position| unshield_utxo_output(token, 1, 0, position))
        .collect::<Vec<_>>();
    utxos.extend((0..5).map(|position| unshield_utxo_output(token, 3, 1, position)));
    utxos.push(unshield_utxo_output(other, 100, 1, 99));
    let mut unknown = unshield_utxo_output(token, 100, 2, 1);
    unknown.poi_statuses.clear();
    unknown.poi_spendable = false;
    utxos.push(unknown);
    let snapshot = ListUtxosOutput {
        chain_id: 1,
        cache_key: "cache".to_string(),
        utxo_count: utxos.len(),
        unspent_count: utxos.len(),
        spent_count: 0,
        local_pending_spent_count: 0,
        utxos,
        totals: Vec::new(),
    };

    assert_eq!(
        max_unshield_amount_from_snapshot(&snapshot, token),
        uint!(35_U256)
    );
}

#[test]
fn refreshed_form_asset_tracks_new_utxos() {
    let token = Address::from([0x11; 20]);
    let original_snapshot = ListUtxosOutput {
        chain_id: 1,
        cache_key: "cache".to_string(),
        utxo_count: 1,
        unspent_count: 1,
        spent_count: 0,
        local_pending_spent_count: 0,
        utxos: vec![unshield_utxo_output(token, 5, 0, 1)],
        totals: vec![wallet_ops::TokenTotal {
            token: token.to_checksum(None),
            total: "5".to_string(),
            poi_verified_total: "5".to_string(),
        }],
    };
    let original_row = format_private_asset_rows(1, &original_snapshot.totals, None)
        .pop()
        .expect("formatted row");
    let original_asset =
        build_unshield_asset(&original_snapshot, &original_row).expect("original asset");
    let updated_snapshot = ListUtxosOutput {
        chain_id: 1,
        cache_key: "cache".to_string(),
        utxo_count: 2,
        unspent_count: 2,
        spent_count: 0,
        local_pending_spent_count: 0,
        utxos: vec![
            unshield_utxo_output(token, 5, 0, 1),
            unshield_utxo_output(token, 3, 0, 2),
        ],
        totals: vec![wallet_ops::TokenTotal {
            token: token.to_checksum(None),
            total: "8".to_string(),
            poi_verified_total: "8".to_string(),
        }],
    };

    let updated = refresh_form_asset_from_snapshot(&updated_snapshot, &original_asset, false, None);

    assert_eq!(updated.total, uint!(8_U256));
    assert_eq!(updated.poi_verified_total, uint!(8_U256));
    assert_eq!(updated.max_batched, uint!(8_U256));
}

#[test]
fn refreshed_form_asset_tracks_spent_out_token() {
    let token = Address::from([0x11; 20]);
    let original_asset = UnshieldAsset {
        chain_id: 1,
        token,
        label: "WETH".to_string(),
        decimals: Some(18),
        total: uint!(5_U256),
        poi_verified_total: uint!(5_U256),
        max_batched: uint!(5_U256),
        icon_path: None,
    };
    let mut spent = unshield_utxo_output(token, 5, 0, 1);
    spent.is_spent = true;
    spent.poi_spendable = false;
    spent.spent_tx_hash =
        Some("0x2222222222222222222222222222222222222222222222222222222222222222".to_string());
    spent.spent_block_number = Some(21);
    let updated_snapshot = ListUtxosOutput {
        chain_id: 1,
        cache_key: "cache".to_string(),
        utxo_count: 1,
        unspent_count: 0,
        spent_count: 1,
        local_pending_spent_count: 0,
        utxos: vec![spent],
        totals: Vec::new(),
    };

    let updated = refresh_form_asset_from_snapshot(&updated_snapshot, &original_asset, false, None);

    assert_eq!(updated.label, "WETH");
    assert_eq!(updated.decimals, Some(18));
    assert_eq!(updated.total, U256::ZERO);
    assert_eq!(updated.poi_verified_total, U256::ZERO);
    assert_eq!(updated.max_batched, U256::ZERO);
}

#[test]
fn max_send_amount_from_snapshot_uses_batched_top_chunks() {
    let token = Address::from([0x12; 20]);
    let other = Address::from([0x22; 20]);
    let mut utxos = (0..20)
        .map(|position| unshield_utxo_output(token, 1, 0, position))
        .collect::<Vec<_>>();
    utxos.extend((0..5).map(|position| unshield_utxo_output(token, 3, 1, position)));
    utxos.push(unshield_utxo_output(other, 100, 1, 99));
    let mut unknown = unshield_utxo_output(token, 100, 2, 1);
    unknown.poi_statuses.clear();
    unknown.poi_spendable = false;
    utxos.push(unknown);
    let snapshot = ListUtxosOutput {
        chain_id: 1,
        cache_key: "cache".to_string(),
        utxo_count: utxos.len(),
        unspent_count: utxos.len(),
        spent_count: 0,
        local_pending_spent_count: 0,
        utxos,
        totals: Vec::new(),
    };

    assert_eq!(
        max_send_amount_from_snapshot(&snapshot, token),
        uint!(35_U256)
    );
}

#[test]
fn build_unshield_asset_includes_max_batched_transaction() {
    let token = Address::from([0x33; 20]);
    let snapshot = ListUtxosOutput {
        chain_id: 1,
        cache_key: "cache".to_string(),
        utxo_count: 2,
        unspent_count: 2,
        spent_count: 0,
        local_pending_spent_count: 0,
        utxos: vec![
            unshield_utxo_output(token, 5, 0, 1),
            unshield_utxo_output(token, 7, 0, 2),
        ],
        totals: vec![wallet_ops::TokenTotal {
            token: token.to_checksum(None),
            total: "12".to_string(),
            poi_verified_total: "12".to_string(),
        }],
    };
    let row = format_private_asset_rows(1, &snapshot.totals, None)
        .into_iter()
        .next()
        .expect("asset row");

    let asset = build_unshield_asset(&snapshot, &row).expect("unshield asset");

    assert_eq!(asset.total, uint!(12_U256));
    assert_eq!(asset.max_batched, uint!(12_U256));
}

#[test]
fn build_send_asset_includes_max_batched_transaction() {
    let token = Address::from([0x34; 20]);
    let snapshot = ListUtxosOutput {
        chain_id: 1,
        cache_key: "cache".to_string(),
        utxo_count: 2,
        unspent_count: 2,
        spent_count: 0,
        local_pending_spent_count: 0,
        utxos: vec![
            unshield_utxo_output(token, 5, 0, 1),
            unshield_utxo_output(token, 7, 0, 2),
        ],
        totals: vec![wallet_ops::TokenTotal {
            token: token.to_checksum(None),
            total: "12".to_string(),
            poi_verified_total: "12".to_string(),
        }],
    };
    let row = format_private_asset_rows(1, &snapshot.totals, None)
        .into_iter()
        .next()
        .expect("asset row");

    let asset = build_send_asset(&snapshot, &row).expect("send asset");

    assert_eq!(asset.total, uint!(12_U256));
    assert_eq!(asset.max_batched, uint!(12_U256));
}

#[test]
fn unshield_key_matches_only_selected_asset() {
    let token = Address::from([0x44; 20]);
    let other = Address::from([0x45; 20]);
    let rows = format_private_asset_rows(
        1,
        &[
            wallet_ops::TokenTotal {
                token: token.to_checksum(None),
                total: "5".to_string(),
                poi_verified_total: "5".to_string(),
            },
            wallet_ops::TokenTotal {
                token: other.to_checksum(None),
                total: "7".to_string(),
                poi_verified_total: "7".to_string(),
            },
        ],
        None,
    );
    let key = UnshieldAssetKey::new(1, token);

    assert_eq!(unshield_asset_key_from_formatted(&rows[0]), Some(key));
    assert!(unshield_key_matches_asset(key, &rows[0]));
    assert!(!unshield_key_matches_asset(key, &rows[1]));
}

#[test]
fn send_key_matches_only_selected_asset() {
    let token = Address::from([0x46; 20]);
    let other = Address::from([0x47; 20]);
    let rows = format_private_asset_rows(
        1,
        &[
            wallet_ops::TokenTotal {
                token: token.to_checksum(None),
                total: "5".to_string(),
                poi_verified_total: "5".to_string(),
            },
            wallet_ops::TokenTotal {
                token: other.to_checksum(None),
                total: "7".to_string(),
                poi_verified_total: "7".to_string(),
            },
        ],
        None,
    );
    let key = UnshieldAssetKey::new(1, token);

    assert_eq!(send_asset_key_from_formatted(&rows[0]), Some(key));
    assert!(send_key_matches_asset(key, &rows[0]));
    assert!(!send_key_matches_asset(key, &rows[1]));
}

#[test]
fn unshield_element_ids_are_asset_scoped() {
    let first = UnshieldAssetKey::new(1, Address::from([0x11; 20]));
    let second = UnshieldAssetKey::new(1, Address::from([0x22; 20]));

    assert_ne!(
        unshield_element_id(first, "cancel").as_ref(),
        unshield_element_id(second, "cancel").as_ref()
    );
    assert_ne!(
        unshield_element_id(first, "copy-to").as_ref(),
        unshield_element_id(first, "copy-data").as_ref()
    );
}

fn public_account_for_search(label: Option<&str>, address: Address) -> PublicAccountMetadata {
    PublicAccountMetadata {
        public_account_uuid: "public-account".to_string(),
        address,
        label: label.map(str::to_string),
        source: PublicAccountSource::Imported,
        scope: PublicAccountScope::Global,
        derivation_index: None,
        status: PublicAccountStatus::Active,
        display_order: 0,
    }
}

#[test]
fn public_account_search_matches_empty_query() {
    let account = public_account_for_search(Some("Main account"), Address::from([0x11; 20]));

    assert!(public_account_matches_search(&account, ""));
    assert!(public_account_matches_search(&account, "   "));
}

#[test]
fn public_account_search_matches_label_partial_case_insensitive() {
    let account = public_account_for_search(Some("Primary Spending"), Address::from([0x22; 20]));

    assert!(public_account_matches_search(&account, "spend"));
    assert!(public_account_matches_search(&account, "PRIMARY"));
}

#[test]
fn public_account_search_matches_address_partial_case_insensitive() {
    let account = public_account_for_search(None, Address::from([0xab; 20]));

    assert!(public_account_matches_search(&account, "0xabab"));
    assert!(public_account_matches_search(&account, "ABABAB"));
}

#[test]
fn public_account_search_rejects_non_matches() {
    let account = public_account_for_search(Some("Primary"), Address::from([0xcd; 20]));

    assert!(!public_account_matches_search(&account, "savings"));
}

#[test]
fn public_address_qr_payload_is_plain_address() {
    let address = Address::from([0xab; 20]);
    let payload = public_address_qr_payload(address);

    assert_eq!(payload, format!("{address:#x}"));
    assert!(!payload.starts_with("ethereum:"));
}

#[test]
fn public_address_qr_payload_fits_qr_with_quiet_zone() {
    let address = Address::from([0x42; 20]);
    let payload = public_address_qr_payload(address);
    let qr = qrcodegen::QrCode::encode_text(&payload, qrcodegen::QrCodeEcc::Medium)
        .expect("public address should fit in QR code");
    let module_range = public_address_qr_module_range(qr.size());

    assert!(qr.size() > 0);
    assert_eq!(PUBLIC_ADDRESS_QR_QUIET_ZONE_MODULES, 4);
    assert_eq!(
        module_range.clone().count(),
        usize::try_from(qr.size() + 8).unwrap()
    );
    assert!(module_range.contains(&-PUBLIC_ADDRESS_QR_QUIET_ZONE_MODULES));
    assert!(module_range.contains(&qr.size()));
}

#[test]
fn public_account_identicon_pattern_is_deterministic_and_symmetric() {
    let address = Address::from([0x42; 20]);
    let pattern = public_account_identicon_pattern(&address);

    assert_eq!(pattern, public_account_identicon_pattern(&address));
    assert!(pattern.iter().any(|active| *active));
    for row in pattern.chunks_exact(PUBLIC_ACCOUNT_IDENTICON_GRID_SIZE) {
        assert_eq!(row[0], row[4]);
        assert_eq!(row[1], row[3]);
    }
}

#[test]
fn public_account_identicon_differs_for_different_addresses() {
    let first = Address::from([0x11; 20]);
    let second = Address::from([0x22; 20]);

    assert_ne!(
        public_account_identicon_pattern(&first),
        public_account_identicon_pattern(&second),
    );
    assert_ne!(
        public_account_identicon_color(&first),
        public_account_identicon_color(&second),
    );
}

#[test]
fn public_account_identicon_zero_address_is_not_blank() {
    let pattern = public_account_identicon_pattern(&Address::from([0; 20]));
    let active_count = pattern.iter().filter(|active| **active).count();

    assert_eq!(active_count, 1);
    assert!(pattern[PUBLIC_ACCOUNT_IDENTICON_CELL_COUNT / 2]);
}

fn public_balance_snapshot_for_test(chain_id: u64) -> PublicBalanceSnapshot {
    let account = public_account_for_search(Some("Main account"), Address::from([0x11; 20]));
    PublicBalanceSnapshot {
        chain_id,
        refreshed_at: SystemTime::UNIX_EPOCH,
        accounts: vec![PublicAccountBalance {
            account,
            balances: vec![PublicBalanceEntry {
                asset: PublicBalanceAsset {
                    id: PublicAssetId::Native,
                    symbol: "ETH".to_string(),
                    decimals: 18,
                },
                amount: PublicBalanceAmount::Available(U256::from(5_u64)),
            }],
        }],
    }
}

#[test]
fn public_balance_helpers_ignore_stale_chain_snapshot() {
    let snapshot = public_balance_snapshot_for_test(1);

    assert_eq!(
        public_account_visible_balances_for_chain(
            Some(&snapshot),
            1,
            "public-account",
            PublicAccountStatus::Active,
        )
        .len(),
        1,
    );
    assert!(
        public_balance_entry_for_chain(
            Some(&snapshot),
            1,
            "public-account",
            PublicAssetId::Native,
            PublicAccountStatus::Active,
        )
        .is_some(),
    );
    assert!(
        public_account_visible_balances_for_chain(
            Some(&snapshot),
            56,
            "public-account",
            PublicAccountStatus::Active,
        )
        .is_empty(),
    );
    assert!(
        public_balance_entry_for_chain(
            Some(&snapshot),
            56,
            "public-account",
            PublicAssetId::Native,
            PublicAccountStatus::Active,
        )
        .is_none(),
    );
    assert!(
        public_account_visible_balances_for_chain(
            Some(&snapshot),
            1,
            "public-account",
            PublicAccountStatus::Inactive,
        )
        .is_empty(),
    );
}

#[test]
fn public_balance_merge_preserves_other_account_status_group() {
    let active = public_balance_snapshot_for_test(1);
    let mut inactive = public_balance_snapshot_for_test(1);
    inactive.accounts[0].account.public_account_uuid = "inactive-account".to_string();
    inactive.accounts[0].account.status = PublicAccountStatus::Inactive;

    let merged =
        merge_public_balance_snapshot(Some(&active), inactive, PublicAccountStatus::Inactive);

    assert!(merged.accounts.iter().any(|account| {
        account.account.public_account_uuid == "public-account"
            && account.account.status == PublicAccountStatus::Active
    }));
    assert!(merged.accounts.iter().any(|account| {
        account.account.public_account_uuid == "inactive-account"
            && account.account.status == PublicAccountStatus::Inactive
    }));
}

#[test]
fn public_action_native_max_subtracts_estimated_gas_reserve() {
    assert_eq!(
        public_action_max_amount_after_reserve(U256::from(100_u64), U256::from(40_u64)),
        Some(U256::from(60_u64)),
    );
    assert_eq!(
        public_action_max_amount_after_reserve(U256::from(100_u64), U256::from(100_u64)),
        None,
    );
    assert_eq!(
        public_action_max_amount_after_reserve(U256::from(100_u64), U256::from(101_u64)),
        None,
    );
}

#[test]
fn public_action_max_label_notes_native_gas_estimate() {
    let native = PublicBalanceEntry {
        asset: PublicBalanceAsset {
            id: PublicAssetId::Native,
            symbol: "ETH".to_string(),
            decimals: 18,
        },
        amount: PublicBalanceAmount::Available(U256::from(1_000_000_000_000_000_000_u128)),
    };
    let token = PublicBalanceEntry {
        asset: PublicBalanceAsset {
            id: PublicAssetId::Erc20(Address::from([0x22; 20])),
            symbol: "USDC".to_string(),
            decimals: 6,
        },
        amount: PublicBalanceAmount::Available(U256::from(1_500_000_u64)),
    };

    assert_eq!(
        public_action_max_label(&native),
        Some("ETH after est. gas".to_string()),
    );
    assert_eq!(
        public_action_max_label(&token),
        Some("1.5 USDC".to_string()),
    );
}

#[test]
fn public_action_progress_steps_use_single_send_step() {
    assert_eq!(
        public_action_progress_steps(PublicActionMode::Send, PublicAssetId::Native),
        vec![PublicActionProgressStep::Send],
    );
}

#[test]
fn public_action_progress_steps_include_wrap_for_native_shield() {
    assert_eq!(
        public_action_progress_steps(PublicActionMode::Shield, PublicAssetId::Native),
        vec![
            PublicActionProgressStep::Wrap,
            PublicActionProgressStep::Approve,
            PublicActionProgressStep::Shield,
        ],
    );
}

#[test]
fn public_action_progress_steps_skip_wrap_for_erc20_shield() {
    assert_eq!(
        public_action_progress_steps(
            PublicActionMode::Shield,
            PublicAssetId::Erc20(Address::from([0xef; 20])),
        ),
        vec![
            PublicActionProgressStep::Approve,
            PublicActionProgressStep::Shield,
        ],
    );
}

#[test]
fn public_action_error_summary_explains_wrap_gas_estimate() {
    assert_eq!(
        public_action_error_summary(
            PublicActionProgressStep::Wrap,
            Some("public-shield-wrap: estimate gas"),
            "ETH",
        ),
        "Could not estimate gas to wrap ETH. Check amount and gas balance.",
    );
}

#[test]
fn public_action_asset_label_uses_native_symbol() {
    assert_eq!(
        public_action_asset_label(1, PublicAssetId::Native, None),
        "ETH"
    );
}

#[test]
fn public_action_error_details_hide_duplicate_summary() {
    let summary = "Could not send publicly.";

    assert_eq!(public_action_error_details(summary, Some(summary)), None);
    assert_eq!(
        public_action_error_details(summary, Some("public-send: estimate gas")),
        Some("public-send: estimate gas".to_string()),
    );
}

#[test]
fn public_action_error_copy_value_includes_context_and_details() {
    assert_eq!(
        public_action_error_copy_value(
            PublicActionProgressStep::Wrap,
            "ETH",
            "Could not estimate gas to wrap ETH.",
            Some("public-shield-wrap: estimate gas: insufficient funds"),
        ),
        "Step: Wrap\nAsset: ETH\nSummary: Could not estimate gas to wrap ETH.\nDetails: public-shield-wrap: estimate gas: insufficient funds",
    );
}

#[test]
fn send_element_ids_are_asset_scoped() {
    let first = UnshieldAssetKey::new(1, Address::from([0x11; 20]));
    let second = UnshieldAssetKey::new(1, Address::from([0x22; 20]));

    assert_ne!(
        send_element_id(first, "cancel").as_ref(),
        send_element_id(second, "cancel").as_ref()
    );
    assert_ne!(
        send_element_id(first, "copy-to").as_ref(),
        send_element_id(first, "copy-data").as_ref()
    );
}

#[test]
fn display_rows_reverse_utxo_order() {
    let output = ListUtxosOutput {
        chain_id: 1,
        cache_key: "cache".to_string(),
        utxo_count: 3,
        unspent_count: 3,
        spent_count: 0,
        local_pending_spent_count: 0,
        utxos: vec![
            utxo_output("0x1111111111111111111111111111111111111111", "1", false),
            utxo_output("0x2222222222222222222222222222222222222222", "2", false),
            utxo_output("0x3333333333333333333333333333333333333333", "3", false),
        ],
        totals: Vec::new(),
    };

    let rows = display_rows_from_output(&output, "", true);
    let amounts: Vec<_> = rows.iter().map(|row| row.amount.as_str()).collect();
    assert_eq!(amounts, ["3", "2", "1"]);
}

#[test]
fn display_rows_include_spent_utxos() {
    let output = ListUtxosOutput {
        chain_id: 1,
        cache_key: "cache".to_string(),
        utxo_count: 2,
        unspent_count: 1,
        spent_count: 1,
        local_pending_spent_count: 0,
        utxos: vec![
            utxo_output("0x1111111111111111111111111111111111111111", "42", true),
            utxo_output("0x2222222222222222222222222222222222222222", "7", false),
        ],
        totals: Vec::new(),
    };

    let rows = display_rows_from_output(&output, "", true);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].amount, "7");
    assert!(!rows[0].is_spent);
    assert_eq!(rows[0].spent_tx_hash, None);
    assert_eq!(rows[1].amount, "42");
    assert!(rows[1].is_spent);
    assert_eq!(
        rows[1].spent_tx_hash.as_deref(),
        Some("0x2222222222222222222222222222222222222222222222222222222222222222")
    );
}

#[test]
fn display_rows_hide_spent_utxos_when_toggle_off() {
    let output = ListUtxosOutput {
        chain_id: 1,
        cache_key: "cache".to_string(),
        utxo_count: 2,
        unspent_count: 1,
        spent_count: 1,
        local_pending_spent_count: 0,
        utxos: vec![
            utxo_output("0x1111111111111111111111111111111111111111", "42", true),
            utxo_output("0x2222222222222222222222222222222222222222", "7", false),
        ],
        totals: Vec::new(),
    };

    let rows = display_rows_from_output(&output, "", false);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].amount, "7");
    assert!(!rows[0].is_spent);
}

#[test]
fn display_rows_keep_pending_spent_visible_when_spent_toggle_off() {
    let mut pending_spent = utxo_output("0x1111111111111111111111111111111111111111", "42", false);
    pending_spent.pending_spent = true;
    pending_spent.poi_spendable = false;
    let output = ListUtxosOutput {
        chain_id: 1,
        cache_key: "cache".to_string(),
        utxo_count: 1,
        unspent_count: 1,
        spent_count: 0,
        local_pending_spent_count: 0,
        utxos: vec![pending_spent],
        totals: Vec::new(),
    };

    let rows = display_rows_from_output(&output, "", false);

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].amount, "42");
    assert!(rows[0].pending_spent);
    assert_eq!(rows[0].poi_status, "Pending spend");
}

#[test]
fn display_rows_keep_local_pending_spent_visible_when_spent_toggle_off() {
    let mut local_pending = utxo_output("0x1111111111111111111111111111111111111111", "42", false);
    local_pending.local_pending_spent = true;
    local_pending.poi_spendable = false;
    let output = ListUtxosOutput {
        chain_id: 1,
        cache_key: "cache".to_string(),
        utxo_count: 1,
        unspent_count: 1,
        spent_count: 0,
        local_pending_spent_count: 1,
        utxos: vec![local_pending],
        totals: Vec::new(),
    };

    let rows = display_rows_from_output(&output, "", false);

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].amount, "42");
    assert!(rows[0].local_pending_spent);
    assert_eq!(rows[0].poi_status, "Locally locked");
}

#[test]
fn display_rows_search_matches_source_tx_hash() {
    let output = ListUtxosOutput {
        chain_id: 1,
        cache_key: "cache".to_string(),
        utxo_count: 2,
        unspent_count: 2,
        spent_count: 0,
        local_pending_spent_count: 0,
        utxos: vec![
            utxo_output_with_hashes(
                "0x1111111111111111111111111111111111111111",
                "42",
                false,
                "0xaAaA000000000000000000000000000000000000000000000000000000000000",
                None,
            ),
            utxo_output_with_hashes(
                "0x2222222222222222222222222222222222222222",
                "7",
                false,
                "0xbbbb000000000000000000000000000000000000000000000000000000000000",
                None,
            ),
        ],
        totals: Vec::new(),
    };

    let rows = display_rows_from_output(&output, "aaaa", true);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].amount, "42");
}

#[test]
fn display_rows_search_matches_spent_tx_hash() {
    let output = ListUtxosOutput {
        chain_id: 1,
        cache_key: "cache".to_string(),
        utxo_count: 2,
        unspent_count: 1,
        spent_count: 1,
        local_pending_spent_count: 0,
        utxos: vec![
            utxo_output_with_hashes(
                "0x1111111111111111111111111111111111111111",
                "42",
                true,
                "0x3333000000000000000000000000000000000000000000000000000000000000",
                Some("0xdead000000000000000000000000000000000000000000000000000000000000"),
            ),
            utxo_output_with_hashes(
                "0x2222222222222222222222222222222222222222",
                "7",
                false,
                "0x4444000000000000000000000000000000000000000000000000000000000000",
                None,
            ),
        ],
        totals: Vec::new(),
    };

    let rows = display_rows_from_output(&output, "dead", true);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].amount, "42");
    assert!(rows[0].is_spent);
}

#[test]
fn display_rows_search_ignores_spent_visibility_toggle() {
    let output = ListUtxosOutput {
        chain_id: 1,
        cache_key: "cache".to_string(),
        utxo_count: 1,
        unspent_count: 0,
        spent_count: 1,
        local_pending_spent_count: 0,
        utxos: vec![utxo_output_with_hashes(
            "0x1111111111111111111111111111111111111111",
            "42",
            true,
            "0x3333000000000000000000000000000000000000000000000000000000000000",
            Some("0xdead000000000000000000000000000000000000000000000000000000000000"),
        )],
        totals: Vec::new(),
    };

    let rows = display_rows_from_output(&output, "dead", false);
    assert_eq!(rows.len(), 1);
    assert!(rows[0].is_spent);
}

#[test]
fn chain_load_uses_default_sync_options() {
    let overrides = super::chain_load_overrides();

    assert_eq!(overrides.init_block_number, None);
    assert_eq!(overrides.sync_to_block, None);
    assert!(overrides.use_indexed_wallet_catch_up);
    assert!(!overrides.rewind_wallet_cache);
}

#[test]
fn repair_cache_block_parses_zero_as_deployment() {
    assert_eq!(parse_repair_cache_block("0"), Ok(None));
    assert_eq!(parse_repair_cache_block(""), Ok(None));
    assert_eq!(parse_repair_cache_block(" 24936249 "), Ok(Some(24936249)));
    assert!(parse_repair_cache_block("nope").is_err());
}

#[test]
fn repair_cache_help_text_only_mentions_hint_when_available() {
    assert!(repair_cache_help_text(true).contains("wallet start block below"));
    assert!(!repair_cache_help_text(false).contains("wallet start block below"));
    assert!(repair_cache_help_text(false).contains("deployment block"));
}

#[test]
fn chain_error_state_preserves_start_block_hint() {
    let state = ChainUtxoState::Error {
        message: Arc::from("sync failed"),
        start_block: Some(24936250),
    };

    assert_eq!(state.start_block(), Some(24936250));
    assert!(!state.renders_table());
}

#[test]
fn loading_summary_uses_sync_stage_and_percent() {
    let commitments =
        SyncProgressUpdate::new(SyncProgressStage::SynchronizingCommitments, 100, 150, 300);
    let indexing = SyncProgressUpdate::new(SyncProgressStage::IndexingUtxos, 100, 150, 300);

    assert_eq!(
        loading_summary(Some(commitments)),
        "Synchronizing commitments · 25%"
    );
    assert_eq!(loading_summary(Some(indexing)), "Indexing UTXOs · 25%");
    assert_eq!(loading_summary(None), "Preparing wallet sync...");
}

#[test]
fn loading_chain_state_keeps_utxo_table_available() {
    let state = ChainUtxoState::Loading { progress: None };

    assert!(state.renders_table());
    assert!(state.is_syncing());
    assert!(!matches!(state, ChainUtxoState::Ready { .. }));
    assert!(state.snapshot().is_none());
}

#[test]
fn progress_detail_clamps_current_block() {
    let progress = SyncProgressUpdate::new(SyncProgressStage::IndexingUtxos, 100, 400, 300);

    assert_eq!(progress_detail(progress), "Block 300 of 300");
}
