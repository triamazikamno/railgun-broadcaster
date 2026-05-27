use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use local_db::{DbConfig, DbStore};

use super::{
    OFFICIAL_POI_ARTIFACT_GATEWAYS, OFFICIAL_POI_ARTIFACT_IPNS_NAME,
    OFFICIAL_POI_ARTIFACT_PUBLISHER_PUBKEY, PoiArtifactManifestSourceSetting, PoiReadSourceSetting,
    WALLET_SETTINGS_KEY, WALLET_SETTINGS_VERSION, WakuDirectPeerSetting, WalletSettings,
    WalletSettingsError, build_effective_chain_configs, build_effective_token_registry,
    decode_wallet_settings, encode_wallet_settings, load_wallet_settings, save_wallet_settings,
    should_show_chain_deployment_metadata_settings,
};
use sync_service::ChainConfigDefaults;

static TEMP_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_db_root() -> PathBuf {
    let dir = std::env::temp_dir().join("railgun-broadcaster-wallet-settings-tests");
    fs::create_dir_all(&dir).expect("create temp db dir");
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let counter = TEMP_DB_COUNTER.fetch_add(1, Ordering::Relaxed);
    dir.join(format!("db-{pid}-{nanos}-{counter}"))
}

#[test]
fn missing_settings_synthesizes_official_indexed_artifact_defaults() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");

    let settings = load_wallet_settings(&store).expect("load settings");
    assert_eq!(settings.version, WALLET_SETTINGS_VERSION);
    assert_eq!(
        settings.poi.read_source,
        PoiReadSourceSetting::IndexedArtifacts
    );
    assert_eq!(
        settings.poi.artifact.publisher_pubkey,
        OFFICIAL_POI_ARTIFACT_PUBLISHER_PUBKEY
    );
    assert_eq!(
        settings.poi.artifact.manifest_source,
        PoiArtifactManifestSourceSetting::IpnsName(OFFICIAL_POI_ARTIFACT_IPNS_NAME.to_string())
    );
    assert_eq!(
        settings.poi.artifact.gateway_urls,
        OFFICIAL_POI_ARTIFACT_GATEWAYS
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    );
    assert!(
        store
            .get_app_settings_record(WALLET_SETTINGS_KEY)
            .expect("load raw settings")
            .is_none()
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn settings_roundtrip_through_local_db() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let mut settings = WalletSettings::default();
    settings.network.mode = super::NetworkModeSetting::Direct;
    settings.poi.read_source = PoiReadSourceSetting::PoiProxy;

    save_wallet_settings(&store, &settings).expect("save settings");
    let loaded = load_wallet_settings(&store).expect("load settings");
    assert_eq!(loaded, settings);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn unsupported_future_settings_version_is_rejected() {
    let settings = WalletSettings {
        version: WALLET_SETTINGS_VERSION + 1,
        ..WalletSettings::default()
    };
    let data = rmp_serde::to_vec_named(&settings).expect("encode future settings");

    let err = decode_wallet_settings(&data).expect_err("future version rejected");
    assert!(matches!(
        err,
        WalletSettingsError::UnsupportedVersion { version }
            if version == WALLET_SETTINGS_VERSION + 1
    ));
}

#[test]
fn validation_rejects_ambiguous_proxy_and_disabled_chains() {
    let mut settings = WalletSettings::default();
    settings.network.proxy_url = Some("http://127.0.0.1:9050".to_string());
    for chain in settings.chains.per_chain.values_mut() {
        chain.enabled = false;
    }

    let err = settings.validate().expect_err("settings invalid");
    assert!(
        err.messages
            .iter()
            .any(|message| message.contains("proxy_url"))
    );
    assert!(
        err.messages
            .iter()
            .any(|message| message.contains("at least one supported chain"))
    );
}

#[test]
fn reset_helpers_restore_defaults() {
    let mut settings = WalletSettings::default();
    settings.network.mode = super::NetworkModeSetting::Direct;
    settings.poi.artifact.gateway_urls.clear();

    settings.reset_network();
    settings.reset_poi();

    assert_eq!(settings.network, super::NetworkSettings::default());
    assert_eq!(settings.poi, super::PoiSettings::default());
}

#[test]
fn effective_chain_configs_use_supported_presets_without_overrides() {
    let settings = WalletSettings::default();
    let configs = build_effective_chain_configs(&settings).expect("build effective configs");
    let ethereum = configs.get(&1).expect("ethereum config");
    let defaults = ChainConfigDefaults::for_chain(1).expect("ethereum defaults");

    assert!(ethereum.enabled);
    assert_eq!(
        ethereum.rpc_endpoints,
        defaults
            .rpc_urls
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    );
    assert!(ethereum.rpc_endpoints.len() > 1);
    assert_eq!(ethereum.finality_depth, defaults.finality_depth);
    assert_eq!(ethereum.deployment_block, defaults.deployment_block);
    assert_eq!(ethereum.v2_start_block, defaults.v2_start_block);
    assert_eq!(ethereum.legacy_shield_block, defaults.legacy_shield_block);
    assert_eq!(ethereum.archive_until_block, defaults.archive_until_block);
    assert_eq!(ethereum.archive_rpc_url, None);
    assert_eq!(
        ethereum.quick_sync_endpoint,
        defaults.quick_sync_endpoint.map(|url| url.to_string())
    );
    assert_eq!(
        ethereum.multicall_contract,
        defaults.multicall_contract.to_string()
    );
}

#[test]
fn effective_chain_configs_apply_supported_overrides_in_order() {
    let mut settings = WalletSettings::default();
    let ethereum = settings
        .chains
        .per_chain
        .get_mut(&1)
        .expect("ethereum settings");
    ethereum.rpc_endpoints = vec![
        "https://rpc-a.example".to_string(),
        "https://rpc-b.example".to_string(),
    ];
    ethereum.quick_sync.endpoint = Some("https://quick.example/graphql".to_string());
    ethereum.finality_depth = Some(64);
    ethereum.contracts.multicall_contract =
        Some("0x0000000000000000000000000000000000000001".to_string());
    ethereum.deployment.deployment_block = Some(11);
    ethereum.deployment.v2_start_block = Some(22);
    ethereum.deployment.legacy_shield_block = Some(33);
    ethereum.deployment.archive_until_block = Some(44);
    ethereum.deployment.archive_rpc_url = Some("https://archive.example".to_string());
    ethereum.gas.gas_limit_buffer = Some(250_000);

    let configs = build_effective_chain_configs(&settings).expect("build effective configs");
    let ethereum = configs.get(&1).expect("ethereum config");

    assert_eq!(
        ethereum.rpc_endpoints,
        vec!["https://rpc-a.example", "https://rpc-b.example"]
    );
    assert_eq!(
        ethereum.quick_sync_endpoint.as_deref(),
        Some("https://quick.example/graphql")
    );
    assert_eq!(ethereum.finality_depth, 64);
    assert_eq!(ethereum.deployment_block, 11);
    assert_eq!(ethereum.v2_start_block, 22);
    assert_eq!(ethereum.legacy_shield_block, 33);
    assert_eq!(ethereum.archive_until_block, 44);
    assert_eq!(
        ethereum.archive_rpc_url.as_deref(),
        Some("https://archive.example")
    );
    assert_eq!(
        ethereum.multicall_contract,
        "0x0000000000000000000000000000000000000001"
    );
    assert_eq!(ethereum.gas.gas_limit_buffer, 250_000);
}

#[test]
fn custom_railgun_contract_requires_deployment_metadata() {
    let mut settings = WalletSettings::default();
    settings
        .chains
        .per_chain
        .get_mut(&1)
        .expect("ethereum settings")
        .contracts
        .railgun_contract = Some("0x0000000000000000000000000000000000000001".to_string());

    let err = settings
        .validate()
        .expect_err("deployment metadata required");
    assert!(
        err.messages
            .iter()
            .any(|message| { message.contains("chains.per_chain.1.deployment.deployment_block") })
    );
    assert!(should_show_chain_deployment_metadata_settings(
        1,
        settings
            .chains
            .per_chain
            .get(&1)
            .expect("ethereum settings")
    ));

    let ethereum = settings
        .chains
        .per_chain
        .get_mut(&1)
        .expect("ethereum settings");
    ethereum.deployment.deployment_block = Some(11);
    ethereum.deployment.v2_start_block = Some(22);
    ethereum.deployment.legacy_shield_block = Some(33);
    ethereum.deployment.archive_until_block = Some(0);

    settings.validate().expect("metadata supplied");
}

#[test]
fn effective_chain_configs_apply_quick_sync_bounds_and_disabled_state() {
    let mut settings = WalletSettings::default();
    let ethereum = settings
        .chains
        .per_chain
        .get_mut(&1)
        .expect("ethereum settings");
    ethereum.quick_sync.enabled = false;
    ethereum.quick_sync.indexed_wallet_block_range = Some(25_000);
    ethereum.block_range = Some(2_000);
    ethereum.poll_interval_secs = Some(30);

    let configs = build_effective_chain_configs(&settings).expect("build effective configs");
    let ethereum = configs.get(&1).expect("ethereum config");

    assert!(!ethereum.quick_sync_enabled);
    assert_eq!(ethereum.indexed_wallet_block_range, 25_000);
    assert_eq!(ethereum.block_range, Some(2_000));
    assert_eq!(ethereum.poll_interval_secs, Some(30));
}

#[test]
fn chain_reset_restores_supported_chain_defaults() {
    let mut settings = WalletSettings::default();
    settings
        .chains
        .per_chain
        .get_mut(&1)
        .expect("ethereum settings")
        .enabled = false;

    settings.reset_chains();

    assert_eq!(settings.chains, super::ChainSettings::default());
    assert!(settings.chains.enabled_chain_ids().contains(&1));
}

#[test]
fn effective_chain_configs_reject_unsupported_chain_ids() {
    let mut settings = WalletSettings::default();
    settings
        .chains
        .per_chain
        .insert(999, super::ChainSettingsOverride::default());

    let err = build_effective_chain_configs(&settings).expect_err("unsupported chain rejected");
    assert!(
        err.messages
            .iter()
            .any(|message| message.contains("custom chain IDs are out of scope"))
    );
}

#[test]
fn effective_token_registry_applies_overrides_tombstones_and_custom_tokens() {
    let mut settings = WalletSettings::default();
    let weth = super::TokenKey {
        chain_id: 1,
        token_address: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".to_string(),
    };
    settings
        .tokens
        .built_in_overrides
        .push(super::BuiltInTokenOverride {
            key: weth,
            symbol: Some("WETHx".to_string()),
            decimals: Some(18),
            icon_path: None,
            price_anchor: Some(super::PriceAnchorSettings::Fixed {
                rate: "2000000000000000000".to_string(),
            }),
        });
    settings.tokens.built_in_tombstones.push(super::TokenKey {
        chain_id: 1,
        token_address: "0xdAC17F958D2ee523a2206206994597C13D831ec7".to_string(),
    });
    settings
        .tokens
        .custom_tokens
        .push(super::CustomTokenSettings {
            chain_id: 1,
            token_address: "0x0000000000000000000000000000000000000002".to_string(),
            symbol: "CSTM".to_string(),
            decimals: 9,
            icon_path: None,
            price_anchor: None,
        });

    let registry = build_effective_token_registry(&settings).expect("build token registry");
    let weth = registry
        .tokens
        .get(&(1, "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2".to_string()))
        .expect("weth token");
    assert_eq!(weth.symbol, "WETHx");
    assert!(weth.price_anchor.is_some());
    assert!(
        !registry
            .tokens
            .contains_key(&(1, "0xdac17f958d2ee523a2206206994597c13d831ec7".to_string()))
    );
    let custom = registry
        .tokens
        .get(&(1, "0x0000000000000000000000000000000000000002".to_string()))
        .expect("custom token");
    assert!(!custom.built_in);
    assert_eq!(custom.decimals, 9);
}

#[test]
fn effective_token_registry_includes_static_price_anchor_defaults() {
    let settings = WalletSettings::default();

    let registry = build_effective_token_registry(&settings).expect("build token registry");

    let weth = registry
        .tokens
        .get(&(1, "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2".to_string()))
        .expect("weth token");
    assert_eq!(
        weth.price_anchor,
        Some(super::PriceAnchorSettings::Fixed {
            rate: "1000000000000000000".to_string(),
        })
    );

    let usdt = registry
        .tokens
        .get(&(1, "0xdac17f958d2ee523a2206206994597c13d831ec7".to_string()))
        .expect("usdt token");
    assert!(matches!(
        usdt.price_anchor,
        Some(super::PriceAnchorSettings::Oracle {
            chain_id: 1,
            token_decimals: 6,
            oracle_decimals: 8,
            is_inversed: false,
            ..
        })
    ));
}

#[test]
fn broadcaster_settings_build_fee_policy_and_validate_thresholds() {
    let mut settings = WalletSettings::default();
    settings.broadcaster.min_anchor_bps = 9_000;
    settings.broadcaster.max_anchor_bps = 11_000;
    settings
        .broadcaster
        .allow_suspicious_broadcasters_by_default = true;
    settings.broadcaster.response_timeout_secs = 45;

    settings.validate().expect("broadcaster settings valid");
    let policy = settings.broadcaster.fee_policy();
    assert_eq!(policy.min_anchor_bps, 9_000);
    assert_eq!(policy.max_anchor_bps, 11_000);
    assert!(policy.allow_suspicious_broadcasters);

    settings.broadcaster.min_anchor_bps = 12_000;
    let err = settings
        .validate()
        .expect_err("invalid thresholds rejected");
    assert!(
        err.messages
            .iter()
            .any(|message| message.contains("min_anchor_bps"))
    );
}

#[test]
fn price_anchor_validation_covers_oracle_and_product_metadata() {
    let mut settings = WalletSettings::default();
    settings
        .tokens
        .price_anchors
        .push(super::TokenPriceAnchorOverride {
            key: super::TokenKey {
                chain_id: 1,
                token_address: "0x0000000000000000000000000000000000000002".to_string(),
            },
            price_anchor: super::PriceAnchorSettings::Product {
                scale_decimals: 18,
                components: vec![super::PriceAnchorSettings::Oracle {
                    chain_id: 1,
                    oracle_address: "0x0000000000000000000000000000000000000003".to_string(),
                    token_decimals: 18,
                    oracle_decimals: 8,
                    is_inversed: false,
                }],
            },
        });

    settings.validate().expect("anchor metadata valid");

    let super::PriceAnchorSettings::Product { components, .. } = &mut settings
        .tokens
        .price_anchors
        .first_mut()
        .expect("price anchor")
        .price_anchor
    else {
        panic!("expected product anchor");
    };
    let super::PriceAnchorSettings::Oracle {
        oracle_decimals, ..
    } = &mut components[0]
    else {
        panic!("expected oracle anchor");
    };
    *oracle_decimals = 37;

    let err = settings
        .validate()
        .expect_err("bad oracle decimals rejected");
    assert!(
        err.messages
            .iter()
            .any(|message| message.contains("oracle_decimals"))
    );
}

#[test]
fn default_poi_read_source_converts_to_official_indexed_artifacts() {
    let settings = WalletSettings::default();
    let super::PoiReadSource::IndexedArtifacts(source) =
        settings.poi_read_source().expect("POI source")
    else {
        panic!("default POI source should be indexed artifacts");
    };

    assert_eq!(
        alloy::hex::encode(source.trusted_publisher_pubkey.as_slice()),
        OFFICIAL_POI_ARTIFACT_PUBLISHER_PUBKEY.trim_start_matches("0x")
    );
    assert_eq!(
        source.manifest_source,
        super::PoiArtifactManifestSource::IpnsName(OFFICIAL_POI_ARTIFACT_IPNS_NAME.to_string())
    );
    assert_eq!(
        source.gateway_urls.len(),
        OFFICIAL_POI_ARTIFACT_GATEWAYS.len()
    );
}

#[test]
fn waku_settings_defaults_match_startup_defaults() {
    let settings = WalletSettings::default();
    assert_eq!(settings.waku.cluster_id, super::DEFAULT_WAKU_CLUSTER_ID);
    assert_eq!(settings.waku.shard_id, super::DEFAULT_WAKU_SHARD_ID);
    assert!(settings.waku.dns_enr_trees.is_none());
    assert!(settings.waku.direct_peers.is_none());
    assert!(settings.waku.doh_endpoint.is_none());
    assert!(settings.waku.doh_fallback_endpoints.is_none());
    assert_eq!(settings.waku.max_peers, super::DEFAULT_WAKU_MAX_PEERS);
    assert_eq!(
        settings.waku.peer_connection_timeout_secs,
        super::DEFAULT_WAKU_PEER_CONNECTION_TIMEOUT_SECS
    );
}

#[test]
fn waku_dns_enr_trees_validate_scheme() {
    let mut settings = WalletSettings::default();
    settings.waku.dns_enr_trees = Some(vec!["https://bad.example".to_string()]);

    let err = settings.validate().expect_err("bad DNS ENR tree rejected");

    assert!(
        err.messages
            .iter()
            .any(|message| message.contains("waku.dns_enr_trees[0]"))
    );
}

#[test]
fn default_waku_direct_peer_is_valid() {
    let peers = super::default_waku_direct_peers();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].peer_id, super::DEFAULT_WAKU_DIRECT_PEER_ID);
    assert_eq!(peers[0].addr, super::DEFAULT_WAKU_DIRECT_PEER_ADDR);

    let mut settings = WalletSettings::default();
    settings.waku.direct_peers = Some(peers);
    settings.validate().expect("default direct peer is valid");
}

#[test]
fn waku_direct_peers_validate_peer_id_and_multiaddr() {
    let mut settings = WalletSettings::default();
    settings.waku.direct_peers = Some(vec![WakuDirectPeerSetting {
        peer_id: "not-a-peer-id".to_string(),
        addr: "not-a-multiaddr".to_string(),
    }]);

    let err = settings.validate().expect_err("bad direct peer rejected");

    assert!(
        err.messages
            .iter()
            .any(|message| message.contains("waku.direct_peers[0].peer_id"))
    );
    assert!(
        err.messages
            .iter()
            .any(|message| message.contains("waku.direct_peers[0].addr"))
    );
}

#[test]
fn waku_doh_fallback_endpoints_validate_url_schemes() {
    let mut settings = WalletSettings::default();
    settings.waku.doh_fallback_endpoints = Some(vec!["ftp://bad.example/dns-query".to_string()]);

    let err = settings
        .validate()
        .expect_err("bad DoH fallback scheme rejected");

    assert!(
        err.messages
            .iter()
            .any(|message| message.contains("waku.doh_fallback_endpoints[0]"))
    );
}

#[test]
fn encoded_settings_decode_without_db() {
    let settings = WalletSettings::default();
    let data = encode_wallet_settings(&settings).expect("encode settings");
    let decoded = decode_wallet_settings(&data).expect("decode settings");
    assert_eq!(decoded, settings);
}
