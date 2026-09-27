use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy::primitives::{Address, Bytes, U256};
use broadcaster_core::crypto::railgun::ViewingKeyData;
use broadcaster_core::query_rpc_pool::QueryRpcPool;
use config::Chain;
use fees::Manager as FeesManager;
use local_db::{DbConfig, DbStore};
use tx_submit::TxBroadcaster;
use waku_relay::client::{Client, ClientConfig, RelayNetworkConfig, RelayNetworkMode};

use super::{BroadcasterService, WAD};

#[test]
fn tx_submitter_stops_when_service_is_dropped() {
    // Use a separate runtime and a wall-clock deadline: the regression spins
    // inside one poll, so an async timeout on that worker cannot interrupt it.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("runtime");
    let db_dir = tempfile::tempdir().expect("database directory");
    let rx = runtime.block_on(async {
        let chain_cfg: Chain = serde_json::from_value(serde_json::json!({
            "key": { "ViewingPrivkey": "0x" },
            "chain_id": 137,
            "fee_bonus": 0,
            "fees_ttl": "60s",
            "fees_refresh_interval": "30s",
            "fees": {},
            "query_rpcs": [],
            "wrapped_native_token": Address::ZERO,
            "submit_rpcs": [],
            "relay_adapt_contract": Address::ZERO,
            "evm_wallets": [Bytes::from(vec![1; 32])]
        }))
        .expect("chain config");
        let query_rpc_pool = Arc::new(QueryRpcPool::new(Vec::new(), Duration::ZERO));
        let client = Client::new_with_network(
            &ClientConfig::default(),
            RelayNetworkConfig {
                mode: RelayNetworkMode::Proxy,
                ..RelayNetworkConfig::default()
            },
        )
        .expect("offline Waku client");
        let viewing_key =
            ViewingKeyData::from_spending_public_key([7; 32], [U256::from(3), U256::from(9)]);
        let addr = viewing_key.derive_address(None).expect("address");
        let (tx, rx) = kanal::bounded_async(20);
        let service = BroadcasterService {
            chain_id: chain_cfg.chain_id,
            db: Arc::new(
                DbStore::open(DbConfig {
                    root_dir: db_dir.path().to_path_buf(),
                })
                .expect("database"),
            ),
            pending_fee_note_assurance_fallback: Arc::default(),
            fee_note_assurance_submission_tracker: Arc::default(),
            key: viewing_key.viewing_private_key,
            master_public_key: viewing_key.master_public_key,
            addr: addr.clone(),
            advertised_addr: addr,
            tx,
            rx,
            broadcaster: Arc::new(
                TxBroadcaster::try_from((chain_cfg, query_rpc_pool.clone()))
                    .expect("transaction broadcaster"),
            ),
            fees_manager: Arc::new(FeesManager::new(
                &HashMap::new(),
                WAD,
                query_rpc_pool.clone(),
                Address::ZERO,
                Address::ZERO,
                Duration::from_mins(1),
            )),
            evm_wallets: Vec::new(),
            count_transact_requests: Arc::default(),
            count_txs_landed: Arc::default(),
            client: Arc::new(client),
            poi: None,
            required_poi_list: Vec::new(),
            query_rpc_pool,
            railgun_contract: None,
            finality_depth: None,
            receipt_poll_interval: Duration::from_secs(1),
            relay_adapt_contract: Address::ZERO,
            relay_adapt_7702_contract: None,
            identifier: None,
            fees_refresh_interval: Duration::from_secs(30),
            fees_ttl: Duration::from_mins(1),
        };
        let rx = service.rx.clone();
        service.spawn_tx_submitter();
        // This is what unwinding an error during a later chain's startup does.
        drop(service);
        rx
    });

    let deadline = Instant::now() + Duration::from_secs(2);
    while rx.receiver_count() > 1 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    let worker_stopped = rx.receiver_count() == 1;
    runtime.shutdown_timeout(Duration::from_millis(100));
    assert!(
        worker_stopped,
        "transaction worker did not stop after sender drop"
    );
}
