use super::resolve_relay_adapt_contract;
use crate::BroadcasterServiceError;
use alloy::primitives::Address;
use broadcaster_core::deployment::RailgunDeployment;
use config::Chain;

#[test]
fn auto_refill_requires_a_legacy_relay_adapt() {
    let auto_refill_chain = |chain_id: u64| -> Chain {
        serde_json::from_value(serde_json::json!({
            "key": { "Mnemonic": {
                "seed_phrase": "test test test test test test test test test test test junk",
                "init_block_number": 0,
                "auto_refill": { "interval": "10m", "min_amount": 1, "target_amount": 2 }
            } },
            "chain_id": chain_id,
            "fee_bonus": 0,
            "fees_ttl": "60s",
            "fees_refresh_interval": "30s",
            "fees": {},
            "query_rpcs": [],
            "wrapped_native_token": Address::ZERO,
            "submit_rpcs": [],
            "evm_wallets": []
        }))
        .expect("chain config")
    };

    let base = RailgunDeployment::for_chain(8453);
    assert!(matches!(
        resolve_relay_adapt_contract(&auto_refill_chain(8453), base.as_ref()),
        Err(BroadcasterServiceError::AutoRefillRequiresRelayAdapt)
    ));
    let ethereum = RailgunDeployment::for_chain(1).expect("ethereum deployment");
    assert_eq!(
        resolve_relay_adapt_contract(&auto_refill_chain(1), Some(&ethereum))
            .expect("default relay adapt"),
        ethereum.relay_adapt_contract
    );
}
