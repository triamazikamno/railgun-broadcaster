use ed25519_dalek::SigningKey;
use poi_indexer_core::publish::ipns::{
    DEFAULT_IPNS_BOOTSTRAP_PEERS, IpnsPublisher, IpnsPublisherConfig, resolve_manifest_cid,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const EMPTY_RAW_CID: &str = "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku";

#[tokio::test]
async fn ipns_manifest_cid_resolves_via_public_dht_when_enabled()
-> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("POI_INDEXER_IPNS_DHT_TEST").ok().as_deref() != Some("1") {
        eprintln!("skipping public IPNS DHT test; set POI_INDEXER_IPNS_DHT_TEST=1 to run it");
        return Ok(());
    }

    let timeout = std::env::var("POI_INDEXER_IPNS_DHT_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse().ok())
        .map_or_else(|| Duration::from_secs(60), Duration::from_secs);
    let config = IpnsPublisherConfig {
        bootstrap_peers: DEFAULT_IPNS_BOOTSTRAP_PEERS
            .iter()
            .map(|addr| addr.parse())
            .collect::<Result<Vec<_>, _>>()?,
        record_lifetime: Duration::from_secs(24 * 60 * 60),
        record_ttl: Duration::from_secs(60 * 60),
        publish_timeout: timeout,
    };
    let signing_key = SigningKey::from_bytes(&[89_u8; 32]);
    let (publisher, publisher_task) = IpnsPublisher::new(&signing_key, config.clone())?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let publisher_task = tokio::spawn(async move { publisher_task.run(shutdown_rx).await });
    let sequence = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after epoch")
        .as_secs();

    let result = async {
        let publication = publisher
            .publish_manifest_cid(EMPTY_RAW_CID, sequence)
            .await?;
        resolve_manifest_cid(publication.peer_id, &config).await
    }
    .await;
    let _ = shutdown_tx.send(true);
    publisher_task.await??;
    let resolved_cid = result?;

    assert_eq!(resolved_cid, EMPTY_RAW_CID);
    Ok(())
}
