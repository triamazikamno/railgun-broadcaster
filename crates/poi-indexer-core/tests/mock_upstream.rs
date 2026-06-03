use alloy_primitives::FixedBytes;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router, routing::post};
use ed25519_dalek::{Signer, SigningKey};
use poi::poi::{PoiEventType, PoiSyncedListEvent, SignedBlockedShield, SignedPoiEvent};
use poi_indexer_core::blocked::BlockedShieldsArtifact;
use poi_indexer_core::scrape::{PageSizeAdapter, RetryPolicy, ScrapeError, ScrapeWorker};
use poi_indexer_core::snapshot::{Lifecycle, SnapshotReader};
use poi_indexer_core::store::{Store, run_migrations};
use poi_indexer_core::verify::{verify_blocked_shield, verify_poi_event};
use reqwest::Url;
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

#[tokio::test]
async fn mock_upstream_serves_node_status_events_and_blocked_shields()
-> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes(&[11_u8; 32]);
    let state = MockState::fixture(&signing_key, 3, 2);
    let (upstream_url, server) = spawn_mock_upstream(state.clone()).await?;

    let status = json_rpc(&upstream_url, "ppoi_node_status", json!({})).await?;
    assert_eq!(status["result"]["status"], "ok");

    let events = json_rpc(
        &upstream_url,
        "ppoi_poi_events",
        json!({
            "chainType": "0",
            "chainID": "1",
            "txidVersion": "V2_PoseidonMerkle",
            "listKey": hex::encode(state.list_key),
            "startIndex": 0,
            "endIndex": 1,
        }),
    )
    .await?;
    let events = serde_json::from_value::<Vec<PoiSyncedListEvent>>(events["result"].clone())?;
    assert_eq!(events.len(), 2);
    let list_key = list_key_bytes(&state.list_key);
    for event in &events {
        verify_poi_event(&event.signed_poi_event, &list_key)?;
    }

    let blocked_shields = json_rpc(
        &upstream_url,
        "ppoi_blocked_shields",
        json!({
            "chainType": "0",
            "chainID": "1",
            "txidVersion": "V2_PoseidonMerkle",
            "listKey": hex::encode(state.list_key),
            "startIndex": 0,
            "endIndex": 10,
        }),
    )
    .await?;
    let blocked_shields =
        serde_json::from_value::<Vec<SignedBlockedShield>>(blocked_shields["result"].clone())?;
    assert_eq!(blocked_shields.len(), 2);
    for record in &blocked_shields {
        verify_blocked_shield(record, &list_key)?;
    }

    assert!(state.method_seen("ppoi_node_status"));
    assert!(state.method_seen("ppoi_poi_events"));
    assert!(state.method_seen("ppoi_blocked_shields"));

    server.abort();
    Ok(())
}

#[tokio::test]
async fn indexer_mock_upstream_produces_decodable_snapshot_with_valid_signatures()
-> Result<(), Box<dyn std::error::Error>> {
    let node = match Postgres::default().start().await {
        Ok(node) => node,
        Err(err) if is_docker_unavailable(&err) => {
            eprintln!("skipping mock upstream snapshot test: Docker is unavailable");
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    let connection_string = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        node.get_host_port_ipv4(5432).await?
    );
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&connection_string)
        .await?;
    run_migrations(&pool).await?;

    let signing_key = SigningKey::from_bytes(&[12_u8; 32]);
    let state = MockState::fixture(&signing_key, 4, 2);
    let (upstream_url, server) = spawn_mock_upstream(state.clone()).await?;
    let store = Store::new(pool);

    let mut worker = worker(&upstream_url, state.list_key, store.clone(), 2, 1, 1);
    worker.run_until_caught_up().await?;
    worker.sync_blocked_shields_until_caught_up().await?;

    let lifecycle = Lifecycle::new(store, upstream_url, 0, [7; 32]);
    let snapshot = SnapshotReader::read(&lifecycle.build_base(&state.list_key, 1, 3).await?)?;
    let blocked_artifact = BlockedShieldsArtifact::read(
        &lifecycle
            .build_blocked_shields_artifact(&state.list_key, 1)
            .await?
            .to_bytes()?,
    )?;

    assert_eq!(snapshot.events.len(), 4);
    assert_eq!(snapshot.blocked_shields.len(), 0);
    assert_eq!(blocked_artifact.blocked_shields.len(), 2);
    let list_key = list_key_bytes(&state.list_key);
    for event in &snapshot.events {
        let signed_event = SignedPoiEvent {
            index: event.event_index,
            blinded_commitment: format!("0x{}", hex::encode(event.blinded_commitment)),
            signature: hex::encode(event.signature),
            event_type: event.event_type,
        };
        verify_poi_event(&signed_event, &list_key)?;
    }
    for record in &blocked_artifact.blocked_shields {
        let signed_record = SignedBlockedShield {
            commitment_hash: record.commitment_hash.clone(),
            blinded_commitment: record.blinded_commitment.clone(),
            block_reason: record.block_reason.clone(),
            signature: record.signature.clone(),
        };
        verify_blocked_shield(&signed_record, &list_key)?;
    }

    server.abort();
    Ok(())
}

#[tokio::test]
async fn blocked_shield_resync_keeps_previous_set_when_paginated_upstream_changes()
-> Result<(), Box<dyn std::error::Error>> {
    let node = match Postgres::default().start().await {
        Ok(node) => node,
        Err(err) if is_docker_unavailable(&err) => {
            eprintln!("skipping blocked-shield mutation test: Docker is unavailable");
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    let connection_string = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        node.get_host_port_ipv4(5432).await?
    );
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&connection_string)
        .await?;
    run_migrations(&pool).await?;

    let signing_key = SigningKey::from_bytes(&[14_u8; 32]);
    let state =
        MockState::fixture(&signing_key, 0, 3).with_first_blocked_removed_after_next_blocked_page();
    let stable_after_removal = state.blocked_shields()[1..].to_vec();
    let (upstream_url, server) = spawn_mock_upstream(state.clone()).await?;
    let store = Store::new(pool);

    let mut tx = store.begin().await?;
    Store::replace_blocked_shields(&mut tx, &state.list_key, 1, &stable_after_removal).await?;
    tx.commit().await?;

    let mut worker = worker(&upstream_url, state.list_key, store.clone(), 2, 2, 1);
    let error = worker
        .sync_blocked_shields_until_caught_up()
        .await
        .expect_err("unstable blocked-shield set should fail this cycle");

    assert!(matches!(
        error,
        ScrapeError::BlockedShieldSetChanged {
            first_count: 2,
            second_count: 2
        }
    ));
    let stored = store.all_blocked_shields(&state.list_key, 1).await?;
    assert_eq!(stored.len(), 2);
    assert_eq!(stored[0].blinded_commitment, [42_u8; 32]);
    assert_eq!(stored[1].blinded_commitment, [43_u8; 32]);

    server.abort();
    Ok(())
}

#[tokio::test]
async fn scrape_worker_shrinks_page_size_after_page_timeouts()
-> Result<(), Box<dyn std::error::Error>> {
    let node = match Postgres::default().start().await {
        Ok(node) => node,
        Err(err) if is_docker_unavailable(&err) => {
            eprintln!("skipping mock upstream retry test: Docker is unavailable");
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    let connection_string = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        node.get_host_port_ipv4(5432).await?
    );
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&connection_string)
        .await?;
    run_migrations(&pool).await?;

    let signing_key = SigningKey::from_bytes(&[13_u8; 32]);
    let state = MockState::fixture(&signing_key, 4, 0)
        .with_event_page_timeout_above(2, Duration::from_millis(50));
    let (upstream_url, server) = spawn_mock_upstream(state.clone()).await?;
    let store = Store::new(pool);

    let mut worker = worker_with_timeout(
        &upstream_url,
        state.list_key,
        store.clone(),
        4,
        4,
        1,
        Duration::from_millis(5),
    );
    worker.run_until_caught_up().await?;

    let stored_events = store.page_event_range(&state.list_key, 1, 0, 10).await?;
    assert_eq!(stored_events.len(), 4);
    assert_eq!(worker.page_size().current_size(), 2);
    assert_eq!(
        state.event_requests(),
        vec![(0, 3), (0, 1), (2, 3), (4, 7), (4, 5)]
    );

    server.abort();
    Ok(())
}

#[tokio::test]
async fn scrape_worker_ingests_mock_upstream_and_resumes_after_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let node = match Postgres::default().start().await {
        Ok(node) => node,
        Err(err) if is_docker_unavailable(&err) => {
            eprintln!("skipping mock upstream scrape test: Docker is unavailable");
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    let connection_string = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        node.get_host_port_ipv4(5432).await?
    );
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&connection_string)
        .await?;
    run_migrations(&pool).await?;

    let signing_key = SigningKey::from_bytes(&[11_u8; 32]);
    let state = MockState::fixture(&signing_key, 3, 0);
    let (upstream_url, server) = spawn_mock_upstream(state.clone()).await?;
    let store = Store::new(pool);

    let first_worker = worker(&upstream_url, state.list_key, store.clone(), 2, 2, 1);
    assert!(matches!(
        first_worker.sync_next_page().await?,
        poi_indexer_core::scrape::SyncPageOutcome::Ingested {
            count: 2,
            last_event_index: 1
        }
    ));

    let mut restarted_worker = worker(&upstream_url, state.list_key, store.clone(), 2, 2, 1);
    restarted_worker.run_until_caught_up().await?;

    let stored_events = store.page_event_range(&state.list_key, 1, 0, 10).await?;
    assert_eq!(stored_events.len(), 3);
    assert_eq!(stored_events[0].event_index, 0);
    assert_eq!(stored_events[1].event_index, 1);
    assert_eq!(stored_events[2].event_index, 2);
    assert_eq!(
        store
            .last_event_index(&state.list_key, 1, &upstream_url)
            .await?,
        Some(2)
    );
    assert_eq!(state.event_requests(), vec![(0, 1), (2, 3), (3, 4)]);

    server.abort();
    Ok(())
}

#[derive(Clone)]
struct MockState {
    list_key: FixedBytes<32>,
    chain_id: u64,
    events: Arc<Vec<PoiSyncedListEvent>>,
    blocked_shields: Arc<Mutex<Vec<SignedBlockedShield>>>,
    requests: Arc<Mutex<Vec<MockRequest>>>,
    timeout_event_pages_larger_than: Option<u64>,
    event_page_timeout_delay: Duration,
    remove_first_blocked_after_next_blocked_page: Arc<Mutex<bool>>,
}

impl MockState {
    fn fixture(signing_key: &SigningKey, event_count: u64, blocked_shield_count: u64) -> Self {
        let list_key = FixedBytes::from(signing_key.verifying_key().to_bytes());
        let events = (0..event_count)
            .map(|index| {
                signed_event(
                    signing_key,
                    index,
                    u8::try_from(index + 1).expect("fixture index fits in u8"),
                    event_type(index),
                )
            })
            .collect::<Vec<_>>();
        let blocked_shields = (0..blocked_shield_count)
            .map(|index| {
                signed_blocked_shield(
                    signing_key,
                    u8::try_from(index + 31).expect("fixture index fits in u8"),
                    u8::try_from(index + 41).expect("fixture index fits in u8"),
                    Some(format!("blocked fixture {index}")),
                )
            })
            .collect::<Vec<_>>();

        Self {
            list_key,
            chain_id: 1,
            events: Arc::new(events),
            blocked_shields: Arc::new(Mutex::new(blocked_shields)),
            requests: Arc::new(Mutex::new(Vec::new())),
            timeout_event_pages_larger_than: None,
            event_page_timeout_delay: Duration::ZERO,
            remove_first_blocked_after_next_blocked_page: Arc::new(Mutex::new(false)),
        }
    }

    const fn with_event_page_timeout_above(mut self, page_size: u64, delay: Duration) -> Self {
        self.timeout_event_pages_larger_than = Some(page_size);
        self.event_page_timeout_delay = delay;
        self
    }

    fn with_first_blocked_removed_after_next_blocked_page(self) -> Self {
        *self
            .remove_first_blocked_after_next_blocked_page
            .lock()
            .expect("blocked-shield mutation flag lock") = true;
        self
    }

    fn blocked_shields(&self) -> Vec<SignedBlockedShield> {
        self.blocked_shields
            .lock()
            .expect("blocked shields lock")
            .clone()
    }

    fn method_seen(&self, method: &str) -> bool {
        self.requests
            .lock()
            .expect("requests lock poisoned")
            .iter()
            .any(|request| request.method == method)
    }

    fn event_requests(&self) -> Vec<(u64, u64)> {
        self.requests
            .lock()
            .expect("requests lock poisoned")
            .iter()
            .filter(|request| request.method == "ppoi_poi_events")
            .filter_map(|request| request.range)
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MockRequest {
    method: String,
    range: Option<(u64, u64)>,
}

async fn spawn_mock_upstream(
    state: MockState,
) -> Result<(String, tokio::task::JoinHandle<()>), Box<dyn std::error::Error>> {
    let app = Router::new().route("/", post(handle_rpc)).with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    let server = tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, app).await {
            panic!("mock upstream server failed: {err}");
        }
    });
    Ok((url, server))
}

async fn handle_rpc(State(state): State<MockState>, Json(body): Json<Value>) -> Response {
    let id = body.get("id").cloned().unwrap_or_else(|| json!(1));
    let method = body
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let range = request_range(&body);
    state
        .requests
        .lock()
        .expect("requests lock poisoned")
        .push(MockRequest {
            method: method.to_string(),
            range,
        });

    match method {
        "ppoi_node_status" => Json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "status": "ok",
                "lists": [{
                    "listKey": hex::encode(state.list_key),
                    "chainIds": [state.chain_id],
                }],
            },
        }))
        .into_response(),
        "ppoi_poi_events" => {
            let (start_index, end_index) = range.unwrap_or_default();
            if state
                .timeout_event_pages_larger_than
                .is_some_and(|max_page_size| {
                    end_index.saturating_sub(start_index).saturating_add(1) > max_page_size
                })
            {
                tokio::time::sleep(state.event_page_timeout_delay).await;
            }
            let result = state
                .events
                .iter()
                .filter(|event| {
                    let index = event.signed_poi_event.index;
                    index >= start_index && index <= end_index
                })
                .cloned()
                .collect::<Vec<_>>();
            Json(json!({ "jsonrpc": "2.0", "id": id, "result": result })).into_response()
        }
        "ppoi_blocked_shields" => {
            let (start_index, end_index) = range.unwrap_or_default();
            let result = {
                let mut blocked_shields =
                    state.blocked_shields.lock().expect("blocked shields lock");
                let result = blocked_shields
                    .iter()
                    .enumerate()
                    .filter(|(index, _record)| {
                        let index = u64::try_from(*index).expect("fixture index fits in u64");
                        index >= start_index && index <= end_index
                    })
                    .map(|(_index, record)| record.clone())
                    .collect::<Vec<_>>();
                let should_remove = {
                    let mut flag = state
                        .remove_first_blocked_after_next_blocked_page
                        .lock()
                        .expect("blocked-shield mutation flag lock");
                    let should_remove = *flag;
                    *flag = false;
                    should_remove
                };
                if should_remove && !blocked_shields.is_empty() {
                    blocked_shields.remove(0);
                }
                result
            };
            Json(json!({ "jsonrpc": "2.0", "id": id, "result": result })).into_response()
        }
        _ => Json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32601, "message": "method not found" }
        }))
        .into_response(),
    }
}

async fn json_rpc(
    upstream_url: &str,
    method: &'static str,
    params: Value,
) -> Result<Value, Box<dyn std::error::Error>> {
    let response = reqwest::Client::new()
        .post(upstream_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        }))
        .send()
        .await?
        .error_for_status()?
        .json::<Value>()
        .await?;
    Ok(response)
}

fn request_range(body: &Value) -> Option<(u64, u64)> {
    Some((
        body["params"]["startIndex"].as_u64()?,
        body["params"]["endIndex"].as_u64()?,
    ))
}

fn worker(
    upstream_url: &str,
    list_key: FixedBytes<32>,
    store: Store,
    current_page_size: usize,
    max_page_size: usize,
    min_page_size: usize,
) -> ScrapeWorker {
    ScrapeWorker::new(
        list_key,
        1,
        upstream_url.to_string(),
        poi::poi::PoiRpcClient::new(Url::parse(upstream_url).expect("valid upstream URL")),
        PageSizeAdapter::new(current_page_size, max_page_size, min_page_size),
        RetryPolicy::new(1, Duration::ZERO, Duration::ZERO),
        store,
        Duration::ZERO,
    )
}

fn worker_with_timeout(
    upstream_url: &str,
    list_key: FixedBytes<32>,
    store: Store,
    current_page_size: usize,
    max_page_size: usize,
    min_page_size: usize,
    timeout: Duration,
) -> ScrapeWorker {
    let http = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .expect("build timeout HTTP client");
    ScrapeWorker::new(
        list_key,
        1,
        upstream_url.to_string(),
        poi::poi::PoiRpcClient::with_http_client(
            Url::parse(upstream_url).expect("valid upstream URL"),
            http,
        ),
        PageSizeAdapter::new(current_page_size, max_page_size, min_page_size),
        RetryPolicy::new(1, Duration::ZERO, Duration::ZERO),
        store,
        Duration::ZERO,
    )
}

fn signed_event(
    signing_key: &SigningKey,
    index: u64,
    commitment_byte: u8,
    event_type: PoiEventType,
) -> PoiSyncedListEvent {
    let blinded_commitment = hex_bytes(commitment_byte, 32);
    let event_type_name = event_type_str(event_type);
    let message = format!(
        r#"{{"index":{index},"blindedCommitment":"{blinded_commitment}","type":"{event_type_name}"}}"#
    );
    let signature = hex::encode(signing_key.sign(message.as_bytes()).to_bytes());

    PoiSyncedListEvent {
        signed_poi_event: SignedPoiEvent {
            index,
            blinded_commitment,
            signature,
            event_type,
        },
        validated_merkleroot: hex_bytes(commitment_byte + 20, 32),
    }
}

fn signed_blocked_shield(
    signing_key: &SigningKey,
    commitment_hash_byte: u8,
    blinded_commitment_byte: u8,
    block_reason: Option<String>,
) -> SignedBlockedShield {
    let commitment_hash = hex_bytes(commitment_hash_byte, 32);
    let blinded_commitment = hex_bytes(blinded_commitment_byte, 32);
    let message = block_reason.as_ref().map_or_else(
        || {
            format!(
                r#"{{"commitmentHash":"{commitment_hash}","blindedCommitment":"{blinded_commitment}"}}"#
            )
        },
        |reason| {
            format!(
                r#"{{"commitmentHash":"{commitment_hash}","blindedCommitment":"{blinded_commitment}","blockReason":"{reason}"}}"#
            )
        },
    );
    let signature = hex::encode(signing_key.sign(message.as_bytes()).to_bytes());

    SignedBlockedShield {
        commitment_hash,
        blinded_commitment,
        block_reason,
        signature,
    }
}

const fn event_type(index: u64) -> PoiEventType {
    match index % 4 {
        0 => PoiEventType::Shield,
        1 => PoiEventType::Transact,
        2 => PoiEventType::Unshield,
        _ => PoiEventType::LegacyTransact,
    }
}

const fn event_type_str(event_type: PoiEventType) -> &'static str {
    match event_type {
        PoiEventType::Shield => "Shield",
        PoiEventType::Transact => "Transact",
        PoiEventType::Unshield => "Unshield",
        PoiEventType::LegacyTransact => "LegacyTransact",
    }
}

fn hex_bytes(byte: u8, len: usize) -> String {
    format!("0x{}", hex::encode(vec![byte; len]))
}

const fn list_key_bytes(list_key: &FixedBytes<32>) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes.copy_from_slice(list_key.as_slice());
    bytes
}

fn is_docker_unavailable(error: &impl std::fmt::Debug) -> bool {
    let message = format!("{error:?}");
    message.contains("SocketNotFoundError") || message.contains("Connection refused")
}
