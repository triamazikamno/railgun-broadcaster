mod graphql;
mod types;

use tracing::info;

use types::Commitment;

use crate::sync::{SyncProgress, SyncResult};
use std::collections::{BTreeMap, HashSet};
use std::num::NonZeroUsize;
use url::Url;

use crate::tree::{MerkleForest, MerkleTreeUpdate, TREE_LEAF_COUNT, normalize_tree_position};

pub use graphql::{DEFAULT_PAGE_SIZE, QuickSyncClient};
pub use types::{
    IndexedLegacyEncryptedCommitment, IndexedLegacyGeneratedCommitment, IndexedNullifier,
    IndexedShieldCommitment, IndexedTransactCommitment,
};

#[derive(Debug, Clone)]
pub struct QuickSyncConfig {
    pub endpoint: Url,
    pub start_block: u64,
    pub end_block: Option<u64>,
    pub page_size: NonZeroUsize,
    /// Optional pre-configured HTTP client (e.g. with proxy support).
    pub http_client: Option<reqwest::Client>,
}

impl Default for QuickSyncConfig {
    fn default() -> Self {
        Self {
            endpoint: Url::parse(
                "https://rail-squid.squids.live/squid-railgun-ethereum-v2/graphql",
            )
            .expect("valid quick sync endpoint"),
            start_block: 0,
            end_block: None,
            page_size: DEFAULT_PAGE_SIZE,
            http_client: None,
        }
    }
}

#[derive(Debug)]
pub struct QuickSyncResult {
    pub forest: MerkleForest,
    pub progress: SyncProgress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuickSyncPageProgress {
    pub start_block: u64,
    pub latest_block: u64,
    pub target_block: Option<u64>,
    pub commitments: usize,
}

pub async fn run_quick_sync(config: QuickSyncConfig) -> SyncResult<QuickSyncResult> {
    let mut forest = MerkleForest::new();
    let progress = run_quick_sync_into(&mut forest, config).await?;

    Ok(QuickSyncResult { forest, progress })
}

pub async fn run_quick_sync_into(
    forest: &mut MerkleForest,
    config: QuickSyncConfig,
) -> SyncResult<SyncProgress> {
    run_quick_sync_into_with_progress(forest, config, |_| {}).await
}

pub async fn run_quick_sync_into_with_progress<F>(
    forest: &mut MerkleForest,
    config: QuickSyncConfig,
    mut on_progress: F,
) -> SyncResult<SyncProgress>
where
    F: FnMut(QuickSyncPageProgress),
{
    let QuickSyncConfig {
        endpoint,
        start_block,
        end_block,
        page_size,
        http_client,
    } = config;
    let page_size_value = page_size.get();
    let client = match http_client {
        Some(c) => QuickSyncClient::with_http_client(endpoint, c),
        None => QuickSyncClient::new(endpoint),
    };

    let mut total_commitments = 0usize;
    let mut latest_block = start_block;
    let mut latest_commitment_block = start_block;
    let max_commitments = 16 * TREE_LEAF_COUNT as usize;
    let mut commitment_ids = HashSet::new();

    let mut commitment_cursor = start_block;
    loop {
        let commitments = client
            .fetch_list::<graphql::CommitmentsData>(
                graphql::COMMITMENTS_QUERY,
                commitment_cursor,
                page_size,
            )
            .await?;
        let commitment_count = commitments.len();
        if commitment_count == 0 {
            break;
        }

        let mut max_block_seen = commitment_cursor;
        let mut max_block_in_range = None;
        let mut batch_map: BTreeMap<(u32, u64), Vec<Commitment>> = BTreeMap::new();
        for commitment in commitments {
            let block_number: u64 = commitment.block_number.to();
            max_block_seen = max_block_seen.max(block_number);
            if let Some(end_block) = end_block
                && block_number > end_block
            {
                continue;
            }
            max_block_in_range = Some(max_block_in_range.unwrap_or(block_number).max(block_number));
            if !commitment_ids.insert(commitment.id) {
                continue;
            }
            let tree_number: u32 = commitment.tree_number.to();
            let batch_start_tree_position: u64 = commitment.batch_start_tree_position.to();
            let key = (tree_number, batch_start_tree_position);
            batch_map.entry(key).or_default().push(commitment);
        }

        for ((_tree_number, _start_position), batch) in batch_map {
            for commitment in batch {
                let tree_number: u32 = commitment.tree_number.to();
                let tree_position: u64 = commitment.tree_position.to();
                let (tree_number, tree_position) =
                    normalize_tree_position(tree_number, tree_position);
                let leaf = MerkleTreeUpdate {
                    tree_number,
                    tree_position,
                    hash: commitment.hash,
                };
                forest.insert_leaf(leaf)?;
                total_commitments += 1;
            }
        }

        if let Some(block) = max_block_in_range {
            latest_commitment_block = latest_commitment_block.max(block);
            latest_block = latest_block.max(block);
        }
        info!(
            target: "quick-sync",
            "commitments page: count={}, latest_block={}",
            total_commitments,
            latest_block
        );
        on_progress(QuickSyncPageProgress {
            start_block,
            latest_block,
            target_block: end_block,
            commitments: total_commitments,
        });

        if commitment_count < page_size_value {
            break;
        }
        if let Some(end_block) = end_block
            && max_block_seen >= end_block
        {
            break;
        }
        if total_commitments >= max_commitments {
            break;
        }
        commitment_cursor = max_block_seen;
    }

    forest.compute_roots();
    if let Some(target_block) = end_block {
        latest_block = latest_block.max(target_block);
        latest_commitment_block = latest_commitment_block.max(target_block);
    }

    Ok(SyncProgress {
        latest_block,
        latest_commitment_block,
        commitments: total_commitments,
        nullifiers: 0,
        unshields: 0,
    })
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::num::NonZeroUsize;
    use std::sync::mpsc::{self, Receiver};
    use std::time::Duration;

    use alloy::primitives::{FixedBytes, U256};
    use url::Url;

    use super::{QuickSyncClient, QuickSyncConfig, run_quick_sync, run_quick_sync_into};
    use crate::tree::{MerkleForest, MerkleTreeUpdate};

    struct MockGraphql {
        url: Url,
        requests: Receiver<String>,
    }

    fn spawn_graphql(responses: Vec<&'static str>) -> MockGraphql {
        spawn_graphql_with_status(responses.into_iter().map(|body| (200, body)).collect())
    }

    fn spawn_graphql_with_status(responses: Vec<(u16, &'static str)>) -> MockGraphql {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let url = Url::parse(&format!(
            "http://{}/graphql",
            listener.local_addr().unwrap()
        ))
        .expect("mock url");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for (status, response) in responses {
                let (mut stream, _) = listener.accept().expect("accept request");
                let body = read_http_body(&mut stream);
                tx.send(body).expect("send request body");
                let reply = format!(
                    "HTTP/1.1 {status} OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    response.len(),
                    response
                );
                stream.write_all(reply.as_bytes()).expect("write response");
            }
        });
        MockGraphql { url, requests: rx }
    }

    fn read_http_body(stream: &mut std::net::TcpStream) -> String {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let read = stream.read(&mut chunk).expect("read request");
            assert!(read > 0, "connection closed before request body");
            buffer.extend_from_slice(&chunk[..read]);
            if let Some((body_start, content_length)) = request_body_bounds(&buffer)
                && buffer.len() >= body_start + content_length
            {
                return String::from_utf8_lossy(&buffer[body_start..body_start + content_length])
                    .to_string();
            }
        }
    }

    fn request_body_bounds(buffer: &[u8]) -> Option<(usize, usize)> {
        let header_end = buffer.windows(4).position(|window| window == b"\r\n\r\n")?;
        let body_start = header_end + 4;
        let headers = String::from_utf8_lossy(&buffer[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case("content-length") {
                    value.trim().parse::<usize>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0);
        Some((body_start, content_length))
    }

    #[tokio::test]
    async fn fetch_squid_height_reads_status_height() {
        let mock = spawn_graphql(vec![r#"{"data":{"squidStatus":{"height":"123"}}}"#]);
        let client = QuickSyncClient::new(mock.url);

        let height = client.fetch_squid_height().await.expect("height");

        assert_eq!(height, 123);
        let request = mock.requests.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(request.contains("squidStatus"));
    }

    #[tokio::test]
    async fn indexed_wallet_probe_accepts_supported_endpoint() {
        let mock = spawn_graphql(vec![
            r#"{"data":{"squidStatus":{"height":"456"},"transactCommitments":[],"shieldCommitments":[],"nullifiers":[],"legacyEncryptedCommitments":[],"legacyGeneratedCommitments":[]}}"#,
        ]);
        let client = QuickSyncClient::new(mock.url);

        let probe = client.probe_indexed_wallet_support().await.expect("probe");

        assert_eq!(probe.height, 456);
        let request = mock.requests.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(request.contains("transactCommitments"));
        assert!(request.contains("shieldCommitments"));
        assert!(request.contains("nullifiers"));
        assert!(request.contains("legacyEncryptedCommitments"));
        assert!(request.contains("legacyGeneratedCommitments"));
        assert!(request.contains("iv"));
        assert!(request.contains("tag"));
        assert!(request.contains("data"));
    }

    #[tokio::test]
    async fn indexed_wallet_probe_rejects_graphql_errors() {
        let mock = spawn_graphql(vec![
            r#"{"data":null,"errors":[{"message":"Cannot query field transactCommitments"}]}"#,
        ]);
        let client = QuickSyncClient::new(mock.url);

        let err = client
            .probe_indexed_wallet_support()
            .await
            .expect_err("probe should fail");

        assert!(err.to_string().contains("graphql errors"));
    }

    #[tokio::test]
    async fn http_status_errors_include_response_body() {
        let mock = spawn_graphql_with_status(vec![(
            400,
            r#"{"errors":[{"message":"bad wallet query"}]}"#,
        )]);
        let client = QuickSyncClient::new(mock.url);

        let err = client
            .probe_indexed_wallet_support()
            .await
            .expect_err("probe should fail");
        let message = err.to_string();

        assert!(message.contains("status 400"));
        assert!(message.contains("bad wallet query"));
    }

    #[tokio::test]
    async fn transact_commitments_parse_nested_ciphertext() {
        let mock = spawn_graphql(vec![
            r#"{"data":{"transactCommitments":[{"id":"0x11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111","transactionHash":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","blockNumber":"12","treeNumber":0,"treePosition":2,"hash":"5","ciphertext":{"ciphertext":{"iv":"0x11111111111111111111111111111111","tag":"0x22222222222222222222222222222222","data":["0x3333333333333333333333333333333333333333333333333333333333333333","0x4444444444444444444444444444444444444444444444444444444444444444","0x5555555555555555555555555555555555555555555555555555555555555555"]},"blindedSenderViewingKey":"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","memo":"0x"}}]}}"#,
        ]);
        let client = QuickSyncClient::new(mock.url);

        let rows = client
            .fetch_transact_commitments(1, 20, NonZeroUsize::new(10).unwrap())
            .await
            .expect("transact rows");

        assert_eq!(rows.len(), 1);
        let mut expected_iv_tag = [0u8; 32];
        expected_iv_tag[..16].fill(0x11);
        expected_iv_tag[16..].fill(0x22);
        assert_eq!(
            rows[0].ciphertext.ciphertext[0],
            FixedBytes::from(expected_iv_tag)
        );
        assert_eq!(
            rows[0].ciphertext.ciphertext[1],
            FixedBytes::from([0x33; 32])
        );
    }

    #[tokio::test]
    async fn malformed_nested_ciphertext_is_rejected() {
        let mock = spawn_graphql(vec![
            r#"{"data":{"transactCommitments":[{"id":"0x11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111","transactionHash":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","blockNumber":"12","treeNumber":0,"treePosition":2,"hash":"5","ciphertext":{"ciphertext":{"iv":"0x11111111111111111111111111111111","tag":"0x22222222222222222222222222222222","data":["0x3333333333333333333333333333333333333333333333333333333333333333"]},"blindedSenderViewingKey":"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","memo":"0x"}}]}}"#,
        ]);
        let client = QuickSyncClient::new(mock.url);

        let err = client
            .fetch_transact_commitments(1, 20, NonZeroUsize::new(10).unwrap())
            .await
            .expect_err("ciphertext should fail");

        assert!(
            err.to_string()
                .contains("expected 3 ciphertext data blocks")
        );
    }

    #[tokio::test]
    async fn shield_commitments_parse_token_type_enum() {
        let mock = spawn_graphql(vec![
            r#"{"data":{"shieldCommitments":[{"id":"0x11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111","transactionHash":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","blockNumber":"12","treeNumber":0,"treePosition":2,"preimage":{"npk":"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","token":{"tokenType":"ERC20","tokenAddress":"0x0000000000000000000000000000000000000000","tokenSubID":"0x00"},"value":"5"},"shieldKey":"0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","encryptedBundle":["0x3333333333333333333333333333333333333333333333333333333333333333","0x4444444444444444444444444444444444444444444444444444444444444444","0x5555555555555555555555555555555555555555555555555555555555555555"]}]}}"#,
        ]);
        let client = QuickSyncClient::new(mock.url);

        let rows = client
            .fetch_shield_commitments(1, 20, NonZeroUsize::new(10).unwrap())
            .await
            .expect("shield rows");

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].preimage().token.tokenType, 0);
    }

    #[tokio::test]
    async fn indexed_wallet_page_fetches_all_streams_in_one_request() {
        let mock = spawn_graphql(vec![
            r#"{"data":{"transactCommitments":[{"id":"0x11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111","transactionHash":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","blockNumber":"12","treeNumber":0,"treePosition":2,"hash":"5","ciphertext":{"ciphertext":{"iv":"0x11111111111111111111111111111111","tag":"0x22222222222222222222222222222222","data":["0x3333333333333333333333333333333333333333333333333333333333333333","0x4444444444444444444444444444444444444444444444444444444444444444","0x5555555555555555555555555555555555555555555555555555555555555555"]},"blindedSenderViewingKey":"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","memo":"0x"}}],"shieldCommitments":[{"id":"0x22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222","transactionHash":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","blockNumber":"13","treeNumber":0,"treePosition":3,"preimage":{"npk":"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","token":{"tokenType":"ERC20","tokenAddress":"0x0000000000000000000000000000000000000000","tokenSubID":"0x00"},"value":"5"},"shieldKey":"0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","encryptedBundle":["0x3333333333333333333333333333333333333333333333333333333333333333","0x4444444444444444444444444444444444444444444444444444444444444444","0x5555555555555555555555555555555555555555555555555555555555555555"]}],"nullifiers":[{"id":"0x33333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333","transactionHash":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","blockNumber":"14","treeNumber":0,"nullifier":"0x01"}]}}"#,
        ]);
        let client = QuickSyncClient::new(mock.url);

        let page = client
            .fetch_indexed_wallet_page(1, 20, NonZeroUsize::new(10).unwrap())
            .await
            .expect("wallet page");

        assert_eq!(page.transact_commitments.len(), 1);
        assert_eq!(page.shield_commitments.len(), 1);
        assert_eq!(page.nullifiers.len(), 1);
        let request = mock.requests.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(request.contains("query IndexedWalletPage"));
        assert!(request.contains("transactCommitments"));
        assert!(request.contains("shieldCommitments"));
        assert!(request.contains("nullifiers"));
        assert!(!request.contains("legacyEncryptedCommitments"));
        assert!(!request.contains("legacyGeneratedCommitments"));
        assert!(mock.requests.try_recv().is_err());
    }

    #[tokio::test]
    async fn indexed_legacy_wallet_page_fetches_only_legacy_streams() {
        let mock = spawn_graphql(vec![
            r#"{"data":{"legacyEncryptedCommitments":[{"id":"0x11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111","transactionHash":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","blockNumber":"12","treeNumber":0,"treePosition":2,"hash":"5","ciphertext":{"ciphertext":{"iv":"0x11111111111111111111111111111111","tag":"0x22222222222222222222222222222222","data":["0x3333333333333333333333333333333333333333333333333333333333333333","0x4444444444444444444444444444444444444444444444444444444444444444","0x5555555555555555555555555555555555555555555555555555555555555555"]},"ephemeralKeys":["0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"],"memo":[]}}],"legacyGeneratedCommitments":[{"id":"0x22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222","transactionHash":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","blockNumber":"13","treeNumber":0,"treePosition":3,"hash":"5","preimage":{"npk":"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","token":{"tokenType":"ERC20","tokenAddress":"0x0000000000000000000000000000000000000000","tokenSubID":"0x00"},"value":"5"},"encryptedRandom":["0x28d5de9f22849ef69dc3639a947c7ce151ade418a2cf331d5e8b7348f4c065","0x44444444444444444444444444444444"]}],"nullifiers":[{"id":"0x33333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333","transactionHash":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","blockNumber":"14","treeNumber":0,"nullifier":"0x01"}]}}"#,
        ]);
        let client = QuickSyncClient::new(mock.url);

        let page = client
            .fetch_indexed_legacy_wallet_page(1, 20, NonZeroUsize::new(10).unwrap())
            .await
            .expect("legacy wallet page");

        assert_eq!(page.legacy_encrypted_commitments.len(), 1);
        assert_eq!(page.legacy_generated_commitments.len(), 1);
        assert_eq!(page.nullifiers.len(), 1);
        let mut expected_random = [0_u8; 32];
        expected_random[1..].copy_from_slice(&[
            0x28, 0xd5, 0xde, 0x9f, 0x22, 0x84, 0x9e, 0xf6, 0x9d, 0xc3, 0x63, 0x9a, 0x94, 0x7c,
            0x7c, 0xe1, 0x51, 0xad, 0xe4, 0x18, 0xa2, 0xcf, 0x33, 0x1d, 0x5e, 0x8b, 0x73, 0x48,
            0xf4, 0xc0, 0x65,
        ]);
        assert_eq!(
            page.legacy_generated_commitments[0].encrypted_random.0,
            FixedBytes::from(expected_random)
        );
        let request = mock.requests.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(request.contains("query IndexedLegacyWalletPage"));
        assert!(request.contains("legacyEncryptedCommitments"));
        assert!(request.contains("legacyGeneratedCommitments"));
        assert!(request.contains("nullifiers"));
        assert!(!request.contains("transactCommitments"));
        assert!(!request.contains("shieldCommitments"));
        assert!(mock.requests.try_recv().is_err());
    }

    #[tokio::test]
    async fn commitment_quick_sync_does_not_fetch_non_forest_entities() {
        let mock = spawn_graphql(vec![r#"{"data":{"commitments":[]}}"#]);
        let result = run_quick_sync(QuickSyncConfig {
            endpoint: mock.url,
            start_block: 10,
            end_block: Some(25),
            page_size: NonZeroUsize::new(10).unwrap(),
            http_client: None,
        })
        .await
        .expect("quick sync");

        assert_eq!(result.progress.latest_commitment_block, 25);
        assert_eq!(result.progress.nullifiers, 0);
        assert_eq!(result.progress.unshields, 0);
        let request = mock.requests.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(request.contains("commitments"));
        assert!(!request.contains("unshields"));
        assert!(!request.contains("nullifiers"));
    }

    #[tokio::test]
    async fn quick_sync_into_advances_existing_forest_to_target() {
        let mock = spawn_graphql(vec![
            r#"{"data":{"commitments":[{"id":"0x11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111","treeNumber":"0","treePosition":"2","batchStartTreePosition":"2","blockNumber":"12","hash":"5"}]}}"#,
        ]);
        let mut forest = MerkleForest::new();
        forest
            .insert_leaf(MerkleTreeUpdate {
                tree_number: 0,
                tree_position: 1,
                hash: U256::from(4_u8),
            })
            .expect("insert existing leaf");

        let progress = run_quick_sync_into(
            &mut forest,
            QuickSyncConfig {
                endpoint: mock.url,
                start_block: 11,
                end_block: Some(20),
                page_size: NonZeroUsize::new(10).unwrap(),
                http_client: None,
            },
        )
        .await
        .expect("quick sync into forest");

        assert_eq!(progress.latest_commitment_block, 20);
        assert_eq!(forest.leaf_at(0, 1), Some(U256::from(4_u8)));
        assert_eq!(forest.leaf_at(0, 2), Some(U256::from(5_u8)));
    }
}
