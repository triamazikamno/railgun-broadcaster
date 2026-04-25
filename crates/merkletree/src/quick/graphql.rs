use std::num::NonZeroUsize;

use reqwest::Client;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::errors::SyncError;
use crate::quick::types::{
    Commitment, IndexedLegacyEncryptedCommitment, IndexedLegacyGeneratedCommitment,
    IndexedNullifier, IndexedShieldCommitment, IndexedTransactCommitment,
};

pub const DEFAULT_PAGE_SIZE: NonZeroUsize =
    NonZeroUsize::new(10_000).expect("default page size is non-zero");

pub(crate) const COMMITMENTS_QUERY: &str = r"
query Commitments($blockNumber: BigInt = 0, $limit: Int = 10000) {
  commitments(
    orderBy: [blockNumber_ASC, treePosition_ASC]
    where: {blockNumber_gte: $blockNumber}
    limit: $limit
  ) {
    id
    treeNumber
    treePosition
    batchStartTreePosition
    blockNumber
    hash
  }
}
";

pub(crate) const SQUID_STATUS_QUERY: &str = r"
query SquidStatus {
  squidStatus {
    height
  }
}
";

pub(crate) const WALLET_PROBE_QUERY: &str = r"
query WalletProbe($fromBlock: BigInt = 0, $toBlock: BigInt = 0, $limit: Int = 1) {
  squidStatus {
    height
  }
  transactCommitments(
    orderBy: [blockNumber_ASC, treePosition_ASC]
    where: {blockNumber_gte: $fromBlock, blockNumber_lte: $toBlock}
    limit: $limit
  ) {
    id
    transactionHash
    blockNumber
    treeNumber
    treePosition
    hash
    ciphertext {
      ciphertext {
        iv
        tag
        data
      }
      blindedSenderViewingKey
      memo
    }
  }
  shieldCommitments(
    orderBy: [blockNumber_ASC, treePosition_ASC]
    where: {blockNumber_gte: $fromBlock, blockNumber_lte: $toBlock}
    limit: $limit
  ) {
    id
    transactionHash
    blockNumber
    treeNumber
    treePosition
    preimage {
      npk
      token {
        tokenType
        tokenAddress
        tokenSubID
      }
      value
    }
    shieldKey
    encryptedBundle
  }
  nullifiers(
    orderBy: [blockNumber_ASC, nullifier_DESC]
    where: {blockNumber_gte: $fromBlock, blockNumber_lte: $toBlock}
    limit: $limit
  ) {
    id
    transactionHash
    blockNumber
    treeNumber
    nullifier
  }
  legacyEncryptedCommitments(
    orderBy: [blockNumber_ASC, treePosition_ASC]
    where: {blockNumber_gte: $fromBlock, blockNumber_lte: $toBlock}
    limit: $limit
  ) {
    id
    transactionHash
    blockNumber
    treeNumber
    treePosition
    hash
    ciphertext {
      ciphertext {
        iv
        tag
        data
      }
      ephemeralKeys
      memo
    }
  }
  legacyGeneratedCommitments(
    orderBy: [blockNumber_ASC, treePosition_ASC]
    where: {blockNumber_gte: $fromBlock, blockNumber_lte: $toBlock}
    limit: $limit
  ) {
    id
    transactionHash
    blockNumber
    treeNumber
    treePosition
    hash
    preimage {
      npk
      token {
        tokenType
        tokenAddress
        tokenSubID
      }
      value
    }
    encryptedRandom
  }
}
";

pub(crate) const INDEXED_WALLET_PAGE_QUERY: &str = r"
query IndexedWalletPage($fromBlock: BigInt = 0, $toBlock: BigInt = 0, $limit: Int = 10000) {
  transactCommitments(
    orderBy: [blockNumber_ASC, treePosition_ASC]
    where: {blockNumber_gte: $fromBlock, blockNumber_lte: $toBlock}
    limit: $limit
  ) {
    id
    transactionHash
    blockNumber
    treeNumber
    treePosition
    hash
    ciphertext {
      ciphertext {
        iv
        tag
        data
      }
      blindedSenderViewingKey
      memo
    }
  }
  shieldCommitments(
    orderBy: [blockNumber_ASC, treePosition_ASC]
    where: {blockNumber_gte: $fromBlock, blockNumber_lte: $toBlock}
    limit: $limit
  ) {
    id
    transactionHash
    blockNumber
    treeNumber
    treePosition
    preimage {
      npk
      token {
        tokenType
        tokenAddress
        tokenSubID
      }
      value
    }
    shieldKey
    encryptedBundle
  }
  nullifiers(
    orderBy: [blockNumber_ASC, nullifier_DESC]
    where: {blockNumber_gte: $fromBlock, blockNumber_lte: $toBlock}
    limit: $limit
  ) {
    id
    transactionHash
    blockNumber
    treeNumber
    nullifier
  }
}
";

pub(crate) const INDEXED_LEGACY_WALLET_PAGE_QUERY: &str = r"
query IndexedLegacyWalletPage($fromBlock: BigInt = 0, $toBlock: BigInt = 0, $limit: Int = 10000) {
  legacyEncryptedCommitments(
    orderBy: [blockNumber_ASC, treePosition_ASC]
    where: {blockNumber_gte: $fromBlock, blockNumber_lte: $toBlock}
    limit: $limit
  ) {
    id
    transactionHash
    blockNumber
    treeNumber
    treePosition
    hash
    ciphertext {
      ciphertext {
        iv
        tag
        data
      }
      ephemeralKeys
      memo
    }
  }
  legacyGeneratedCommitments(
    orderBy: [blockNumber_ASC, treePosition_ASC]
    where: {blockNumber_gte: $fromBlock, blockNumber_lte: $toBlock}
    limit: $limit
  ) {
    id
    transactionHash
    blockNumber
    treeNumber
    treePosition
    hash
    preimage {
      npk
      token {
        tokenType
        tokenAddress
        tokenSubID
      }
      value
    }
    encryptedRandom
  }
  nullifiers(
    orderBy: [blockNumber_ASC, nullifier_DESC]
    where: {blockNumber_gte: $fromBlock, blockNumber_lte: $toBlock}
    limit: $limit
  ) {
    id
    transactionHash
    blockNumber
    treeNumber
    nullifier
  }
}
";

pub(crate) const TRANSACT_COMMITMENTS_QUERY: &str = r"
query TransactCommitments($fromBlock: BigInt = 0, $toBlock: BigInt = 0, $limit: Int = 10000) {
  transactCommitments(
    orderBy: [blockNumber_ASC, treePosition_ASC]
    where: {blockNumber_gte: $fromBlock, blockNumber_lte: $toBlock}
    limit: $limit
  ) {
    id
    transactionHash
    blockNumber
    treeNumber
    treePosition
    hash
    ciphertext {
      ciphertext {
        iv
        tag
        data
      }
      blindedSenderViewingKey
      memo
    }
  }
}
";

pub(crate) const SHIELD_COMMITMENTS_QUERY: &str = r"
query ShieldCommitments($fromBlock: BigInt = 0, $toBlock: BigInt = 0, $limit: Int = 10000) {
  shieldCommitments(
    orderBy: [blockNumber_ASC, treePosition_ASC]
    where: {blockNumber_gte: $fromBlock, blockNumber_lte: $toBlock}
    limit: $limit
  ) {
    id
    transactionHash
    blockNumber
    treeNumber
    treePosition
    preimage {
      npk
      token {
        tokenType
        tokenAddress
        tokenSubID
      }
      value
    }
    shieldKey
    encryptedBundle
  }
}
";

pub(crate) const INDEXED_NULLIFIERS_QUERY: &str = r"
query IndexedNullifiers($fromBlock: BigInt = 0, $toBlock: BigInt = 0, $limit: Int = 10000) {
  nullifiers(
    orderBy: [blockNumber_ASC, nullifier_DESC]
    where: {blockNumber_gte: $fromBlock, blockNumber_lte: $toBlock}
    limit: $limit
  ) {
    id
    transactionHash
    blockNumber
    treeNumber
    nullifier
  }
}
";

#[derive(Debug, Clone)]
pub struct QuickSyncClient {
    endpoint: Url,
    client: Client,
}

impl QuickSyncClient {
    #[must_use]
    pub fn new(endpoint: Url) -> Self {
        Self {
            endpoint,
            client: Client::new(),
        }
    }

    /// Creates a client that routes all traffic through the given
    /// pre-configured [`reqwest::Client`] (e.g. one with a SOCKS proxy).
    #[must_use]
    pub const fn with_http_client(endpoint: Url, client: Client) -> Self {
        Self { endpoint, client }
    }

    pub(crate) async fn fetch_list<D>(
        &self,
        query: &str,
        block_number: u64,
        page_size: NonZeroUsize,
    ) -> Result<Vec<D::Item>, SyncError>
    where
        D: DeserializeOwned + GraphList,
    {
        let limit = page_size.get();
        let variables = GraphVariables {
            block_number: block_number.to_string(),
            limit: limit.min(i32::MAX as usize) as i32,
        };
        let response: GraphResponse<D> = self.post_graph(query, &variables).await?;
        validate_graph_response(&response)?;
        let data = response.data.ok_or(SyncError::MissingData)?;
        Ok(data.items())
    }

    pub async fn fetch_squid_height(&self) -> Result<u64, SyncError> {
        let variables = EmptyVariables {};
        let response: GraphResponse<SquidStatusData> =
            self.post_graph(SQUID_STATUS_QUERY, &variables).await?;
        validate_graph_response(&response)?;
        let data = response.data.ok_or(SyncError::MissingData)?;
        Ok(data.squid_status.height.to())
    }

    pub async fn probe_indexed_wallet_support(&self) -> Result<IndexedWalletProbe, SyncError> {
        let variables = GraphRangeVariables {
            from_block: "0".to_string(),
            to_block: "0".to_string(),
            limit: 1,
        };
        let response: GraphResponse<IndexedWalletProbeData> =
            self.post_graph(WALLET_PROBE_QUERY, &variables).await?;
        validate_graph_response(&response)?;
        let data = response.data.ok_or(SyncError::MissingData)?;
        Ok(IndexedWalletProbe {
            height: data.squid_status.height.to(),
        })
    }

    pub async fn fetch_transact_commitments(
        &self,
        from_block: u64,
        to_block: u64,
        page_size: NonZeroUsize,
    ) -> Result<Vec<IndexedTransactCommitment>, SyncError> {
        self.fetch_range::<IndexedTransactCommitmentsData>(
            TRANSACT_COMMITMENTS_QUERY,
            from_block,
            to_block,
            page_size,
        )
        .await
    }

    pub async fn fetch_indexed_wallet_page(
        &self,
        from_block: u64,
        to_block: u64,
        page_size: NonZeroUsize,
    ) -> Result<IndexedWalletPageData, SyncError> {
        let limit = page_size.get();
        let variables = GraphRangeVariables {
            from_block: from_block.to_string(),
            to_block: to_block.to_string(),
            limit: limit.min(i32::MAX as usize) as i32,
        };
        let response: GraphResponse<IndexedWalletPageData> = self
            .post_graph(INDEXED_WALLET_PAGE_QUERY, &variables)
            .await?;
        validate_graph_response(&response)?;
        response.data.ok_or(SyncError::MissingData)
    }

    pub async fn fetch_indexed_legacy_wallet_page(
        &self,
        from_block: u64,
        to_block: u64,
        page_size: NonZeroUsize,
    ) -> Result<IndexedLegacyWalletPageData, SyncError> {
        let limit = page_size.get();
        let variables = GraphRangeVariables {
            from_block: from_block.to_string(),
            to_block: to_block.to_string(),
            limit: limit.min(i32::MAX as usize) as i32,
        };
        let response: GraphResponse<IndexedLegacyWalletPageData> = self
            .post_graph(INDEXED_LEGACY_WALLET_PAGE_QUERY, &variables)
            .await?;
        validate_graph_response(&response)?;
        response.data.ok_or(SyncError::MissingData)
    }

    pub async fn fetch_shield_commitments(
        &self,
        from_block: u64,
        to_block: u64,
        page_size: NonZeroUsize,
    ) -> Result<Vec<IndexedShieldCommitment>, SyncError> {
        self.fetch_range::<IndexedShieldCommitmentsData>(
            SHIELD_COMMITMENTS_QUERY,
            from_block,
            to_block,
            page_size,
        )
        .await
    }

    pub async fn fetch_indexed_nullifiers(
        &self,
        from_block: u64,
        to_block: u64,
        page_size: NonZeroUsize,
    ) -> Result<Vec<IndexedNullifier>, SyncError> {
        self.fetch_range::<IndexedNullifiersData>(
            INDEXED_NULLIFIERS_QUERY,
            from_block,
            to_block,
            page_size,
        )
        .await
    }

    pub(crate) async fn fetch_range<D>(
        &self,
        query: &str,
        from_block: u64,
        to_block: u64,
        page_size: NonZeroUsize,
    ) -> Result<Vec<D::Item>, SyncError>
    where
        D: DeserializeOwned + GraphList,
    {
        let limit = page_size.get();
        let variables = GraphRangeVariables {
            from_block: from_block.to_string(),
            to_block: to_block.to_string(),
            limit: limit.min(i32::MAX as usize) as i32,
        };
        let response: GraphResponse<D> = self.post_graph(query, &variables).await?;
        validate_graph_response(&response)?;
        let data = response.data.ok_or(SyncError::MissingData)?;
        Ok(data.items())
    }

    async fn post_graph<T, V>(
        &self,
        query: &str,
        variables: &V,
    ) -> Result<GraphResponse<T>, SyncError>
    where
        T: DeserializeOwned,
        V: Serialize,
    {
        let request = GraphRequest { query, variables };

        let response = self
            .client
            .post(self.endpoint.clone())
            .json(&request)
            .send()
            .await?;

        let status = response.status();
        let body = response.text().await?;
        if !status.is_success() {
            return Err(SyncError::UnexpectedFormat(format!(
                "graphql request failed with status {status}: {body}"
            )));
        }

        serde_json::from_str::<GraphResponse<T>>(&body)
            .map_err(|err| SyncError::UnexpectedFormat(format!("invalid graphql response: {err}")))
    }
}

#[derive(Debug, Serialize)]
struct GraphRequest<'a, V> {
    query: &'a str,
    variables: &'a V,
}

#[derive(Debug, Serialize)]
struct EmptyVariables {}

#[derive(Debug, Serialize)]
struct GraphVariables {
    #[serde(rename = "blockNumber")]
    block_number: String,
    limit: i32,
}

#[derive(Debug, Serialize)]
struct GraphRangeVariables {
    #[serde(rename = "fromBlock")]
    from_block: String,
    #[serde(rename = "toBlock")]
    to_block: String,
    limit: i32,
}

#[derive(Debug, Deserialize)]
struct GraphResponse<T> {
    data: Option<T>,
    errors: Option<Vec<GraphError>>,
}

fn validate_graph_response<T>(response: &GraphResponse<T>) -> Result<(), SyncError> {
    if let Some(errors) = &response.errors {
        let message = errors
            .iter()
            .map(|error| error.message.as_str())
            .collect::<Vec<_>>()
            .join("; ");
        return Err(SyncError::UnexpectedFormat(format!(
            "graphql errors: {message}"
        )));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct GraphError {
    message: String,
}

pub(crate) trait GraphList {
    type Item;

    fn items(self) -> Vec<Self::Item>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexedWalletProbe {
    pub height: u64,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SquidStatusData {
    #[serde(rename = "squidStatus")]
    squid_status: SquidStatus,
}

#[derive(Debug, Deserialize)]
struct SquidStatus {
    height: alloy::primitives::U256,
}

#[derive(Debug, Deserialize)]
pub(crate) struct IndexedWalletProbeData {
    #[serde(rename = "squidStatus")]
    squid_status: SquidStatus,
    #[allow(dead_code)]
    #[serde(rename = "transactCommitments")]
    transact_commitments: Vec<IndexedTransactCommitment>,
    #[allow(dead_code)]
    #[serde(rename = "shieldCommitments")]
    shield_commitments: Vec<IndexedShieldCommitment>,
    #[allow(dead_code)]
    nullifiers: Vec<IndexedNullifier>,
    #[allow(dead_code)]
    #[serde(rename = "legacyEncryptedCommitments")]
    legacy_encrypted_commitments: Vec<IndexedLegacyEncryptedCommitment>,
    #[allow(dead_code)]
    #[serde(rename = "legacyGeneratedCommitments")]
    legacy_generated_commitments: Vec<IndexedLegacyGeneratedCommitment>,
}

#[derive(Debug, Deserialize)]
pub struct IndexedWalletPageData {
    #[serde(rename = "transactCommitments")]
    pub transact_commitments: Vec<IndexedTransactCommitment>,
    #[serde(rename = "shieldCommitments")]
    pub shield_commitments: Vec<IndexedShieldCommitment>,
    pub nullifiers: Vec<IndexedNullifier>,
}

#[derive(Debug, Deserialize)]
pub struct IndexedLegacyWalletPageData {
    #[serde(rename = "legacyEncryptedCommitments")]
    pub legacy_encrypted_commitments: Vec<IndexedLegacyEncryptedCommitment>,
    #[serde(rename = "legacyGeneratedCommitments")]
    pub legacy_generated_commitments: Vec<IndexedLegacyGeneratedCommitment>,
    pub nullifiers: Vec<IndexedNullifier>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CommitmentsData {
    commitments: Vec<Commitment>,
}

impl GraphList for CommitmentsData {
    type Item = Commitment;

    fn items(self) -> Vec<Self::Item> {
        self.commitments
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct IndexedTransactCommitmentsData {
    #[serde(rename = "transactCommitments")]
    transact_commitments: Vec<IndexedTransactCommitment>,
}

impl GraphList for IndexedTransactCommitmentsData {
    type Item = IndexedTransactCommitment;

    fn items(self) -> Vec<Self::Item> {
        self.transact_commitments
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct IndexedShieldCommitmentsData {
    #[serde(rename = "shieldCommitments")]
    shield_commitments: Vec<IndexedShieldCommitment>,
}

impl GraphList for IndexedShieldCommitmentsData {
    type Item = IndexedShieldCommitment;

    fn items(self) -> Vec<Self::Item> {
        self.shield_commitments
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct IndexedNullifiersData {
    nullifiers: Vec<IndexedNullifier>,
}

impl GraphList for IndexedNullifiersData {
    type Item = IndexedNullifier;

    fn items(self) -> Vec<Self::Item> {
        self.nullifiers
    }
}
