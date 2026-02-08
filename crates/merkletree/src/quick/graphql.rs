use std::num::NonZeroUsize;

use reqwest::Client;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::errors::SyncError;
use crate::quick::types::{Commitment, Nullifier, Unshield};

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

pub(crate) const NULLIFIERS_QUERY: &str = r"
query Nullifiers($blockNumber: BigInt = 0, $limit: Int = 10000) {
  nullifiers(
    orderBy: [blockNumber_ASC, nullifier_DESC]
    where: {blockNumber_gte: $blockNumber}
    limit: $limit
  ) {
    id
    blockNumber
    treeNumber
  }
}
";

pub(crate) const UNSHIELDS_QUERY: &str = r"
query Unshields($blockNumber: BigInt = 0, $limit: Int = 10000) {
  unshields(
    orderBy: [blockNumber_ASC, eventLogIndex_ASC]
    where: {blockNumber_gte: $blockNumber}
    limit: $limit
  ) {
    id
    blockNumber
    eventLogIndex
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

    pub(crate) async fn fetch_list<D>(
        &self,
        query: &str,
        block_number: u64,
        page_size: NonZeroUsize,
    ) -> Result<Vec<D::Item>, SyncError>
    where
        D: DeserializeOwned + GraphList,
    {
        let response: GraphResponse<D> = self.post_graph(query, block_number, page_size).await?;
        if let Some(errors) = response.errors {
            let message = errors
                .into_iter()
                .map(|error| error.message)
                .collect::<Vec<_>>()
                .join("; ");
            return Err(SyncError::UnexpectedFormat(format!(
                "graphql errors: {message}"
            )));
        }
        let data = response.data.ok_or(SyncError::MissingData)?;
        Ok(data.items())
    }

    async fn post_graph<T: DeserializeOwned>(
        &self,
        query: &str,
        block_number: u64,
        page_size: NonZeroUsize,
    ) -> Result<GraphResponse<T>, SyncError> {
        let limit = page_size.get();
        let request = GraphRequest {
            query,
            variables: GraphVariables {
                block_number: block_number.to_string(),
                limit: limit.min(i32::MAX as usize) as i32,
            },
        };

        let response = self
            .client
            .post(self.endpoint.clone())
            .json(&request)
            .send()
            .await?
            .error_for_status()?;

        let parsed = response.json::<GraphResponse<T>>().await?;
        Ok(parsed)
    }
}

#[derive(Debug, Serialize)]
struct GraphRequest<'a> {
    query: &'a str,
    variables: GraphVariables,
}

#[derive(Debug, Serialize)]
struct GraphVariables {
    #[serde(rename = "blockNumber")]
    block_number: String,
    limit: i32,
}

#[derive(Debug, Deserialize)]
struct GraphResponse<T> {
    data: Option<T>,
    errors: Option<Vec<GraphError>>,
}

#[derive(Debug, Deserialize)]
struct GraphError {
    message: String,
}

pub(crate) trait GraphList {
    type Item;

    fn items(self) -> Vec<Self::Item>;
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
pub(crate) struct NullifiersData {
    nullifiers: Vec<Nullifier>,
}

impl GraphList for NullifiersData {
    type Item = Nullifier;

    fn items(self) -> Vec<Self::Item> {
        self.nullifiers
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct UnshieldsData {
    unshields: Vec<Unshield>,
}

impl GraphList for UnshieldsData {
    type Item = Unshield;

    fn items(self) -> Vec<Self::Item> {
        self.unshields
    }
}
