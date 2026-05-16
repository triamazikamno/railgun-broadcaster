use async_trait::async_trait;
use cid::Cid;
use cid::multihash::Multihash;
use futures_util::future::join_all;
use s3::creds::Credentials;
use s3::{Bucket, Region};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;
use thiserror::Error;

const FILEBASE_SERVICE: &str = "filebase";
const FILEBASE_ENDPOINT: &str = "https://s3.filebase.com";
const FILEBASE_REGION: &str = "us-east-1";
const DEFAULT_FILEBASE_KEY_PREFIX: &str = "poi-indexer";
const SHA2_256_MULTIHASH_CODE: u64 = 0x12;
const RAW_MULTICODEC: u64 = 0x55;
const FILEBASE_CID_METADATA: &str = "cid";
const FILEBASE_CID_HEADER: &str = "x-amz-meta-cid";

pub type BoxError = Box<dyn Error + Send + Sync + 'static>;

#[async_trait]
pub trait IpfsClient: Send + Sync {
    fn service_name(&self) -> &'static str;

    async fn pin_bytes(&self, bytes: &[u8]) -> Result<Cid, IpfsError>;

    async fn unpin(&self, cid: &Cid) -> Result<(), IpfsError>;

    async fn contains(&self, cid: &Cid) -> Result<bool, IpfsError>;
}

pub async fn pin_snapshot_file(client: &dyn IpfsClient, bytes: &[u8]) -> Result<Cid, IpfsError> {
    client.pin_bytes(bytes).await
}

pub async fn pin_blocked_shields(client: &dyn IpfsClient, bytes: &[u8]) -> Result<Cid, IpfsError> {
    client.pin_bytes(bytes).await
}

pub async fn pin_manifest(
    client: &dyn IpfsClient,
    manifest_bytes: &[u8],
) -> Result<Cid, IpfsError> {
    client.pin_bytes(manifest_bytes).await
}

#[derive(Clone)]
pub struct MultiPinner {
    clients: Vec<Arc<dyn IpfsClient>>,
    quorum: usize,
}

impl std::fmt::Debug for MultiPinner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MultiPinner")
            .field("clients", &self.clients.len())
            .field("quorum", &self.quorum)
            .finish()
    }
}

impl MultiPinner {
    pub fn new(clients: Vec<Arc<dyn IpfsClient>>, quorum: usize) -> Result<Self, IpfsError> {
        if clients.is_empty() {
            return Err(IpfsError::NoPinningServices);
        }
        if quorum == 0 || quorum > clients.len() {
            return Err(IpfsError::InvalidQuorum {
                quorum,
                clients: clients.len(),
            });
        }

        Ok(Self { clients, quorum })
    }

    #[must_use]
    pub const fn quorum(&self) -> usize {
        self.quorum
    }

    #[must_use]
    pub const fn client_count(&self) -> usize {
        self.clients.len()
    }
}

#[async_trait]
impl IpfsClient for MultiPinner {
    fn service_name(&self) -> &'static str {
        "multi-pinner"
    }

    async fn pin_bytes(&self, bytes: &[u8]) -> Result<Cid, IpfsError> {
        let results = join_all(self.clients.iter().map(|client| async move {
            let service = client.service_name().to_string();
            (service, client.pin_bytes(bytes).await)
        }))
        .await;

        let mut cid_groups = Vec::<(Cid, Vec<String>)>::new();
        let mut mismatches = Vec::new();
        let mut failures = Vec::new();

        for (service, result) in results {
            match result {
                Ok(returned) => add_cid_success(&mut cid_groups, returned, service),
                Err(error) => {
                    tracing::warn!(service, ?error, "failed to pin to IPFS service");
                    failures.push(PinningServiceFailure {
                        service,
                        error: error.to_string(),
                    });
                }
            }
        }

        cid_groups.sort_by_key(|group| std::cmp::Reverse(group.1.len()));
        if let Some((cid, successes)) = cid_groups.first()
            && successes.len() >= self.quorum
        {
            return Ok(*cid);
        }

        let (candidate, successes) = cid_groups
            .first()
            .cloned()
            .unwrap_or((raw_block_cid(bytes)?, Vec::new()));
        for (returned, services) in cid_groups.into_iter().skip(1) {
            mismatches.extend(
                services
                    .into_iter()
                    .map(|service| PinningCidMismatch { service, returned }),
            );
        }

        Err(IpfsError::PinningQuorumNotMet {
            expected: Box::new(candidate),
            required: self.quorum,
            successes,
            mismatches,
            failures,
        })
    }

    async fn unpin(&self, cid: &Cid) -> Result<(), IpfsError> {
        let results = join_all(self.clients.iter().map(|client| async move {
            let service = client.service_name().to_string();
            (service, client.unpin(cid).await)
        }))
        .await;

        let mut successes = Vec::new();
        let mut failures = Vec::new();
        for (service, result) in results {
            match result {
                Ok(()) => successes.push(service),
                Err(error) => failures.push(PinningServiceFailure {
                    service,
                    error: error.to_string(),
                }),
            }
        }

        if successes.len() >= self.quorum {
            return Ok(());
        }

        Err(IpfsError::UnpinningQuorumNotMet {
            cid: Box::new(*cid),
            required: self.quorum,
            successes,
            failures,
        })
    }

    async fn contains(&self, cid: &Cid) -> Result<bool, IpfsError> {
        let results = join_all(self.clients.iter().map(|client| async move {
            let service = client.service_name().to_string();
            (service, client.contains(cid).await)
        }))
        .await;

        let mut present = Vec::new();
        let mut missing = Vec::new();
        let mut failures = Vec::new();
        for (service, result) in results {
            match result {
                Ok(true) => present.push(service),
                Ok(false) => missing.push(service),
                Err(error) => failures.push(PinningServiceFailure {
                    service,
                    error: error.to_string(),
                }),
            }
        }

        if present.len() >= self.quorum {
            return Ok(true);
        }
        if failures.is_empty() {
            return Ok(false);
        }

        Err(IpfsError::ContainsQuorumUndecidable {
            cid: Box::new(*cid),
            required: self.quorum,
            present,
            missing,
            failures,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinningCidMismatch {
    pub service: String,
    pub returned: Cid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinningServiceFailure {
    pub service: String,
    pub error: String,
}

#[derive(Debug, Clone)]
pub struct FilebaseIpfsClient {
    bucket: Box<Bucket>,
    key_prefix: String,
}

impl FilebaseIpfsClient {
    pub fn new(
        access_key: impl AsRef<str>,
        secret_key: impl AsRef<str>,
        bucket_name: impl AsRef<str>,
    ) -> Result<Self, IpfsError> {
        Self::with_endpoint(
            access_key,
            secret_key,
            bucket_name,
            FILEBASE_ENDPOINT,
            FILEBASE_REGION,
            DEFAULT_FILEBASE_KEY_PREFIX,
        )
    }

    pub fn with_endpoint(
        access_key: impl AsRef<str>,
        secret_key: impl AsRef<str>,
        bucket_name: impl AsRef<str>,
        endpoint: impl Into<String>,
        region: impl Into<String>,
        key_prefix: impl Into<String>,
    ) -> Result<Self, IpfsError> {
        let endpoint = endpoint.into();
        validate_filebase_endpoint(&endpoint)?;
        let credentials = Credentials::new(
            Some(access_key.as_ref()),
            Some(secret_key.as_ref()),
            None,
            None,
            None,
        )
        .map_err(|source| IpfsError::ClientBuild {
            service: FILEBASE_SERVICE.to_string(),
            source: Box::new(source),
        })?;
        let region = Region::Custom {
            region: region.into(),
            endpoint,
        };
        let bucket = Bucket::new(bucket_name.as_ref(), region, credentials)
            .map_err(|source| IpfsError::ClientBuild {
                service: FILEBASE_SERVICE.to_string(),
                source: Box::new(source),
            })?
            .with_path_style();

        Ok(Self {
            bucket,
            key_prefix: key_prefix.into(),
        })
    }

    fn object_key(&self, cid: &Cid) -> String {
        let cid = cid.to_string();
        let prefix = self.key_prefix.trim_matches('/');
        if prefix.is_empty() {
            cid
        } else {
            format!("{prefix}/{cid}")
        }
    }

    fn temporary_object_key(&self, cid: &Cid) -> String {
        let cid = cid.to_string();
        let prefix = self.key_prefix.trim_matches('/');
        if prefix.is_empty() {
            format!("tmp/{cid}")
        } else {
            format!("{prefix}/tmp/{cid}")
        }
    }

    async fn returned_cid_from_filebase(
        &self,
        key: &str,
        headers: &HashMap<String, String>,
    ) -> Result<Cid, IpfsError> {
        if let Some(cid) = header_value(headers, FILEBASE_CID_HEADER) {
            return parse_service_cid(FILEBASE_SERVICE, cid);
        }

        let (head, status) =
            self.bucket
                .head_object(key)
                .await
                .map_err(|source| IpfsError::PinFailed {
                    service: FILEBASE_SERVICE.to_string(),
                    source: Box::new(source),
                })?;
        if !(200..300).contains(&status) {
            return Err(IpfsError::PinHttpStatus {
                service: FILEBASE_SERVICE.to_string(),
                status,
                body: String::new(),
            });
        }

        let metadata = head.metadata.unwrap_or_default();
        header_value(&metadata, FILEBASE_CID_METADATA).map_or_else(
            || {
                Err(IpfsError::MissingCid {
                    service: FILEBASE_SERVICE.to_string(),
                })
            },
            |cid| parse_service_cid(FILEBASE_SERVICE, cid),
        )
    }

    async fn copy_object(&self, from: &str, to: &str) -> Result<(), IpfsError> {
        let status = self
            .bucket
            .copy_object_internal(from, to)
            .await
            .map_err(|source| IpfsError::PinFailed {
                service: FILEBASE_SERVICE.to_string(),
                source: Box::new(source),
            })?;

        if !(200..300).contains(&status) {
            return Err(IpfsError::PinHttpStatus {
                service: FILEBASE_SERVICE.to_string(),
                status,
                body: String::new(),
            });
        }

        tracing::info!(
            service = FILEBASE_SERVICE,
            temporary_key = from,
            final_key = to,
            copy_status = status,
            "copied Filebase object to stable CID key"
        );
        Ok(())
    }

    async fn delete_temporary_object(&self, key: &str) {
        if let Err(error) = self.bucket.delete_object(key).await {
            tracing::warn!(
                service = FILEBASE_SERVICE,
                key,
                error = %error,
                "failed to delete temporary Filebase object"
            );
        }
    }
}

#[async_trait]
impl IpfsClient for FilebaseIpfsClient {
    fn service_name(&self) -> &'static str {
        FILEBASE_SERVICE
    }

    async fn pin_bytes(&self, bytes: &[u8]) -> Result<Cid, IpfsError> {
        let temporary_cid = raw_block_cid(bytes)?;
        let temporary_key = self.temporary_object_key(&temporary_cid);
        let response = self
            .bucket
            .put_object_builder(&temporary_key, bytes)
            .with_content_type("application/octet-stream")
            .execute()
            .await
            .map_err(|source| IpfsError::PinFailed {
                service: FILEBASE_SERVICE.to_string(),
                source: Box::new(source),
            })?;
        if !(200..300).contains(&response.status_code()) {
            return Err(IpfsError::PinHttpStatus {
                service: FILEBASE_SERVICE.to_string(),
                status: response.status_code(),
                body: response_body(&response),
            });
        }

        let returned_cid = self
            .returned_cid_from_filebase(&temporary_key, &response.headers())
            .await?;
        let final_key = self.object_key(&returned_cid);
        tracing::info!(
            service = FILEBASE_SERVICE,
            temporary_key = %temporary_key,
            final_key = %final_key,
            put_status = response.status_code(),
            cid = %returned_cid,
            "uploaded bytes to Filebase"
        );
        if final_key != temporary_key {
            self.copy_object(&temporary_key, &final_key).await?;
            self.delete_temporary_object(&temporary_key).await;
        }

        Ok(returned_cid)
    }

    async fn unpin(&self, cid: &Cid) -> Result<(), IpfsError> {
        let key = self.object_key(cid);
        let response =
            self.bucket
                .delete_object(&key)
                .await
                .map_err(|source| IpfsError::UnpinFailed {
                    service: FILEBASE_SERVICE.to_string(),
                    cid: Box::new(*cid),
                    source: Box::new(source),
                })?;
        ensure_unpin_response_success(FILEBASE_SERVICE, cid, &response)
    }

    async fn contains(&self, cid: &Cid) -> Result<bool, IpfsError> {
        let key = self.object_key(cid);
        let (_head, status) =
            self.bucket
                .head_object(&key)
                .await
                .map_err(|source| IpfsError::ContainsFailed {
                    service: FILEBASE_SERVICE.to_string(),
                    cid: Box::new(*cid),
                    source: Box::new(source),
                })?;

        match status {
            200..=299 => Ok(true),
            404 => Ok(false),
            status => Err(IpfsError::ContainsHttpStatus {
                service: FILEBASE_SERVICE.to_string(),
                status,
                body: String::new(),
            }),
        }
    }
}

fn add_cid_success(cid_groups: &mut Vec<(Cid, Vec<String>)>, returned: Cid, service: String) {
    if let Some((_cid, services)) = cid_groups
        .iter_mut()
        .find(|(cid, _services)| *cid == returned)
    {
        services.push(service);
    } else {
        cid_groups.push((returned, vec![service]));
    }
}

fn validate_filebase_endpoint(endpoint: &str) -> Result<(), IpfsError> {
    let url = reqwest::Url::parse(endpoint).map_err(|source| IpfsError::InvalidEndpoint {
        service: FILEBASE_SERVICE,
        endpoint: endpoint.to_string(),
        reason: source.to_string(),
    })?;
    if url.path() != "/" && !url.path().is_empty() {
        return Err(IpfsError::InvalidEndpoint {
            service: FILEBASE_SERVICE,
            endpoint: endpoint.to_string(),
            reason: "endpoint must not include a path; configure the bucket with POI_INDEXER_FILEBASE_BUCKET".to_string(),
        });
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(IpfsError::InvalidEndpoint {
            service: FILEBASE_SERVICE,
            endpoint: endpoint.to_string(),
            reason: "endpoint must not include a query string or fragment".to_string(),
        });
    }
    if url.host_str().is_some_and(is_filebase_bucket_endpoint) {
        return Err(IpfsError::InvalidEndpoint {
            service: FILEBASE_SERVICE,
            endpoint: endpoint.to_string(),
            reason: "bucket-specific Filebase endpoints are not supported with path-style S3; use https://s3.filebase.com".to_string(),
        });
    }

    Ok(())
}

fn is_filebase_bucket_endpoint(host: &str) -> bool {
    host.ends_with(".s3.filebase.io") || host.ends_with(".s3.filebase.com")
}

pub fn raw_block_cid(bytes: &[u8]) -> Result<Cid, IpfsError> {
    let digest = Sha256::digest(bytes);
    let multihash =
        Multihash::<64>::wrap(SHA2_256_MULTIHASH_CODE, &digest).map_err(IpfsError::Multihash)?;
    Ok(Cid::new_v1(RAW_MULTICODEC, multihash))
}

fn header_value<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _value)| key.eq_ignore_ascii_case(name))
        .map(|(_key, value)| value.as_str())
}

fn parse_service_cid(service: &str, cid: &str) -> Result<Cid, IpfsError> {
    Cid::try_from(cid.trim()).map_err(|source| IpfsError::InvalidCid {
        service: service.to_string(),
        cid: cid.to_string(),
        source,
    })
}

fn response_body(response: &s3::request::ResponseData) -> String {
    String::from_utf8_lossy(response.as_slice()).into_owned()
}

fn ensure_unpin_response_success(
    service: &str,
    cid: &Cid,
    response: &s3::request::ResponseData,
) -> Result<(), IpfsError> {
    if (200..300).contains(&response.status_code()) {
        return Ok(());
    }

    Err(IpfsError::UnpinHttpStatus {
        service: service.to_string(),
        cid: Box::new(*cid),
        status: response.status_code(),
        body: response_body(response),
    })
}

#[derive(Debug, Error)]
pub enum IpfsError {
    #[error("failed to construct raw block multihash")]
    Multihash(#[source] cid::multihash::Error),
    #[error("invalid {service} endpoint {endpoint}: {reason}")]
    InvalidEndpoint {
        service: &'static str,
        endpoint: String,
        reason: String,
    },
    #[error("failed to build {service} client")]
    ClientBuild {
        service: String,
        #[source]
        source: BoxError,
    },
    #[error("at least one IPFS pinning service is required")]
    NoPinningServices,
    #[error("pinning quorum {quorum} is invalid for {clients} services")]
    InvalidQuorum { quorum: usize, clients: usize },
    #[error("{service} returned invalid CID {cid}")]
    InvalidCid {
        service: String,
        cid: String,
        #[source]
        source: cid::Error,
    },
    #[error("{service} response did not include a CID")]
    MissingCid { service: String },
    #[error("{service} returned CID {returned}, expected {expected}")]
    CidMismatch {
        service: String,
        expected: Box<Cid>,
        returned: Box<Cid>,
    },
    #[error(
        "pinning quorum not met for CID {expected}: {successes_len}/{required} services returned the expected CID",
        successes_len = successes.len()
    )]
    PinningQuorumNotMet {
        expected: Box<Cid>,
        required: usize,
        successes: Vec<String>,
        mismatches: Vec<PinningCidMismatch>,
        failures: Vec<PinningServiceFailure>,
    },
    #[error("{service} pin failed with HTTP status {status}: {body}")]
    PinHttpStatus {
        service: String,
        status: u16,
        body: String,
    },
    #[error(
        "unpinning quorum not met for CID {cid}: {successes_len}/{required} services unpinned it",
        successes_len = successes.len()
    )]
    UnpinningQuorumNotMet {
        cid: Box<Cid>,
        required: usize,
        successes: Vec<String>,
        failures: Vec<PinningServiceFailure>,
    },
    #[error("{service} unpin failed for CID {cid} with HTTP status {status}: {body}")]
    UnpinHttpStatus {
        service: String,
        cid: Box<Cid>,
        status: u16,
        body: String,
    },
    #[error(
        "contains quorum not decidable for CID {cid}: {present_len}/{required} services reported it present",
        present_len = present.len()
    )]
    ContainsQuorumUndecidable {
        cid: Box<Cid>,
        required: usize,
        present: Vec<String>,
        missing: Vec<String>,
        failures: Vec<PinningServiceFailure>,
    },
    #[error("{service} contains check failed with HTTP status {status}: {body}")]
    ContainsHttpStatus {
        service: String,
        status: u16,
        body: String,
    },
    #[error("{service} pin failed")]
    PinFailed {
        service: String,
        #[source]
        source: BoxError,
    },
    #[error("{service} unpin failed for CID {cid}")]
    UnpinFailed {
        service: String,
        cid: Box<Cid>,
        #[source]
        source: BoxError,
    },
    #[error("{service} contains check failed for CID {cid}")]
    ContainsFailed {
        service: String,
        cid: Box<Cid>,
        #[source]
        source: BoxError,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    const EMPTY_RAW_CID: &str = "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku";

    #[derive(Debug)]
    struct RecordingClient {
        service: &'static str,
        calls: Mutex<Vec<Vec<u8>>>,
        cid: Cid,
        contains: bool,
    }

    #[async_trait]
    impl IpfsClient for RecordingClient {
        fn service_name(&self) -> &'static str {
            self.service
        }

        async fn pin_bytes(&self, bytes: &[u8]) -> Result<Cid, IpfsError> {
            self.calls.lock().expect("calls lock").push(bytes.to_vec());
            Ok(self.cid)
        }

        async fn unpin(&self, _cid: &Cid) -> Result<(), IpfsError> {
            Ok(())
        }

        async fn contains(&self, _cid: &Cid) -> Result<bool, IpfsError> {
            Ok(self.contains)
        }
    }

    #[tokio::test]
    async fn pin_helpers_delegate_to_client() {
        let client = RecordingClient {
            service: "recording",
            calls: Mutex::new(Vec::new()),
            cid: Cid::try_from(EMPTY_RAW_CID).expect("test CID"),
            contains: true,
        };
        let ipfs_client: &dyn IpfsClient = &client;

        let snapshot_cid = pin_snapshot_file(ipfs_client, b"snapshot")
            .await
            .expect("pin snapshot");
        let blocked_cid = pin_blocked_shields(ipfs_client, b"blocked")
            .await
            .expect("pin blocked shields");
        let manifest_cid = pin_manifest(ipfs_client, b"manifest")
            .await
            .expect("pin manifest");

        assert_eq!(snapshot_cid, client.cid);
        assert_eq!(blocked_cid, client.cid);
        assert_eq!(manifest_cid, client.cid);
        assert_eq!(
            client.calls.lock().expect("calls lock").as_slice(),
            &[
                b"snapshot".to_vec(),
                b"blocked".to_vec(),
                b"manifest".to_vec()
            ]
        );
    }

    #[test]
    fn raw_block_cid_matches_empty_bytes_vector() {
        assert_eq!(
            raw_block_cid(b"").expect("raw CID").to_string(),
            EMPTY_RAW_CID
        );
    }

    #[tokio::test]
    async fn multi_pinner_succeeds_when_quorum_returns_same_service_cid() {
        let bytes = b"same bytes everywhere";
        let expected = raw_block_cid(b"service-generated CID").expect("expected CID");
        let first = Arc::new(RecordingClient {
            service: "first",
            calls: Mutex::new(Vec::new()),
            cid: expected,
            contains: true,
        });
        let second = Arc::new(RecordingClient {
            service: "second",
            calls: Mutex::new(Vec::new()),
            cid: expected,
            contains: true,
        });
        let pinner = MultiPinner::new(vec![first, second], 2).expect("multi pinner");

        let cid = pinner.pin_bytes(bytes).await.expect("pin bytes");

        assert_eq!(cid, expected);
    }

    #[tokio::test]
    async fn multi_pinner_quorum_one_returns_service_cid() {
        let returned = raw_block_cid(b"filebase CID").expect("returned CID");
        let client = Arc::new(RecordingClient {
            service: "filebase",
            calls: Mutex::new(Vec::new()),
            cid: returned,
            contains: true,
        });
        let pinner = MultiPinner::new(vec![client], 1).expect("multi pinner");

        let cid = pinner
            .pin_bytes(b"snapshot bytes")
            .await
            .expect("pin bytes");

        assert_eq!(cid, returned);
    }

    #[tokio::test]
    async fn multi_pinner_rejects_cid_mismatch_before_quorum() {
        let bytes = b"expected bytes";
        let expected = raw_block_cid(b"first service CID").expect("expected CID");
        let wrong = raw_block_cid(b"other bytes").expect("wrong CID");
        let first = Arc::new(RecordingClient {
            service: "first",
            calls: Mutex::new(Vec::new()),
            cid: expected,
            contains: true,
        });
        let second = Arc::new(RecordingClient {
            service: "second",
            calls: Mutex::new(Vec::new()),
            cid: wrong,
            contains: true,
        });
        let pinner = MultiPinner::new(vec![first, second], 2).expect("multi pinner");

        let error = pinner.pin_bytes(bytes).await.expect_err("quorum failure");

        match error {
            IpfsError::PinningQuorumNotMet {
                successes,
                mismatches,
                failures,
                ..
            } => {
                assert_eq!(successes, ["first".to_string()]);
                assert_eq!(mismatches.len(), 1);
                assert_eq!(mismatches[0].service, "second");
                assert_eq!(mismatches[0].returned, wrong);
                assert!(failures.is_empty());
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn multi_pinner_contains_requires_quorum_present() {
        let cid = raw_block_cid(b"available").expect("test CID");
        let first = Arc::new(RecordingClient {
            service: "first",
            calls: Mutex::new(Vec::new()),
            cid,
            contains: true,
        });
        let second = Arc::new(RecordingClient {
            service: "second",
            calls: Mutex::new(Vec::new()),
            cid,
            contains: false,
        });

        let quorum_one =
            MultiPinner::new(vec![first.clone(), second.clone()], 1).expect("quorum one pinner");
        let quorum_two = MultiPinner::new(vec![first, second], 2).expect("quorum two pinner");

        assert!(quorum_one.contains(&cid).await.expect("contains check"));
        assert!(!quorum_two.contains(&cid).await.expect("contains check"));
    }

    #[test]
    fn header_value_matches_metadata_case_insensitively() {
        let headers = HashMap::from([("Cid".to_string(), EMPTY_RAW_CID.to_string())]);

        assert_eq!(header_value(&headers, "cid"), Some(EMPTY_RAW_CID));
    }

    #[test]
    fn filebase_endpoint_validation_rejects_bucket_specific_hosts() {
        let error = validate_filebase_endpoint("https://ppoi.s3.filebase.io")
            .expect_err("bucket-specific endpoint should fail");

        assert!(error.to_string().contains("bucket-specific"));
    }

    #[test]
    fn filebase_endpoint_validation_rejects_paths() {
        let error = validate_filebase_endpoint("https://s3.filebase.com/ppoi")
            .expect_err("pathful endpoint should fail");

        assert!(error.to_string().contains("must not include a path"));
    }

    #[test]
    fn filebase_unpin_rejects_failed_delete_status() {
        let cid = Cid::try_from(EMPTY_RAW_CID).expect("test CID");
        let response =
            s3::request::ResponseData::new(Vec::from("access denied").into(), 403, HashMap::new());

        let error = ensure_unpin_response_success(FILEBASE_SERVICE, &cid, &response)
            .expect_err("failed delete response should be rejected");

        match error {
            IpfsError::UnpinHttpStatus {
                service,
                cid: error_cid,
                status,
                body,
            } => {
                assert_eq!(service, FILEBASE_SERVICE);
                assert_eq!(*error_cid, cid);
                assert_eq!(status, 403);
                assert_eq!(body, "access denied");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
