use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use alloy::primitives::FixedBytes;
use brotli::Decompressor;
use reqwest::blocking::Client;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

const DEFAULT_GATEWAY: &str = "https://ipfs-lb.com";
const DEFAULT_IPFS_HASH: &str = "QmUsmnK4PFc7zDp2cmC4wBZxYLjNyRgWfs5GNcJJ2uLcpU";
const ARTIFACTS_DIR: &str = "db/railgun/blobs/artifacts";
const ARTIFACTS_LIST_FILE: &str = "artifacts.json";
const ARTIFACTS_HASHES_FILE: &str = "artifact-v2-hashes.json";

const ARTIFACTS_LIST_EMBED: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/resources/metadata/artifacts.json"
));
const ARTIFACTS_HASHES_EMBED: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/resources/metadata/artifact-v2-hashes.json"
));

#[derive(Debug, Error)]
pub enum ArtifactError {
    #[error("unsupported artifact variant {nullifiers}x{commitments}")]
    UnsupportedVariant {
        nullifiers: usize,
        commitments: usize,
    },
    #[error("read artifact list: {0}")]
    ArtifactList(#[source] serde_json::Error),
    #[error("read artifact file {path}: {source}")]
    ArtifactFile {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("read artifact hashes: {0}")]
    ArtifactHashes(#[source] std::io::Error),
    #[error("parse artifact hashes: {0}")]
    HashesParse(#[source] serde_json::Error),
    #[error("missing artifact hash for {variant}")]
    MissingHash { variant: String },
    #[error("invalid url {url}: {source}")]
    InvalidUrl {
        url: String,
        source: url::ParseError,
    },
    #[error("download failed for {url}: {source}")]
    Download { source: reqwest::Error, url: Url },
    #[error("brotli decompress failed: {0}")]
    Decompress(#[source] std::io::Error),
    #[error("hash mismatch for {label}: got {actual}, expected {expected}")]
    HashMismatch {
        label: String,
        actual: String,
        expected: String,
    },
}

#[derive(Debug, Deserialize)]
struct ArtifactSpec {
    nullifiers: usize,
    commitments: usize,
}

#[derive(Debug, Deserialize)]
struct ArtifactHashes {
    zkey: FixedBytes<32>,
    wasm: FixedBytes<32>,
    #[serde(default)]
    #[allow(dead_code)]
    dat: Option<FixedBytes<32>>,
}

#[derive(Debug)]
pub struct Artifacts {
    pub zkey: Vec<u8>,
    pub wasm: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ArtifactSource {
    pub gateway: Url,
    pub ipfs_hash: String,
    pub out_dir: PathBuf,
    pub metadata_dir: Option<PathBuf>,
}

impl Default for ArtifactSource {
    fn default() -> Self {
        Self {
            gateway: Url::parse(DEFAULT_GATEWAY).expect("valid gateway url"),
            ipfs_hash: DEFAULT_IPFS_HASH.to_string(),
            out_dir: PathBuf::from(ARTIFACTS_DIR),
            metadata_dir: None,
        }
    }
}

impl ArtifactSource {
    #[must_use]
    pub fn new(gateway: Url, ipfs_hash: String, out_dir: PathBuf) -> Self {
        Self {
            gateway,
            ipfs_hash,
            out_dir,
            metadata_dir: None,
        }
    }

    #[must_use]
    pub fn with_cache_dir(mut self, path: PathBuf) -> Self {
        self.out_dir = path;
        self
    }

    pub fn with_metadata_dir(mut self, path: PathBuf) -> Result<Self, ArtifactError> {
        validate_metadata_dir(&path)?;
        self.metadata_dir = Some(path);
        Ok(self)
    }
}

#[derive(Debug, Clone)]
pub struct ArtifactPaths {
    pub zkey: PathBuf,
    pub wasm: PathBuf,
}

#[must_use]
pub fn variant_name(nullifiers: usize, commitments: usize) -> String {
    format!("{nullifiers:02}x{commitments:02}")
}

pub fn list_variants(source: &ArtifactSource) -> Result<Vec<String>, ArtifactError> {
    let specs = artifact_specs(source)?;
    let mut variants: Vec<String> = specs
        .iter()
        .map(|spec| variant_name(spec.nullifiers, spec.commitments))
        .collect();
    variants.sort();
    Ok(variants)
}

#[must_use]
pub fn artifact_paths(variant: &str, source: &ArtifactSource) -> ArtifactPaths {
    let base = source.out_dir.join(variant);
    ArtifactPaths {
        zkey: base.join("zkey"),
        wasm: base.join("wasm"),
    }
}

fn validate_metadata_dir(path: &Path) -> Result<(), ArtifactError> {
    let list_path = path.join(ARTIFACTS_LIST_FILE);
    let hashes_path = path.join(ARTIFACTS_HASHES_FILE);
    fs::read(&list_path).map_err(|source| ArtifactError::ArtifactFile {
        path: list_path,
        source,
    })?;
    fs::read(&hashes_path).map_err(ArtifactError::ArtifactHashes)?;
    Ok(())
}

pub fn ensure_artifacts_with_source(
    nullifiers: usize,
    commitments: usize,
    source: &ArtifactSource,
) -> Result<ArtifactPaths, ArtifactError> {
    assert_variant_exists(source, nullifiers, commitments)?;
    let variant = variant_name(nullifiers, commitments);
    let paths = artifact_paths(&variant, source);
    if paths.zkey.exists() && paths.wasm.exists() {
        return Ok(paths);
    }
    download_variant(&variant, source, false)?;
    Ok(paths)
}

pub fn download_variants(
    variants: &[String],
    source: &ArtifactSource,
    force: bool,
) -> Result<Vec<ArtifactPaths>, ArtifactError> {
    let mut out = Vec::with_capacity(variants.len());
    for variant in variants {
        out.push(download_variant(variant, source, force)?);
    }
    Ok(out)
}

pub fn download_variant(
    variant: &str,
    source: &ArtifactSource,
    force: bool,
) -> Result<ArtifactPaths, ArtifactError> {
    let hashes = load_hashes(source)?;
    let expected = hashes
        .get(variant)
        .ok_or_else(|| ArtifactError::MissingHash {
            variant: variant.to_string(),
        })?;
    let paths = artifact_paths(variant, source);

    if !force && paths.zkey.exists() && paths.wasm.exists() {
        return Ok(paths);
    }

    let zkey_parent = paths
        .zkey
        .parent()
        .ok_or_else(|| ArtifactError::ArtifactFile {
            path: paths.zkey.clone(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "zkey path missing parent",
            ),
        })?;
    fs::create_dir_all(zkey_parent).map_err(|source| ArtifactError::ArtifactFile {
        path: paths.zkey.clone(),
        source,
    })?;

    let urls = artifact_urls(source, variant)?;
    let client = Client::new();

    let zkey_br = fetch_bytes(&client, &urls.zkey)?;
    let wasm_br = fetch_bytes(&client, &urls.wasm)?;

    let zkey = brotli_decompress(&zkey_br)?;
    let wasm = brotli_decompress(&wasm_br)?;

    validate_hash("zkey", &zkey, expected.zkey.as_slice())?;
    validate_hash("wasm", &wasm, expected.wasm.as_slice())?;

    write_if_needed(&paths.zkey, &zkey, force)?;
    write_if_needed(&paths.wasm, &wasm, force)?;

    Ok(paths)
}

pub fn load_artifacts(nullifiers: usize, commitments: usize) -> Result<Artifacts, ArtifactError> {
    let source = ArtifactSource::default();
    load_artifacts_with_source(nullifiers, commitments, &source)
}

pub fn load_artifacts_with_source(
    nullifiers: usize,
    commitments: usize,
    source: &ArtifactSource,
) -> Result<Artifacts, ArtifactError> {
    assert_variant_exists(source, nullifiers, commitments)?;
    let variant = variant_name(nullifiers, commitments);
    let paths = artifact_paths(&variant, source);

    let zkey = fs::read(&paths.zkey).map_err(|source| ArtifactError::ArtifactFile {
        path: paths.zkey.clone(),
        source,
    })?;
    let wasm = fs::read(&paths.wasm).map_err(|source| ArtifactError::ArtifactFile {
        path: paths.wasm.clone(),
        source,
    })?;

    Ok(Artifacts { zkey, wasm })
}

pub fn expected_zkey_hash(
    variant: &str,
    source: &ArtifactSource,
) -> Result<FixedBytes<32>, ArtifactError> {
    let hashes = load_hashes(source)?;
    let expected = hashes
        .get(variant)
        .ok_or_else(|| ArtifactError::MissingHash {
            variant: variant.to_string(),
        })?;
    Ok(expected.zkey)
}

fn assert_variant_exists(
    source: &ArtifactSource,
    nullifiers: usize,
    commitments: usize,
) -> Result<(), ArtifactError> {
    let specs = artifact_specs(source)?;
    let exists = specs
        .iter()
        .any(|spec| spec.nullifiers == nullifiers && spec.commitments == commitments);
    if exists {
        Ok(())
    } else {
        Err(ArtifactError::UnsupportedVariant {
            nullifiers,
            commitments,
        })
    }
}

fn artifact_specs(source: &ArtifactSource) -> Result<Vec<ArtifactSpec>, ArtifactError> {
    if let Some(dir) = source.metadata_dir.as_ref() {
        let path = dir.join(ARTIFACTS_LIST_FILE);
        let data =
            fs::read(&path).map_err(|source| ArtifactError::ArtifactFile { path, source })?;
        serde_json::from_slice(&data).map_err(ArtifactError::ArtifactList)
    } else {
        serde_json::from_slice(ARTIFACTS_LIST_EMBED).map_err(ArtifactError::ArtifactList)
    }
}

fn load_hashes(source: &ArtifactSource) -> Result<HashMap<String, ArtifactHashes>, ArtifactError> {
    if let Some(dir) = source.metadata_dir.as_ref() {
        let path = dir.join(ARTIFACTS_HASHES_FILE);
        let data = fs::read(&path).map_err(ArtifactError::ArtifactHashes)?;
        serde_json::from_slice(&data).map_err(ArtifactError::HashesParse)
    } else {
        serde_json::from_slice(ARTIFACTS_HASHES_EMBED).map_err(ArtifactError::HashesParse)
    }
}

struct ArtifactUrls {
    zkey: Url,
    wasm: Url,
}

fn artifact_urls(source: &ArtifactSource, variant: &str) -> Result<ArtifactUrls, ArtifactError> {
    let base_suffix = format!("ipfs/{}/", source.ipfs_hash);
    let base = source
        .gateway
        .join(&base_suffix)
        .map_err(|source| ArtifactError::InvalidUrl {
            url: base_suffix,
            source,
        })?;
    let zkey_path = format!("circuits/{variant}/zkey.br");
    let wasm_path = format!("prover/snarkjs/{variant}.wasm.br");
    let zkey = base
        .join(&zkey_path)
        .map_err(|source| ArtifactError::InvalidUrl {
            url: format!("{base}{zkey_path}"),
            source,
        })?;
    let wasm = base
        .join(&wasm_path)
        .map_err(|source| ArtifactError::InvalidUrl {
            url: format!("{base}{wasm_path}"),
            source,
        })?;
    Ok(ArtifactUrls { zkey, wasm })
}

fn fetch_bytes(client: &Client, url: &Url) -> Result<bytes::Bytes, ArtifactError> {
    client
        .get(url.clone())
        .send()
        .map_err(|source| ArtifactError::Download {
            source,
            url: url.clone(),
        })?
        .bytes()
        .map_err(|source| ArtifactError::Download {
            source,
            url: url.clone(),
        })
}

fn brotli_decompress(data: &[u8]) -> Result<Vec<u8>, ArtifactError> {
    let mut out = Vec::new();
    let mut reader = Decompressor::new(data, 4096);
    reader
        .read_to_end(&mut out)
        .map_err(ArtifactError::Decompress)?;
    Ok(out)
}

fn validate_hash(label: &str, data: &[u8], expected: &[u8]) -> Result<(), ArtifactError> {
    let digest = Sha256::digest(data);
    if digest.as_slice() != expected {
        let actual = hex::encode(digest);
        let expected = hex::encode(expected);
        return Err(ArtifactError::HashMismatch {
            label: label.to_string(),
            actual,
            expected,
        });
    }
    Ok(())
}

fn write_if_needed(path: &Path, data: &[u8], force: bool) -> Result<(), ArtifactError> {
    if path.exists() && !force {
        return Ok(());
    }
    fs::write(path, data).map_err(|source| ArtifactError::ArtifactFile {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}
