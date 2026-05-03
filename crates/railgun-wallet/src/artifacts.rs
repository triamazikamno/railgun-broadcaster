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
const DEFAULT_POI_IPFS_HASH: &str = "QmZrP9zaZw2LwErT2yA6VpMWm65UdToQiKj4DtStVsUJHr";
const ARTIFACTS_DIR: &str = "db/railgun/blobs/artifacts";
const ARTIFACTS_LIST_FILE: &str = "artifacts.json";
const ARTIFACTS_HASHES_FILE: &str = "artifact-v2-hashes.json";
const POI_ARTIFACT_PREFIX: &str = "POI_";
const POI_ARTIFACT_CACHE_DIR: &str = "artifacts-v2.1/poi-nov-2-23";

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
    #[error("unsupported POI artifact variant {variant}")]
    UnsupportedPoiVariant { variant: String },
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
    pub poi_ipfs_hash: String,
    pub out_dir: PathBuf,
    pub metadata_dir: Option<PathBuf>,
    /// Optional proxy URL for artifact downloads (e.g. `socks5h://127.0.0.1:9050`).
    pub proxy: Option<Url>,
}

impl Default for ArtifactSource {
    fn default() -> Self {
        Self {
            gateway: Url::parse(DEFAULT_GATEWAY).expect("valid gateway url"),
            ipfs_hash: DEFAULT_IPFS_HASH.to_string(),
            poi_ipfs_hash: DEFAULT_POI_IPFS_HASH.to_string(),
            out_dir: PathBuf::from(ARTIFACTS_DIR),
            metadata_dir: None,
            proxy: None,
        }
    }
}

impl ArtifactSource {
    #[must_use]
    pub fn new(gateway: Url, ipfs_hash: String, out_dir: PathBuf) -> Self {
        Self {
            gateway,
            ipfs_hash,
            poi_ipfs_hash: DEFAULT_POI_IPFS_HASH.to_string(),
            out_dir,
            metadata_dir: None,
            proxy: None,
        }
    }

    #[must_use]
    pub fn with_cache_dir(mut self, path: PathBuf) -> Self {
        self.out_dir = path;
        self
    }

    #[must_use]
    pub fn with_poi_ipfs_hash(mut self, ipfs_hash: String) -> Self {
        self.poi_ipfs_hash = ipfs_hash;
        self
    }

    #[must_use]
    pub fn with_proxy(mut self, proxy: Url) -> Self {
        self.proxy = Some(proxy);
        self
    }

    pub fn with_metadata_dir(mut self, path: PathBuf) -> Result<Self, ArtifactError> {
        validate_metadata_dir(&path)?;
        self.metadata_dir = Some(path);
        Ok(self)
    }

    pub fn list_variants(&self) -> Result<Vec<String>, ArtifactError> {
        let specs = self.artifact_specs()?;
        let mut variants: Vec<String> = specs
            .iter()
            .map(|spec| variant_name(spec.nullifiers, spec.commitments))
            .collect();
        variants.sort();
        Ok(variants)
    }

    #[must_use]
    pub fn artifact_paths(&self, variant: &str) -> ArtifactPaths {
        let base = if is_poi_variant(variant) {
            self.out_dir.join(POI_ARTIFACT_CACHE_DIR).join(variant)
        } else {
            self.out_dir.join(variant)
        };
        ArtifactPaths {
            zkey: base.join("zkey"),
            wasm: base.join("wasm"),
        }
    }

    pub fn ensure_artifacts(
        &self,
        nullifiers: usize,
        commitments: usize,
    ) -> Result<ArtifactPaths, ArtifactError> {
        self.assert_variant_exists(nullifiers, commitments)?;
        let variant = variant_name(nullifiers, commitments);
        let paths = self.artifact_paths(&variant);
        if paths.zkey.exists() && paths.wasm.exists() {
            return Ok(paths);
        }
        self.download_variant(&variant, false)?;
        Ok(paths)
    }

    pub fn ensure_poi_artifacts(
        &self,
        max_inputs: usize,
        max_outputs: usize,
    ) -> Result<ArtifactPaths, ArtifactError> {
        let variant = poi_variant_name(max_inputs, max_outputs);
        assert_supported_poi_variant(&variant)?;
        let paths = self.artifact_paths(&variant);
        if paths.zkey.exists() && paths.wasm.exists() {
            return Ok(paths);
        }
        self.download_variant(&variant, false)?;
        Ok(paths)
    }

    pub fn download_variants(
        &self,
        variants: &[String],
        force: bool,
    ) -> Result<Vec<ArtifactPaths>, ArtifactError> {
        let mut out = Vec::with_capacity(variants.len());
        for variant in variants {
            out.push(self.download_variant(variant, force)?);
        }
        Ok(out)
    }

    pub fn download_variant(
        &self,
        variant: &str,
        force: bool,
    ) -> Result<ArtifactPaths, ArtifactError> {
        let hashes = self.load_hashes()?;
        let expected = hashes
            .get(variant)
            .ok_or_else(|| ArtifactError::MissingHash {
                variant: variant.to_string(),
            })?;
        let paths = self.artifact_paths(variant);

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

        let urls = self.artifact_urls(variant)?;
        let client = {
            let mut builder = Client::builder();
            if let Some(proxy_url) = &self.proxy {
                let proxy = reqwest::Proxy::all(proxy_url.as_str()).map_err(|source| {
                    ArtifactError::Download {
                        source,
                        url: proxy_url.clone(),
                    }
                })?;
                builder = builder.proxy(proxy);
            }
            builder.build().map_err(|source| ArtifactError::Download {
                source,
                url: urls.zkey.clone(),
            })?
        };

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

    pub fn load_artifacts(
        &self,
        nullifiers: usize,
        commitments: usize,
    ) -> Result<Artifacts, ArtifactError> {
        self.assert_variant_exists(nullifiers, commitments)?;
        let variant = variant_name(nullifiers, commitments);
        let paths = self.artifact_paths(&variant);

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

    pub fn expected_zkey_hash(&self, variant: &str) -> Result<FixedBytes<32>, ArtifactError> {
        let hashes = self.load_hashes()?;
        let expected = hashes
            .get(variant)
            .ok_or_else(|| ArtifactError::MissingHash {
                variant: variant.to_string(),
            })?;
        Ok(expected.zkey)
    }

    fn assert_variant_exists(
        &self,
        nullifiers: usize,
        commitments: usize,
    ) -> Result<(), ArtifactError> {
        let specs = self.artifact_specs()?;
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

    fn artifact_specs(&self) -> Result<Vec<ArtifactSpec>, ArtifactError> {
        if let Some(dir) = self.metadata_dir.as_ref() {
            let path = dir.join(ARTIFACTS_LIST_FILE);
            let data =
                fs::read(&path).map_err(|source| ArtifactError::ArtifactFile { path, source })?;
            serde_json::from_slice(&data).map_err(ArtifactError::ArtifactList)
        } else {
            serde_json::from_slice(ARTIFACTS_LIST_EMBED).map_err(ArtifactError::ArtifactList)
        }
    }

    fn load_hashes(&self) -> Result<HashMap<String, ArtifactHashes>, ArtifactError> {
        if let Some(dir) = self.metadata_dir.as_ref() {
            let path = dir.join(ARTIFACTS_HASHES_FILE);
            let data = fs::read(&path).map_err(ArtifactError::ArtifactHashes)?;
            serde_json::from_slice(&data).map_err(ArtifactError::HashesParse)
        } else {
            serde_json::from_slice(ARTIFACTS_HASHES_EMBED).map_err(ArtifactError::HashesParse)
        }
    }

    fn artifact_urls(&self, variant: &str) -> Result<ArtifactUrls, ArtifactError> {
        let base_suffix = if is_poi_variant(variant) {
            assert_supported_poi_variant(variant)?;
            format!("ipfs/{}/", self.poi_ipfs_hash)
        } else {
            format!("ipfs/{}/", self.ipfs_hash)
        };
        let base = self
            .gateway
            .join(&base_suffix)
            .map_err(|source| ArtifactError::InvalidUrl {
                url: base_suffix,
                source,
            })?;
        let (zkey_path, wasm_path) = if is_poi_variant(variant) {
            (format!("{variant}/zkey.br"), format!("{variant}/wasm.br"))
        } else {
            (
                format!("circuits/{variant}/zkey.br"),
                format!("prover/snarkjs/{variant}.wasm.br"),
            )
        };
        let zkey = base
            .join(&zkey_path)
            .map_err(|source| ArtifactError::InvalidUrl {
                url: zkey_path,
                source,
            })?;
        let wasm = base
            .join(&wasm_path)
            .map_err(|source| ArtifactError::InvalidUrl {
                url: wasm_path,
                source,
            })?;
        Ok(ArtifactUrls { zkey, wasm })
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

#[must_use]
pub fn poi_variant_name(max_inputs: usize, max_outputs: usize) -> String {
    format!("{POI_ARTIFACT_PREFIX}{max_inputs}x{max_outputs}")
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

pub fn load_artifacts(nullifiers: usize, commitments: usize) -> Result<Artifacts, ArtifactError> {
    let source = ArtifactSource::default();
    source.load_artifacts(nullifiers, commitments)
}

struct ArtifactUrls {
    zkey: Url,
    wasm: Url,
}

fn is_poi_variant(variant: &str) -> bool {
    variant.starts_with(POI_ARTIFACT_PREFIX)
}

fn assert_supported_poi_variant(variant: &str) -> Result<(), ArtifactError> {
    if variant == poi_variant_name(3, 3) || variant == poi_variant_name(13, 13) {
        Ok(())
    } else {
        Err(ArtifactError::UnsupportedPoiVariant {
            variant: variant.to_string(),
        })
    }
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{ArtifactSource, poi_variant_name};

    #[test]
    fn poi_variant_name_matches_expected_shape() {
        assert_eq!(poi_variant_name(3, 3), "POI_3x3");
        assert_eq!(poi_variant_name(13, 13), "POI_13x13");
    }

    #[test]
    fn poi_artifact_paths_use_poi_cache_dir() {
        let source = ArtifactSource::default().with_cache_dir(PathBuf::from("cache"));

        let paths = source.artifact_paths("POI_3x3");

        assert_eq!(
            paths.zkey,
            PathBuf::from("cache/artifacts-v2.1/poi-nov-2-23/POI_3x3/zkey")
        );
        assert_eq!(
            paths.wasm,
            PathBuf::from("cache/artifacts-v2.1/poi-nov-2-23/POI_3x3/wasm")
        );
    }

    #[test]
    fn poi_artifact_urls_use_poi_ipfs_hash_and_flat_paths() {
        let source = ArtifactSource::default().with_poi_ipfs_hash("poi-hash".to_string());

        let urls = source.artifact_urls("POI_13x13").expect("poi urls");

        assert_eq!(
            urls.zkey.as_str(),
            "https://ipfs-lb.com/ipfs/poi-hash/POI_13x13/zkey.br"
        );
        assert_eq!(
            urls.wasm.as_str(),
            "https://ipfs-lb.com/ipfs/poi-hash/POI_13x13/wasm.br"
        );
    }

    #[test]
    fn unsupported_poi_variant_is_rejected_before_download() {
        let source = ArtifactSource::default();

        let error = source
            .ensure_poi_artifacts(4, 4)
            .expect_err("unsupported poi variant should fail");

        assert!(error.to_string().contains("POI_4x4"));
    }
}
