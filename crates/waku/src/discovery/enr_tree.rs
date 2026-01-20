use super::DiscoveredPeer;
use super::enr::decode_enr_record;
use super::error::EnrTreeError;
use super::txt::TxtResolver;
use base64::Engine;
use data_encoding::BASE32_NOPAD;
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};
use rand::rng;
use rand::seq::SliceRandom;
use sha3::{Digest, Keccak256};
use std::collections::HashSet;
use std::sync::OnceLock;

const TREE_PREFIX: &str = "enrtree:";
const ROOT_PREFIX: &str = "enrtree-root:";
const BRANCH_PREFIX: &str = "enrtree-branch:";
const RECORD_PREFIX: &str = "enr:";

#[derive(Debug, Clone)]
struct EnrTreeRef {
    public_key_b32: String,
    domain: String,
    e_root: String,
}

pub(super) async fn discover_from_tree(
    resolver: &TxtResolver,
    tree_url: &str,
    max_txt_queries: usize,
    max_enrs: usize,
) -> Result<Vec<DiscoveredPeer>, EnrTreeError> {
    let mut tree_ref = parse_tree(tree_url)?;

    // Root TXT record is stored at the tree domain.
    let root_txt = resolver.resolve_txt(&tree_ref.domain).await?;

    let root_record = root_txt
        .into_iter()
        .find(|s| s.starts_with(ROOT_PREFIX))
        .ok_or_else(|| EnrTreeError::MissingRoot(tree_ref.domain.clone()))?;

    tree_ref.e_root = parse_and_verify_root(&root_record, &tree_ref.public_key_b32)?;

    let mut peers = Vec::new();
    let mut seen_records = HashSet::<String>::new();

    let mut total_queries = 0;
    let mut empty_or_duplicate = 0;

    while peers.len() < max_enrs && total_queries < max_txt_queries {
        let (maybe_record, used_queries) = random_walk_one_record(resolver, &tree_ref, 64).await?;
        total_queries += used_queries;

        let Some(record) = maybe_record else {
            empty_or_duplicate += 1;
            if empty_or_duplicate > 50 {
                break;
            }
            continue;
        };

        if seen_records.contains(&record) {
            empty_or_duplicate += 1;
            continue;
        }

        seen_records.insert(record.clone());

        if let Ok(peer) = decode_enr_record(&record) {
            peers.push(peer);
        }

        // Stop if the tree isn't yielding anything new.
        if empty_or_duplicate > 50 {
            break;
        }
    }

    Ok(peers)
}

async fn random_walk_one_record(
    resolver: &TxtResolver,
    tree: &EnrTreeRef,
    max_steps: usize,
) -> Result<(Option<String>, usize), EnrTreeError> {
    let mut current = tree.e_root.clone();
    let mut visited = HashSet::<String>::new();
    let mut queries = 0;

    for _ in 0..max_steps {
        queries += 1;

        // Location is either the top level tree entry host or a subdomain of it.
        let location = if current == tree.domain {
            tree.domain.clone()
        } else {
            format!("{current}.{}", tree.domain)
        };

        let txt_records = resolver.resolve_txt(&location).await.unwrap_or_default();
        if txt_records.is_empty() {
            return Ok((None, queries));
        }

        let entry = txt_records.join("");

        if entry.starts_with(ROOT_PREFIX) {
            // reset to the (verified) eRoot.
            current = parse_and_verify_root(&entry, &tree.public_key_b32)?;
            continue;
        }

        if entry.starts_with(BRANCH_PREFIX) {
            let mut branches = parse_branch(&entry)?;
            branches.shuffle(&mut rng());

            // Prefer unvisited branches to reduce loops.
            let next = branches
                .iter()
                .find(|b| !visited.contains(*b))
                .cloned()
                .or_else(|| branches.first().cloned());

            let Some(next) = next else {
                return Ok((None, queries));
            };

            visited.insert(current);
            current = next;
            continue;
        }

        if entry.starts_with(RECORD_PREFIX) {
            return Ok((Some(entry), queries));
        }

        // Unknown entry.
        return Ok((None, queries));
    }

    Ok((None, queries))
}

fn parse_tree(tree: &str) -> Result<EnrTreeRef, EnrTreeError> {
    if !tree.starts_with(TREE_PREFIX) {
        return Err(EnrTreeError::InvalidTreeUrlPrefix);
    }

    let without_prefix = tree
        .strip_prefix("enrtree://")
        .ok_or(EnrTreeError::InvalidTreeUrlPrefix)?;

    let (public_key_b32, domain) = without_prefix
        .split_once('@')
        .ok_or(EnrTreeError::InvalidTreeUrlFormat)?;

    Ok(EnrTreeRef {
        public_key_b32: public_key_b32.to_string(),
        domain: domain.to_string(),
        e_root: String::new(),
    })
}

fn parse_and_verify_root(root: &str, public_key_b32: &str) -> Result<String, EnrTreeError> {
    if !root.starts_with(ROOT_PREFIX) {
        return Err(EnrTreeError::InvalidRootPrefix);
    }

    let root_values = parse_root_values(root)?;

    let public_key_bytes = BASE32_NOPAD.decode(public_key_b32.as_bytes())?;

    let verifying_key = VerifyingKey::from_sec1_bytes(&public_key_bytes)?;

    // Signature is 65 bytes (recovery id at end). Verify uses compact 64-byte signature.
    let sig_bytes =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(root_values.signature)?;

    if sig_bytes.len() < 64 {
        return Err(EnrTreeError::InvalidSignatureLength);
    }

    let signature = Signature::from_slice(&sig_bytes[..64])?;

    let signed_component = root
        .split(" sig")
        .next()
        .ok_or(EnrTreeError::InvalidRootFormat)?;

    let mut hasher = Keccak256::new();
    hasher.update(signed_component.as_bytes());
    let digest = hasher.finalize();

    verifying_key
        .verify_prehash(digest.as_ref(), &signature)
        .map_err(|_| EnrTreeError::SignatureVerificationFailed)?;

    Ok(root_values.e_root)
}

#[derive(Debug)]
struct RootValues {
    e_root: String,
    signature: String,
}

fn parse_root_values(txt: &str) -> Result<RootValues, EnrTreeError> {
    static ROOT_RE: OnceLock<regex::Regex> = OnceLock::new();
    let re = ROOT_RE.get_or_init(|| {
        regex::Regex::new(r"^enrtree-root:v1 e=([^ ]+) l=([^ ]+) seq=(\d+) sig=([^ ]+)$")
            .expect("valid ENR tree root regex")
    });

    let caps = re.captures(txt).ok_or(EnrTreeError::InvalidRootFormat)?;

    let e_root = caps
        .get(1)
        .ok_or(EnrTreeError::InvalidRootFormat)?
        .as_str()
        .to_string();

    let signature = caps
        .get(4)
        .ok_or(EnrTreeError::InvalidRootFormat)?
        .as_str()
        .to_string();

    Ok(RootValues { e_root, signature })
}

fn parse_branch(branch: &str) -> Result<Vec<String>, EnrTreeError> {
    if !branch.starts_with(BRANCH_PREFIX) {
        return Err(EnrTreeError::InvalidBranchPrefix);
    }

    let suffix = branch
        .strip_prefix(BRANCH_PREFIX)
        .ok_or(EnrTreeError::InvalidBranchPrefix)?;

    Ok(suffix.split(',').map(|s| s.trim().to_string()).collect())
}
