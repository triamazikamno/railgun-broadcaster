use std::ops::Deref;
use std::sync::LazyLock;

use alloy::primitives::U256;
use ark_ed_on_bn254::Fq;
use ark_ff::{AdditiveGroup, Field, MontFp};
use bloock_blake_rs::Blake512;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use ruint::uint;
use sha2::{Digest, Sha512};
use thiserror::Error;

use broadcaster_core::crypto::ark_utils::prime_field_to_u256;
use broadcaster_core::crypto::poseidon::poseidon;
use broadcaster_core::crypto::railgun::{
    Address as RailgunAddress, AddressData, RailgunError, ViewingKeyData,
};

type HmacSha512 = Hmac<Sha512>;
type U512 = ruint::Uint<512, 8>;

const BABYJUB_SEED: &[u8] = b"babyjubjub seed";
const HARDENED_OFFSET: u32 = 0x8000_0000;
const BABYJUB_A: u64 = 168_700;
const BABYJUB_D: u64 = 168_696;
const BABYJUB_BASE8_X: Fq =
    MontFp!("5299619240641551281634865583518297030282874472190772894086521144482721001553");
const BABYJUB_BASE8_Y: Fq =
    MontFp!("16950150798460657717958625567821834550301663161624707787222815936182638968203");

static BABYJUB_SUBORDER: LazyLock<BigUint> = LazyLock::new(|| {
    BigUint::from_bytes_be(&[
        0x06, 0x0c, 0x89, 0xce, 0x5c, 0x26, 0x34, 0x05, 0x37, 0x0a, 0x08, 0xb6, 0xd0, 0x30, 0x2b,
        0x0b, 0xab, 0x3e, 0xed, 0xb8, 0x39, 0x20, 0xee, 0x0a, 0x67, 0x72, 0x97, 0xdc, 0x39, 0x21,
        0x26, 0xf1,
    ])
});

const ED25519_ORDER: U512 =
    uint!(0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed_U512);

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("invalid mnemonic")]
    InvalidMnemonic,
    #[error("invalid derivation path")]
    InvalidPath,
    #[error("ed25519 pubkey invalid")]
    InvalidEd25519Pubkey,
}

#[derive(Debug, Clone)]
pub struct WalletKeys {
    pub spending_private_key: [u8; 32],
    pub spending_public_key: [U256; 2],
    pub viewing: ViewingKeyData,
}

#[derive(Debug, Clone)]
pub struct EddsaSignature {
    pub r8: [U256; 2],
    pub s: U256,
}

#[derive(Debug, Clone, Copy)]
struct BabyJubPoint {
    x: Fq,
    y: Fq,
}

impl BabyJubPoint {
    fn new(x: Fq, y: Fq) -> Self {
        Self { x, y }
    }

    fn base8() -> Self {
        Self::new(BABYJUB_BASE8_X, BABYJUB_BASE8_Y)
    }

    fn add(self, other: Self) -> Self {
        let a_const = Fq::from(BABYJUB_A);
        let d_const = Fq::from(BABYJUB_D);

        let beta = self.x * other.y;
        let gamma = self.y * other.x;
        let delta = (self.y - a_const * self.x) * (other.x + other.y);
        let tau = beta * gamma;
        let dtau = d_const * tau;

        let denom_x = (Fq::ONE + dtau).inverse().expect("non-zero denominator");
        let denom_y = (Fq::ONE - dtau).inverse().expect("non-zero denominator");

        let x = (beta + gamma) * denom_x;
        let y = (delta + (a_const * beta - gamma)) * denom_y;

        Self::new(x, y)
    }

    fn mul(self, scalar: BigUint) -> Self {
        let mut res = Self::new(Fq::ZERO, Fq::ONE);
        let mut rem = scalar;
        let mut exp = self;
        let one = BigUint::one();

        while !rem.is_zero() {
            if (&rem & &one) == one {
                res = res.add(exp);
            }
            exp = exp.add(exp);
            rem >>= 1u32;
        }

        res
    }
}

impl WalletKeys {
    pub fn from_mnemonic(mnemonic: &str, index: u32) -> Result<Self, KeyError> {
        let seed = bip39_seed(mnemonic)?;
        let spending_node = WalletNode::try_from_path(&seed, &spending_path(index))?;
        let viewing_node = WalletNode::try_from_path(&seed, &viewing_path(index))?;

        let spending_private_key = spending_node.chain_key;
        let viewing_private_key = viewing_node.chain_key;
        let spending_public_key = public_spending_key(&spending_private_key);
        let viewing =
            ViewingKeyData::from_spending_public_key(viewing_private_key, spending_public_key);

        Ok(Self {
            spending_private_key,
            spending_public_key,
            viewing,
        })
    }

    #[must_use]
    pub fn address_data(&self) -> AddressData {
        self.viewing.address_data()
    }

    pub fn wallet_id(&self, chain_id: u64, chain_type: u8) -> Result<String, RailgunError> {
        let address = RailgunAddress::try_from_parts(
            self.viewing.master_public_key,
            self.viewing.viewing_public_key,
            Some((chain_type, chain_id)),
        )?;
        Ok(address.to_string())
    }
}

impl EddsaSignature {
    #[must_use]
    pub fn new(private_key: &[u8; 32], msg: U256) -> Self {
        let s_buff = blake512_prune(private_key);
        let s = BigUint::from_bytes_le(&s_buff[..32]);
        let base8 = BabyJubPoint::base8();
        let a_scalar = s.clone() >> 3u32;
        let a = base8.mul(a_scalar);

        let mut compose = [0u8; 64];
        compose[..32].copy_from_slice(&s_buff[32..]);
        compose[32..].copy_from_slice(&msg.to_le_bytes::<32>());

        let r_buff = blake512_bytes(&compose);
        let suborder = BABYJUB_SUBORDER.deref();
        let mut r = BigUint::from_bytes_le(&r_buff);
        r %= suborder;

        let r8 = base8.mul(r.clone());

        let hm = poseidon(vec![
            prime_field_to_u256(r8.x),
            prime_field_to_u256(r8.y),
            prime_field_to_u256(a.x),
            prime_field_to_u256(a.y),
            msg,
        ]);
        let s_term = (BigUint::from(hm) * &s) % suborder;
        let s_value = (r + s_term) % suborder;

        Self {
            r8: [prime_field_to_u256(r8.x), prime_field_to_u256(r8.y)],
            s: U256::from(s_value),
        }
    }
}

#[must_use]
pub fn public_spending_key(private_key: &[u8; 32]) -> [U256; 2] {
    let s_buff = blake512_prune(private_key);
    let s = BigUint::from_bytes_le(&s_buff[..32]);
    let base8 = BabyJubPoint::base8();
    let a_scalar = s >> 3u32;
    let point = base8.mul(a_scalar);
    [prime_field_to_u256(point.x), prime_field_to_u256(point.y)]
}

fn blake512_bytes(data: &[u8]) -> [u8; 64] {
    let mut hasher = Blake512::default();
    hasher.write(data);
    let result = hasher.sum(&[]);
    let mut out = [0u8; 64];
    out.copy_from_slice(&result[..64]);
    out
}

fn blake512_prune(private_key: &[u8; 32]) -> [u8; 64] {
    let mut buff = blake512_bytes(private_key);
    buff[0] &= 0xF8;
    buff[31] &= 0x7F;
    buff[31] |= 0x40;
    buff
}

pub fn note_blinding_keys(
    sender_viewing_pubkey: &[u8; 32],
    receiver_viewing_pubkey: &[u8; 32],
    shared_random: [u8; 16],
    sender_random: [u8; 15],
) -> Result<([u8; 32], [u8; 32]), KeyError> {
    let blinding_scalar = blinding_scalar(shared_random, sender_random);
    let sender_point = CompressedEdwardsY(*sender_viewing_pubkey)
        .decompress()
        .ok_or(KeyError::InvalidEd25519Pubkey)?;
    let receiver_point = CompressedEdwardsY(*receiver_viewing_pubkey)
        .decompress()
        .ok_or(KeyError::InvalidEd25519Pubkey)?;
    let blinded_sender = (sender_point * blinding_scalar).compress().to_bytes();
    let blinded_receiver = (receiver_point * blinding_scalar).compress().to_bytes();
    Ok((blinded_sender, blinded_receiver))
}

fn spending_path(index: u32) -> String {
    format!("m/44'/1984'/0'/0'/{index}'")
}

fn viewing_path(index: u32) -> String {
    format!("m/420'/1984'/0'/0'/{index}'")
}

fn bip39_seed(mnemonic: &str) -> Result<[u8; 64], KeyError> {
    let mnemonic = bip39::Mnemonic::parse(mnemonic).map_err(|_| KeyError::InvalidMnemonic)?;
    let seed = mnemonic.to_seed("");
    let mut out = [0u8; 64];
    out.copy_from_slice(&seed);
    Ok(out)
}

#[derive(Debug, Clone, Copy)]
struct WalletNode {
    chain_key: [u8; 32],
    chain_code: [u8; 32],
}

impl WalletNode {
    fn new(chain_key: [u8; 32], chain_code: [u8; 32]) -> Self {
        Self {
            chain_key,
            chain_code,
        }
    }

    fn from_seed(seed: &[u8; 64]) -> Self {
        let Ok(mut mac) = HmacSha512::new_from_slice(BABYJUB_SEED) else {
            unreachable!("HMAC accepts any key length");
        };
        mac.update(seed);
        let result = mac.finalize().into_bytes();
        let mut chain_key = [0u8; 32];
        let mut chain_code = [0u8; 32];
        chain_key.copy_from_slice(&result[..32]);
        chain_code.copy_from_slice(&result[32..64]);
        Self::new(chain_key, chain_code)
    }

    fn derive_hardened(&self, index: u32, offset: u32) -> Self {
        let index = index.wrapping_add(offset);
        let mut preimage = [0u8; 1 + 32 + 4];
        preimage[1..33].copy_from_slice(&self.chain_key);
        preimage[33..37].copy_from_slice(&index.to_be_bytes());

        let Ok(mut mac) = HmacSha512::new_from_slice(&self.chain_code) else {
            unreachable!("HMAC accepts any key length");
        };
        mac.update(&preimage);
        let result = mac.finalize().into_bytes();
        let mut chain_key = [0u8; 32];
        let mut chain_code = [0u8; 32];
        chain_key.copy_from_slice(&result[..32]);
        chain_code.copy_from_slice(&result[32..64]);
        Self::new(chain_key, chain_code)
    }

    fn try_from_path(seed: &[u8; 64], path: &str) -> Result<Self, KeyError> {
        let master = Self::from_seed(seed);
        let segments = parse_path(path)?;
        segments.into_iter().try_fold(master, |node, segment| {
            Ok(node.derive_hardened(segment, HARDENED_OFFSET))
        })
    }
}

fn parse_path(path: &str) -> Result<Vec<u32>, KeyError> {
    if !path.starts_with('m') {
        return Err(KeyError::InvalidPath);
    }
    let mut segments = Vec::new();
    for segment in path.split('/').skip(1) {
        if !segment.ends_with('\'') {
            return Err(KeyError::InvalidPath);
        }
        let value = segment.trim_end_matches('\'');
        let parsed = value.parse::<u32>().map_err(|_| KeyError::InvalidPath)?;
        segments.push(parsed);
    }
    Ok(segments)
}

fn blinding_scalar(shared_random: [u8; 16], sender_random: [u8; 15]) -> Scalar {
    let mut shared = [0u8; 32];
    shared[16..].copy_from_slice(&shared_random);
    let mut sender = [0u8; 32];
    sender[17..].copy_from_slice(&sender_random);
    let shared_val = U256::from_be_bytes(shared);
    let sender_val = U256::from_be_bytes(sender);
    let final_val = shared_val ^ sender_val;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&final_val.to_be_bytes::<32>());
    seed_to_scalar(&seed)
}

fn seed_to_scalar(seed: &[u8; 32]) -> Scalar {
    let hash = Sha512::digest(seed);
    let hash_val = U512::from_be_slice(&hash);
    let mut scalar = hash_val % ED25519_ORDER;
    if scalar.is_zero() {
        scalar = U512::ONE;
    }
    let bytes = scalar.to_le_bytes::<64>();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[..32]);
    Scalar::from_bytes_mod_order(out)
}
