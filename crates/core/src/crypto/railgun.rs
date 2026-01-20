use crate::crypto::poseidon::poseidon;
use crate::serde_helpers::hex_array32;
use alloy::primitives::{Bytes, U256};
use ark_ed_on_bn254::Fq;
use ark_ff::{BigInteger, Field, PrimeField};
use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32m, Hrp};
use ed25519_dalek::SigningKey;
use std::fmt::Display;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct Address(String);
impl Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub type PublicKey = [u8; 32];

#[derive(Debug, Error)]
pub enum RailgunError {
    #[error("bech32 decode failed: {0}")]
    Bech32Decode(#[from] bech32::primitives::decode::CheckedHrpstringError),
    #[error("unexpected hrp: {0}")]
    UnexpectedHrp(String),
    #[error("unexpected decoded length: {0}")]
    UnexpectedLength(usize),
    #[error("unsupported address version: {0}")]
    UnsupportedVersion(u8),
    #[error("msgpack decode failed: {0}")]
    MsgpackDecode(#[from] rmp_serde::decode::Error),
    #[error("encode address failed: {0}")]
    Bech32Encode(#[from] bech32::EncodeError),
    #[error("invalid point: den=0")]
    InvalidPointDen,
    #[error("invalid point: no sqrt")]
    InvalidPointSqrt,
    #[error("invalid hrp")]
    InvalidHrp,
}

impl TryFrom<&Address> for PublicKey {
    type Error = RailgunError;
    fn try_from(addr: &Address) -> Result<Self, Self::Error> {
        let checked = CheckedHrpstring::new::<Bech32m>(&addr.0)?;

        if checked.hrp().as_str() != "0zk" {
            return Err(RailgunError::UnexpectedHrp(checked.hrp().to_string()));
        }

        let bytes: Vec<u8> = checked.byte_iter().collect();

        if bytes.len() != 73 {
            return Err(RailgunError::UnexpectedLength(bytes.len()));
        }

        let version = bytes[0];
        if version != 1 {
            return Err(RailgunError::UnsupportedVersion(version));
        }

        let mut vpk = [0u8; 32];
        vpk.copy_from_slice(&bytes[41..73]);
        Ok(vpk)
    }
}

impl From<&str> for Address {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl AsRef<str> for Address {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct PrivateKey(Bytes);

impl From<Bytes> for PrivateKey {
    fn from(value: Bytes) -> Self {
        Self(value)
    }
}

#[derive(Debug, serde::Deserialize)]
struct ShareableViewingKeyData {
    #[serde(deserialize_with = "hex_array32::deserialize")]
    vpriv: [u8; 32],
    #[serde(deserialize_with = "hex_array32::deserialize")]
    spub: [u8; 32],
}

impl TryFrom<&PrivateKey> for ShareableViewingKeyData {
    type Error = RailgunError;
    fn try_from(private_key: &PrivateKey) -> Result<Self, Self::Error> {
        Ok(rmp_serde::from_slice(&private_key.0)?)
    }
}

impl PrivateKey {
    pub fn decode_vpriv(&self) -> Result<[u8; 32], RailgunError> {
        Ok(ShareableViewingKeyData::try_from(self)?.vpriv)
    }
    pub fn derive_address(&self, chain: Option<(u8, u64)>) -> Result<Address, RailgunError> {
        let key_data = ShareableViewingKeyData::try_from(self)?;

        let viewing_pubkey = SigningKey::from_bytes(&key_data.vpriv)
            .verifying_key()
            .to_bytes();

        let (spub_x, spub_y) = babyjub_unpack_point_circom(key_data.spub)?;

        let nullifying = poseidon(vec![U256::from_be_slice(&key_data.vpriv)]);
        let mpk = poseidon(vec![
            U256::from_be_slice(spub_x.into_bigint().to_bytes_be().as_slice()),
            U256::from_be_slice(spub_y.into_bigint().to_bytes_be().as_slice()),
            nullifying,
        ]);

        let net = xor_railgun(network_id_bytes(chain));

        let mut payload = Vec::with_capacity(73);
        payload.push(0x01);
        payload.extend_from_slice(mpk.to_be_bytes::<32>().as_slice());
        payload.extend_from_slice(&net);
        payload.extend_from_slice(&viewing_pubkey);

        let hrp = Hrp::parse("0zk").map_err(|_| RailgunError::InvalidHrp)?;
        let addr = bech32::encode::<Bech32m>(hrp, &payload)?;
        Ok(Address(addr))
    }
}

fn network_id_bytes(chain: Option<(u8, u64)>) -> [u8; 8] {
    match chain {
        None => [0xffu8; 8], // ALL_CHAINS
        Some((chain_type, chain_id)) => {
            let mut out = [0u8; 8];
            out[0] = chain_type;

            // 7 bytes big-endian (uint56)
            let id = chain_id & 0x00FF_FFFF_FFFF_FFFF;
            let be = id.to_be_bytes(); // 8
            out[1..8].copy_from_slice(&be[1..8]);
            out
        }
    }
}

fn xor_railgun(mut b: [u8; 8]) -> [u8; 8] {
    let r = b"railgun";
    for i in 0..8 {
        let x = if i < r.len() { r[i] } else { 0u8 };
        b[i] ^= x;
    }
    b
}

fn babyjub_unpack_point_circom(packed: [u8; 32]) -> Result<(Fq, Fq), RailgunError> {
    let mut y_bytes = packed;
    let x_parity = (y_bytes[31] & 0x80) != 0;
    y_bytes[31] &= 0x7f;

    let y = Fq::from_le_bytes_mod_order(&y_bytes);

    let a = Fq::from(168_700_u64);
    let d = Fq::from(168_696_u64);

    let y2 = y.square();
    let num = Fq::ONE - y2;
    let den = a - d * y2;

    let den_inv = den.inverse().ok_or(RailgunError::InvalidPointDen)?;
    let x2 = num * den_inv;

    let mut x = x2.sqrt().ok_or(RailgunError::InvalidPointSqrt)?;

    let x_is_odd = (x.into_bigint().0[0] & 1) == 1;
    if x_is_odd != x_parity {
        x = -x;
    }

    Ok((x, y))
}
