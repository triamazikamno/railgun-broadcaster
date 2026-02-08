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

#[derive(Debug, Clone, Copy)]
pub struct AddressData {
    pub master_public_key: U256,
    pub viewing_public_key: PublicKey,
}

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

impl Address {
    pub fn try_from_parts(
        master_public_key: U256,
        viewing_public_key: PublicKey,
        chain: Option<(u8, u64)>,
    ) -> Result<Self, RailgunError> {
        let net = xor_railgun(network_id_bytes(chain));

        let mut payload = Vec::with_capacity(73);
        payload.push(0x01);
        payload.extend_from_slice(&master_public_key.to_be_bytes::<32>());
        payload.extend_from_slice(&net);
        payload.extend_from_slice(&viewing_public_key);

        let hrp = Hrp::parse("0zk").map_err(|_| RailgunError::InvalidHrp)?;
        let addr = bech32::encode::<Bech32m>(hrp, &payload)?;
        Ok(Self(addr))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct ShareableViewingKey(Bytes);

impl From<Bytes> for ShareableViewingKey {
    fn from(value: Bytes) -> Self {
        Self(value)
    }
}

#[derive(Debug, serde::Deserialize)]
struct ShareableViewingKeyPayload {
    #[serde(deserialize_with = "hex_array32::deserialize")]
    vpriv: [u8; 32],
    #[serde(deserialize_with = "hex_array32::deserialize")]
    spub: [u8; 32],
}

impl TryFrom<&ShareableViewingKey> for ShareableViewingKeyPayload {
    type Error = RailgunError;
    fn try_from(viewing_key: &ShareableViewingKey) -> Result<Self, Self::Error> {
        Ok(rmp_serde::from_slice(&viewing_key.0)?)
    }
}

impl ShareableViewingKey {
    pub fn decode_viewing_private_key(&self) -> Result<[u8; 32], RailgunError> {
        Ok(ShareableViewingKeyPayload::try_from(self)?.vpriv)
    }

    pub fn decode_viewing_key_data(&self) -> Result<ViewingKeyData, RailgunError> {
        let key_data = ShareableViewingKeyPayload::try_from(self)?;
        ViewingKeyData::from_packed_spending_public_key(key_data.vpriv, key_data.spub)
    }

    pub fn derive_address(&self, chain: Option<(u8, u64)>) -> Result<Address, RailgunError> {
        let key_data = self.decode_viewing_key_data()?;
        key_data.derive_address(chain)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ViewingKeyData {
    pub viewing_private_key: [u8; 32],
    pub viewing_public_key: PublicKey,
    pub nullifying_key: U256,
    pub master_public_key: U256,
}

impl ViewingKeyData {
    #[must_use]
    pub fn from_spending_public_key(
        viewing_private_key: [u8; 32],
        spending_public_key: [U256; 2],
    ) -> Self {
        let viewing_public_key = derive_viewing_public_key(&viewing_private_key);
        let nullifying_key = derive_nullifying_key(&viewing_private_key);
        let master_public_key = derive_master_public_key(spending_public_key, nullifying_key);
        Self {
            viewing_private_key,
            viewing_public_key,
            nullifying_key,
            master_public_key,
        }
    }

    pub fn from_packed_spending_public_key(
        viewing_private_key: [u8; 32],
        packed_spending_public_key: [u8; 32],
    ) -> Result<Self, RailgunError> {
        let spending_public_key = unpack_spending_public_key(packed_spending_public_key)?;
        Ok(Self::from_spending_public_key(
            viewing_private_key,
            spending_public_key,
        ))
    }

    #[must_use]
    pub fn address_data(&self) -> AddressData {
        AddressData::from(self)
    }

    pub fn derive_address(&self, chain: Option<(u8, u64)>) -> Result<Address, RailgunError> {
        Address::try_from_parts(self.master_public_key, self.viewing_public_key, chain)
    }
}

impl From<&ViewingKeyData> for AddressData {
    fn from(value: &ViewingKeyData) -> Self {
        Self {
            master_public_key: value.master_public_key,
            viewing_public_key: value.viewing_public_key,
        }
    }
}

#[must_use]
pub fn derive_viewing_public_key(viewing_private_key: &[u8; 32]) -> PublicKey {
    SigningKey::from_bytes(viewing_private_key)
        .verifying_key()
        .to_bytes()
}

#[must_use]
pub fn derive_nullifying_key(viewing_private_key: &[u8; 32]) -> U256 {
    poseidon(vec![U256::from_be_slice(viewing_private_key)])
}

#[must_use]
pub fn derive_master_public_key(spending_public_key: [U256; 2], nullifying_key: U256) -> U256 {
    poseidon(vec![
        spending_public_key[0],
        spending_public_key[1],
        nullifying_key,
    ])
}

#[must_use]
pub fn pack_chain_id(chain_type: u8, chain_id: u64) -> u64 {
    let id = chain_id & 0x00FF_FFFF_FFFF_FFFF;
    (u64::from(chain_type) << 56) | id
}

fn network_id_bytes(chain: Option<(u8, u64)>) -> [u8; 8] {
    match chain {
        None => [0xffu8; 8], // ALL_CHAINS
        Some((chain_type, chain_id)) => pack_chain_id(chain_type, chain_id).to_be_bytes(),
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

fn unpack_spending_public_key(packed: [u8; 32]) -> Result<[U256; 2], RailgunError> {
    let (spub_x, spub_y) = babyjub_unpack_point_circom(packed)?;
    Ok([
        U256::from_be_slice(spub_x.into_bigint().to_bytes_be().as_slice()),
        U256::from_be_slice(spub_y.into_bigint().to_bytes_be().as_slice()),
    ])
}
