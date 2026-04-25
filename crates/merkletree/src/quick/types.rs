use std::fmt;

use alloy::primitives::{Address, Bytes, FixedBytes, U256, Uint};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer};

use broadcaster_core::contracts::railgun::{
    CommitmentPreimage, LegacyCommitmentPreimage, ShieldCiphertext, TokenData,
};

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Commitment {
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_64")]
    pub id: FixedBytes<64>,
    #[serde(rename = "treeNumber")]
    pub tree_number: U256,
    #[serde(rename = "treePosition")]
    pub tree_position: U256,
    #[serde(rename = "batchStartTreePosition")]
    pub batch_start_tree_position: U256,
    #[serde(rename = "blockNumber")]
    pub block_number: U256,
    pub hash: U256,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub(crate) struct Nullifier {
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_64")]
    pub id: FixedBytes<64>,
    #[serde(rename = "blockNumber")]
    pub block_number: U256,
    #[serde(rename = "treeNumber")]
    pub tree_number: U256,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub(crate) struct Unshield {
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_36")]
    pub id: FixedBytes<36>,
    #[serde(rename = "blockNumber")]
    pub block_number: U256,
    #[serde(rename = "eventLogIndex")]
    pub event_log_index: U256,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IndexedTransactCommitment {
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_64")]
    pub id: FixedBytes<64>,
    #[serde(rename = "transactionHash")]
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_32")]
    pub transaction_hash: FixedBytes<32>,
    #[serde(rename = "blockNumber")]
    pub block_number: U256,
    #[serde(rename = "treeNumber")]
    pub tree_number: U256,
    #[serde(rename = "treePosition")]
    pub tree_position: U256,
    pub hash: U256,
    pub ciphertext: IndexedCommitmentCiphertext,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IndexedLegacyEncryptedCommitment {
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_64")]
    pub id: FixedBytes<64>,
    #[serde(rename = "transactionHash")]
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_32")]
    pub transaction_hash: FixedBytes<32>,
    #[serde(rename = "blockNumber")]
    pub block_number: U256,
    #[serde(rename = "treeNumber")]
    pub tree_number: U256,
    #[serde(rename = "treePosition")]
    pub tree_position: U256,
    pub hash: U256,
    pub ciphertext: IndexedLegacyCommitmentCiphertext,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IndexedLegacyCommitmentCiphertext {
    #[serde(deserialize_with = "deserialize_commitment_ciphertext")]
    pub ciphertext: [FixedBytes<32>; 4],
    #[serde(
        rename = "ephemeralKeys",
        deserialize_with = "deserialize_indexed_fixed_bytes_array_32_2"
    )]
    pub ephemeral_keys: [FixedBytes<32>; 2],
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_vec_32")]
    pub memo: Vec<FixedBytes<32>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IndexedLegacyGeneratedCommitment {
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_64")]
    pub id: FixedBytes<64>,
    #[serde(rename = "transactionHash")]
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_32")]
    pub transaction_hash: FixedBytes<32>,
    #[serde(rename = "blockNumber")]
    pub block_number: U256,
    #[serde(rename = "treeNumber")]
    pub tree_number: U256,
    #[serde(rename = "treePosition")]
    pub tree_position: U256,
    pub hash: U256,
    pub preimage: IndexedLegacyCommitmentPreimage,
    #[serde(
        rename = "encryptedRandom",
        deserialize_with = "deserialize_indexed_encrypted_random"
    )]
    pub encrypted_random: (FixedBytes<32>, FixedBytes<16>),
}

#[derive(Debug, Clone, Deserialize)]
pub struct IndexedCommitmentCiphertext {
    #[serde(deserialize_with = "deserialize_commitment_ciphertext")]
    pub ciphertext: [FixedBytes<32>; 4],
    #[serde(rename = "blindedSenderViewingKey")]
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_32")]
    pub blinded_sender_viewing_key: FixedBytes<32>,
    pub memo: Bytes,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IndexedShieldCommitment {
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_64")]
    pub id: FixedBytes<64>,
    #[serde(rename = "transactionHash")]
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_32")]
    pub transaction_hash: FixedBytes<32>,
    #[serde(rename = "blockNumber")]
    pub block_number: U256,
    #[serde(rename = "treeNumber")]
    pub tree_number: U256,
    #[serde(rename = "treePosition")]
    pub tree_position: U256,
    pub preimage: IndexedCommitmentPreimage,
    #[serde(rename = "shieldKey")]
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_32")]
    pub shield_key: FixedBytes<32>,
    #[serde(rename = "encryptedBundle")]
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_array_32_3")]
    pub encrypted_bundle: [FixedBytes<32>; 3],
}

impl IndexedShieldCommitment {
    #[must_use]
    pub fn preimage(&self) -> CommitmentPreimage {
        self.preimage.clone().into()
    }

    #[must_use]
    pub const fn shield_ciphertext(&self) -> ShieldCiphertext {
        ShieldCiphertext {
            encryptedBundle: self.encrypted_bundle,
            shieldKey: self.shield_key,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct IndexedCommitmentPreimage {
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_32")]
    pub npk: FixedBytes<32>,
    pub token: IndexedTokenData,
    pub value: U256,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IndexedLegacyCommitmentPreimage {
    pub npk: U256,
    pub token: IndexedTokenData,
    pub value: U256,
}

impl From<IndexedLegacyCommitmentPreimage> for LegacyCommitmentPreimage {
    fn from(value: IndexedLegacyCommitmentPreimage) -> Self {
        Self {
            npk: value.npk,
            token: value.token.into(),
            value: Uint::<120, 2>::from(value.value.to::<u128>()),
        }
    }
}

impl From<IndexedCommitmentPreimage> for CommitmentPreimage {
    fn from(value: IndexedCommitmentPreimage) -> Self {
        Self {
            npk: value.npk,
            token: value.token.into(),
            value: Uint::<120, 2>::from(value.value.to::<u128>()),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct IndexedTokenData {
    #[serde(rename = "tokenType", deserialize_with = "deserialize_token_type")]
    pub token_type: u8,
    #[serde(rename = "tokenAddress")]
    pub token_address: Address,
    #[serde(rename = "tokenSubID")]
    pub token_sub_id: U256,
}

#[derive(Debug, Deserialize)]
struct IndexedCiphertextPayload {
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_16")]
    iv: FixedBytes<16>,
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_16")]
    tag: FixedBytes<16>,
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_vec_32")]
    data: Vec<FixedBytes<32>>,
}

#[derive(Debug, Deserialize)]
struct IndexedEncryptedRandom(
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_32")] FixedBytes<32>,
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_16")] FixedBytes<16>,
);

#[derive(Debug, Deserialize)]
struct IndexedFixedBytes<const N: usize>(
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes")] FixedBytes<N>,
);

fn deserialize_indexed_fixed_bytes_16<'de, D>(deserializer: D) -> Result<FixedBytes<16>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_indexed_fixed_bytes(deserializer)
}

fn deserialize_indexed_fixed_bytes_32<'de, D>(deserializer: D) -> Result<FixedBytes<32>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_indexed_fixed_bytes(deserializer)
}

fn deserialize_indexed_fixed_bytes_36<'de, D>(deserializer: D) -> Result<FixedBytes<36>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_indexed_fixed_bytes(deserializer)
}

fn deserialize_indexed_fixed_bytes_64<'de, D>(deserializer: D) -> Result<FixedBytes<64>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_indexed_fixed_bytes(deserializer)
}

fn deserialize_indexed_fixed_bytes<'de, D, const N: usize>(
    deserializer: D,
) -> Result<FixedBytes<N>, D::Error>
where
    D: Deserializer<'de>,
{
    struct IndexedFixedBytesVisitor<const N: usize>;

    impl<const N: usize> Visitor<'_> for IndexedFixedBytesVisitor<N> {
        type Value = FixedBytes<N>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "0x-prefixed hex string up to {N} bytes")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            parse_left_padded_hex(value)
        }
    }

    deserializer.deserialize_str(IndexedFixedBytesVisitor::<N>)
}

fn parse_left_padded_hex<E, const N: usize>(value: &str) -> Result<FixedBytes<N>, E>
where
    E: de::Error,
{
    let hex = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .ok_or_else(|| E::custom("expected 0x-prefixed hex string"))?;
    let byte_len = hex.len().div_ceil(2);
    if byte_len > N {
        return Err(E::custom(format!(
            "expected at most {N} bytes, got {byte_len} bytes"
        )));
    }

    let mut bytes = [0_u8; N];
    let mut index = N - byte_len;
    let hex_bytes = hex.as_bytes();
    let offset = if hex_bytes.len() % 2 == 1 {
        bytes[index] = decode_hex_nibble(hex_bytes[0])?;
        index += 1;
        1
    } else {
        0
    };
    for pair in hex_bytes[offset..].chunks_exact(2) {
        let high = decode_hex_nibble(pair[0])?;
        let low = decode_hex_nibble(pair[1])?;
        bytes[index] = (high << 4) | low;
        index += 1;
    }

    Ok(FixedBytes::from(bytes))
}

fn decode_hex_nibble<E>(value: u8) -> Result<u8, E>
where
    E: de::Error,
{
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(E::custom(format!(
            "invalid hex character: {}",
            char::from(value)
        ))),
    }
}

fn deserialize_indexed_fixed_bytes_array<'de, D, const N: usize, const LEN: usize>(
    deserializer: D,
) -> Result<[FixedBytes<N>; LEN], D::Error>
where
    D: Deserializer<'de>,
{
    let values = Vec::<IndexedFixedBytes<N>>::deserialize(deserializer)?;
    let values = values.into_iter().map(|value| value.0).collect::<Vec<_>>();
    values.try_into().map_err(|values: Vec<_>| {
        de::Error::custom(format!(
            "expected {LEN} fixed byte values, got {}",
            values.len()
        ))
    })
}

fn deserialize_indexed_fixed_bytes_array_32_2<'de, D>(
    deserializer: D,
) -> Result<[FixedBytes<32>; 2], D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_indexed_fixed_bytes_array(deserializer)
}

fn deserialize_indexed_fixed_bytes_array_32_3<'de, D>(
    deserializer: D,
) -> Result<[FixedBytes<32>; 3], D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_indexed_fixed_bytes_array(deserializer)
}

fn deserialize_indexed_fixed_bytes_vec_32<'de, D>(
    deserializer: D,
) -> Result<Vec<FixedBytes<32>>, D::Error>
where
    D: Deserializer<'de>,
{
    let values = Vec::<IndexedFixedBytes<32>>::deserialize(deserializer)?;
    Ok(values.into_iter().map(|value| value.0).collect())
}

fn deserialize_indexed_encrypted_random<'de, D>(
    deserializer: D,
) -> Result<(FixedBytes<32>, FixedBytes<16>), D::Error>
where
    D: Deserializer<'de>,
{
    let encrypted_random = IndexedEncryptedRandom::deserialize(deserializer)?;
    Ok((encrypted_random.0, encrypted_random.1))
}

fn deserialize_commitment_ciphertext<'de, D>(
    deserializer: D,
) -> Result<[FixedBytes<32>; 4], D::Error>
where
    D: Deserializer<'de>,
{
    let payload = IndexedCiphertextPayload::deserialize(deserializer)?;
    let [first, second, third]: [FixedBytes<32>; 3] =
        payload.data.try_into().map_err(|data: Vec<_>| {
            de::Error::custom(format!(
                "expected 3 ciphertext data blocks, got {}",
                data.len()
            ))
        })?;
    let mut iv_tag = [0u8; 32];
    iv_tag[..16].copy_from_slice(&payload.iv.0);
    iv_tag[16..].copy_from_slice(&payload.tag.0);
    Ok([FixedBytes::from(iv_tag), first, second, third])
}

fn deserialize_token_type<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: Deserializer<'de>,
{
    struct TokenTypeVisitor;

    impl Visitor<'_> for TokenTypeVisitor {
        type Value = u8;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("RAILGUN token type enum or numeric token type")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            match value {
                "ERC20" => Ok(0),
                "ERC721" => Ok(1),
                "ERC1155" => Ok(2),
                other => other
                    .parse::<u8>()
                    .map_err(|_| E::custom(format!("unsupported indexed token type: {other}"))),
            }
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            u8::try_from(value).map_err(|_| E::custom(format!("token type out of range: {value}")))
        }
    }

    deserializer.deserialize_any(TokenTypeVisitor)
}

impl From<IndexedTokenData> for TokenData {
    fn from(value: IndexedTokenData) -> Self {
        Self {
            tokenType: value.token_type,
            tokenAddress: value.token_address,
            tokenSubID: value.token_sub_id,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct IndexedNullifier {
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_64")]
    pub id: FixedBytes<64>,
    #[serde(rename = "transactionHash")]
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_32")]
    pub transaction_hash: FixedBytes<32>,
    #[serde(rename = "blockNumber")]
    pub block_number: U256,
    #[serde(rename = "treeNumber")]
    pub tree_number: U256,
    pub nullifier: U256,
}
