use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use alloy::primitives::{Address, U256};
use alloy::signers::k256::ecdsa::SigningKey;
use alloy::signers::local::{MnemonicBuilder, PrivateKeySigner};
use argon2::{Algorithm, Argon2, Params, Version};
use broadcaster_core::crypto::railgun::{RailgunError, ViewingKeyData};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use getrandom::fill;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit as HmacKeyInit, Mac};
use local_db::{DbConfig, DbStore, WalletMeta};
use railgun_wallet::keys::KeyError;
use railgun_wallet::wallet_cache::{
    WalletCacheError, deserialize_wallet_utxo, serialize_wallet_utxo, wallet_utxo_stable_identity,
};
use railgun_wallet::{
    RailgunSpendSigner, WalletKeys, WalletUtxo, bip39_entropy_from_mnemonic,
    bip39_mnemonic_from_entropy,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

mod core;
mod crypto;
mod models;
mod records;
mod store;
mod unlock;
mod view_cache;

pub use core::*;
pub use crypto::*;
pub use models::*;
pub use records::*;
pub use unlock::*;

#[cfg(test)]
mod tests;
