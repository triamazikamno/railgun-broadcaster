use super::{Address, Deserialize, KEY_LEN, Serialize, U256, ViewingKeyData, WalletKeys, Zeroize};

#[derive(Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct WalletViewBundle {
    pub derivation_index: u32,
    pub spending_public_key: [[u8; KEY_LEN]; 2],
    pub viewing_private_key: [u8; KEY_LEN],
    pub viewing_public_key: [u8; KEY_LEN],
    pub nullifying_key: [u8; KEY_LEN],
    pub master_public_key: [u8; KEY_LEN],
}

impl WalletViewBundle {
    #[must_use]
    pub fn from_wallet_keys(derivation_index: u32, wallet: &WalletKeys) -> Self {
        Self {
            derivation_index,
            spending_public_key: wallet.spending_public_key.map(|value| value.to_be_bytes()),
            viewing_private_key: wallet.viewing.viewing_private_key,
            viewing_public_key: wallet.viewing.viewing_public_key,
            nullifying_key: wallet.viewing.nullifying_key.to_be_bytes(),
            master_public_key: wallet.viewing.master_public_key.to_be_bytes(),
        }
    }

    #[must_use]
    pub const fn scan_keys(&self) -> ViewingKeyData {
        ViewingKeyData {
            viewing_private_key: self.viewing_private_key,
            viewing_public_key: self.viewing_public_key,
            nullifying_key: U256::from_be_bytes(self.nullifying_key),
            master_public_key: U256::from_be_bytes(self.master_public_key),
        }
    }

    #[must_use]
    pub const fn spending_public_key(&self) -> [U256; 2] {
        [
            U256::from_be_bytes(self.spending_public_key[0]),
            U256::from_be_bytes(self.spending_public_key[1]),
        ]
    }
}

#[derive(Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct WalletSpendBundle {
    pub derivation_index: u32,
    pub bip39_language: String,
    pub bip39_entropy: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum WalletStatus {
    #[default]
    Active,
    Inactive,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum WalletSource {
    Generated,
    #[default]
    Imported,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletMetadataBundle {
    pub wallet_uuid: String,
    pub label: String,
    pub derivation_index: u32,
    #[serde(default)]
    pub source: WalletSource,
    #[serde(default)]
    pub status: WalletStatus,
    #[serde(default)]
    pub display_order: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PublicAccountSource {
    Derived,
    Imported,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PublicAccountScope {
    PrivateWallet { wallet_uuid: String },
    Global,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PublicAccountStatus {
    Active,
    #[serde(alias = "Hidden")]
    Inactive,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicAccountMetadata {
    pub public_account_uuid: String,
    pub address: Address,
    pub label: Option<String>,
    pub source: PublicAccountSource,
    pub scope: PublicAccountScope,
    pub derivation_index: Option<u32>,
    pub status: PublicAccountStatus,
    pub display_order: u32,
}

impl PublicAccountMetadata {
    #[must_use]
    pub fn is_active_for_wallet(&self, wallet_uuid: &str) -> bool {
        self.status == PublicAccountStatus::Active && self.is_scoped_to_wallet(wallet_uuid)
    }

    #[must_use]
    pub fn is_scoped_to_wallet(&self, wallet_uuid: &str) -> bool {
        match &self.scope {
            PublicAccountScope::PrivateWallet {
                wallet_uuid: scoped,
            } => scoped == wallet_uuid,
            PublicAccountScope::Global => true,
        }
    }

    #[must_use]
    pub const fn is_global(&self) -> bool {
        matches!(self.scope, PublicAccountScope::Global)
    }
}

#[derive(Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct PublicAccountSecret {
    pub private_key: [u8; KEY_LEN],
}

#[derive(Deserialize)]
pub(super) struct WalletMetadataWire {
    pub(super) wallet_uuid: String,
    pub(super) label: String,
    pub(super) derivation_index: u32,
    #[serde(default)]
    pub(super) source: Option<WalletSource>,
    #[serde(default)]
    pub(super) status: Option<WalletStatus>,
    #[serde(default)]
    pub(super) display_order: Option<u32>,
}

pub(super) struct DecodedWalletMetadata {
    pub(super) metadata: WalletMetadataBundle,
    pub(super) missing_lifecycle_fields: bool,
    pub(super) missing_display_order: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct WalletChainMetadataBundle {
    pub wallet_chain_uuid: String,
    pub wallet_uuid: String,
    pub chain_type: u8,
    pub chain_id: u64,
    pub contract: String,
    pub start_block: u64,
    pub last_scanned_block: u64,
    pub last_scanned_block_hash: Option<[u8; KEY_LEN]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poi_read_source: Option<String>,
}
