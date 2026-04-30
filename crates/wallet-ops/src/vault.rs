use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use getrandom::fill;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit as HmacKeyInit, Mac};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use broadcaster_core::crypto::railgun::{RailgunError, ViewingKeyData};
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

const VAULT_VERSION: u32 = 1;
const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const DEFAULT_MEMORY_COST_KIB: u32 = 64 * 1024;
const DEFAULT_TIME_COST: u32 = 3;
const DEFAULT_PARALLELISM: u32 = 1;
const VAULT_AAD_PREFIX: &[u8] = b"railgun-desktop-wallet-vault";
const VAULT_METADATA_KEY: &str = "vault|meta";
const WALLET_METADATA_PREFIX: &str = "wallet-meta|";
const WALLET_VIEW_PREFIX: &str = "wallet-view|";
const WALLET_SPEND_PREFIX: &str = "wallet-spend|";
const WALLET_CHAIN_METADATA_PREFIX: &str = "wallet-chain-meta|";
const WALLET_CACHE_ROW_PREFIX: &str = "wallet-cache-row|";
type HmacSha256 = Hmac<Sha256>;
type VaultRecordEntries = Vec<(String, Vec<u8>)>;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("random generation failed")]
    Random,
    #[error("invalid key derivation parameters")]
    InvalidKdfParams,
    #[error("key derivation failed")]
    Kdf,
    #[error("key separation failed")]
    KeySeparation,
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed")]
    Decrypt,
    #[error("encode failed: {0}")]
    Encode(#[from] rmp_serde::encode::Error),
    #[error("decode failed: {0}")]
    Decode(#[from] rmp_serde::decode::Error),
    #[error("db failed: {0}")]
    Db(#[from] local_db::DbError),
    #[error("io failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("wallet key failed: {0}")]
    Key(#[from] KeyError),
    #[error("unsupported vault version {0}")]
    UnsupportedVersion(u32),
    #[error("vault already exists")]
    VaultAlreadyExists,
    #[error("vault not found")]
    VaultNotFound,
    #[error("unlock failed")]
    UnlockFailed,
    #[error("spend grant is invalid")]
    InvalidSpendGrant,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    pub memory_cost_kib: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            memory_cost_kib: DEFAULT_MEMORY_COST_KIB,
            time_cost: DEFAULT_TIME_COST,
            parallelism: DEFAULT_PARALLELISM,
        }
    }
}

impl KdfParams {
    #[must_use]
    pub const fn new(memory_cost_kib: u32, time_cost: u32, parallelism: u32) -> Self {
        Self {
            memory_cost_kib,
            time_cost,
            parallelism,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedRecord {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultMetadata {
    pub version: u32,
    pub kdf: KdfParams,
    pub salt: [u8; SALT_LEN],
    pub wrapped_view_dek: EncryptedRecord,
    pub wrapped_spend_dek: EncryptedRecord,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordKind {
    ViewDek,
    SpendDek,
    WalletViewBundle,
    WalletSpendBundle,
    WalletMetadata,
    WalletChainMetadata,
    WalletCacheRow,
}

impl RecordKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ViewDek => "view-dek",
            Self::SpendDek => "spend-dek",
            Self::WalletViewBundle => "wallet-view-bundle",
            Self::WalletSpendBundle => "wallet-spend-bundle",
            Self::WalletMetadata => "wallet-metadata",
            Self::WalletChainMetadata => "wallet-chain-metadata",
            Self::WalletCacheRow => "wallet-cache-row",
        }
    }
}

pub struct SecretKey(Zeroizing<[u8; KEY_LEN]>);

impl SecretKey {
    fn random() -> Result<Self, VaultError> {
        let mut key = [0u8; KEY_LEN];
        fill(&mut key).map_err(|_| VaultError::Random)?;
        Ok(Self(Zeroizing::new(key)))
    }

    #[allow(clippy::needless_pass_by_value)]
    fn from_zeroizing_vec(bytes: Zeroizing<Vec<u8>>) -> Result<Self, VaultError> {
        if bytes.len() != KEY_LEN {
            return Err(VaultError::UnlockFailed);
        }
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(&bytes);
        Ok(Self(Zeroizing::new(key)))
    }

    #[must_use]
    pub fn expose_secret(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

pub struct CreatedVault {
    pub metadata: VaultMetadata,
    pub view: ViewUnlock,
    pub spend: SpendUnlock,
}

pub struct DesktopVaultStore {
    db: Arc<DbStore>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredWalletRecord {
    pub wallet_id: String,
    pub derivation_index: u32,
    pub view_record_key: String,
    pub spend_record_key: String,
}

pub struct GeneratedSeedMaterial {
    pub mnemonic: Zeroizing<String>,
    pub entropy: Zeroizing<Vec<u8>>,
}

pub struct DesktopViewSession {
    wallet_id: String,
    derivation_index: u32,
    scan_keys: ViewingKeyData,
    view: ViewUnlock,
}

pub struct SoftwareRailgunSpendSigner {
    wallet: WalletKeys,
}

pub struct DesktopEncryptedWalletCacheStore {
    db: Arc<DbStore>,
    view_session: Arc<DesktopViewSession>,
    metadata: Mutex<WalletChainMetadataBundle>,
    cache_keys: CacheKeys,
}

impl RailgunSpendSigner for SoftwareRailgunSpendSigner {
    fn spending_public_key(&self) -> [alloy::primitives::U256; 2] {
        self.wallet.spending_public_key()
    }

    fn sign_spend_message(&self, msg: alloy::primitives::U256) -> [alloy::primitives::U256; 3] {
        self.wallet.sign_spend_message(msg)
    }
}

impl Drop for SoftwareRailgunSpendSigner {
    fn drop(&mut self) {
        self.wallet.spending_private_key.zeroize();
        self.wallet.viewing.viewing_private_key.zeroize();
    }
}

impl DesktopVaultStore {
    pub fn open(db_path: PathBuf) -> Result<Self, VaultError> {
        let db = DbStore::open(DbConfig { root_dir: db_path })?;
        Ok(Self { db: Arc::new(db) })
    }

    #[must_use]
    pub const fn from_db(db: Arc<DbStore>) -> Self {
        Self { db }
    }

    #[must_use]
    pub fn db(&self) -> Arc<DbStore> {
        Arc::clone(&self.db)
    }

    pub fn create_vault(&self, password: &str) -> Result<CreatedVault, VaultError> {
        self.create_vault_with_params(password, KdfParams::default())
    }

    pub fn create_vault_with_params(
        &self,
        password: &str,
        kdf: KdfParams,
    ) -> Result<CreatedVault, VaultError> {
        let created = create_with_params(password, kdf)?;
        let data = rmp_serde::to_vec_named(&created.metadata)?;
        if !self
            .db
            .put_desktop_wallet_vault_record_if_absent(VAULT_METADATA_KEY, &data)?
        {
            return Err(VaultError::VaultAlreadyExists);
        }
        Ok(created)
    }

    pub fn metadata(&self) -> Result<VaultMetadata, VaultError> {
        let data = self
            .db
            .get_desktop_wallet_vault_record(VAULT_METADATA_KEY)?
            .ok_or(VaultError::VaultNotFound)?;
        Ok(rmp_serde::from_slice(&data)?)
    }

    pub fn vault_exists(&self) -> Result<bool, VaultError> {
        Ok(self
            .db
            .get_desktop_wallet_vault_record(VAULT_METADATA_KEY)?
            .is_some())
    }

    pub fn put_metadata(&self, metadata: &VaultMetadata) -> Result<(), VaultError> {
        let data = rmp_serde::to_vec_named(metadata)?;
        self.db
            .put_desktop_wallet_vault_record(VAULT_METADATA_KEY, &data)?;
        Ok(())
    }

    pub fn unlock_view(&self, password: &str) -> Result<ViewUnlock, VaultError> {
        let metadata = self.metadata()?;
        unlock_view(&metadata, password)
    }

    pub fn create_spend_grant(&self, password: &str) -> Result<SpendGrant, VaultError> {
        let metadata = self.metadata()?;
        create_spend_grant(&metadata, password)
    }

    pub fn store_wallet_from_entropy(
        &self,
        password: &str,
        wallet_id: &str,
        derivation_index: u32,
        bip39_language: impl Into<String>,
        entropy: &[u8],
    ) -> Result<StoredWalletRecord, VaultError> {
        let (stored, records) = self.encrypted_wallet_records_from_entropy(
            password,
            wallet_id,
            derivation_index,
            bip39_language.into(),
            entropy,
            None,
        )?;
        self.db.put_desktop_wallet_vault_records(&records)?;
        Ok(stored)
    }

    pub fn store_wallet_from_entropy_with_metadata(
        &self,
        password: &str,
        wallet_id: &str,
        derivation_index: u32,
        bip39_language: impl Into<String>,
        entropy: &[u8],
        metadata: &WalletMetadataBundle,
    ) -> Result<StoredWalletRecord, VaultError> {
        let (stored, records) = self.encrypted_wallet_records_from_entropy(
            password,
            wallet_id,
            derivation_index,
            bip39_language.into(),
            entropy,
            Some(metadata),
        )?;
        self.db.put_desktop_wallet_vault_records(&records)?;
        Ok(stored)
    }

    pub fn store_generated_wallet(
        &self,
        password: &str,
        wallet_id: &str,
        derivation_index: u32,
        bip39_language: impl Into<String>,
        seed: &GeneratedSeedMaterial,
    ) -> Result<StoredWalletRecord, VaultError> {
        self.store_wallet_from_entropy(
            password,
            wallet_id,
            derivation_index,
            bip39_language,
            &seed.entropy,
        )
    }

    pub fn store_generated_wallet_with_metadata(
        &self,
        password: &str,
        wallet_id: &str,
        derivation_index: u32,
        bip39_language: impl Into<String>,
        seed: &GeneratedSeedMaterial,
        metadata: &WalletMetadataBundle,
    ) -> Result<StoredWalletRecord, VaultError> {
        self.store_wallet_from_entropy_with_metadata(
            password,
            wallet_id,
            derivation_index,
            bip39_language,
            &seed.entropy,
            metadata,
        )
    }

    pub fn import_wallet_mnemonic(
        &self,
        password: &str,
        wallet_id: &str,
        derivation_index: u32,
        bip39_language: impl Into<String>,
        mnemonic: &str,
    ) -> Result<StoredWalletRecord, VaultError> {
        let entropy = Zeroizing::new(bip39_entropy_from_mnemonic(mnemonic)?);
        self.store_wallet_from_entropy(
            password,
            wallet_id,
            derivation_index,
            bip39_language,
            &entropy,
        )
    }

    pub fn import_wallet_mnemonic_with_metadata(
        &self,
        password: &str,
        wallet_id: &str,
        derivation_index: u32,
        bip39_language: impl Into<String>,
        mnemonic: &str,
        metadata: &WalletMetadataBundle,
    ) -> Result<StoredWalletRecord, VaultError> {
        let entropy = Zeroizing::new(bip39_entropy_from_mnemonic(mnemonic)?);
        self.store_wallet_from_entropy_with_metadata(
            password,
            wallet_id,
            derivation_index,
            bip39_language,
            &entropy,
            metadata,
        )
    }

    pub fn load_view_bundle(
        &self,
        password: &str,
        wallet_id: &str,
    ) -> Result<WalletViewBundle, VaultError> {
        let view = self.unlock_view(password)?;
        let record = self.encrypted_record(&wallet_view_record_key(wallet_id))?;
        view.decrypt_view_bundle(wallet_id, &record)
    }

    pub fn list_wallet_ids(&self) -> Result<Vec<String>, VaultError> {
        let records = self
            .db
            .list_desktop_wallet_vault_records(WALLET_VIEW_PREFIX)?;
        Ok(records
            .into_iter()
            .filter_map(|record| {
                record
                    .key
                    .strip_prefix(WALLET_VIEW_PREFIX)
                    .map(str::to_owned)
            })
            .collect())
    }

    pub fn load_view_session(
        &self,
        password: &str,
        wallet_id: &str,
    ) -> Result<DesktopViewSession, VaultError> {
        let view = self.unlock_view(password)?;
        let record = self.encrypted_record(&wallet_view_record_key(wallet_id))?;
        let bundle = view.decrypt_view_bundle(wallet_id, &record)?;
        Ok(DesktopViewSession::from_bundle(
            wallet_id.to_owned(),
            &bundle,
            view,
        ))
    }

    pub fn unlock_first_view_session(
        &self,
        password: &str,
    ) -> Result<Option<DesktopViewSession>, VaultError> {
        let view = self.unlock_view(password)?;
        let Some(wallet_id) = self.list_wallet_ids()?.into_iter().next() else {
            return Ok(None);
        };
        let record = self.encrypted_record(&wallet_view_record_key(&wallet_id))?;
        let bundle = view.decrypt_view_bundle(&wallet_id, &record)?;
        Ok(Some(DesktopViewSession::from_bundle(
            wallet_id, &bundle, view,
        )))
    }

    pub fn load_spend_bundle(
        &self,
        grant: &mut SpendGrant,
        wallet_id: &str,
    ) -> Result<WalletSpendBundle, VaultError> {
        let record = self.encrypted_record(&wallet_spend_record_key(wallet_id))?;
        grant
            .take_spend_unlock()?
            .decrypt_spend_bundle(wallet_id, &record)
    }

    pub fn railgun_spend_signer(
        &self,
        grant: &mut SpendGrant,
        wallet_id: &str,
    ) -> Result<SoftwareRailgunSpendSigner, VaultError> {
        let bundle = self.load_spend_bundle(grant, wallet_id)?;
        let wallet =
            WalletKeys::from_bip39_entropy(&bundle.bip39_entropy, bundle.derivation_index)?;
        Ok(SoftwareRailgunSpendSigner { wallet })
    }

    pub fn store_wallet_metadata(
        &self,
        password: &str,
        metadata: &WalletMetadataBundle,
    ) -> Result<(), VaultError> {
        let view = self.unlock_view(password)?;
        let record = view.encrypt_wallet_metadata(&metadata.wallet_uuid, metadata)?;
        self.put_encrypted_record(&wallet_metadata_record_key(&metadata.wallet_uuid), &record)
    }

    pub fn load_wallet_metadata(
        &self,
        password: &str,
        wallet_uuid: &str,
    ) -> Result<WalletMetadataBundle, VaultError> {
        let view = self.unlock_view(password)?;
        let record = self.encrypted_record(&wallet_metadata_record_key(wallet_uuid))?;
        view.decrypt_wallet_metadata(wallet_uuid, &record)
    }

    pub fn store_wallet_chain_metadata(
        &self,
        password: &str,
        metadata: &WalletChainMetadataBundle,
    ) -> Result<(), VaultError> {
        let view = self.unlock_view(password)?;
        let record = view.encrypt_wallet_chain_metadata(&metadata.wallet_chain_uuid, metadata)?;
        self.put_encrypted_record(
            &wallet_chain_metadata_record_key(&metadata.wallet_chain_uuid),
            &record,
        )
    }

    pub fn load_wallet_chain_metadata(
        &self,
        password: &str,
        wallet_chain_uuid: &str,
    ) -> Result<WalletChainMetadataBundle, VaultError> {
        let view = self.unlock_view(password)?;
        let record = self.encrypted_record(&wallet_chain_metadata_record_key(wallet_chain_uuid))?;
        view.decrypt_wallet_chain_metadata(wallet_chain_uuid, &record)
    }

    pub fn wallet_chain_metadata_for_session(
        &self,
        view_session: &DesktopViewSession,
        chain_type: u8,
        chain_id: u64,
        contract: &str,
        start_block: u64,
    ) -> Result<WalletChainMetadataBundle, VaultError> {
        let records = self
            .db
            .list_desktop_wallet_vault_records(WALLET_CHAIN_METADATA_PREFIX)?;
        for stored in records {
            let Some(wallet_chain_uuid) = stored.key.strip_prefix(WALLET_CHAIN_METADATA_PREFIX)
            else {
                continue;
            };
            let record: EncryptedRecord = rmp_serde::from_slice(&stored.payload)?;
            let metadata =
                view_session.decrypt_wallet_chain_metadata(wallet_chain_uuid, &record)?;
            if metadata.wallet_uuid == view_session.wallet_id()
                && metadata.chain_type == chain_type
                && metadata.chain_id == chain_id
                && metadata.contract.eq_ignore_ascii_case(contract)
            {
                return Ok(metadata);
            }
        }

        let wallet_chain_uuid = generate_opaque_id()?;
        let metadata = WalletChainMetadataBundle {
            wallet_chain_uuid,
            wallet_uuid: view_session.wallet_id().to_owned(),
            chain_type,
            chain_id,
            contract: contract.to_owned(),
            start_block,
            last_scanned_block: start_block.saturating_sub(1),
            last_scanned_block_hash: None,
        };
        self.store_wallet_chain_metadata_with_session(view_session, &metadata)?;
        Ok(metadata)
    }

    pub fn store_wallet_chain_metadata_with_session(
        &self,
        view_session: &DesktopViewSession,
        metadata: &WalletChainMetadataBundle,
    ) -> Result<(), VaultError> {
        let record =
            view_session.encrypt_wallet_chain_metadata(&metadata.wallet_chain_uuid, metadata)?;
        self.put_encrypted_record(
            &wallet_chain_metadata_record_key(&metadata.wallet_chain_uuid),
            &record,
        )
    }

    pub fn reset_wallet_chain_cache_with_session(
        &self,
        view_session: &DesktopViewSession,
        metadata: &mut WalletChainMetadataBundle,
        start_block: u64,
    ) -> Result<(), VaultError> {
        metadata.last_scanned_block = start_block.saturating_sub(1);
        metadata.last_scanned_block_hash = None;
        let record =
            view_session.encrypt_wallet_chain_metadata(&metadata.wallet_chain_uuid, metadata)?;
        let data = rmp_serde::to_vec_named(&record)?;
        self.db.replace_desktop_wallet_vault_prefix_with_records(
            &wallet_cache_row_prefix(&metadata.wallet_chain_uuid),
            &[(
                wallet_chain_metadata_record_key(&metadata.wallet_chain_uuid),
                data,
            )],
        )?;
        Ok(())
    }

    pub fn rewind_wallet_chain_cache_with_session(
        &self,
        view_session: &DesktopViewSession,
        metadata: &mut WalletChainMetadataBundle,
        start_block: u64,
    ) -> Result<(), VaultError> {
        let cache_keys = view_session.derive_cache_keys(&metadata.wallet_chain_uuid)?;
        let row_prefix = wallet_cache_row_prefix(&metadata.wallet_chain_uuid);
        let existing_rows = self.db.list_desktop_wallet_vault_records(&row_prefix)?;
        let mut records = Vec::with_capacity(existing_rows.len() + 1);
        let mut dropped_rows = 0usize;
        let mut cleared_spent_rows = 0usize;
        let mut invalid_rows = 0usize;

        for stored in existing_rows {
            let Some(row_id_hex) = stored.key.strip_prefix(&row_prefix) else {
                invalid_rows += 1;
                continue;
            };
            let Ok(row_id_bytes) = alloy::hex::decode(row_id_hex) else {
                invalid_rows += 1;
                continue;
            };
            let Ok(row_id) = row_id_bytes.try_into() else {
                invalid_rows += 1;
                continue;
            };
            let record: EncryptedRecord = rmp_serde::from_slice(&stored.payload)?;
            let plaintext = cache_keys
                .decrypt_row(&row_id, &record)
                .map_err(|_| VaultError::Decrypt)?;
            let mut utxo =
                deserialize_wallet_utxo(&plaintext).map_err(vault_error_from_wallet_cache)?;
            if utxo.utxo.source.block_number >= start_block {
                dropped_rows += 1;
                continue;
            }
            if utxo
                .spent
                .as_ref()
                .is_some_and(|spent| spent.block_number >= start_block)
            {
                utxo.spent = None;
                cleared_spent_rows += 1;
            }

            let stable_identity = wallet_utxo_stable_identity(&utxo);
            let expected_row_id =
                cache_keys.row_id(utxo.utxo.tree, utxo.utxo.position, &stable_identity);
            if expected_row_id != row_id {
                invalid_rows += 1;
                continue;
            }

            let plaintext = serialize_wallet_utxo(&utxo).map_err(vault_error_from_wallet_cache)?;
            let record = cache_keys
                .encrypt_row(&row_id, &plaintext)
                .map_err(|_| VaultError::Encrypt)?;
            let data = rmp_serde::to_vec_named(&record)?;
            records.push((
                wallet_cache_row_record_key(&metadata.wallet_chain_uuid, &row_id),
                data,
            ));
        }

        metadata.last_scanned_block = start_block.saturating_sub(1);
        metadata.last_scanned_block_hash = None;
        let record =
            view_session.encrypt_wallet_chain_metadata(&metadata.wallet_chain_uuid, metadata)?;
        let data = rmp_serde::to_vec_named(&record)?;
        records.push((
            wallet_chain_metadata_record_key(&metadata.wallet_chain_uuid),
            data,
        ));
        self.db
            .replace_desktop_wallet_vault_prefix_with_records(&row_prefix, &records)?;
        tracing::info!(
            wallet_chain_uuid = %metadata.wallet_chain_uuid,
            start_block,
            retained_rows = records.len().saturating_sub(1),
            dropped_rows,
            cleared_spent_rows,
            invalid_rows,
            "rewound encrypted desktop wallet cache"
        );
        Ok(())
    }

    fn encrypted_record(&self, key: &str) -> Result<EncryptedRecord, VaultError> {
        let data = self
            .db
            .get_desktop_wallet_vault_record(key)?
            .ok_or(VaultError::VaultNotFound)?;
        Ok(rmp_serde::from_slice(&data)?)
    }

    fn put_encrypted_record(&self, key: &str, record: &EncryptedRecord) -> Result<(), VaultError> {
        let (_, data) = encrypted_record_entry(key.to_string(), record)?;
        self.db.put_desktop_wallet_vault_record(key, &data)?;
        Ok(())
    }

    fn encrypted_wallet_records_from_entropy(
        &self,
        password: &str,
        wallet_id: &str,
        derivation_index: u32,
        bip39_language: String,
        entropy: &[u8],
        metadata: Option<&WalletMetadataBundle>,
    ) -> Result<(StoredWalletRecord, VaultRecordEntries), VaultError> {
        let vault_metadata = self.metadata()?;
        let view = unlock_view(&vault_metadata, password)?;
        let spend = unlock_spend(&vault_metadata, password)?;
        let wallet = WalletKeys::from_bip39_entropy(entropy, derivation_index)?;
        let view_bundle = WalletViewBundle::from_wallet_keys(derivation_index, &wallet);
        let spend_bundle = WalletSpendBundle {
            derivation_index,
            bip39_language,
            bip39_entropy: entropy.to_vec(),
        };

        let view_record = view.encrypt_view_bundle(wallet_id, &view_bundle)?;
        let spend_record = spend.encrypt_spend_bundle(wallet_id, &spend_bundle)?;
        let view_record_key = wallet_view_record_key(wallet_id);
        let spend_record_key = wallet_spend_record_key(wallet_id);
        let mut records = Vec::with_capacity(2 + usize::from(metadata.is_some()));
        records.push(encrypted_record_entry(
            view_record_key.clone(),
            &view_record,
        )?);
        records.push(encrypted_record_entry(
            spend_record_key.clone(),
            &spend_record,
        )?);

        if let Some(metadata) = metadata {
            let record = view.encrypt_wallet_metadata(&metadata.wallet_uuid, metadata)?;
            records.push(encrypted_record_entry(
                wallet_metadata_record_key(&metadata.wallet_uuid),
                &record,
            )?);
        }

        Ok((
            StoredWalletRecord {
                wallet_id: wallet_id.to_string(),
                derivation_index,
                view_record_key,
                spend_record_key,
            },
            records,
        ))
    }
}

fn encrypted_record_entry(
    key: String,
    record: &EncryptedRecord,
) -> Result<(String, Vec<u8>), VaultError> {
    Ok((key, rmp_serde::to_vec_named(record)?))
}

impl DesktopViewSession {
    #[must_use]
    pub const fn from_bundle(
        wallet_id: String,
        bundle: &WalletViewBundle,
        view: ViewUnlock,
    ) -> Self {
        Self {
            wallet_id,
            derivation_index: bundle.derivation_index,
            scan_keys: bundle.scan_keys(),
            view,
        }
    }

    #[must_use]
    pub fn wallet_id(&self) -> &str {
        &self.wallet_id
    }

    #[must_use]
    pub const fn derivation_index(&self) -> u32 {
        self.derivation_index
    }

    #[must_use]
    pub const fn scan_keys(&self) -> ViewingKeyData {
        self.scan_keys
    }

    pub fn receive_address(&self) -> Result<String, RailgunError> {
        Ok(self.scan_keys.derive_address(None)?.to_string())
    }

    pub fn encrypt_wallet_chain_metadata(
        &self,
        wallet_chain_uuid: &str,
        metadata: &WalletChainMetadataBundle,
    ) -> Result<EncryptedRecord, VaultError> {
        self.view
            .encrypt_wallet_chain_metadata(wallet_chain_uuid, metadata)
    }

    pub fn decrypt_wallet_chain_metadata(
        &self,
        wallet_chain_uuid: &str,
        record: &EncryptedRecord,
    ) -> Result<WalletChainMetadataBundle, VaultError> {
        self.view
            .decrypt_wallet_chain_metadata(wallet_chain_uuid, record)
    }

    pub fn derive_cache_keys(&self, wallet_chain_uuid: &str) -> Result<CacheKeys, VaultError> {
        self.view.derive_cache_keys(wallet_chain_uuid)
    }
}

impl DesktopEncryptedWalletCacheStore {
    pub fn new(
        db: Arc<DbStore>,
        view_session: Arc<DesktopViewSession>,
        metadata: WalletChainMetadataBundle,
    ) -> Result<Self, VaultError> {
        let cache_keys = view_session.derive_cache_keys(&metadata.wallet_chain_uuid)?;
        Ok(Self {
            db,
            view_session,
            metadata: Mutex::new(metadata),
            cache_keys,
        })
    }

    fn wallet_chain_uuid(&self) -> Result<String, WalletCacheError> {
        Ok(self
            .metadata
            .lock()
            .map_err(|_| WalletCacheError::Crypto)?
            .wallet_chain_uuid
            .clone())
    }
}

impl sync_service::WalletCacheStore for DesktopEncryptedWalletCacheStore {
    fn store_wallet_utxos(
        &self,
        _wallet_id: &str,
        utxos: &[WalletUtxo],
        last_scanned_block: Option<u64>,
        last_scanned_block_hash: Option<[u8; KEY_LEN]>,
    ) -> Result<(), WalletCacheError> {
        let wallet_chain_uuid = self.wallet_chain_uuid()?;
        let mut records =
            Vec::with_capacity(utxos.len() + usize::from(last_scanned_block.is_some()));

        for utxo in utxos {
            let stable_identity = wallet_utxo_stable_identity(utxo);
            let row_id =
                self.cache_keys
                    .row_id(utxo.utxo.tree, utxo.utxo.position, &stable_identity);
            let plaintext = serialize_wallet_utxo(utxo)?;
            let record = self
                .cache_keys
                .encrypt_row(&row_id, &plaintext)
                .map_err(|_| WalletCacheError::Crypto)?;
            let data = rmp_serde::to_vec_named(&record)?;
            records.push((
                wallet_cache_row_record_key(&wallet_chain_uuid, &row_id),
                data,
            ));
        }

        let (unspent, spent) = wallet_cache_counts(utxos);
        if let Some(last_scanned_block) = last_scanned_block {
            let mut metadata = self.metadata.lock().map_err(|_| WalletCacheError::Crypto)?;
            metadata.last_scanned_block = last_scanned_block;
            metadata.last_scanned_block_hash = last_scanned_block_hash;
            let record = self
                .view_session
                .encrypt_wallet_chain_metadata(&metadata.wallet_chain_uuid, &metadata)
                .map_err(|_| WalletCacheError::Crypto)?;
            let data = rmp_serde::to_vec_named(&record)?;
            records.push((
                wallet_chain_metadata_record_key(&metadata.wallet_chain_uuid),
                data,
            ));
        }

        self.db.put_desktop_wallet_vault_records(&records)?;
        tracing::debug!(
            wallet_chain_uuid,
            rows = utxos.len(),
            unspent,
            spent,
            last_scanned_block,
            "upserted encrypted desktop wallet cache"
        );

        Ok(())
    }

    fn load_wallet_utxos(&self, _wallet_id: &str) -> Result<Vec<WalletUtxo>, WalletCacheError> {
        let wallet_chain_uuid = self.wallet_chain_uuid()?;
        let row_prefix = wallet_cache_row_prefix(&wallet_chain_uuid);
        let records = self.db.list_desktop_wallet_vault_records(&row_prefix)?;
        let mut out = Vec::with_capacity(records.len());
        for stored in records {
            let Some(row_id_hex) = stored.key.strip_prefix(&row_prefix) else {
                continue;
            };
            let row_id_bytes =
                alloy::hex::decode(row_id_hex).map_err(|_| WalletCacheError::Crypto)?;
            let row_id: [u8; KEY_LEN] = row_id_bytes
                .try_into()
                .map_err(|_| WalletCacheError::Crypto)?;
            let record: EncryptedRecord = rmp_serde::from_slice(&stored.payload)?;
            let plaintext = self
                .cache_keys
                .decrypt_row(&row_id, &record)
                .map_err(|_| WalletCacheError::Crypto)?;
            out.push(deserialize_wallet_utxo(&plaintext)?);
        }
        let (unspent, spent) = wallet_cache_counts(&out);
        tracing::debug!(
            wallet_chain_uuid,
            rows = out.len(),
            unspent,
            spent,
            "loaded encrypted desktop wallet cache"
        );
        Ok(out)
    }

    fn get_wallet_meta(&self, _wallet_id: &str) -> Result<Option<WalletMeta>, WalletCacheError> {
        let metadata = self.metadata.lock().map_err(|_| WalletCacheError::Crypto)?;
        Ok(Some(WalletMeta {
            last_scanned_block: metadata.last_scanned_block,
            updated_at: 0,
            last_scanned_block_hash: metadata.last_scanned_block_hash,
        }))
    }

    fn update_wallet_meta(
        &self,
        _wallet_id: &str,
        last_scanned_block: u64,
        last_scanned_block_hash: Option<[u8; KEY_LEN]>,
    ) -> Result<(), WalletCacheError> {
        let mut metadata = self.metadata.lock().map_err(|_| WalletCacheError::Crypto)?;
        metadata.last_scanned_block = last_scanned_block;
        metadata.last_scanned_block_hash = last_scanned_block_hash;
        let record = self
            .view_session
            .encrypt_wallet_chain_metadata(&metadata.wallet_chain_uuid, &metadata)
            .map_err(|_| WalletCacheError::Crypto)?;
        let data = rmp_serde::to_vec_named(&record)?;
        self.db.put_desktop_wallet_vault_records(&[(
            wallet_chain_metadata_record_key(&metadata.wallet_chain_uuid),
            data,
        )])?;
        tracing::debug!(
            wallet_chain_uuid = %metadata.wallet_chain_uuid,
            last_scanned_block,
            "updated encrypted desktop wallet cache metadata"
        );
        Ok(())
    }

    fn reset_wallet_cache(
        &self,
        _wallet_id: &str,
        last_scanned_block: u64,
    ) -> Result<(), WalletCacheError> {
        let mut metadata = self.metadata.lock().map_err(|_| WalletCacheError::Crypto)?;
        metadata.last_scanned_block = last_scanned_block;
        metadata.last_scanned_block_hash = None;
        let record = self
            .view_session
            .encrypt_wallet_chain_metadata(&metadata.wallet_chain_uuid, &metadata)
            .map_err(|_| WalletCacheError::Crypto)?;
        let data = rmp_serde::to_vec_named(&record)?;
        self.db.replace_desktop_wallet_vault_prefix_with_records(
            &wallet_cache_row_prefix(&metadata.wallet_chain_uuid),
            &[(
                wallet_chain_metadata_record_key(&metadata.wallet_chain_uuid),
                data,
            )],
        )?;
        Ok(())
    }
}

pub struct ViewUnlock {
    view_dek: SecretKey,
}

impl ViewUnlock {
    #[must_use]
    pub const fn view_dek(&self) -> &SecretKey {
        &self.view_dek
    }

    pub fn encrypt_record(
        &self,
        kind: RecordKind,
        record_id: &str,
        plaintext: &[u8],
    ) -> Result<EncryptedRecord, VaultError> {
        encrypt_payload(&self.view_dek, kind, record_id, plaintext)
    }

    pub fn decrypt_record(
        &self,
        kind: RecordKind,
        record_id: &str,
        record: &EncryptedRecord,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        decrypt_payload(&self.view_dek, kind, record_id, record)
    }

    pub fn encrypt_view_bundle(
        &self,
        wallet_id: &str,
        bundle: &WalletViewBundle,
    ) -> Result<EncryptedRecord, VaultError> {
        encrypt_serialized(
            &self.view_dek,
            RecordKind::WalletViewBundle,
            wallet_id,
            bundle,
        )
    }

    pub fn decrypt_view_bundle(
        &self,
        wallet_id: &str,
        record: &EncryptedRecord,
    ) -> Result<WalletViewBundle, VaultError> {
        decrypt_serialized(
            &self.view_dek,
            RecordKind::WalletViewBundle,
            wallet_id,
            record,
        )
    }

    pub fn encrypt_wallet_metadata(
        &self,
        wallet_uuid: &str,
        metadata: &WalletMetadataBundle,
    ) -> Result<EncryptedRecord, VaultError> {
        encrypt_serialized(
            &self.view_dek,
            RecordKind::WalletMetadata,
            wallet_uuid,
            metadata,
        )
    }

    pub fn decrypt_wallet_metadata(
        &self,
        wallet_uuid: &str,
        record: &EncryptedRecord,
    ) -> Result<WalletMetadataBundle, VaultError> {
        decrypt_serialized(
            &self.view_dek,
            RecordKind::WalletMetadata,
            wallet_uuid,
            record,
        )
    }

    pub fn encrypt_wallet_chain_metadata(
        &self,
        wallet_chain_uuid: &str,
        metadata: &WalletChainMetadataBundle,
    ) -> Result<EncryptedRecord, VaultError> {
        encrypt_serialized(
            &self.view_dek,
            RecordKind::WalletChainMetadata,
            wallet_chain_uuid,
            metadata,
        )
    }

    pub fn decrypt_wallet_chain_metadata(
        &self,
        wallet_chain_uuid: &str,
        record: &EncryptedRecord,
    ) -> Result<WalletChainMetadataBundle, VaultError> {
        decrypt_serialized(
            &self.view_dek,
            RecordKind::WalletChainMetadata,
            wallet_chain_uuid,
            record,
        )
    }

    pub fn derive_cache_keys(&self, wallet_chain_uuid: &str) -> Result<CacheKeys, VaultError> {
        Ok(CacheKeys {
            index: derive_context_key(
                &self.view_dek,
                b"cache-index",
                wallet_chain_uuid.as_bytes(),
            )?,
            data: derive_context_key(&self.view_dek, b"cache-data", wallet_chain_uuid.as_bytes())?,
        })
    }
}

pub struct SpendUnlock {
    spend_dek: SecretKey,
}

impl SpendUnlock {
    #[must_use]
    pub const fn spend_dek(&self) -> &SecretKey {
        &self.spend_dek
    }

    pub fn encrypt_record(
        &self,
        kind: RecordKind,
        record_id: &str,
        plaintext: &[u8],
    ) -> Result<EncryptedRecord, VaultError> {
        encrypt_payload(&self.spend_dek, kind, record_id, plaintext)
    }

    pub fn decrypt_record(
        &self,
        kind: RecordKind,
        record_id: &str,
        record: &EncryptedRecord,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        decrypt_payload(&self.spend_dek, kind, record_id, record)
    }

    pub fn encrypt_spend_bundle(
        &self,
        wallet_id: &str,
        bundle: &WalletSpendBundle,
    ) -> Result<EncryptedRecord, VaultError> {
        encrypt_serialized(
            &self.spend_dek,
            RecordKind::WalletSpendBundle,
            wallet_id,
            bundle,
        )
    }

    pub fn decrypt_spend_bundle(
        &self,
        wallet_id: &str,
        record: &EncryptedRecord,
    ) -> Result<WalletSpendBundle, VaultError> {
        decrypt_serialized(
            &self.spend_dek,
            RecordKind::WalletSpendBundle,
            wallet_id,
            record,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpendGrantPolicy {
    OneUse,
}

pub struct SpendGrant {
    policy: SpendGrantPolicy,
    spend: Option<SpendUnlock>,
}

pub struct CacheKeys {
    index: SecretKey,
    data: SecretKey,
}

impl CacheKeys {
    /// # Panics
    ///
    /// Panics only if HMAC rejects a fixed-size SHA-256 key, which should be
    /// unreachable for the selected MAC implementation.
    #[must_use]
    pub fn row_id(&self, tree: u32, position: u64, stable_utxo_identity: &[u8]) -> [u8; KEY_LEN] {
        let mut mac = HmacSha256::new_from_slice(self.index.expose_secret())
            .expect("HMAC accepts any key length");
        mac.update(b"wallet-cache-row:v1");
        mac.update(&tree.to_be_bytes());
        mac.update(&position.to_be_bytes());
        mac.update(stable_utxo_identity);
        mac.finalize().into_bytes().into()
    }

    #[must_use]
    pub fn row_record_id(row_id: &[u8; KEY_LEN]) -> String {
        alloy::hex::encode(row_id)
    }

    pub fn encrypt_row(
        &self,
        row_id: &[u8; KEY_LEN],
        plaintext: &[u8],
    ) -> Result<EncryptedRecord, VaultError> {
        let record_id = Self::row_record_id(row_id);
        encrypt_payload(
            &self.data,
            RecordKind::WalletCacheRow,
            &record_id,
            plaintext,
        )
    }

    pub fn decrypt_row(
        &self,
        row_id: &[u8; KEY_LEN],
        record: &EncryptedRecord,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let record_id = Self::row_record_id(row_id);
        decrypt_payload(&self.data, RecordKind::WalletCacheRow, &record_id, record)
    }
}

impl SpendGrant {
    #[must_use]
    pub const fn one_use(spend: SpendUnlock) -> Self {
        Self {
            policy: SpendGrantPolicy::OneUse,
            spend: Some(spend),
        }
    }

    #[must_use]
    pub const fn policy(&self) -> SpendGrantPolicy {
        self.policy
    }

    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.spend.is_some()
    }

    pub fn spend_unlock(&self) -> Result<&SpendUnlock, VaultError> {
        self.spend.as_ref().ok_or(VaultError::InvalidSpendGrant)
    }

    pub fn take_spend_unlock(&mut self) -> Result<SpendUnlock, VaultError> {
        self.spend.take().ok_or(VaultError::InvalidSpendGrant)
    }

    pub fn invalidate(&mut self) {
        self.spend.take();
    }
}

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
            nullifying_key: alloy::primitives::U256::from_be_bytes(self.nullifying_key),
            master_public_key: alloy::primitives::U256::from_be_bytes(self.master_public_key),
        }
    }
}

#[derive(Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct WalletSpendBundle {
    pub derivation_index: u32,
    pub bip39_language: String,
    pub bip39_entropy: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct WalletMetadataBundle {
    pub wallet_uuid: String,
    pub label: String,
    pub derivation_index: u32,
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
}

#[must_use]
pub const fn current_vault_version() -> u32 {
    VAULT_VERSION
}

pub fn create(password: &str) -> Result<CreatedVault, VaultError> {
    create_with_params(password, KdfParams::default())
}

pub fn create_with_params(password: &str, kdf: KdfParams) -> Result<CreatedVault, VaultError> {
    let mut salt = [0u8; SALT_LEN];
    fill(&mut salt).map_err(|_| VaultError::Random)?;

    let root_key = derive_root_key(password.as_bytes(), &salt, kdf)?;
    let wrapping_keys = derive_wrapping_keys(&root_key)?;
    let view_dek = SecretKey::random()?;
    let spend_dek = SecretKey::random()?;

    let wrapped_view_dek = encrypt_payload(
        &wrapping_keys.view,
        RecordKind::ViewDek,
        "vault",
        view_dek.expose_secret(),
    )?;
    let wrapped_spend_dek = encrypt_payload(
        &wrapping_keys.spend,
        RecordKind::SpendDek,
        "vault",
        spend_dek.expose_secret(),
    )?;
    let metadata = VaultMetadata {
        version: VAULT_VERSION,
        kdf,
        salt,
        wrapped_view_dek,
        wrapped_spend_dek,
    };

    Ok(CreatedVault {
        metadata,
        view: ViewUnlock { view_dek },
        spend: SpendUnlock { spend_dek },
    })
}

pub fn unlock_view(metadata: &VaultMetadata, password: &str) -> Result<ViewUnlock, VaultError> {
    validate_version(metadata.version)?;
    let root_key = derive_root_key_for_unlock(password.as_bytes(), &metadata.salt, metadata.kdf)?;
    let wrapping_keys = derive_wrapping_keys_for_unlock(&root_key)?;
    let view_dek = decrypt_wrapped_key(
        &wrapping_keys.view,
        RecordKind::ViewDek,
        &metadata.wrapped_view_dek,
    )?;
    Ok(ViewUnlock { view_dek })
}

pub fn unlock_spend(metadata: &VaultMetadata, password: &str) -> Result<SpendUnlock, VaultError> {
    validate_version(metadata.version)?;
    let root_key = derive_root_key_for_unlock(password.as_bytes(), &metadata.salt, metadata.kdf)?;
    let wrapping_keys = derive_wrapping_keys_for_unlock(&root_key)?;
    let spend_dek = decrypt_wrapped_key(
        &wrapping_keys.spend,
        RecordKind::SpendDek,
        &metadata.wrapped_spend_dek,
    )?;
    Ok(SpendUnlock { spend_dek })
}

pub fn create_spend_grant(
    metadata: &VaultMetadata,
    password: &str,
) -> Result<SpendGrant, VaultError> {
    unlock_spend(metadata, password).map(SpendGrant::one_use)
}

pub fn generate_seed_material() -> Result<GeneratedSeedMaterial, VaultError> {
    let mut entropy = vec![0u8; 32];
    fill(&mut entropy).map_err(|_| VaultError::Random)?;
    let mnemonic = bip39_mnemonic_from_entropy(&entropy)?;
    Ok(GeneratedSeedMaterial {
        mnemonic: Zeroizing::new(mnemonic),
        entropy: Zeroizing::new(entropy),
    })
}

pub fn generate_opaque_id() -> Result<String, VaultError> {
    let mut bytes = [0u8; 16];
    fill(&mut bytes).map_err(|_| VaultError::Random)?;
    Ok(alloy::hex::encode(bytes))
}

pub fn enable_best_effort_runtime_hardening() {
    disable_core_dumps();
}

#[cfg(unix)]
fn disable_core_dumps() {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // Best effort only: failure must not prevent wallet startup.
    unsafe {
        let _ = libc::setrlimit(libc::RLIMIT_CORE, std::ptr::addr_of!(limit));
    }
}

#[cfg(not(unix))]
const fn disable_core_dumps() {}

const fn validate_version(version: u32) -> Result<(), VaultError> {
    if version == VAULT_VERSION {
        Ok(())
    } else {
        Err(VaultError::UnsupportedVersion(version))
    }
}

fn decrypt_wrapped_key(
    wrapping_key: &SecretKey,
    kind: RecordKind,
    record: &EncryptedRecord,
) -> Result<SecretKey, VaultError> {
    decrypt_payload(wrapping_key, kind, "vault", record)
        .and_then(SecretKey::from_zeroizing_vec)
        .map_err(|error| match error {
            VaultError::UnsupportedVersion(version) => VaultError::UnsupportedVersion(version),
            _ => VaultError::UnlockFailed,
        })
}

fn derive_root_key_for_unlock(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    kdf: KdfParams,
) -> Result<SecretKey, VaultError> {
    derive_root_key(password, salt, kdf).map_err(|_| VaultError::UnlockFailed)
}

fn derive_wrapping_keys_for_unlock(root_key: &SecretKey) -> Result<WrappingKeys, VaultError> {
    derive_wrapping_keys(root_key).map_err(|_| VaultError::UnlockFailed)
}

fn derive_root_key(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    kdf: KdfParams,
) -> Result<SecretKey, VaultError> {
    let params = Params::new(
        kdf.memory_cost_kib,
        kdf.time_cost,
        kdf.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|_| VaultError::InvalidKdfParams)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(password, salt, output.as_mut())
        .map_err(|_| VaultError::Kdf)?;
    Ok(SecretKey(output))
}

struct WrappingKeys {
    view: SecretKey,
    spend: SecretKey,
}

fn derive_wrapping_keys(root_key: &SecretKey) -> Result<WrappingKeys, VaultError> {
    Ok(WrappingKeys {
        view: derive_domain_key(root_key, b"view-wrap")?,
        spend: derive_domain_key(root_key, b"spend-wrap")?,
    })
}

pub fn derive_domain_key(source_key: &SecretKey, label: &[u8]) -> Result<SecretKey, VaultError> {
    let hkdf = Hkdf::<Sha256>::from_prk(source_key.expose_secret())
        .map_err(|_| VaultError::KeySeparation)?;
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(label, out.as_mut())
        .map_err(|_| VaultError::KeySeparation)?;
    Ok(SecretKey(out))
}

pub fn derive_context_key(
    source_key: &SecretKey,
    label: &[u8],
    context: &[u8],
) -> Result<SecretKey, VaultError> {
    let mut info = Vec::with_capacity(label.len() + context.len() + 1);
    info.extend_from_slice(label);
    info.extend_from_slice(b":");
    info.extend_from_slice(context);
    derive_domain_key(source_key, &info)
}

pub fn encrypt_payload(
    key: &SecretKey,
    kind: RecordKind,
    record_id: &str,
    plaintext: &[u8],
) -> Result<EncryptedRecord, VaultError> {
    let mut nonce = [0u8; NONCE_LEN];
    fill(&mut nonce).map_err(|_| VaultError::Random)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.expose_secret()).map_err(|_| VaultError::Encrypt)?;
    let aad = record_aad(kind, record_id);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| VaultError::Encrypt)?;
    Ok(EncryptedRecord { nonce, ciphertext })
}

pub fn decrypt_payload(
    key: &SecretKey,
    kind: RecordKind,
    record_id: &str,
    record: &EncryptedRecord,
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.expose_secret()).map_err(|_| VaultError::Decrypt)?;
    let aad = record_aad(kind, record_id);
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&record.nonce),
            Payload {
                msg: &record.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| VaultError::Decrypt)?;
    Ok(Zeroizing::new(plaintext))
}

pub fn encrypt_serialized<T: Serialize>(
    key: &SecretKey,
    kind: RecordKind,
    record_id: &str,
    value: &T,
) -> Result<EncryptedRecord, VaultError> {
    let mut plaintext = Zeroizing::new(rmp_serde::to_vec_named(value)?);
    let record = encrypt_payload(key, kind, record_id, &plaintext)?;
    plaintext.zeroize();
    Ok(record)
}

pub fn decrypt_serialized<T: DeserializeOwned>(
    key: &SecretKey,
    kind: RecordKind,
    record_id: &str,
    record: &EncryptedRecord,
) -> Result<T, VaultError> {
    let plaintext = decrypt_payload(key, kind, record_id, record)?;
    Ok(rmp_serde::from_slice(&plaintext)?)
}

fn record_aad(kind: RecordKind, record_id: &str) -> Vec<u8> {
    let mut aad =
        Vec::with_capacity(VAULT_AAD_PREFIX.len() + kind.as_str().len() + record_id.len() + 16);
    aad.extend_from_slice(VAULT_AAD_PREFIX);
    aad.extend_from_slice(b":v1:");
    aad.extend_from_slice(kind.as_str().as_bytes());
    aad.extend_from_slice(b":");
    aad.extend_from_slice(record_id.as_bytes());
    aad
}

fn wallet_view_record_key(wallet_id: &str) -> String {
    format!("{WALLET_VIEW_PREFIX}{wallet_id}")
}

fn wallet_spend_record_key(wallet_id: &str) -> String {
    format!("{WALLET_SPEND_PREFIX}{wallet_id}")
}

fn wallet_metadata_record_key(wallet_uuid: &str) -> String {
    format!("{WALLET_METADATA_PREFIX}{wallet_uuid}")
}

fn wallet_chain_metadata_record_key(wallet_chain_uuid: &str) -> String {
    format!("{WALLET_CHAIN_METADATA_PREFIX}{wallet_chain_uuid}")
}

fn wallet_cache_row_prefix(wallet_chain_uuid: &str) -> String {
    format!("{WALLET_CACHE_ROW_PREFIX}{wallet_chain_uuid}|")
}

fn wallet_cache_row_record_key(wallet_chain_uuid: &str, row_id: &[u8; KEY_LEN]) -> String {
    format!(
        "{}{row_id}",
        wallet_cache_row_prefix(wallet_chain_uuid),
        row_id = CacheKeys::row_record_id(row_id)
    )
}

fn wallet_cache_counts(utxos: &[WalletUtxo]) -> (usize, usize) {
    let spent = utxos.iter().filter(|utxo| utxo.is_spent()).count();
    (utxos.len().saturating_sub(spent), spent)
}

fn vault_error_from_wallet_cache(error: WalletCacheError) -> VaultError {
    match error {
        WalletCacheError::Encode(error) => VaultError::Encode(error),
        WalletCacheError::Decode(error) => VaultError::Decode(error),
        WalletCacheError::Db(error) => VaultError::Db(error),
        WalletCacheError::Io(error) => VaultError::Io(error),
        WalletCacheError::Crypto => VaultError::Decrypt,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    const TEST_PASSWORD: &str = "correct horse battery staple";
    const TEST_WALLET_ID: &str = "wallet-1";
    static TEMP_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_kdf() -> KdfParams {
        KdfParams::new(1024, 1, 1)
    }

    fn temp_db_root() -> PathBuf {
        let dir = std::env::temp_dir().join("railgun-broadcaster-wallet-vault-tests");
        fs::create_dir_all(&dir).expect("create temp db dir");
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let counter = TEMP_DB_COUNTER.fetch_add(1, Ordering::Relaxed);
        dir.join(format!("db-{pid}-{nanos}-{counter}"))
    }

    #[test]
    fn create_and_unlock_view() {
        let created = create_with_params(TEST_PASSWORD, test_kdf()).expect("create vault");
        let unlocked = unlock_view(&created.metadata, TEST_PASSWORD).expect("unlock view");

        let record = unlocked
            .encrypt_record(
                RecordKind::WalletChainMetadata,
                TEST_WALLET_ID,
                b"chain metadata",
            )
            .expect("encrypt");
        let plaintext = unlocked
            .decrypt_record(RecordKind::WalletChainMetadata, TEST_WALLET_ID, &record)
            .expect("decrypt");

        assert_eq!(&*plaintext, b"chain metadata");
    }

    #[test]
    fn desktop_vault_store_persists_metadata() {
        let root_dir = temp_db_root();
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let store = DesktopVaultStore::from_db(Arc::clone(&db));
        let created = create_with_params(TEST_PASSWORD, test_kdf()).expect("create vault");

        store
            .put_metadata(&created.metadata)
            .expect("persist metadata");
        let loaded = store.metadata().expect("load metadata");
        let unlocked = unlock_view(&loaded, TEST_PASSWORD).expect("unlock loaded metadata");
        let record = unlocked
            .encrypt_record(
                RecordKind::WalletChainMetadata,
                TEST_WALLET_ID,
                b"chain metadata",
            )
            .expect("encrypt");

        assert_eq!(loaded.version, current_vault_version());
        assert_eq!(loaded.kdf, test_kdf());
        assert!(
            unlocked
                .decrypt_record(RecordKind::WalletChainMetadata, TEST_WALLET_ID, &record)
                .is_ok()
        );

        drop(store);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[test]
    fn create_vault_does_not_overwrite_existing_metadata() {
        let root_dir = temp_db_root();
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let store = DesktopVaultStore::from_db(Arc::clone(&db));

        let created = store
            .create_vault_with_params(TEST_PASSWORD, test_kdf())
            .expect("create vault");
        assert!(matches!(
            store.create_vault_with_params("different password", test_kdf()),
            Err(VaultError::VaultAlreadyExists)
        ));

        let loaded = store.metadata().expect("load metadata");
        assert_eq!(loaded, created.metadata);
        assert!(store.unlock_view(TEST_PASSWORD).is_ok());

        drop(store);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[test]
    fn imported_wallet_stores_encrypted_view_and_spend_bundles() {
        let root_dir = temp_db_root();
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let store = DesktopVaultStore::from_db(Arc::clone(&db));
        let created = create_with_params(TEST_PASSWORD, test_kdf()).expect("create vault");
        store
            .put_metadata(&created.metadata)
            .expect("persist metadata");
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet_id = "opaque-wallet-id";

        let stored = store
            .import_wallet_mnemonic(TEST_PASSWORD, wallet_id, 0, "english", mnemonic)
            .expect("import wallet");
        let view_payload = db
            .get_desktop_wallet_vault_record(&stored.view_record_key)
            .expect("load view record")
            .expect("view record present");
        let spend_payload = db
            .get_desktop_wallet_vault_record(&stored.spend_record_key)
            .expect("load spend record")
            .expect("spend record present");
        let view_bundle = store
            .load_view_bundle(TEST_PASSWORD, wallet_id)
            .expect("load view bundle");
        let mut grant = store
            .create_spend_grant(TEST_PASSWORD)
            .expect("create grant");
        let spend_bundle = store
            .load_spend_bundle(&mut grant, wallet_id)
            .expect("load spend bundle");

        assert_eq!(view_bundle.derivation_index, 0);
        assert_eq!(spend_bundle.derivation_index, 0);
        assert_eq!(spend_bundle.bip39_language, "english");
        assert_eq!(
            spend_bundle.bip39_entropy,
            bip39_entropy_from_mnemonic(mnemonic).expect("mnemonic entropy")
        );
        assert!(!contains_subsequence(&view_payload, mnemonic.as_bytes()));
        assert!(!contains_subsequence(&spend_payload, mnemonic.as_bytes()));

        grant.invalidate();
        assert!(matches!(
            store.load_spend_bundle(&mut grant, wallet_id),
            Err(VaultError::InvalidSpendGrant)
        ));
        let mut fresh_grant = store
            .create_spend_grant(TEST_PASSWORD)
            .expect("create fresh grant");
        assert!(store.load_spend_bundle(&mut fresh_grant, wallet_id).is_ok());

        drop(store);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[test]
    fn wallet_with_metadata_stores_records_in_one_batch() {
        let root_dir = temp_db_root();
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let store = DesktopVaultStore::from_db(Arc::clone(&db));
        let created = create_with_params(TEST_PASSWORD, test_kdf()).expect("create vault");
        store
            .put_metadata(&created.metadata)
            .expect("persist metadata");
        let seed = generate_seed_material().expect("generate seed");
        let wallet_id = "wallet-with-metadata";
        let metadata = WalletMetadataBundle {
            wallet_uuid: wallet_id.to_string(),
            label: "Primary wallet".to_string(),
            derivation_index: 0,
        };

        let stored = store
            .store_generated_wallet_with_metadata(
                TEST_PASSWORD,
                wallet_id,
                0,
                "english",
                &seed,
                &metadata,
            )
            .expect("store wallet with metadata");

        assert!(
            db.get_desktop_wallet_vault_record(&stored.view_record_key)
                .expect("load view record")
                .is_some()
        );
        assert!(
            db.get_desktop_wallet_vault_record(&stored.spend_record_key)
                .expect("load spend record")
                .is_some()
        );
        let loaded = store
            .load_wallet_metadata(TEST_PASSWORD, wallet_id)
            .expect("load wallet metadata");
        assert_eq!(loaded.wallet_uuid, wallet_id);
        assert_eq!(loaded.label, "Primary wallet");
        assert_eq!(loaded.derivation_index, 0);

        drop(store);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[test]
    fn generated_wallet_seed_material_stores_encrypted_bundles() {
        let root_dir = temp_db_root();
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let store = DesktopVaultStore::from_db(Arc::clone(&db));
        let created = create_with_params(TEST_PASSWORD, test_kdf()).expect("create vault");
        store
            .put_metadata(&created.metadata)
            .expect("persist metadata");
        let seed = generate_seed_material().expect("generate seed");
        let wallet_id = "generated-wallet-id";

        let stored = store
            .store_generated_wallet(TEST_PASSWORD, wallet_id, 0, "english", &seed)
            .expect("store generated wallet");
        let view_payload = db
            .get_desktop_wallet_vault_record(&stored.view_record_key)
            .expect("load view record")
            .expect("view record present");
        let spend_payload = db
            .get_desktop_wallet_vault_record(&stored.spend_record_key)
            .expect("load spend record")
            .expect("spend record present");
        let mut grant = store
            .create_spend_grant(TEST_PASSWORD)
            .expect("create grant");
        let spend_bundle = store
            .load_spend_bundle(&mut grant, wallet_id)
            .expect("load spend bundle");

        assert_eq!(spend_bundle.bip39_entropy, seed.entropy.as_slice());
        assert!(!contains_subsequence(
            &view_payload,
            seed.mnemonic.as_bytes()
        ));
        assert!(!contains_subsequence(
            &spend_payload,
            seed.mnemonic.as_bytes()
        ));
        assert!(!contains_subsequence(
            &view_payload,
            seed.entropy.as_slice()
        ));
        assert!(!contains_subsequence(
            &spend_payload,
            seed.entropy.as_slice()
        ));

        drop(store);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[test]
    fn first_view_session_loads_only_view_material() {
        let root_dir = temp_db_root();
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let store = DesktopVaultStore::from_db(Arc::clone(&db));
        let created = create_with_params(TEST_PASSWORD, test_kdf()).expect("create vault");
        store
            .put_metadata(&created.metadata)
            .expect("persist metadata");
        assert!(
            store
                .unlock_first_view_session(TEST_PASSWORD)
                .expect("unlock empty vault")
                .is_none()
        );

        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet_id = "first-view-wallet";
        store
            .import_wallet_mnemonic(TEST_PASSWORD, wallet_id, 0, "english", mnemonic)
            .expect("import wallet");
        let view_session = store
            .unlock_first_view_session(TEST_PASSWORD)
            .expect("unlock first wallet")
            .expect("view session present");
        let wallet = WalletKeys::from_mnemonic(mnemonic, 0).expect("derive wallet");

        assert_eq!(view_session.wallet_id(), wallet_id);
        assert_eq!(view_session.derivation_index(), 0);
        assert_eq!(
            view_session.scan_keys().master_public_key,
            wallet.viewing.master_public_key
        );
        assert_eq!(
            view_session.scan_keys().nullifying_key,
            wallet.viewing.nullifying_key
        );
        assert!(matches!(
            store.unlock_first_view_session("wrong password"),
            Err(VaultError::UnlockFailed)
        ));

        drop(store);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[test]
    fn view_session_receive_address_uses_all_chains_address() {
        let root_dir = temp_db_root();
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let store = DesktopVaultStore::from_db(Arc::clone(&db));
        let created = create_with_params(TEST_PASSWORD, test_kdf()).expect("create vault");
        store
            .put_metadata(&created.metadata)
            .expect("persist metadata");
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet_id = "receive-address-wallet";
        store
            .import_wallet_mnemonic(TEST_PASSWORD, wallet_id, 0, "english", mnemonic)
            .expect("import wallet");
        let view_session = store
            .load_view_session(TEST_PASSWORD, wallet_id)
            .expect("load view session");
        let wallet = WalletKeys::from_mnemonic(mnemonic, 0).expect("derive wallet");
        let all_chains = wallet
            .viewing
            .derive_address(None)
            .expect("derive all-chains address")
            .to_string();
        let ethereum_scoped = wallet
            .viewing
            .derive_address(Some((0, 1)))
            .expect("derive ethereum-scoped address")
            .to_string();
        let bsc_scoped = wallet
            .viewing
            .derive_address(Some((0, 56)))
            .expect("derive bsc-scoped address")
            .to_string();

        assert_eq!(
            view_session.receive_address().expect("receive address"),
            all_chains
        );
        assert_ne!(all_chains, ethereum_scoped);
        assert_ne!(all_chains, bsc_scoped);

        drop(store);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[test]
    fn opaque_wallet_metadata_keeps_chain_details_encrypted() {
        let root_dir = temp_db_root();
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let store = DesktopVaultStore::from_db(Arc::clone(&db));
        let created = create_with_params(TEST_PASSWORD, test_kdf()).expect("create vault");
        store
            .put_metadata(&created.metadata)
            .expect("persist metadata");
        let wallet_uuid = generate_opaque_id().expect("wallet uuid");
        let wallet_chain_uuid = generate_opaque_id().expect("wallet chain uuid");
        let wallet_metadata = WalletMetadataBundle {
            wallet_uuid: wallet_uuid.clone(),
            label: "primary wallet".to_string(),
            derivation_index: 0,
        };
        let chain_metadata = WalletChainMetadataBundle {
            wallet_chain_uuid: wallet_chain_uuid.clone(),
            wallet_uuid: wallet_uuid.clone(),
            chain_type: 0,
            chain_id: 1,
            contract: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
            start_block: 100,
            last_scanned_block: 200,
            last_scanned_block_hash: Some([9u8; KEY_LEN]),
        };

        store
            .store_wallet_metadata(TEST_PASSWORD, &wallet_metadata)
            .expect("store wallet metadata");
        store
            .store_wallet_chain_metadata(TEST_PASSWORD, &chain_metadata)
            .expect("store chain metadata");
        let wallet_payload = db
            .get_desktop_wallet_vault_record(&wallet_metadata_record_key(&wallet_uuid))
            .expect("load wallet metadata record")
            .expect("wallet metadata present");
        let chain_payload = db
            .get_desktop_wallet_vault_record(&wallet_chain_metadata_record_key(&wallet_chain_uuid))
            .expect("load chain metadata record")
            .expect("chain metadata present");
        let loaded_wallet = store
            .load_wallet_metadata(TEST_PASSWORD, &wallet_uuid)
            .expect("load wallet metadata");
        let loaded_chain = store
            .load_wallet_chain_metadata(TEST_PASSWORD, &wallet_chain_uuid)
            .expect("load chain metadata");

        assert_eq!(wallet_uuid.len(), 32);
        assert_eq!(wallet_chain_uuid.len(), 32);
        assert_eq!(loaded_wallet.label, "primary wallet");
        assert_eq!(loaded_chain.chain_id, 1);
        assert_eq!(loaded_chain.contract, chain_metadata.contract);
        assert!(!contains_subsequence(&wallet_payload, b"primary wallet"));
        assert!(!contains_subsequence(&chain_payload, b"1234567890abcdef"));

        drop(store);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[test]
    fn software_spend_signer_requires_valid_grant() {
        let root_dir = temp_db_root();
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let store = DesktopVaultStore::from_db(Arc::clone(&db));
        let created = create_with_params(TEST_PASSWORD, test_kdf()).expect("create vault");
        store
            .put_metadata(&created.metadata)
            .expect("persist metadata");
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet_id = "spend-signer-wallet";
        store
            .import_wallet_mnemonic(TEST_PASSWORD, wallet_id, 0, "english", mnemonic)
            .expect("import wallet");
        let mut grant = store
            .create_spend_grant(TEST_PASSWORD)
            .expect("create grant");

        let signer = store
            .railgun_spend_signer(&mut grant, wallet_id)
            .expect("load signer");
        let signature = signer.sign_spend_message(alloy::primitives::U256::from(7_u8));

        assert_ne!(signature, [alloy::primitives::U256::ZERO; 3]);
        assert!(!grant.is_valid());
        assert!(matches!(
            store.railgun_spend_signer(&mut grant, wallet_id),
            Err(VaultError::InvalidSpendGrant)
        ));

        drop(store);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[test]
    fn wrong_password_returns_generic_unlock_error() {
        let created = create_with_params(TEST_PASSWORD, test_kdf()).expect("create vault");
        let Err(error) = unlock_view(&created.metadata, "wrong password") else {
            panic!("unlock unexpectedly succeeded");
        };

        assert!(matches!(error, VaultError::UnlockFailed));
    }

    #[test]
    fn tampered_wrapped_key_returns_generic_unlock_error() {
        let created = create_with_params(TEST_PASSWORD, test_kdf()).expect("create vault");
        let mut metadata = created.metadata;
        metadata.wrapped_view_dek.ciphertext[0] ^= 0x01;

        let Err(error) = unlock_view(&metadata, TEST_PASSWORD) else {
            panic!("unlock unexpectedly succeeded");
        };

        assert!(matches!(error, VaultError::UnlockFailed));
    }

    #[test]
    fn view_and_spend_bundles_use_separate_keys() {
        let created = create_with_params(TEST_PASSWORD, test_kdf()).expect("create vault");
        let view_bundle = WalletViewBundle {
            derivation_index: 0,
            spending_public_key: [[1u8; KEY_LEN], [2u8; KEY_LEN]],
            viewing_private_key: [3u8; KEY_LEN],
            viewing_public_key: [4u8; KEY_LEN],
            nullifying_key: [5u8; KEY_LEN],
            master_public_key: [6u8; KEY_LEN],
        };
        let spend_bundle = WalletSpendBundle {
            derivation_index: 0,
            bip39_language: "english".to_string(),
            bip39_entropy: vec![7u8; 32],
        };

        let view_record = created
            .view
            .encrypt_view_bundle(TEST_WALLET_ID, &view_bundle)
            .expect("encrypt view bundle");
        let spend_record = created
            .spend
            .encrypt_spend_bundle(TEST_WALLET_ID, &spend_bundle)
            .expect("encrypt spend bundle");

        assert!(
            created
                .view
                .decrypt_view_bundle(TEST_WALLET_ID, &view_record)
                .is_ok()
        );
        assert!(
            created
                .spend
                .decrypt_spend_bundle(TEST_WALLET_ID, &spend_record)
                .is_ok()
        );
        assert!(
            created
                .view
                .decrypt_record(RecordKind::WalletSpendBundle, TEST_WALLET_ID, &spend_record)
                .is_err()
        );
        assert!(
            created
                .spend
                .decrypt_record(RecordKind::WalletViewBundle, TEST_WALLET_ID, &view_record)
                .is_err()
        );
    }

    #[test]
    fn spend_grant_is_one_use_and_invalidates() {
        let created = create_with_params(TEST_PASSWORD, test_kdf()).expect("create vault");
        let mut grant = create_spend_grant(&created.metadata, TEST_PASSWORD).expect("grant");

        assert_eq!(grant.policy(), SpendGrantPolicy::OneUse);
        assert!(grant.is_valid());
        assert!(grant.spend_unlock().is_ok());

        grant.invalidate();

        assert!(!grant.is_valid());
        assert!(matches!(
            grant.spend_unlock(),
            Err(VaultError::InvalidSpendGrant)
        ));
    }

    #[test]
    fn aad_binds_record_kind_and_id() {
        let created = create_with_params(TEST_PASSWORD, test_kdf()).expect("create vault");
        let record = created
            .view
            .encrypt_record(
                RecordKind::WalletChainMetadata,
                TEST_WALLET_ID,
                b"chain metadata",
            )
            .expect("encrypt");

        assert!(
            created
                .view
                .decrypt_record(RecordKind::WalletCacheRow, TEST_WALLET_ID, &record)
                .is_err()
        );
        assert!(
            created
                .view
                .decrypt_record(RecordKind::WalletChainMetadata, "other-wallet", &record)
                .is_err()
        );
    }

    #[test]
    fn cache_row_ids_are_deterministic_and_context_bound() {
        let created = create_with_params(TEST_PASSWORD, test_kdf()).expect("create vault");
        let cache_keys = created
            .view
            .derive_cache_keys("opaque-wallet-chain-a")
            .expect("cache keys");
        let other_cache_keys = created
            .view
            .derive_cache_keys("opaque-wallet-chain-b")
            .expect("other cache keys");

        let row_id = cache_keys.row_id(4, 42, b"stable-utxo");
        let same_row_id = cache_keys.row_id(4, 42, b"stable-utxo");
        let other_position = cache_keys.row_id(4, 43, b"stable-utxo");
        let other_namespace = other_cache_keys.row_id(4, 42, b"stable-utxo");

        assert_eq!(row_id, same_row_id);
        assert_ne!(row_id, other_position);
        assert_ne!(row_id, other_namespace);
        assert_eq!(CacheKeys::row_record_id(&row_id).len(), 64);
    }

    #[test]
    fn encrypted_cache_rows_are_bound_to_opaque_row_id() {
        let created = create_with_params(TEST_PASSWORD, test_kdf()).expect("create vault");
        let cache_keys = created
            .view
            .derive_cache_keys("opaque-wallet-chain")
            .expect("cache keys");
        let row_id = cache_keys.row_id(4, 42, b"stable-utxo");
        let other_row_id = cache_keys.row_id(4, 43, b"stable-utxo");
        let record = cache_keys
            .encrypt_row(&row_id, b"private utxo payload")
            .expect("encrypt row");
        let mut tampered = record.clone();
        tampered.ciphertext[0] ^= 0x01;

        let plaintext = cache_keys
            .decrypt_row(&row_id, &record)
            .expect("decrypt row");
        assert_eq!(&*plaintext, b"private utxo payload");
        assert!(cache_keys.decrypt_row(&other_row_id, &record).is_err());
        assert!(cache_keys.decrypt_row(&row_id, &tampered).is_err());
    }

    #[test]
    fn encrypted_cache_store_hides_wallet_history_details() {
        use alloy::primitives::{FixedBytes, U256};
        use railgun_wallet::{Note, Utxo, UtxoCommitmentKind, UtxoSource};
        use sync_service::WalletCacheStore;

        let root_dir = temp_db_root();
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let store = DesktopVaultStore::from_db(Arc::clone(&db));
        let created = create_with_params(TEST_PASSWORD, test_kdf()).expect("create vault");
        store
            .put_metadata(&created.metadata)
            .expect("persist metadata");
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet_id = "encrypted-cache-wallet";
        store
            .import_wallet_mnemonic(TEST_PASSWORD, wallet_id, 0, "english", mnemonic)
            .expect("import wallet");
        let view_session = Arc::new(
            store
                .load_view_session(TEST_PASSWORD, wallet_id)
                .expect("load view session"),
        );
        let chain_metadata = store
            .wallet_chain_metadata_for_session(
                view_session.as_ref(),
                0,
                1,
                "0x1111111111111111111111111111111111111111",
                100,
            )
            .expect("chain metadata");
        let wallet_chain_uuid = chain_metadata.wallet_chain_uuid.clone();
        let cache_store = DesktopEncryptedWalletCacheStore::new(
            Arc::clone(&db),
            Arc::clone(&view_session),
            chain_metadata,
        )
        .expect("encrypted cache store");
        let wallet_utxo = WalletUtxo {
            utxo: Utxo::new(
                Note {
                    token_hash: U256::from_be_bytes([0x44; KEY_LEN]),
                    value: U256::from_be_bytes([0x55; KEY_LEN]),
                    random: [0x66; 16],
                    npk: U256::from_be_bytes([0x77; KEY_LEN]),
                },
                7,
                42,
                UtxoSource {
                    tx_hash: FixedBytes::from([0x88; KEY_LEN]),
                    block_number: 123,
                    block_timestamp: 1_700_000_123,
                },
                UtxoCommitmentKind::Transact,
            ),
            spent: Some(UtxoSource {
                tx_hash: FixedBytes::from([0x99; KEY_LEN]),
                block_number: 124,
                block_timestamp: 1_700_000_124,
            }),
        };

        cache_store
            .store_wallet_utxos(
                "ignored-cache-key",
                std::slice::from_ref(&wallet_utxo),
                Some(150),
                Some([0xaa; KEY_LEN]),
            )
            .expect("store encrypted cache");
        let rows = db
            .list_desktop_wallet_vault_records(&wallet_cache_row_prefix(&wallet_chain_uuid))
            .expect("list encrypted cache rows");
        let chain_payload = db
            .get_desktop_wallet_vault_record(&wallet_chain_metadata_record_key(&wallet_chain_uuid))
            .expect("load chain metadata record")
            .expect("chain metadata present");
        let loaded = cache_store
            .load_wallet_utxos("ignored-cache-key")
            .expect("load encrypted cache");
        let loaded_meta = store
            .load_wallet_chain_metadata(TEST_PASSWORD, &wallet_chain_uuid)
            .expect("load updated chain metadata");

        assert_eq!(rows.len(), 1);
        assert_eq!(loaded.len(), 1);
        assert_eq!(
            loaded[0].utxo.note.token_hash,
            wallet_utxo.utxo.note.token_hash
        );
        assert_eq!(
            loaded[0].utxo.source.tx_hash,
            wallet_utxo.utxo.source.tx_hash
        );
        assert_eq!(loaded[0].spent, wallet_utxo.spent);
        assert_eq!(loaded_meta.last_scanned_block, 150);
        assert_eq!(loaded_meta.last_scanned_block_hash, Some([0xaa; KEY_LEN]));

        let row_key = rows[0].key.as_bytes();
        let row_payload = &rows[0].payload;
        assert!(!contains_subsequence(row_key, b"1111111111111111"));
        assert!(!contains_subsequence(row_payload, &[0x44; KEY_LEN]));
        assert!(!contains_subsequence(row_payload, &[0x55; KEY_LEN]));
        assert!(!contains_subsequence(row_payload, &[0x66; 16]));
        assert!(!contains_subsequence(row_payload, &[0x77; KEY_LEN]));
        assert!(!contains_subsequence(row_payload, &[0x88; KEY_LEN]));
        assert!(!contains_subsequence(row_payload, &[0x99; KEY_LEN]));
        assert!(!contains_subsequence(&chain_payload, b"1111111111111111"));

        drop(store);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[test]
    fn encrypted_cache_upsert_does_not_delete_existing_rows() {
        use alloy::primitives::{FixedBytes, U256};
        use railgun_wallet::{Note, Utxo, UtxoCommitmentKind, UtxoSource};
        use sync_service::WalletCacheStore;

        let root_dir = temp_db_root();
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let store = DesktopVaultStore::from_db(Arc::clone(&db));
        let created = create_with_params(TEST_PASSWORD, test_kdf()).expect("create vault");
        store
            .put_metadata(&created.metadata)
            .expect("persist metadata");
        let wallet_id = "encrypted-cache-upsert-wallet";
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        store
            .import_wallet_mnemonic(TEST_PASSWORD, wallet_id, 0, "english", mnemonic)
            .expect("import wallet");
        let view_session = Arc::new(
            store
                .load_view_session(TEST_PASSWORD, wallet_id)
                .expect("load view session"),
        );
        let mut chain_metadata = store
            .wallet_chain_metadata_for_session(
                view_session.as_ref(),
                0,
                1,
                "0x1111111111111111111111111111111111111111",
                100,
            )
            .expect("chain metadata");
        let wallet_chain_uuid = chain_metadata.wallet_chain_uuid.clone();
        let cache_store = DesktopEncryptedWalletCacheStore::new(
            Arc::clone(&db),
            Arc::clone(&view_session),
            chain_metadata.clone(),
        )
        .expect("encrypted cache store");
        let first = WalletUtxo {
            utxo: Utxo::new(
                Note {
                    token_hash: U256::from_be_bytes([0x11; KEY_LEN]),
                    value: U256::from(1_u8),
                    random: [0x22; 16],
                    npk: U256::from_be_bytes([0x33; KEY_LEN]),
                },
                3,
                1,
                UtxoSource {
                    tx_hash: FixedBytes::from([0x44; KEY_LEN]),
                    block_number: 101,
                    block_timestamp: 1_700_000_101,
                },
                UtxoCommitmentKind::Transact,
            ),
            spent: None,
        };
        let mut second = first.clone();
        second.utxo.position = 2;
        second.utxo.source.tx_hash = FixedBytes::from([0x55; KEY_LEN]);
        let mut rewound_source = first.clone();
        rewound_source.utxo.position = 3;
        rewound_source.utxo.source = UtxoSource {
            tx_hash: FixedBytes::from([0x66; KEY_LEN]),
            block_number: 170,
            block_timestamp: 1_700_000_170,
        };
        let mut rewound_spend = first.clone();
        rewound_spend.utxo.position = 4;
        rewound_spend.utxo.source.tx_hash = FixedBytes::from([0x77; KEY_LEN]);
        rewound_spend.spent = Some(UtxoSource {
            tx_hash: FixedBytes::from([0x88; KEY_LEN]),
            block_number: 170,
            block_timestamp: 1_700_000_170,
        });

        cache_store
            .store_wallet_utxos(
                "ignored",
                &[first.clone(), second, rewound_source, rewound_spend],
                Some(110),
                None,
            )
            .expect("store full cache");
        cache_store
            .store_wallet_utxos("ignored", std::slice::from_ref(&first), Some(120), None)
            .expect("upsert partial cache");
        let loaded = cache_store
            .load_wallet_utxos("ignored")
            .expect("load upserted cache");
        assert_eq!(loaded.len(), 4);
        assert!(loaded.iter().any(|utxo| utxo.utxo.position == 1));
        assert!(loaded.iter().any(|utxo| utxo.utxo.position == 2));
        assert!(loaded.iter().any(|utxo| utxo.utxo.position == 3));
        assert!(loaded.iter().any(|utxo| utxo.utxo.position == 4));

        store
            .rewind_wallet_chain_cache_with_session(view_session.as_ref(), &mut chain_metadata, 150)
            .expect("rewind encrypted cache");
        let loaded = cache_store
            .load_wallet_utxos("ignored")
            .expect("load rewound cache");
        assert_eq!(loaded.len(), 3);
        assert!(loaded.iter().any(|utxo| utxo.utxo.position == 1));
        assert!(loaded.iter().any(|utxo| utxo.utxo.position == 2));
        assert!(!loaded.iter().any(|utxo| utxo.utxo.position == 3));
        assert!(
            loaded
                .iter()
                .any(|utxo| utxo.utxo.position == 4 && utxo.spent.is_none())
        );
        let metadata = store
            .load_wallet_chain_metadata(TEST_PASSWORD, &wallet_chain_uuid)
            .expect("load rewound metadata");
        assert_eq!(metadata.last_scanned_block, 149);
        assert_eq!(metadata.last_scanned_block_hash, None);

        store
            .reset_wallet_chain_cache_with_session(view_session.as_ref(), &mut chain_metadata, 160)
            .expect("reset encrypted cache");
        assert!(
            cache_store
                .load_wallet_utxos("ignored")
                .expect("load reset cache")
                .is_empty()
        );
        let metadata = store
            .load_wallet_chain_metadata(TEST_PASSWORD, &wallet_chain_uuid)
            .expect("load reset metadata");
        assert_eq!(metadata.last_scanned_block, 159);
        assert_eq!(metadata.last_scanned_block_hash, None);

        drop(store);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[test]
    fn desktop_vault_first_run_unlock_wallet_setup_and_spend_prompt_flow() {
        let root_dir = temp_db_root();
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let store = DesktopVaultStore::from_db(Arc::clone(&db));

        assert!(!store.vault_exists().expect("inspect empty vault"));
        let created = store
            .create_vault_with_params(TEST_PASSWORD, test_kdf())
            .expect("create vault");
        assert_eq!(created.metadata.version, current_vault_version());
        assert!(store.vault_exists().expect("inspect created vault"));
        assert!(
            store
                .unlock_first_view_session(TEST_PASSWORD)
                .expect("unlock empty vault")
                .is_none()
        );

        let generated_seed = generate_seed_material().expect("generate wallet");
        store
            .store_generated_wallet(
                TEST_PASSWORD,
                "generated-wallet",
                0,
                "english",
                &generated_seed,
            )
            .expect("store generated wallet");
        let generated_session = store
            .unlock_first_view_session(TEST_PASSWORD)
            .expect("unlock generated wallet")
            .expect("generated session");
        assert_eq!(generated_session.wallet_id(), "generated-wallet");

        let imported_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        store
            .import_wallet_mnemonic(
                TEST_PASSWORD,
                "imported-wallet",
                0,
                "english",
                imported_mnemonic,
            )
            .expect("import wallet");
        let imported_session = store
            .load_view_session(TEST_PASSWORD, "imported-wallet")
            .expect("load imported wallet");
        assert_eq!(imported_session.wallet_id(), "imported-wallet");
        assert!(matches!(
            store.create_spend_grant("wrong password"),
            Err(VaultError::UnlockFailed)
        ));

        let mut grant = store
            .create_spend_grant(TEST_PASSWORD)
            .expect("fresh spend grant");
        let _signer = store
            .railgun_spend_signer(&mut grant, imported_session.wallet_id())
            .expect("spend signer from grant");
        assert!(!grant.is_valid());
        assert!(matches!(
            store.railgun_spend_signer(&mut grant, imported_session.wallet_id()),
            Err(VaultError::InvalidSpendGrant)
        ));

        drop(store);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty()
            && haystack
                .windows(needle.len())
                .any(|window| window == needle)
    }
}
