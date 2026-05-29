use super::{
    Arc, BROADCASTER_BANNED_PREFIX, BROADCASTER_FAVORITE_PREFIX, BTreeSet,
    BroadcasterAddressIdentity, BroadcasterPreferenceEntry, BroadcasterPreferences, CreatedVault,
    DbConfig, DbStore, DesktopVaultStore, DesktopViewSession, EncryptedRecord,
    GeneratedSeedMaterial, KEY_LEN, KdfParams, LoadedWalletMetadata, PRIVATE_ADDRESS_BOOK_PREFIX,
    PUBLIC_ACCOUNT_METADATA_PREFIX, PUBLIC_ADDRESS_BOOK_PREFIX, PathBuf, PrivateAddressBookEntry,
    PublicAccountMetadata, PublicAccountScope, PublicAccountSecret, PublicAccountSource,
    PublicAccountStatus, PublicAddressBookEntry, RecordKind, SoftwareRailgunSpendSigner,
    SpendGrant, StoredWalletRecord, VAULT_METADATA_KEY, VaultError, VaultMetadata,
    VaultRecordEntries, ViewUnlock, WALLET_CHAIN_METADATA_PREFIX, WALLET_VIEW_PREFIX,
    WalletChainMetadataBundle, WalletKeys, WalletMetadataBundle, WalletSource, WalletSpendBundle,
    WalletStatus, WalletViewBundle, Zeroizing, assign_missing_display_orders,
    bip39_entropy_from_mnemonic, broadcaster_banned_record_entry, broadcaster_banned_record_key,
    broadcaster_favorite_record_entry, broadcaster_favorite_record_key,
    broadcaster_preference_entry_identity, create_spend_grant, create_with_params,
    default_wallet_label_for_metadata, derive_public_evm_address_from_entropy,
    derive_public_evm_private_key_from_entropy, deserialize_wallet_utxo,
    ensure_private_address_book_address_available,
    ensure_private_address_book_address_available_for_update,
    ensure_public_account_address_available, ensure_public_address_book_address_available,
    ensure_public_address_book_address_available_for_update, generate_opaque_id,
    initial_derived_public_account, next_derived_public_account_index,
    next_private_address_book_display_order, next_public_account_display_order,
    next_public_address_book_display_order, next_wallet_display_order,
    normalize_public_account_label, parse_public_evm_private_key,
    private_address_book_record_entry, private_address_book_record_key,
    public_account_metadata_record_entry, public_account_metadata_record_key,
    public_account_secret_record_entry, public_account_secret_record_key,
    public_address_book_record_entry, public_address_book_record_key,
    public_evm_address_from_private_key, serialize_wallet_utxo,
    sort_broadcaster_preference_entries, sort_private_address_book_entries,
    sort_public_account_metadata, sort_public_address_book_entries, sort_wallet_metadata,
    unlock_spend, unlock_view, validate_address_book_label,
    validate_broadcaster_preference_address, validate_private_address_book_address,
    validate_public_address_book_address, validate_wallet_label, vault_error_from_wallet_cache,
    wallet_cache_row_prefix, wallet_cache_row_record_key, wallet_chain_metadata_record_key,
    wallet_metadata_record_entry, wallet_metadata_record_key, wallet_spend_record_key,
    wallet_utxo_stable_identity, wallet_view_record_key,
};

#[derive(Clone)]
struct LoadedBroadcasterPreferenceEntry {
    entry_uuid: String,
    entry: BroadcasterPreferenceEntry,
    identity: BroadcasterAddressIdentity,
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

    pub fn load_view_session_with_view_session(
        &self,
        view_session: &DesktopViewSession,
        wallet_id: &str,
    ) -> Result<DesktopViewSession, VaultError> {
        let record = self.encrypted_record(&wallet_view_record_key(wallet_id))?;
        let bundle = view_session.view.decrypt_view_bundle(wallet_id, &record)?;
        Ok(DesktopViewSession::from_bundle(
            wallet_id.to_owned(),
            &bundle,
            view_session.view.clone_unlock(),
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

    pub fn list_active_public_accounts_for_session(
        &self,
        view_session: &DesktopViewSession,
    ) -> Result<Vec<PublicAccountMetadata>, VaultError> {
        self.list_public_accounts_for_session(view_session, false)
    }

    pub fn list_public_accounts_for_session(
        &self,
        view_session: &DesktopViewSession,
        include_inactive: bool,
    ) -> Result<Vec<PublicAccountMetadata>, VaultError> {
        let mut accounts = self.list_public_account_metadata_with_view(&view_session.view)?;
        let wallet_id = view_session.wallet_id();
        accounts.retain(|account| {
            account.is_scoped_to_wallet(wallet_id)
                && (include_inactive || account.status == PublicAccountStatus::Active)
        });
        sort_public_account_metadata(&mut accounts);
        Ok(accounts)
    }

    pub fn next_derived_public_account_index_for_session(
        &self,
        view_session: &DesktopViewSession,
    ) -> Result<u32, VaultError> {
        let accounts = self.list_public_account_metadata_with_view(&view_session.view)?;
        next_derived_public_account_index(&accounts, view_session.wallet_id())
    }

    pub fn list_private_address_book_entries_for_session(
        &self,
        view_session: &DesktopViewSession,
    ) -> Result<Vec<PrivateAddressBookEntry>, VaultError> {
        self.list_private_address_book_entries_with_view(&view_session.view)
    }

    pub fn list_public_address_book_entries_for_session(
        &self,
        view_session: &DesktopViewSession,
    ) -> Result<Vec<PublicAddressBookEntry>, VaultError> {
        self.list_public_address_book_entries_with_view(&view_session.view)
    }

    pub fn list_broadcaster_preferences_for_session(
        &self,
        view_session: &DesktopViewSession,
    ) -> Result<BroadcasterPreferences, VaultError> {
        let banned = self.list_broadcaster_banned_entries_with_view(&view_session.view)?;
        let banned_identities = banned
            .iter()
            .map(|loaded| loaded.identity)
            .collect::<BTreeSet<_>>();
        let mut favorites = self
            .list_broadcaster_favorite_entries_with_view(&view_session.view)?
            .into_iter()
            .filter(|loaded| !banned_identities.contains(&loaded.identity))
            .map(|loaded| loaded.entry)
            .collect::<Vec<_>>();
        let mut banned = banned
            .into_iter()
            .map(|loaded| loaded.entry)
            .collect::<Vec<_>>();
        sort_broadcaster_preference_entries(&mut favorites);
        sort_broadcaster_preference_entries(&mut banned);
        Ok(BroadcasterPreferences { favorites, banned })
    }

    pub fn list_favorite_broadcasters_for_session(
        &self,
        view_session: &DesktopViewSession,
    ) -> Result<Vec<BroadcasterPreferenceEntry>, VaultError> {
        Ok(self
            .list_broadcaster_preferences_for_session(view_session)?
            .favorites)
    }

    pub fn list_banned_broadcasters_for_session(
        &self,
        view_session: &DesktopViewSession,
    ) -> Result<Vec<BroadcasterPreferenceEntry>, VaultError> {
        Ok(self
            .list_broadcaster_preferences_for_session(view_session)?
            .banned)
    }

    pub fn add_favorite_broadcaster_for_session(
        &self,
        view_session: &DesktopViewSession,
        address: &str,
    ) -> Result<BroadcasterPreferenceEntry, VaultError> {
        let (address, identity) = validate_broadcaster_preference_address(address)?;
        let favorites = self.list_broadcaster_favorite_entries_with_view(&view_session.view)?;
        let banned = self.list_broadcaster_banned_entries_with_view(&view_session.view)?;
        let existing = favorites
            .iter()
            .find(|loaded| loaded.identity == identity)
            .cloned();
        for loaded in banned.iter().filter(|loaded| loaded.identity == identity) {
            self.db
                .delete_desktop_wallet_vault_record(&broadcaster_banned_record_key(
                    &loaded.entry_uuid,
                ))?;
        }
        if let Some(existing) = existing {
            return Ok(existing.entry);
        }

        let entry_uuid = generate_opaque_id()?;
        let entry = BroadcasterPreferenceEntry { address };
        let (key, data) =
            broadcaster_favorite_record_entry(&view_session.view, &entry_uuid, &entry)?;
        self.db.put_desktop_wallet_vault_record(&key, &data)?;
        Ok(entry)
    }

    pub fn add_banned_broadcaster_for_session(
        &self,
        view_session: &DesktopViewSession,
        address: &str,
    ) -> Result<BroadcasterPreferenceEntry, VaultError> {
        let (address, identity) = validate_broadcaster_preference_address(address)?;
        let favorites = self.list_broadcaster_favorite_entries_with_view(&view_session.view)?;
        let banned = self.list_broadcaster_banned_entries_with_view(&view_session.view)?;
        let existing = banned
            .iter()
            .find(|loaded| loaded.identity == identity)
            .cloned();
        for loaded in favorites
            .iter()
            .filter(|loaded| loaded.identity == identity)
        {
            self.db
                .delete_desktop_wallet_vault_record(&broadcaster_favorite_record_key(
                    &loaded.entry_uuid,
                ))?;
        }
        if let Some(existing) = existing {
            return Ok(existing.entry);
        }

        let entry_uuid = generate_opaque_id()?;
        let entry = BroadcasterPreferenceEntry { address };
        let (key, data) = broadcaster_banned_record_entry(&view_session.view, &entry_uuid, &entry)?;
        self.db.put_desktop_wallet_vault_record(&key, &data)?;
        Ok(entry)
    }

    pub fn remove_favorite_broadcaster_for_session(
        &self,
        view_session: &DesktopViewSession,
        address: &str,
    ) -> Result<Option<BroadcasterPreferenceEntry>, VaultError> {
        let (_, identity) = validate_broadcaster_preference_address(address)?;
        let favorites = self.list_broadcaster_favorite_entries_with_view(&view_session.view)?;
        let Some(loaded) = favorites
            .into_iter()
            .find(|loaded| loaded.identity == identity)
        else {
            return Ok(None);
        };
        self.db
            .delete_desktop_wallet_vault_record(&broadcaster_favorite_record_key(
                &loaded.entry_uuid,
            ))?;
        Ok(Some(loaded.entry))
    }

    pub fn remove_banned_broadcaster_for_session(
        &self,
        view_session: &DesktopViewSession,
        address: &str,
    ) -> Result<Option<BroadcasterPreferenceEntry>, VaultError> {
        let (_, identity) = validate_broadcaster_preference_address(address)?;
        let banned = self.list_broadcaster_banned_entries_with_view(&view_session.view)?;
        let Some(loaded) = banned
            .into_iter()
            .find(|loaded| loaded.identity == identity)
        else {
            return Ok(None);
        };
        self.db
            .delete_desktop_wallet_vault_record(&broadcaster_banned_record_key(
                &loaded.entry_uuid,
            ))?;
        Ok(Some(loaded.entry))
    }

    pub fn add_private_address_book_entry_for_session(
        &self,
        view_session: &DesktopViewSession,
        label: &str,
        address: &str,
    ) -> Result<PrivateAddressBookEntry, VaultError> {
        let label = validate_address_book_label(label)?;
        let address = validate_private_address_book_address(address)?;
        let entries = self.list_private_address_book_entries_with_view(&view_session.view)?;
        let active_private_recipients = self.active_private_receive_addresses(view_session)?;
        ensure_private_address_book_address_available(
            &entries,
            &active_private_recipients,
            &address,
        )?;

        let entry = PrivateAddressBookEntry {
            entry_uuid: generate_opaque_id()?,
            label,
            address,
            display_order: next_private_address_book_display_order(&entries)?,
        };
        let (key, data) = private_address_book_record_entry(&view_session.view, &entry)?;
        self.db.put_desktop_wallet_vault_record(&key, &data)?;
        Ok(entry)
    }

    pub fn add_public_address_book_entry_for_session(
        &self,
        view_session: &DesktopViewSession,
        label: &str,
        address: &str,
    ) -> Result<PublicAddressBookEntry, VaultError> {
        let label = validate_address_book_label(label)?;
        let address = validate_public_address_book_address(address)?;
        let entries = self.list_public_address_book_entries_with_view(&view_session.view)?;
        let accounts = self.list_public_accounts_for_session(view_session, false)?;
        ensure_public_address_book_address_available(&entries, &accounts, address)?;

        let entry = PublicAddressBookEntry {
            entry_uuid: generate_opaque_id()?,
            label,
            address,
            display_order: next_public_address_book_display_order(&entries)?,
        };
        let (key, data) = public_address_book_record_entry(&view_session.view, &entry)?;
        self.db.put_desktop_wallet_vault_record(&key, &data)?;
        Ok(entry)
    }

    pub fn update_private_address_book_entry_for_session(
        &self,
        view_session: &DesktopViewSession,
        entry_uuid: &str,
        label: &str,
        address: &str,
    ) -> Result<PrivateAddressBookEntry, VaultError> {
        let label = validate_address_book_label(label)?;
        let address = validate_private_address_book_address(address)?;
        let mut entries = self.list_private_address_book_entries_with_view(&view_session.view)?;
        let Some(entry_index) = entries
            .iter()
            .position(|entry| entry.entry_uuid == entry_uuid)
        else {
            return Err(VaultError::PrivateAddressBookEntryNotFound);
        };
        let active_private_recipients = self.active_private_receive_addresses(view_session)?;
        ensure_private_address_book_address_available_for_update(
            &entries,
            &active_private_recipients,
            entry_uuid,
            &address,
        )?;

        entries[entry_index].label = label;
        entries[entry_index].address = address;
        let updated = entries[entry_index].clone();
        let (key, data) = private_address_book_record_entry(&view_session.view, &updated)?;
        self.db.put_desktop_wallet_vault_record(&key, &data)?;
        Ok(updated)
    }

    pub fn update_public_address_book_entry_for_session(
        &self,
        view_session: &DesktopViewSession,
        entry_uuid: &str,
        label: &str,
        address: &str,
    ) -> Result<PublicAddressBookEntry, VaultError> {
        let label = validate_address_book_label(label)?;
        let address = validate_public_address_book_address(address)?;
        let mut entries = self.list_public_address_book_entries_with_view(&view_session.view)?;
        let Some(entry_index) = entries
            .iter()
            .position(|entry| entry.entry_uuid == entry_uuid)
        else {
            return Err(VaultError::PublicAddressBookEntryNotFound);
        };
        let accounts = self.list_public_accounts_for_session(view_session, false)?;
        ensure_public_address_book_address_available_for_update(
            &entries, &accounts, entry_uuid, address,
        )?;

        entries[entry_index].label = label;
        entries[entry_index].address = address;
        let updated = entries[entry_index].clone();
        let (key, data) = public_address_book_record_entry(&view_session.view, &updated)?;
        self.db.put_desktop_wallet_vault_record(&key, &data)?;
        Ok(updated)
    }

    pub fn delete_private_address_book_entry_for_session(
        &self,
        view_session: &DesktopViewSession,
        entry_uuid: &str,
    ) -> Result<PrivateAddressBookEntry, VaultError> {
        let entries = self.list_private_address_book_entries_with_view(&view_session.view)?;
        let Some(entry) = entries
            .into_iter()
            .find(|entry| entry.entry_uuid == entry_uuid)
        else {
            return Err(VaultError::PrivateAddressBookEntryNotFound);
        };
        self.db
            .delete_desktop_wallet_vault_record(&private_address_book_record_key(entry_uuid))?;
        Ok(entry)
    }

    pub fn delete_public_address_book_entry_for_session(
        &self,
        view_session: &DesktopViewSession,
        entry_uuid: &str,
    ) -> Result<PublicAddressBookEntry, VaultError> {
        let entries = self.list_public_address_book_entries_with_view(&view_session.view)?;
        let Some(entry) = entries
            .into_iter()
            .find(|entry| entry.entry_uuid == entry_uuid)
        else {
            return Err(VaultError::PublicAddressBookEntryNotFound);
        };
        self.db
            .delete_desktop_wallet_vault_record(&public_address_book_record_key(entry_uuid))?;
        Ok(entry)
    }

    fn active_private_receive_addresses(
        &self,
        view_session: &DesktopViewSession,
    ) -> Result<Vec<String>, VaultError> {
        let mut metadata = self.list_wallet_metadata_with_view(&view_session.view)?;
        metadata.retain(|metadata| metadata.status == WalletStatus::Active);
        let mut addresses = Vec::with_capacity(metadata.len());
        for metadata in metadata {
            let session =
                self.load_view_session_with_view_session(view_session, &metadata.wallet_uuid)?;
            addresses.push(
                session
                    .receive_address()
                    .map_err(|_| VaultError::InvalidPrivateAddressBookAddress)?,
            );
        }
        Ok(addresses)
    }

    pub fn add_derived_public_account(
        &self,
        password: &str,
        view_session: &DesktopViewSession,
        label: Option<&str>,
    ) -> Result<PublicAccountMetadata, VaultError> {
        let vault_metadata = self.metadata()?;
        let view = unlock_view(&vault_metadata, password)?;
        let spend = unlock_spend(&vault_metadata, password)?;
        let wallet_id = view_session.wallet_id();
        let accounts = self.list_public_account_metadata_with_view(&view)?;
        let derivation_index = next_derived_public_account_index(&accounts, wallet_id)?;
        let spend_record = self.encrypted_record(&wallet_spend_record_key(wallet_id))?;
        let spend_bundle = spend.decrypt_spend_bundle(wallet_id, &spend_record)?;
        let address =
            derive_public_evm_address_from_entropy(&spend_bundle.bip39_entropy, derivation_index)?;
        ensure_public_account_address_available(
            &accounts,
            address,
            &PublicAccountScope::PrivateWallet {
                wallet_uuid: wallet_id.to_owned(),
            },
            wallet_id,
        )?;

        let account = PublicAccountMetadata {
            public_account_uuid: generate_opaque_id()?,
            address,
            label: normalize_public_account_label(label),
            source: PublicAccountSource::Derived,
            scope: PublicAccountScope::PrivateWallet {
                wallet_uuid: wallet_id.to_owned(),
            },
            derivation_index: Some(derivation_index),
            status: PublicAccountStatus::Active,
            display_order: next_public_account_display_order(&accounts)?,
        };
        let (key, data) = public_account_metadata_record_entry(&view, &account)?;
        self.db.put_desktop_wallet_vault_record(&key, &data)?;
        Ok(account)
    }

    pub fn import_public_account(
        &self,
        password: &str,
        view_session: &DesktopViewSession,
        private_key_hex: &str,
        label: Option<&str>,
        global: bool,
    ) -> Result<PublicAccountMetadata, VaultError> {
        let vault_metadata = self.metadata()?;
        let view = unlock_view(&vault_metadata, password)?;
        let spend = unlock_spend(&vault_metadata, password)?;
        let private_key = parse_public_evm_private_key(private_key_hex)?;
        let address = public_evm_address_from_private_key(&private_key)?;
        let accounts = self.list_public_account_metadata_with_view(&view)?;
        let scope = if global {
            PublicAccountScope::Global
        } else {
            PublicAccountScope::PrivateWallet {
                wallet_uuid: view_session.wallet_id().to_owned(),
            }
        };
        ensure_public_account_address_available(
            &accounts,
            address,
            &scope,
            view_session.wallet_id(),
        )?;

        let account = PublicAccountMetadata {
            public_account_uuid: generate_opaque_id()?,
            address,
            label: normalize_public_account_label(label),
            source: PublicAccountSource::Imported,
            scope,
            derivation_index: None,
            status: PublicAccountStatus::Active,
            display_order: next_public_account_display_order(&accounts)?,
        };
        let secret = PublicAccountSecret {
            private_key: *private_key,
        };
        let metadata_entry = public_account_metadata_record_entry(&view, &account)?;
        let secret_entry = public_account_secret_record_entry(&spend, &account, &secret)?;
        self.db
            .put_desktop_wallet_vault_records(&[metadata_entry, secret_entry])?;
        Ok(account)
    }

    pub fn update_public_account_label(
        &self,
        view_session: &DesktopViewSession,
        public_account_uuid: &str,
        label: Option<&str>,
    ) -> Result<PublicAccountMetadata, VaultError> {
        let mut accounts = self.list_public_account_metadata_with_view(&view_session.view)?;
        let Some(account) = accounts
            .iter_mut()
            .find(|account| account.public_account_uuid == public_account_uuid)
        else {
            return Err(VaultError::PublicAccountNotFound);
        };
        if !account.is_scoped_to_wallet(view_session.wallet_id()) {
            return Err(VaultError::PublicAccountNotFound);
        }
        account.label = normalize_public_account_label(label);
        let updated = account.clone();
        let (key, data) = public_account_metadata_record_entry(&view_session.view, &updated)?;
        self.db.put_desktop_wallet_vault_record(&key, &data)?;
        Ok(updated)
    }

    pub fn deactivate_derived_public_account(
        &self,
        view_session: &DesktopViewSession,
        public_account_uuid: &str,
    ) -> Result<PublicAccountMetadata, VaultError> {
        let mut accounts = self.list_public_account_metadata_with_view(&view_session.view)?;
        let Some(account) = accounts
            .iter_mut()
            .find(|account| account.public_account_uuid == public_account_uuid)
        else {
            return Err(VaultError::PublicAccountNotFound);
        };
        if !account.is_active_for_wallet(view_session.wallet_id()) {
            return Err(VaultError::PublicAccountNotFound);
        }
        if account.source != PublicAccountSource::Derived {
            return Err(VaultError::InvalidPublicAccountOperation);
        }
        account.status = PublicAccountStatus::Inactive;
        let updated = account.clone();
        let (key, data) = public_account_metadata_record_entry(&view_session.view, &updated)?;
        self.db.put_desktop_wallet_vault_record(&key, &data)?;
        Ok(updated)
    }

    pub fn activate_derived_public_account(
        &self,
        view_session: &DesktopViewSession,
        public_account_uuid: &str,
    ) -> Result<PublicAccountMetadata, VaultError> {
        let mut accounts = self.list_public_account_metadata_with_view(&view_session.view)?;
        let Some(account_index) = accounts
            .iter()
            .position(|account| account.public_account_uuid == public_account_uuid)
        else {
            return Err(VaultError::PublicAccountNotFound);
        };
        let account = &accounts[account_index];
        if !account.is_scoped_to_wallet(view_session.wallet_id()) {
            return Err(VaultError::PublicAccountNotFound);
        }
        if account.source != PublicAccountSource::Derived {
            return Err(VaultError::InvalidPublicAccountOperation);
        }
        if account.status == PublicAccountStatus::Inactive {
            ensure_public_account_address_available(
                &accounts,
                account.address,
                &account.scope,
                view_session.wallet_id(),
            )?;
            accounts[account_index].status = PublicAccountStatus::Active;
        }
        let updated = accounts[account_index].clone();
        let (key, data) = public_account_metadata_record_entry(&view_session.view, &updated)?;
        self.db.put_desktop_wallet_vault_record(&key, &data)?;
        Ok(updated)
    }

    pub fn delete_imported_public_account(
        &self,
        view_session: &DesktopViewSession,
        public_account_uuid: &str,
    ) -> Result<PublicAccountMetadata, VaultError> {
        let accounts = self.list_public_account_metadata_with_view(&view_session.view)?;
        let Some(account) = accounts
            .into_iter()
            .find(|account| account.public_account_uuid == public_account_uuid)
        else {
            return Err(VaultError::PublicAccountNotFound);
        };
        if !account.is_active_for_wallet(view_session.wallet_id()) {
            return Err(VaultError::PublicAccountNotFound);
        }
        if account.source != PublicAccountSource::Imported {
            return Err(VaultError::InvalidPublicAccountOperation);
        }

        self.db
            .delete_desktop_wallet_vault_record(&public_account_metadata_record_key(
                &account.public_account_uuid,
            ))?;
        self.db
            .delete_desktop_wallet_vault_record(&public_account_secret_record_key(
                &account.public_account_uuid,
            ))?;
        Ok(account)
    }

    pub fn public_account_signing_key(
        &self,
        grant: &mut SpendGrant,
        view_session: &DesktopViewSession,
        public_account_uuid: &str,
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
        let accounts = self.list_public_accounts_for_session(view_session, true)?;
        let Some(account) = accounts
            .into_iter()
            .find(|account| account.public_account_uuid == public_account_uuid)
        else {
            return Err(VaultError::PublicAccountNotFound);
        };
        let spend = grant.take_spend_unlock()?;
        match account.source {
            PublicAccountSource::Derived => {
                let Some(derivation_index) = account.derivation_index else {
                    return Err(VaultError::InvalidPublicAccountOperation);
                };
                let wallet_id = view_session.wallet_id();
                let spend_record = self.encrypted_record(&wallet_spend_record_key(wallet_id))?;
                let spend_bundle = spend.decrypt_spend_bundle(wallet_id, &spend_record)?;
                derive_public_evm_private_key_from_entropy(
                    &spend_bundle.bip39_entropy,
                    derivation_index,
                )
            }
            PublicAccountSource::Imported => {
                let record = self.encrypted_record(&public_account_secret_record_key(
                    &account.public_account_uuid,
                ))?;
                let secret =
                    spend.decrypt_public_account_secret(&account.public_account_uuid, &record)?;
                Ok(Zeroizing::new(secret.private_key))
            }
        }
    }

    pub fn store_wallet_metadata(
        &self,
        password: &str,
        metadata: &WalletMetadataBundle,
    ) -> Result<(), VaultError> {
        let view = self.unlock_view(password)?;
        self.store_wallet_metadata_with_view(&view, metadata)
    }

    fn store_wallet_metadata_with_view(
        &self,
        view: &ViewUnlock,
        metadata: &WalletMetadataBundle,
    ) -> Result<(), VaultError> {
        let (key, data) = wallet_metadata_record_entry(view, metadata)?;
        self.db.put_desktop_wallet_vault_record(&key, &data)?;
        Ok(())
    }

    fn store_wallet_metadata_batch_with_view(
        &self,
        view: &ViewUnlock,
        metadata: &[WalletMetadataBundle],
    ) -> Result<(), VaultError> {
        let records = metadata
            .iter()
            .map(|metadata| wallet_metadata_record_entry(view, metadata))
            .collect::<Result<Vec<_>, _>>()?;
        self.db.put_desktop_wallet_vault_records(&records)?;
        Ok(())
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

    pub fn list_wallet_metadata(
        &self,
        password: &str,
    ) -> Result<Vec<WalletMetadataBundle>, VaultError> {
        let view = self.unlock_view(password)?;
        self.list_wallet_metadata_with_view(&view)
    }

    pub fn list_wallet_metadata_for_session(
        &self,
        view_session: &DesktopViewSession,
        include_inactive: bool,
    ) -> Result<Vec<WalletMetadataBundle>, VaultError> {
        let mut metadata = self.list_wallet_metadata_with_view(&view_session.view)?;
        if !include_inactive {
            metadata.retain(|metadata| metadata.status == WalletStatus::Active);
        }
        sort_wallet_metadata(&mut metadata);
        Ok(metadata)
    }

    fn list_wallet_metadata_with_view(
        &self,
        view: &ViewUnlock,
    ) -> Result<Vec<WalletMetadataBundle>, VaultError> {
        let mut wallet_ids = self.list_wallet_ids()?;
        wallet_ids.sort();

        let mut loaded = Vec::with_capacity(wallet_ids.len());
        let mut missing_wallets = Vec::new();
        for wallet_id in wallet_ids {
            let Some(record) =
                self.encrypted_record_optional(&wallet_metadata_record_key(&wallet_id))?
            else {
                let view_record = self.encrypted_record(&wallet_view_record_key(&wallet_id))?;
                let view_bundle = view.decrypt_view_bundle(&wallet_id, &view_record)?;
                missing_wallets.push((wallet_id, view_bundle.derivation_index));
                continue;
            };

            let mut decoded = view.decrypt_wallet_metadata_record(&wallet_id, &record)?;
            if decoded.metadata.wallet_uuid != wallet_id {
                decoded.metadata.wallet_uuid.clone_from(&wallet_id);
                decoded.missing_lifecycle_fields = true;
            }
            loaded.push(LoadedWalletMetadata {
                metadata: decoded.metadata,
                needs_persist: decoded.missing_lifecycle_fields,
                missing_display_order: decoded.missing_display_order,
            });
        }

        for (wallet_id, derivation_index) in missing_wallets {
            let existing = loaded
                .iter()
                .map(|loaded| loaded.metadata.clone())
                .collect::<Vec<_>>();
            let label = default_wallet_label_for_metadata(&existing);
            loaded.push(LoadedWalletMetadata {
                metadata: WalletMetadataBundle {
                    wallet_uuid: wallet_id,
                    label,
                    derivation_index,
                    source: WalletSource::Imported,
                    status: WalletStatus::Active,
                    display_order: 0,
                },
                needs_persist: true,
                missing_display_order: true,
            });
        }

        assign_missing_display_orders(&mut loaded)?;
        if loaded.iter().any(|loaded| loaded.needs_persist) {
            let mut records = Vec::new();
            for loaded in loaded.iter().filter(|loaded| loaded.needs_persist) {
                records.push(wallet_metadata_record_entry(view, &loaded.metadata)?);
            }
            self.db.put_desktop_wallet_vault_records(&records)?;
        }

        let mut metadata = loaded
            .into_iter()
            .map(|loaded| loaded.metadata)
            .collect::<Vec<_>>();
        sort_wallet_metadata(&mut metadata);
        Ok(metadata)
    }

    pub fn active_wallet_metadata(
        &self,
        password: &str,
    ) -> Result<Vec<WalletMetadataBundle>, VaultError> {
        let mut metadata = self.list_wallet_metadata(password)?;
        metadata.retain(|metadata| metadata.status == WalletStatus::Active);
        sort_wallet_metadata(&mut metadata);
        Ok(metadata)
    }

    pub fn default_wallet_label(&self, password: &str) -> Result<String, VaultError> {
        let metadata = self.list_wallet_metadata(password)?;
        Ok(default_wallet_label_for_metadata(&metadata))
    }

    pub fn new_wallet_metadata(
        &self,
        password: &str,
        wallet_uuid: &str,
        derivation_index: u32,
        source: WalletSource,
        label: &str,
    ) -> Result<WalletMetadataBundle, VaultError> {
        let existing = self.list_wallet_metadata(password)?;
        let label = validate_wallet_label(label, &existing, None)?;
        let display_order = next_wallet_display_order(&existing)?;
        Ok(WalletMetadataBundle {
            wallet_uuid: wallet_uuid.to_owned(),
            label,
            derivation_index,
            source,
            status: WalletStatus::Active,
            display_order,
        })
    }

    pub fn update_wallet_label(
        &self,
        password: &str,
        wallet_uuid: &str,
        label: &str,
    ) -> Result<WalletMetadataBundle, VaultError> {
        let view = self.unlock_view(password)?;
        self.update_wallet_label_with_view(&view, wallet_uuid, label)
    }

    pub fn update_wallet_label_for_session(
        &self,
        view_session: &DesktopViewSession,
        wallet_uuid: &str,
        label: &str,
    ) -> Result<WalletMetadataBundle, VaultError> {
        self.update_wallet_label_with_view(&view_session.view, wallet_uuid, label)
    }

    fn update_wallet_label_with_view(
        &self,
        view: &ViewUnlock,
        wallet_uuid: &str,
        label: &str,
    ) -> Result<WalletMetadataBundle, VaultError> {
        let mut metadata = self.list_wallet_metadata_with_view(view)?;
        let label = validate_wallet_label(label, &metadata, Some(wallet_uuid))?;
        let Some(target) = metadata
            .iter_mut()
            .find(|metadata| metadata.wallet_uuid == wallet_uuid)
        else {
            return Err(VaultError::WalletNotFound);
        };
        target.label = label;
        let updated = target.clone();
        self.store_wallet_metadata_with_view(view, &updated)?;
        Ok(updated)
    }

    pub fn reorder_active_wallets(
        &self,
        password: &str,
        ordered_wallet_uuids: &[String],
    ) -> Result<Vec<WalletMetadataBundle>, VaultError> {
        let view = self.unlock_view(password)?;
        self.reorder_active_wallets_with_view(&view, ordered_wallet_uuids)
    }

    pub fn reorder_active_wallets_for_session(
        &self,
        view_session: &DesktopViewSession,
        ordered_wallet_uuids: &[String],
    ) -> Result<Vec<WalletMetadataBundle>, VaultError> {
        self.reorder_active_wallets_with_view(&view_session.view, ordered_wallet_uuids)
    }

    fn reorder_active_wallets_with_view(
        &self,
        view: &ViewUnlock,
        ordered_wallet_uuids: &[String],
    ) -> Result<Vec<WalletMetadataBundle>, VaultError> {
        let mut metadata = self.list_wallet_metadata_with_view(view)?;
        let active_ids = metadata
            .iter()
            .filter(|metadata| metadata.status == WalletStatus::Active)
            .map(|metadata| metadata.wallet_uuid.as_str())
            .collect::<BTreeSet<_>>();
        let submitted_ids = ordered_wallet_uuids
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if active_ids != submitted_ids || submitted_ids.len() != ordered_wallet_uuids.len() {
            return Err(VaultError::InvalidWalletOrder);
        }

        for (display_order, wallet_uuid) in ordered_wallet_uuids.iter().enumerate() {
            let display_order =
                u32::try_from(display_order).map_err(|_| VaultError::WalletDisplayOrderOverflow)?;
            let Some(target) = metadata
                .iter_mut()
                .find(|metadata| metadata.wallet_uuid == *wallet_uuid)
            else {
                return Err(VaultError::InvalidWalletOrder);
            };
            target.display_order = display_order;
        }

        self.store_wallet_metadata_batch_with_view(view, &metadata)?;
        metadata.retain(|metadata| metadata.status == WalletStatus::Active);
        sort_wallet_metadata(&mut metadata);
        Ok(metadata)
    }

    pub fn deactivate_wallet(
        &self,
        password: &str,
        wallet_uuid: &str,
    ) -> Result<WalletMetadataBundle, VaultError> {
        let view = self.unlock_view(password)?;
        self.set_wallet_active_with_view(&view, wallet_uuid, false)
    }

    pub fn set_wallet_active_for_session(
        &self,
        view_session: &DesktopViewSession,
        wallet_uuid: &str,
        active: bool,
    ) -> Result<WalletMetadataBundle, VaultError> {
        self.set_wallet_active_with_view(&view_session.view, wallet_uuid, active)
    }

    fn set_wallet_active_with_view(
        &self,
        view: &ViewUnlock,
        wallet_uuid: &str,
        active: bool,
    ) -> Result<WalletMetadataBundle, VaultError> {
        let mut metadata = self.list_wallet_metadata_with_view(view)?;
        let active_count = metadata
            .iter()
            .filter(|metadata| metadata.status == WalletStatus::Active)
            .count();
        let Some(target_index) = metadata
            .iter()
            .position(|metadata| metadata.wallet_uuid == wallet_uuid)
        else {
            return Err(VaultError::WalletNotFound);
        };

        let target_status = metadata[target_index].status;
        if active {
            if target_status == WalletStatus::Active {
                return Ok(metadata[target_index].clone());
            }
            metadata[target_index].status = WalletStatus::Active;
            metadata[target_index].display_order = next_wallet_display_order(&metadata)?;
        } else {
            if target_status == WalletStatus::Inactive {
                return Ok(metadata[target_index].clone());
            }
            if active_count <= 1 {
                return Err(VaultError::LastActiveWallet);
            }
            metadata[target_index].status = WalletStatus::Inactive;
        }

        let updated = metadata[target_index].clone();
        self.store_wallet_metadata_with_view(view, &updated)?;
        Ok(updated)
    }

    pub fn delete_wallet_for_session(
        &self,
        view_session: &DesktopViewSession,
        wallet_uuid: &str,
    ) -> Result<WalletMetadataBundle, VaultError> {
        self.delete_wallet_with_view(&view_session.view, wallet_uuid)
    }

    fn delete_wallet_with_view(
        &self,
        view: &ViewUnlock,
        wallet_uuid: &str,
    ) -> Result<WalletMetadataBundle, VaultError> {
        let metadata = self.list_wallet_metadata_with_view(view)?;
        let Some(target) = metadata
            .iter()
            .find(|metadata| metadata.wallet_uuid == wallet_uuid)
            .cloned()
        else {
            return Err(VaultError::WalletNotFound);
        };
        let active_count = metadata
            .iter()
            .filter(|metadata| metadata.status == WalletStatus::Active)
            .count();
        if target.status == WalletStatus::Active && active_count <= 1 {
            return Err(VaultError::LastActiveWallet);
        }

        let mut keys_to_delete = vec![
            wallet_metadata_record_key(wallet_uuid),
            wallet_view_record_key(wallet_uuid),
            wallet_spend_record_key(wallet_uuid),
        ];

        let chain_records = self
            .db
            .list_desktop_wallet_vault_records(WALLET_CHAIN_METADATA_PREFIX)?;
        for stored in chain_records {
            let Some(wallet_chain_uuid) = stored.key.strip_prefix(WALLET_CHAIN_METADATA_PREFIX)
            else {
                continue;
            };
            let record: EncryptedRecord = rmp_serde::from_slice(&stored.payload)?;
            let metadata = view.decrypt_wallet_chain_metadata(wallet_chain_uuid, &record)?;
            if metadata.wallet_uuid != wallet_uuid {
                continue;
            }
            let cache_rows = self
                .db
                .list_desktop_wallet_vault_records(&wallet_cache_row_prefix(wallet_chain_uuid))?;
            keys_to_delete.push(stored.key);
            keys_to_delete.extend(cache_rows.into_iter().map(|row| row.key));
        }

        for account in self.list_public_account_metadata_with_view(view)? {
            if matches!(
                &account.scope,
                PublicAccountScope::PrivateWallet { wallet_uuid: scoped } if scoped == wallet_uuid
            ) {
                keys_to_delete.push(public_account_metadata_record_key(
                    &account.public_account_uuid,
                ));
                keys_to_delete.push(public_account_secret_record_key(
                    &account.public_account_uuid,
                ));
            }
        }

        for key in keys_to_delete {
            self.db.delete_desktop_wallet_vault_record(&key)?;
        }

        Ok(target)
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
        if let Some(metadata) = self.find_wallet_chain_metadata_for_session(
            view_session,
            chain_type,
            chain_id,
            contract,
        )? {
            return Ok(metadata);
        }

        self.create_wallet_chain_metadata_for_session(
            view_session,
            chain_type,
            chain_id,
            contract,
            start_block,
            start_block.saturating_sub(1),
        )
    }

    pub fn find_wallet_chain_metadata_for_session(
        &self,
        view_session: &DesktopViewSession,
        chain_type: u8,
        chain_id: u64,
        contract: &str,
    ) -> Result<Option<WalletChainMetadataBundle>, VaultError> {
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
                return Ok(Some(metadata));
            }
        }

        Ok(None)
    }

    pub fn create_wallet_chain_metadata_for_session(
        &self,
        view_session: &DesktopViewSession,
        chain_type: u8,
        chain_id: u64,
        contract: &str,
        start_block: u64,
        last_scanned_block: u64,
    ) -> Result<WalletChainMetadataBundle, VaultError> {
        let wallet_chain_uuid = generate_opaque_id()?;
        let metadata = WalletChainMetadataBundle {
            wallet_chain_uuid,
            wallet_uuid: view_session.wallet_id().to_owned(),
            chain_type,
            chain_id,
            contract: contract.to_owned(),
            start_block,
            last_scanned_block,
            last_scanned_block_hash: None,
            poi_read_source: None,
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

    fn encrypted_record_optional(&self, key: &str) -> Result<Option<EncryptedRecord>, VaultError> {
        self.db
            .get_desktop_wallet_vault_record(key)?
            .map(|data| rmp_serde::from_slice(&data).map_err(VaultError::from))
            .transpose()
    }

    fn put_encrypted_record(&self, key: &str, record: &EncryptedRecord) -> Result<(), VaultError> {
        let (_, data) = record.to_record_entry(key.to_string())?;
        self.db.put_desktop_wallet_vault_record(key, &data)?;
        Ok(())
    }

    fn list_public_account_metadata_with_view(
        &self,
        view: &ViewUnlock,
    ) -> Result<Vec<PublicAccountMetadata>, VaultError> {
        let records = self
            .db
            .list_desktop_wallet_vault_records(PUBLIC_ACCOUNT_METADATA_PREFIX)?;
        let mut accounts = Vec::with_capacity(records.len());
        for stored in records {
            let Some(public_account_uuid) = stored.key.strip_prefix(PUBLIC_ACCOUNT_METADATA_PREFIX)
            else {
                continue;
            };
            let record: EncryptedRecord = rmp_serde::from_slice(&stored.payload)?;
            let mut account = view.decrypt_public_account_metadata(public_account_uuid, &record)?;
            if account.public_account_uuid != public_account_uuid {
                public_account_uuid.clone_into(&mut account.public_account_uuid);
            }
            accounts.push(account);
        }
        sort_public_account_metadata(&mut accounts);
        Ok(accounts)
    }

    fn list_private_address_book_entries_with_view(
        &self,
        view: &ViewUnlock,
    ) -> Result<Vec<PrivateAddressBookEntry>, VaultError> {
        let records = self
            .db
            .list_desktop_wallet_vault_records(PRIVATE_ADDRESS_BOOK_PREFIX)?;
        let mut entries = Vec::with_capacity(records.len());
        for stored in records {
            let Some(entry_uuid) = stored.key.strip_prefix(PRIVATE_ADDRESS_BOOK_PREFIX) else {
                continue;
            };
            let record: EncryptedRecord = rmp_serde::from_slice(&stored.payload)?;
            let mut entry = view.decrypt_private_address_book_entry(entry_uuid, &record)?;
            if entry.entry_uuid != entry_uuid {
                entry_uuid.clone_into(&mut entry.entry_uuid);
            }
            entries.push(entry);
        }
        sort_private_address_book_entries(&mut entries);
        Ok(entries)
    }

    fn list_public_address_book_entries_with_view(
        &self,
        view: &ViewUnlock,
    ) -> Result<Vec<PublicAddressBookEntry>, VaultError> {
        let records = self
            .db
            .list_desktop_wallet_vault_records(PUBLIC_ADDRESS_BOOK_PREFIX)?;
        let mut entries = Vec::with_capacity(records.len());
        for stored in records {
            let Some(entry_uuid) = stored.key.strip_prefix(PUBLIC_ADDRESS_BOOK_PREFIX) else {
                continue;
            };
            let record: EncryptedRecord = rmp_serde::from_slice(&stored.payload)?;
            let mut entry = view.decrypt_public_address_book_entry(entry_uuid, &record)?;
            if entry.entry_uuid != entry_uuid {
                entry_uuid.clone_into(&mut entry.entry_uuid);
            }
            entries.push(entry);
        }
        sort_public_address_book_entries(&mut entries);
        Ok(entries)
    }

    fn list_broadcaster_favorite_entries_with_view(
        &self,
        view: &ViewUnlock,
    ) -> Result<Vec<LoadedBroadcasterPreferenceEntry>, VaultError> {
        self.list_broadcaster_preference_entries_with_view(
            view,
            BROADCASTER_FAVORITE_PREFIX,
            RecordKind::BroadcasterFavoriteEntry,
            "favorite",
        )
    }

    fn list_broadcaster_banned_entries_with_view(
        &self,
        view: &ViewUnlock,
    ) -> Result<Vec<LoadedBroadcasterPreferenceEntry>, VaultError> {
        self.list_broadcaster_preference_entries_with_view(
            view,
            BROADCASTER_BANNED_PREFIX,
            RecordKind::BroadcasterBannedEntry,
            "banned",
        )
    }

    fn list_broadcaster_preference_entries_with_view(
        &self,
        view: &ViewUnlock,
        prefix: &str,
        kind: RecordKind,
        preference_kind: &str,
    ) -> Result<Vec<LoadedBroadcasterPreferenceEntry>, VaultError> {
        let records = self.db.list_desktop_wallet_vault_records(prefix)?;
        let mut entries = Vec::with_capacity(records.len());
        let mut seen = BTreeSet::new();
        for stored in records {
            let Some(entry_uuid) = stored.key.strip_prefix(prefix) else {
                continue;
            };
            let Ok(record) = rmp_serde::from_slice::<EncryptedRecord>(&stored.payload) else {
                tracing::warn!(
                    kind = preference_kind,
                    "ignoring invalid broadcaster preference record"
                );
                continue;
            };
            let Ok(entry) = view.decrypt_broadcaster_preference_entry(kind, entry_uuid, &record)
            else {
                tracing::warn!(
                    kind = preference_kind,
                    "ignoring undecryptable broadcaster preference record"
                );
                continue;
            };
            let Ok(identity) = broadcaster_preference_entry_identity(&entry) else {
                tracing::warn!(
                    kind = preference_kind,
                    "ignoring invalid broadcaster preference address"
                );
                continue;
            };
            if seen.insert(identity) {
                entries.push(LoadedBroadcasterPreferenceEntry {
                    entry_uuid: entry_uuid.to_owned(),
                    entry,
                    identity,
                });
            }
        }
        entries.sort_by(|left, right| left.entry.address.cmp(&right.entry.address));
        Ok(entries)
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
        let existing_public_accounts = if metadata.is_some() {
            self.list_public_account_metadata_with_view(&view)?
        } else {
            Vec::new()
        };

        let view_record = view.encrypt_view_bundle(wallet_id, &view_bundle)?;
        let spend_record = spend.encrypt_spend_bundle(wallet_id, &spend_bundle)?;
        let view_record_key = wallet_view_record_key(wallet_id);
        let spend_record_key = wallet_spend_record_key(wallet_id);
        let mut records = Vec::with_capacity(2 + usize::from(metadata.is_some()) * 2);
        records.push(view_record.to_record_entry(view_record_key.clone())?);
        records.push(spend_record.to_record_entry(spend_record_key.clone())?);

        if let Some(metadata) = metadata {
            let record = view.encrypt_wallet_metadata(&metadata.wallet_uuid, metadata)?;
            records
                .push(record.to_record_entry(wallet_metadata_record_key(&metadata.wallet_uuid))?);

            let public_account =
                initial_derived_public_account(wallet_id, entropy, &existing_public_accounts)?;
            records.push(public_account_metadata_record_entry(
                &view,
                &public_account,
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
