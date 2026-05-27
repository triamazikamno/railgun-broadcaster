use super::{
    Arc, CacheKeys, DbStore, DesktopEncryptedWalletCacheStore, DesktopViewSession, EncryptedRecord,
    Instant, KEY_LEN, Mutex, RailgunError, U256, VaultError, ViewUnlock, ViewingKeyData,
    WalletCacheError, WalletChainMetadataBundle, WalletMeta, WalletUtxo, WalletViewBundle,
    deserialize_wallet_utxo, serialize_wallet_utxo, wallet_cache_counts, wallet_cache_row_prefix,
    wallet_cache_row_record_key, wallet_chain_metadata_record_key, wallet_utxo_stable_identity,
};

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
            spending_public_key: bundle.spending_public_key(),
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

    #[must_use]
    pub const fn spending_public_key(&self) -> [U256; 2] {
        self.spending_public_key
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
        let started = Instant::now();
        let wallet_chain_uuid = self.wallet_chain_uuid()?;
        let encode_started = Instant::now();
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
        let encode_elapsed_ms = encode_started.elapsed().as_millis();

        let (unspent, spent) = wallet_cache_counts(utxos);
        if let Some(last_scanned_block) = last_scanned_block {
            let metadata_started = Instant::now();
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
            tracing::debug!(
                wallet_chain_uuid = %metadata.wallet_chain_uuid,
                last_scanned_block,
                elapsed_ms = metadata_started.elapsed().as_millis(),
                "encoded encrypted desktop wallet cache metadata"
            );
        }

        let db_started = Instant::now();
        if let Err(err) = self.db.put_desktop_wallet_vault_records(&records) {
            tracing::debug!(
                ?err,
                wallet_chain_uuid,
                rows = utxos.len(),
                records = records.len(),
                encode_elapsed_ms,
                db_elapsed_ms = db_started.elapsed().as_millis(),
                elapsed_ms = started.elapsed().as_millis(),
                "failed to upsert encrypted desktop wallet cache"
            );
            return Err(err.into());
        }
        tracing::debug!(
            wallet_chain_uuid,
            rows = utxos.len(),
            records = records.len(),
            unspent,
            spent,
            last_scanned_block,
            encode_elapsed_ms,
            db_elapsed_ms = db_started.elapsed().as_millis(),
            elapsed_ms = started.elapsed().as_millis(),
            "upserted encrypted desktop wallet cache"
        );

        Ok(())
    }

    fn load_wallet_utxos(&self, _wallet_id: &str) -> Result<Vec<WalletUtxo>, WalletCacheError> {
        let started = Instant::now();
        let wallet_chain_uuid = self.wallet_chain_uuid()?;
        let row_prefix = wallet_cache_row_prefix(&wallet_chain_uuid);
        let db_started = Instant::now();
        let records = self.db.list_desktop_wallet_vault_records(&row_prefix)?;
        let db_elapsed_ms = db_started.elapsed().as_millis();
        let decode_started = Instant::now();
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
            db_elapsed_ms,
            decode_elapsed_ms = decode_started.elapsed().as_millis(),
            elapsed_ms = started.elapsed().as_millis(),
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
        let started = Instant::now();
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
            elapsed_ms = started.elapsed().as_millis(),
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

    fn replace_wallet_cache(
        &self,
        _wallet_id: &str,
        utxos: &[WalletUtxo],
        last_scanned_block: u64,
        last_scanned_block_hash: Option<[u8; KEY_LEN]>,
    ) -> Result<(), WalletCacheError> {
        let started = Instant::now();
        let wallet_chain_uuid = self.wallet_chain_uuid()?;
        let row_prefix = wallet_cache_row_prefix(&wallet_chain_uuid);
        let encode_started = Instant::now();
        let mut records = Vec::with_capacity(utxos.len() + 1);

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
        let encode_elapsed_ms = encode_started.elapsed().as_millis();
        drop(metadata);

        let db_started = Instant::now();
        self.db
            .replace_desktop_wallet_vault_prefix_with_records(&row_prefix, &records)?;
        let (unspent, spent) = wallet_cache_counts(utxos);
        tracing::debug!(
            wallet_chain_uuid,
            rows = utxos.len(),
            records = records.len(),
            unspent,
            spent,
            last_scanned_block,
            encode_elapsed_ms,
            db_elapsed_ms = db_started.elapsed().as_millis(),
            elapsed_ms = started.elapsed().as_millis(),
            "replaced encrypted desktop wallet cache"
        );
        Ok(())
    }
}
