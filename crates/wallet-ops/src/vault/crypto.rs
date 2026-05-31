use super::{
    Aead, Algorithm, Argon2, CreatedVault, DeserializeOwned, EncryptedRecord,
    GeneratedSeedMaterial, Hkdf, KEY_LEN, KdfParams, KeyInit, NONCE_LEN, Params, Payload,
    RecordKind, SALT_LEN, SecretKey, Serialize, Sha256, SpendGrant, SpendUnlock, VAULT_VERSION,
    VaultError, VaultMetadata, Version, ViewUnlock, XChaCha20Poly1305, XNonce, Zeroize, Zeroizing,
    bip39_mnemonic_from_entropy, fill,
};

#[must_use]
pub const fn current_vault_version() -> u32 {
    VAULT_VERSION
}

#[must_use]
pub const fn legacy_vault_version() -> u32 {
    1
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
    if version == VAULT_VERSION || version == legacy_vault_version() {
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
    let aad = kind.aad(record_id);
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
    let aad = kind.aad(record_id);
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
