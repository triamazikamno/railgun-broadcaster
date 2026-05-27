use super::{
    DbStore, WALLET_SETTINGS_KEY, WALLET_SETTINGS_VERSION, WalletSettings, WalletSettingsError,
};

pub fn load_wallet_settings(store: &DbStore) -> Result<WalletSettings, WalletSettingsError> {
    let Some(payload) = store.get_app_settings_record(WALLET_SETTINGS_KEY)? else {
        return Ok(WalletSettings::default());
    };
    decode_wallet_settings(&payload)
}

pub fn save_wallet_settings(
    store: &DbStore,
    settings: &WalletSettings,
) -> Result<(), WalletSettingsError> {
    let mut settings = settings.clone();
    settings.version = WALLET_SETTINGS_VERSION;
    settings.validate()?;
    let payload = encode_wallet_settings(&settings)?;
    store.put_app_settings_record(WALLET_SETTINGS_KEY, &payload)?;
    Ok(())
}

pub fn delete_wallet_settings(store: &DbStore) -> Result<(), WalletSettingsError> {
    store.delete_app_settings_record(WALLET_SETTINGS_KEY)?;
    Ok(())
}

pub fn encode_wallet_settings(settings: &WalletSettings) -> Result<Vec<u8>, WalletSettingsError> {
    let mut settings = settings.clone();
    settings.version = WALLET_SETTINGS_VERSION;
    Ok(rmp_serde::to_vec_named(&settings)?)
}

pub fn decode_wallet_settings(data: &[u8]) -> Result<WalletSettings, WalletSettingsError> {
    let settings: WalletSettings = rmp_serde::from_slice(data)?;
    if settings.version != WALLET_SETTINGS_VERSION {
        return Err(WalletSettingsError::UnsupportedVersion {
            version: settings.version,
        });
    }
    Ok(settings)
}
