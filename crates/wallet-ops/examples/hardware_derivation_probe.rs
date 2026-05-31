use std::env;

use eyre::{Result, eyre};
use wallet_ops::hardware::{
    DEFAULT_HARDWARE_DERIVATION_PATH, HardwareDerivationClient, HardwareDerivationDescriptor,
    HardwareWalletSyncIntent, parse_bip32_path,
};
use wallet_ops::hardware::{
    ledger::LedgerHardwareDerivationClient, trezor::TrezorHardwareDerivationClient,
};

fn main() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run())
}

async fn run() -> Result<()> {
    let command = env::args().nth(1).unwrap_or_else(|| "all".to_owned());
    match command.as_str() {
        "all" => {
            ledger_version().await?;
            ledger_eip1024().await?;
            trezor_features()?;
            trezor_cipher().await?;
        }
        "ledger-version" => ledger_version().await?,
        "ledger-eip1024" => ledger_eip1024().await?,
        "trezor-features" => trezor_features()?,
        "trezor-cipher" => trezor_cipher().await?,
        _ => {
            return Err(eyre!(
                "unknown command; use all, ledger-version, ledger-eip1024, trezor-features, or trezor-cipher"
            ));
        }
    }
    Ok(())
}

async fn ledger_version() -> Result<()> {
    let client = LedgerHardwareDerivationClient::connect().await?;
    let version = client.ethereum_app_version().await?;
    println!("Ledger Ethereum app version: {version}");
    Ok(())
}

async fn ledger_eip1024() -> Result<()> {
    let mut client = LedgerHardwareDerivationClient::connect().await?;
    let profile_fingerprint = client
        .profile_fingerprint(&parse_bip32_path(DEFAULT_HARDWARE_DERIVATION_PATH)?)
        .await?;
    let descriptor = HardwareDerivationDescriptor::ledger_eip1024_v1(
        parse_bip32_path(DEFAULT_HARDWARE_DERIVATION_PATH)?,
        0,
        profile_fingerprint,
        HardwareWalletSyncIntent::CreateNew,
    );
    println!("Approve the Ledger EIP-1024 shared-secret request on the device.");
    let output = client.derive_hardware_output(&descriptor).await?;
    println!(
        "Ledger EIP-1024 shared-secret operation succeeded with {} bytes.",
        output.expose_secret().len()
    );
    drop(output);
    Ok(())
}

fn trezor_features() -> Result<()> {
    let client = TrezorHardwareDerivationClient::connect()?;
    let info = client.device_info()?;
    println!("Trezor model: {}", info.model);
    println!("Trezor vendor: {}", info.vendor);
    println!("Trezor firmware version: {}", info.version);
    println!("Trezor initialized: {}", info.initialized);
    println!(
        "Trezor passphrase protection: {}",
        info.passphrase_protection
    );
    println!("Trezor bootloader mode: {}", info.bootloader_mode);
    Ok(())
}

async fn trezor_cipher() -> Result<()> {
    let mut client = TrezorHardwareDerivationClient::connect()?;
    let profile_fingerprint =
        client.profile_fingerprint(&parse_bip32_path(DEFAULT_HARDWARE_DERIVATION_PATH)?)?;
    let descriptor = HardwareDerivationDescriptor::trezor_cipher_key_value_v1(
        parse_bip32_path(DEFAULT_HARDWARE_DERIVATION_PATH)?,
        0,
        profile_fingerprint,
        HardwareWalletSyncIntent::CreateNew,
    );
    println!("Approve the Trezor CipherKeyValue request on the device.");
    let output = client.derive_hardware_output(&descriptor).await?;
    println!(
        "Trezor CipherKeyValue operation succeeded with {} bytes.",
        output.expose_secret().len()
    );
    drop(output);
    Ok(())
}
