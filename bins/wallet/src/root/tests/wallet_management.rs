use super::*;
use crate::root::manage_wallets::wallet_management_switch_requires_device;

fn hardware_wallet_metadata(
    wallet_uuid: &str,
    label: &str,
    device_kind: wallet_ops::hardware::HardwareDeviceKind,
    status: WalletStatus,
    display_order: u32,
    account_index: u32,
    profile_fingerprint: &str,
) -> WalletMetadataBundle {
    let path = wallet_ops::hardware::parse_bip32_path("m/44'/60'/0'/0/0").expect("valid path");
    let descriptor = match device_kind {
        wallet_ops::hardware::HardwareDeviceKind::Ledger => {
            wallet_ops::hardware::HardwareDerivationDescriptor::ledger_eip1024_v1(
                path,
                account_index,
                profile_fingerprint.to_owned(),
                wallet_ops::hardware::HardwareWalletSyncIntent::CreateNew,
            )
        }
        wallet_ops::hardware::HardwareDeviceKind::Trezor => {
            wallet_ops::hardware::HardwareDerivationDescriptor::trezor_cipher_key_value_v1(
                path,
                account_index,
                profile_fingerprint.to_owned(),
                wallet_ops::hardware::HardwareWalletSyncIntent::CreateNew,
            )
        }
    };
    let profile = wallet_ops::vault::HardwareProfileMetadata::from_descriptor(&descriptor);
    let identity = wallet_ops::vault::HardwareRailgunAccountIdentity {
        spending_public_key: [[0; 32]; 2],
        viewing_public_key: [0; 32],
    };
    let mut wallet = wallet_metadata(
        wallet_uuid,
        label,
        WalletSource::from_hardware_device_kind(device_kind),
        status,
        display_order,
    );
    wallet.hardware_account = Some(
        wallet_ops::vault::HardwareRailgunAccountMetadata::synthetic_software_v1(
            profile.profile_id,
            account_index,
            label,
            descriptor,
            identity,
        ),
    );
    wallet
}

#[test]
fn wallet_options_hide_inactive_and_sort_active_metadata() {
    let options = wallet_options_from_metadata(vec![
        wallet_metadata(
            "wallet-b",
            "Beta",
            WalletSource::Imported,
            WalletStatus::Active,
            2,
        ),
        wallet_metadata(
            "wallet-hidden",
            "Hidden",
            WalletSource::Imported,
            WalletStatus::Inactive,
            0,
        ),
        wallet_metadata(
            "wallet-a",
            "Alpha",
            WalletSource::Generated,
            WalletStatus::Active,
            1,
        ),
    ]);

    assert_eq!(options.len(), 2);
    assert_eq!(options[0].wallet_id.as_ref(), "wallet-a");
    assert_eq!(options[0].source, WalletSource::Generated);
    assert_eq!(options[1].wallet_id.as_ref(), "wallet-b");
}

#[test]
fn wallet_select_items_group_hardware_accounts_by_device() {
    let items = crate::root::vault::wallet_select_items_from_metadata(&[
        wallet_metadata(
            "wallet-a",
            "Alpha",
            WalletSource::Generated,
            WalletStatus::Active,
            0,
        ),
        hardware_wallet_metadata(
            "ledger-0",
            "Ledger account 0",
            wallet_ops::hardware::HardwareDeviceKind::Ledger,
            WalletStatus::Active,
            1,
            0,
            "ledger:evm:0x1111111111111111111111111111111111111111",
        ),
        hardware_wallet_metadata(
            "ledger-1",
            "Ledger account 1",
            wallet_ops::hardware::HardwareDeviceKind::Ledger,
            WalletStatus::Active,
            2,
            1,
            "ledger:evm:0x1111111111111111111111111111111111111111",
        ),
        hardware_wallet_metadata(
            "trezor-0",
            "Trezor account 0",
            wallet_ops::hardware::HardwareDeviceKind::Trezor,
            WalletStatus::Active,
            3,
            0,
            "trezor:evm:0x2222222222222222222222222222222222222222",
        ),
    ]);

    assert_eq!(
        items
            .iter()
            .map(|item| item.label.as_ref())
            .collect::<Vec<_>>(),
        vec!["Alpha", "Ledger", "Trezor"]
    );
    assert_eq!(
        items
            .iter()
            .map(|item| item.wallet_id.as_ref())
            .collect::<Vec<_>>(),
        vec![
            "wallet-a",
            crate::root::vault::hardware_device_wallet_select_value(
                wallet_ops::hardware::HardwareDeviceKind::Ledger,
            ),
            crate::root::vault::hardware_device_wallet_select_value(
                wallet_ops::hardware::HardwareDeviceKind::Trezor,
            ),
        ]
    );
}

#[test]
fn wallet_select_items_only_show_hardware_device_with_active_account() {
    let legacy_descriptor_only = wallet_metadata(
        "legacy-ledger",
        "Legacy Ledger",
        WalletSource::LedgerDerived,
        WalletStatus::Active,
        0,
    );
    let hidden_ledger = hardware_wallet_metadata(
        "hidden-ledger",
        "Hidden Ledger",
        wallet_ops::hardware::HardwareDeviceKind::Ledger,
        WalletStatus::Inactive,
        1,
        0,
        "ledger:evm:0x1111111111111111111111111111111111111111",
    );
    let items = crate::root::vault::wallet_select_items_from_metadata(&[
        legacy_descriptor_only,
        hidden_ledger,
        wallet_metadata(
            "wallet-a",
            "Alpha",
            WalletSource::Imported,
            WalletStatus::Active,
            2,
        ),
    ]);

    assert_eq!(items.len(), 1);
    assert_eq!(items[0].wallet_id.as_ref(), "wallet-a");
}

#[test]
fn selected_hardware_wallet_maps_to_device_selector_value() {
    let metadata = vec![hardware_wallet_metadata(
        "ledger-1",
        "Ledger account 1",
        wallet_ops::hardware::HardwareDeviceKind::Ledger,
        WalletStatus::Active,
        0,
        1,
        "ledger:evm:0x1111111111111111111111111111111111111111",
    )];
    let selected_wallet_id = Arc::<str>::from("ledger-1");

    assert_eq!(
        crate::root::vault::wallet_select_value_for_selected_wallet(
            &selected_wallet_id,
            &metadata,
        )
        .as_ref(),
        crate::root::vault::hardware_device_wallet_select_value(
            wallet_ops::hardware::HardwareDeviceKind::Ledger,
        )
    );
}

#[test]
fn hardware_wallet_display_info_compacts_profile_account_label() {
    let wallet = hardware_wallet_metadata(
        "trezor-0",
        "Trezor hardware profile 2 account 0",
        wallet_ops::hardware::HardwareDeviceKind::Trezor,
        WalletStatus::Active,
        0,
        0,
        "trezor:evm:0x2222222222222222222222222222222222222222",
    );

    let info = crate::root::vault::hardware_wallet_display_info(&wallet, None)
        .expect("hardware wallet display info");

    assert_eq!(info.chip_label, "Profile 2 / Account 0");
    assert_eq!(
        info.detail_label,
        "Trezor: Trezor hardware profile 2 account 0"
    );
}

#[test]
fn hardware_wallet_display_info_uses_active_profile_label() {
    let wallet = hardware_wallet_metadata(
        "trezor-0",
        "Trezor hardware profile 2 account 0",
        wallet_ops::hardware::HardwareDeviceKind::Trezor,
        WalletStatus::Active,
        0,
        0,
        "trezor:evm:0x2222222222222222222222222222222222222222",
    );
    let account = wallet.hardware_account.as_ref().expect("hardware account");
    let mut profile =
        wallet_ops::vault::HardwareProfileMetadata::from_descriptor(&account.descriptor);
    profile.profile_id.clone_from(&account.profile_id);
    profile.label = "Main Trezor".to_owned();

    let info = crate::root::vault::hardware_wallet_display_info(&wallet, Some(&profile))
        .expect("hardware wallet display info");

    assert_eq!(info.chip_label, "Main Trezor / Account 0");
    assert_eq!(info.detail_label, "Trezor: Main Trezor account 0");
}

#[test]
fn hardware_wallet_display_info_combines_profile_and_renamed_wallet_label() {
    let mut wallet = hardware_wallet_metadata(
        "trezor-0",
        "Trezor hardware profile 2 account 0",
        wallet_ops::hardware::HardwareDeviceKind::Trezor,
        WalletStatus::Active,
        0,
        0,
        "trezor:evm:0x2222222222222222222222222222222222222222",
    );
    let account = wallet.hardware_account.as_ref().expect("hardware account");
    let mut profile =
        wallet_ops::vault::HardwareProfileMetadata::from_descriptor(&account.descriptor);
    profile.profile_id.clone_from(&account.profile_id);
    profile.label = "Main Trezor".to_owned();
    wallet.label = "pp1 account 0".to_owned();

    let info = crate::root::vault::hardware_wallet_display_info(&wallet, Some(&profile))
        .expect("hardware wallet display info");

    assert_eq!(info.chip_label, "Main Trezor / pp1");
    assert_eq!(info.detail_label, "Trezor: Main Trezor / pp1 account 0");
}

#[test]
fn wallet_management_rows_split_and_sort_like_selector() {
    let metadata = vec![
        wallet_metadata(
            "wallet-b",
            "Beta",
            WalletSource::Imported,
            WalletStatus::Active,
            2,
        ),
        wallet_metadata(
            "wallet-hidden",
            "Hidden",
            WalletSource::Imported,
            WalletStatus::Inactive,
            0,
        ),
        wallet_metadata(
            "wallet-a",
            "Alpha",
            WalletSource::Generated,
            WalletStatus::Active,
            1,
        ),
    ];

    let active = active_wallet_management_rows(&metadata);
    let hidden = hidden_wallet_management_rows(&metadata);

    assert_eq!(
        active
            .iter()
            .map(|metadata| metadata.wallet_uuid.as_str())
            .collect::<Vec<_>>(),
        vec!["wallet-a", "wallet-b"]
    );
    assert_eq!(hidden.len(), 1);
    assert_eq!(hidden[0].wallet_uuid, "wallet-hidden");
}

#[test]
fn wallet_source_label_includes_hardware_descriptor_details() {
    let mut wallet = wallet_metadata(
        "wallet-ledger",
        "Ledger",
        WalletSource::LedgerDerived,
        WalletStatus::Active,
        0,
    );
    wallet.hardware_descriptor = Some(
        wallet_ops::hardware::HardwareDerivationDescriptor::ledger_eip1024_v1(
            wallet_ops::hardware::parse_bip32_path("m/44'/60'/0'/0/0").expect("valid path"),
            2,
            "ledger:evm:0x1111111111111111111111111111111111111111".to_string(),
            wallet_ops::hardware::HardwareWalletSyncIntent::RecoverExisting,
        ),
    );

    assert_eq!(
        wallet_source_label(&wallet),
        "Ledger-derived wallet - account 2"
    );
}

#[test]
fn hardware_setup_copy_covers_choices_and_passphrase_guidance() {
    assert_eq!(
        crate::root::vault_ui::hardware_create_button_id(
            wallet_ops::hardware::HardwareDeviceKind::Ledger,
        ),
        "create-ledger-derived-wallet"
    );
    assert_eq!(
        crate::root::vault_ui::hardware_recover_button_id(
            wallet_ops::hardware::HardwareDeviceKind::Trezor,
        ),
        "recover-trezor-derived-wallet"
    );

    let copy = crate::root::vault_ui::hardware_setup_notice_lines(
        wallet_ops::hardware::HardwareDeviceKind::Ledger,
    )
    .join("\n");
    assert!(copy.contains("Connect your Ledger"));
    assert!(copy.contains("hardware passphrase wallet"));
    assert!(copy.contains("Do not enter that passphrase into this app"));
    assert!(copy.contains("Create new starts from the current safe head"));
    assert!(copy.contains("Recover existing backfills from deployment"));
    assert!(copy.contains("not true hardware signing"));

    let progress_title = crate::root::vault_ui::hardware_setup_progress_title(
        wallet_ops::hardware::HardwareDeviceKind::Ledger,
    );
    let progress_detail = crate::root::vault_ui::hardware_setup_progress_detail(
        wallet_ops::hardware::HardwareDeviceKind::Ledger,
    );
    assert_eq!(progress_title, "Waiting for Ledger approval");
    assert!(progress_detail.contains("Check your Ledger"));
    assert!(progress_detail.contains("public key or shared secret"));
}

#[test]
fn hardware_setup_enter_retries_last_sync_intent() {
    assert_eq!(
        default_hardware_wallet_setup_intent(None, false),
        wallet_ops::hardware::HardwareWalletSyncIntent::CreateNew,
    );
    assert_eq!(
        default_hardware_wallet_setup_intent(
            Some(wallet_ops::hardware::HardwareWalletSyncIntent::RecoverExisting,),
            false
        ),
        wallet_ops::hardware::HardwareWalletSyncIntent::RecoverExisting,
    );
    assert_eq!(
        default_hardware_wallet_setup_intent(
            Some(wallet_ops::hardware::HardwareWalletSyncIntent::CreateNew),
            true,
        ),
        wallet_ops::hardware::HardwareWalletSyncIntent::RecoverExisting,
    );
}

#[test]
fn stale_hardware_setup_result_is_rejected_after_generation_change() {
    assert!(hardware_wallet_creation_result_is_current(3, 3));
    assert!(!hardware_wallet_creation_result_is_current(4, 3));
}

#[test]
fn hardware_restore_account_index_input_parses_optional_index() {
    assert_eq!(parse_hardware_wallet_restore_account_index(""), Ok(None));
    assert_eq!(
        parse_hardware_wallet_restore_account_index("  7 "),
        Ok(Some(7))
    );
    assert_eq!(
        parse_hardware_wallet_restore_account_index("2147483647"),
        Ok(Some(2_147_483_647))
    );
    assert!(parse_hardware_wallet_restore_account_index("-1").is_err());
    assert!(parse_hardware_wallet_restore_account_index("abc").is_err());
    assert!(parse_hardware_wallet_restore_account_index("2147483648").is_err());
}

#[test]
fn hardware_profile_recovery_inputs_are_bounded() {
    assert_eq!(parse_hardware_exact_recovery_index(" 7 "), Ok(7));
    assert_eq!(parse_hardware_recovery_range("2", "3"), Ok(vec![2, 3, 4]));
    assert_eq!(
        parse_hardware_recovery_range("0", "255")
            .expect("max range")
            .len(),
        255
    );
    assert!(parse_hardware_exact_recovery_index("2147483648").is_err());
    assert!(parse_hardware_recovery_range("0", "0").is_err());
    assert!(parse_hardware_recovery_range("0", "256").is_err());
    assert!(parse_hardware_recovery_range("2147483647", "2").is_err());
}

#[test]
fn hardware_profile_copy_warns_about_non_secret_labels_and_trezor_modes() {
    assert!(hardware_profile_label_warning().contains("non-secret metadata"));
    assert!(hardware_profile_label_warning().contains("Do not put your hardware passphrase"));
    assert!(
        trezor_passphrase_mode_copy(wallet_ops::vault::TrezorPassphraseMode::NoPassphrase)
            .contains("standard Trezor wallet")
    );
    assert!(
        trezor_passphrase_mode_copy(wallet_ops::vault::TrezorPassphraseMode::EnterOnTrezor)
            .contains("entered on your Trezor")
    );
    assert!(
        trezor_passphrase_mode_copy(wallet_ops::vault::TrezorPassphraseMode::EnterInApp)
            .contains("clears it immediately")
    );
    assert_eq!(
        crate::root::vault::effective_trezor_passphrase_mode(
            wallet_ops::vault::TrezorPassphraseMode::EnterInApp,
            true,
        ),
        wallet_ops::vault::TrezorPassphraseMode::NoPassphrase,
    );
    assert_eq!(
        crate::root::vault::effective_trezor_passphrase_mode(
            wallet_ops::vault::TrezorPassphraseMode::EnterInApp,
            false,
        ),
        wallet_ops::vault::TrezorPassphraseMode::EnterInApp,
    );
}

#[test]
fn hardware_profile_picker_actions_have_stable_test_ids() {
    assert_eq!(
        HARDWARE_PROFILE_ADD_SUBACCOUNT_BUTTON_ID,
        "hardware-profile-add-subaccount"
    );
    assert_eq!(
        HARDWARE_PROFILE_RECOVER_EXACT_BUTTON_ID,
        "hardware-profile-recover-exact"
    );
    assert_eq!(
        HARDWARE_PROFILE_RECOVER_RANGE_BUTTON_ID,
        "hardware-profile-recover-range"
    );
}

#[cfg(feature = "hardware")]
#[test]
fn hardware_profile_picker_filters_to_unlocked_profile_and_locks_others() {
    use wallet_ops::vault::{
        HardwareProfileMetadata, HardwareRailgunAccountIdentity, HardwareRailgunAccountMetadata,
    };

    let descriptor_a = wallet_ops::hardware::HardwareDerivationDescriptor::ledger_eip1024_v1(
        wallet_ops::hardware::parse_bip32_path("m/44'/60'/0'/0/0").expect("valid path"),
        0,
        "ledger:evm:0x1111111111111111111111111111111111111111".to_string(),
        wallet_ops::hardware::HardwareWalletSyncIntent::CreateNew,
    );
    let descriptor_b = wallet_ops::hardware::HardwareDerivationDescriptor::ledger_eip1024_v1(
        wallet_ops::hardware::parse_bip32_path("m/44'/60'/0'/0/0").expect("valid path"),
        0,
        "ledger:evm:0x2222222222222222222222222222222222222222".to_string(),
        wallet_ops::hardware::HardwareWalletSyncIntent::CreateNew,
    );
    let profile_a = HardwareProfileMetadata::from_descriptor(&descriptor_a);
    let profile_b = HardwareProfileMetadata::from_descriptor(&descriptor_b);
    let identity = HardwareRailgunAccountIdentity {
        spending_public_key: [[0; 32]; 2],
        viewing_public_key: [0; 32],
    };
    let mut wallet_a = wallet_metadata(
        "wallet-a",
        "Ledger A",
        WalletSource::LedgerDerived,
        WalletStatus::Active,
        0,
    );
    wallet_a.hardware_account = Some(HardwareRailgunAccountMetadata::synthetic_software_v1(
        profile_a.profile_id.clone(),
        0,
        "Ledger A",
        descriptor_a,
        identity.clone(),
    ));
    let mut wallet_b = wallet_metadata(
        "wallet-b",
        "Ledger B",
        WalletSource::LedgerDerived,
        WalletStatus::Active,
        1,
    );
    wallet_b.hardware_account = Some(HardwareRailgunAccountMetadata::synthetic_software_v1(
        profile_b.profile_id,
        0,
        "Ledger B",
        descriptor_b,
        identity,
    ));

    let (matching, locked) = crate::root::vault::hardware_account_picker_rows(
        &[wallet_a, wallet_b],
        &profile_a.profile_id,
        Some("wallet-a"),
    );

    assert_eq!(matching.len(), 1);
    assert_eq!(matching[0].wallet_id.as_ref(), "wallet-a");
    assert!(matching[0].active);
    assert_eq!(locked.len(), 1);
    assert_eq!(locked[0].wallet_id.as_ref(), "wallet-b");
}

#[cfg(feature = "hardware")]
#[test]
fn hardware_profile_auto_open_respects_target_wallet() {
    let profile_fingerprint = "ledger:evm:0x1111111111111111111111111111111111111111";
    let wallet_a = hardware_wallet_metadata(
        "wallet-a",
        "Ledger account 0",
        wallet_ops::hardware::HardwareDeviceKind::Ledger,
        WalletStatus::Active,
        0,
        0,
        profile_fingerprint,
    );
    let wallet_b = hardware_wallet_metadata(
        "wallet-b",
        "Ledger account 1",
        wallet_ops::hardware::HardwareDeviceKind::Ledger,
        WalletStatus::Active,
        1,
        1,
        profile_fingerprint,
    );
    let profile_id = wallet_a
        .hardware_account
        .as_ref()
        .expect("hardware account")
        .profile_id
        .clone();
    let (accounts, locked) =
        crate::root::vault::hardware_account_picker_rows(&[wallet_a, wallet_b], &profile_id, None);
    assert!(locked.is_empty());
    assert_eq!(accounts.len(), 2);

    let mut state = crate::root::vault::HardwareProfileUnlockState::default();
    state.accounts = accounts;
    state.target_wallet_id = Some(Arc::from("wallet-b"));

    assert_eq!(
        crate::root::vault::hardware_profile_auto_open_wallet_id(&state)
            .expect("target is valid")
            .expect("target opens")
            .as_ref(),
        "wallet-b"
    );

    state.target_wallet_id = None;
    assert!(
        crate::root::vault::hardware_profile_auto_open_wallet_id(&state)
            .expect("multiple supported accounts are valid")
            .is_none()
    );

    state.accounts = vec![state.accounts[0].clone()];
    assert_eq!(
        crate::root::vault::hardware_profile_auto_open_wallet_id(&state)
            .expect("single supported account is valid")
            .expect("open-wallet purpose auto-opens single account")
            .as_ref(),
        "wallet-a"
    );

    state.purpose = crate::root::vault::HardwareProfileUnlockPurpose::AddWallet;
    assert!(
        crate::root::vault::hardware_profile_auto_open_wallet_id(&state)
            .expect("add-wallet purpose is valid")
            .is_none()
    );

    state.target_wallet_id = Some(Arc::from("wallet-a"));
    assert_eq!(
        crate::root::vault::hardware_profile_auto_open_wallet_id(&state)
            .expect("explicit target is valid")
            .expect("explicit target opens even in add-wallet purpose")
            .as_ref(),
        "wallet-a"
    );

    state.target_wallet_id = Some(Arc::from("missing-wallet"));
    assert!(
        crate::root::vault::hardware_profile_auto_open_wallet_id(&state)
            .expect_err("missing target mismatches profile")
            .contains("does not match")
    );
}

#[cfg(feature = "hardware")]
#[test]
fn hardware_profile_picker_marks_unsupported_backend_non_actionable() {
    use wallet_ops::vault::{
        HardwareProfileMetadata, HardwareRailgunAccountCustodyBackend,
        HardwareRailgunAccountIdentity, HardwareRailgunAccountMetadata,
    };

    let descriptor = wallet_ops::hardware::HardwareDerivationDescriptor::ledger_eip1024_v1(
        wallet_ops::hardware::parse_bip32_path("m/44'/60'/0'/0/0").expect("valid path"),
        0,
        "ledger:evm:0x1111111111111111111111111111111111111111".to_string(),
        wallet_ops::hardware::HardwareWalletSyncIntent::CreateNew,
    );
    let profile = HardwareProfileMetadata::from_descriptor(&descriptor);
    let mut wallet = wallet_metadata(
        "wallet-unsupported",
        "Native",
        WalletSource::LedgerDerived,
        WalletStatus::Active,
        0,
    );
    wallet.hardware_account = Some(HardwareRailgunAccountMetadata {
        profile_id: profile.profile_id.clone(),
        account_index: 0,
        label: "Native".to_string(),
        descriptor,
        account_identity: HardwareRailgunAccountIdentity {
            spending_public_key: [[0; 32]; 2],
            viewing_public_key: [0; 32],
        },
        receive_address: None,
        custody_backend: HardwareRailgunAccountCustodyBackend::NativeRailgunV1,
    });

    let (matching, locked) =
        crate::root::vault::hardware_account_picker_rows(&[wallet], &profile.profile_id, None);

    assert!(locked.is_empty());
    assert_eq!(matching.len(), 1);
    assert!(!matching[0].supported);
}

#[test]
fn wallet_label_vault_errors_are_actionable() {
    assert_eq!(
        crate::root::vault::vault_error_message(&wallet_ops::vault::VaultError::InvalidWalletLabel)
            .as_ref(),
        "Enter a wallet name before continuing."
    );
    assert_eq!(
        crate::root::vault::vault_error_message(
            &wallet_ops::vault::VaultError::DuplicateWalletLabel,
        )
        .as_ref(),
        "A wallet with that name already exists. Choose a different wallet name."
    );
    assert_eq!(
        crate::root::vault::hardware_setup_vault_error_message(
            &wallet_ops::vault::VaultError::DuplicateWalletLabel,
            "  trezor  ",
        )
        .as_ref(),
        "A wallet named \"trezor\" already exists. Choose a different wallet name."
    );
    assert!(
        crate::root::vault::vault_error_message(
            &wallet_ops::vault::VaultError::DuplicateHardwareWalletAccountIndex,
        )
        .contains("account index already exists")
    );
}

#[cfg(feature = "hardware")]
#[test]
fn hardware_setup_password_preservation_policy_keeps_early_device_errors() {
    use wallet_ops::hardware::HardwareDerivationError;

    assert!(crate::root::vault::hardware_setup_error_preserves_password(
        &HardwareDerivationError::LedgerUnavailable("unlock Ledger")
    ));
    assert!(crate::root::vault::hardware_setup_error_preserves_password(
        &HardwareDerivationError::LedgerStatus {
            operation: "get Ethereum address",
            status: 0x6511,
            message: "Open the Ethereum app on your Ledger, then retry.",
        }
    ));
    assert!(crate::root::vault::hardware_setup_error_preserves_password(
        &HardwareDerivationError::TrezorBridge(
            "Trezor Bridge did not report a connected device".to_owned()
        )
    ));
    assert!(crate::root::vault::hardware_setup_error_preserves_password(
        &HardwareDerivationError::TrezorLocked
    ));
    assert!(
        !crate::root::vault::hardware_setup_error_preserves_password(
            &HardwareDerivationError::LedgerStatus {
                operation: "derive Railgun secret",
                status: 0x6985,
                message: "The request was rejected or the Ledger is not ready. Approve on device or retry.",
            }
        )
    );
    assert!(
        !crate::root::vault::hardware_setup_error_preserves_password(
            &HardwareDerivationError::UnexpectedHardwareResponse("bad response")
        )
    );
}

#[cfg(feature = "hardware")]
#[test]
fn hardware_profile_approval_errors_are_user_friendly() {
    use wallet_ops::hardware::HardwareDerivationError;

    assert!(
        crate::root::vault::hardware_profile_should_reconnect_after_error(
            &HardwareDerivationError::LedgerUnavailable(
                "hidapi error: hid_error is not implemented yet",
            ),
            false,
        )
    );
    assert!(
        !crate::root::vault::hardware_profile_should_reconnect_after_error(
            &HardwareDerivationError::LedgerUnavailable(
                "hidapi error: hid_error is not implemented yet",
            ),
            true,
        )
    );
    assert!(
        !crate::root::vault::hardware_profile_should_reconnect_after_error(
            &HardwareDerivationError::UnexpectedHardwareResponse("bad response"),
            false,
        )
    );

    let locked = crate::root::vault::hardware_profile_hardware_error_message(
        "Hardware account creation failed",
        &HardwareDerivationError::LedgerUnavailable(
            "hidapi error: hid_error is not implemented yet",
        ),
        true,
    );
    assert_eq!(
        locked.as_ref(),
        "Ledger locked or disconnected before the request was approved. Unlock your Ledger, open the Ethereum app, then try again."
    );
    assert!(!locked.contains("hidapi"));

    let before_approval = crate::root::vault::hardware_profile_hardware_error_message(
        "Hardware account creation failed",
        &HardwareDerivationError::LedgerUnavailable(
            "hidapi error: hid_error is not implemented yet",
        ),
        false,
    );
    assert_eq!(
        before_approval.as_ref(),
        "Connect and unlock your Ledger, open the Ethereum app, then try again."
    );
    assert!(!before_approval.contains("hidapi"));

    let rejected = crate::root::vault::hardware_profile_hardware_error_message(
        "Hardware account creation failed",
        &HardwareDerivationError::LedgerStatus {
            operation: "derive Railgun secret",
            status: 0x6982,
            message: "The request was rejected on your Ledger.",
        },
        true,
    );
    assert_eq!(
        rejected.as_ref(),
        "Request rejected on Ledger. Try again when you are ready to approve it."
    );

    let trezor_locked = crate::root::vault::hardware_profile_hardware_error_message(
        "Hardware account creation failed",
        &HardwareDerivationError::TrezorLocked,
        false,
    );
    assert_eq!(
        trezor_locked.as_ref(),
        "Unlock your Trezor, then try again."
    );
}

#[cfg(feature = "hardware")]
#[test]
fn hardware_profile_detection_retries_generic_ledger_readiness_status() {
    use wallet_ops::hardware::HardwareDerivationError;

    let detection_status = HardwareDerivationError::LedgerStatus {
        operation: "get Ethereum address",
        status: 0x5515,
        message: "Ledger returned an unexpected status. Open the Ethereum app on your Ledger and retry.",
    };
    assert!(crate::root::vault::hardware_profile_detection_should_retry(
        &detection_status,
    ));
    assert!(
        crate::root::vault::hardware_profile_detection_should_suppress_initial_ledger_progress(
            &detection_status,
        )
    );
    assert!(!crate::root::vault::hardware_profile_detection_ledger_is_unlocked(&detection_status,));

    let ethereum_app_status = HardwareDerivationError::LedgerStatus {
        operation: "get Ethereum address",
        status: 0x6511,
        message: "Open the Ethereum app on your Ledger, then retry.",
    };
    assert!(crate::root::vault::hardware_profile_detection_should_retry(
        &ethereum_app_status,
    ));
    assert!(
        crate::root::vault::hardware_profile_detection_ledger_is_unlocked(&ethereum_app_status,)
    );

    let locked_status = HardwareDerivationError::LedgerStatus {
        operation: "get Ethereum address",
        status: 0x6b0c,
        message: "Unlock your Ledger, then retry.",
    };
    assert!(crate::root::vault::hardware_profile_detection_should_retry(
        &locked_status,
    ));
    assert!(
        crate::root::vault::hardware_profile_detection_should_suppress_initial_ledger_progress(
            &locked_status,
        )
    );
    assert!(!crate::root::vault::hardware_profile_detection_ledger_is_unlocked(&locked_status,));

    let unavailable = HardwareDerivationError::LedgerUnavailable("Ledger is not connected");
    assert!(crate::root::vault::hardware_profile_detection_should_retry(
        &unavailable,
    ));
    assert!(
        !crate::root::vault::hardware_profile_detection_should_suppress_initial_ledger_progress(
            &unavailable,
        )
    );

    let trezor_locked = HardwareDerivationError::TrezorLocked;
    assert!(crate::root::vault::hardware_profile_detection_should_retry(
        &trezor_locked,
    ));
    assert!(
        crate::root::vault::hardware_profile_detection_should_suppress_initial_trezor_progress(
            &trezor_locked,
        )
    );

    let trezor_pin = HardwareDerivationError::UnsupportedTrezorPinMatrix;
    assert!(crate::root::vault::hardware_profile_detection_should_retry(
        &trezor_pin,
    ));

    let approval_status = HardwareDerivationError::LedgerStatus {
        operation: "derive Railgun secret",
        status: 0x6985,
        message: "The request was rejected or the Ledger is not ready. Approve on device or retry.",
    };
    assert!(!crate::root::vault::hardware_profile_detection_should_retry(&approval_status,));
}

#[cfg(feature = "hardware")]
#[test]
fn hardware_profile_approval_address_is_parsed_from_session_binding() {
    use wallet_ops::hardware::HardwareDeviceKind;
    use wallet_ops::vault::{
        HardwareProfileBinding, HardwareProfileBindingKind, HardwareProfileSession,
    };

    let session = HardwareProfileSession::unmatched(
        HardwareDeviceKind::Ledger,
        HardwareProfileBinding::evm_address_fingerprint(
            "ledger:evm:0x000000000000000000000000000000000000dead",
        ),
        None,
    );
    assert_eq!(
        crate::root::vault::hardware_profile_evm_address_for_session(Some(&session)).as_deref(),
        Some("0x000000000000000000000000000000000000dead"),
    );

    let wrong_prefix = HardwareProfileSession::unmatched(
        HardwareDeviceKind::Ledger,
        HardwareProfileBinding::evm_address_fingerprint(
            "trezor:evm:0x000000000000000000000000000000000000dead",
        ),
        None,
    );
    assert!(
        crate::root::vault::hardware_profile_evm_address_for_session(Some(&wrong_prefix,))
            .is_none()
    );

    let native_binding = HardwareProfileSession::unmatched(
        HardwareDeviceKind::Ledger,
        HardwareProfileBinding {
            kind: HardwareProfileBindingKind::NativeRailgunFingerprint,
            fingerprint: "ledger:native:abc".to_owned(),
        },
        None,
    );
    assert!(
        crate::root::vault::hardware_profile_evm_address_for_session(Some(&native_binding,))
            .is_none()
    );
}

#[cfg(feature = "hardware")]
#[test]
fn trezor_hardware_profile_approval_copy_uses_cipher_value_label() {
    use crate::root::vault::HardwareProfileApprovalPrompt;
    use wallet_ops::hardware::HardwareDeviceKind;

    let wallet = hardware_wallet_metadata(
        "trezor-0",
        "Trezor hardware profile account 0",
        HardwareDeviceKind::Trezor,
        WalletStatus::Active,
        0,
        0,
        "trezor:evm:0x000000000000000000000000000000000000dead",
    );
    let account = wallet.hardware_account.as_ref().expect("hardware account");
    let prompt = crate::root::vault::hardware_profile_approval_prompt_for_account(account)
        .expect("trezor approval prompt");

    assert_eq!(
        prompt,
        HardwareProfileApprovalPrompt::TrezorCipherKeyValue(std::sync::Arc::from(
            "Railgun wallet v1 account 0",
        )),
    );

    let copy = crate::root::vault_ui::hardware_profile_approval_copy(
        HardwareDeviceKind::Trezor,
        Some(&prompt),
    );
    assert_eq!(copy.intro, "Your Trezor should show ENCRYPT VALUE for:");
    assert_eq!(copy.value.as_deref(), Some("Railgun wallet v1 account 0"));
    assert!(copy.warning.contains("Only approve if this value matches"));
    assert!(!copy.intro.contains("address"));
    assert!(!copy.warning.contains("address"));
}

#[cfg(feature = "hardware")]
#[test]
fn ledger_hardware_profile_approval_copy_keeps_address_comparison() {
    use crate::root::vault::HardwareProfileApprovalPrompt;
    use wallet_ops::hardware::HardwareDeviceKind;

    let prompt = HardwareProfileApprovalPrompt::EvmAddress(std::sync::Arc::from(
        "0x000000000000000000000000000000000000dead",
    ));
    let copy = crate::root::vault_ui::hardware_profile_approval_copy(
        HardwareDeviceKind::Ledger,
        Some(&prompt),
    );

    assert_eq!(
        copy.intro,
        "Compare this Ledger address with the one shown on your device:"
    );
    assert_eq!(
        copy.value.as_deref(),
        Some("0x000000000000000000000000000000000000dead")
    );
    assert!(copy.warning.contains("Only approve if they match"));
}

#[test]
fn hardware_public_account_copy_uses_device_signing_language() {
    let copy = crate::root::public_account::hardware_public_account_setup_copy(
        wallet_ops::hardware::HardwareDeviceKind::Trezor,
    );

    assert!(copy.contains("hardware-native Public EVM account"));
    assert!(copy.contains("Trezor"));
    assert!(copy.contains("partitioned by the selected Private wallet account index"));
    assert!(copy.contains("Confirm the receive address on your device"));
    assert!(copy.contains("public transactions will require device approval"));
    assert_eq!(
        crate::root::public_account::public_account_source_label(
            wallet_ops::vault::PublicAccountSource::HardwareDerived,
        ),
        "Hardware"
    );
    assert!(
        crate::root::public_action::public_send_authorization_detail(
            wallet_ops::vault::PublicAccountSource::HardwareDerived,
        )
        .contains("approve the public send transaction on the device")
    );
    assert!(
        crate::root::public_action::public_shield_authorization_detail(
            wallet_ops::vault::PublicAccountSource::HardwareDerived,
        )
        .contains("approve the shield key message")
    );
}

#[test]
fn trezor_app_passphrase_prompt_waits_for_expired_session() {
    let mut session = wallet_ops::vault::HardwareProfileSession::unmatched(
        wallet_ops::hardware::HardwareDeviceKind::Trezor,
        wallet_ops::vault::HardwareProfileBinding::evm_address_fingerprint(
            "trezor:evm:0x1111111111111111111111111111111111111111",
        ),
        Some(vec![1, 2, 3]),
    );

    assert!(!crate::root::vault::hardware_session_needs_trezor_app_passphrase(&session));

    session.set_trezor_passphrase_mode(wallet_ops::vault::TrezorPassphraseMode::EnterInApp);
    assert!(!crate::root::vault::hardware_session_needs_trezor_app_passphrase(&session));

    session.discard_trezor_session();
    assert!(crate::root::vault::hardware_session_needs_trezor_app_passphrase(&session));

    session.set_trezor_passphrase_mode(wallet_ops::vault::TrezorPassphraseMode::NoPassphrase);
    assert!(!crate::root::vault::hardware_session_needs_trezor_app_passphrase(&session));
}

#[cfg(feature = "hardware")]
#[test]
fn trezor_stale_session_errors_include_identity_mismatches() {
    assert!(crate::root::vault::trezor_session_stale_error_message(
        "Vault error: derived hardware wallet key does not match the stored wallet"
    ));
    assert!(crate::root::vault::trezor_session_stale_error_message(
        "hardware public signer profile mismatch: wrong device or passphrase context is active"
    ));
    assert!(crate::root::vault::trezor_session_stale_error_message(
        "hardware public account identity mismatch: expected 0x0, got 0x1"
    ));
    assert!(crate::root::vault::trezor_session_stale_error_message(
        "Trezor requested an app-entered passphrase but none was provided"
    ));
    assert!(!crate::root::vault::trezor_session_stale_error_message(
        "network request timed out"
    ));
}

#[test]
fn wallet_ids_after_drop_moves_active_wallets_between_drop_zones() {
    let active = vec![
        Arc::from("wallet-a"),
        Arc::from("wallet-b"),
        Arc::from("wallet-c"),
    ];

    assert_eq!(
        wallet_ids_after_drop(&active, "wallet-c", 0),
        Some(vec![
            "wallet-c".to_string(),
            "wallet-a".to_string(),
            "wallet-b".to_string(),
        ])
    );
    assert_eq!(
        wallet_ids_after_drop(&active, "wallet-a", active.len()),
        Some(vec![
            "wallet-b".to_string(),
            "wallet-c".to_string(),
            "wallet-a".to_string(),
        ])
    );
    assert_eq!(wallet_ids_after_drop(&active, "wallet-b", 1), None);
    assert_eq!(wallet_ids_after_drop(&active, "missing", 1), None);
}

#[test]
fn selected_wallet_after_metadata_refresh_keeps_or_switches_selection() {
    let options = wallet_options_from_metadata(vec![
        wallet_metadata(
            "wallet-a",
            "Alpha",
            WalletSource::Generated,
            WalletStatus::Active,
            0,
        ),
        wallet_metadata(
            "wallet-b",
            "Beta",
            WalletSource::Imported,
            WalletStatus::Active,
            1,
        ),
    ]);

    assert_eq!(
        selected_wallet_after_metadata_refresh(Some("wallet-b"), &options),
        WalletManagementSelection::KeepSelected
    );
    assert_eq!(
        selected_wallet_after_metadata_refresh(Some("wallet-hidden"), &options),
        WalletManagementSelection::SwitchTo(Arc::from("wallet-a"))
    );
    assert_eq!(
        selected_wallet_after_metadata_refresh(None, &[]),
        WalletManagementSelection::NoActiveWallet
    );
}

#[test]
fn wallet_management_switch_requires_device_for_hardware_target() {
    let options = wallet_options_from_metadata(vec![
        hardware_wallet_metadata(
            "ledger-0",
            "Ledger account 0",
            wallet_ops::hardware::HardwareDeviceKind::Ledger,
            WalletStatus::Active,
            0,
            0,
            "ledger:evm:0x1111111111111111111111111111111111111111",
        ),
        wallet_metadata(
            "wallet-a",
            "Alpha",
            WalletSource::Generated,
            WalletStatus::Active,
            1,
        ),
    ]);

    assert!(wallet_management_switch_requires_device(
        "ledger-0", &options
    ));
    assert!(!wallet_management_switch_requires_device(
        "wallet-a", &options
    ));
}

#[test]
fn wallet_select_item_matches_label_and_wallet_id() {
    let wallet = WalletSelectItem {
        wallet_id: "wallet-a".into(),
        label: "Alpha".into(),
    };

    assert!(wallet.matches("alpha"));
    assert!(wallet.matches("wallet-a"));
    assert!(!wallet.matches("add"));
}

#[test]
fn wallet_generation_guard_rejects_stale_async_results() {
    assert!(wallet_generation_matches(
        Some("wallet-a"),
        2,
        "wallet-a",
        2
    ));
    assert!(!wallet_generation_matches(
        Some("wallet-b"),
        2,
        "wallet-a",
        2
    ));
    assert!(!wallet_generation_matches(
        Some("wallet-a"),
        3,
        "wallet-a",
        2
    ));
    assert!(!wallet_generation_matches(None, 2, "wallet-a", 2));
}
