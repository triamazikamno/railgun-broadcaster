use super::*;

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
    assert_eq!(options[0].label.as_ref(), "Alpha");
    assert_eq!(options[0].source, WalletSource::Generated);
    assert_eq!(options[1].wallet_id.as_ref(), "wallet-b");
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
            None,
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
