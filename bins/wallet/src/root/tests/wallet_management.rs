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
