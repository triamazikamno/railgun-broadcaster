use super::*;

impl WalletRoot {
    pub(in crate::root) fn active_self_broadcast_gas_payer_accounts(
        &self,
    ) -> Vec<PublicAccountMetadata> {
        self.public_accounts
            .iter()
            .filter(|account| account.status == PublicAccountStatus::Active)
            .cloned()
            .collect()
    }

    pub(in crate::root) fn default_self_broadcast_gas_payer_uuid(&self) -> Option<Arc<str>> {
        default_self_broadcast_gas_payer_uuid(&self.active_self_broadcast_gas_payer_accounts())
    }

    pub(in crate::root) fn new_self_broadcast_gas_payer_select(
        &self,
        chain_id: u64,
        selected_uuid: Option<&str>,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) -> Entity<SelectState<SearchableVec<SelfBroadcastGasPayerSelectItem>>> {
        let accounts = self.active_self_broadcast_gas_payer_accounts();
        let items = self_broadcast_gas_payer_select_items(
            &accounts,
            chain_id,
            self.public_balance_snapshot.as_deref(),
        );
        let selected_index = self_broadcast_gas_payer_select_index(&items, selected_uuid);
        cx.new(|cx| {
            SelectState::new(SearchableVec::new(items), selected_index, window, cx).searchable(true)
        })
    }

    pub(in crate::root) fn new_private_action_asset_select(
        &self,
        kind: DeliveryFormKind,
        chain_id: u64,
        selected_token: Address,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) -> (
        Entity<SelectState<SearchableVec<PrivateActionAssetSelectItem>>>,
        Vec<PrivateActionAssetSelectItem>,
    ) {
        let assets = self.private_action_asset_options(kind, chain_id);
        let items = private_action_asset_select_items(&assets);
        let selected_index = private_action_asset_select_index(&items, selected_token);
        let state_items = items.clone();
        (
            cx.new(|cx| {
                SelectState::new(SearchableVec::new(items), selected_index, window, cx)
                    .searchable(true)
            }),
            state_items,
        )
    }

    pub(in crate::root) fn sync_self_broadcast_gas_payer_selects(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let accounts = self.active_self_broadcast_gas_payer_accounts();
        let snapshot = self.public_balance_snapshot.clone();
        for form in self.send_forms.values_mut() {
            let selected = normalized_self_broadcast_gas_payer_uuid(
                form.self_broadcast_gas_payer_uuid.as_ref(),
                &accounts,
            );
            form.self_broadcast_gas_payer_uuid.clone_from(&selected);
            sync_self_broadcast_gas_payer_select_entity(
                &form.self_broadcast_gas_payer_select,
                &accounts,
                form.asset.chain_id,
                snapshot.as_deref(),
                selected.as_ref(),
                window,
                cx,
            );
        }
        for form in self.unshield_forms.values_mut() {
            let selected = normalized_self_broadcast_gas_payer_uuid(
                form.self_broadcast_gas_payer_uuid.as_ref(),
                &accounts,
            );
            form.self_broadcast_gas_payer_uuid.clone_from(&selected);
            sync_self_broadcast_gas_payer_select_entity(
                &form.self_broadcast_gas_payer_select,
                &accounts,
                form.asset.chain_id,
                snapshot.as_deref(),
                selected.as_ref(),
                window,
                cx,
            );
        }
    }

    pub(in crate::root) fn sync_self_broadcast_gas_payer_select(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let accounts = self.active_self_broadcast_gas_payer_accounts();
        let snapshot = self.public_balance_snapshot.clone();
        match kind {
            DeliveryFormKind::Send => {
                let Some(form) = self.send_forms.get_mut(&key) else {
                    return;
                };
                sync_self_broadcast_gas_payer_select_entity(
                    &form.self_broadcast_gas_payer_select,
                    &accounts,
                    form.asset.chain_id,
                    snapshot.as_deref(),
                    form.self_broadcast_gas_payer_uuid.as_ref(),
                    window,
                    cx,
                );
            }
            DeliveryFormKind::Unshield => {
                let Some(form) = self.unshield_forms.get_mut(&key) else {
                    return;
                };
                sync_self_broadcast_gas_payer_select_entity(
                    &form.self_broadcast_gas_payer_select,
                    &accounts,
                    form.asset.chain_id,
                    snapshot.as_deref(),
                    form.self_broadcast_gas_payer_uuid.as_ref(),
                    window,
                    cx,
                );
            }
        }
    }

    pub(in crate::root) fn selected_self_broadcast_gas_payer_account(
        &self,
        selected_uuid: Option<&str>,
    ) -> Option<&PublicAccountMetadata> {
        let selected_uuid = selected_uuid?;
        self.public_accounts.iter().find(|account| {
            account.status == PublicAccountStatus::Active
                && account.public_account_uuid == selected_uuid
        })
    }
}

pub(in crate::root) fn default_self_broadcast_gas_payer_uuid(
    accounts: &[PublicAccountMetadata],
) -> Option<Arc<str>> {
    (accounts.len() == 1).then(|| Arc::from(accounts[0].public_account_uuid.as_str()))
}

#[cfg(test)]
pub(in crate::root) fn self_broadcast_gas_payer_matches_search(
    account: &PublicAccountMetadata,
    query: &str,
) -> bool {
    self_broadcast_gas_payer_fields_match(
        public_account_display_label(account).as_deref(),
        &account.address,
        query,
    )
}

pub(in crate::root) fn self_broadcast_gas_payer_fields_match(
    label: Option<&str>,
    address: &Address,
    query: &str,
) -> bool {
    let query = query.trim().to_ascii_lowercase();
    if query.is_empty() {
        return true;
    }
    let full_address = address.to_checksum(None).to_ascii_lowercase();
    let lower_hex_address = format!("{address:#x}");
    let short = short_address(address).to_ascii_lowercase();
    label.is_some_and(|label| label.to_ascii_lowercase().contains(&query))
        || full_address.contains(&query)
        || lower_hex_address.contains(&query)
        || short.contains(&query)
}

pub(in crate::root) fn self_broadcast_gas_payer_label(account: &PublicAccountMetadata) -> String {
    public_account_display_label(account).unwrap_or_else(|| short_address(&account.address))
}

pub(in crate::root) fn self_broadcast_native_balance_entry(
    snapshot: Option<&PublicBalanceSnapshot>,
    chain_id: u64,
    public_account_uuid: &str,
) -> Option<PublicBalanceEntry> {
    public_balance_entry_for_chain(
        snapshot,
        chain_id,
        public_account_uuid,
        PublicAssetId::Native,
        PublicAccountStatus::Active,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::root) enum SelfBroadcastNativeBalanceState {
    Unknown,
    Zero,
    Positive,
}

pub(in crate::root) fn self_broadcast_native_balance_state(
    snapshot: Option<&PublicBalanceSnapshot>,
    chain_id: u64,
    public_account_uuid: &str,
) -> SelfBroadcastNativeBalanceState {
    match self_broadcast_native_balance_entry(snapshot, chain_id, public_account_uuid)
        .map(|entry| entry.amount)
    {
        Some(PublicBalanceAmount::Available(amount)) if amount.is_zero() => {
            SelfBroadcastNativeBalanceState::Zero
        }
        Some(PublicBalanceAmount::Available(_)) => SelfBroadcastNativeBalanceState::Positive,
        Some(PublicBalanceAmount::Unavailable) | None => SelfBroadcastNativeBalanceState::Unknown,
    }
}

pub(in crate::root) fn self_broadcast_native_balance_label(
    snapshot: Option<&PublicBalanceSnapshot>,
    chain_id: u64,
    public_account_uuid: &str,
) -> String {
    self_broadcast_native_balance_entry(snapshot, chain_id, public_account_uuid).map_or_else(
        || "unavailable".to_string(),
        |entry| public_balance_amount_label(&entry.amount, entry.asset.decimals),
    )
}

pub(in crate::root) fn random_self_broadcast_gas_payer_uuid(
    accounts: &[PublicAccountMetadata],
    selected_uuid: Option<&str>,
    chain_id: u64,
    snapshot: Option<&PublicBalanceSnapshot>,
) -> Option<Arc<str>> {
    let candidates = accounts
        .iter()
        .filter(|account| {
            self_broadcast_gas_payer_random_candidate(account, selected_uuid, chain_id, snapshot)
        })
        .collect::<Vec<_>>();
    candidates
        .choose(&mut rand::rng())
        .map(|account| Arc::from(account.public_account_uuid.as_str()))
}

pub(in crate::root) fn self_broadcast_initial_gas_values(
    selection: &SelfBroadcastGasFeeSelection,
    quote: Option<SelfBroadcastGasFeeQuote>,
) -> Option<(u128, u128)> {
    match *selection {
        SelfBroadcastGasFeeSelection::Auto => quote.map(|quote| {
            (
                quote.suggested_max_fee_per_gas,
                quote.suggested_max_priority_fee_per_gas,
            )
        }),
        SelfBroadcastGasFeeSelection::Custom {
            max_fee_per_gas,
            max_priority_fee_per_gas,
        } => Some((max_fee_per_gas, max_priority_fee_per_gas)),
    }
}

pub(in crate::root) fn self_broadcast_gas_payer_random_candidate(
    account: &PublicAccountMetadata,
    selected_uuid: Option<&str>,
    chain_id: u64,
    snapshot: Option<&PublicBalanceSnapshot>,
) -> bool {
    Some(account.public_account_uuid.as_str()) != selected_uuid
        && self_broadcast_native_balance_state(snapshot, chain_id, &account.public_account_uuid)
            != SelfBroadcastNativeBalanceState::Zero
}

pub(in crate::root) fn normalized_self_broadcast_gas_payer_uuid(
    selected_uuid: Option<&Arc<str>>,
    accounts: &[PublicAccountMetadata],
) -> Option<Arc<str>> {
    selected_uuid
        .filter(|uuid| {
            accounts
                .iter()
                .any(|account| account.public_account_uuid.as_str() == uuid.as_ref())
        })
        .cloned()
        .or_else(|| default_self_broadcast_gas_payer_uuid(accounts))
}

pub(in crate::root) fn self_broadcast_gas_payer_select_items(
    accounts: &[PublicAccountMetadata],
    chain_id: u64,
    snapshot: Option<&PublicBalanceSnapshot>,
) -> Vec<SelfBroadcastGasPayerSelectItem> {
    accounts
        .iter()
        .map(|account| SelfBroadcastGasPayerSelectItem {
            public_account_uuid: Arc::from(account.public_account_uuid.as_str()),
            label: Arc::from(self_broadcast_gas_payer_label(account)),
            address: account.address,
            chain_id,
            balance_label: Arc::from(self_broadcast_native_balance_label(
                snapshot,
                chain_id,
                &account.public_account_uuid,
            )),
        })
        .collect()
}

pub(in crate::root) fn self_broadcast_gas_payer_select_index(
    items: &[SelfBroadcastGasPayerSelectItem],
    selected_uuid: Option<&str>,
) -> Option<IndexPath> {
    let selected_uuid = selected_uuid?;
    items
        .iter()
        .position(|item| item.public_account_uuid.as_ref() == selected_uuid)
        .map(|index| IndexPath::default().row(index))
}

pub(in crate::root) fn sync_self_broadcast_gas_payer_select_entity(
    select: &Entity<SelectState<SearchableVec<SelfBroadcastGasPayerSelectItem>>>,
    accounts: &[PublicAccountMetadata],
    chain_id: u64,
    snapshot: Option<&PublicBalanceSnapshot>,
    selected_uuid: Option<&Arc<str>>,
    window: &mut Window,
    cx: &mut Context<'_, WalletRoot>,
) {
    let items = self_broadcast_gas_payer_select_items(accounts, chain_id, snapshot);
    select.update(cx, |select, cx| {
        select.set_items(SearchableVec::new(items), window, cx);
        if let Some(uuid) = selected_uuid {
            select.set_selected_value(uuid, window, cx);
        } else {
            select.set_selected_index(None, window, cx);
        }
    });
}

pub(in crate::root) fn private_action_asset_select_items(
    assets: &[UnshieldAsset],
) -> Vec<PrivateActionAssetSelectItem> {
    assets
        .iter()
        .map(|asset| PrivateActionAssetSelectItem {
            token: asset.token,
            label: Arc::from(asset.label.as_str()),
            icon_path: asset.icon_path.clone(),
        })
        .collect()
}

pub(in crate::root) fn private_action_asset_select_index(
    items: &[PrivateActionAssetSelectItem],
    selected_token: Address,
) -> Option<IndexPath> {
    items
        .iter()
        .position(|item| item.token == selected_token)
        .map(|index| IndexPath::default().row(index))
}

pub(in crate::root) fn sync_private_action_asset_select_entity(
    select: &Entity<SelectState<SearchableVec<PrivateActionAssetSelectItem>>>,
    assets: &[UnshieldAsset],
    selected_token: Address,
    window: &mut Window,
    cx: &mut Context<'_, WalletRoot>,
) {
    let items = private_action_asset_select_items(assets);
    let selected_index = private_action_asset_select_index(&items, selected_token);
    select.update(cx, |select, cx| {
        select.set_items(SearchableVec::new(items), window, cx);
        select.set_selected_index(selected_index, window, cx);
    });
}
