use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;

use gpui::Context;
use railgun_ui::{chain_icon_path, chain_name, format_token_amount, short_address};
use wallet_ops::{
    PublicAssetId, PublicBalanceAmount, PublicBalanceEntry, PublicBalanceSnapshot,
    refresh_public_balances, settings::EffectiveTokenRegistry, vault::PublicAccountStatus,
};

use super::{WalletRoot, WalletTab, format_report_chain, token_display_metadata};

pub(super) fn public_asset_label(
    chain_id: u64,
    asset: PublicAssetId,
    registry: Option<&EffectiveTokenRegistry>,
) -> String {
    match asset {
        PublicAssetId::Native => chain_name(chain_id).map_or_else(
            || "Native".to_string(),
            |name| match chain_id {
                56 => "BNB".to_string(),
                137 => "MATIC".to_string(),
                _ => format!("{name} native"),
            },
        ),
        PublicAssetId::Erc20(token) => token_display_metadata(registry, chain_id, &token)
            .map_or_else(|| short_address(&token), |info| info.symbol),
    }
}

pub(super) fn public_asset_decimals(
    chain_id: u64,
    asset: PublicAssetId,
    registry: Option<&EffectiveTokenRegistry>,
) -> Option<u8> {
    match asset {
        PublicAssetId::Native => Some(18),
        PublicAssetId::Erc20(token) => {
            token_display_metadata(registry, chain_id, &token).map(|info| info.decimals)
        }
    }
}

pub(super) fn public_asset_icon_path(
    chain_id: u64,
    asset: PublicAssetId,
    registry: Option<&EffectiveTokenRegistry>,
) -> Option<PathBuf> {
    match asset {
        PublicAssetId::Native => chain_icon_path(chain_id),
        PublicAssetId::Erc20(token) => {
            token_display_metadata(registry, chain_id, &token).and_then(|info| info.icon_path)
        }
    }
}

pub(super) fn merge_public_balance_snapshot(
    current: Option<&PublicBalanceSnapshot>,
    refreshed: PublicBalanceSnapshot,
    refreshed_status: PublicAccountStatus,
) -> PublicBalanceSnapshot {
    let Some(current) = current.filter(|current| current.chain_id == refreshed.chain_id) else {
        return refreshed;
    };
    let refreshed_ids = refreshed
        .accounts
        .iter()
        .map(|account| account.account.public_account_uuid.clone())
        .collect::<BTreeSet<_>>();
    let mut accounts = current
        .accounts
        .iter()
        .filter(|account| {
            account.account.status != refreshed_status
                && !refreshed_ids.contains(account.account.public_account_uuid.as_str())
        })
        .cloned()
        .collect::<Vec<_>>();
    accounts.extend(refreshed.accounts);
    PublicBalanceSnapshot {
        chain_id: refreshed.chain_id,
        refreshed_at: refreshed.refreshed_at,
        accounts,
    }
}

pub(super) fn public_balance_amount_label(amount: &PublicBalanceAmount, decimals: u8) -> String {
    match amount {
        PublicBalanceAmount::Available(amount) => format_token_amount(*amount, decimals),
        PublicBalanceAmount::Unavailable => "unavailable".to_string(),
    }
}

pub(super) fn public_balance_entry_for_chain(
    snapshot: Option<&PublicBalanceSnapshot>,
    chain_id: u64,
    public_account_uuid: &str,
    asset: PublicAssetId,
    status: PublicAccountStatus,
) -> Option<PublicBalanceEntry> {
    let snapshot = snapshot.filter(|snapshot| snapshot.chain_id == chain_id)?;
    snapshot
        .accounts
        .iter()
        .find(|account| {
            account.account.public_account_uuid.as_str() == public_account_uuid
                && account.account.status == status
        })?
        .balances
        .iter()
        .find(|entry| entry.asset.id == asset)
        .cloned()
}

pub(super) fn public_account_visible_balances_for_chain(
    snapshot: Option<&PublicBalanceSnapshot>,
    chain_id: u64,
    public_account_uuid: &str,
    status: PublicAccountStatus,
) -> Vec<PublicBalanceEntry> {
    let Some(snapshot) = snapshot.filter(|snapshot| snapshot.chain_id == chain_id) else {
        return Vec::new();
    };
    snapshot
        .accounts
        .iter()
        .find(|account| {
            account.account.public_account_uuid.as_str() == public_account_uuid
                && account.account.status == status
        })
        .map_or_else(Vec::new, |account| {
            account
                .balances
                .iter()
                .filter(|entry| {
                    matches!(
                        &entry.amount,
                        PublicBalanceAmount::Available(amount) if !amount.is_zero()
                    )
                })
                .cloned()
                .collect()
        })
}

impl WalletRoot {
    pub(super) fn selected_public_balance_entry(&self) -> Option<PublicBalanceEntry> {
        let public_account_uuid = self.public_form.selected_account_uuid.as_deref()?;
        let asset = self.public_form.selected_asset?;
        let status = self
            .public_account_for_uuid(Some(public_account_uuid))?
            .status;
        self.public_balance_entry(public_account_uuid, asset, status)
    }

    fn public_balance_entry(
        &self,
        public_account_uuid: &str,
        asset: PublicAssetId,
        status: PublicAccountStatus,
    ) -> Option<PublicBalanceEntry> {
        public_balance_entry_for_chain(
            self.public_balance_snapshot.as_deref(),
            self.selected_chain,
            public_account_uuid,
            asset,
            status,
        )
    }

    pub(super) fn clear_public_chain_balance_state(&mut self) {
        self.public_balance_snapshot = None;
        self.public_balance_error = None;
        self.public_balance_refreshing = false;
        self.public_balance_generation = self.public_balance_generation.wrapping_add(1);
        self.public_inactive_balance_error = None;
        self.public_inactive_balance_refreshing = false;
        self.public_inactive_balance_generation =
            self.public_inactive_balance_generation.wrapping_add(1);
        self.public_form.selected_asset = None;
        self.public_form.action_progress.clear();
        self.public_form.expanded_action_error_steps.clear();
        self.public_form.send_error = None;
        self.public_form.shield_error = None;
    }

    pub(super) fn schedule_public_balance_refresh(&mut self, cx: &mut Context<'_, Self>) {
        let accounts = self
            .public_accounts
            .iter()
            .filter(|account| account.status == PublicAccountStatus::Active)
            .cloned()
            .collect::<Vec<_>>();
        if self.public_balance_refreshing || accounts.is_empty() {
            return;
        }
        let chain_id = self.selected_chain;
        let account_ids = accounts
            .iter()
            .map(|account| account.public_account_uuid.clone())
            .collect::<Vec<_>>();
        let http = self.http.clone();
        let effective_chain = self.effective_chain_configs.get(&chain_id).cloned();
        let effective_token_registry = self.effective_token_registry.clone();
        self.public_balance_refreshing = true;
        self.public_balance_error = None;
        self.public_balance_generation = self.public_balance_generation.wrapping_add(1);
        let generation = self.public_balance_generation;
        let active_wallet_id = self.selected_wallet_id.clone();
        let join = self.runtime.spawn(async move {
            refresh_public_balances(
                chain_id,
                &accounts,
                effective_chain.as_ref(),
                Some(&effective_token_registry),
                &http,
            )
            .await
        });
        cx.spawn(async move |this, cx| {
            let result = join.await;
            let _ = this.update(cx, |root, cx| {
                if root.public_balance_generation != generation {
                    return;
                }
                root.public_balance_refreshing = false;
                let current_account_ids = root
                    .public_accounts
                    .iter()
                    .filter(|account| account.status == PublicAccountStatus::Active)
                    .map(|account| account.public_account_uuid.as_str())
                    .collect::<Vec<_>>();
                let account_set_unchanged = current_account_ids.len() == account_ids.len()
                    && current_account_ids
                        .into_iter()
                        .eq(account_ids.iter().map(String::as_str));
                if root.selected_wallet_id != active_wallet_id
                    || root.selected_chain != chain_id
                    || !account_set_unchanged
                {
                    if root.active_wallet_tab == WalletTab::Public
                        && root.has_active_public_accounts()
                    {
                        root.schedule_public_balance_refresh(cx);
                    }
                    cx.notify();
                    return;
                }
                match result {
                    Ok(Ok(snapshot)) => {
                        root.public_balance_snapshot =
                            Some(Arc::new(merge_public_balance_snapshot(
                                root.public_balance_snapshot.as_deref(),
                                snapshot,
                                PublicAccountStatus::Active,
                            )));
                        root.public_balance_error = None;
                    }
                    Ok(Err(error)) => {
                        root.public_balance_error = Some(Arc::from(format_report_chain(&error)));
                    }
                    Err(error) => {
                        root.public_balance_error =
                            Some(Arc::from(format!("Public balance refresh failed: {error}")));
                    }
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    pub(super) fn schedule_inactive_public_balance_refresh(&mut self, cx: &mut Context<'_, Self>) {
        let accounts = self
            .public_accounts
            .iter()
            .filter(|account| account.status == PublicAccountStatus::Inactive)
            .cloned()
            .collect::<Vec<_>>();
        if self.public_inactive_balance_refreshing || accounts.is_empty() {
            return;
        }
        let chain_id = self.selected_chain;
        let account_ids = accounts
            .iter()
            .map(|account| account.public_account_uuid.clone())
            .collect::<Vec<_>>();
        let http = self.http.clone();
        let effective_chain = self.effective_chain_configs.get(&chain_id).cloned();
        let effective_token_registry = self.effective_token_registry.clone();
        self.public_inactive_balance_refreshing = true;
        self.public_inactive_balance_error = None;
        self.public_inactive_balance_generation =
            self.public_inactive_balance_generation.wrapping_add(1);
        let generation = self.public_inactive_balance_generation;
        let active_wallet_id = self.selected_wallet_id.clone();
        let join = self.runtime.spawn(async move {
            refresh_public_balances(
                chain_id,
                &accounts,
                effective_chain.as_ref(),
                Some(&effective_token_registry),
                &http,
            )
            .await
        });
        cx.spawn(async move |this, cx| {
            let result = join.await;
            let _ = this.update(cx, |root, cx| {
                if root.public_inactive_balance_generation != generation {
                    return;
                }
                root.public_inactive_balance_refreshing = false;
                let current_account_ids = root
                    .public_accounts
                    .iter()
                    .filter(|account| account.status == PublicAccountStatus::Inactive)
                    .map(|account| account.public_account_uuid.as_str())
                    .collect::<Vec<_>>();
                let account_set_unchanged = current_account_ids.len() == account_ids.len()
                    && current_account_ids
                        .into_iter()
                        .eq(account_ids.iter().map(String::as_str));
                if root.selected_wallet_id != active_wallet_id
                    || root.selected_chain != chain_id
                    || !account_set_unchanged
                {
                    if root.active_wallet_tab == WalletTab::Public
                        && root.public_form.inactive_accounts_open
                        && root
                            .public_accounts
                            .iter()
                            .any(|account| account.status == PublicAccountStatus::Inactive)
                    {
                        root.schedule_inactive_public_balance_refresh(cx);
                    }
                    cx.notify();
                    return;
                }
                match result {
                    Ok(Ok(snapshot)) => {
                        root.public_balance_snapshot =
                            Some(Arc::new(merge_public_balance_snapshot(
                                root.public_balance_snapshot.as_deref(),
                                snapshot,
                                PublicAccountStatus::Inactive,
                            )));
                        root.public_inactive_balance_error = None;
                    }
                    Ok(Err(error)) => {
                        root.public_inactive_balance_error =
                            Some(Arc::from(format_report_chain(&error)));
                    }
                    Err(error) => {
                        root.public_inactive_balance_error = Some(Arc::from(format!(
                            "Inactive public balance refresh failed: {error}"
                        )));
                    }
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }
}
