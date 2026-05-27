use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use broadcaster_monitor::{EventRx, Shared};
use gpui::{AppContext, Context, Entity, Focusable, Pixels, SharedString, Window, px};
use gpui_component::{
    IndexPath,
    input::{InputEvent, InputState},
    resizable::ResizableState,
    select::{SearchableVec, SelectEvent, SelectState},
    table::{TableEvent, TableState},
};
use tokio::runtime::Handle;
use tokio::sync::{OnceCell, watch};
use ui::logs::LogsPane;
use ui::theme::APP_TEXT_SIZE;
use wallet_ops::{
    BlockedShieldRescueUtxoId, BroadcasterFeePolicy, HttpContext, PoiCacheService, PoiReadSource,
    ProverCacheBuildProgress, PublicBalanceSnapshot, PublicBroadcasterWakuClient,
    TokenAnchorRateCache, TokenAnchorRefreshHandle, WalletNetworkHealth, WalletSessionStore,
    settings::{EffectiveChainConfig, EffectiveTokenRegistry, load_wallet_settings},
    subscribe_prover_cache_build,
    vault::{
        DesktopVaultStore, DesktopViewSession, GeneratedSeedMaterial, PublicAccountMetadata,
        WalletMetadataBundle,
    },
};
use zeroize::Zeroizing;

mod actions;
mod broadcaster_picker;
mod chain_load;
mod dialogs;
mod gas_fee;
mod manage_wallets;
mod network;
mod private_action;
mod private_assets;
mod private_broadcaster;
mod public_account;
mod public_action;
mod public_balances;
mod public_broadcaster;
mod public_broadcaster_cost;
mod settings;
mod shell;
mod sidebar;
mod spend_authorization;
mod startup;
mod tokens;
mod ui_helpers;
mod utxo;
mod vault;
mod vault_ui;
mod wallet_header;

#[cfg(test)]
mod tests;

pub(crate) use actions::{install_utxo_navigation_bindings, install_wallet_action_bindings};
pub(crate) use shell::{WalletAppOptions, open_wallet_window};

use broadcaster_picker::BroadcasterPickerState;
use chain_load::{ChainUtxoState, chain_load_overrides, start_shared_poi_cache_service};
use gas_fee::Eip1559GasFeeEditorState;
use manage_wallets::ManageWalletsState;
use network::TorExitIpQueryState;
use private_action::{
    DeliveryFormKind, DeliveryMode, PrivateActionFormState, SendFormState, UnshieldAsset,
    UnshieldAssetKey, UnshieldFormState,
};
use private_broadcaster::PrivateBroadcasterProgressState;
use public_account::PublicAccountFormState;
use public_action::PublicActionMode;
use public_balances::{
    public_account_visible_balances_for_chain, public_asset_decimals, public_asset_label,
    public_balance_amount_label,
};
use public_broadcaster::{
    PublicBroadcasterFeeTokenOption, broadcaster_candidate_anchor_rate,
    effective_public_broadcaster_fee_mode, ethereum_weth_public_broadcaster_count,
    public_broadcaster_fee_token_warning, public_broadcaster_submit_disabled_for_fee_token_options,
    send_form_max_entered_amount, should_show_broadcaster_fee_mode_toggle,
    should_show_distinct_amount, unshield_form_max_entered_amount,
};
use settings::WalletSettingsEditor;
use shell::WalletTab;
use sidebar::Activity;
use spend_authorization::{SpendAuthorizationCache, SpendAuthorizationLifetime};
use startup::WalletStartupRoot;
use tokens::{
    format_exact_token_amount_for_display, format_native_token_amount_for_display,
    format_send_amount_input, format_unshield_amount_input, is_effective_wrapped_native_token,
    native_token_display_label, native_wrapped_output_labels, parse_address, token_display_label,
    token_display_metadata,
};
use ui_helpers::{
    centered_message, labeled_field, rgb_with_alpha, secondary_dialog_content_width,
    token_label_row,
};
use utxo::{BlockedShieldRescueRowState, UtxoDelegate, should_focus_utxo_table};
use vault::{VaultState, WalletOption, WalletSetupMode, vault_error_kind};
use wallet_header::{ChainSelectItem, WalletSelectItem};

#[cfg(test)]
use broadcaster_picker::{
    BroadcasterChoice, broadcaster_choice_supported_by_candidates,
    should_preserve_estimate_after_broadcaster_policy_change,
};
#[cfg(test)]
use chain_load::{loading_summary, progress_detail, wallet_generation_matches};
#[cfg(test)]
use gas_fee::{format_gwei, parse_gwei_to_wei, validate_custom_gas_fee};
#[cfg(test)]
use manage_wallets::{
    WalletManagementSelection, active_wallet_management_rows, hidden_wallet_management_rows,
    selected_wallet_after_metadata_refresh, wallet_ids_after_drop,
};
#[cfg(test)]
use private_action::{
    PrivateActionMetric, SEND_AUTHORIZATION_FAILED_ERROR, SelfBroadcastNativeBalanceState,
    UNSHIELD_AUTHORIZATION_FAILED_ERROR, adjusted_amount_for_max_change,
    default_self_broadcast_gas_payer_uuid, form_error_clears_public_broadcaster_cost_estimate,
    format_exact_asset_amount_for_display, format_form_error_for_asset,
    private_action_assets_from_snapshot, private_action_metric_display_amount,
    private_action_metrics, random_self_broadcast_gas_payer_uuid,
    self_broadcast_gas_payer_matches_search, self_broadcast_native_balance_label,
    self_broadcast_native_balance_state, send_element_id,
    send_public_broadcaster_estimate_input_error, unshield_element_id,
    unshield_public_broadcaster_estimate_input_error,
};
#[cfg(test)]
use private_assets::{
    format_private_asset_rows, format_total, max_send_amount_from_snapshot,
    max_unshield_amount_from_snapshot, private_asset_display_amounts,
    refresh_form_asset_from_snapshot, send_asset_key_from_formatted, send_key_matches_asset,
    unshield_asset_key_from_formatted, unshield_key_matches_asset,
};
#[cfg(test)]
use private_broadcaster::{
    apply_private_broadcaster_progress_stage, ensure_self_broadcast_unshield_progress_stage,
    fail_private_broadcaster_progress_steps_at_stage, finish_private_broadcaster_progress_steps,
    finish_private_broadcaster_progress_steps_at_stage,
    finish_private_self_broadcast_progress_steps_at_stage,
    mark_private_broadcaster_active_step_stopped, private_broadcaster_progress_footer_action,
    private_broadcaster_progress_steps, private_progress_stage_disables_stop,
    self_broadcast_progress_steps,
};
#[cfg(test)]
use public_account::{
    PUBLIC_ACCOUNT_IDENTICON_CELL_COUNT, PUBLIC_ACCOUNT_IDENTICON_GRID_SIZE,
    PUBLIC_ADDRESS_QR_QUIET_ZONE_MODULES, next_public_account_label_number,
    public_account_identicon_color, public_account_identicon_pattern,
    public_account_matches_search, public_address_qr_module_range, public_address_qr_payload,
};
#[cfg(test)]
use public_action::{
    ProgressFooterAction, PublicActionStepState, PublicActionStepStatus,
    mark_public_action_active_step_stopped, progress_footer_action, public_action_accepts_update,
    public_action_closed_active_step, public_action_error_copy_value, public_action_error_details,
    public_action_error_summary, public_action_max_amount_after_reserve,
    public_action_progress_footer_action, public_action_progress_steps, public_action_step_color,
    public_action_step_detail, public_action_step_is_final_handoff,
    public_action_step_uses_stop_marker,
};
#[cfg(test)]
use public_balances::{
    merge_public_balance_snapshot, public_asset_icon_path, public_balance_entry_for_chain,
    public_balance_usd_label,
};
#[cfg(test)]
use public_broadcaster::{
    fee_token_option_has_eligible_broadcaster, public_broadcaster_fee_token_options_from_snapshot,
    required_relay_adapt_for_unwrap, resolve_selected_public_broadcaster_fee_token,
};
#[cfg(test)]
use public_broadcaster_cost::{
    CostEstimateStatus, format_public_broadcaster_fee_margin, public_broadcaster_cost_status_text,
    should_render_public_broadcaster_cost_preview,
};
#[cfg(test)]
use settings::{
    PriceAnchorComponentDialogValues, PriceAnchorDialogValues, SettingsApplyMode,
    StartupSettingsActionState, add_chain_rpc_endpoint, add_poi_gateway_url, add_waku_direct_peer,
    add_waku_dns_enr_tree, add_waku_doh_fallback_endpoint, classify_settings_apply_mode,
    display_chain_contract_settings, display_chain_quick_sync_endpoint,
    display_chain_rpc_endpoints, display_price_anchor_entries, display_token_entries,
    display_waku_direct_peers, display_waku_dns_enr_trees, display_waku_doh_endpoint,
    display_waku_doh_fallback_endpoints, format_anchor_bps_exact_range, format_anchor_bps_percent,
    format_anchor_bps_percent_range, format_anchor_premium_range,
    price_anchor_dialog_values_from_entry, price_anchor_override_from_dialog_values,
    price_anchor_token_primary_label, remove_chain_rpc_endpoint, remove_poi_gateway_url,
    remove_waku_direct_peer, remove_waku_dns_enr_tree, remove_waku_doh_fallback_endpoint,
    set_chain_rpc_endpoint, set_poi_gateway_url, set_price_anchor_override, set_waku_direct_peer,
    set_waku_dns_enr_tree, set_waku_doh_fallback_endpoint, settings_draft_after_discard,
    settings_restart_action_enabled, settings_restart_reuses_active_network,
    settings_save_action_enabled, should_show_proxy_url_setting, should_show_proxy_waku_disclaimer,
    startup_settings_action_state,
};
#[cfg(test)]
use sidebar::sidebar_primary_activity_order;
#[cfg(test)]
use spend_authorization::{
    is_spend_authorization_failure_error, remembered_spend_authorization_valid_for_test,
};
#[cfg(test)]
use startup::load_validated_startup_settings;
#[cfg(test)]
use utxo::{
    activity_classification_icon_style, apply_blocked_shield_rescue_rows, display_rows_from_output,
    format_compact_age, should_show_blocked_shield_refund_action,
};
#[cfg(test)]
use vault::wallet_options_from_metadata;
#[cfg(test)]
use vault_ui::should_show_pre_unlock_settings_action;
#[cfg(test)]
use wallet_header::{parse_repair_cache_block, repair_cache_help_text};
#[cfg(test)]
use wallet_ops::public_broadcaster_candidates_for_asset;

const SIDEBAR_WIDTH: Pixels = px(220.0);
const SIDEBAR_AUTO_COLLAPSE_WIDTH: Pixels = px(900.0);
const LOGS_DRAWER_HEIGHT: Pixels = px(260.0);
const LOGS_DRAWER_MIN_HEIGHT: Pixels = px(160.0);
const LOGS_DRAWER_MAX_HEIGHT: Pixels = px(600.0);
const BROADCASTER_PICKER_MAX_HEIGHT: Pixels = px(680.0);
const PRIVATE_ACTION_FORM_MAX_HEIGHT: Pixels = px(820.0);
const PRIVATE_ASSET_LIST_WIDTH: Pixels = px(760.0);
const PRIVATE_BROADCASTER_PROGRESS_DIALOG_WIDTH: Pixels = px(560.0);
const PUBLIC_ACCOUNT_DIALOG_WIDTH: Pixels = px(460.0);
const PUBLIC_ADDRESS_QR_DIALOG_WIDTH: Pixels = px(440.0);
const PUBLIC_ACTION_DIALOG_WIDTH: Pixels = px(520.0);
const HERO_STAGE_MAX_WIDTH: Pixels = px(1440.0);
const HERO_WIDE_BREAKPOINT: Pixels = px(1280.0);
const HERO_MEDIUM_BREAKPOINT: Pixels = px(720.0);
const HERO_CARD_MAX_WIDTH: Pixels = px(520.0);
const NETWORK_HEALTH_REFRESH_INTERVAL: Duration = Duration::from_secs(5);
const TOR_HEALTH_RETRY_TIMEOUT: Duration = Duration::from_secs(5);
const TOR_EXIT_IP_QUERY_TIMEOUT: Duration = Duration::from_secs(10);
const TOR_EXIT_IP_QUERY_URL: &str = "https://ifconfig.me/ip";
const UNSHIELD_SPINNER_REFRESH_INTERVAL: Duration = Duration::from_millis(250);
const UTXO_AGE_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const COST_ESTIMATE_DEBOUNCE: Duration = Duration::from_secs(1);
const SECONDS_PER_MINUTE: u64 = 60;
const SECONDS_PER_HOUR: u64 = 60 * SECONDS_PER_MINUTE;
const SECONDS_PER_DAY: u64 = 24 * SECONDS_PER_HOUR;
const SECONDS_PER_MONTH: u64 = 30 * SECONDS_PER_DAY;
const SECONDS_PER_YEAR: u64 = 365 * SECONDS_PER_DAY;
const TABLE_KEY_CONTEXT: &str = "Table";
const PROVER_CACHE_BUILD_DISCOVERY_INTERVAL: Duration = Duration::from_secs(1);
pub(crate) struct WalletRoot {
    options: WalletAppOptions,
    vault_store: Option<Arc<DesktopVaultStore>>,
    poi_read_source: PoiReadSource,
    effective_chain_configs: BTreeMap<u64, EffectiveChainConfig>,
    effective_token_registry: EffectiveTokenRegistry,
    public_balance_refresh_interval: Duration,
    public_broadcaster_policy: BroadcasterFeePolicy,
    public_broadcaster_response_timeout: Duration,
    public_broadcaster_republish_interval: Duration,
    default_allow_suspicious_broadcasters: bool,
    vault_state: VaultState,
    wallet_setup_mode: WalletSetupMode,
    vault_error: Option<Arc<str>>,
    unlock_in_progress: bool,
    repair_cache_error: Option<Arc<str>>,
    setup_password: Option<Zeroizing<String>>,
    spend_authorization_cache: Option<SpendAuthorizationCache>,
    spend_authorization_lifetime: SpendAuthorizationLifetime,
    view_session: Option<Arc<DesktopViewSession>>,
    generated_seed: Option<GeneratedSeedMaterial>,
    http: HttpContext,
    network_health: WalletNetworkHealth,
    waku_worker_shutdown: watch::Sender<bool>,
    network_status_popover_open: bool,
    network_status_error: Option<Arc<str>>,
    tor_exit_ip_query: TorExitIpQueryState,
    tor_state_reset_confirming: bool,
    prover_cache_build_progress: Option<ProverCacheBuildProgress>,
    prover_cache_build_popover_open: bool,
    prover_cache_build_monitor_active: bool,
    prover_cache_build_completed: bool,
    runtime: Handle,
    monitor_state: Shared,
    waku: Arc<PublicBroadcasterWakuClient>,
    public_broadcaster_anchor_cache: Arc<TokenAnchorRateCache>,
    public_broadcaster_anchor_refresh: TokenAnchorRefreshHandle,
    monitor: Entity<broadcaster_monitor_gpui::BroadcasterMonitorPane>,
    logs: Entity<LogsPane>,
    settings_editor: Option<Entity<WalletSettingsEditor>>,
    settings_error: Option<Arc<str>>,
    active_activity: Activity,
    active_wallet_tab: WalletTab,
    sidebar_manually_collapsed: bool,
    sidebar_narrow_expanded: bool,
    sidebar_public_broadcaster_count: usize,
    wallet_select: Entity<SelectState<SearchableVec<WalletSelectItem>>>,
    wallet_metadata: Vec<WalletMetadataBundle>,
    wallet_options: Vec<WalletOption>,
    manage_wallets: ManageWalletsState,
    manage_wallet_label_input: Entity<InputState>,
    selected_wallet_id: Option<Arc<str>>,
    active_wallet_generation: u64,
    wallet_switch_generation: u64,
    selected_chain: u64,
    chain_select: Entity<SelectState<Vec<ChainSelectItem>>>,
    chain_states: BTreeMap<u64, ChainUtxoState>,
    poi_cache_service: Option<Arc<PoiCacheService>>,
    session_store: Arc<OnceCell<Arc<WalletSessionStore>>>,
    unlock_password_input: Entity<InputState>,
    new_password_input: Entity<InputState>,
    confirm_password_input: Entity<InputState>,
    wallet_name_input: Entity<InputState>,
    add_wallet_password_input: Entity<InputState>,
    import_mnemonic_input: Entity<InputState>,
    public_accounts: Vec<PublicAccountMetadata>,
    public_form: PublicAccountFormState,
    public_balance_snapshot: Option<Arc<PublicBalanceSnapshot>>,
    public_balance_error: Option<Arc<str>>,
    public_balance_refreshing: bool,
    public_balance_generation: u64,
    public_inactive_balance_error: Option<Arc<str>>,
    public_inactive_balance_refreshing: bool,
    public_inactive_balance_generation: u64,
    send_forms: BTreeMap<UnshieldAssetKey, SendFormState>,
    private_action_form: Option<PrivateActionFormState>,
    send_generation_seq: u64,
    unshield_generation_seq: u64,
    cost_estimate_seq: u64,
    unshield_forms: BTreeMap<UnshieldAssetKey, UnshieldFormState>,
    private_broadcaster_progress: Option<PrivateBroadcasterProgressState>,
    broadcaster_picker: Option<BroadcasterPickerState>,
    unshield_spinner_tick: usize,
    repair_cache_block_input: Entity<InputState>,
    tx_search_input: Entity<InputState>,
    tx_search_query: Arc<str>,
    show_spent_utxos: bool,
    local_pending_spent_clear_confirming: bool,
    blocked_shield_rescue_lookup_generation: u64,
    blocked_shield_rescue_rows: BTreeMap<BlockedShieldRescueUtxoId, BlockedShieldRescueRowState>,
    blocked_shield_refunds_in_flight: BTreeSet<BlockedShieldRescueUtxoId>,
    utxo_table: Entity<TableState<UtxoDelegate>>,
    focus_vault_input_on_render: bool,
    focus_utxo_table_on_render: bool,
    focus_public_account_search_on_render: bool,
    logs_open: bool,
    drawer_split: Entity<ResizableState>,
}

impl Drop for WalletRoot {
    fn drop(&mut self) {
        let _ = self.waku_worker_shutdown.send(true);
        if let Some(service) = self.poi_cache_service.as_ref() {
            service.shutdown();
        }
        if let Some(store) = self.session_store.get().cloned() {
            self.runtime.spawn(async move {
                store.shutdown().await;
            });
        }
    }
}

impl WalletRoot {
    const fn is_prover_cache_building(&self) -> bool {
        self.prover_cache_build_progress.is_some()
    }

    fn wallet_db_root_dir(&self) -> Option<PathBuf> {
        self.vault_store
            .as_ref()
            .map(|store| store.db().root_dir().to_path_buf())
    }

    fn ensure_prover_cache_build_monitor(&mut self, cx: &Context<'_, Self>) {
        if self.prover_cache_build_monitor_active {
            return;
        }
        let Some(db_path) = self.wallet_db_root_dir() else {
            return;
        };
        self.prover_cache_build_monitor_active = true;
        cx.spawn(async move |this, cx| {
            loop {
                if let Some(mut progress_rx) = subscribe_prover_cache_build(&db_path) {
                    let progress = progress_rx.borrow().clone();
                    if this
                        .update(cx, |root, cx| {
                            root.set_prover_cache_build_progress(progress, cx);
                        })
                        .is_err()
                    {
                        break;
                    }

                    loop {
                        if progress_rx.changed().await.is_err() {
                            let _ = this.update(cx, |root, cx| {
                                root.set_prover_cache_build_progress(None, cx);
                            });
                            break;
                        }
                        let progress = progress_rx.borrow().clone();
                        let is_complete = progress.is_none();
                        if this
                            .update(cx, |root, cx| {
                                root.set_prover_cache_build_progress(progress, cx);
                            })
                            .is_err()
                        {
                            return;
                        }
                        if is_complete {
                            break;
                        }
                    }
                }

                cx.background_executor()
                    .timer(PROVER_CACHE_BUILD_DISCOVERY_INTERVAL)
                    .await;
            }
        })
        .detach();
    }

    fn set_prover_cache_build_progress(
        &mut self,
        progress: Option<ProverCacheBuildProgress>,
        cx: &mut Context<'_, Self>,
    ) {
        self.prover_cache_build_progress = progress;
        if self.prover_cache_build_progress.is_none() {
            self.prover_cache_build_popover_open = false;
        }
        cx.notify();
    }

    fn update_prover_cache_build_progress(
        &mut self,
        progress: ProverCacheBuildProgress,
        cx: &mut Context<'_, Self>,
    ) {
        self.prover_cache_build_progress = Some(progress);
        cx.notify();
    }

    fn finish_prover_cache_build_progress(&mut self, cx: &mut Context<'_, Self>) {
        self.prover_cache_build_progress = None;
        self.prover_cache_build_popover_open = false;
        cx.notify();
    }

    fn set_prover_cache_build_popover_open(&mut self, open: bool, cx: &mut Context<'_, Self>) {
        if self.prover_cache_build_popover_open != open {
            self.prover_cache_build_popover_open = open;
            cx.notify();
        }
    }
}

impl WalletRoot {
    fn new(
        options: WalletAppOptions,
        http: HttpContext,
        waku_worker_shutdown: watch::Sender<bool>,
        vault_store: Arc<DesktopVaultStore>,
        chain_ids: &[u64],
        effective_chain_configs: BTreeMap<u64, EffectiveChainConfig>,
        effective_token_registry: EffectiveTokenRegistry,
        public_balance_refresh_interval: Duration,
        public_broadcaster_policy: BroadcasterFeePolicy,
        public_broadcaster_response_timeout: Duration,
        public_broadcaster_republish_interval: Duration,
        default_allow_suspicious_broadcasters: bool,
        poi_read_source: PoiReadSource,
        runtime: Handle,
        monitor_state: Shared,
        waku: Arc<PublicBroadcasterWakuClient>,
        public_broadcaster_anchor_cache: Arc<TokenAnchorRateCache>,
        public_broadcaster_anchor_refresh: TokenAnchorRefreshHandle,
        mut monitor_event_rx: EventRx,
        monitor: Entity<broadcaster_monitor_gpui::BroadcasterMonitorPane>,
        logs: Entity<LogsPane>,
        startup_root: &Entity<WalletStartupRoot>,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) -> Self {
        let chain_select_items: Vec<_> = chain_ids
            .iter()
            .copied()
            .map(|chain_id| ChainSelectItem { chain_id })
            .collect();
        let initial_chain_id = chain_ids[0];
        let selected_chain_index = Some(IndexPath::default().row(0));
        let mut chain_states = BTreeMap::new();
        for chain_id in chain_ids {
            chain_states.insert(*chain_id, ChainUtxoState::Idle);
        }
        let vault_store = Some(vault_store);
        let poi_cache_service = start_shared_poi_cache_service(
            &poi_read_source,
            vault_store.as_ref(),
            &http,
            &runtime,
            chain_ids,
        );
        let (settings_editor, settings_error) = match vault_store.as_ref() {
            Some(store) => {
                let db = store.db();
                match load_wallet_settings(db.as_ref()) {
                    Ok(settings) => (
                        Some(cx.new({
                            let store = Arc::clone(store);
                            let runtime = runtime.clone();
                            let startup_root = startup_root.clone();
                            let active_root = cx.weak_entity();
                            move |_| {
                                WalletSettingsEditor::new(
                                    store,
                                    runtime,
                                    settings,
                                    Some(startup_root),
                                    Some(active_root),
                                )
                            }
                        })),
                        None,
                    ),
                    Err(error) => (None, Some(Arc::from(error.to_string()))),
                }
            }
            None => (None, Some(Arc::from("Wallet database is unavailable"))),
        };
        let (vault_state, vault_error) = match vault_store.as_ref() {
            Some(store) => match store.vault_exists() {
                Ok(true) => (VaultState::UnlockVault, None),
                Ok(false) => (VaultState::CreateVault, None),
                Err(error) => (
                    VaultState::Error(Arc::from("Failed to inspect wallet vault storage")),
                    Some(Arc::from(error.to_string())),
                ),
            },
            None => (
                VaultState::Error(Arc::from("Failed to open wallet vault storage")),
                None,
            ),
        };
        let focus_vault_input_on_render = matches!(
            vault_state,
            VaultState::CreateVault | VaultState::UnlockVault
        );
        let unlock_password_input = new_masked_input(window, cx, "vault password");
        let new_password_input = new_masked_input(window, cx, "new vault password");
        let confirm_password_input = new_masked_input(window, cx, "confirm vault password");
        let wallet_name_input = new_text_input(window, cx, "wallet name");
        let manage_wallet_label_input = new_text_input(window, cx, "wallet label");
        let add_wallet_password_input = new_masked_input(window, cx, "vault password");
        let import_mnemonic_input = cx.new(|cx| {
            InputState::new(window, cx)
                .auto_grow(3, 6)
                .placeholder("paste recovery phrase")
        });
        let public_account_search_input = new_text_input(window, cx, "search accounts");
        let public_form = PublicAccountFormState {
            add_label_input: new_text_input(window, cx, "account label"),
            add_password_input: new_masked_input(window, cx, "vault password"),
            import_label_input: new_text_input(window, cx, "account label"),
            import_private_key_input: new_masked_input(window, cx, "private key hex"),
            import_password_input: new_masked_input(window, cx, "vault password"),
            edit_label_input: new_text_input(window, cx, "account label"),
            search_input: public_account_search_input.clone(),
            send_recipient_input: new_text_input(window, cx, "0x recipient"),
            send_amount_input: new_text_input(window, cx, "amount"),
            shield_amount_input: new_text_input(window, cx, "amount"),
            send_gas_fee: Eip1559GasFeeEditorState::new(window, cx),
            shield_gas_fee: Eip1559GasFeeEditorState::new(window, cx),
            import_global: false,
            selected_account_uuid: None,
            editing_account_uuid: None,
            search_query: Arc::from(""),
            selected_asset: None,
            action_mode: PublicActionMode::Shield,
            action_generation: 0,
            action_progress: Vec::new(),
            expanded_action_error_steps: BTreeSet::new(),
            action_progress_dialog_open: false,
            action_progress_asset_label: Arc::from(""),
            action_progress_icon_path: None,
            action_task_abort_handle: None,
            action_stop_available: false,
            action_stopped: false,
            action_command_tx: None,
            action_attempts: Vec::new(),
            action_current_gas_fee: None,
            action_action_error: None,
            next_derived_index: None,
            next_account_label_number: 1,
            error: None,
            send_error: None,
            shield_error: None,
            adding_account: false,
            importing_account: false,
            sending: false,
            shielding: false,
            active_accounts_open: true,
            inactive_accounts_open: false,
            pending_global_delete_uuid: None,
        };
        let repair_cache_block_input = new_text_input(window, cx, "0 = deployment block");
        let tx_search_input = new_text_input(window, cx, "search tx hash");
        let chain_select =
            cx.new(|cx| SelectState::new(chain_select_items, selected_chain_index, window, cx));
        let wallet_select = cx.new(|cx| {
            SelectState::new(SearchableVec::new(Vec::new()), None, window, cx).searchable(true)
        });
        let root_weak = cx.weak_entity();
        let utxo_table = cx.new(|cx| {
            TableState::new(
                UtxoDelegate::new(root_weak.clone(), tx_search_input.clone()),
                window,
                cx,
            )
        });
        let network_health = http.network_health();
        let sidebar_public_broadcaster_count =
            ethereum_weth_public_broadcaster_count(&monitor_state.read().fee_rows());
        let mut anchor_refresh_rx = public_broadcaster_anchor_cache.subscribe_refreshes();
        let root = Self {
            selected_chain: initial_chain_id,
            options,
            vault_store,
            poi_read_source,
            effective_chain_configs,
            effective_token_registry,
            public_balance_refresh_interval,
            public_broadcaster_policy,
            public_broadcaster_response_timeout,
            public_broadcaster_republish_interval,
            default_allow_suspicious_broadcasters,
            vault_state,
            wallet_setup_mode: WalletSetupMode::Choose,
            vault_error,
            unlock_in_progress: false,
            repair_cache_error: None,
            setup_password: None,
            spend_authorization_cache: None,
            spend_authorization_lifetime: SpendAuthorizationLifetime::Once,
            view_session: None,
            generated_seed: None,
            http,
            network_health,
            waku_worker_shutdown,
            network_status_popover_open: false,
            network_status_error: None,
            tor_exit_ip_query: TorExitIpQueryState::Idle,
            tor_state_reset_confirming: false,
            prover_cache_build_progress: None,
            prover_cache_build_popover_open: false,
            prover_cache_build_monitor_active: false,
            prover_cache_build_completed: false,
            runtime,
            monitor_state,
            waku,
            public_broadcaster_anchor_cache,
            public_broadcaster_anchor_refresh,
            monitor,
            logs,
            settings_editor,
            settings_error,
            active_activity: Activity::Wallet,
            active_wallet_tab: WalletTab::default(),
            sidebar_manually_collapsed: false,
            sidebar_narrow_expanded: false,
            sidebar_public_broadcaster_count,
            wallet_select: wallet_select.clone(),
            wallet_metadata: Vec::new(),
            wallet_options: Vec::new(),
            manage_wallets: ManageWalletsState::default(),
            manage_wallet_label_input,
            selected_wallet_id: None,
            active_wallet_generation: 0,
            wallet_switch_generation: 0,
            chain_select: chain_select.clone(),
            chain_states,
            poi_cache_service,
            session_store: Arc::new(OnceCell::new()),
            unlock_password_input,
            new_password_input,
            confirm_password_input,
            wallet_name_input,
            add_wallet_password_input,
            import_mnemonic_input,
            public_accounts: Vec::new(),
            public_form,
            public_balance_snapshot: None,
            public_balance_error: None,
            public_balance_refreshing: false,
            public_balance_generation: 0,
            public_inactive_balance_error: None,
            public_inactive_balance_refreshing: false,
            public_inactive_balance_generation: 0,
            send_forms: BTreeMap::new(),
            private_action_form: None,
            send_generation_seq: 0,
            unshield_generation_seq: 0,
            cost_estimate_seq: 0,
            unshield_forms: BTreeMap::new(),
            private_broadcaster_progress: None,
            broadcaster_picker: None,
            unshield_spinner_tick: 0,
            repair_cache_block_input,
            tx_search_input: tx_search_input.clone(),
            tx_search_query: Arc::from(""),
            show_spent_utxos: false,
            local_pending_spent_clear_confirming: false,
            blocked_shield_rescue_lookup_generation: 0,
            blocked_shield_rescue_rows: BTreeMap::new(),
            blocked_shield_refunds_in_flight: BTreeSet::new(),
            utxo_table,
            focus_vault_input_on_render,
            focus_utxo_table_on_render: false,
            focus_public_account_search_on_render: false,
            logs_open: false,
            drawer_split: cx.new(|_| ResizableState::default()),
        };
        cx.subscribe(&tx_search_input, |this, input, event: &InputEvent, cx| {
            if matches!(event, InputEvent::Change) {
                let query = input.read(cx).value().trim().to_ascii_lowercase();
                this.tx_search_query = Arc::from(query);
                this.sync_utxo_table(cx);
                cx.notify();
            }
        })
        .detach();
        cx.subscribe(
            &public_account_search_input,
            |this, input, event: &InputEvent, cx| {
                if matches!(event, InputEvent::Change) {
                    let query = input.read(cx).value().trim().to_ascii_lowercase();
                    this.public_form.search_query = Arc::from(query);
                    cx.notify();
                }
            },
        )
        .detach();
        cx.subscribe_in(
            &chain_select,
            window,
            |this, _select, event: &SelectEvent<Vec<ChainSelectItem>>, window, cx| {
                let SelectEvent::Confirm(Some(chain_id)) = event else {
                    return;
                };
                this.select_chain(*chain_id, window, cx);
                cx.defer_in(window, |_this, window, _cx| {
                    window.blur();
                });
            },
        )
        .detach();
        cx.subscribe_in(
            &wallet_select,
            window,
            |this, _select, event: &SelectEvent<SearchableVec<WalletSelectItem>>, window, cx| {
                let SelectEvent::Confirm(Some(value)) = event else {
                    return;
                };
                this.select_wallet(value.as_ref(), window, cx);
                cx.defer_in(window, |_this, window, _cx| {
                    window.blur();
                });
            },
        )
        .detach();
        cx.subscribe_in(
            &root.unlock_password_input,
            window,
            |this, _input, event: &InputEvent, window, cx| {
                if matches!(event, InputEvent::PressEnter { .. }) {
                    this.unlock_vault_from_input(window, cx);
                }
            },
        )
        .detach();
        cx.subscribe_in(
            &root.new_password_input,
            window,
            |this, input, event: &InputEvent, window, cx| {
                if !matches!(event, InputEvent::PressEnter { .. }) {
                    return;
                }
                let password_entered = !input.read(cx).value().trim().is_empty();
                let confirm_empty = this
                    .confirm_password_input
                    .read(cx)
                    .value()
                    .trim()
                    .is_empty();
                if password_entered && confirm_empty {
                    this.confirm_password_input
                        .read(cx)
                        .focus_handle(cx)
                        .focus(window);
                } else {
                    this.create_vault_from_inputs(window, cx);
                }
            },
        )
        .detach();
        cx.subscribe_in(
            &root.confirm_password_input,
            window,
            |this, _input, event: &InputEvent, window, cx| {
                if matches!(event, InputEvent::PressEnter { .. }) {
                    this.create_vault_from_inputs(window, cx);
                }
            },
        )
        .detach();
        cx.subscribe(
            &root.repair_cache_block_input,
            |this, _input, event: &InputEvent, cx| {
                if matches!(event, InputEvent::PressEnter { .. }) {
                    this.repair_wallet_cache_from_input(cx);
                }
            },
        )
        .detach();
        cx.subscribe_in(
            &root.manage_wallet_label_input,
            window,
            |this, _input, event: &InputEvent, window, cx| {
                if matches!(event, InputEvent::PressEnter { .. }) {
                    this.save_wallet_label_edit(window, cx);
                }
            },
        )
        .detach();
        cx.subscribe(&root.utxo_table, |_, table, event: &TableEvent, cx| {
            if let TableEvent::ColumnWidthsChanged(widths) = event {
                table.update(cx, |table, cx| {
                    table.delegate_mut().set_column_widths(widths);
                    cx.notify();
                });
            }
        })
        .detach();
        cx.spawn(async move |this, cx| {
            while monitor_event_rx.changed().await.is_ok() {
                if this
                    .update(cx, |root, cx| {
                        let current_public_broadcaster_count =
                            ethereum_weth_public_broadcaster_count(&root.monitor_fee_rows());
                        let public_broadcaster_count_changed = root
                            .sidebar_public_broadcaster_count
                            != current_public_broadcaster_count;
                        root.sidebar_public_broadcaster_count = current_public_broadcaster_count;
                        if root
                            .send_forms
                            .values()
                            .any(|form| form.delivery_mode == DeliveryMode::PublicBroadcaster)
                            || root
                                .unshield_forms
                                .values()
                                .any(|form| form.delivery_mode == DeliveryMode::PublicBroadcaster)
                            || public_broadcaster_count_changed
                        {
                            cx.notify();
                        }
                    })
                    .is_err()
                {
                    break;
                }
            }
        })
        .detach();
        cx.spawn(async move |this, cx| {
            while anchor_refresh_rx.changed().await.is_ok() {
                if this.update(cx, |_root, cx| cx.notify()).is_err() {
                    break;
                }
            }
        })
        .detach();
        cx.subscribe_in(
            &root.public_form.add_password_input,
            window,
            |this, _input, event: &InputEvent, window, cx| {
                if matches!(event, InputEvent::PressEnter { .. }) {
                    this.add_public_derived_account_from_input(window, cx);
                }
            },
        )
        .detach();
        cx.subscribe_in(
            &root.public_form.import_password_input,
            window,
            |this, _input, event: &InputEvent, window, cx| {
                if matches!(event, InputEvent::PressEnter { .. }) {
                    this.import_public_account_from_input(window, cx);
                }
            },
        )
        .detach();
        cx.subscribe_in(
            &root.public_form.edit_label_input,
            window,
            |this, _input, event: &InputEvent, window, cx| {
                if matches!(event, InputEvent::PressEnter { .. }) {
                    this.update_selected_public_account_label(window, cx);
                }
            },
        )
        .detach();
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(UTXO_AGE_REFRESH_INTERVAL)
                    .await;
                if this
                    .update(cx, |root, cx| {
                        if matches!(
                            root.chain_states.get(&root.selected_chain),
                            Some(state) if state.snapshot().is_some()
                        ) {
                            root.utxo_table.update(cx, |_table, cx| cx.notify());
                            cx.notify();
                        }
                    })
                    .is_err()
                {
                    break;
                }
            }
        })
        .detach();
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(UNSHIELD_SPINNER_REFRESH_INTERVAL)
                    .await;
                if this
                    .update(cx, |root, cx| {
                        if root.send_forms.values().any(|form| {
                            form.generating || form.cost_estimate_pending || form.estimating_cost
                        }) || root.unshield_forms.values().any(|form| {
                            form.generating || form.cost_estimate_pending || form.estimating_cost
                        }) {
                            root.unshield_spinner_tick = root.unshield_spinner_tick.wrapping_add(1);
                            cx.notify();
                        }
                    })
                    .is_err()
                {
                    break;
                }
            }
        })
        .detach();
        let public_balance_refresh_interval = root.public_balance_refresh_interval;
        cx.spawn(async move |this, cx| {
            let interval = public_balance_refresh_interval;
            loop {
                cx.background_executor().timer(interval).await;
                if this
                    .update(cx, |root, cx| {
                        if root.active_wallet_tab == WalletTab::Public {
                            root.schedule_public_balance_refresh(cx);
                        }
                    })
                    .is_err()
                {
                    break;
                }
            }
        })
        .detach();
        root.spawn_network_health_monitor(cx);
        root
    }
}

pub(super) fn new_text_input<T>(
    window: &mut Window,
    cx: &mut Context<'_, T>,
    placeholder: &'static str,
) -> Entity<InputState> {
    cx.new(|cx| InputState::new(window, cx).placeholder(placeholder))
}

pub(super) fn new_masked_input<T>(
    window: &mut Window,
    cx: &mut Context<'_, T>,
    placeholder: &'static str,
) -> Entity<InputState> {
    cx.new(|cx| {
        InputState::new(window, cx)
            .placeholder(placeholder)
            .masked(true)
    })
}

pub(super) fn new_prefilled_input<T>(
    window: &mut Window,
    cx: &mut Context<'_, T>,
    placeholder: &'static str,
    value: impl Into<SharedString>,
) -> Entity<InputState> {
    let value = value.into();
    cx.new(move |cx| {
        let mut input = InputState::new(window, cx).placeholder(placeholder);
        input.set_value(value.clone(), window, cx);
        input
    })
}

fn format_report_chain(error: &eyre::Report) -> String {
    let mut parts = error.chain().map(ToString::to_string);
    let Some(mut message) = parts.next() else {
        return error.to_string();
    };
    for part in parts {
        if message.ends_with(&part) {
            continue;
        }
        message.push_str(": ");
        message.push_str(&part);
    }
    message
}
