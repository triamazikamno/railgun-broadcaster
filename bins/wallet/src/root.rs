use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::primitives::{Address, U256};
use broadcaster_monitor::{EventRx, Shared};
use chrono::{DateTime, Local, Utc};
use gpui::{
    App, AppContext, Bounds, Context, Entity, FocusHandle, Focusable, InteractiveElement,
    IntoElement, KeyBinding, MouseButton, ParentElement, Pixels, Point, Render, SharedString,
    StatefulInteractiveElement, Styled, Window, WindowBounds, WindowOptions, div, img,
    prelude::FluentBuilder as _, px, relative, rgb, size,
};
use gpui_component::{
    Disableable, Root, Selectable, Sizable, StyledExt,
    button::{Button, ButtonGroup, ButtonVariants},
    input::{Input, InputEvent, InputState},
    popover::Popover,
    resizable::{ResizableState, resizable_panel, v_resizable},
    scroll::ScrollableElement,
    table::{Column, Table, TableDelegate, TableState},
    tooltip::Tooltip,
    v_flex,
};
use railgun_ui::{
    DEFAULT_CHAINS, chain_icon_path, chain_name, format_broadcaster_address_label,
    format_token_amount, lookup_token, short_address, token_icon_path,
};
use reqwest::Url;
use tokio::runtime::Handle;
use tokio::sync::{OnceCell, watch};
use ui::clipboard::copy_with_toast;
use ui::controls::{app_button, app_button_base, app_input, app_muted_text, app_strong_text};
use ui::icons;
use ui::logs::{LogStore, LogsPane};
use ui::theme::{self, APP_FONT_FAMILY, APP_TEXT_SIZE};
use wallet_ops::{
    DesktopSendCalldataRequest, DesktopSendPublicBroadcasterEstimateRequest,
    DesktopSendPublicBroadcasterRequest, DesktopUnshieldCalldataRequest,
    DesktopUnshieldPublicBroadcasterEstimateRequest, DesktopUnshieldPublicBroadcasterRequest,
    HttpContext, ListUtxosOutput, PreparedSendCall, PreparedUnshieldCall,
    PublicBroadcasterCandidate, PublicBroadcasterCostEstimate, PublicBroadcasterFeeMode,
    PublicBroadcasterResultKind, PublicBroadcasterSelection, PublicBroadcasterSubmissionResult,
    PublicBroadcasterWakuClient, SyncProgressUpdate, TokenTotal, TransactionGenerationStage,
    UtxoOutput, ViewWalletChainSessionRequest, WalletSessionStore,
    eligible_public_broadcasters_for_asset, estimate_desktop_send_public_broadcaster_cost,
    estimate_desktop_unshield_public_broadcaster_cost, is_wrapped_native_token,
    max_send_amount_from_outputs as planner_max_send_amount_from_outputs,
    max_unshield_amount_from_outputs as planner_max_unshield_amount_from_outputs,
    parse_railgun_recipient, parse_send_amount, parse_unshield_amount,
    prepare_desktop_send_calldata, prepare_desktop_unshield_calldata, select_public_broadcaster,
    sort_specific_public_broadcasters, submit_desktop_send_public_broadcaster,
    submit_desktop_unshield_public_broadcaster,
    vault::{
        DesktopVaultStore, DesktopViewSession, GeneratedSeedMaterial, VaultError,
        WalletMetadataBundle, generate_opaque_id, generate_seed_material,
    },
};
use zeroize::Zeroizing;

const ACTIVITY_RAIL_WIDTH: Pixels = px(48.0);
const LOGS_DRAWER_HEIGHT: Pixels = px(260.0);
const LOGS_DRAWER_MIN_HEIGHT: Pixels = px(160.0);
const LOGS_DRAWER_MAX_HEIGHT: Pixels = px(600.0);
const FILTER_POPOVER_MAX_HEIGHT: Pixels = px(450.0);
const BROADCASTER_PICKER_MAX_HEIGHT: Pixels = px(680.0);
const PRIVATE_ASSET_LIST_WIDTH: Pixels = px(760.0);
const UNSHIELD_SPINNER_REFRESH_INTERVAL: Duration = Duration::from_millis(250);
const UTXO_AGE_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const COST_ESTIMATE_DEBOUNCE: Duration = Duration::from_secs(1);
const PUBLIC_BROADCASTER_RESPONSE_TIMEOUT: Duration = Duration::from_secs(120);
const SECONDS_PER_MINUTE: u64 = 60;
const SECONDS_PER_HOUR: u64 = 60 * SECONDS_PER_MINUTE;
const SECONDS_PER_DAY: u64 = 24 * SECONDS_PER_HOUR;
const SECONDS_PER_MONTH: u64 = 30 * SECONDS_PER_DAY;
const SECONDS_PER_YEAR: u64 = 365 * SECONDS_PER_DAY;
const TABLE_KEY_CONTEXT: &str = "Table";
const BROADCASTER_PICKER_KEY_CONTEXT: &str = "BroadcasterPicker";
const COST_ESTIMATE_DETAIL_TEXT_SIZE: Pixels = px(11.0);

#[derive(Clone, Debug, Default, Eq, PartialEq, gpui::Action)]
#[action(no_json)]
pub(crate) struct UtxoPageUp;

#[derive(Clone, Debug, Default, Eq, PartialEq, gpui::Action)]
#[action(no_json)]
pub(crate) struct UtxoPageDown;

#[derive(Clone, Debug, Default, Eq, PartialEq, gpui::Action)]
#[action(no_json)]
pub(crate) struct UtxoHome;

#[derive(Clone, Debug, Default, Eq, PartialEq, gpui::Action)]
#[action(no_json)]
pub(crate) struct UtxoEnd;

#[derive(Clone, Debug, Default, Eq, PartialEq, gpui::Action)]
#[action(no_json)]
pub(crate) struct CloseBroadcasterPicker;

pub(crate) fn install_utxo_navigation_bindings(app: &mut App) {
    app.bind_keys([
        KeyBinding::new("pageup", UtxoPageUp, Some(TABLE_KEY_CONTEXT)),
        KeyBinding::new("pagedown", UtxoPageDown, Some(TABLE_KEY_CONTEXT)),
        KeyBinding::new("home", UtxoHome, Some(TABLE_KEY_CONTEXT)),
        KeyBinding::new("end", UtxoEnd, Some(TABLE_KEY_CONTEXT)),
        KeyBinding::new(
            "escape",
            CloseBroadcasterPicker,
            Some(BROADCASTER_PICKER_KEY_CONTEXT),
        ),
    ]);
}

#[derive(Clone)]
pub(crate) struct WalletAppOptions {
    initial_chain_id: u64,
    db_path: PathBuf,
    init_block_number: Option<u64>,
    sync_to_block: Option<u64>,
    use_indexed_wallet_catch_up: bool,
    rewind_wallet_cache: bool,
    rpc_url: Option<Url>,
}

impl From<crate::cli::Options> for WalletAppOptions {
    fn from(value: crate::cli::Options) -> Self {
        Self {
            initial_chain_id: value.chain_id,
            db_path: value.db_path,
            init_block_number: value.init_block_number,
            sync_to_block: value.sync_to_block,
            use_indexed_wallet_catch_up: !value.disable_indexed_wallet_catch_up,
            rewind_wallet_cache: value.rewind_wallet_cache,
            rpc_url: value.rpc_url,
        }
    }
}

pub(crate) fn open_wallet_window(
    app: &mut App,
    options: WalletAppOptions,
    http: HttpContext,
    runtime: Handle,
    monitor: Shared,
    waku: Arc<PublicBroadcasterWakuClient>,
    event_rx: EventRx,
    chain_ids: Vec<u64>,
    logs: LogStore,
) {
    wallet_ops::vault::enable_best_effort_runtime_hardening();
    let window_options = WindowOptions {
        window_bounds: Some(WindowBounds::Windowed(Bounds {
            origin: Point::default(),
            size: size(px(1_360.0), px(860.0)),
        })),
        titlebar: Some(gpui::TitlebarOptions {
            title: Some(SharedString::from("Wallet")),
            appears_transparent: false,
            traffic_light_position: None,
        }),
        ..Default::default()
    };

    if let Err(error) = app.open_window(window_options, |window, cx| {
        let monitor_state = monitor.clone();
        let monitor = cx.new(|cx| {
            broadcaster_monitor_gpui::BroadcasterMonitorPane::new(
                monitor, event_rx, chain_ids, window, cx,
            )
        });
        let logs = cx.new(|cx| LogsPane::new(logs, window, cx));
        let root = cx.new(|cx| {
            WalletRoot::new(
                options,
                http,
                runtime,
                monitor_state,
                waku,
                monitor,
                logs,
                window,
                cx,
            )
        });
        cx.new(|cx| Root::new(root, window, cx))
    }) {
        tracing::error!(%error, "failed to open wallet window");
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Activity {
    Wallet,
    Broadcaster,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum WalletTab {
    #[default]
    Private,
    Public,
    Activity,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum DeliveryMode {
    #[default]
    ManualCalldata,
    PublicBroadcaster,
    SelfBroadcast,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeliveryFormKind {
    Send,
    Unshield,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
enum BroadcasterChoice {
    #[default]
    Random,
    Specific {
        railgun_address: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BroadcasterPickerSort {
    FeeAscReliabilityDesc,
}

struct BroadcasterPickerState {
    kind: DeliveryFormKind,
    key: UnshieldAssetKey,
    query_input: Entity<InputState>,
    focus_handle: FocusHandle,
    sort: BroadcasterPickerSort,
}

enum SendResult {
    Manual(PreparedSendCall),
    PublicBroadcaster(Box<PublicBroadcasterSubmissionResult>),
}

enum UnshieldResult {
    Manual(PreparedUnshieldCall),
    PublicBroadcaster(Box<PublicBroadcasterSubmissionResult>),
}

impl WalletTab {
    const ALL: [Self; 3] = [Self::Private, Self::Public, Self::Activity];

    const fn label(self) -> &'static str {
        match self {
            Self::Private => "Private",
            Self::Public => "Public",
            Self::Activity => "Activity",
        }
    }

    fn icon_path(self) -> PathBuf {
        match self {
            Self::Private => icons::shield_check_icon_path(),
            Self::Public => icons::globe_icon_path(),
            Self::Activity => icons::activity_icon_path(),
        }
    }

    const fn shows_utxos(self) -> bool {
        matches!(self, Self::Activity)
    }
}

#[derive(Clone)]
struct WalletOption {
    wallet_id: Arc<str>,
    label: Arc<str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PrivateActionMetric {
    label: &'static str,
    amount: U256,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CostEstimateStatus {
    Estimating,
}

#[derive(Clone, Eq, PartialEq)]
struct UnshieldAsset {
    chain_id: u64,
    token: Address,
    label: String,
    decimals: Option<u8>,
    total: U256,
    poi_verified_total: U256,
    max_batched: U256,
    icon_path: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct UnshieldAssetKey {
    chain_id: u64,
    token: Address,
}

impl UnshieldAssetKey {
    const fn new(chain_id: u64, token: Address) -> Self {
        Self { chain_id, token }
    }

    const fn from_asset(asset: &UnshieldAsset) -> Self {
        Self::new(asset.chain_id, asset.token)
    }
}

struct UnshieldFormState {
    asset: UnshieldAsset,
    recipient_input: Entity<InputState>,
    amount_input: Entity<InputState>,
    password_input: Entity<InputState>,
    unwrap: bool,
    delivery_mode: DeliveryMode,
    broadcaster_choice: BroadcasterChoice,
    broadcaster_fee_mode: PublicBroadcasterFeeMode,
    cost_estimate_pending: bool,
    estimating_cost: bool,
    cost_estimate: Option<PublicBroadcasterCostEstimate>,
    estimate_id: u64,
    generation_id: u64,
    generating: bool,
    generation_stage: TransactionGenerationStage,
    error: Option<Arc<str>>,
    result: Option<UnshieldResult>,
}

struct SendFormState {
    asset: UnshieldAsset,
    recipient_input: Entity<InputState>,
    amount_input: Entity<InputState>,
    password_input: Entity<InputState>,
    delivery_mode: DeliveryMode,
    broadcaster_choice: BroadcasterChoice,
    broadcaster_fee_mode: PublicBroadcasterFeeMode,
    cost_estimate_pending: bool,
    estimating_cost: bool,
    cost_estimate: Option<PublicBroadcasterCostEstimate>,
    estimate_id: u64,
    generation_id: u64,
    generating: bool,
    generation_stage: TransactionGenerationStage,
    error: Option<Arc<str>>,
    result: Option<SendResult>,
}

enum ChainUtxoState {
    Idle,
    Loading {
        progress: Option<SyncProgressUpdate>,
    },
    Syncing {
        snapshot: Arc<ListUtxosOutput>,
        progress: Option<SyncProgressUpdate>,
        session: Arc<wallet_ops::WalletSession>,
    },
    Ready {
        snapshot: Arc<ListUtxosOutput>,
        session: Arc<wallet_ops::WalletSession>,
    },
    Error(Arc<str>),
}

impl ChainUtxoState {
    const fn snapshot(&self) -> Option<&Arc<ListUtxosOutput>> {
        match self {
            Self::Syncing { snapshot, .. } | Self::Ready { snapshot, .. } => Some(snapshot),
            Self::Idle | Self::Loading { .. } | Self::Error(_) => None,
        }
    }

    const fn progress(&self) -> Option<SyncProgressUpdate> {
        match self {
            Self::Loading { progress } | Self::Syncing { progress, .. } => *progress,
            Self::Idle | Self::Ready { .. } | Self::Error(_) => None,
        }
    }

    const fn renders_table(&self) -> bool {
        matches!(
            self,
            Self::Loading { .. } | Self::Syncing { .. } | Self::Ready { .. }
        )
    }

    const fn is_ready(&self) -> bool {
        matches!(self, Self::Ready { .. })
    }

    const fn is_syncing(&self) -> bool {
        matches!(self, Self::Loading { .. } | Self::Syncing { .. })
    }
}

enum VaultState {
    CreateVault,
    UnlockVault,
    SetupWallet,
    ViewUnlocked,
    Error(Arc<str>),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WalletSetupMode {
    Choose,
    GeneratedReview,
    Import,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ChainLoadSource {
    Initial,
    Selection,
}

#[derive(Clone, Copy)]
enum UtxoNavigation {
    PageUp,
    PageDown,
    Home,
    End,
}

#[derive(Clone)]
struct ChainLoadOverrides {
    init_block_number: Option<u64>,
    sync_to_block: Option<u64>,
    use_indexed_wallet_catch_up: bool,
    rewind_wallet_cache: bool,
    rpc_url: Option<Url>,
}

fn chain_load_overrides(
    options: &WalletAppOptions,
    chain_id: u64,
    source: ChainLoadSource,
) -> ChainLoadOverrides {
    if source == ChainLoadSource::Initial && chain_id == options.initial_chain_id {
        return ChainLoadOverrides {
            init_block_number: options.init_block_number,
            sync_to_block: options.sync_to_block,
            use_indexed_wallet_catch_up: options.use_indexed_wallet_catch_up,
            rewind_wallet_cache: options.rewind_wallet_cache,
            rpc_url: options.rpc_url.clone(),
        };
    }

    ChainLoadOverrides {
        init_block_number: None,
        sync_to_block: None,
        use_indexed_wallet_catch_up: true,
        rewind_wallet_cache: false,
        rpc_url: None,
    }
}

pub(crate) struct WalletRoot {
    options: WalletAppOptions,
    vault_store: Option<Arc<DesktopVaultStore>>,
    vault_state: VaultState,
    wallet_setup_mode: WalletSetupMode,
    vault_error: Option<Arc<str>>,
    unlock_in_progress: bool,
    spend_status: Option<Arc<str>>,
    repair_cache_error: Option<Arc<str>>,
    setup_password: Option<Zeroizing<String>>,
    view_session: Option<Arc<DesktopViewSession>>,
    generated_seed: Option<GeneratedSeedMaterial>,
    http: HttpContext,
    runtime: Handle,
    monitor_state: Shared,
    waku: Arc<PublicBroadcasterWakuClient>,
    monitor: Entity<broadcaster_monitor_gpui::BroadcasterMonitorPane>,
    logs: Entity<LogsPane>,
    active_activity: Activity,
    active_wallet_tab: WalletTab,
    wallet_options: Vec<WalletOption>,
    selected_wallet_id: Option<Arc<str>>,
    selected_chain: u64,
    chain_ids: Vec<u64>,
    chain_states: BTreeMap<u64, ChainUtxoState>,
    session_store: Arc<OnceCell<Arc<WalletSessionStore>>>,
    unlock_password_input: Entity<InputState>,
    new_password_input: Entity<InputState>,
    confirm_password_input: Entity<InputState>,
    import_mnemonic_input: Entity<InputState>,
    spend_password_input: Entity<InputState>,
    send_forms: BTreeMap<UnshieldAssetKey, SendFormState>,
    send_generation_seq: u64,
    unshield_generation_seq: u64,
    cost_estimate_seq: u64,
    unshield_forms: BTreeMap<UnshieldAssetKey, UnshieldFormState>,
    broadcaster_picker: Option<BroadcasterPickerState>,
    unshield_spinner_tick: usize,
    repair_cache_block_input: Entity<InputState>,
    tx_search_input: Entity<InputState>,
    tx_search_query: Arc<str>,
    show_spent_utxos: bool,
    utxo_table: Entity<TableState<UtxoDelegate>>,
    focus_unlock_password_on_render: bool,
    focus_utxo_table_on_render: bool,
    logs_open: bool,
    drawer_split: Entity<ResizableState>,
}

impl WalletRoot {
    fn new(
        options: WalletAppOptions,
        http: HttpContext,
        runtime: Handle,
        monitor_state: Shared,
        waku: Arc<PublicBroadcasterWakuClient>,
        monitor: Entity<broadcaster_monitor_gpui::BroadcasterMonitorPane>,
        logs: Entity<LogsPane>,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) -> Self {
        let chain_ids = DEFAULT_CHAINS.to_vec();
        let mut chain_states = BTreeMap::new();
        for chain_id in &chain_ids {
            chain_states.insert(*chain_id, ChainUtxoState::Idle);
        }
        let vault_store = match DesktopVaultStore::open(options.db_path.clone()) {
            Ok(store) => Some(Arc::new(store)),
            Err(error) => {
                tracing::error!(%error, "failed to open desktop wallet vault store");
                None
            }
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
        let focus_unlock_password_on_render = matches!(vault_state, VaultState::UnlockVault);
        let unlock_password_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("vault password")
                .masked(true)
        });
        let new_password_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("new vault password")
                .masked(true)
        });
        let confirm_password_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("confirm vault password")
                .masked(true)
        });
        let import_mnemonic_input = cx.new(|cx| {
            InputState::new(window, cx)
                .auto_grow(3, 6)
                .placeholder("paste recovery phrase")
        });
        let spend_password_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("spend password")
                .masked(true)
        });
        let repair_cache_block_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("0 = deployment block"));
        let tx_search_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("search tx hash"));
        let utxo_table =
            cx.new(|cx| TableState::new(UtxoDelegate::new(tx_search_input.clone()), window, cx));

        let root = Self {
            selected_chain: options.initial_chain_id,
            options,
            vault_store,
            vault_state,
            wallet_setup_mode: WalletSetupMode::Choose,
            vault_error,
            unlock_in_progress: false,
            spend_status: None,
            repair_cache_error: None,
            setup_password: None,
            view_session: None,
            generated_seed: None,
            http,
            runtime,
            monitor_state,
            waku,
            monitor,
            logs,
            active_activity: Activity::Wallet,
            active_wallet_tab: WalletTab::default(),
            wallet_options: Vec::new(),
            selected_wallet_id: None,
            chain_ids,
            chain_states,
            session_store: Arc::new(OnceCell::new()),
            unlock_password_input,
            new_password_input,
            confirm_password_input,
            import_mnemonic_input,
            spend_password_input,
            send_forms: BTreeMap::new(),
            send_generation_seq: 0,
            unshield_generation_seq: 0,
            cost_estimate_seq: 0,
            unshield_forms: BTreeMap::new(),
            broadcaster_picker: None,
            unshield_spinner_tick: 0,
            repair_cache_block_input,
            tx_search_input: tx_search_input.clone(),
            tx_search_query: Arc::from(""),
            show_spent_utxos: true,
            utxo_table,
            focus_unlock_password_on_render,
            focus_utxo_table_on_render: false,
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
        cx.subscribe_in(
            &root.spend_password_input,
            window,
            |this, _input, event: &InputEvent, window, cx| {
                if matches!(event, InputEvent::PressEnter { .. }) {
                    this.authorize_spend_from_input(window, cx);
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
                            root.utxo_table.update(cx, TableState::refresh);
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
        root
    }

    fn ensure_chain_load(
        &mut self,
        chain_id: u64,
        source: ChainLoadSource,
        cx: &mut Context<'_, Self>,
    ) {
        let overrides = chain_load_overrides(&self.options, chain_id, source);
        self.start_chain_load(chain_id, overrides, false, cx);
    }

    fn start_chain_load(
        &mut self,
        chain_id: u64,
        overrides: ChainLoadOverrides,
        force: bool,
        cx: &mut Context<'_, Self>,
    ) {
        if matches!(
            self.chain_states.get(&chain_id),
            Some(
                ChainUtxoState::Loading { .. }
                    | ChainUtxoState::Syncing { .. }
                    | ChainUtxoState::Ready { .. }
            )
        ) && !force
        {
            return;
        }

        let previous_session = if force {
            match self.chain_states.remove(&chain_id) {
                Some(
                    ChainUtxoState::Syncing { session, .. } | ChainUtxoState::Ready { session, .. },
                ) => Some(session),
                Some(state) => {
                    self.chain_states.insert(chain_id, state);
                    None
                }
                None => None,
            }
        } else {
            None
        };

        self.chain_states
            .insert(chain_id, ChainUtxoState::Loading { progress: None });
        self.sync_utxo_table(cx);

        let Some(view_session) = self.view_session.clone() else {
            self.chain_states.insert(
                chain_id,
                ChainUtxoState::Error(Arc::from("wallet vault is locked")),
            );
            self.sync_utxo_table(cx);
            cx.notify();
            return;
        };
        let (progress_tx, mut progress_rx) = tokio::sync::watch::channel(None);
        let request = ViewWalletChainSessionRequest {
            view_session,
            chain_id,
            init_block_number: overrides.init_block_number,
            sync_to_block: overrides.sync_to_block,
            use_indexed_wallet_catch_up: overrides.use_indexed_wallet_catch_up,
            rewind_wallet_cache: overrides.rewind_wallet_cache,
            progress_tx: Some(progress_tx),
        };
        let rpc_url = overrides.rpc_url;
        let db_path = self.options.db_path.clone();
        let http = self.http.clone();
        let session_store = Arc::clone(&self.session_store);
        let vault_db = self.vault_store.as_ref().map(|store| store.db());
        let join = self.runtime.spawn(async move {
            if let Some(previous_session) = previous_session {
                previous_session.stop().await?;
            }
            let store = session_store
                .get_or_try_init(|| {
                    let db_path = db_path.clone();
                    let vault_db = vault_db.clone();
                    async move {
                        Ok::<Arc<WalletSessionStore>, eyre::Report>(Arc::new(match vault_db {
                            Some(db) => WalletSessionStore::from_db(db),
                            None => WalletSessionStore::open(db_path)?,
                        }))
                    }
                })
                .await?
                .clone();
            store
                .start_view_wallet_session_immediate(request, rpc_url, &http)
                .await
        });

        cx.spawn(async move |this, cx| {
            loop {
                if progress_rx.changed().await.is_err() {
                    break;
                }
                let progress = *progress_rx.borrow();
                let should_continue = this.update(cx, |root, cx| {
                    match root.chain_states.get_mut(&chain_id) {
                        Some(
                            ChainUtxoState::Loading { progress: state }
                            | ChainUtxoState::Syncing {
                                progress: state, ..
                            },
                        ) => *state = progress,
                        Some(
                            ChainUtxoState::Idle
                            | ChainUtxoState::Ready { .. }
                            | ChainUtxoState::Error(_),
                        )
                        | None => return false,
                    }
                    cx.notify();
                    true
                });
                if !matches!(should_continue, Ok(true)) {
                    break;
                }
            }
        })
        .detach();

        cx.spawn(async move |this, cx| {
            let session = match join.await {
                Ok(Ok(session)) => Arc::new(session),
                Ok(Err(error)) => {
                    let _ = this.update(cx, |root, cx| {
                        root.chain_states.insert(
                            chain_id,
                            ChainUtxoState::Error(Arc::from(error.to_string())),
                        );
                        if root.selected_chain == chain_id {
                            root.sync_utxo_table(cx);
                        }
                        cx.notify();
                    });
                    return;
                }
                Err(error) => {
                    let _ = this.update(cx, |root, cx| {
                        root.chain_states.insert(
                            chain_id,
                            ChainUtxoState::Error(Arc::from(format!(
                                "wallet UTXO task failed: {error}"
                            ))),
                        );
                        if root.selected_chain == chain_id {
                            root.sync_utxo_table(cx);
                        }
                        cx.notify();
                    });
                    return;
                }
            };

            let mut snapshots_rx = session.snapshots_rx.clone();
            let mut ready_rx = session.ready_rx.clone();
            let initial_snapshot = snapshots_rx.borrow().clone();
            let mut ready = *ready_rx.borrow();

            let _ = this.update(cx, |root, cx| {
                let progress = root
                    .chain_states
                    .get(&chain_id)
                    .and_then(ChainUtxoState::progress);
                let state = if ready {
                    ChainUtxoState::Ready {
                        snapshot: initial_snapshot.clone(),
                        session: session.clone(),
                    }
                } else {
                    ChainUtxoState::Syncing {
                        snapshot: initial_snapshot.clone(),
                        progress,
                        session: session.clone(),
                    }
                };
                root.chain_states.insert(chain_id, state);
                if root.selected_chain == chain_id {
                    root.sync_utxo_table(cx);
                    root.focus_utxo_table_on_render = should_focus_utxo_table(
                        root.active_activity,
                        root.active_wallet_tab,
                        root.chain_states.get(&chain_id),
                    );
                }
                cx.notify();
            });

            loop {
                tokio::select! {
                    changed = snapshots_rx.changed() => {
                        if changed.is_err() {
                            break;
                        }
                        let snapshot = snapshots_rx.borrow().clone();
                        let should_continue = this.update(cx, |root, cx| {
                            {
                                let Some(state) = root.chain_states.get_mut(&chain_id) else {
                                    return false;
                                };
                                match state {
                                    ChainUtxoState::Syncing { snapshot: current, .. }
                                    | ChainUtxoState::Ready { snapshot: current, .. } => {
                                        *current = snapshot.clone();
                                    }
                                    ChainUtxoState::Idle
                                    | ChainUtxoState::Loading { .. }
                                    | ChainUtxoState::Error(_) => return false,
                                }
                            }
                            root.refresh_open_form_assets_for_snapshot(&snapshot, cx);
                            if root.selected_chain == chain_id {
                                root.sync_utxo_table(cx);
                            }
                            cx.notify();
                            true
                        });
                        if !matches!(should_continue, Ok(true)) {
                            break;
                        }
                    }
                    changed = ready_rx.changed(), if !ready => {
                        if changed.is_err() {
                            ready = true;
                            continue;
                        }
                        ready = *ready_rx.borrow();
                        if !ready {
                            continue;
                        }
                        let should_continue = this.update(cx, |root, cx| {
                            let Some(state) = root.chain_states.remove(&chain_id) else {
                                return false;
                            };
                            match state {
                                ChainUtxoState::Syncing { snapshot, session, .. } => {
                                    root.chain_states.insert(
                                        chain_id,
                                        ChainUtxoState::Ready { snapshot, session },
                                    );
                                    if root.selected_chain == chain_id {
                                        root.sync_utxo_table(cx);
                                    }
                                    cx.notify();
                                    true
                                }
                                ChainUtxoState::Ready { .. } => {
                                    root.chain_states.insert(chain_id, state);
                                    true
                                }
                                ChainUtxoState::Idle
                                | ChainUtxoState::Loading { .. }
                                | ChainUtxoState::Error(_) => {
                                    root.chain_states.insert(chain_id, state);
                                    false
                                }
                            }
                        });
                        if !matches!(should_continue, Ok(true)) {
                            break;
                        }
                    }
                }
            }
        })
        .detach();
    }

    fn sync_utxo_table(&self, cx: &mut Context<'_, Self>) {
        let rows = match self.chain_states.get(&self.selected_chain) {
            Some(state) => state.snapshot().map_or_else(Vec::new, |snapshot| {
                display_rows_from_output(
                    snapshot,
                    self.tx_search_query.as_ref(),
                    self.show_spent_utxos,
                )
            }),
            _ => Vec::new(),
        };
        self.utxo_table.update(cx, |state, cx| {
            state.delegate_mut().set_rows(rows);
            state.refresh(cx);
        });
    }

    fn select_chain(&mut self, chain_id: u64, cx: &mut Context<'_, Self>) {
        if self.selected_chain == chain_id {
            return;
        }
        self.selected_chain = chain_id;
        self.send_forms.clear();
        self.unshield_forms.clear();
        self.sync_utxo_table(cx);
        if should_focus_utxo_table(
            self.active_activity,
            self.active_wallet_tab,
            self.chain_states.get(&chain_id),
        ) {
            self.focus_utxo_table_on_render = true;
        }
        self.ensure_chain_load(chain_id, ChainLoadSource::Selection, cx);
        cx.notify();
    }

    fn select_wallet(&mut self, wallet_id: Arc<str>, cx: &mut Context<'_, Self>) {
        if self.selected_wallet_id.as_deref() == Some(wallet_id.as_ref()) {
            return;
        }
        self.selected_wallet_id = Some(wallet_id);
        self.send_forms.clear();
        self.unshield_forms.clear();
        cx.notify();
    }

    fn select_wallet_tab(&mut self, tab: WalletTab, cx: &mut Context<'_, Self>) {
        if self.active_wallet_tab == tab {
            return;
        }
        self.active_wallet_tab = tab;
        self.focus_utxo_table_on_render = should_focus_utxo_table(
            self.active_activity,
            self.active_wallet_tab,
            self.chain_states.get(&self.selected_chain),
        );
        cx.notify();
    }

    fn selected_wallet_label(&self) -> SharedString {
        self.selected_wallet_id
            .as_ref()
            .and_then(|selected| {
                self.wallet_options
                    .iter()
                    .find(|option| option.wallet_id.as_ref() == selected.as_ref())
            })
            .map_or_else(
                || SharedString::from("Primary wallet"),
                |option| SharedString::from(option.label.to_string()),
            )
    }

    fn toggle_spent_visibility(&mut self, cx: &mut Context<'_, Self>) {
        self.show_spent_utxos = !self.show_spent_utxos;
        self.sync_utxo_table(cx);
        cx.notify();
    }

    fn repair_wallet_cache_from_input(&mut self, cx: &mut Context<'_, Self>) -> bool {
        if self
            .chain_states
            .get(&self.selected_chain)
            .is_some_and(ChainUtxoState::is_syncing)
        {
            self.repair_cache_error = Some(Arc::from(
                "Wait for wallet sync to finish before repairing the cache",
            ));
            cx.notify();
            return false;
        }

        let raw_block = self.repair_cache_block_input.read(cx).value();
        let rewind_from = match parse_repair_cache_block(raw_block.as_ref()) {
            Ok(rewind_from) => rewind_from,
            Err(message) => {
                self.repair_cache_error = Some(Arc::from(message));
                cx.notify();
                return false;
            }
        };

        let mut overrides =
            chain_load_overrides(&self.options, self.selected_chain, ChainLoadSource::Initial);
        overrides.init_block_number = rewind_from;
        overrides.sync_to_block = None;
        overrides.rewind_wallet_cache = true;
        self.repair_cache_error = None;
        self.start_chain_load(self.selected_chain, overrides, true, cx);
        cx.notify();
        true
    }

    fn focus_utxo_table_if_requested(&mut self, window: &mut Window, cx: &Context<'_, Self>) {
        if !self.focus_utxo_table_on_render
            || !should_focus_utxo_table(
                self.active_activity,
                self.active_wallet_tab,
                self.chain_states.get(&self.selected_chain),
            )
        {
            return;
        }
        if self
            .tx_search_input
            .read(cx)
            .focus_handle(cx)
            .is_focused(window)
        {
            return;
        }

        self.utxo_table.read(cx).focus_handle(cx).focus(window);
        self.focus_utxo_table_on_render = false;
    }

    fn focus_unlock_password_if_requested(&mut self, window: &mut Window, cx: &Context<'_, Self>) {
        if !self.focus_unlock_password_on_render
            || !matches!(self.vault_state, VaultState::UnlockVault)
        {
            return;
        }

        self.unlock_password_input
            .read(cx)
            .focus_handle(cx)
            .focus(window);
        self.focus_unlock_password_on_render = false;
    }

    fn apply_public_broadcaster_error_amount_adjustments(
        &mut self,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let mut reschedule = Vec::new();

        for (key, form) in &mut self.send_forms {
            if form.delivery_mode != DeliveryMode::PublicBroadcaster || form.generating {
                continue;
            }
            let Some(max_entered_amount) = form
                .error
                .as_deref()
                .and_then(form_error_public_broadcaster_max_entered_amount)
            else {
                continue;
            };
            if apply_amount_adjustment_for_max_change(
                &form.amount_input,
                &form.asset,
                None,
                Some(max_entered_amount),
                window,
                cx,
            ) {
                form.error = None;
                form.cost_estimate = None;
                form.estimate_id = 0;
                form.cost_estimate_pending = false;
                form.estimating_cost = false;
                reschedule.push((DeliveryFormKind::Send, *key));
            }
        }

        for (key, form) in &mut self.unshield_forms {
            if form.delivery_mode != DeliveryMode::PublicBroadcaster || form.generating {
                continue;
            }
            let Some(max_entered_amount) = form
                .error
                .as_deref()
                .and_then(form_error_public_broadcaster_max_entered_amount)
            else {
                continue;
            };
            if apply_amount_adjustment_for_max_change(
                &form.amount_input,
                &form.asset,
                None,
                Some(max_entered_amount),
                window,
                cx,
            ) {
                form.error = None;
                form.cost_estimate = None;
                form.estimate_id = 0;
                form.cost_estimate_pending = false;
                form.estimating_cost = false;
                reschedule.push((DeliveryFormKind::Unshield, *key));
            }
        }

        for (kind, key) in reschedule {
            self.schedule_public_broadcaster_cost_estimate(kind, key, cx);
        }
    }

    fn refresh_open_form_assets_for_snapshot(
        &mut self,
        snapshot: &ListUtxosOutput,
        cx: &mut Context<'_, Self>,
    ) {
        let mut reschedule_estimates = Vec::new();
        for (key, form) in &mut self.send_forms {
            if key.chain_id != snapshot.chain_id {
                continue;
            }
            let updated = refresh_form_asset_from_snapshot(snapshot, &form.asset, true);
            if form.asset == updated {
                continue;
            }
            form.asset = updated;
            if form.delivery_mode == DeliveryMode::PublicBroadcaster && !form.generating {
                form.cost_estimate = None;
                form.estimate_id = 0;
                form.cost_estimate_pending = false;
                form.estimating_cost = false;
                reschedule_estimates.push((DeliveryFormKind::Send, *key));
            }
        }
        for (key, form) in &mut self.unshield_forms {
            if key.chain_id != snapshot.chain_id {
                continue;
            }
            let updated = refresh_form_asset_from_snapshot(snapshot, &form.asset, false);
            if form.asset == updated {
                continue;
            }
            form.asset = updated;
            if form.delivery_mode == DeliveryMode::PublicBroadcaster && !form.generating {
                form.cost_estimate = None;
                form.estimate_id = 0;
                form.cost_estimate_pending = false;
                form.estimating_cost = false;
                reschedule_estimates.push((DeliveryFormKind::Unshield, *key));
            }
        }
        for (kind, key) in reschedule_estimates {
            self.schedule_public_broadcaster_cost_estimate(kind, key, cx);
        }
    }

    fn create_vault_from_inputs(&mut self, window: &mut Window, cx: &mut Context<'_, Self>) {
        let Some(store) = self.vault_store.as_ref() else {
            self.set_vault_error("Wallet vault storage is unavailable", cx);
            return;
        };
        let password = Self::read_and_clear_input(&self.new_password_input, window, cx);
        let confirm = Self::read_and_clear_input(&self.confirm_password_input, window, cx);

        if password.trim().is_empty() {
            self.set_vault_error("Enter a vault password to continue", cx);
            return;
        }
        if password.as_str() != confirm.as_str() {
            self.set_vault_error("Vault passwords do not match", cx);
            return;
        }

        match store.create_vault(password.as_str()) {
            Ok(_) => {
                self.setup_password = Some(password);
                self.vault_error = None;
                self.vault_state = VaultState::SetupWallet;
                self.wallet_setup_mode = WalletSetupMode::Choose;
                cx.notify();
            }
            Err(VaultError::VaultAlreadyExists) => {
                self.vault_state = VaultState::UnlockVault;
                self.focus_unlock_password_on_render = true;
                self.set_vault_error("A wallet vault already exists. Unlock it to continue.", cx);
            }
            Err(error) => self.handle_vault_error(&error, cx),
        }
    }

    fn unlock_vault_from_input(&mut self, window: &mut Window, cx: &mut Context<'_, Self>) {
        if self.unlock_in_progress {
            return;
        }
        let Some(store) = self.vault_store.as_ref() else {
            self.set_vault_error("Wallet vault storage is unavailable", cx);
            return;
        };
        let password = Self::read_and_clear_input(&self.unlock_password_input, window, cx);
        if password.trim().is_empty() {
            self.set_vault_error("Enter the vault password to continue", cx);
            return;
        }

        let store = Arc::clone(store);
        self.unlock_in_progress = true;
        self.vault_error = None;
        cx.notify();

        let join = self.runtime.spawn_blocking(move || {
            store
                .unlock_first_view_session(password.as_str())
                .map(|session| (session, password))
        });
        cx.spawn(async move |this, cx| {
            let result = join.await;
            let _ = this.update(cx, |root, cx| {
                root.unlock_in_progress = false;
                match result {
                    Ok(Ok((Some(session), _password))) => root.enter_view_unlocked(session, cx),
                    Ok(Ok((None, password))) => {
                        root.setup_password = Some(password);
                        root.vault_error = None;
                        root.vault_state = VaultState::SetupWallet;
                        root.wallet_setup_mode = WalletSetupMode::Choose;
                        cx.notify();
                    }
                    Ok(Err(error)) => {
                        root.focus_unlock_password_on_render = true;
                        root.handle_vault_error(&error, cx);
                    }
                    Err(error) => {
                        tracing::warn!(%error, "desktop wallet vault unlock task failed");
                        root.focus_unlock_password_on_render = true;
                        root.set_vault_error(
                            "Unlock failed. Check the password and try again.",
                            cx,
                        );
                    }
                }
            });
        })
        .detach();
    }

    fn choose_generated_wallet(&mut self, cx: &mut Context<'_, Self>) {
        match generate_seed_material() {
            Ok(seed) => {
                self.generated_seed = Some(seed);
                self.vault_error = None;
                self.wallet_setup_mode = WalletSetupMode::GeneratedReview;
                cx.notify();
            }
            Err(error) => self.handle_vault_error(&error, cx),
        }
    }

    fn choose_import_wallet(&mut self, cx: &mut Context<'_, Self>) {
        self.generated_seed = None;
        self.vault_error = None;
        self.wallet_setup_mode = WalletSetupMode::Import;
        cx.notify();
    }

    fn back_to_wallet_setup_choice(&mut self, window: &mut Window, cx: &mut Context<'_, Self>) {
        self.generated_seed = None;
        self.import_mnemonic_input
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.vault_error = None;
        self.wallet_setup_mode = WalletSetupMode::Choose;
        cx.notify();
    }

    fn store_generated_wallet(&mut self, cx: &mut Context<'_, Self>) {
        let wallet_id = match generate_opaque_id() {
            Ok(wallet_id) => wallet_id,
            Err(error) => {
                self.handle_vault_error(&error, cx);
                return;
            }
        };
        let result = {
            let Some(store) = self.vault_store.as_ref() else {
                self.set_vault_error("Wallet vault storage is unavailable", cx);
                return;
            };
            let Some(password) = self.setup_password.as_ref() else {
                self.set_vault_error("Unlock the wallet vault before adding a wallet", cx);
                return;
            };
            let Some(seed) = self.generated_seed.as_ref() else {
                self.set_vault_error("Generate a recovery phrase before creating the wallet", cx);
                return;
            };
            let metadata = WalletMetadataBundle {
                wallet_uuid: wallet_id.clone(),
                label: "Primary wallet".to_string(),
                derivation_index: 0,
            };
            store
                .store_generated_wallet_with_metadata(
                    password.as_str(),
                    &wallet_id,
                    0,
                    "english",
                    seed,
                    &metadata,
                )
                .and_then(|_| store.load_view_session(password.as_str(), &wallet_id))
        };

        match result {
            Ok(session) => self.enter_view_unlocked(session, cx),
            Err(error) => self.handle_vault_error(&error, cx),
        }
    }

    fn store_imported_wallet(&mut self, window: &mut Window, cx: &mut Context<'_, Self>) {
        let mnemonic = Self::read_and_clear_input(&self.import_mnemonic_input, window, cx);
        if mnemonic.trim().is_empty() {
            self.set_vault_error("Paste a recovery phrase to import", cx);
            return;
        }
        let wallet_id = match generate_opaque_id() {
            Ok(wallet_id) => wallet_id,
            Err(error) => {
                self.handle_vault_error(&error, cx);
                return;
            }
        };

        let result = {
            let Some(store) = self.vault_store.as_ref() else {
                self.set_vault_error("Wallet vault storage is unavailable", cx);
                return;
            };
            let Some(password) = self.setup_password.as_ref() else {
                self.set_vault_error("Unlock the wallet vault before importing a wallet", cx);
                return;
            };
            let metadata = WalletMetadataBundle {
                wallet_uuid: wallet_id.clone(),
                label: "Primary wallet".to_string(),
                derivation_index: 0,
            };
            store
                .import_wallet_mnemonic_with_metadata(
                    password.as_str(),
                    &wallet_id,
                    0,
                    "english",
                    mnemonic.as_str(),
                    &metadata,
                )
                .and_then(|_| store.load_view_session(password.as_str(), &wallet_id))
        };

        match result {
            Ok(session) => self.enter_view_unlocked(session, cx),
            Err(error) => self.handle_vault_error(&error, cx),
        }
    }

    fn install_view_session(&mut self, session: DesktopViewSession, cx: &mut Context<'_, Self>) {
        let session = Arc::new(session);
        let wallet_id: Arc<str> = Arc::from(session.wallet_id().to_owned());
        self.view_session = Some(session);
        self.wallet_options = vec![WalletOption {
            wallet_id: Arc::clone(&wallet_id),
            label: Arc::from("Primary wallet"),
        }];
        self.selected_wallet_id = Some(wallet_id);
        self.send_forms.clear();
        self.unshield_forms.clear();
        self.active_wallet_tab = WalletTab::default();
        self.setup_password = None;
        self.generated_seed = None;
        self.vault_error = None;
        self.vault_state = VaultState::ViewUnlocked;
        self.wallet_setup_mode = WalletSetupMode::Choose;
        self.session_store = Arc::new(OnceCell::new());
        for state in self.chain_states.values_mut() {
            *state = ChainUtxoState::Idle;
        }
        self.sync_utxo_table(cx);
        self.ensure_chain_load(self.selected_chain, ChainLoadSource::Initial, cx);
        cx.notify();
    }

    fn enter_view_unlocked(&mut self, session: DesktopViewSession, cx: &mut Context<'_, Self>) {
        self.install_view_session(session, cx);
    }

    fn lock_vault(&mut self, cx: &mut Context<'_, Self>) {
        if let Some(store) = self.session_store.get().cloned() {
            self.runtime.spawn(async move {
                store.shutdown().await;
            });
        }
        self.view_session = None;
        self.wallet_options.clear();
        self.selected_wallet_id = None;
        self.send_forms.clear();
        self.unshield_forms.clear();
        self.active_wallet_tab = WalletTab::default();
        self.setup_password = None;
        self.generated_seed = None;
        self.vault_error = None;
        self.spend_status = None;
        self.repair_cache_error = None;
        self.vault_state = VaultState::UnlockVault;
        self.wallet_setup_mode = WalletSetupMode::Choose;
        self.session_store = Arc::new(OnceCell::new());
        self.focus_unlock_password_on_render = true;
        for state in self.chain_states.values_mut() {
            *state = ChainUtxoState::Idle;
        }
        self.sync_utxo_table(cx);
        cx.notify();
    }

    fn authorize_spend_from_input(&mut self, window: &mut Window, cx: &mut Context<'_, Self>) {
        if !self
            .chain_states
            .get(&self.selected_chain)
            .is_some_and(ChainUtxoState::is_ready)
        {
            self.spend_status = None;
            self.set_vault_error(
                "Wait for wallet sync to finish before authorizing a spend",
                cx,
            );
            return;
        }
        let Some(store) = self.vault_store.as_ref() else {
            self.set_vault_error("Wallet vault storage is unavailable", cx);
            return;
        };
        let Some(view_session) = self.view_session.as_ref() else {
            self.set_vault_error("Unlock the wallet vault before authorizing a spend", cx);
            return;
        };
        let password = Self::read_and_clear_input(&self.spend_password_input, window, cx);
        if password.trim().is_empty() {
            self.set_vault_error(
                "Enter the vault password to authorize this spend action",
                cx,
            );
            return;
        }

        let result = store
            .create_spend_grant(password.as_str())
            .and_then(|mut grant| {
                let _signer = store.railgun_spend_signer(&mut grant, view_session.wallet_id())?;
                if grant.is_valid() {
                    grant.invalidate();
                }
                Ok(())
            });

        match result {
            Ok(()) => {
                self.vault_error = None;
                self.spend_status = Some(Arc::from(
                    "Spend password accepted. The one-use grant was consumed.",
                ));
                cx.notify();
            }
            Err(error) => {
                self.spend_status = None;
                self.handle_vault_error(&error, cx);
            }
        }
    }

    fn open_send_form(
        &mut self,
        asset: UnshieldAsset,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let key = UnshieldAssetKey::from_asset(&asset);
        if self.send_forms.contains_key(&key) {
            return;
        }
        self.send_forms.retain(|existing_key, form| {
            *existing_key == key || Self::send_form_is_dirty(form, cx)
        });
        let amount = format_send_amount_input(asset.max_batched, asset.decimals);
        let amount_input = cx.new(|cx| {
            let mut input = InputState::new(window, cx).placeholder("amount");
            input.set_value(&amount, window, cx);
            input
        });
        let recipient_input = cx.new(|cx| InputState::new(window, cx).placeholder("0zk recipient"));
        let password_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("vault password")
                .masked(true)
        });
        cx.subscribe_in(
            &password_input,
            window,
            move |this, _input, event: &InputEvent, window, cx| {
                if matches!(event, InputEvent::PressEnter { .. }) {
                    this.generate_send_calldata_from_form(key, window, cx);
                }
            },
        )
        .detach();
        cx.subscribe(
            &recipient_input,
            move |this, _input, event: &InputEvent, cx| {
                if matches!(event, InputEvent::Change) {
                    this.clear_send_form_prepared_output(key, cx);
                    this.schedule_public_broadcaster_cost_estimate(DeliveryFormKind::Send, key, cx);
                }
            },
        )
        .detach();
        cx.subscribe(
            &amount_input,
            move |this, _input, event: &InputEvent, cx| {
                if matches!(event, InputEvent::Change) {
                    this.clear_send_form_prepared_output(key, cx);
                    this.schedule_public_broadcaster_cost_estimate(DeliveryFormKind::Send, key, cx);
                }
            },
        )
        .detach();
        self.send_forms.insert(
            key,
            SendFormState {
                asset,
                recipient_input,
                amount_input,
                password_input,
                delivery_mode: DeliveryMode::ManualCalldata,
                broadcaster_choice: BroadcasterChoice::Random,
                broadcaster_fee_mode: PublicBroadcasterFeeMode::DeductFromAmount,
                cost_estimate_pending: false,
                estimating_cost: false,
                cost_estimate: None,
                estimate_id: 0,
                generation_id: 0,
                generating: false,
                generation_stage: TransactionGenerationStage::default(),
                error: None,
                result: None,
            },
        );
        cx.notify();
    }

    fn send_form_is_dirty(form: &SendFormState, cx: &Context<'_, Self>) -> bool {
        if form.generating || form.error.is_some() || form.result.is_some() {
            return true;
        }
        if !form.recipient_input.read(cx).value().trim().is_empty() {
            return true;
        }
        if !form.password_input.read(cx).value().trim().is_empty() {
            return true;
        }

        let default_amount = format_send_amount_input(form.asset.max_batched, form.asset.decimals);
        form.amount_input.read(cx).value().trim() != default_amount
    }

    fn clear_send_form_prepared_output(
        &mut self,
        key: UnshieldAssetKey,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(form) = self.send_forms.get_mut(&key) else {
            return;
        };
        if form.generating
            || (form.result.is_none() && form.error.is_none() && form.cost_estimate.is_none())
        {
            return;
        }
        form.result = None;
        form.error = None;
        form.cost_estimate = None;
        form.estimate_id = 0;
        form.cost_estimate_pending = false;
        form.estimating_cost = false;
        cx.notify();
    }

    fn set_send_delivery_mode(
        &mut self,
        key: UnshieldAssetKey,
        mode: DeliveryMode,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(form) = self.send_forms.get_mut(&key) else {
            return;
        };
        if form.generating || form.delivery_mode == mode || mode == DeliveryMode::SelfBroadcast {
            return;
        }
        let old_max =
            send_form_max_entered_amount(form, form.delivery_mode, form.broadcaster_fee_mode);
        let new_max = send_form_max_entered_amount(form, mode, form.broadcaster_fee_mode);
        let adjusted = apply_amount_adjustment_for_max_change(
            &form.amount_input,
            &form.asset,
            old_max,
            new_max,
            window,
            cx,
        );
        form.delivery_mode = mode;
        form.error = None;
        form.result = None;
        if mode == DeliveryMode::PublicBroadcaster || adjusted {
            form.cost_estimate = None;
        }
        form.estimate_id = 0;
        form.cost_estimate_pending = false;
        form.estimating_cost = false;
        cx.notify();
        self.schedule_public_broadcaster_cost_estimate(DeliveryFormKind::Send, key, cx);
    }

    fn set_send_broadcaster_choice(
        &mut self,
        key: UnshieldAssetKey,
        choice: BroadcasterChoice,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(form) = self.send_forms.get_mut(&key) else {
            return;
        };
        if form.generating || form.broadcaster_choice == choice {
            return;
        }
        form.broadcaster_choice = choice;
        form.error = None;
        form.result = None;
        form.cost_estimate = None;
        form.estimate_id = 0;
        form.cost_estimate_pending = false;
        form.estimating_cost = false;
        cx.notify();
        self.schedule_public_broadcaster_cost_estimate(DeliveryFormKind::Send, key, cx);
    }

    fn set_send_broadcaster_fee_mode(
        &mut self,
        key: UnshieldAssetKey,
        fee_mode: PublicBroadcasterFeeMode,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(form) = self.send_forms.get_mut(&key) else {
            return;
        };
        if form.generating || form.broadcaster_fee_mode == fee_mode {
            return;
        }
        let old_max =
            send_form_max_entered_amount(form, form.delivery_mode, form.broadcaster_fee_mode);
        let new_max = send_form_max_entered_amount(form, form.delivery_mode, fee_mode);
        apply_amount_adjustment_for_max_change(
            &form.amount_input,
            &form.asset,
            old_max,
            new_max,
            window,
            cx,
        );
        form.broadcaster_fee_mode = fee_mode;
        form.error = None;
        form.result = None;
        form.cost_estimate = None;
        form.estimate_id = 0;
        form.cost_estimate_pending = false;
        form.estimating_cost = false;
        cx.notify();
        self.schedule_public_broadcaster_cost_estimate(DeliveryFormKind::Send, key, cx);
    }

    fn schedule_public_broadcaster_cost_estimate(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        cx: &mut Context<'_, Self>,
    ) {
        let should_schedule = match kind {
            DeliveryFormKind::Send => self.send_forms.get(&key).is_some_and(|form| {
                !form.generating && form.delivery_mode == DeliveryMode::PublicBroadcaster
            }),
            DeliveryFormKind::Unshield => self.unshield_forms.get(&key).is_some_and(|form| {
                !form.generating && form.delivery_mode == DeliveryMode::PublicBroadcaster
            }),
        };
        if !should_schedule {
            return;
        }

        self.cost_estimate_seq = self.cost_estimate_seq.wrapping_add(1);
        let estimate_id = self.cost_estimate_seq;
        match kind {
            DeliveryFormKind::Send => {
                if let Some(form) = self.send_forms.get_mut(&key) {
                    form.estimate_id = estimate_id;
                    form.cost_estimate_pending = true;
                    form.estimating_cost = false;
                    form.cost_estimate = None;
                    form.error = None;
                }
            }
            DeliveryFormKind::Unshield => {
                if let Some(form) = self.unshield_forms.get_mut(&key) {
                    form.estimate_id = estimate_id;
                    form.cost_estimate_pending = true;
                    form.estimating_cost = false;
                    form.cost_estimate = None;
                    form.error = None;
                }
            }
        }
        cx.notify();

        cx.spawn(async move |this, cx| {
            tokio::time::sleep(COST_ESTIMATE_DEBOUNCE).await;
            let _ = this.update(cx, |root, cx| {
                let current_id = match kind {
                    DeliveryFormKind::Send => {
                        root.send_forms.get(&key).map(|form| form.estimate_id)
                    }
                    DeliveryFormKind::Unshield => {
                        root.unshield_forms.get(&key).map(|form| form.estimate_id)
                    }
                };
                if current_id != Some(estimate_id) {
                    return;
                }
                match kind {
                    DeliveryFormKind::Send => {
                        root.estimate_send_public_broadcaster_cost_from_form(key, cx);
                    }
                    DeliveryFormKind::Unshield => {
                        root.estimate_unshield_public_broadcaster_cost_from_form(key, cx);
                    }
                }
            });
        })
        .detach();
    }

    fn clear_pending_public_broadcaster_cost_estimate(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        cx: &mut Context<'_, Self>,
    ) {
        let changed = match kind {
            DeliveryFormKind::Send => self.send_forms.get_mut(&key).is_some_and(|form| {
                let changed = form.cost_estimate_pending || form.estimating_cost;
                form.cost_estimate_pending = false;
                form.estimating_cost = false;
                form.estimate_id = 0;
                changed
            }),
            DeliveryFormKind::Unshield => self.unshield_forms.get_mut(&key).is_some_and(|form| {
                let changed = form.cost_estimate_pending || form.estimating_cost;
                form.cost_estimate_pending = false;
                form.estimating_cost = false;
                form.estimate_id = 0;
                changed
            }),
        };
        if changed {
            cx.notify();
        }
    }

    fn estimate_send_public_broadcaster_cost_from_form(
        &mut self,
        key: UnshieldAssetKey,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(form) = self.send_forms.get(&key) else {
            return;
        };
        if form.generating
            || form.estimating_cost
            || form.delivery_mode != DeliveryMode::PublicBroadcaster
        {
            return;
        }
        let asset = form.asset.clone();
        let recipient = form.recipient_input.read(cx).value().trim().to_string();
        let amount_raw = form.amount_input.read(cx).value().to_string();
        let broadcaster_choice = form.broadcaster_choice.clone();
        let fee_mode = form.broadcaster_fee_mode;
        if parse_railgun_recipient(recipient.as_str()).is_err() {
            self.clear_pending_public_broadcaster_cost_estimate(DeliveryFormKind::Send, key, cx);
            return;
        }
        let amount = match parse_send_amount(amount_raw.as_str(), asset.decimals) {
            Ok(amount) if !amount.is_zero() => amount,
            Ok(_) | Err(_) => {
                self.clear_pending_public_broadcaster_cost_estimate(
                    DeliveryFormKind::Send,
                    key,
                    cx,
                );
                return;
            }
        };
        if amount > asset.max_batched {
            self.clear_pending_public_broadcaster_cost_estimate(DeliveryFormKind::Send, key, cx);
            return;
        }
        let Some(ChainUtxoState::Ready { session, .. }) = self.chain_states.get(&asset.chain_id)
        else {
            self.clear_pending_public_broadcaster_cost_estimate(DeliveryFormKind::Send, key, cx);
            return;
        };
        let session = Arc::clone(session);
        let fee_rows = self.monitor_fee_rows();
        let Ok(candidates) =
            eligible_public_broadcasters_for_asset(&fee_rows, asset.chain_id, asset.token, false)
        else {
            self.clear_pending_public_broadcaster_cost_estimate(DeliveryFormKind::Send, key, cx);
            return;
        };
        let selection = Self::public_broadcaster_selection(&broadcaster_choice);
        if select_public_broadcaster(&candidates, &selection).is_err() {
            self.clear_pending_public_broadcaster_cost_estimate(DeliveryFormKind::Send, key, cx);
            return;
        }

        self.cost_estimate_seq = self.cost_estimate_seq.wrapping_add(1);
        let estimate_id = self.cost_estimate_seq;
        if let Some(form) = self.send_forms.get_mut(&key) {
            form.cost_estimate_pending = false;
            form.estimating_cost = true;
            form.cost_estimate = None;
            form.error = None;
            form.estimate_id = estimate_id;
        }
        cx.notify();

        let request = DesktopSendPublicBroadcasterEstimateRequest {
            chain_id: asset.chain_id,
            session,
            token: asset.token,
            amount,
            recipient,
            fee_rows,
            selection,
            fee_mode,
        };
        let http = self.http.clone();
        let join = self.runtime.spawn(async move {
            estimate_desktop_send_public_broadcaster_cost(request, &http).await
        });
        cx.spawn(async move |this, cx| {
            let result = match join.await {
                Ok(result) => result,
                Err(error) => Err(eyre::eyre!("send cost estimate task failed: {error}")),
            };
            let _ = this.update(cx, |root, cx| {
                let Some(form) = root.send_forms.get_mut(&key) else {
                    return;
                };
                if form.estimate_id != estimate_id {
                    return;
                }
                form.cost_estimate_pending = false;
                form.estimating_cost = false;
                match result {
                    Ok(estimate) => {
                        form.error = None;
                        form.cost_estimate = Some(estimate);
                    }
                    Err(error) => {
                        form.cost_estimate = None;
                        form.error = Some(Arc::from(error.to_string()));
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn monitor_fee_rows(&self) -> Vec<broadcaster_monitor::FeeRow> {
        self.monitor_state.read().fee_rows()
    }

    fn public_broadcaster_selection(choice: &BroadcasterChoice) -> PublicBroadcasterSelection {
        match choice {
            BroadcasterChoice::Random => PublicBroadcasterSelection::Random,
            BroadcasterChoice::Specific { railgun_address } => {
                PublicBroadcasterSelection::Specific {
                    railgun_address: railgun_address.clone(),
                }
            }
        }
    }

    fn open_broadcaster_picker(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let form_exists = match kind {
            DeliveryFormKind::Send => self.send_forms.contains_key(&key),
            DeliveryFormKind::Unshield => self.unshield_forms.contains_key(&key),
        };
        if !form_exists {
            return;
        }

        let query_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("search broadcasters"));
        let focus_handle = cx.focus_handle();
        cx.subscribe(&query_input, |_this, _input, event: &InputEvent, cx| {
            if matches!(event, InputEvent::Change) {
                cx.notify();
            }
        })
        .detach();
        self.broadcaster_picker = Some(BroadcasterPickerState {
            kind,
            key,
            query_input,
            focus_handle,
            sort: BroadcasterPickerSort::FeeAscReliabilityDesc,
        });
        if let Some(picker) = self.broadcaster_picker.as_ref() {
            picker.query_input.read(cx).focus_handle(cx).focus(window);
        }
        cx.notify();
    }

    fn close_broadcaster_picker(&mut self, cx: &mut Context<'_, Self>) {
        self.broadcaster_picker = None;
        cx.notify();
    }

    fn choose_broadcaster_from_picker(
        &mut self,
        kind: DeliveryFormKind,
        key: UnshieldAssetKey,
        railgun_address: String,
        cx: &mut Context<'_, Self>,
    ) {
        let choice = BroadcasterChoice::Specific { railgun_address };
        match kind {
            DeliveryFormKind::Send => self.set_send_broadcaster_choice(key, choice, cx),
            DeliveryFormKind::Unshield => self.set_unshield_broadcaster_choice(key, choice, cx),
        }
        self.broadcaster_picker = None;
        cx.notify();
    }

    fn generate_send_calldata_from_form(
        &mut self,
        key: UnshieldAssetKey,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(form) = self.send_forms.get(&key) else {
            return;
        };
        if form.generating {
            return;
        }
        let asset = form.asset.clone();
        let recipient_input = form.recipient_input.clone();
        let amount_input = form.amount_input.clone();
        let password_input = form.password_input.clone();
        let delivery_mode = form.delivery_mode;
        let broadcaster_choice = form.broadcaster_choice.clone();
        let broadcaster_fee_mode = form.broadcaster_fee_mode;

        let Some(view_session) = self.view_session.clone() else {
            self.set_send_form_error(key, "Unlock the wallet vault before sending", cx);
            return;
        };
        let Some(vault_store) = self.vault_store.clone() else {
            self.set_send_form_error(key, "Wallet vault storage is unavailable", cx);
            return;
        };
        let Some(ChainUtxoState::Ready { session, .. }) = self.chain_states.get(&asset.chain_id)
        else {
            self.set_send_form_error(key, "Wait for wallet sync to finish before sending", cx);
            return;
        };
        let session = Arc::clone(session);
        if asset.max_batched.is_zero() {
            self.set_send_form_error(
                key,
                "No POI-verified private notes are spendable in a batched send",
                cx,
            );
            return;
        }

        let recipient_raw = recipient_input.read(cx).value().to_string();
        if let Err(error) = parse_railgun_recipient(recipient_raw.as_str()) {
            self.set_send_form_error(key, error.to_string(), cx);
            return;
        }
        let recipient = recipient_raw.trim().to_string();
        let amount_raw = amount_input.read(cx).value().to_string();
        let amount = match parse_send_amount(amount_raw.as_str(), asset.decimals) {
            Ok(amount) if !amount.is_zero() => amount,
            Ok(_) => {
                self.set_send_form_error(key, "Enter an amount greater than zero", cx);
                return;
            }
            Err(error) => {
                self.set_send_form_error(key, error.to_string(), cx);
                return;
            }
        };
        if amount > asset.max_batched {
            self.set_send_form_error(
                key,
                format!(
                    "Amount exceeds max POI-verified batched transaction: {}",
                    format_send_amount_input(asset.max_batched, asset.decimals)
                ),
                cx,
            );
            return;
        }

        let fee_rows = if delivery_mode == DeliveryMode::PublicBroadcaster {
            let rows = self.monitor_fee_rows();
            let candidates = match eligible_public_broadcasters_for_asset(
                &rows,
                asset.chain_id,
                asset.token,
                false,
            ) {
                Ok(candidates) => candidates,
                Err(error) => {
                    self.set_send_form_error(key, error.to_string(), cx);
                    return;
                }
            };
            if let Err(error) = select_public_broadcaster(
                &candidates,
                &Self::public_broadcaster_selection(&broadcaster_choice),
            ) {
                self.set_send_form_error(key, error.to_string(), cx);
                return;
            }
            rows
        } else {
            Vec::new()
        };

        let password_empty = password_input.read(cx).value().trim().is_empty();
        if password_empty {
            self.set_send_form_error(key, "Enter the vault password to prepare this send", cx);
            return;
        }
        let vault_password = Self::read_and_clear_input(&password_input, window, cx);

        self.send_generation_seq = self.send_generation_seq.wrapping_add(1);
        let generation_id = self.send_generation_seq;
        let (progress_tx, progress_rx) = watch::channel(TransactionGenerationStage::default());
        if let Some(form) = self.send_forms.get_mut(&key) {
            form.generation_id = generation_id;
            form.generating = true;
            form.generation_stage = TransactionGenerationStage::default();
            form.cost_estimate_pending = false;
            form.estimating_cost = false;
            form.estimate_id = 0;
            form.error = None;
            form.result = None;
        }
        cx.notify();

        let http = self.http.clone();
        let waku = Arc::clone(&self.waku);
        let chain_id = asset.chain_id;
        let token = asset.token;
        let join = match delivery_mode {
            DeliveryMode::ManualCalldata => {
                let request = DesktopSendCalldataRequest {
                    chain_id,
                    view_session,
                    session,
                    vault_store,
                    vault_password,
                    token,
                    amount,
                    recipient,
                    verify_proof: true,
                    progress_tx: Some(progress_tx),
                };
                self.runtime.spawn(async move {
                    prepare_desktop_send_calldata(request, &http)
                        .await
                        .map(SendResult::Manual)
                })
            }
            DeliveryMode::PublicBroadcaster => {
                let request = DesktopSendPublicBroadcasterRequest {
                    chain_id,
                    view_session,
                    session,
                    vault_store,
                    vault_password,
                    token,
                    amount,
                    recipient,
                    verify_proof: true,
                    fee_rows,
                    selection: Self::public_broadcaster_selection(&broadcaster_choice),
                    fee_mode: broadcaster_fee_mode,
                    waku,
                    response_timeout: PUBLIC_BROADCASTER_RESPONSE_TIMEOUT,
                    progress_tx: Some(progress_tx),
                };
                self.runtime.spawn(async move {
                    submit_desktop_send_public_broadcaster(request, &http)
                        .await
                        .map(|result| SendResult::PublicBroadcaster(Box::new(result)))
                })
            }
            DeliveryMode::SelfBroadcast => {
                self.set_send_form_error(key, "Self-broadcast is not available yet", cx);
                return;
            }
        };
        Self::watch_send_generation_stage(key, generation_id, progress_rx, cx);
        cx.spawn(async move |this, cx| {
            let result = match join.await {
                Ok(result) => result,
                Err(error) => Err(eyre::eyre!("send generation task failed: {error}")),
            };
            let _ = this.update(cx, |root, cx| {
                let Some(form) = root.send_forms.get_mut(&key) else {
                    return;
                };
                if form.asset.chain_id != chain_id || form.asset.token != token {
                    return;
                }
                if form.generation_id != generation_id || !form.generating {
                    return;
                }
                form.generating = false;
                match result {
                    Ok(result) => {
                        form.error = None;
                        form.result = Some(result);
                    }
                    Err(error) => {
                        form.result = None;
                        form.error = Some(Arc::from(error.to_string()));
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn watch_send_generation_stage(
        key: UnshieldAssetKey,
        generation_id: u64,
        mut progress_rx: watch::Receiver<TransactionGenerationStage>,
        cx: &Context<'_, Self>,
    ) {
        cx.spawn(async move |this, cx| {
            while progress_rx.changed().await.is_ok() {
                let stage = *progress_rx.borrow_and_update();
                if this
                    .update(cx, |root, cx| {
                        let Some(form) = root.send_forms.get_mut(&key) else {
                            return;
                        };
                        if form.generation_id != generation_id || !form.generating {
                            return;
                        }
                        form.generation_stage = stage;
                        cx.notify();
                    })
                    .is_err()
                {
                    break;
                }
            }
        })
        .detach();
    }

    fn set_send_form_error(
        &mut self,
        key: UnshieldAssetKey,
        message: impl Into<Arc<str>>,
        cx: &mut Context<'_, Self>,
    ) {
        if let Some(form) = self.send_forms.get_mut(&key) {
            form.generating = false;
            form.cost_estimate_pending = false;
            form.estimating_cost = false;
            form.estimate_id = 0;
            form.result = None;
            form.error = Some(message.into());
            cx.notify();
        }
    }

    fn open_unshield_form(
        &mut self,
        asset: UnshieldAsset,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let key = UnshieldAssetKey::from_asset(&asset);
        if self.unshield_forms.contains_key(&key) {
            return;
        }
        self.unshield_forms.retain(|existing_key, form| {
            *existing_key == key || Self::unshield_form_is_dirty(form, cx)
        });
        let amount = format_unshield_amount_input(asset.max_batched, asset.decimals);
        let amount_input = cx.new(|cx| {
            let mut input = InputState::new(window, cx).placeholder("amount");
            input.set_value(&amount, window, cx);
            input
        });
        let recipient_input = cx.new(|cx| InputState::new(window, cx).placeholder("0x recipient"));
        let password_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("vault password")
                .masked(true)
        });
        cx.subscribe_in(
            &password_input,
            window,
            move |this, _input, event: &InputEvent, window, cx| {
                if matches!(event, InputEvent::PressEnter { .. }) {
                    this.generate_unshield_calldata_from_form(key, window, cx);
                }
            },
        )
        .detach();
        cx.subscribe(
            &recipient_input,
            move |this, _input, event: &InputEvent, cx| {
                if matches!(event, InputEvent::Change) {
                    this.clear_unshield_form_prepared_output(key, cx);
                    this.schedule_public_broadcaster_cost_estimate(
                        DeliveryFormKind::Unshield,
                        key,
                        cx,
                    );
                }
            },
        )
        .detach();
        cx.subscribe(
            &amount_input,
            move |this, _input, event: &InputEvent, cx| {
                if matches!(event, InputEvent::Change) {
                    this.clear_unshield_form_prepared_output(key, cx);
                    this.schedule_public_broadcaster_cost_estimate(
                        DeliveryFormKind::Unshield,
                        key,
                        cx,
                    );
                }
            },
        )
        .detach();
        self.unshield_forms.insert(
            key,
            UnshieldFormState {
                asset,
                recipient_input,
                amount_input,
                password_input,
                unwrap: false,
                delivery_mode: DeliveryMode::ManualCalldata,
                broadcaster_choice: BroadcasterChoice::Random,
                broadcaster_fee_mode: PublicBroadcasterFeeMode::DeductFromAmount,
                cost_estimate_pending: false,
                estimating_cost: false,
                cost_estimate: None,
                estimate_id: 0,
                generation_id: 0,
                generating: false,
                generation_stage: TransactionGenerationStage::default(),
                error: None,
                result: None,
            },
        );
        cx.notify();
    }

    fn unshield_form_is_dirty(form: &UnshieldFormState, cx: &Context<'_, Self>) -> bool {
        if form.generating
            || form.unwrap
            || form.error.is_some()
            || form.result.is_some()
            || form.cost_estimate.is_some()
        {
            return true;
        }
        if !form.recipient_input.read(cx).value().trim().is_empty() {
            return true;
        }
        if !form.password_input.read(cx).value().trim().is_empty() {
            return true;
        }

        let default_amount =
            format_unshield_amount_input(form.asset.max_batched, form.asset.decimals);
        form.amount_input.read(cx).value().trim() != default_amount
    }

    fn set_unshield_unwrap(
        &mut self,
        key: UnshieldAssetKey,
        unwrap: bool,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(form) = self.unshield_forms.get_mut(&key) else {
            return;
        };
        if !is_wrapped_native_token(form.asset.chain_id, form.asset.token)
            || form.generating
            || form.unwrap == unwrap
        {
            return;
        }
        form.unwrap = unwrap;
        form.error = None;
        form.result = None;
        form.cost_estimate = None;
        form.estimate_id = 0;
        form.cost_estimate_pending = false;
        form.estimating_cost = false;
        cx.notify();
        self.schedule_public_broadcaster_cost_estimate(DeliveryFormKind::Unshield, key, cx);
    }

    fn set_unshield_broadcaster_fee_mode(
        &mut self,
        key: UnshieldAssetKey,
        fee_mode: PublicBroadcasterFeeMode,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(form) = self.unshield_forms.get_mut(&key) else {
            return;
        };
        if form.generating || form.broadcaster_fee_mode == fee_mode {
            return;
        }
        let old_max =
            unshield_form_max_entered_amount(form, form.delivery_mode, form.broadcaster_fee_mode);
        let new_max = unshield_form_max_entered_amount(form, form.delivery_mode, fee_mode);
        apply_amount_adjustment_for_max_change(
            &form.amount_input,
            &form.asset,
            old_max,
            new_max,
            window,
            cx,
        );
        form.broadcaster_fee_mode = fee_mode;
        form.error = None;
        form.result = None;
        form.cost_estimate = None;
        form.estimate_id = 0;
        form.cost_estimate_pending = false;
        form.estimating_cost = false;
        cx.notify();
        self.schedule_public_broadcaster_cost_estimate(DeliveryFormKind::Unshield, key, cx);
    }

    fn clear_unshield_form_prepared_output(
        &mut self,
        key: UnshieldAssetKey,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(form) = self.unshield_forms.get_mut(&key) else {
            return;
        };
        if form.generating
            || (form.result.is_none() && form.error.is_none() && form.cost_estimate.is_none())
        {
            return;
        }
        form.result = None;
        form.error = None;
        form.cost_estimate = None;
        form.estimate_id = 0;
        form.cost_estimate_pending = false;
        form.estimating_cost = false;
        cx.notify();
        self.schedule_public_broadcaster_cost_estimate(DeliveryFormKind::Unshield, key, cx);
    }

    fn set_unshield_delivery_mode(
        &mut self,
        key: UnshieldAssetKey,
        mode: DeliveryMode,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(form) = self.unshield_forms.get_mut(&key) else {
            return;
        };
        if form.generating || form.delivery_mode == mode || mode == DeliveryMode::SelfBroadcast {
            return;
        }
        let old_max =
            unshield_form_max_entered_amount(form, form.delivery_mode, form.broadcaster_fee_mode);
        let new_max = unshield_form_max_entered_amount(form, mode, form.broadcaster_fee_mode);
        let adjusted = apply_amount_adjustment_for_max_change(
            &form.amount_input,
            &form.asset,
            old_max,
            new_max,
            window,
            cx,
        );
        form.delivery_mode = mode;
        form.error = None;
        form.result = None;
        if mode == DeliveryMode::PublicBroadcaster || adjusted {
            form.cost_estimate = None;
        }
        form.estimate_id = 0;
        form.cost_estimate_pending = false;
        form.estimating_cost = false;
        cx.notify();
        self.schedule_public_broadcaster_cost_estimate(DeliveryFormKind::Unshield, key, cx);
    }

    fn set_unshield_broadcaster_choice(
        &mut self,
        key: UnshieldAssetKey,
        choice: BroadcasterChoice,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(form) = self.unshield_forms.get_mut(&key) else {
            return;
        };
        if form.generating || form.broadcaster_choice == choice {
            return;
        }
        form.broadcaster_choice = choice;
        form.error = None;
        form.result = None;
        form.cost_estimate = None;
        form.estimate_id = 0;
        form.cost_estimate_pending = false;
        form.estimating_cost = false;
        cx.notify();
        self.schedule_public_broadcaster_cost_estimate(DeliveryFormKind::Unshield, key, cx);
    }

    fn estimate_unshield_public_broadcaster_cost_from_form(
        &mut self,
        key: UnshieldAssetKey,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(form) = self.unshield_forms.get(&key) else {
            return;
        };
        if form.generating
            || form.estimating_cost
            || form.delivery_mode != DeliveryMode::PublicBroadcaster
        {
            return;
        }
        let asset = form.asset.clone();
        let unwrap = form.unwrap;
        let recipient_raw = form.recipient_input.read(cx).value().to_string();
        let amount_raw = form.amount_input.read(cx).value().to_string();
        let broadcaster_choice = form.broadcaster_choice.clone();
        let fee_mode = form.broadcaster_fee_mode;
        let Ok(recipient) = recipient_raw.trim().parse::<Address>() else {
            self.clear_pending_public_broadcaster_cost_estimate(
                DeliveryFormKind::Unshield,
                key,
                cx,
            );
            return;
        };
        let amount = match parse_unshield_amount(amount_raw.as_str(), asset.decimals) {
            Ok(amount) if !amount.is_zero() => amount,
            Ok(_) | Err(_) => {
                self.clear_pending_public_broadcaster_cost_estimate(
                    DeliveryFormKind::Unshield,
                    key,
                    cx,
                );
                return;
            }
        };
        if amount > asset.max_batched {
            self.clear_pending_public_broadcaster_cost_estimate(
                DeliveryFormKind::Unshield,
                key,
                cx,
            );
            return;
        }
        let Some(ChainUtxoState::Ready { session, .. }) = self.chain_states.get(&asset.chain_id)
        else {
            self.clear_pending_public_broadcaster_cost_estimate(
                DeliveryFormKind::Unshield,
                key,
                cx,
            );
            return;
        };
        let session = Arc::clone(session);
        let fee_rows = self.monitor_fee_rows();
        let Ok(candidates) =
            eligible_public_broadcasters_for_asset(&fee_rows, asset.chain_id, asset.token, unwrap)
        else {
            self.clear_pending_public_broadcaster_cost_estimate(
                DeliveryFormKind::Unshield,
                key,
                cx,
            );
            return;
        };
        let selection = Self::public_broadcaster_selection(&broadcaster_choice);
        if select_public_broadcaster(&candidates, &selection).is_err() {
            self.clear_pending_public_broadcaster_cost_estimate(
                DeliveryFormKind::Unshield,
                key,
                cx,
            );
            return;
        }

        self.cost_estimate_seq = self.cost_estimate_seq.wrapping_add(1);
        let estimate_id = self.cost_estimate_seq;
        if let Some(form) = self.unshield_forms.get_mut(&key) {
            form.cost_estimate_pending = false;
            form.estimating_cost = true;
            form.cost_estimate = None;
            form.error = None;
            form.estimate_id = estimate_id;
        }
        cx.notify();

        let request = DesktopUnshieldPublicBroadcasterEstimateRequest {
            chain_id: asset.chain_id,
            session,
            token: asset.token,
            amount,
            recipient,
            unwrap,
            fee_rows,
            selection,
            fee_mode,
        };
        let http = self.http.clone();
        let join = self.runtime.spawn(async move {
            estimate_desktop_unshield_public_broadcaster_cost(request, &http).await
        });
        cx.spawn(async move |this, cx| {
            let result = match join.await {
                Ok(result) => result,
                Err(error) => Err(eyre::eyre!("unshield cost estimate task failed: {error}")),
            };
            let _ = this.update(cx, |root, cx| {
                let Some(form) = root.unshield_forms.get_mut(&key) else {
                    return;
                };
                if form.estimate_id != estimate_id {
                    return;
                }
                form.cost_estimate_pending = false;
                form.estimating_cost = false;
                match result {
                    Ok(estimate) => {
                        form.error = None;
                        form.cost_estimate = Some(estimate);
                    }
                    Err(error) => {
                        form.cost_estimate = None;
                        form.error = Some(Arc::from(error.to_string()));
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn generate_unshield_calldata_from_form(
        &mut self,
        key: UnshieldAssetKey,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        let Some(form) = self.unshield_forms.get(&key) else {
            return;
        };
        if form.generating {
            return;
        }
        let asset = form.asset.clone();
        let unwrap = form.unwrap;
        let recipient_input = form.recipient_input.clone();
        let amount_input = form.amount_input.clone();
        let password_input = form.password_input.clone();
        let delivery_mode = form.delivery_mode;
        let broadcaster_choice = form.broadcaster_choice.clone();
        let broadcaster_fee_mode = form.broadcaster_fee_mode;

        let Some(view_session) = self.view_session.clone() else {
            self.set_unshield_form_error(key, "Unlock the wallet vault before unshielding", cx);
            return;
        };
        let Some(vault_store) = self.vault_store.clone() else {
            self.set_unshield_form_error(key, "Wallet vault storage is unavailable", cx);
            return;
        };
        let Some(ChainUtxoState::Ready { session, .. }) = self.chain_states.get(&asset.chain_id)
        else {
            self.set_unshield_form_error(
                key,
                "Wait for wallet sync to finish before unshielding",
                cx,
            );
            return;
        };
        let session = Arc::clone(session);
        if asset.max_batched.is_zero() {
            self.set_unshield_form_error(
                key,
                "No POI-verified private notes are spendable in a batched unshield",
                cx,
            );
            return;
        }

        let recipient_raw = recipient_input.read(cx).value().to_string();
        let Some(recipient) = parse_address(recipient_raw.trim()) else {
            self.set_unshield_form_error(key, "Enter a valid public EVM recipient address", cx);
            return;
        };
        let amount_raw = amount_input.read(cx).value().to_string();
        let amount = match parse_unshield_amount(amount_raw.as_str(), asset.decimals) {
            Ok(amount) if !amount.is_zero() => amount,
            Ok(_) => {
                self.set_unshield_form_error(key, "Enter an amount greater than zero", cx);
                return;
            }
            Err(error) => {
                self.set_unshield_form_error(key, error.to_string(), cx);
                return;
            }
        };
        if amount > asset.max_batched {
            self.set_unshield_form_error(
                key,
                format!(
                    "Amount exceeds max POI-verified batched transaction: {}",
                    format_unshield_amount_input(asset.max_batched, asset.decimals)
                ),
                cx,
            );
            return;
        }

        let fee_rows = if delivery_mode == DeliveryMode::PublicBroadcaster {
            let rows = self.monitor_fee_rows();
            let candidates = match eligible_public_broadcasters_for_asset(
                &rows,
                asset.chain_id,
                asset.token,
                unwrap,
            ) {
                Ok(candidates) => candidates,
                Err(error) => {
                    self.set_unshield_form_error(key, error.to_string(), cx);
                    return;
                }
            };
            if let Err(error) = select_public_broadcaster(
                &candidates,
                &Self::public_broadcaster_selection(&broadcaster_choice),
            ) {
                self.set_unshield_form_error(key, error.to_string(), cx);
                return;
            }
            rows
        } else {
            Vec::new()
        };

        let password_empty = password_input.read(cx).value().trim().is_empty();
        if password_empty {
            self.set_unshield_form_error(
                key,
                "Enter the vault password to prepare this unshield",
                cx,
            );
            return;
        }
        let vault_password = Self::read_and_clear_input(&password_input, window, cx);

        self.unshield_generation_seq = self.unshield_generation_seq.wrapping_add(1);
        let generation_id = self.unshield_generation_seq;
        let (progress_tx, progress_rx) = watch::channel(TransactionGenerationStage::default());
        if let Some(form) = self.unshield_forms.get_mut(&key) {
            form.generation_id = generation_id;
            form.generating = true;
            form.generation_stage = TransactionGenerationStage::default();
            form.cost_estimate_pending = false;
            form.estimating_cost = false;
            form.estimate_id = 0;
            form.error = None;
            form.result = None;
        }
        cx.notify();

        let http = self.http.clone();
        let waku = Arc::clone(&self.waku);
        let chain_id = asset.chain_id;
        let token = asset.token;
        let join = match delivery_mode {
            DeliveryMode::ManualCalldata => {
                let request = DesktopUnshieldCalldataRequest {
                    chain_id,
                    view_session,
                    session,
                    vault_store,
                    vault_password,
                    token,
                    amount,
                    recipient,
                    unwrap,
                    verify_proof: true,
                    progress_tx: Some(progress_tx),
                };
                self.runtime.spawn(async move {
                    prepare_desktop_unshield_calldata(request, &http)
                        .await
                        .map(UnshieldResult::Manual)
                })
            }
            DeliveryMode::PublicBroadcaster => {
                let request = DesktopUnshieldPublicBroadcasterRequest {
                    chain_id,
                    view_session,
                    session,
                    vault_store,
                    vault_password,
                    token,
                    amount,
                    recipient,
                    unwrap,
                    verify_proof: true,
                    fee_rows,
                    selection: Self::public_broadcaster_selection(&broadcaster_choice),
                    fee_mode: broadcaster_fee_mode,
                    waku,
                    response_timeout: PUBLIC_BROADCASTER_RESPONSE_TIMEOUT,
                    progress_tx: Some(progress_tx),
                };
                self.runtime.spawn(async move {
                    submit_desktop_unshield_public_broadcaster(request, &http)
                        .await
                        .map(|result| UnshieldResult::PublicBroadcaster(Box::new(result)))
                })
            }
            DeliveryMode::SelfBroadcast => {
                self.set_unshield_form_error(key, "Self-broadcast is not available yet", cx);
                return;
            }
        };
        Self::watch_unshield_generation_stage(key, generation_id, progress_rx, cx);
        cx.spawn(async move |this, cx| {
            let result = match join.await {
                Ok(result) => result,
                Err(error) => Err(eyre::eyre!("unshield generation task failed: {error}")),
            };
            let _ = this.update(cx, |root, cx| {
                let Some(form) = root.unshield_forms.get_mut(&key) else {
                    return;
                };
                if form.asset.chain_id != chain_id || form.asset.token != token {
                    return;
                }
                if form.generation_id != generation_id || !form.generating {
                    return;
                }
                form.generating = false;
                match result {
                    Ok(result) => {
                        form.error = None;
                        form.result = Some(result);
                    }
                    Err(error) => {
                        form.result = None;
                        form.error = Some(Arc::from(error.to_string()));
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn watch_unshield_generation_stage(
        key: UnshieldAssetKey,
        generation_id: u64,
        mut progress_rx: watch::Receiver<TransactionGenerationStage>,
        cx: &Context<'_, Self>,
    ) {
        cx.spawn(async move |this, cx| {
            while progress_rx.changed().await.is_ok() {
                let stage = *progress_rx.borrow_and_update();
                if this
                    .update(cx, |root, cx| {
                        let Some(form) = root.unshield_forms.get_mut(&key) else {
                            return;
                        };
                        if form.generation_id != generation_id || !form.generating {
                            return;
                        }
                        form.generation_stage = stage;
                        cx.notify();
                    })
                    .is_err()
                {
                    break;
                }
            }
        })
        .detach();
    }

    fn set_unshield_form_error(
        &mut self,
        key: UnshieldAssetKey,
        message: impl Into<Arc<str>>,
        cx: &mut Context<'_, Self>,
    ) {
        if let Some(form) = self.unshield_forms.get_mut(&key) {
            form.generating = false;
            form.cost_estimate_pending = false;
            form.estimating_cost = false;
            form.estimate_id = 0;
            form.result = None;
            form.error = Some(message.into());
            cx.notify();
        }
    }

    fn read_and_clear_input(
        input: &Entity<InputState>,
        window: &mut Window,
        cx: &mut Context<'_, Self>,
    ) -> Zeroizing<String> {
        let value = Zeroizing::new(input.read(cx).value().to_string());
        input.update(cx, |input, cx| input.set_value("", window, cx));
        value
    }

    fn handle_vault_error(&mut self, error: &VaultError, cx: &mut Context<'_, Self>) {
        tracing::warn!(
            error_kind = vault_error_kind(error),
            "desktop wallet vault operation failed"
        );
        let message: Arc<str> = match error {
            VaultError::UnlockFailed => "Unlock failed. Check the password and try again.".into(),
            VaultError::Key(_) => "Invalid recovery phrase. Paste it again to retry.".into(),
            VaultError::VaultNotFound => {
                "Wallet vault not found. Create a new vault to continue.".into()
            }
            _ => "Wallet vault operation failed. See logs for non-sensitive diagnostics.".into(),
        };
        self.set_vault_error(message, cx);
    }

    fn set_vault_error(&mut self, message: impl Into<Arc<str>>, cx: &mut Context<'_, Self>) {
        self.vault_error = Some(message.into());
        cx.notify();
    }

    fn render_activity_rail(&self, root: Entity<Self>) -> impl IntoElement {
        div()
            .w(ACTIVITY_RAIL_WIDTH)
            .h_full()
            .flex_none()
            .flex()
            .flex_col()
            .items_center()
            .bg(rgb(theme::SURFACE))
            .border_r_1()
            .border_color(rgb(theme::BORDER))
            .child(Self::render_activity_button(
                "activity-wallet",
                icons::wallet_icon_path(),
                "Wallets",
                self.active_activity == Activity::Wallet,
                false,
                {
                    let root = root.clone();
                    move |_event, _window, cx| {
                        root.update(cx, |root, cx| {
                            root.active_activity = Activity::Wallet;
                            root.focus_utxo_table_on_render = should_focus_utxo_table(
                                root.active_activity,
                                root.active_wallet_tab,
                                root.chain_states.get(&root.selected_chain),
                            );
                            cx.notify();
                        });
                    }
                },
            ))
            .child(Self::render_activity_button(
                "activity-broadcaster",
                icons::robot_icon_path(),
                "Public broadcasters",
                self.active_activity == Activity::Broadcaster,
                false,
                {
                    let root = root.clone();
                    move |_event, _window, cx| {
                        root.update(cx, |root, cx| {
                            root.active_activity = Activity::Broadcaster;
                            cx.notify();
                        });
                    }
                },
            ))
            .child(div().flex_1())
            .child(Self::render_activity_button(
                "activity-logs",
                icons::logs_icon_path(),
                if self.logs_open {
                    "Hide logs"
                } else {
                    "Show logs"
                },
                self.logs_open,
                true,
                move |_event, _window, cx| {
                    root.update(cx, |root, cx| {
                        root.logs_open = !root.logs_open;
                        cx.notify();
                    });
                },
            ))
    }

    fn render_activity_button(
        id: &'static str,
        icon: PathBuf,
        tooltip: &'static str,
        active: bool,
        align_bottom: bool,
        on_click: impl Fn(&gpui::ClickEvent, &mut Window, &mut App) + 'static,
    ) -> impl IntoElement {
        div()
            .id(id)
            .when(!align_bottom, |this| this.mt(px(10.0)))
            .when(align_bottom, |this| this.mb(px(10.0)))
            .size(px(36.0))
            .flex()
            .items_center()
            .justify_center()
            .rounded_md()
            .cursor_pointer()
            .when(active, |this| this.bg(rgb(theme::SELECTED_SURFACE)))
            .when(!active, |this| {
                this.bg(rgb(theme::SURFACE))
                    .hover(|this| this.bg(rgb(theme::SURFACE_HOVER)))
            })
            .tooltip(move |window, cx| Tooltip::new(tooltip).build(window, cx))
            .on_click(on_click)
            .child(img(icon).size(px(18.0)).flex_none())
    }

    fn render_vault_gate(&self, root: Entity<Self>) -> impl IntoElement {
        div()
            .size_full()
            .flex()
            .items_center()
            .justify_center()
            .bg(rgb(theme::BACKGROUND))
            .p(px(24.0))
            .child(match &self.vault_state {
                VaultState::CreateVault => self.render_create_vault(root).into_any_element(),
                VaultState::UnlockVault => self.render_unlock_vault(root).into_any_element(),
                VaultState::SetupWallet => self.render_wallet_setup(root).into_any_element(),
                VaultState::ViewUnlocked => div().into_any_element(),
                VaultState::Error(message) => self.render_vault_fatal(message).into_any_element(),
            })
    }

    fn render_create_vault(&self, root: Entity<Self>) -> gpui::Div {
        let submit_root = root;
        let mut card = vault_card(
            "Create wallet vault",
            "Choose one password for this desktop wallet vault. It will be required every time the app starts.",
        );
        if let Some(error) = self.render_vault_error() {
            card = card.child(error);
        }

        card.child(app_input(&self.new_password_input))
            .child(app_input(&self.confirm_password_input))
            .child(
                app_button("create-wallet-vault", "Create vault")
                    .primary()
                    .w_full()
                    .on_click(move |_event, window, cx| {
                        submit_root.update(cx, |root, cx| {
                            root.create_vault_from_inputs(window, cx);
                        });
                    }),
            )
            .child(
                div()
                    .text_size(APP_TEXT_SIZE)
                    .text_color(rgb(theme::TEXT_MUTED))
                    .child("No OS keychain or mnemonic startup argument is used in v1."),
            )
    }

    fn render_unlock_vault(&self, root: Entity<Self>) -> gpui::Div {
        let submit_root = root;
        let mut card = vault_card(
            "Unlock wallet vault",
            "Enter the vault password to view wallet balances and history.",
        );
        if let Some(error) = self.render_vault_error() {
            card = card.child(error);
        }

        card.child(app_input(&self.unlock_password_input).disabled(self.unlock_in_progress))
            .child(
                app_button("unlock-wallet-vault", "Unlock vault")
                    .primary()
                    .w_full()
                    .loading(self.unlock_in_progress)
                    .disabled(self.unlock_in_progress)
                    .on_click(move |_event, window, cx| {
                        submit_root.update(cx, |root, cx| {
                            root.unlock_vault_from_input(window, cx);
                        });
                    }),
            )
            .child(
                div()
                    .text_size(APP_TEXT_SIZE)
                    .text_color(rgb(theme::TEXT_MUTED))
                    .child("Unlocking view mode does not decrypt spend material."),
            )
    }

    fn render_wallet_setup(&self, root: Entity<Self>) -> gpui::Div {
        match self.wallet_setup_mode {
            WalletSetupMode::Choose => self.render_wallet_setup_choice(root),
            WalletSetupMode::GeneratedReview => self.render_generated_wallet_review(root),
            WalletSetupMode::Import => self.render_import_wallet(root),
        }
    }

    fn render_wallet_setup_choice(&self, root: Entity<Self>) -> gpui::Div {
        let generate_root = root.clone();
        let import_root = root;
        let mut card = vault_card(
            "Add your first wallet",
            "Generate a new recovery phrase or import an existing one. Seed material will be encrypted into the vault.",
        );
        if let Some(error) = self.render_vault_error() {
            card = card.child(error);
        }

        card.child(
            app_button("generate-vault-wallet", "Generate new wallet")
                .primary()
                .w_full()
                .on_click(move |_event, _window, cx| {
                    generate_root.update(cx, |root, cx| {
                        root.choose_generated_wallet(cx);
                    });
                }),
        )
        .child(
            app_button("import-vault-wallet", "Import recovery phrase")
                .outline()
                .w_full()
                .on_click(move |_event, _window, cx| {
                    import_root.update(cx, |root, cx| {
                        root.choose_import_wallet(cx);
                    });
                }),
        )
    }

    fn render_generated_wallet_review(&self, root: Entity<Self>) -> gpui::Div {
        let confirm_root = root.clone();
        let back_root = root;
        let phrase = self
            .generated_seed
            .as_ref()
            .map_or_else(String::new, |seed| seed.mnemonic.to_string());
        let mut card = vault_card(
            "Save recovery phrase",
            "Write this phrase down before continuing. It is shown once and then encrypted into the vault.",
        );
        if let Some(error) = self.render_vault_error() {
            card = card.child(error);
        }

        card.child(
            div()
                .w_full()
                .p(px(14.0))
                .rounded_md()
                .border_1()
                .border_color(rgb(theme::BORDER_STRONG))
                .bg(rgb(theme::SURFACE_ELEVATED))
                .text_color(rgb(theme::WARNING))
                .text_size(APP_TEXT_SIZE)
                .line_height(px(21.0))
                .child(SharedString::from(phrase)),
        )
        .child(
            app_button("confirm-generated-wallet", "I saved it, create wallet")
                .primary()
                .w_full()
                .on_click(move |_event, _window, cx| {
                    confirm_root.update(cx, |root, cx| {
                        root.store_generated_wallet(cx);
                    });
                }),
        )
        .child(
            app_button("back-generated-wallet", "Back")
                .ghost()
                .w_full()
                .on_click(move |_event, window, cx| {
                    back_root.update(cx, |root, cx| {
                        root.back_to_wallet_setup_choice(window, cx);
                    });
                }),
        )
    }

    fn render_import_wallet(&self, root: Entity<Self>) -> gpui::Div {
        let import_root = root.clone();
        let back_root = root;
        let mut card = vault_card(
            "Import wallet",
            "Paste the recovery phrase. The phrase is validated, converted to canonical entropy, and cleared from the input.",
        );
        if let Some(error) = self.render_vault_error() {
            card = card.child(error);
        }

        card.child(app_input(&self.import_mnemonic_input))
            .child(
                app_button("store-imported-wallet", "Import wallet")
                    .primary()
                    .w_full()
                    .on_click(move |_event, window, cx| {
                        import_root.update(cx, |root, cx| {
                            root.store_imported_wallet(window, cx);
                        });
                    }),
            )
            .child(
                app_button("back-import-wallet", "Back")
                    .ghost()
                    .w_full()
                    .on_click(move |_event, window, cx| {
                        back_root.update(cx, |root, cx| {
                            root.back_to_wallet_setup_choice(window, cx);
                        });
                    }),
            )
    }

    fn render_vault_fatal(&self, message: &str) -> gpui::Div {
        let mut card = vault_card(
            "Wallet vault unavailable",
            SharedString::from(message.to_owned()),
        );
        if let Some(error) = self.render_vault_error() {
            card = card.child(error);
        }
        card
    }

    fn render_vault_error(&self) -> Option<gpui::AnyElement> {
        self.vault_error.as_ref().map(|message| {
            div()
                .w_full()
                .p(px(10.0))
                .rounded_md()
                .bg(rgb(theme::DANGER_BG))
                .border_1()
                .border_color(rgb(theme::DANGER))
                .text_color(rgb(theme::DANGER))
                .text_size(APP_TEXT_SIZE)
                .child(SharedString::from(message.to_string()))
                .into_any_element()
        })
    }

    fn render_workspace(&self, root: Entity<Self>, window: &Window) -> impl IntoElement {
        if self.logs_open {
            div().size_full().min_w(px(0.0)).min_h(px(0.0)).child(
                v_resizable("wallet-logs-drawer")
                    .with_state(&self.drawer_split)
                    .child(
                        resizable_panel().child(
                            div()
                                .size_full()
                                .min_w(px(0.0))
                                .min_h(px(0.0))
                                .child(self.render_active_content(&root, window)),
                        ),
                    )
                    .child(
                        resizable_panel()
                            .size(LOGS_DRAWER_HEIGHT)
                            .size_range(LOGS_DRAWER_MIN_HEIGHT..LOGS_DRAWER_MAX_HEIGHT)
                            .child(
                                div()
                                    .size_full()
                                    .min_w(px(0.0))
                                    .min_h(px(0.0))
                                    .child(self.render_logs_drawer(root)),
                            ),
                    ),
            )
        } else {
            div()
                .size_full()
                .min_w(px(0.0))
                .min_h(px(0.0))
                .child(self.render_active_content(&root, window))
        }
    }

    fn render_active_content(&self, root: &Entity<Self>, window: &Window) -> gpui::AnyElement {
        match self.active_activity {
            Activity::Wallet => self.render_wallet_view(root, window).into_any_element(),
            Activity::Broadcaster => self.monitor.clone().into_any_element(),
        }
    }

    fn render_wallet_view(&self, root: &Entity<Self>, window: &Window) -> impl IntoElement {
        div()
            .size_full()
            .min_w(px(0.0))
            .min_h(px(0.0))
            .flex()
            .flex_col()
            .bg(rgb(theme::SURFACE_ELEVATED))
            .child(self.render_wallet_header(root))
            .child(self.render_wallet_tabs(root))
            .child(
                div()
                    .flex_1()
                    .min_w(px(0.0))
                    .min_h(px(0.0))
                    .p(px(12.0))
                    .child(self.render_wallet_content(root, window)),
            )
            .children(self.render_sync_status_bar())
    }

    fn render_sync_status_bar(&self) -> Option<gpui::AnyElement> {
        let progress = self
            .chain_states
            .get(&self.selected_chain)
            .filter(|state| state.is_syncing())
            .map(ChainUtxoState::progress)?;
        Some(sync_status_bar(progress).into_any_element())
    }

    fn render_wallet_header(&self, root: &Entity<Self>) -> impl IntoElement {
        let lock_root = root.clone();
        let receive_address = self
            .view_session
            .as_ref()
            .and_then(|session| session.receive_address().ok());

        div()
            .h(px(52.0))
            .flex_none()
            .flex()
            .items_center()
            .gap_3()
            .px(px(14.0))
            .bg(rgb(theme::SURFACE))
            .border_b_1()
            .border_color(rgb(theme::BORDER))
            .child(self.render_wallet_selector(root.clone()))
            .child(self.render_chain_selector(root.clone()))
            .child(div().flex_1())
            .children(receive_address.map(|address| {
                let copy_address = address.clone();
                app_button(
                    "wallet-receive-address",
                    SharedString::from(short_hash(&address)),
                )
                .ghost()
                .xsmall()
                .text_color(rgb(theme::TEAL))
                .tooltip("Copy receive address")
                .on_click(move |_event, window, cx| {
                    copy_with_toast(copy_address.clone(), window, cx);
                })
            }))
            .child(self.render_repair_cache_popover(root.clone()))
            .child(
                app_button_base("wallet-lock-vault")
                    .outline()
                    .xsmall()
                    .px(px(10.0))
                    .py(px(15.0))
                    .tooltip("Lock vault")
                    .child(img(icons::lock_icon_path()).size(px(12.0)).flex_none())
                    .on_click(move |_event, _window, cx| {
                        lock_root.update(cx, |root, cx| {
                            root.lock_vault(cx);
                        });
                    }),
            )
    }

    fn render_repair_cache_popover(&self, root: Entity<Self>) -> impl IntoElement {
        let input = self.repair_cache_block_input.clone();
        let error = self.repair_cache_error.clone();
        let disabled = matches!(
            self.chain_states.get(&self.selected_chain),
            Some(state) if state.is_syncing()
        );

        Popover::new("wallet-repair-cache")
            .trigger(
                app_button_base("wallet-repair-cache-trigger")
                    .outline()
                    .xsmall()
                    .px(px(10.0))
                    .py(px(15.0))
                    .disabled(disabled)
                    .tooltip("Repair wallet cache")
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .child(img(icons::wrench_icon_path()).size(px(12.0)).flex_none()),
                    ),
            )
            .content(move |_state, _window, cx| {
                let popover = cx.entity();
                let submit_root = root.clone();
                let cancel_popover = popover.clone();
                let submit_popover = popover;
                v_flex()
                    .w(px(320.0))
                    .gap_3()
                    .child(app_strong_text("Repair wallet cache"))
                    .child(app_muted_text(
                        "Rewind and rescan this chain's wallet cache. Use 0 for deployment block.",
                    ))
                    .child(app_input(&input))
                    .children(error.as_ref().map(|message| {
                        div()
                            .text_size(APP_TEXT_SIZE)
                            .text_color(rgb(theme::DANGER))
                            .child(SharedString::from(message.to_string()))
                    }))
                    .child(
                        div()
                            .flex()
                            .justify_end()
                            .gap_2()
                            .child(
                                app_button("wallet-repair-cache-cancel", "Cancel")
                                    .ghost()
                                    .small()
                                    .on_click(move |_event, window, cx| {
                                        cancel_popover
                                            .update(cx, |state, cx| state.dismiss(window, cx));
                                    }),
                            )
                            .child(
                                app_button("wallet-repair-cache-submit", "Repair")
                                    .primary()
                                    .small()
                                    .on_click(move |_event, window, cx| {
                                        let submitted = submit_root.update(cx, |root, cx| {
                                            root.repair_wallet_cache_from_input(cx)
                                        });
                                        if submitted {
                                            submit_popover.update(cx, |state, cx| {
                                                state.dismiss(window, cx);
                                            });
                                        }
                                    }),
                            ),
                    )
            })
    }

    fn render_wallet_selector(&self, root: Entity<Self>) -> impl IntoElement {
        let selected_label = self.selected_wallet_label();
        let selected_wallet_id = self.selected_wallet_id.clone();
        let wallet_options = self.wallet_options.clone();

        Popover::new("wallet-selector")
            .trigger(
                app_button_base("wallet-selector-trigger")
                    .ghost()
                    .small()
                    .justify_start()
                    .child(wallet_label_row(selected_label)),
            )
            .content(move |_state, _window, cx| {
                let popover = cx.entity();
                let root = root.clone();
                let selected_wallet_id = selected_wallet_id.clone();
                v_flex()
                    .gap_1()
                    .min_w(px(190.0))
                    .children(wallet_options.clone().into_iter().map(move |option| {
                        let root = root.clone();
                        let popover = popover.clone();
                        let wallet_id = Arc::clone(&option.wallet_id);
                        let is_selected = selected_wallet_id
                            .as_ref()
                            .is_some_and(|selected| selected.as_ref() == option.wallet_id.as_ref());
                        app_button_base(SharedString::from(format!(
                            "wallet-selector-option-{}",
                            option.wallet_id
                        )))
                        .ghost()
                        .small()
                        .w_full()
                        .justify_start()
                        .when(is_selected, |button| {
                            button.bg(rgb(theme::SELECTED_SURFACE))
                        })
                        .child(wallet_label_row(SharedString::from(
                            option.label.to_string(),
                        )))
                        .on_click(move |_event, window, cx| {
                            root.update(cx, |root, cx| {
                                root.select_wallet(Arc::clone(&wallet_id), cx);
                            });
                            popover.update(cx, |state, cx| state.dismiss(window, cx));
                        })
                    }))
            })
    }

    fn render_wallet_tabs(&self, root: &Entity<Self>) -> impl IntoElement {
        div()
            .h(px(40.0))
            .flex_none()
            .flex()
            .items_end()
            .gap_2()
            .px(px(14.0))
            .pt(px(7.0))
            .bg(rgb(theme::SURFACE))
            .children(WalletTab::ALL.into_iter().map(|tab| {
                Self::render_wallet_tab_button(root.clone(), tab, self.active_wallet_tab == tab)
            }))
    }

    fn render_wallet_tab_button(
        root: Entity<Self>,
        tab: WalletTab,
        active: bool,
    ) -> impl IntoElement {
        let label = tab.label();
        div()
            .id(SharedString::from(format!(
                "wallet-tab-{}",
                label.to_ascii_lowercase()
            )))
            .h(px(34.0))
            .min_w(px(92.0))
            .px(px(16.0))
            .flex()
            .items_center()
            .justify_center()
            .gap_2()
            .cursor_pointer()
            .text_size(APP_TEXT_SIZE)
            .rounded_t_md()
            .when(active, |button| {
                button
                    .bg(rgb(theme::SURFACE_ELEVATED))
                    .border_t_1()
                    .border_l_1()
                    .border_r_1()
                    .border_color(rgb(theme::BORDER))
                    .text_color(rgb(theme::TEXT))
                    .font_weight(gpui::FontWeight::SEMIBOLD)
            })
            .when(!active, |button| {
                button.text_color(rgb(theme::TEXT_MUTED)).hover(|button| {
                    button
                        .bg(rgb(theme::SURFACE_HOVER_SUBTLE))
                        .text_color(rgb(theme::TEXT))
                })
            })
            .child(
                img(tab.icon_path())
                    .size(px(18.0))
                    .flex_none()
                    .opacity(if active { 1.0 } else { 0.75 }),
            )
            .child(label)
            .on_click(move |_event, _window, cx| {
                root.update(cx, |root, cx| {
                    root.select_wallet_tab(tab, cx);
                });
            })
    }

    fn render_wallet_content(&self, root: &Entity<Self>, window: &Window) -> gpui::AnyElement {
        match self.active_wallet_tab {
            WalletTab::Private => self.render_private_assets_body(root),
            WalletTab::Public => Self::render_public_wallet_body().into_any_element(),
            WalletTab::Activity => self.render_utxo_body(root, window).into_any_element(),
        }
    }

    fn render_private_assets_body(&self, root: &Entity<Self>) -> gpui::AnyElement {
        match self.chain_states.get(&self.selected_chain) {
            Some(ChainUtxoState::Error(error)) => error_message(error.as_ref()).into_any_element(),
            Some(ChainUtxoState::Loading { progress }) => {
                centered_message(loading_summary(*progress)).into_any_element()
            }
            Some(ChainUtxoState::Syncing {
                snapshot, progress, ..
            }) => self.render_private_asset_snapshot(root, snapshot, false, true, *progress),
            Some(ChainUtxoState::Ready { snapshot, .. }) => {
                self.render_private_asset_snapshot(root, snapshot, true, false, None)
            }
            Some(ChainUtxoState::Idle) | None => {
                centered_message("Select a chain to load private balances").into_any_element()
            }
        }
    }

    fn render_private_asset_snapshot(
        &self,
        root: &Entity<Self>,
        snapshot: &ListUtxosOutput,
        chain_ready: bool,
        syncing: bool,
        progress: Option<SyncProgressUpdate>,
    ) -> gpui::AnyElement {
        let assets = format_private_asset_rows(snapshot.chain_id, &snapshot.totals);
        let asset_keys = assets
            .iter()
            .filter_map(unshield_asset_key_from_formatted)
            .collect::<Vec<_>>();
        let extra_form_keys = self
            .send_forms
            .keys()
            .filter(|key| key.chain_id == snapshot.chain_id && !asset_keys.contains(key))
            .map(|key| (DeliveryFormKind::Send, *key))
            .chain(
                self.unshield_forms
                    .keys()
                    .filter(|key| {
                        key.chain_id == snapshot.chain_id
                            && !asset_keys.contains(key)
                            && !self.send_forms.contains_key(key)
                    })
                    .map(|key| (DeliveryFormKind::Unshield, *key)),
            )
            .collect::<Vec<_>>();
        if assets.is_empty() && extra_form_keys.is_empty() {
            return centered_message(if syncing {
                loading_summary(progress)
            } else {
                "No private assets found".to_string()
            })
            .into_any_element();
        }

        div()
            .size_full()
            .min_w(px(0.0))
            .min_h(px(0.0))
            .overflow_y_scrollbar()
            .child(
                div()
                    .w(PRIVATE_ASSET_LIST_WIDTH)
                    .max_w_full()
                    .mx_auto()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .children(assets.into_iter().enumerate().map(|(ix, asset)| {
                        let send_form_key = send_asset_key_from_formatted(&asset);
                        if let Some(key) = send_form_key
                            && self.send_forms.contains_key(&key)
                        {
                            return self.render_send_form(root.clone(), key).into_any_element();
                        }
                        let form_key = unshield_asset_key_from_formatted(&asset);
                        if let Some(key) = form_key
                            && self.unshield_forms.contains_key(&key)
                        {
                            self.render_unshield_form(root.clone(), key)
                                .into_any_element()
                        } else {
                            Self::render_private_asset_row(
                                root.clone(),
                                ix,
                                asset,
                                snapshot,
                                chain_ready,
                            )
                            .into_any_element()
                        }
                    }))
                    .children(extra_form_keys.into_iter().map(|(kind, key)| {
                        match kind {
                            DeliveryFormKind::Send => {
                                self.render_send_form(root.clone(), key).into_any_element()
                            }
                            DeliveryFormKind::Unshield => self
                                .render_unshield_form(root.clone(), key)
                                .into_any_element(),
                        }
                    })),
            )
            .into_any_element()
    }

    fn render_private_asset_row(
        root: Entity<Self>,
        ix: usize,
        asset: FormattedTokenTotal,
        snapshot: &ListUtxosOutput,
        chain_ready: bool,
    ) -> gpui::Div {
        let send_asset = build_send_asset(snapshot, &asset);
        let can_send = chain_ready && send_asset.is_some();
        let unshield_asset = build_unshield_asset(snapshot, &asset);
        let can_unshield = chain_ready && unshield_asset.is_some();
        let send_tooltip = if can_send {
            "Prepare private send calldata"
        } else if chain_ready {
            "Token cannot be sent from this row"
        } else {
            "Available after wallet sync finishes"
        };
        let unshield_tooltip = if can_unshield {
            "Prepare unshield calldata"
        } else if chain_ready {
            "Token cannot be unshielded from this row"
        } else {
            "Available after wallet sync finishes"
        };
        let send_opacity = if can_send { 1.0 } else { 0.5 };
        let unshield_opacity = if can_unshield { 1.0 } else { 0.5 };
        let show_pending_poi = should_show_pending_poi_amount(asset.pending_poi_total);
        let pending_poi_amount = asset.pending_poi_amount.clone();
        let send_root = root.clone();
        let unshield_root = root;

        div()
            .w_full()
            .flex()
            .items_center()
            .gap_4()
            .p(px(16.0))
            .rounded_lg()
            .bg(rgb(theme::SURFACE))
            .border_1()
            .border_color(rgb(theme::BORDER))
            .child(
                div()
                    .flex_1()
                    .min_w(px(0.0))
                    .flex()
                    .items_center()
                    .text_size(theme::ASSET_SYMBOL_TEXT_SIZE)
                    .text_color(rgb(theme::TEXT))
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .child(private_asset_label_row(
                        SharedString::from(asset.label.clone()),
                        asset.icon_path,
                    )),
            )
            .child(
                div()
                    .min_w(px(150.0))
                    .flex()
                    .flex_col()
                    .items_end()
                    .child(
                        div()
                            .text_color(rgb(theme::WARNING))
                            .text_size(theme::BALANCE_TEXT_SIZE)
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child(SharedString::from(asset.amount)),
                    )
                    .when(show_pending_poi, |column| {
                        column.child(app_muted_text(format!(
                            "*Pending POI: {pending_poi_amount}"
                        )))
                    }),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(
                        app_button(
                            SharedString::from(format!("wallet-asset-send-{ix}")),
                            "Send",
                        )
                        .xsmall()
                        .outline()
                        .p(px(12.0))
                        .disabled(!can_send)
                        .opacity(send_opacity)
                        .tooltip(send_tooltip)
                        .on_click(move |_event, window, cx| {
                            let Some(asset) = send_asset.clone() else {
                                return;
                            };
                            send_root.update(cx, |root, cx| {
                                root.open_send_form(asset, window, cx);
                            });
                        }),
                    )
                    .child(
                        app_button(
                            SharedString::from(format!("wallet-asset-unshield-{ix}")),
                            "Unshield",
                        )
                        .xsmall()
                        .outline()
                        .p(px(12.0))
                        .disabled(!can_unshield)
                        .opacity(unshield_opacity)
                        .tooltip(unshield_tooltip)
                        .on_click(move |_event, window, cx| {
                            let Some(asset) = unshield_asset.clone() else {
                                return;
                            };
                            unshield_root.update(cx, |root, cx| {
                                root.open_unshield_form(asset, window, cx);
                            });
                        }),
                    ),
            )
    }

    fn render_send_form(&self, root: Entity<Self>, key: UnshieldAssetKey) -> gpui::Div {
        let Some(form) = self.send_forms.get(&key) else {
            return div();
        };
        let asset = &form.asset;
        let unit_hint = if asset.decimals.is_some() {
            format!("{} amount", asset.label)
        } else {
            "Raw base units for this unknown token".to_string()
        };
        let description = if form.delivery_mode == DeliveryMode::PublicBroadcaster {
            "Submit a private transfer through a public broadcaster."
        } else {
            "Generate calldata for a private transfer to another 0zk address."
        };

        let delivery_root = root.clone();
        let chooser_root = root.clone();
        let fee_mode_root = root.clone();
        let submit_root = root.clone();
        let cancel_root = root;

        let mut card = div()
            .w_full()
            .flex()
            .flex_col()
            .gap_3()
            .p(px(16.0))
            .rounded_lg()
            .bg(rgb(theme::SURFACE))
            .border_1()
            .border_color(rgb(theme::BORDER_STRONG))
            .child(
                div()
                    .flex()
                    .items_start()
                    .gap_3()
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(0.0))
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(
                                div()
                                    .text_color(rgb(theme::TEXT))
                                    .font_weight(gpui::FontWeight::SEMIBOLD)
                                    .child(private_asset_label_row(
                                        SharedString::from(format!("Send {}", asset.label)),
                                        asset.icon_path.clone(),
                                    )),
                            )
                            .child(app_muted_text(description)),
                    )
                    .child(
                        app_button(send_element_id(key, "cancel"), "Cancel")
                            .ghost()
                            .xsmall()
                            .disabled(form.generating)
                            .on_click(move |_event, _window, cx| {
                                cancel_root.update(cx, |root, cx| {
                                    root.send_forms.remove(&key);
                                    cx.notify();
                                });
                            }),
                    ),
            )
            .child(render_private_action_metrics(
                key,
                DeliveryFormKind::Send,
                form.amount_input.clone(),
                asset,
                form.generating,
            ));

        if asset.total > asset.max_batched {
            card = card.child(
                div()
                    .p(px(10.0))
                    .rounded_md()
                    .bg(rgb(theme::WARNING_BG))
                    .border_1()
                    .border_color(rgb(theme::WARNING))
                    .text_color(rgb(theme::WARNING))
                    .text_size(APP_TEXT_SIZE)
                    .child("Spend capacity is limited by private note fragmentation and POI verification status. One send can spend up to 8 proof chunks."),
            );
        }

        card = card.child(render_delivery_selector(
            delivery_root,
            key,
            DeliveryFormKind::Send,
            form.delivery_mode,
            form.generating,
        ));
        if form.delivery_mode == DeliveryMode::PublicBroadcaster {
            let candidates = eligible_public_broadcasters_for_asset(
                &self.monitor_fee_rows(),
                asset.chain_id,
                asset.token,
                false,
            )
            .unwrap_or_default();
            card = card.child(render_broadcaster_chooser(
                chooser_root,
                key,
                DeliveryFormKind::Send,
                &form.broadcaster_choice,
                candidates,
                form.generating,
            ));
            card = card.child(render_broadcaster_fee_mode_toggle(
                fee_mode_root,
                key,
                DeliveryFormKind::Send,
                form.broadcaster_fee_mode,
                form.generating,
            ));
        }

        card = card
            .child(
                div()
                    .flex()
                    .items_end()
                    .gap_3()
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(0.0))
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(app_muted_text("Recipient 0zk address"))
                            .child(
                                private_action_input(&form.recipient_input)
                                    .disabled(form.generating),
                            ),
                    )
                    .child(
                        div()
                            .w(px(220.0))
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(app_muted_text(unit_hint))
                            .child(
                                private_action_input(&form.amount_input).disabled(form.generating),
                            ),
                    ),
            )
            .child(
                div()
                    .flex()
                    .items_end()
                    .gap_3()
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(0.0))
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(app_muted_text("Vault password"))
                            .child(
                                private_action_input(&form.password_input)
                                    .disabled(form.generating),
                            ),
                    )
                    .child(
                        app_button(
                            send_element_id(key, "generate"),
                            if form.generating {
                                "Preparing..."
                            } else if form.delivery_mode == DeliveryMode::PublicBroadcaster {
                                "Submit via broadcaster"
                            } else {
                                "Generate calldata"
                            },
                        )
                        .primary()
                        .loading(form.generating)
                        .disabled(form.generating)
                        .on_click(move |_event, window, cx| {
                            submit_root.update(cx, |root, cx| {
                                root.generate_send_calldata_from_form(key, window, cx);
                            });
                        }),
                    ),
            );

        if form.delivery_mode == DeliveryMode::PublicBroadcaster {
            if let Some(status) =
                public_broadcaster_cost_status(form.cost_estimate_pending, form.estimating_cost)
            {
                card = card.child(render_public_broadcaster_cost_status(
                    self.unshield_spinner_tick,
                    status,
                ));
            } else if let Some(estimate) = form.cost_estimate.as_ref() {
                card = card.child(render_public_broadcaster_cost_estimate(asset, estimate));
            }
        }

        if form.generating {
            card = card.child(render_unshield_generating_status(
                self.unshield_spinner_tick,
                form.generation_stage,
            ));
        }

        if let Some(error) = form.error.as_ref() {
            card = card.child(
                div()
                    .p(px(10.0))
                    .rounded_md()
                    .bg(rgb(theme::DANGER_BG))
                    .border_1()
                    .border_color(rgb(theme::DANGER))
                    .text_color(rgb(theme::DANGER))
                    .text_size(APP_TEXT_SIZE)
                    .child(SharedString::from(format_form_error_for_asset(
                        error, asset,
                    ))),
            );
        }

        if let Some(result) = form.result.as_ref() {
            card = card.child(match result {
                SendResult::Manual(result) => render_send_result(key, result),
                SendResult::PublicBroadcaster(result) => {
                    render_public_broadcaster_result(key, DeliveryFormKind::Send, result)
                }
            });
        }

        card
    }

    fn render_unshield_form(&self, root: Entity<Self>, key: UnshieldAssetKey) -> gpui::Div {
        let Some(form) = self.unshield_forms.get(&key) else {
            return div();
        };
        let asset = &form.asset;
        let unwrap_supported = is_wrapped_native_token(asset.chain_id, asset.token);
        let unit_hint = if asset.decimals.is_some() {
            format!("{} amount", asset.label)
        } else {
            "Raw base units for this unknown token".to_string()
        };
        let description = if form.delivery_mode == DeliveryMode::PublicBroadcaster {
            "Submit an unshield transaction through a public broadcaster."
        } else {
            "Generate calldata only. This does not submit a public transaction."
        };

        let delivery_root = root.clone();
        let chooser_root = root.clone();
        let fee_mode_root = root.clone();
        let output_root = root.clone();
        let submit_root = root.clone();
        let cancel_root = root;

        let mut card = div()
            .w_full()
            .flex()
            .flex_col()
            .gap_3()
            .p(px(16.0))
            .rounded_lg()
            .bg(rgb(theme::SURFACE))
            .border_1()
            .border_color(rgb(theme::BORDER_STRONG))
            .child(
                div()
                    .flex()
                    .items_start()
                    .gap_3()
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(0.0))
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(
                                div()
                                    .text_color(rgb(theme::TEXT))
                                    .font_weight(gpui::FontWeight::SEMIBOLD)
                                    .child(private_asset_label_row(
                                        SharedString::from(format!("Unshield {}", asset.label)),
                                        asset.icon_path.clone(),
                                    )),
                            )
                            .child(app_muted_text(description)),
                    )
                    .child(
                        app_button(unshield_element_id(key, "cancel"), "Cancel")
                            .ghost()
                            .xsmall()
                            .disabled(form.generating)
                            .on_click(move |_event, _window, cx| {
                                cancel_root.update(cx, |root, cx| {
                                    root.unshield_forms.remove(&key);
                                    cx.notify();
                                });
                            }),
                    ),
            )
            .child(render_private_action_metrics(
                key,
                DeliveryFormKind::Unshield,
                form.amount_input.clone(),
                asset,
                form.generating,
            ));

        if asset.total > asset.max_batched {
            card = card.child(
                div()
                    .p(px(10.0))
                    .rounded_md()
                    .bg(rgb(theme::WARNING_BG))
                    .border_1()
                    .border_color(rgb(theme::WARNING))
                    .text_color(rgb(theme::WARNING))
                    .text_size(APP_TEXT_SIZE)
                    .child("Spend capacity is limited by private note fragmentation and POI verification status. One unshield can spend up to 8 proof chunks."),
            );
        }

        card = card.child(render_delivery_selector(
            delivery_root,
            key,
            DeliveryFormKind::Unshield,
            form.delivery_mode,
            form.generating,
        ));
        if form.delivery_mode == DeliveryMode::PublicBroadcaster {
            let candidates = eligible_public_broadcasters_for_asset(
                &self.monitor_fee_rows(),
                asset.chain_id,
                asset.token,
                form.unwrap,
            )
            .unwrap_or_default();
            card = card.child(render_broadcaster_chooser(
                chooser_root,
                key,
                DeliveryFormKind::Unshield,
                &form.broadcaster_choice,
                candidates,
                form.generating,
            ));
            card = card.child(render_broadcaster_fee_mode_toggle(
                fee_mode_root,
                key,
                DeliveryFormKind::Unshield,
                form.broadcaster_fee_mode,
                form.generating,
            ));
        }

        card = card
            .child(
                div()
                    .flex()
                    .items_end()
                    .gap_3()
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(0.0))
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(app_muted_text("Recipient"))
                            .child(
                                private_action_input(&form.recipient_input)
                                    .disabled(form.generating),
                            ),
                    )
                    .children(unwrap_supported.then(|| {
                        render_unshield_output_toggle(
                            output_root.clone(),
                            key,
                            asset.chain_id,
                            form.unwrap,
                            form.generating,
                        )
                    }))
                    .child(
                        div()
                            .w(px(220.0))
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(app_muted_text(unit_hint))
                            .child(
                                private_action_input(&form.amount_input).disabled(form.generating),
                            ),
                    ),
            )
            .child(
                div()
                    .flex()
                    .items_end()
                    .gap_3()
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(0.0))
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(app_muted_text("Vault password"))
                            .child(
                                private_action_input(&form.password_input)
                                    .disabled(form.generating),
                            ),
                    )
                    .child(
                        app_button(
                            unshield_element_id(key, "generate"),
                            if form.generating {
                                "Preparing..."
                            } else if form.delivery_mode == DeliveryMode::PublicBroadcaster {
                                "Submit via broadcaster"
                            } else {
                                "Generate calldata"
                            },
                        )
                        .primary()
                        .loading(form.generating)
                        .disabled(form.generating)
                        .on_click(move |_event, window, cx| {
                            submit_root.update(cx, |root, cx| {
                                root.generate_unshield_calldata_from_form(key, window, cx);
                            });
                        }),
                    ),
            );

        if form.delivery_mode == DeliveryMode::PublicBroadcaster {
            if let Some(status) =
                public_broadcaster_cost_status(form.cost_estimate_pending, form.estimating_cost)
            {
                card = card.child(render_public_broadcaster_cost_status(
                    self.unshield_spinner_tick,
                    status,
                ));
            } else if let Some(estimate) = form.cost_estimate.as_ref() {
                card = card.child(render_public_broadcaster_cost_estimate(asset, estimate));
            }
        }

        if form.generating {
            card = card.child(render_unshield_generating_status(
                self.unshield_spinner_tick,
                form.generation_stage,
            ));
        }

        if let Some(error) = form.error.as_ref() {
            card = card.child(
                div()
                    .p(px(10.0))
                    .rounded_md()
                    .bg(rgb(theme::DANGER_BG))
                    .border_1()
                    .border_color(rgb(theme::DANGER))
                    .text_color(rgb(theme::DANGER))
                    .text_size(APP_TEXT_SIZE)
                    .child(SharedString::from(format_form_error_for_asset(
                        error, asset,
                    ))),
            );
        }

        if let Some(result) = form.result.as_ref() {
            card = card.child(match result {
                UnshieldResult::Manual(result) => render_unshield_result(key, result),
                UnshieldResult::PublicBroadcaster(result) => {
                    render_public_broadcaster_result(key, DeliveryFormKind::Unshield, result)
                }
            });
        }

        card
    }

    fn render_public_wallet_body() -> gpui::Div {
        div()
            .size_full()
            .flex()
            .items_center()
            .justify_center()
            .child(
                div()
                    .w(px(480.0))
                    .max_w_full()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .p(px(20.0))
                    .rounded_lg()
                    .bg(rgb(theme::SURFACE))
                    .border_1()
                    .border_color(rgb(theme::BORDER))
                    .child(app_strong_text("Public accounts"))
                    .child(
                        app_muted_text(
                            "Public EVM account management, shielding, and related workflows will appear here.",
                        )
                        .line_height(px(18.0)),
                    ),
            )
    }

    fn render_chain_selector(&self, root: Entity<Self>) -> impl IntoElement {
        let selected_chain = self.selected_chain;
        let chain_ids = self.chain_ids.clone();

        Popover::new("wallet-chain-selector")
            .trigger(
                app_button_base("wallet-chain-selector-trigger")
                    .ghost()
                    .small()
                    .justify_start()
                    .child(chain_label_row(selected_chain)),
            )
            .content(move |_state, window, cx| {
                let popover = cx.entity();
                let max_height =
                    (window.viewport_size().height * 0.7).min(FILTER_POPOVER_MAX_HEIGHT);
                let root = root.clone();
                v_flex()
                    .gap_1()
                    .min_w(px(180.0))
                    .max_h(max_height)
                    .overflow_y_scrollbar()
                    .children(chain_ids.clone().into_iter().map(move |chain_id| {
                        let root = root.clone();
                        let popover = popover.clone();
                        app_button_base(SharedString::from(format!("wallet-chain-{chain_id}")))
                            .ghost()
                            .small()
                            .w_full()
                            .justify_start()
                            .child(chain_label_row(chain_id))
                            .on_click(move |_event, window, cx| {
                                root.update(cx, |root, cx| {
                                    root.select_chain(chain_id, cx);
                                });
                                popover.update(cx, |state, cx| state.dismiss(window, cx));
                            })
                    }))
            })
    }

    fn render_utxo_body(&self, root: &Entity<Self>, window: &Window) -> impl IntoElement {
        match self.chain_states.get(&self.selected_chain) {
            Some(ChainUtxoState::Error(error)) => error_message(error.as_ref()),
            Some(ChainUtxoState::Ready { snapshot, .. }) if snapshot.utxo_count == 0 => {
                centered_message("No UTXOs found")
            }
            Some(state) if state.renders_table() => div()
                .size_full()
                .min_w(px(0.0))
                .min_h(px(0.0))
                .flex()
                .flex_col()
                .gap_2()
                .child(self.render_utxo_controls(root.clone()))
                .child(
                    div()
                        .flex_1()
                        .min_w(px(0.0))
                        .min_h(px(0.0))
                        .on_mouse_down(MouseButton::Left, {
                            let table = self.utxo_table.clone();
                            move |_event, window, cx| {
                                table.update(cx, |table, cx| {
                                    table.focus_handle(cx).focus(window);
                                });
                            }
                        })
                        .on_action(window.listener_for(root, Self::on_action_utxo_page_up))
                        .on_action(window.listener_for(root, Self::on_action_utxo_page_down))
                        .on_action(window.listener_for(root, Self::on_action_utxo_home))
                        .on_action(window.listener_for(root, Self::on_action_utxo_end))
                        .child(Table::new(&self.utxo_table)),
                ),
            _ => centered_message("Select a chain to load UTXOs"),
        }
    }

    fn render_utxo_controls(&self, root: Entity<Self>) -> impl IntoElement {
        let spend_root = root.clone();
        let search_active = !self.tx_search_query.is_empty();
        let chain_ready = self
            .chain_states
            .get(&self.selected_chain)
            .is_some_and(ChainUtxoState::is_ready);
        let clear_search_input = self.tx_search_input.clone();
        let clear_search_table = self.utxo_table.clone();
        let search_input = app_input(&self.tx_search_input).when(search_active, |input| {
            input.suffix(
                div()
                    .id("wallet-search-clear")
                    .size(px(18.0))
                    .flex()
                    .items_center()
                    .justify_center()
                    .rounded_sm()
                    .cursor_pointer()
                    .hover(|this| this.bg(rgb(theme::SURFACE_HOVER)))
                    .tooltip(|window, cx| Tooltip::new("Clear search").build(window, cx))
                    .on_click(move |_event, window, cx| {
                        clear_search_input.update(cx, |input, cx| {
                            input.set_value("", window, cx);
                        });
                        clear_search_table.update(cx, |table, cx| {
                            table.focus_handle(cx).focus(window);
                        });
                    })
                    .child(img(icons::close_icon_path()).size(px(12.0)).flex_none()),
            )
        });
        let spent_toggle_label = if self.show_spent_utxos {
            "Hide spent"
        } else {
            "Show spent"
        };
        let spent_toggle = app_button("wallet-toggle-spent-utxos", spent_toggle_label)
            .xsmall()
            .outline()
            .p(px(12.0))
            .disabled(search_active)
            .opacity(if search_active { 0.45 } else { 1.0 })
            .on_click(move |_event, _window, cx| {
                root.update(cx, |root, cx| {
                    root.toggle_spent_visibility(cx);
                });
            });
        let spent_toggle = if self.show_spent_utxos || search_active {
            spent_toggle.ghost()
        } else {
            spent_toggle.primary()
        };

        div()
            .flex_none()
            .flex()
            .items_center()
            .justify_start()
            .gap_2()
            .child(div().w(px(280.0)).child(search_input))
            .child(spent_toggle)
            .child(
                div()
                    .w(px(180.0))
                    .child(app_input(&self.spend_password_input).disabled(!chain_ready)),
            )
            .child(
                app_button("wallet-authorize-spend", "Authorize spend")
                    .xsmall()
                    .outline()
                    .p(px(12.0))
                    .disabled(!chain_ready)
                    .on_click(move |_event, window, cx| {
                        spend_root.update(cx, |root, cx| {
                            root.authorize_spend_from_input(window, cx);
                        });
                    }),
            )
            .children(self.spend_status.as_ref().map(|message| {
                div()
                    .text_size(APP_TEXT_SIZE)
                    .text_color(rgb(theme::SUCCESS))
                    .child(SharedString::from(message.to_string()))
            }))
    }

    fn on_action_utxo_page_up(
        &mut self,
        _: &UtxoPageUp,
        _: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        self.navigate_utxo_table(UtxoNavigation::PageUp, cx);
    }

    fn on_action_utxo_page_down(
        &mut self,
        _: &UtxoPageDown,
        _: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        self.navigate_utxo_table(UtxoNavigation::PageDown, cx);
    }

    fn on_action_utxo_home(&mut self, _: &UtxoHome, _: &mut Window, cx: &mut Context<'_, Self>) {
        self.navigate_utxo_table(UtxoNavigation::Home, cx);
    }

    fn on_action_utxo_end(&mut self, _: &UtxoEnd, _: &mut Window, cx: &mut Context<'_, Self>) {
        self.navigate_utxo_table(UtxoNavigation::End, cx);
    }

    fn on_action_close_broadcaster_picker(
        &mut self,
        _: &CloseBroadcasterPicker,
        _: &mut Window,
        cx: &mut Context<'_, Self>,
    ) {
        if self.broadcaster_picker.is_some() {
            self.close_broadcaster_picker(cx);
        }
    }

    fn navigate_utxo_table(&self, navigation: UtxoNavigation, cx: &mut Context<'_, Self>) {
        if !should_focus_utxo_table(
            self.active_activity,
            self.active_wallet_tab,
            self.chain_states.get(&self.selected_chain),
        ) {
            return;
        }

        self.utxo_table.update(cx, |table, cx| {
            let rows_count = table.delegate().rows_count(cx);
            if rows_count == 0 {
                return;
            }

            let visible_rows = table.visible_range().rows().clone();
            let page_size = visible_rows.len().saturating_sub(1).max(1);
            let last_row = rows_count.saturating_sub(1);
            let selected_row = table.selected_row();
            let target_row = match navigation {
                UtxoNavigation::Home => 0,
                UtxoNavigation::End => last_row,
                UtxoNavigation::PageUp => selected_row
                    .unwrap_or(visible_rows.start)
                    .saturating_sub(page_size),
                UtxoNavigation::PageDown => selected_row
                    .unwrap_or_else(|| visible_rows.end.saturating_sub(1))
                    .saturating_add(page_size)
                    .min(last_row),
            };

            table.set_selected_row(target_row, cx);
        });
    }

    fn render_logs_drawer(&self, root: Entity<Self>) -> impl IntoElement {
        div()
            .size_full()
            .min_w(px(0.0))
            .min_h(px(0.0))
            .flex()
            .flex_col()
            .bg(rgb(theme::SURFACE_ELEVATED))
            .border_t_1()
            .border_color(rgb(theme::BORDER))
            .child(
                div()
                    .h(px(34.0))
                    .flex()
                    .items_center()
                    .px(px(12.0))
                    .bg(rgb(theme::SURFACE))
                    .border_b_1()
                    .border_color(rgb(theme::BORDER))
                    .child(img(icons::logs_icon_path()).size(px(16.0)).flex_none())
                    .child(
                        div()
                            .ml(px(8.0))
                            .text_color(rgb(theme::TEXT))
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child("Logs"),
                    )
                    .child(div().flex_1())
                    .child(
                        div()
                            .id("close-wallet-logs-drawer")
                            .size(px(24.0))
                            .flex()
                            .items_center()
                            .justify_center()
                            .rounded_sm()
                            .cursor_pointer()
                            .text_color(rgb(theme::TEXT_MUTED))
                            .hover(|this| {
                                this.bg(rgb(theme::SURFACE_HOVER))
                                    .text_color(rgb(theme::TEXT))
                            })
                            .tooltip(|window, cx| Tooltip::new("Hide logs").build(window, cx))
                            .on_click(move |_event, _window, cx| {
                                root.update(cx, |root, cx| {
                                    root.logs_open = false;
                                    cx.notify();
                                });
                            })
                            .child(img(icons::close_icon_path()).size(px(14.0)).flex_none()),
                    ),
            )
            .child(
                div()
                    .flex_1()
                    .min_w(px(0.0))
                    .min_h(px(0.0))
                    .child(self.logs.clone()),
            )
    }

    fn render_broadcaster_picker_modal(
        &self,
        root: &Entity<Self>,
        window: &Window,
        cx: &Context<'_, Self>,
    ) -> gpui::Div {
        let Some(picker) = self.broadcaster_picker.as_ref() else {
            return div();
        };
        let Some((asset_label, chain_id, token, unwrap, current_choice, generating)) =
            (match picker.kind {
                DeliveryFormKind::Send => self.send_forms.get(&picker.key).map(|form| {
                    (
                        form.asset.label.clone(),
                        form.asset.chain_id,
                        form.asset.token,
                        false,
                        form.broadcaster_choice.clone(),
                        form.generating,
                    )
                }),
                DeliveryFormKind::Unshield => self.unshield_forms.get(&picker.key).map(|form| {
                    (
                        form.asset.label.clone(),
                        form.asset.chain_id,
                        form.asset.token,
                        form.unwrap,
                        form.broadcaster_choice.clone(),
                        form.generating,
                    )
                }),
            })
        else {
            return div();
        };
        let query = picker
            .query_input
            .read(cx)
            .value()
            .trim()
            .to_ascii_lowercase();
        let chain_label = chain_name(chain_id).map_or_else(|| chain_id.to_string(), str::to_owned);
        let mut candidates = eligible_public_broadcasters_for_asset(
            &self.monitor_fee_rows(),
            chain_id,
            token,
            unwrap,
        )
        .unwrap_or_default();
        match picker.sort {
            BroadcasterPickerSort::FeeAscReliabilityDesc => {
                candidates = sort_specific_public_broadcasters(candidates);
            }
        }
        let total_count = candidates.len();
        let candidates: Vec<_> = candidates
            .into_iter()
            .filter(|candidate| broadcaster_candidate_matches_query(candidate, &query))
            .collect();
        let filtered_count = candidates.len();
        let close_root = root.clone();
        let modal_action_root = root.clone();
        let modal_focus = picker.focus_handle.clone();
        let rows_focus = picker.focus_handle.clone();
        let sort_focus = picker.focus_handle.clone();
        let max_height = (window.viewport_size().height * 0.82).min(BROADCASTER_PICKER_MAX_HEIGHT);

        let mut rows = div()
            .flex_1()
            .min_h(px(0.0))
            .flex()
            .flex_col()
            .gap_2()
            .on_mouse_down(MouseButton::Left, move |_event, window, _cx| {
                rows_focus.focus(window);
            })
            .overflow_y_scrollbar();

        if candidates.is_empty() {
            rows = rows.child(
                div()
                    .p(px(16.0))
                    .rounded_md()
                    .bg(rgb(theme::SURFACE))
                    .border_1()
                    .border_color(rgb(theme::BORDER))
                    .child(app_muted_text(if total_count == 0 {
                        "No eligible broadcaster currently advertises this token."
                    } else {
                        "No broadcasters match this search."
                    })),
            );
        } else {
            for candidate in candidates {
                let candidate_root = root.clone();
                let railgun_address = candidate.railgun_address.clone();
                let selected = matches!(
                    current_choice,
                    BroadcasterChoice::Specific { railgun_address: ref selected } if selected == &railgun_address
                );
                let kind = picker.kind;
                let key = picker.key;
                rows = rows.child(
                    div()
                        .id(delivery_element_id(
                            key,
                            kind,
                            &format!(
                                "modal-{}",
                                stable_broadcaster_element_suffix(&railgun_address)
                            ),
                        ))
                        .w_full()
                        .min_h(px(58.0))
                        .p(px(10.0))
                        .rounded_md()
                        .border_1()
                        .border_color(rgb(if selected {
                            theme::SUCCESS
                        } else {
                            theme::BORDER
                        }))
                        .bg(rgb(if selected {
                            theme::SELECTED_SURFACE
                        } else {
                            theme::SURFACE
                        }))
                        .when(!generating, |row| {
                            row.cursor_pointer()
                                .hover(|row| row.bg(rgb(theme::SURFACE_HOVER)))
                        })
                        .child(render_broadcaster_picker_row(&candidate, selected))
                        .on_click(move |_event, _window, cx| {
                            if generating {
                                return;
                            }
                            candidate_root.update(cx, |root, cx| {
                                root.choose_broadcaster_from_picker(
                                    kind,
                                    key,
                                    railgun_address.clone(),
                                    cx,
                                );
                            });
                        }),
                );
            }
        }

        div()
            .absolute()
            .size_full()
            .flex()
            .items_center()
            .justify_center()
            .p(px(24.0))
            .bg(rgb(theme::BACKGROUND))
            .child(
                div()
                    .w(px(760.0))
                    .max_w_full()
                    .max_h(max_height)
                    .tab_group()
                    .key_context(BROADCASTER_PICKER_KEY_CONTEXT)
                    .track_focus(&modal_focus)
                    .on_action(window.listener_for(
                        &modal_action_root,
                        Self::on_action_close_broadcaster_picker,
                    ))
                    .flex()
                    .flex_col()
                    .gap_3()
                    .p(px(18.0))
                    .rounded_lg()
                    .bg(rgb(theme::SURFACE_ELEVATED))
                    .border_1()
                    .border_color(rgb(theme::BORDER_STRONG))
                    .child(
                        div()
                            .flex()
                            .items_start()
                            .gap_3()
                            .child(
                                div()
                                    .flex_1()
                                    .min_w(px(0.0))
                                    .flex()
                                    .flex_col()
                                    .gap_1()
                                    .child(app_strong_text("Choose public broadcaster"))
                                    .child(app_muted_text(format!(
                                        "{asset_label} on {chain_label}. Specific selection is optional; random remains available."
                                    ))),
                            )
                            .child(
                                app_button("broadcaster-picker-close", "Close")
                                    .ghost()
                                    .xsmall()
                                    .on_click(move |_event, _window, cx| {
                                        close_root.update(cx, |root, cx| {
                                            root.close_broadcaster_picker(cx);
                                        });
                                    }),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .items_end()
                            .gap_3()
                            .child(
                                div()
                                    .flex_1()
                                    .min_w(px(0.0))
                                    .flex()
                                    .flex_col()
                                    .gap_1()
                                    .child(app_muted_text("Search"))
                                    .child(app_input(&picker.query_input).disabled(generating)),
                            )
                            .child(
                                div()
                                    .w(px(210.0))
                                    .flex()
                                    .flex_col()
                                    .gap_1()
                                    .child(app_muted_text("Sort"))
                                    .child(
                                        div()
                                            .p(px(9.0))
                                            .rounded_md()
                                            .bg(rgb(theme::SURFACE))
                                            .border_1()
                                            .border_color(rgb(theme::BORDER))
                                            .on_mouse_down(MouseButton::Left, move |_event, window, _cx| {
                                                sort_focus.focus(window);
                                            })
                                            .text_color(rgb(theme::TEXT_MUTED))
                                            .child("Fee asc, reliability desc"),
                                    ),
                            ),
                    )
                    .child(app_muted_text(format!(
                        "Showing {filtered_count} of {total_count} eligible broadcasters"
                    )))
                    .child(rows),
            )
    }
}

impl Render for WalletRoot {
    fn render(&mut self, window: &mut Window, cx: &mut Context<'_, Self>) -> impl IntoElement {
        self.apply_public_broadcaster_error_amount_adjustments(window, cx);
        self.focus_unlock_password_if_requested(window, cx);
        self.focus_utxo_table_if_requested(window, cx);

        let root = cx.entity();
        if !matches!(self.vault_state, VaultState::ViewUnlocked) {
            return div()
                .relative()
                .size_full()
                .bg(rgb(theme::BACKGROUND))
                .text_color(rgb(theme::TEXT))
                .font_family(APP_FONT_FAMILY)
                .text_size(APP_TEXT_SIZE)
                .child(self.render_vault_gate(root))
                .children(Root::render_notification_layer(window, cx));
        }

        div()
            .relative()
            .size_full()
            .flex()
            .bg(rgb(theme::SURFACE_ELEVATED))
            .text_color(rgb(theme::TEXT))
            .font_family(APP_FONT_FAMILY)
            .text_size(APP_TEXT_SIZE)
            .on_action(window.listener_for(&root, Self::on_action_close_broadcaster_picker))
            .child(self.render_activity_rail(root.clone()))
            .child(
                div()
                    .flex_1()
                    .h_full()
                    .min_w(px(0.0))
                    .min_h(px(0.0))
                    .child(self.render_workspace(root, window)),
            )
            .children(
                self.broadcaster_picker
                    .as_ref()
                    .map(|_| self.render_broadcaster_picker_modal(&cx.entity(), window, cx)),
            )
            .children(Root::render_notification_layer(window, cx))
    }
}

#[derive(Clone)]
struct UtxoDisplayRow {
    tree_position: String,
    token: String,
    token_icon_path: Option<PathBuf>,
    amount: String,
    poi_status: String,
    poi_spendable: bool,
    source_tx_hash: String,
    source_block_timestamp: u64,
    spent_tx_hash: Option<String>,
    token_address: String,
    is_spent: bool,
}

struct UtxoDelegate {
    rows: Arc<[UtxoDisplayRow]>,
    columns: [Column; 7],
    tx_search_input: Entity<InputState>,
}

impl UtxoDelegate {
    fn new(tx_search_input: Entity<InputState>) -> Self {
        Self {
            rows: Arc::from(Vec::<UtxoDisplayRow>::new()),
            columns: [
                Column::new("tree_position", "tree/position")
                    .width(px(120.0))
                    .movable(false),
                Column::new("generated", "generated")
                    .width(px(130.0))
                    .movable(false),
                Column::new("token", "token")
                    .width(px(150.0))
                    .movable(false),
                Column::new("amount", "amount")
                    .width(px(160.0))
                    .movable(false),
                Column::new("poi", "POI").width(px(130.0)).movable(false),
                Column::new("source_tx", "source tx")
                    .width(px(170.0))
                    .movable(false),
                Column::new("spent_tx", "spent tx")
                    .width(px(170.0))
                    .movable(false),
            ],
            tx_search_input,
        }
    }

    fn set_rows(&mut self, rows: Vec<UtxoDisplayRow>) {
        self.rows = Arc::from(rows);
    }
}

impl TableDelegate for UtxoDelegate {
    fn columns_count(&self, _: &App) -> usize {
        self.columns.len()
    }

    fn rows_count(&self, _: &App) -> usize {
        self.rows.len()
    }

    fn column(&self, col_ix: usize, _: &App) -> &Column {
        &self.columns[col_ix]
    }

    fn render_tr(
        &mut self,
        row_ix: usize,
        _window: &mut Window,
        _cx: &mut Context<'_, TableState<Self>>,
    ) -> gpui::Stateful<gpui::Div> {
        let row = div().id(("row", row_ix));
        if self.rows.get(row_ix).is_some_and(|row| row.is_spent) {
            return row.bg(rgb(theme::SPENT_ROW_BG));
        }
        row
    }

    fn render_td(
        &mut self,
        row_ix: usize,
        col_ix: usize,
        _window: &mut Window,
        _cx: &mut Context<'_, TableState<Self>>,
    ) -> impl IntoElement {
        let row = &self.rows[row_ix];
        match col_ix {
            0 => div()
                .text_color(utxo_cell_text_color(row, rgb(theme::TEXT)))
                .child(SharedString::from(row.tree_position.clone()))
                .into_any_element(),
            1 => {
                let tooltip = SharedString::from(local_datetime_label(row.source_block_timestamp));
                div()
                    .id(SharedString::from(format!("wallet-generated-{row_ix}")))
                    .text_color(utxo_cell_text_color(row, rgb(theme::TEXT_MUTED)))
                    .tooltip(move |window, cx| Tooltip::new(tooltip.clone()).build(window, cx))
                    .child(SharedString::from(generated_age_label(
                        row.source_block_timestamp,
                    )))
                    .into_any_element()
            }
            2 => {
                let address = row.token_address.clone();
                div()
                    .id(SharedString::from(format!("wallet-token-cell-{row_ix}")))
                    .cursor_pointer()
                    .font_bold()
                    .text_color(utxo_cell_text_color(row, rgb(theme::TEXT)))
                    .child(token_label_row(
                        SharedString::from(row.token.clone()),
                        row.token_icon_path.clone(),
                        px(14.0),
                    ))
                    .on_click(move |_event, window, cx| {
                        copy_with_toast(address.clone(), window, cx);
                    })
                    .into_any_element()
            }
            3 => div()
                .text_color(utxo_cell_text_color(row, rgb(theme::WARNING)))
                .child(SharedString::from(row.amount.clone()))
                .into_any_element(),
            4 => div()
                .text_color(utxo_cell_text_color(
                    row,
                    if row.poi_spendable {
                        rgb(theme::TEAL)
                    } else {
                        rgb(theme::WARNING)
                    },
                ))
                .child(SharedString::from(row.poi_status.clone()))
                .into_any_element(),
            5 => tx_hash_cell(
                row,
                row_ix,
                "source",
                &row.source_tx_hash,
                rgb(theme::TEAL),
                self.tx_search_input.clone(),
            ),
            _ => match row.spent_tx_hash.as_deref() {
                Some(tx_hash) => tx_hash_cell(
                    row,
                    row_ix,
                    "spent",
                    tx_hash,
                    rgb(theme::DANGER),
                    self.tx_search_input.clone(),
                ),
                None => div()
                    .text_color(rgb(theme::TEXT_SUBTLE))
                    .child("-")
                    .into_any_element(),
            },
        }
    }
}

fn tx_hash_cell(
    row: &UtxoDisplayRow,
    row_ix: usize,
    kind: &'static str,
    tx_hash: &str,
    color: gpui::Rgba,
    tx_search_input: Entity<InputState>,
) -> gpui::AnyElement {
    let display_hash = short_hash(tx_hash);
    let search_hash = tx_hash.to_string();
    let copy_hash = tx_hash.to_string();
    let group = SharedString::from(format!("wallet-{kind}-tx-group-{row_ix}"));

    div()
        .group(group.clone())
        .id(SharedString::from(format!("wallet-{kind}-tx-{row_ix}")))
        .flex()
        .items_center()
        .gap_1()
        .child(
            div()
                .id(SharedString::from(format!(
                    "wallet-{kind}-tx-copy-{row_ix}"
                )))
                .cursor_pointer()
                .text_color(utxo_cell_text_color(row, color))
                .child(SharedString::from(display_hash))
                .on_click(move |_event, window, cx| {
                    copy_with_toast(copy_hash.clone(), window, cx);
                }),
        )
        .child(
            div()
                .id(SharedString::from(format!(
                    "wallet-{kind}-tx-search-{row_ix}"
                )))
                .size(px(16.0))
                .flex()
                .items_center()
                .justify_center()
                .rounded_sm()
                .cursor_pointer()
                .opacity(0.0)
                .group_hover(group, |this| this.opacity(1.0))
                .hover(|this| this.bg(rgb(theme::SURFACE_HOVER)))
                .tooltip(|window, cx| Tooltip::new("Filter by this transaction").build(window, cx))
                .on_click(move |_event, window, cx| {
                    tx_search_input.update(cx, |input, cx| {
                        input.set_value(search_hash.clone(), window, cx);
                    });
                })
                .child(img(icons::search_icon_path()).size(px(10.0)).flex_none()),
        )
        .into_any_element()
}

fn utxo_cell_text_color(row: &UtxoDisplayRow, color: gpui::Rgba) -> gpui::Rgba {
    if row.is_spent {
        rgb(theme::SPENT_TEXT)
    } else {
        color
    }
}

fn should_focus_utxo_table(
    active_activity: Activity,
    active_wallet_tab: WalletTab,
    state: Option<&ChainUtxoState>,
) -> bool {
    active_activity == Activity::Wallet
        && active_wallet_tab.shows_utxos()
        && state.is_some_and(ChainUtxoState::renders_table)
}

fn centered_message(message: impl Into<SharedString>) -> gpui::Div {
    let message = message.into();
    div()
        .size_full()
        .flex()
        .items_center()
        .justify_center()
        .text_color(rgb(theme::TEXT_SUBTLE))
        .child(message)
}

fn private_action_input(state: &Entity<InputState>) -> Input {
    Input::new(state).px(px(12.0)).py(px(8.0))
}

fn vault_card(title: &'static str, subtitle: impl Into<SharedString>) -> gpui::Div {
    let subtitle = subtitle.into();
    div()
        .w(px(500.0))
        .max_w_full()
        .flex()
        .flex_col()
        .gap_3()
        .p(px(22.0))
        .rounded_lg()
        .bg(rgb(theme::SURFACE))
        .border_1()
        .border_color(rgb(theme::BORDER))
        .child(app_strong_text(title))
        .child(app_muted_text(subtitle).line_height(px(18.0)))
}

fn loading_summary(progress: Option<SyncProgressUpdate>) -> String {
    progress.map_or_else(
        || "Preparing wallet sync...".to_string(),
        |progress| format!("{} · {}%", progress.stage.label(), progress.percent()),
    )
}

fn sync_status_bar(progress: Option<SyncProgressUpdate>) -> gpui::Div {
    let title = progress.map_or("Preparing wallet sync", |progress| progress.stage.label());
    let percent = progress.map_or(0, SyncProgressUpdate::percent);
    let detail = progress.map_or_else(
        || "Waiting for indexed sync progress...".to_string(),
        progress_detail,
    );
    let fill_width = relative(f32::from(percent) / 100.0);

    div()
        .h(px(36.0))
        .flex_none()
        .flex()
        .items_center()
        .gap_3()
        .px(px(12.0))
        .bg(rgb(theme::SURFACE))
        .border_t_1()
        .border_color(rgb(theme::BORDER))
        .child(
            div()
                .min_w(px(170.0))
                .text_color(rgb(theme::TEXT))
                .font_weight(gpui::FontWeight::SEMIBOLD)
                .child(title),
        )
        .child(
            div()
                .w(px(190.0))
                .h(px(6.0))
                .rounded_md()
                .overflow_hidden()
                .bg(rgb(theme::SURFACE_HOVER))
                .child(
                    div()
                        .h_full()
                        .w(fill_width)
                        .rounded_md()
                        .bg(rgb(theme::INFO)),
                ),
        )
        .child(
            div()
                .w(px(42.0))
                .text_color(rgb(theme::INFO))
                .font_weight(gpui::FontWeight::SEMIBOLD)
                .child(SharedString::from(format!("{percent}%"))),
        )
        .child(
            div()
                .flex_1()
                .min_w(px(0.0))
                .text_color(rgb(theme::TEXT_MUTED))
                .text_size(APP_TEXT_SIZE)
                .child(SharedString::from(detail)),
        )
}

fn progress_detail(progress: SyncProgressUpdate) -> String {
    let current = progress
        .current_block
        .max(progress.start_block)
        .min(progress.target_block);
    format!("Block {current} of {}", progress.target_block)
}

fn error_message(message: &str) -> gpui::Div {
    div()
        .size_full()
        .flex()
        .items_center()
        .justify_center()
        .text_color(rgb(theme::DANGER))
        .child(SharedString::from(message.to_owned()))
}

fn chain_label_row(chain_id: u64) -> impl IntoElement {
    let label = chain_name(chain_id).map_or_else(|| chain_id.to_string(), str::to_owned);
    let mut row = div()
        .flex()
        .items_center()
        .gap_2()
        .text_color(rgb(theme::TEXT))
        .text_size(APP_TEXT_SIZE);
    if let Some(path) = chain_icon_path(chain_id) {
        row = row.child(img(path).size(px(16.0)).flex_none());
    }
    row.child(SharedString::from(label))
}

fn wallet_label_row(label: SharedString) -> impl IntoElement {
    div()
        .flex()
        .items_center()
        .gap_2()
        .text_color(rgb(theme::TEXT))
        .text_size(APP_TEXT_SIZE)
        .child(img(icons::wallet_icon_path()).size(px(16.0)).flex_none())
        .child(label)
}

fn token_label_row(
    label: SharedString,
    icon_path: Option<PathBuf>,
    icon_size: Pixels,
) -> gpui::Div {
    let mut row = div().flex().items_center().gap_1();
    if let Some(path) = icon_path {
        row = row.child(img(path).size(icon_size).rounded_full().flex_none());
    }
    row.child(label)
}

fn private_asset_label_row(label: SharedString, icon_path: Option<PathBuf>) -> gpui::Div {
    let mut row = div().flex().items_center().gap_2();
    if let Some(path) = icon_path {
        row = row.child(img(path).size(px(32.0)).rounded_full().flex_none());
    }
    row.child(label)
}

#[derive(Clone)]
struct FormattedTokenTotal {
    chain_id: u64,
    token: Option<Address>,
    label: String,
    amount: String,
    pending_poi_amount: String,
    total: Option<U256>,
    poi_verified_total: Option<U256>,
    pending_poi_total: Option<U256>,
    decimals: Option<u8>,
    icon_path: Option<PathBuf>,
}

fn format_private_asset_rows(chain_id: u64, totals: &[TokenTotal]) -> Vec<FormattedTokenTotal> {
    totals
        .iter()
        .map(|total| format_total_parts(chain_id, total))
        .collect()
}

#[cfg(test)]
fn format_total(chain_id: u64, total: &TokenTotal) -> String {
    let formatted = format_total_parts(chain_id, total);
    format!("{} {}", formatted.label, formatted.amount)
}

fn format_total_parts(chain_id: u64, total: &TokenTotal) -> FormattedTokenTotal {
    let total_raw = U256::from_str_radix(&total.total, 10).ok();
    let poi_verified_total_raw = U256::from_str_radix(&total.poi_verified_total, 10).ok();
    let pending_poi_total = pending_poi_total(total_raw, poi_verified_total_raw);
    let Some(address) = parse_address(&total.token) else {
        return FormattedTokenTotal {
            chain_id,
            token: None,
            label: total.token.clone(),
            amount: total.total.clone(),
            pending_poi_amount: format_pending_poi_amount(pending_poi_total, None),
            total: total_raw,
            poi_verified_total: poi_verified_total_raw,
            pending_poi_total,
            decimals: None,
            icon_path: None,
        };
    };
    let Some(token) = lookup_token(chain_id, &address) else {
        return FormattedTokenTotal {
            chain_id,
            token: Some(address),
            label: short_address(&address),
            amount: total.total.clone(),
            pending_poi_amount: format_pending_poi_amount(pending_poi_total, None),
            total: total_raw,
            poi_verified_total: poi_verified_total_raw,
            pending_poi_total,
            decimals: None,
            icon_path: None,
        };
    };
    let amount = total_raw.map_or_else(
        || total.total.clone(),
        |value| format_token_amount(value, token.decimals),
    );
    FormattedTokenTotal {
        chain_id,
        token: Some(address),
        label: token.symbol.to_owned(),
        amount,
        pending_poi_amount: format_pending_poi_amount(pending_poi_total, Some(token.decimals)),
        total: total_raw,
        poi_verified_total: poi_verified_total_raw,
        pending_poi_total,
        decimals: Some(token.decimals),
        icon_path: token_icon_path(chain_id, &address),
    }
}

fn pending_poi_total(total: Option<U256>, poi_verified_total: Option<U256>) -> Option<U256> {
    total
        .zip(poi_verified_total)
        .map(|(total, poi_verified_total)| total.saturating_sub(poi_verified_total))
}

fn format_pending_poi_amount(pending_poi_total: Option<U256>, decimals: Option<u8>) -> String {
    pending_poi_total.as_ref().map_or_else(
        || "0".to_string(),
        |value| {
            if let Some(decimals) = decimals {
                format_token_amount(*value, decimals)
            } else {
                value.to_string()
            }
        },
    )
}

fn should_show_pending_poi_amount(pending_poi_total: Option<U256>) -> bool {
    pending_poi_total.is_some_and(|amount| !amount.is_zero())
}

fn build_unshield_asset(
    snapshot: &ListUtxosOutput,
    asset: &FormattedTokenTotal,
) -> Option<UnshieldAsset> {
    let token = asset.token?;
    let total = asset.total?;
    let poi_verified_total = asset.poi_verified_total?;
    let max_batched = max_unshield_amount_from_snapshot(snapshot, token);
    if max_batched.is_zero() {
        return None;
    }
    Some(UnshieldAsset {
        chain_id: asset.chain_id,
        token,
        label: asset.label.clone(),
        decimals: asset.decimals,
        total,
        poi_verified_total,
        max_batched,
        icon_path: asset.icon_path.clone(),
    })
}

fn build_send_asset(
    snapshot: &ListUtxosOutput,
    asset: &FormattedTokenTotal,
) -> Option<UnshieldAsset> {
    let token = asset.token?;
    let total = asset.total?;
    let poi_verified_total = asset.poi_verified_total?;
    let max_batched = max_send_amount_from_snapshot(snapshot, token);
    if max_batched.is_zero() {
        return None;
    }
    Some(UnshieldAsset {
        chain_id: asset.chain_id,
        token,
        label: asset.label.clone(),
        decimals: asset.decimals,
        total,
        poi_verified_total,
        max_batched,
        icon_path: asset.icon_path.clone(),
    })
}

fn refresh_form_asset_from_snapshot(
    snapshot: &ListUtxosOutput,
    current: &UnshieldAsset,
    send: bool,
) -> UnshieldAsset {
    let formatted = format_private_asset_rows(snapshot.chain_id, &snapshot.totals)
        .into_iter()
        .find(|asset| asset.token == Some(current.token));
    let total = formatted
        .as_ref()
        .and_then(|asset| asset.total)
        .unwrap_or_default();
    let poi_verified_total = formatted
        .as_ref()
        .and_then(|asset| asset.poi_verified_total)
        .unwrap_or_default();
    let max_batched = if send {
        max_send_amount_from_snapshot(snapshot, current.token)
    } else {
        max_unshield_amount_from_snapshot(snapshot, current.token)
    };

    UnshieldAsset {
        chain_id: current.chain_id,
        token: current.token,
        label: formatted
            .as_ref()
            .map_or_else(|| current.label.clone(), |asset| asset.label.clone()),
        decimals: formatted
            .as_ref()
            .and_then(|asset| asset.decimals)
            .or(current.decimals),
        total,
        poi_verified_total,
        max_batched,
        icon_path: formatted
            .as_ref()
            .and_then(|asset| asset.icon_path.clone())
            .or_else(|| current.icon_path.clone()),
    }
}

fn send_asset_key_from_formatted(asset: &FormattedTokenTotal) -> Option<UnshieldAssetKey> {
    unshield_asset_key_from_formatted(asset)
}

#[cfg(test)]
fn send_key_matches_asset(key: UnshieldAssetKey, asset: &FormattedTokenTotal) -> bool {
    send_asset_key_from_formatted(asset) == Some(key)
}

fn send_element_id(key: UnshieldAssetKey, action: &str) -> SharedString {
    SharedString::from(format!(
        "wallet-send-{}-{}-{action}",
        key.chain_id,
        key.token.to_checksum(None)
    ))
}

fn unshield_asset_key_from_formatted(asset: &FormattedTokenTotal) -> Option<UnshieldAssetKey> {
    asset
        .token
        .map(|token| UnshieldAssetKey::new(asset.chain_id, token))
}

#[cfg(test)]
fn unshield_key_matches_asset(key: UnshieldAssetKey, asset: &FormattedTokenTotal) -> bool {
    unshield_asset_key_from_formatted(asset) == Some(key)
}

fn unshield_element_id(key: UnshieldAssetKey, action: &str) -> SharedString {
    SharedString::from(format!(
        "wallet-unshield-{}-{}-{action}",
        key.chain_id,
        key.token.to_checksum(None)
    ))
}

fn delivery_element_id(
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    action: &str,
) -> SharedString {
    match kind {
        DeliveryFormKind::Send => send_element_id(key, action),
        DeliveryFormKind::Unshield => unshield_element_id(key, action),
    }
}

fn selected_broadcaster_label(
    choice: &BroadcasterChoice,
    candidates: &[PublicBroadcasterCandidate],
) -> String {
    let BroadcasterChoice::Specific { railgun_address } = choice else {
        return "Choose specific broadcaster".to_string();
    };
    candidates
        .iter()
        .find(|candidate| candidate.railgun_address == *railgun_address)
        .map_or_else(
            || "Specific broadcaster unavailable".to_string(),
            |candidate| {
                format!(
                    "{} · fee {} · rel {:.0}%",
                    broadcaster_candidate_label(candidate),
                    broadcaster_candidate_fee_label(candidate),
                    candidate.reliability * 100.0
                )
            },
        )
}

const fn stable_broadcaster_element_suffix(railgun_address: &str) -> &str {
    railgun_address
}

fn broadcaster_candidate_label(candidate: &PublicBroadcasterCandidate) -> String {
    format_broadcaster_address_label(&candidate.railgun_address, candidate.identifier.as_deref())
}

fn broadcaster_candidate_fee_label(candidate: &PublicBroadcasterCandidate) -> String {
    lookup_token(candidate.chain_id, &candidate.token).map_or_else(
        || candidate.fee.to_string(),
        |info| format_token_amount(candidate.fee, info.decimals),
    )
}

fn format_exact_candidate_token_amount(
    candidate: &PublicBroadcasterCandidate,
    amount: U256,
) -> String {
    lookup_token(candidate.chain_id, &candidate.token).map_or_else(
        || format!("{amount} raw token units"),
        |info| {
            format!(
                "{} {}",
                format_send_amount_input(amount, Some(info.decimals)),
                info.symbol
            )
        },
    )
}

fn format_exact_asset_amount_for_display(amount: U256, asset: &UnshieldAsset) -> String {
    asset.decimals.map_or_else(
        || format!("{amount} raw token units"),
        |decimals| {
            format!(
                "{} {}",
                format_send_amount_input(amount, Some(decimals)),
                asset.label
            )
        },
    )
}

fn should_show_distinct_amount(entered_amount: U256, amount: U256) -> bool {
    amount != entered_amount
}

fn public_broadcaster_max_entered_amount_for_mode(
    max_receiver_amount: U256,
    fee_amount: U256,
    fee_mode: PublicBroadcasterFeeMode,
) -> U256 {
    match fee_mode {
        PublicBroadcasterFeeMode::DeductFromAmount => max_receiver_amount + fee_amount,
        PublicBroadcasterFeeMode::AddToAmount => max_receiver_amount,
    }
}

fn cost_estimate_max_entered_amount_for_mode(
    estimate: &PublicBroadcasterCostEstimate,
    fee_mode: PublicBroadcasterFeeMode,
) -> U256 {
    public_broadcaster_max_entered_amount_for_mode(
        estimate.max_receiver_amount,
        estimate.fee_amount,
        fee_mode,
    )
}

fn send_form_max_entered_amount(
    form: &SendFormState,
    delivery_mode: DeliveryMode,
    fee_mode: PublicBroadcasterFeeMode,
) -> Option<U256> {
    match delivery_mode {
        DeliveryMode::ManualCalldata => Some(form.asset.max_batched),
        DeliveryMode::PublicBroadcaster => form
            .cost_estimate
            .as_ref()
            .map(|estimate| cost_estimate_max_entered_amount_for_mode(estimate, fee_mode)),
        DeliveryMode::SelfBroadcast => None,
    }
}

fn unshield_form_max_entered_amount(
    form: &UnshieldFormState,
    delivery_mode: DeliveryMode,
    fee_mode: PublicBroadcasterFeeMode,
) -> Option<U256> {
    match delivery_mode {
        DeliveryMode::ManualCalldata => Some(form.asset.max_batched),
        DeliveryMode::PublicBroadcaster => form
            .cost_estimate
            .as_ref()
            .map(|estimate| cost_estimate_max_entered_amount_for_mode(estimate, fee_mode)),
        DeliveryMode::SelfBroadcast => None,
    }
}

fn adjusted_amount_for_max_change(
    current_amount: U256,
    old_max: Option<U256>,
    new_max: U256,
) -> Option<U256> {
    if current_amount > new_max {
        return Some(new_max);
    }
    if let Some(old_max) = old_max
        && current_amount == old_max
        && new_max > old_max
    {
        return Some(new_max);
    }
    None
}

fn apply_amount_adjustment_for_max_change(
    input: &Entity<InputState>,
    asset: &UnshieldAsset,
    old_max: Option<U256>,
    new_max: Option<U256>,
    window: &mut Window,
    cx: &mut Context<'_, WalletRoot>,
) -> bool {
    let Some(new_max) = new_max else {
        return false;
    };
    let current_value = input.read(cx).value().to_string();
    let Ok(current_amount) = parse_send_amount(current_value.as_str(), asset.decimals) else {
        return false;
    };
    let Some(adjusted_amount) = adjusted_amount_for_max_change(current_amount, old_max, new_max)
    else {
        return false;
    };
    let adjusted = format_send_amount_input(adjusted_amount, asset.decimals);
    input.update(cx, |input, cx| input.set_value(adjusted, window, cx));
    true
}

fn format_form_error_for_asset(error: &str, asset: &UnshieldAsset) -> String {
    if let Some(max_spendable) = form_error_public_broadcaster_max_entered_amount(error) {
        return format!(
            "Max POI-verified entered amount for public broadcaster: {}. Try a smaller amount or switch fee mode.",
            format_exact_asset_amount_for_display(max_spendable, asset)
        );
    }

    if let Some(max_spendable) = form_error_max_immediately_spendable(error) {
        return format!(
            "Amount exceeds max POI-verified amount for public broadcaster: {}. Try a smaller amount or switch fee mode.",
            format_exact_asset_amount_for_display(max_spendable, asset)
        );
    }

    match error {
        "entered amount must be greater than the broadcaster fee" => format!(
            "Entered amount must be greater than the broadcaster fee for {}. Choose add fee on top or enter a larger amount.",
            asset.label
        ),
        _ => error.to_string(),
    }
}

fn form_error_public_broadcaster_max_entered_amount(error: &str) -> Option<U256> {
    const MARKER: &str = "public broadcaster max entered amount: ";
    form_error_decimal_after_marker(error, MARKER)
}

fn form_error_max_immediately_spendable(error: &str) -> Option<U256> {
    const MARKER: &str = "max immediately spendable: ";
    form_error_decimal_after_marker(error, MARKER)
}

fn form_error_decimal_after_marker(error: &str, marker: &str) -> Option<U256> {
    let start = error.find(marker)? + marker.len();
    let digits = error[start..]
        .trim_start()
        .split(|ch: char| !ch.is_ascii_digit())
        .next()?;
    if digits.is_empty() {
        return None;
    }
    U256::from_str_radix(digits, 10).ok()
}

fn format_gwei(wei: u128) -> String {
    format_token_amount(U256::from(wei), 9)
}

fn public_broadcaster_fee_mode_summary(
    fee_mode: PublicBroadcasterFeeMode,
    entered_amount: U256,
    receiver_amount: U256,
    protocol_fee_amount: U256,
    broadcaster: &PublicBroadcasterCandidate,
) -> String {
    match fee_mode {
        PublicBroadcasterFeeMode::AddToAmount => {
            if protocol_fee_amount.is_zero() {
                "Recipient receives the full entered amount; broadcaster fee is added to spend."
                    .to_string()
            } else {
                format!(
                    "Recipient receives the entered amount minus {} RAILGUN protocol fee; broadcaster fee is added to spend.",
                    format_exact_candidate_token_amount(broadcaster, protocol_fee_amount)
                )
            }
        }
        PublicBroadcasterFeeMode::DeductFromAmount => {
            let reduction = entered_amount.saturating_sub(receiver_amount);
            if reduction.is_zero() && protocol_fee_amount.is_zero() {
                "Recipient receives the entered amount because the broadcaster fee is zero."
                    .to_string()
            } else if protocol_fee_amount.is_zero() {
                format!(
                    "Recipient amount is reduced by {} because broadcaster fee is paid from the entered amount.",
                    format_exact_candidate_token_amount(broadcaster, reduction)
                )
            } else if reduction.is_zero() {
                format!(
                    "Recipient amount is reduced by {} RAILGUN protocol fee.",
                    format_exact_candidate_token_amount(broadcaster, protocol_fee_amount)
                )
            } else {
                format!(
                    "Recipient amount is reduced by {} broadcaster fee and {} RAILGUN protocol fee.",
                    format_exact_candidate_token_amount(broadcaster, reduction),
                    format_exact_candidate_token_amount(broadcaster, protocol_fee_amount)
                )
            }
        }
    }
}

fn broadcaster_candidate_matches_query(
    candidate: &PublicBroadcasterCandidate,
    query: &str,
) -> bool {
    if query.is_empty() {
        return true;
    }
    candidate
        .railgun_address
        .to_ascii_lowercase()
        .contains(query)
        || candidate.fees_id.to_ascii_lowercase().contains(query)
        || candidate
            .identifier
            .as_deref()
            .is_some_and(|identifier| identifier.to_ascii_lowercase().contains(query))
        || candidate.version.to_ascii_lowercase().contains(query)
        || candidate
            .token
            .to_checksum(None)
            .to_ascii_lowercase()
            .contains(query)
}

fn render_broadcaster_picker_row(
    candidate: &PublicBroadcasterCandidate,
    selected: bool,
) -> gpui::Div {
    let poi_hint = if candidate.required_poi_list_keys.is_empty() {
        ""
    } else {
        " · requires POI"
    };
    div()
        .w_full()
        .flex()
        .items_center()
        .gap_3()
        .child(
            div()
                .flex_1()
                .min_w(px(0.0))
                .flex()
                .flex_col()
                .gap_1()
                .child(
                    div()
                        .text_color(rgb(theme::TEXT))
                        .font_weight(gpui::FontWeight::SEMIBOLD)
                        .child(broadcaster_candidate_label(candidate)),
                )
                .child(app_muted_text(format!(
                    "fee {} · reliability {:.0}% · wallets {} · v{}{}",
                    broadcaster_candidate_fee_label(candidate),
                    candidate.reliability * 100.0,
                    candidate.available_wallets,
                    candidate.version,
                    poi_hint
                ))),
        )
        .child(
            div()
                .w(px(92.0))
                .flex_none()
                .flex()
                .justify_end()
                .text_color(rgb(if selected {
                    theme::SUCCESS
                } else {
                    theme::TEXT_MUTED
                }))
                .child(if selected { "Selected" } else { "Use" }),
        )
}

fn max_unshield_amount_from_snapshot(snapshot: &ListUtxosOutput, token: Address) -> U256 {
    planner_max_unshield_amount_from_outputs(&snapshot.utxos, token)
}

fn max_send_amount_from_snapshot(snapshot: &ListUtxosOutput, token: Address) -> U256 {
    planner_max_send_amount_from_outputs(&snapshot.utxos, token)
}

fn format_unshield_amount_input(amount: U256, decimals: Option<u8>) -> String {
    let Some(decimals) = decimals else {
        return amount.to_string();
    };
    if decimals == 0 {
        return amount.to_string();
    }

    let divisor = U256::from(10_u8).pow(U256::from(decimals));
    let whole = amount / divisor;
    let fractional = amount % divisor;
    if fractional.is_zero() {
        return whole.to_string();
    }

    let fractional = fractional.to_string();
    let padded = format!("{fractional:0>width$}", width = decimals as usize);
    format!("{whole}.{}", padded.trim_end_matches('0'))
}

fn format_send_amount_input(amount: U256, decimals: Option<u8>) -> String {
    format_unshield_amount_input(amount, decimals)
}

fn private_action_metrics(asset: &UnshieldAsset) -> Vec<PrivateActionMetric> {
    let mut metrics = vec![PrivateActionMetric {
        label: "Total private balance",
        amount: asset.total,
    }];
    if asset.poi_verified_total != asset.total {
        metrics.push(PrivateActionMetric {
            label: "POI-verified balance",
            amount: asset.poi_verified_total,
        });
    }
    if asset.max_batched != asset.total {
        metrics.push(PrivateActionMetric {
            label: "Max batched transaction",
            amount: asset.max_batched,
        });
    }
    metrics
}

fn render_private_action_metrics(
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    amount_input: Entity<InputState>,
    asset: &UnshieldAsset,
    disabled: bool,
) -> gpui::Div {
    let decimals = asset.decimals;
    div()
        .flex()
        .flex_wrap()
        .gap_2()
        .children(
            private_action_metrics(asset)
                .into_iter()
                .map(move |metric| {
                    render_private_action_metric(
                        amount_input.clone(),
                        delivery_element_id(
                            key,
                            kind,
                            private_action_metric_id_suffix(metric.label),
                        ),
                        metric,
                        decimals,
                        disabled,
                    )
                }),
        )
}

fn render_private_action_metric(
    amount_input: Entity<InputState>,
    id: SharedString,
    metric: PrivateActionMetric,
    decimals: Option<u8>,
    disabled: bool,
) -> impl IntoElement {
    let value = format_unshield_amount_input(metric.amount, decimals);
    let click_value = value.clone();
    div()
        .id(id)
        .flex_none()
        .px(px(12.0))
        .py(px(10.0))
        .rounded_md()
        .bg(rgb(theme::SURFACE_ELEVATED))
        .border_1()
        .border_color(rgb(theme::BORDER))
        .flex()
        .items_center()
        .gap_2()
        .when(!disabled, |this| {
            this.cursor_pointer()
                .hover(|this| this.bg(rgb(theme::SURFACE_HOVER)))
                .on_click(move |_event, window, cx| {
                    let value = click_value.clone();
                    amount_input.update(cx, |input, cx| {
                        input.set_value(value, window, cx);
                    });
                })
        })
        .child(app_muted_text(metric.label))
        .child(
            div()
                .text_color(rgb(theme::WARNING))
                .font_weight(gpui::FontWeight::SEMIBOLD)
                .child(SharedString::from(value)),
        )
}

fn private_action_metric_id_suffix(label: &'static str) -> &'static str {
    match label {
        "Total private balance" => "metric-total",
        "POI-verified balance" => "metric-poi-verified",
        "Max batched transaction" => "metric-max-batched",
        _ => "metric",
    }
}

fn render_unshield_generating_status(tick: usize, stage: TransactionGenerationStage) -> gpui::Div {
    div()
        .flex()
        .items_center()
        .gap_3()
        .p(px(10.0))
        .rounded_md()
        .bg(rgb(theme::SURFACE_ELEVATED))
        .border_1()
        .border_color(rgb(theme::INFO))
        .child(
            div()
                .size(px(22.0))
                .flex()
                .items_center()
                .justify_center()
                .rounded_full()
                .bg(rgb(theme::BACKGROUND))
                .text_color(rgb(theme::INFO))
                .font_weight(gpui::FontWeight::SEMIBOLD)
                .child(unshield_spinner_frame(tick)),
        )
        .child(
            div()
                .flex()
                .flex_col()
                .gap_1()
                .child(
                    div()
                        .text_color(rgb(theme::TEXT))
                        .font_weight(gpui::FontWeight::SEMIBOLD)
                        .child(stage.label()),
                )
                .child(app_muted_text(stage.detail())),
        )
}

const fn unshield_spinner_frame(tick: usize) -> &'static str {
    const FRAMES: [&str; 4] = ["|", "/", "-", "\\"];
    FRAMES[tick % FRAMES.len()]
}

#[cfg(test)]
const fn send_spinner_frame(tick: usize) -> &'static str {
    unshield_spinner_frame(tick)
}

fn render_delivery_selector(
    root: Entity<WalletRoot>,
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    mode: DeliveryMode,
    generating: bool,
) -> gpui::Div {
    let manual_root = root.clone();
    let public_root = root;
    div()
        .flex()
        .flex_col()
        .gap_2()
        .child(app_muted_text("Delivery mode"))
        .child(
            div()
                .flex()
                .flex_wrap()
                .gap_2()
                .child(
                    app_button(delivery_element_id(key, kind, "manual"), "Manual calldata")
                        .xsmall()
                        .outline()
                        .p(px(12.0))
                        .when(mode == DeliveryMode::ManualCalldata, |button| {
                            button.primary()
                        })
                        .disabled(generating)
                        .on_click(move |_event, window, cx| {
                            manual_root.update(cx, |root, cx| match kind {
                                DeliveryFormKind::Send => root.set_send_delivery_mode(
                                    key,
                                    DeliveryMode::ManualCalldata,
                                    window,
                                    cx,
                                ),
                                DeliveryFormKind::Unshield => root.set_unshield_delivery_mode(
                                    key,
                                    DeliveryMode::ManualCalldata,
                                    window,
                                    cx,
                                ),
                            });
                        }),
                )
                .child(
                    app_button(
                        delivery_element_id(key, kind, "public"),
                        "Public broadcaster",
                    )
                    .xsmall()
                    .outline()
                    .p(px(12.0))
                    .when(mode == DeliveryMode::PublicBroadcaster, |button| {
                        button.primary()
                    })
                    .disabled(generating)
                    .on_click(move |_event, window, cx| {
                        public_root.update(cx, |root, cx| match kind {
                            DeliveryFormKind::Send => root.set_send_delivery_mode(
                                key,
                                DeliveryMode::PublicBroadcaster,
                                window,
                                cx,
                            ),
                            DeliveryFormKind::Unshield => root.set_unshield_delivery_mode(
                                key,
                                DeliveryMode::PublicBroadcaster,
                                window,
                                cx,
                            ),
                        });
                    }),
                )
                .child(
                    app_button(delivery_element_id(key, kind, "self"), "Self-broadcast")
                        .xsmall()
                        .outline()
                        .p(px(12.0))
                        .disabled(true),
                ),
        )
}

fn render_broadcaster_chooser(
    root: Entity<WalletRoot>,
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    choice: &BroadcasterChoice,
    candidates: Vec<PublicBroadcasterCandidate>,
    generating: bool,
) -> gpui::Div {
    let random_root = root.clone();
    let modal_root = root;
    let sorted = sort_specific_public_broadcasters(candidates);
    let specific_label = selected_broadcaster_label(choice, &sorted);
    let list = div()
        .flex()
        .flex_col()
        .gap_2()
        .p(px(10.0))
        .rounded_md()
        .bg(rgb(theme::SURFACE_ELEVATED))
        .border_1()
        .border_color(rgb(theme::BORDER))
        .child(app_muted_text(format!(
            "Eligible same-token broadcasters: {}",
            sorted.len()
        )))
        .child(
            app_button(
                delivery_element_id(key, kind, "random"),
                "Random broadcaster",
            )
            .xsmall()
            .outline()
            .p(px(12.0))
            .when(matches!(choice, BroadcasterChoice::Random), |button| {
                button.primary()
            })
            .disabled(generating || sorted.is_empty())
            .on_click(move |_event, _window, cx| {
                random_root.update(cx, |root, cx| match kind {
                    DeliveryFormKind::Send => {
                        root.set_send_broadcaster_choice(key, BroadcasterChoice::Random, cx);
                    }
                    DeliveryFormKind::Unshield => {
                        root.set_unshield_broadcaster_choice(key, BroadcasterChoice::Random, cx);
                    }
                });
            }),
        )
        .child(
            app_button(
                delivery_element_id(key, kind, "choose-specific"),
                specific_label,
            )
            .xsmall()
            .outline()
            .p(px(12.0))
            .when(
                matches!(choice, BroadcasterChoice::Specific { .. }),
                ButtonVariants::primary,
            )
            .disabled(generating || sorted.is_empty())
            .on_click(move |_event, window, cx| {
                modal_root.update(cx, |root, cx| {
                    root.open_broadcaster_picker(kind, key, window, cx);
                });
            }),
        );

    if sorted.is_empty() {
        return list.child(app_muted_text(
            "No eligible broadcaster currently advertises this token.",
        ));
    }

    list.child(app_muted_text(
        "Open the broadcaster picker to search, inspect, and choose a specific broadcaster.",
    ))
}

fn render_unshield_output_toggle(
    root: Entity<WalletRoot>,
    key: UnshieldAssetKey,
    chain_id: u64,
    unwrap: bool,
    generating: bool,
) -> gpui::Div {
    let Some((native_label, wrapped_label)) = native_wrapped_output_labels(chain_id) else {
        return div();
    };
    div()
        .flex()
        .flex_col()
        .gap_1()
        .child(app_muted_text("Output"))
        .child(
            ButtonGroup::new(unshield_element_id(key, "output-toggle"))
                .outline()
                .disabled(generating)
                .child(
                    app_button(unshield_element_id(key, "output-native"), native_label)
                        .selected(unwrap)
                        .disabled(generating),
                )
                .child(
                    app_button(unshield_element_id(key, "output-wrapped"), wrapped_label)
                        .selected(!unwrap)
                        .disabled(generating),
                )
                .on_click(move |selected, _window, cx| {
                    let Some(index) = selected.first() else {
                        return;
                    };
                    let unwrap = *index == 0;
                    root.update(cx, |root, cx| {
                        root.set_unshield_unwrap(key, unwrap, cx);
                    });
                }),
        )
}

const fn native_wrapped_output_labels(chain_id: u64) -> Option<(&'static str, &'static str)> {
    match chain_id {
        1 | 42161 => Some(("ETH", "WETH")),
        56 => Some(("BNB", "WBNB")),
        137 => Some(("MATIC", "WMATIC")),
        _ => None,
    }
}

fn render_broadcaster_fee_mode_toggle(
    root: Entity<WalletRoot>,
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    mode: PublicBroadcasterFeeMode,
    generating: bool,
) -> gpui::Div {
    let helper = match mode {
        PublicBroadcasterFeeMode::DeductFromAmount => {
            "Recipient receives the entered amount minus the broadcaster fee."
        }
        PublicBroadcasterFeeMode::AddToAmount => {
            "Recipient receives the full entered amount; broadcaster fee is added to spend."
        }
    };
    div()
        .flex()
        .flex_col()
        .gap_2()
        .p(px(10.0))
        .rounded_md()
        .bg(rgb(theme::SURFACE_ELEVATED))
        .border_1()
        .border_color(rgb(theme::BORDER))
        .child(
            div()
                .flex()
                .gap_2()
                .child(render_broadcaster_fee_mode_button(
                    root.clone(),
                    key,
                    kind,
                    mode,
                    PublicBroadcasterFeeMode::DeductFromAmount,
                    "Deduct fee from amount",
                    generating,
                ))
                .child(render_broadcaster_fee_mode_button(
                    root,
                    key,
                    kind,
                    mode,
                    PublicBroadcasterFeeMode::AddToAmount,
                    "Add fee on top",
                    generating,
                )),
        )
        .child(app_muted_text(helper))
}

fn render_broadcaster_fee_mode_button(
    root: Entity<WalletRoot>,
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    current_mode: PublicBroadcasterFeeMode,
    target_mode: PublicBroadcasterFeeMode,
    label: &'static str,
    generating: bool,
) -> Button {
    app_button(
        delivery_element_id(
            key,
            kind,
            match target_mode {
                PublicBroadcasterFeeMode::DeductFromAmount => "fee-mode-deduct",
                PublicBroadcasterFeeMode::AddToAmount => "fee-mode-add",
            },
        ),
        label,
    )
    .xsmall()
    .outline()
    .p(px(12.0))
    .when(current_mode == target_mode, ButtonVariants::primary)
    .disabled(generating)
    .on_click(move |_event, window, cx| {
        root.update(cx, |root, cx| match kind {
            DeliveryFormKind::Send => {
                root.set_send_broadcaster_fee_mode(key, target_mode, window, cx);
            }
            DeliveryFormKind::Unshield => {
                root.set_unshield_broadcaster_fee_mode(key, target_mode, window, cx);
            }
        });
    })
}

fn render_send_result(key: UnshieldAssetKey, result: &PreparedSendCall) -> gpui::Div {
    div()
        .flex()
        .flex_col()
        .gap_2()
        .p(px(12.0))
        .rounded_md()
        .bg(rgb(theme::SURFACE_ELEVATED))
        .border_1()
        .border_color(rgb(theme::SUCCESS))
        .child(app_strong_text("Prepared send calldata"))
        .child(app_muted_text(
            "Submit this transaction externally. The wallet has not broadcast it.",
        ))
        .child(render_unshield_copy_field(
            "To",
            result.to.to_checksum(None),
            send_element_id(key, "copy-to"),
        ))
        .child(render_unshield_copy_field(
            "Calldata",
            result.data.clone(),
            send_element_id(key, "copy-data"),
        ))
}

fn render_public_broadcaster_result(
    key: UnshieldAssetKey,
    kind: DeliveryFormKind,
    result: &PublicBroadcasterSubmissionResult,
) -> gpui::Div {
    let (title, detail, border, extra) = match &result.result {
        PublicBroadcasterResultKind::Submitted { tx_hash } => (
            "Submitted via public broadcaster",
            format!(
                "{} accepted the transaction.",
                broadcaster_candidate_label(&result.broadcaster)
            ),
            theme::SUCCESS,
            Some(("Tx hash", tx_hash.clone(), "copy-public-tx")),
        ),
        PublicBroadcasterResultKind::Failed { error } => (
            "Public broadcaster failed",
            error.clone(),
            theme::DANGER,
            None,
        ),
        PublicBroadcasterResultKind::TimedOut => (
            "Public broadcaster timed out",
            "No decryptable broadcaster response arrived before the timeout.".to_string(),
            theme::WARNING,
            None,
        ),
    };
    let mut card = div()
        .flex()
        .flex_col()
        .gap_2()
        .p(px(12.0))
        .rounded_md()
        .bg(rgb(theme::SURFACE_ELEVATED))
        .border_1()
        .border_color(rgb(border))
        .child(app_strong_text(title))
        .child(app_muted_text(detail))
        .child(cost_estimate_row(
            "Entered amount",
            format_exact_candidate_token_amount(&result.broadcaster, result.entered_amount),
        ))
        .child(cost_estimate_row(
            "Recipient receives",
            format_exact_candidate_token_amount(&result.broadcaster, result.recipient_amount),
        ))
        .child(cost_estimate_row(
            "Total private spend",
            format_exact_candidate_token_amount(&result.broadcaster, result.total_private_spend),
        ))
        .child(cost_estimate_row(
            "Broadcaster fee",
            format_exact_candidate_token_amount(&result.broadcaster, result.fee_amount),
        ))
        .when(result.protocol_fee_bps > 0, |card| {
            card.child(cost_estimate_row(
                "RAILGUN protocol fee",
                format!(
                    "{} ({} bps)",
                    format_exact_candidate_token_amount(
                        &result.broadcaster,
                        result.protocol_fee_amount
                    ),
                    result.protocol_fee_bps
                ),
            ))
        })
        .child(app_muted_text(format!(
            "Estimated gas: {} gas @ {} gwei",
            result.gas_limit,
            format_gwei(result.min_gas_price)
        )))
        .child(app_muted_text(public_broadcaster_fee_mode_summary(
            result.fee_mode,
            result.entered_amount,
            result.receiver_amount,
            result.protocol_fee_amount,
            &result.broadcaster,
        )));
    if let Some((label, value, action)) = extra {
        card = card.child(render_unshield_copy_field(
            label,
            value,
            delivery_element_id(key, kind, action),
        ));
    }
    card
}

fn render_public_broadcaster_cost_estimate(
    asset: &UnshieldAsset,
    estimate: &PublicBroadcasterCostEstimate,
) -> gpui::Div {
    div()
        .flex()
        .flex_col()
        .gap_2()
        .p(px(12.0))
        .rounded_md()
        .bg(rgb(theme::SURFACE_ELEVATED))
        .border_1()
        .border_color(rgb(theme::BORDER_STRONG))
        .child(app_strong_text("Estimated public broadcaster cost"))
        .child(cost_estimate_detail_text(
            "Proof is not generated yet; the final fee may move slightly before publish.",
        ))
        .child(cost_estimate_row(
            "Broadcaster",
            broadcaster_candidate_label(&estimate.broadcaster),
        ))
        .child(cost_estimate_row(
            "Recipient receives",
            format_exact_asset_amount_for_display(estimate.recipient_amount, asset),
        ))
        .child(cost_estimate_row(
            "Broadcaster fee",
            format_exact_asset_amount_for_display(estimate.fee_amount, asset),
        ))
        .when(estimate.protocol_fee_bps > 0, |card| {
            card.child(cost_estimate_row(
                "RAILGUN protocol fee",
                format!(
                    "{} ({} bps)",
                    format_exact_asset_amount_for_display(estimate.protocol_fee_amount, asset),
                    estimate.protocol_fee_bps
                ),
            ))
        })
        .when(
            should_show_distinct_amount(estimate.entered_amount, estimate.total_private_spend),
            |card| {
                card.child(cost_estimate_row(
                    "Total private spend",
                    format_exact_asset_amount_for_display(estimate.total_private_spend, asset),
                ))
            },
        )
        .when(
            should_show_distinct_amount(estimate.entered_amount, estimate.max_entered_amount),
            |card| {
                card.child(cost_estimate_row(
                    "Max via broadcaster",
                    format_exact_asset_amount_for_display(estimate.max_entered_amount, asset),
                ))
            },
        )
        .child(cost_estimate_detail_row(
            "Network gas",
            format!(
                "{} gas @ {} gwei",
                estimate.gas_limit,
                format_gwei(estimate.min_gas_price)
            ),
        ))
        .child(cost_estimate_detail_text(format!(
            "Shape: {} proofs · {} inputs · {} private outputs · {} public outputs",
            estimate.transaction_count,
            estimate.input_count,
            estimate.private_output_count,
            estimate.public_output_count
        )))
        .child(cost_estimate_detail_text(
            public_broadcaster_fee_mode_summary(
                estimate.fee_mode,
                estimate.entered_amount,
                estimate.receiver_amount,
                estimate.protocol_fee_amount,
                &estimate.broadcaster,
            ),
        ))
}

const fn public_broadcaster_cost_status(
    pending: bool,
    estimating: bool,
) -> Option<CostEstimateStatus> {
    if pending {
        None
    } else if estimating {
        Some(CostEstimateStatus::Estimating)
    } else {
        None
    }
}

const fn public_broadcaster_cost_status_text(
    status: CostEstimateStatus,
) -> (&'static str, &'static str) {
    match status {
        CostEstimateStatus::Estimating => (
            "Estimating public broadcaster cost...",
            "Using current gas price, broadcaster fee rate, and selected private note shape.",
        ),
    }
}

fn render_public_broadcaster_cost_status(tick: usize, status: CostEstimateStatus) -> gpui::Div {
    let (title, detail) = public_broadcaster_cost_status_text(status);
    div()
        .flex()
        .items_center()
        .gap_3()
        .p(px(12.0))
        .rounded_md()
        .bg(rgb(theme::SURFACE_ELEVATED))
        .border_1()
        .border_color(rgb(theme::BORDER))
        .child(
            div()
                .size(px(22.0))
                .flex()
                .items_center()
                .justify_center()
                .rounded_full()
                .bg(rgb(theme::BACKGROUND))
                .text_color(rgb(theme::INFO))
                .font_weight(gpui::FontWeight::SEMIBOLD)
                .child(unshield_spinner_frame(tick)),
        )
        .child(
            div()
                .flex()
                .flex_col()
                .gap_1()
                .child(app_strong_text(title))
                .child(app_muted_text(detail)),
        )
}

fn cost_estimate_row(label: &'static str, value: String) -> gpui::Div {
    div()
        .flex()
        .items_center()
        .justify_between()
        .gap_3()
        .child(app_muted_text(label))
        .child(app_strong_text(value))
}

fn cost_estimate_detail_text(text: impl Into<SharedString>) -> gpui::Div {
    div()
        .text_color(rgb(theme::TEXT_SUBTLE))
        .text_size(COST_ESTIMATE_DETAIL_TEXT_SIZE)
        .line_height(px(15.0))
        .child(text.into())
}

fn cost_estimate_detail_value(text: impl Into<SharedString>) -> gpui::Div {
    cost_estimate_detail_text(text).font_weight(gpui::FontWeight::SEMIBOLD)
}

fn cost_estimate_detail_row(label: &'static str, value: String) -> gpui::Div {
    div()
        .flex()
        .items_center()
        .justify_between()
        .gap_3()
        .child(cost_estimate_detail_text(label))
        .child(cost_estimate_detail_value(value))
}

fn render_unshield_result(key: UnshieldAssetKey, result: &PreparedUnshieldCall) -> gpui::Div {
    div()
        .flex()
        .flex_col()
        .gap_2()
        .p(px(12.0))
        .rounded_md()
        .bg(rgb(theme::SURFACE_ELEVATED))
        .border_1()
        .border_color(rgb(theme::SUCCESS))
        .child(app_strong_text("Prepared calldata"))
        .child(app_muted_text(
            "Submit this transaction externally. The wallet has not broadcast it.",
        ))
        .child(render_unshield_copy_field(
            "To",
            result.to.to_checksum(None),
            unshield_element_id(key, "copy-to"),
        ))
        .child(render_unshield_copy_field(
            "Calldata",
            result.data.clone(),
            unshield_element_id(key, "copy-data"),
        ))
}

fn render_unshield_copy_field(
    label: &'static str,
    value: String,
    button_id: SharedString,
) -> gpui::Div {
    let copy_value = value.clone();
    div()
        .flex()
        .items_start()
        .gap_2()
        .child(
            div()
                .w(px(72.0))
                .flex_none()
                .text_color(rgb(theme::TEXT_MUTED))
                .child(label),
        )
        .child(
            div()
                .flex_1()
                .min_w(px(0.0))
                .p(px(8.0))
                .rounded_sm()
                .bg(rgb(theme::BACKGROUND))
                .border_1()
                .border_color(rgb(theme::BORDER))
                .font_family(APP_FONT_FAMILY)
                .text_size(APP_TEXT_SIZE)
                .child(SharedString::from(value)),
        )
        .child(app_button(button_id, "Copy").xsmall().outline().on_click(
            move |_event, window, cx| {
                copy_with_toast(copy_value.clone(), window, cx);
            },
        ))
}

fn display_rows_from_output(
    output: &ListUtxosOutput,
    tx_query: &str,
    show_spent_utxos: bool,
) -> Vec<UtxoDisplayRow> {
    let tx_query = tx_query.trim().to_ascii_lowercase();
    let mut rows: Vec<_> = output
        .utxos
        .iter()
        .filter(|row| matches_utxo_filters(row, &tx_query, show_spent_utxos))
        .map(|row| display_row_from_utxo(output.chain_id, row))
        .collect();
    rows.reverse();
    rows
}

fn matches_utxo_filters(row: &UtxoOutput, tx_query: &str, show_spent_utxos: bool) -> bool {
    if tx_query.is_empty() {
        return show_spent_utxos || !row.is_spent;
    }

    row.source_tx_hash.to_ascii_lowercase().contains(tx_query)
        || row
            .spent_tx_hash
            .as_deref()
            .is_some_and(|hash| hash.to_ascii_lowercase().contains(tx_query))
}

fn display_row_from_utxo(chain_id: u64, row: &UtxoOutput) -> UtxoDisplayRow {
    let Some(address) = parse_address(&row.token) else {
        return UtxoDisplayRow {
            tree_position: format_tree_position(row.tree, row.position),
            token: row.token.clone(),
            token_icon_path: None,
            amount: row.value.clone(),
            poi_status: format_poi_status(row),
            poi_spendable: row.poi_spendable,
            source_tx_hash: row.source_tx_hash.clone(),
            source_block_timestamp: row.source_block_timestamp,
            spent_tx_hash: row.spent_tx_hash.clone(),
            token_address: row.token.clone(),
            is_spent: row.is_spent,
        };
    };

    let (token, amount, token_icon_path) = if let Some(token) = lookup_token(chain_id, &address) {
        let amount = U256::from_str_radix(&row.value, 10).map_or_else(
            |_| row.value.clone(),
            |value| format_token_amount(value, token.decimals),
        );
        (
            token.symbol.to_owned(),
            amount,
            token_icon_path(chain_id, &address),
        )
    } else {
        (short_address(&address), row.value.clone(), None)
    };

    UtxoDisplayRow {
        tree_position: format_tree_position(row.tree, row.position),
        token,
        token_icon_path,
        amount,
        poi_status: format_poi_status(row),
        poi_spendable: row.poi_spendable,
        source_tx_hash: row.source_tx_hash.clone(),
        source_block_timestamp: row.source_block_timestamp,
        spent_tx_hash: row.spent_tx_hash.clone(),
        token_address: address.to_checksum(None),
        is_spent: row.is_spent,
    }
}

fn format_poi_status(row: &UtxoOutput) -> String {
    if row.poi_statuses.is_empty() {
        return "Unknown".to_string();
    }
    let mut statuses: Vec<_> = row.poi_statuses.values().cloned().collect();
    statuses.sort();
    statuses.dedup();
    if statuses.len() == 1 {
        statuses.remove(0)
    } else {
        statuses.join(", ")
    }
}

fn format_tree_position(tree: u32, position: u64) -> String {
    format!("{tree}/{position}")
}

fn generated_age_label(timestamp: u64) -> String {
    let age_secs = now_epoch_secs().saturating_sub(timestamp);
    format!("{} ago", format_compact_age(age_secs))
}

fn format_compact_age(age_secs: u64) -> String {
    if age_secs < SECONDS_PER_MINUTE {
        return format!("{age_secs}s");
    }

    if age_secs < SECONDS_PER_HOUR {
        return format!("{}m", age_secs / SECONDS_PER_MINUTE);
    }

    if age_secs < 3 * SECONDS_PER_HOUR {
        return format_age_parts(
            age_secs / SECONDS_PER_HOUR,
            "h",
            (age_secs % SECONDS_PER_HOUR) / SECONDS_PER_MINUTE,
            "m",
        );
    }

    if age_secs < SECONDS_PER_DAY {
        return format!("{}h", age_secs / SECONDS_PER_HOUR);
    }

    if age_secs < 3 * SECONDS_PER_DAY {
        return format_age_parts(
            age_secs / SECONDS_PER_DAY,
            "d",
            (age_secs % SECONDS_PER_DAY) / SECONDS_PER_HOUR,
            "h",
        );
    }

    if age_secs < 30 * SECONDS_PER_DAY {
        return format!("{}d", age_secs / SECONDS_PER_DAY);
    }

    if age_secs < 3 * SECONDS_PER_MONTH {
        return format_age_parts(
            age_secs / SECONDS_PER_MONTH,
            "mo",
            (age_secs % SECONDS_PER_MONTH) / SECONDS_PER_DAY,
            "d",
        );
    }

    if age_secs < SECONDS_PER_YEAR {
        return format!("{}mo", age_secs / SECONDS_PER_MONTH);
    }

    if age_secs < 3 * SECONDS_PER_YEAR {
        return format_age_parts(
            age_secs / SECONDS_PER_YEAR,
            "y",
            (age_secs % SECONDS_PER_YEAR) / SECONDS_PER_MONTH,
            "mo",
        );
    }

    format!("{}y", age_secs / SECONDS_PER_YEAR)
}

fn format_age_parts(
    primary: u64,
    primary_unit: &str,
    secondary: u64,
    secondary_unit: &str,
) -> String {
    if secondary == 0 {
        format!("{primary}{primary_unit}")
    } else {
        format!("{primary}{primary_unit} {secondary}{secondary_unit}")
    }
}

fn local_datetime_label(timestamp: u64) -> String {
    let Ok(seconds) = i64::try_from(timestamp) else {
        return format!("Unix timestamp {timestamp}");
    };
    let Some(utc) = DateTime::<Utc>::from_timestamp(seconds, 0) else {
        return format!("Unix timestamp {timestamp}");
    };
    utc.with_timezone(&Local)
        .format("%Y-%m-%d %H:%M:%S %Z")
        .to_string()
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn short_hash(hash: &str) -> String {
    if hash.len() <= 14 {
        return hash.to_string();
    }
    format!("{}...{}", &hash[..8], &hash[hash.len() - 6..])
}

fn parse_address(raw: &str) -> Option<Address> {
    raw.parse().ok()
}

fn parse_repair_cache_block(raw: &str) -> Result<Option<u64>, &'static str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "0" {
        return Ok(None);
    }
    let block = trimmed
        .parse::<u64>()
        .map_err(|_| "Enter a block number, or 0 for deployment block.")?;
    Ok(Some(block))
}

const fn vault_error_kind(error: &VaultError) -> &'static str {
    match error {
        VaultError::Random => "random",
        VaultError::InvalidKdfParams => "invalid_kdf_params",
        VaultError::Kdf => "kdf",
        VaultError::KeySeparation => "key_separation",
        VaultError::Encrypt => "encrypt",
        VaultError::Decrypt => "decrypt",
        VaultError::Encode(_) => "encode",
        VaultError::Decode(_) => "decode",
        VaultError::Db(_) => "db",
        VaultError::Io(_) => "io",
        VaultError::Key(_) => "key",
        VaultError::UnsupportedVersion(_) => "unsupported_version",
        VaultError::VaultAlreadyExists => "vault_already_exists",
        VaultError::VaultNotFound => "vault_not_found",
        VaultError::UnlockFailed => "unlock_failed",
        VaultError::InvalidSpendGrant => "invalid_spend_grant",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use alloy::primitives::{Address, U256};
    use wallet_ops::{
        ListUtxosOutput, SyncProgressStage, SyncProgressUpdate, TransactionGenerationStage,
        UtxoOutput,
    };

    use super::{
        Activity, ChainLoadSource, ChainUtxoState, CostEstimateStatus, PrivateActionMetric,
        SECONDS_PER_DAY, SECONDS_PER_HOUR, SECONDS_PER_MINUTE, SECONDS_PER_MONTH, SECONDS_PER_YEAR,
        UnshieldAsset, UnshieldAssetKey, WalletAppOptions, WalletTab,
        adjusted_amount_for_max_change, build_send_asset, build_unshield_asset,
        chain_load_overrides, display_rows_from_output, format_compact_age,
        format_exact_asset_amount_for_display, format_form_error_for_asset,
        format_private_asset_rows, format_send_amount_input, format_total,
        format_unshield_amount_input, loading_summary, max_send_amount_from_snapshot,
        max_unshield_amount_from_snapshot, native_wrapped_output_labels, parse_repair_cache_block,
        private_action_metrics, progress_detail, public_broadcaster_cost_status,
        public_broadcaster_cost_status_text, refresh_form_asset_from_snapshot,
        send_asset_key_from_formatted, send_element_id, send_key_matches_asset, send_spinner_frame,
        should_focus_utxo_table, should_show_distinct_amount, should_show_pending_poi_amount,
        unshield_asset_key_from_formatted, unshield_element_id, unshield_key_matches_asset,
        unshield_spinner_frame,
    };

    fn wallet_options_with_overrides() -> WalletAppOptions {
        WalletAppOptions {
            initial_chain_id: 1,
            db_path: PathBuf::from("db"),
            init_block_number: Some(123),
            sync_to_block: Some(456),
            use_indexed_wallet_catch_up: false,
            rewind_wallet_cache: true,
            rpc_url: Some(reqwest::Url::parse("https://example.invalid/rpc").unwrap()),
        }
    }

    fn utxo_output(token: &str, value: &str, is_spent: bool) -> UtxoOutput {
        const SOURCE_TX_HASH: &str =
            "0x1111111111111111111111111111111111111111111111111111111111111111";
        const SPENT_TX_HASH: &str =
            "0x2222222222222222222222222222222222222222222222222222222222222222";

        utxo_output_with_hashes(
            token,
            value,
            is_spent,
            SOURCE_TX_HASH,
            is_spent.then_some(SPENT_TX_HASH),
        )
    }

    fn utxo_output_with_hashes(
        token: &str,
        value: &str,
        is_spent: bool,
        source_tx_hash: &str,
        spent_tx_hash: Option<&str>,
    ) -> UtxoOutput {
        UtxoOutput {
            tree: 0,
            position: 7,
            token: token.to_string(),
            value: value.to_string(),
            commitment_kind: "Transact".to_string(),
            commitment: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            npk: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            blinded_commitment:
                "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
            poi_statuses: BTreeMap::from([(
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string(),
                if is_spent { "Unknown" } else { "Valid" }.to_string(),
            )]),
            poi_spendable: !is_spent,
            source_tx_hash: source_tx_hash.to_string(),
            source_block_number: 11,
            source_block_timestamp: 1_700_000_011,
            is_spent,
            spent_tx_hash: spent_tx_hash.map(str::to_string),
            spent_block_number: spent_tx_hash.map(|_| 21),
        }
    }

    fn unshield_utxo_output(token: Address, value: u64, tree: u32, position: u64) -> UtxoOutput {
        UtxoOutput {
            tree,
            position,
            token: token.to_checksum(None),
            value: value.to_string(),
            commitment_kind: "Transact".to_string(),
            commitment: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            npk: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            blinded_commitment:
                "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
            poi_statuses: BTreeMap::from([(
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string(),
                "Valid".to_string(),
            )]),
            poi_spendable: true,
            source_tx_hash: "0x1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            source_block_number: 11,
            source_block_timestamp: 1_700_000_011,
            is_spent: false,
            spent_tx_hash: None,
            spent_block_number: None,
        }
    }

    #[test]
    fn display_rows_use_known_token_metadata() {
        let output = ListUtxosOutput {
            chain_id: 1,
            cache_key: "cache".to_string(),
            utxo_count: 1,
            unspent_count: 1,
            spent_count: 0,
            utxos: vec![utxo_output(
                "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                "1234567",
                false,
            )],
            totals: Vec::new(),
        };

        let rows = display_rows_from_output(&output, "", true);
        assert_eq!(rows[0].token, "USDC");
        assert_eq!(rows[0].amount, "1.23");
        assert_eq!(rows[0].tree_position, "0/7");
        assert_eq!(rows[0].poi_status, "Valid");
        assert!(rows[0].poi_spendable);
        assert_eq!(rows[0].source_block_timestamp, 1_700_000_011);
        assert!(rows[0].token_icon_path.is_some());
        assert!(!rows[0].is_spent);
    }

    #[test]
    fn compact_age_uses_expected_thresholds() {
        const M: u64 = SECONDS_PER_MINUTE;
        const H: u64 = SECONDS_PER_HOUR;
        const D: u64 = SECONDS_PER_DAY;
        const MO: u64 = SECONDS_PER_MONTH;
        const Y: u64 = SECONDS_PER_YEAR;

        assert_eq!(format_compact_age(0), "0s");
        assert_eq!(format_compact_age(59), "59s");
        assert_eq!(format_compact_age(M), "1m");
        assert_eq!(format_compact_age(59 * M + 59), "59m");
        assert_eq!(format_compact_age(H), "1h");
        assert_eq!(format_compact_age(2 * H + 14 * M), "2h 14m");
        assert_eq!(format_compact_age(3 * H), "3h");
        assert_eq!(format_compact_age(23 * H + 59 * M), "23h");
        assert_eq!(format_compact_age(D), "1d");
        assert_eq!(format_compact_age(2 * D + 3 * H), "2d 3h");
        assert_eq!(format_compact_age(3 * D), "3d");
        assert_eq!(format_compact_age(29 * D), "29d");
        assert_eq!(format_compact_age(30 * D), "1mo");
        assert_eq!(format_compact_age(2 * MO + 4 * D), "2mo 4d");
        assert_eq!(format_compact_age(3 * MO), "3mo");
        assert_eq!(format_compact_age(11 * MO), "11mo");
        assert_eq!(format_compact_age(Y), "1y");
        assert_eq!(format_compact_age(2 * Y + 3 * MO), "2y 3mo");
        assert_eq!(format_compact_age(3 * Y), "3y");
    }

    #[test]
    fn display_rows_fall_back_for_unknown_token_metadata() {
        let output = ListUtxosOutput {
            chain_id: 1,
            cache_key: "cache".to_string(),
            utxo_count: 1,
            unspent_count: 1,
            spent_count: 0,
            utxos: vec![utxo_output(
                "0x1111111111111111111111111111111111111111",
                "42",
                false,
            )],
            totals: Vec::new(),
        };

        let rows = display_rows_from_output(&output, "", true);
        assert_eq!(rows[0].amount, "42");
        assert_eq!(
            rows[0].token_address,
            "0x1111111111111111111111111111111111111111"
        );
        assert_eq!(rows[0].token_icon_path, None);
    }

    #[test]
    fn totals_format_known_token_amount() {
        let total = wallet_ops::TokenTotal {
            token: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
            total: "1234567".to_string(),
            poi_verified_total: "1234567".to_string(),
        };

        assert_eq!(format_total(1, &total), "USDC 1.23");
    }

    #[test]
    fn form_error_formats_broadcaster_max_in_token_units() {
        let asset = UnshieldAsset {
            chain_id: 1,
            token: Address::ZERO,
            label: "USDC".to_string(),
            decimals: Some(6),
            total: U256::ZERO,
            poi_verified_total: U256::ZERO,
            max_batched: U256::ZERO,
            icon_path: None,
        };

        let formatted = format_form_error_for_asset(
            "build public broadcaster send proof: public broadcaster max entered amount: 388585770",
            &asset,
        );

        assert_eq!(
            formatted,
            "Max POI-verified entered amount for public broadcaster: 388.58577 USDC. Try a smaller amount or switch fee mode."
        );
    }

    #[test]
    fn public_broadcaster_amount_display_is_exact() {
        let asset = UnshieldAsset {
            chain_id: 1,
            token: Address::ZERO,
            label: "USDC".to_string(),
            decimals: Some(6),
            total: U256::ZERO,
            poi_verified_total: U256::ZERO,
            max_batched: U256::ZERO,
            icon_path: None,
        };

        assert_eq!(
            format_exact_asset_amount_for_display(U256::from(388_429_885_u64), &asset),
            "388.429885 USDC"
        );
        assert_eq!(
            format_exact_asset_amount_for_display(U256::from(14_390_115_u64), &asset),
            "14.390115 USDC"
        );
    }

    #[test]
    fn public_broadcaster_estimate_hides_duplicate_amount_rows() {
        let entered = U256::from(388_429_885_u64);

        assert!(!should_show_distinct_amount(entered, entered));
        assert!(should_show_distinct_amount(
            entered,
            entered + U256::from(1_u8)
        ));
    }

    #[test]
    fn public_broadcaster_cost_status_separates_pending_from_estimating() {
        assert_eq!(public_broadcaster_cost_status(true, false), None);
        assert_eq!(
            public_broadcaster_cost_status(false, true),
            Some(CostEstimateStatus::Estimating)
        );
        assert_eq!(public_broadcaster_cost_status(true, true), None);
        assert_eq!(public_broadcaster_cost_status(false, false), None);
        assert_eq!(
            public_broadcaster_cost_status_text(CostEstimateStatus::Estimating).0,
            "Estimating public broadcaster cost..."
        );
    }

    #[test]
    fn amount_adjustment_clamps_or_raises_only_at_mode_max() {
        assert_eq!(
            adjusted_amount_for_max_change(
                U256::from(120_u8),
                Some(U256::from(120_u8)),
                U256::from(100_u8),
            ),
            Some(U256::from(100_u8))
        );
        assert_eq!(
            adjusted_amount_for_max_change(
                U256::from(100_u8),
                Some(U256::from(100_u8)),
                U256::from(120_u8),
            ),
            Some(U256::from(120_u8))
        );
        assert_eq!(
            adjusted_amount_for_max_change(
                U256::from(90_u8),
                Some(U256::from(100_u8)),
                U256::from(120_u8),
            ),
            None
        );
    }

    #[test]
    fn private_tab_is_default_wallet_tab() {
        assert_eq!(WalletTab::default(), WalletTab::Private);
    }

    #[test]
    fn utxo_table_focus_is_activity_scoped() {
        let state = ChainUtxoState::Loading { progress: None };

        assert!(!should_focus_utxo_table(
            Activity::Wallet,
            WalletTab::Private,
            Some(&state)
        ));
        assert!(!should_focus_utxo_table(
            Activity::Broadcaster,
            WalletTab::Activity,
            Some(&state)
        ));
        assert!(should_focus_utxo_table(
            Activity::Wallet,
            WalletTab::Activity,
            Some(&state)
        ));
    }

    #[test]
    fn private_asset_rows_use_totals_formatting() {
        let totals = [wallet_ops::TokenTotal {
            token: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
            total: "1234567".to_string(),
            poi_verified_total: "1000000".to_string(),
        }];

        let rows = format_private_asset_rows(1, &totals);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].label, "USDC");
        assert_eq!(rows[0].amount, "1.23");
        assert_eq!(rows[0].pending_poi_amount, "0.23457");
        assert_eq!(rows[0].pending_poi_total, Some(U256::from(234_567_u64)));
        assert!(should_show_pending_poi_amount(rows[0].pending_poi_total));
        assert!(rows[0].icon_path.is_some());
    }

    #[test]
    fn private_asset_rows_hide_zero_pending_poi() {
        let totals = [wallet_ops::TokenTotal {
            token: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
            total: "1234567".to_string(),
            poi_verified_total: "1234567".to_string(),
        }];

        let rows = format_private_asset_rows(1, &totals);

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].pending_poi_amount, "0");
        assert_eq!(rows[0].pending_poi_total, Some(U256::ZERO));
        assert!(!should_show_pending_poi_amount(rows[0].pending_poi_total));
    }

    #[test]
    fn unshield_amount_input_formats_exact_token_units() {
        assert_eq!(
            format_unshield_amount_input(U256::from(1_230_000_u64), Some(6)),
            "1.23"
        );
        assert_eq!(
            format_unshield_amount_input(U256::from(1_000_000_u64), Some(6)),
            "1"
        );
        assert_eq!(format_unshield_amount_input(U256::from(42_u8), None), "42");
    }

    #[test]
    fn send_amount_input_formats_exact_token_units() {
        assert_eq!(
            format_send_amount_input(U256::from(1_230_000_u64), Some(6)),
            "1.23"
        );
        assert_eq!(
            format_send_amount_input(U256::from(1_000_000_u64), Some(6)),
            "1"
        );
        assert_eq!(format_send_amount_input(U256::from(42_u8), None), "42");
    }

    #[test]
    fn unshield_spinner_frames_cycle() {
        assert_eq!(unshield_spinner_frame(0), "|");
        assert_eq!(unshield_spinner_frame(1), "/");
        assert_eq!(unshield_spinner_frame(2), "-");
        assert_eq!(unshield_spinner_frame(3), "\\");
        assert_eq!(unshield_spinner_frame(4), "|");
    }

    #[test]
    fn send_spinner_frames_cycle() {
        assert_eq!(send_spinner_frame(0), "|");
        assert_eq!(send_spinner_frame(1), "/");
        assert_eq!(send_spinner_frame(2), "-");
        assert_eq!(send_spinner_frame(3), "\\");
        assert_eq!(send_spinner_frame(4), "|");
    }

    #[test]
    fn transaction_generation_stage_text_is_specific() {
        assert_eq!(
            TransactionGenerationStage::SelectingPrivateNotes.label(),
            "Selecting private notes"
        );
        assert_eq!(
            TransactionGenerationStage::ProvingTransaction.detail(),
            "Generating the zero-knowledge proof. This is usually the slowest step."
        );
        assert_eq!(
            TransactionGenerationStage::PublishingToBroadcaster.label(),
            "Publishing to broadcaster"
        );
        assert_eq!(
            TransactionGenerationStage::WaitingForBroadcasterResponse.detail(),
            "Waiting for the selected broadcaster to respond."
        );
    }

    #[test]
    fn private_action_metrics_hide_values_matching_total() {
        let token = Address::from([0x11; 20]);
        let mut asset = UnshieldAsset {
            chain_id: 1,
            token,
            label: "WETH".to_string(),
            decimals: Some(18),
            total: U256::from(10_u8),
            poi_verified_total: U256::from(10_u8),
            max_batched: U256::from(10_u8),
            icon_path: None,
        };

        assert_eq!(
            private_action_metrics(&asset),
            vec![PrivateActionMetric {
                label: "Total private balance",
                amount: U256::from(10_u8),
            }]
        );

        asset.poi_verified_total = U256::from(7_u8);
        assert_eq!(
            private_action_metrics(&asset),
            vec![
                PrivateActionMetric {
                    label: "Total private balance",
                    amount: U256::from(10_u8),
                },
                PrivateActionMetric {
                    label: "POI-verified balance",
                    amount: U256::from(7_u8),
                },
            ]
        );

        asset.poi_verified_total = asset.total;
        asset.max_batched = U256::from(8_u8);
        assert_eq!(
            private_action_metrics(&asset),
            vec![
                PrivateActionMetric {
                    label: "Total private balance",
                    amount: U256::from(10_u8),
                },
                PrivateActionMetric {
                    label: "Max batched transaction",
                    amount: U256::from(8_u8),
                },
            ]
        );
    }

    #[test]
    fn native_wrapped_output_labels_are_chain_specific() {
        assert_eq!(native_wrapped_output_labels(1), Some(("ETH", "WETH")));
        assert_eq!(native_wrapped_output_labels(56), Some(("BNB", "WBNB")));
        assert_eq!(native_wrapped_output_labels(137), Some(("MATIC", "WMATIC")));
        assert_eq!(native_wrapped_output_labels(42161), Some(("ETH", "WETH")));
        assert_eq!(native_wrapped_output_labels(999_999), None);
    }

    #[test]
    fn max_unshield_amount_from_snapshot_uses_batched_top_chunks() {
        let token = Address::from([0x11; 20]);
        let other = Address::from([0x22; 20]);
        let mut utxos = (0..20)
            .map(|position| unshield_utxo_output(token, 1, 0, position))
            .collect::<Vec<_>>();
        utxos.extend((0..5).map(|position| unshield_utxo_output(token, 3, 1, position)));
        utxos.push(unshield_utxo_output(other, 100, 1, 99));
        let mut unknown = unshield_utxo_output(token, 100, 2, 1);
        unknown.poi_statuses.clear();
        unknown.poi_spendable = false;
        utxos.push(unknown);
        let snapshot = ListUtxosOutput {
            chain_id: 1,
            cache_key: "cache".to_string(),
            utxo_count: utxos.len(),
            unspent_count: utxos.len(),
            spent_count: 0,
            utxos,
            totals: Vec::new(),
        };

        assert_eq!(
            max_unshield_amount_from_snapshot(&snapshot, token),
            U256::from(35_u8)
        );
    }

    #[test]
    fn refreshed_form_asset_tracks_new_utxos() {
        let token = Address::from([0x11; 20]);
        let original_snapshot = ListUtxosOutput {
            chain_id: 1,
            cache_key: "cache".to_string(),
            utxo_count: 1,
            unspent_count: 1,
            spent_count: 0,
            utxos: vec![unshield_utxo_output(token, 5, 0, 1)],
            totals: vec![wallet_ops::TokenTotal {
                token: token.to_checksum(None),
                total: "5".to_string(),
                poi_verified_total: "5".to_string(),
            }],
        };
        let original_row = format_private_asset_rows(1, &original_snapshot.totals)
            .pop()
            .expect("formatted row");
        let original_asset =
            build_unshield_asset(&original_snapshot, &original_row).expect("original asset");
        let updated_snapshot = ListUtxosOutput {
            chain_id: 1,
            cache_key: "cache".to_string(),
            utxo_count: 2,
            unspent_count: 2,
            spent_count: 0,
            utxos: vec![
                unshield_utxo_output(token, 5, 0, 1),
                unshield_utxo_output(token, 3, 0, 2),
            ],
            totals: vec![wallet_ops::TokenTotal {
                token: token.to_checksum(None),
                total: "8".to_string(),
                poi_verified_total: "8".to_string(),
            }],
        };

        let updated = refresh_form_asset_from_snapshot(&updated_snapshot, &original_asset, false);

        assert_eq!(updated.total, U256::from(8_u8));
        assert_eq!(updated.poi_verified_total, U256::from(8_u8));
        assert_eq!(updated.max_batched, U256::from(8_u8));
    }

    #[test]
    fn refreshed_form_asset_tracks_spent_out_token() {
        let token = Address::from([0x11; 20]);
        let original_asset = UnshieldAsset {
            chain_id: 1,
            token,
            label: "WETH".to_string(),
            decimals: Some(18),
            total: U256::from(5_u8),
            poi_verified_total: U256::from(5_u8),
            max_batched: U256::from(5_u8),
            icon_path: None,
        };
        let mut spent = unshield_utxo_output(token, 5, 0, 1);
        spent.is_spent = true;
        spent.poi_spendable = false;
        spent.spent_tx_hash =
            Some("0x2222222222222222222222222222222222222222222222222222222222222222".to_string());
        spent.spent_block_number = Some(21);
        let updated_snapshot = ListUtxosOutput {
            chain_id: 1,
            cache_key: "cache".to_string(),
            utxo_count: 1,
            unspent_count: 0,
            spent_count: 1,
            utxos: vec![spent],
            totals: Vec::new(),
        };

        let updated = refresh_form_asset_from_snapshot(&updated_snapshot, &original_asset, false);

        assert_eq!(updated.label, "WETH");
        assert_eq!(updated.decimals, Some(18));
        assert_eq!(updated.total, U256::ZERO);
        assert_eq!(updated.poi_verified_total, U256::ZERO);
        assert_eq!(updated.max_batched, U256::ZERO);
    }

    #[test]
    fn max_send_amount_from_snapshot_uses_batched_top_chunks() {
        let token = Address::from([0x12; 20]);
        let other = Address::from([0x22; 20]);
        let mut utxos = (0..20)
            .map(|position| unshield_utxo_output(token, 1, 0, position))
            .collect::<Vec<_>>();
        utxos.extend((0..5).map(|position| unshield_utxo_output(token, 3, 1, position)));
        utxos.push(unshield_utxo_output(other, 100, 1, 99));
        let mut unknown = unshield_utxo_output(token, 100, 2, 1);
        unknown.poi_statuses.clear();
        unknown.poi_spendable = false;
        utxos.push(unknown);
        let snapshot = ListUtxosOutput {
            chain_id: 1,
            cache_key: "cache".to_string(),
            utxo_count: utxos.len(),
            unspent_count: utxos.len(),
            spent_count: 0,
            utxos,
            totals: Vec::new(),
        };

        assert_eq!(
            max_send_amount_from_snapshot(&snapshot, token),
            U256::from(35_u8)
        );
    }

    #[test]
    fn build_unshield_asset_includes_max_batched_transaction() {
        let token = Address::from([0x33; 20]);
        let snapshot = ListUtxosOutput {
            chain_id: 1,
            cache_key: "cache".to_string(),
            utxo_count: 2,
            unspent_count: 2,
            spent_count: 0,
            utxos: vec![
                unshield_utxo_output(token, 5, 0, 1),
                unshield_utxo_output(token, 7, 0, 2),
            ],
            totals: vec![wallet_ops::TokenTotal {
                token: token.to_checksum(None),
                total: "12".to_string(),
                poi_verified_total: "12".to_string(),
            }],
        };
        let row = format_private_asset_rows(1, &snapshot.totals)
            .into_iter()
            .next()
            .expect("asset row");

        let asset = build_unshield_asset(&snapshot, &row).expect("unshield asset");

        assert_eq!(asset.total, U256::from(12_u8));
        assert_eq!(asset.max_batched, U256::from(12_u8));
    }

    #[test]
    fn build_send_asset_includes_max_batched_transaction() {
        let token = Address::from([0x34; 20]);
        let snapshot = ListUtxosOutput {
            chain_id: 1,
            cache_key: "cache".to_string(),
            utxo_count: 2,
            unspent_count: 2,
            spent_count: 0,
            utxos: vec![
                unshield_utxo_output(token, 5, 0, 1),
                unshield_utxo_output(token, 7, 0, 2),
            ],
            totals: vec![wallet_ops::TokenTotal {
                token: token.to_checksum(None),
                total: "12".to_string(),
                poi_verified_total: "12".to_string(),
            }],
        };
        let row = format_private_asset_rows(1, &snapshot.totals)
            .into_iter()
            .next()
            .expect("asset row");

        let asset = build_send_asset(&snapshot, &row).expect("send asset");

        assert_eq!(asset.total, U256::from(12_u8));
        assert_eq!(asset.max_batched, U256::from(12_u8));
    }

    #[test]
    fn unshield_key_matches_only_selected_asset() {
        let token = Address::from([0x44; 20]);
        let other = Address::from([0x45; 20]);
        let rows = format_private_asset_rows(
            1,
            &[
                wallet_ops::TokenTotal {
                    token: token.to_checksum(None),
                    total: "5".to_string(),
                    poi_verified_total: "5".to_string(),
                },
                wallet_ops::TokenTotal {
                    token: other.to_checksum(None),
                    total: "7".to_string(),
                    poi_verified_total: "7".to_string(),
                },
            ],
        );
        let key = UnshieldAssetKey::new(1, token);

        assert_eq!(unshield_asset_key_from_formatted(&rows[0]), Some(key));
        assert!(unshield_key_matches_asset(key, &rows[0]));
        assert!(!unshield_key_matches_asset(key, &rows[1]));
    }

    #[test]
    fn send_key_matches_only_selected_asset() {
        let token = Address::from([0x46; 20]);
        let other = Address::from([0x47; 20]);
        let rows = format_private_asset_rows(
            1,
            &[
                wallet_ops::TokenTotal {
                    token: token.to_checksum(None),
                    total: "5".to_string(),
                    poi_verified_total: "5".to_string(),
                },
                wallet_ops::TokenTotal {
                    token: other.to_checksum(None),
                    total: "7".to_string(),
                    poi_verified_total: "7".to_string(),
                },
            ],
        );
        let key = UnshieldAssetKey::new(1, token);

        assert_eq!(send_asset_key_from_formatted(&rows[0]), Some(key));
        assert!(send_key_matches_asset(key, &rows[0]));
        assert!(!send_key_matches_asset(key, &rows[1]));
    }

    #[test]
    fn unshield_element_ids_are_asset_scoped() {
        let first = UnshieldAssetKey::new(1, Address::from([0x11; 20]));
        let second = UnshieldAssetKey::new(1, Address::from([0x22; 20]));

        assert_ne!(
            unshield_element_id(first, "cancel").as_ref(),
            unshield_element_id(second, "cancel").as_ref()
        );
        assert_ne!(
            unshield_element_id(first, "copy-to").as_ref(),
            unshield_element_id(first, "copy-data").as_ref()
        );
    }

    #[test]
    fn send_element_ids_are_asset_scoped() {
        let first = UnshieldAssetKey::new(1, Address::from([0x11; 20]));
        let second = UnshieldAssetKey::new(1, Address::from([0x22; 20]));

        assert_ne!(
            send_element_id(first, "cancel").as_ref(),
            send_element_id(second, "cancel").as_ref()
        );
        assert_ne!(
            send_element_id(first, "copy-to").as_ref(),
            send_element_id(first, "copy-data").as_ref()
        );
    }

    #[test]
    fn display_rows_reverse_utxo_order() {
        let output = ListUtxosOutput {
            chain_id: 1,
            cache_key: "cache".to_string(),
            utxo_count: 3,
            unspent_count: 3,
            spent_count: 0,
            utxos: vec![
                utxo_output("0x1111111111111111111111111111111111111111", "1", false),
                utxo_output("0x2222222222222222222222222222222222222222", "2", false),
                utxo_output("0x3333333333333333333333333333333333333333", "3", false),
            ],
            totals: Vec::new(),
        };

        let rows = display_rows_from_output(&output, "", true);
        let amounts: Vec<_> = rows.iter().map(|row| row.amount.as_str()).collect();
        assert_eq!(amounts, ["3", "2", "1"]);
    }

    #[test]
    fn display_rows_include_spent_utxos() {
        let output = ListUtxosOutput {
            chain_id: 1,
            cache_key: "cache".to_string(),
            utxo_count: 2,
            unspent_count: 1,
            spent_count: 1,
            utxos: vec![
                utxo_output("0x1111111111111111111111111111111111111111", "42", true),
                utxo_output("0x2222222222222222222222222222222222222222", "7", false),
            ],
            totals: Vec::new(),
        };

        let rows = display_rows_from_output(&output, "", true);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].amount, "7");
        assert!(!rows[0].is_spent);
        assert_eq!(rows[0].spent_tx_hash, None);
        assert_eq!(rows[1].amount, "42");
        assert!(rows[1].is_spent);
        assert_eq!(
            rows[1].spent_tx_hash.as_deref(),
            Some("0x2222222222222222222222222222222222222222222222222222222222222222")
        );
    }

    #[test]
    fn display_rows_hide_spent_utxos_when_toggle_off() {
        let output = ListUtxosOutput {
            chain_id: 1,
            cache_key: "cache".to_string(),
            utxo_count: 2,
            unspent_count: 1,
            spent_count: 1,
            utxos: vec![
                utxo_output("0x1111111111111111111111111111111111111111", "42", true),
                utxo_output("0x2222222222222222222222222222222222222222", "7", false),
            ],
            totals: Vec::new(),
        };

        let rows = display_rows_from_output(&output, "", false);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].amount, "7");
        assert!(!rows[0].is_spent);
    }

    #[test]
    fn display_rows_search_matches_source_tx_hash() {
        let output = ListUtxosOutput {
            chain_id: 1,
            cache_key: "cache".to_string(),
            utxo_count: 2,
            unspent_count: 2,
            spent_count: 0,
            utxos: vec![
                utxo_output_with_hashes(
                    "0x1111111111111111111111111111111111111111",
                    "42",
                    false,
                    "0xaAaA000000000000000000000000000000000000000000000000000000000000",
                    None,
                ),
                utxo_output_with_hashes(
                    "0x2222222222222222222222222222222222222222",
                    "7",
                    false,
                    "0xbbbb000000000000000000000000000000000000000000000000000000000000",
                    None,
                ),
            ],
            totals: Vec::new(),
        };

        let rows = display_rows_from_output(&output, "aaaa", true);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].amount, "42");
    }

    #[test]
    fn display_rows_search_matches_spent_tx_hash() {
        let output = ListUtxosOutput {
            chain_id: 1,
            cache_key: "cache".to_string(),
            utxo_count: 2,
            unspent_count: 1,
            spent_count: 1,
            utxos: vec![
                utxo_output_with_hashes(
                    "0x1111111111111111111111111111111111111111",
                    "42",
                    true,
                    "0x3333000000000000000000000000000000000000000000000000000000000000",
                    Some("0xdead000000000000000000000000000000000000000000000000000000000000"),
                ),
                utxo_output_with_hashes(
                    "0x2222222222222222222222222222222222222222",
                    "7",
                    false,
                    "0x4444000000000000000000000000000000000000000000000000000000000000",
                    None,
                ),
            ],
            totals: Vec::new(),
        };

        let rows = display_rows_from_output(&output, "dead", true);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].amount, "42");
        assert!(rows[0].is_spent);
    }

    #[test]
    fn display_rows_search_ignores_spent_visibility_toggle() {
        let output = ListUtxosOutput {
            chain_id: 1,
            cache_key: "cache".to_string(),
            utxo_count: 1,
            unspent_count: 0,
            spent_count: 1,
            utxos: vec![utxo_output_with_hashes(
                "0x1111111111111111111111111111111111111111",
                "42",
                true,
                "0x3333000000000000000000000000000000000000000000000000000000000000",
                Some("0xdead000000000000000000000000000000000000000000000000000000000000"),
            )],
            totals: Vec::new(),
        };

        let rows = display_rows_from_output(&output, "dead", false);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].is_spent);
    }

    #[test]
    fn initial_chain_load_uses_cli_overrides() {
        let options = wallet_options_with_overrides();
        let overrides = chain_load_overrides(&options, 1, ChainLoadSource::Initial);

        assert_eq!(overrides.init_block_number, Some(123));
        assert_eq!(overrides.sync_to_block, Some(456));
        assert!(!overrides.use_indexed_wallet_catch_up);
        assert!(overrides.rewind_wallet_cache);
        assert_eq!(overrides.rpc_url, options.rpc_url);
    }

    #[test]
    fn selected_chain_load_ignores_cli_overrides() {
        let options = wallet_options_with_overrides();
        let overrides = chain_load_overrides(&options, 56, ChainLoadSource::Selection);

        assert_eq!(overrides.init_block_number, None);
        assert_eq!(overrides.sync_to_block, None);
        assert!(overrides.use_indexed_wallet_catch_up);
        assert!(!overrides.rewind_wallet_cache);
        assert_eq!(overrides.rpc_url, None);
    }

    #[test]
    fn selected_initial_chain_reload_ignores_cli_overrides() {
        let options = wallet_options_with_overrides();
        let overrides = chain_load_overrides(&options, 1, ChainLoadSource::Selection);

        assert_eq!(overrides.init_block_number, None);
        assert_eq!(overrides.sync_to_block, None);
        assert!(overrides.use_indexed_wallet_catch_up);
        assert!(!overrides.rewind_wallet_cache);
        assert_eq!(overrides.rpc_url, None);
    }

    #[test]
    fn repair_cache_block_parses_zero_as_deployment() {
        assert_eq!(parse_repair_cache_block("0"), Ok(None));
        assert_eq!(parse_repair_cache_block(""), Ok(None));
        assert_eq!(parse_repair_cache_block(" 24936249 "), Ok(Some(24936249)));
        assert!(parse_repair_cache_block("nope").is_err());
    }

    #[test]
    fn loading_summary_uses_sync_stage_and_percent() {
        let commitments =
            SyncProgressUpdate::new(SyncProgressStage::SynchronizingCommitments, 100, 150, 300);
        let indexing = SyncProgressUpdate::new(SyncProgressStage::IndexingUtxos, 100, 150, 300);

        assert_eq!(
            loading_summary(Some(commitments)),
            "Synchronizing commitments · 25%"
        );
        assert_eq!(loading_summary(Some(indexing)), "Indexing UTXOs · 25%");
        assert_eq!(loading_summary(None), "Preparing wallet sync...");
    }

    #[test]
    fn loading_chain_state_keeps_utxo_table_available() {
        let state = ChainUtxoState::Loading { progress: None };

        assert!(state.renders_table());
        assert!(state.is_syncing());
        assert!(!state.is_ready());
        assert!(state.snapshot().is_none());
    }

    #[test]
    fn progress_detail_clamps_current_block() {
        let progress = SyncProgressUpdate::new(SyncProgressStage::IndexingUtxos, 100, 400, 300);

        assert_eq!(progress_detail(progress), "Block 300 of 300");
    }
}
