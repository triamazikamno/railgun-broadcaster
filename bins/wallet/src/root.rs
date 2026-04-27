use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::primitives::{Address, U256};
use broadcaster_monitor::{EventRx, Shared};
use chrono::{DateTime, Local, Utc};
use gpui::{
    App, AppContext, Bounds, Context, Entity, Focusable, InteractiveElement, IntoElement,
    KeyBinding, MouseButton, ParentElement, Pixels, Point, Render, SharedString,
    StatefulInteractiveElement, Styled, Window, WindowBounds, WindowOptions, div, img,
    prelude::FluentBuilder as _, px, relative, rgb, size,
};
use gpui_component::{
    Disableable, Root, Sizable, StyledExt,
    button::ButtonVariants,
    input::{InputEvent, InputState},
    popover::Popover,
    resizable::{ResizableState, resizable_panel, v_resizable},
    scroll::ScrollableElement,
    table::{Column, Table, TableDelegate, TableState},
    tooltip::Tooltip,
    v_flex,
};
use railgun_ui::{
    DEFAULT_CHAINS, chain_icon_path, chain_name, format_token_amount, lookup_token, short_address,
    token_icon_path,
};
use reqwest::Url;
use tokio::runtime::Handle;
use tokio::sync::OnceCell;
use ui::clipboard::copy_with_toast;
use ui::controls::{app_button, app_button_base, app_input, app_muted_text, app_strong_text};
use ui::icons;
use ui::logs::{LogStore, LogsPane};
use ui::theme::{self, APP_FONT_FAMILY, APP_TEXT_SIZE};
use wallet_ops::{
    HttpContext, ListUtxosOutput, SyncProgressUpdate, TokenTotal, UtxoOutput,
    ViewWalletChainSessionRequest, WalletSessionStore,
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
const UTXO_AGE_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const SECONDS_PER_MINUTE: u64 = 60;
const SECONDS_PER_HOUR: u64 = 60 * SECONDS_PER_MINUTE;
const SECONDS_PER_DAY: u64 = 24 * SECONDS_PER_HOUR;
const SECONDS_PER_MONTH: u64 = 30 * SECONDS_PER_DAY;
const SECONDS_PER_YEAR: u64 = 365 * SECONDS_PER_DAY;
const TABLE_KEY_CONTEXT: &str = "Table";

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

pub(crate) fn install_utxo_navigation_bindings(app: &mut App) {
    app.bind_keys([
        KeyBinding::new("pageup", UtxoPageUp, Some(TABLE_KEY_CONTEXT)),
        KeyBinding::new("pagedown", UtxoPageDown, Some(TABLE_KEY_CONTEXT)),
        KeyBinding::new("home", UtxoHome, Some(TABLE_KEY_CONTEXT)),
        KeyBinding::new("end", UtxoEnd, Some(TABLE_KEY_CONTEXT)),
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
        let monitor = cx.new(|cx| {
            broadcaster_monitor_gpui::BroadcasterMonitorPane::new(
                monitor, event_rx, chain_ids, window, cx,
            )
        });
        let logs = cx.new(|cx| LogsPane::new(logs, window, cx));
        let root = cx.new(|cx| WalletRoot::new(options, http, runtime, monitor, logs, window, cx));
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

enum ChainUtxoState {
    Idle,
    Loading {
        progress: Option<SyncProgressUpdate>,
    },
    Ready {
        snapshot: Arc<ListUtxosOutput>,
        _session: Arc<wallet_ops::WalletSession>,
    },
    Error(Arc<str>),
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
    monitor: Entity<broadcaster_monitor_gpui::BroadcasterMonitorPane>,
    logs: Entity<LogsPane>,
    active_activity: Activity,
    selected_chain: u64,
    chain_ids: Vec<u64>,
    chain_states: BTreeMap<u64, ChainUtxoState>,
    session_store: Arc<OnceCell<Arc<WalletSessionStore>>>,
    unlock_password_input: Entity<InputState>,
    new_password_input: Entity<InputState>,
    confirm_password_input: Entity<InputState>,
    import_mnemonic_input: Entity<InputState>,
    spend_password_input: Entity<InputState>,
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
            monitor,
            logs,
            active_activity: Activity::Wallet,
            chain_ids,
            chain_states,
            session_store: Arc::new(OnceCell::new()),
            unlock_password_input,
            new_password_input,
            confirm_password_input,
            import_mnemonic_input,
            spend_password_input,
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
                            Some(ChainUtxoState::Ready { .. })
                        ) {
                            root.utxo_table.update(cx, |state, cx| state.refresh(cx));
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
            Some(ChainUtxoState::Loading { .. } | ChainUtxoState::Ready { .. })
        ) && !force
        {
            return;
        }

        let previous_session = if force {
            match self.chain_states.remove(&chain_id) {
                Some(ChainUtxoState::Ready {
                    _session: session, ..
                }) => Some(session),
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
                .start_view_wallet_session(request, rpc_url, &http)
                .await
        });

        cx.spawn(async move |this, cx| {
            loop {
                if progress_rx.changed().await.is_err() {
                    break;
                }
                let progress = *progress_rx.borrow();
                let should_continue = this.update(cx, |root, cx| {
                    let Some(ChainUtxoState::Loading { progress: state }) =
                        root.chain_states.get_mut(&chain_id)
                    else {
                        return false;
                    };
                    *state = progress;
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
            let initial_snapshot = snapshots_rx.borrow().clone();

            let _ = this.update(cx, |root, cx| {
                root.chain_states.insert(
                    chain_id,
                    ChainUtxoState::Ready {
                        snapshot: initial_snapshot,
                        _session: session.clone(),
                    },
                );
                if root.selected_chain == chain_id {
                    root.sync_utxo_table(cx);
                    root.focus_utxo_table_on_render = true;
                }
                cx.notify();
            });

            loop {
                if snapshots_rx.changed().await.is_err() {
                    break;
                }
                let snapshot = snapshots_rx.borrow().clone();
                if this
                    .update(cx, |root, cx| {
                        root.chain_states.insert(
                            chain_id,
                            ChainUtxoState::Ready {
                                snapshot,
                                _session: session.clone(),
                            },
                        );
                        if root.selected_chain == chain_id {
                            root.sync_utxo_table(cx);
                        }
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

    fn sync_utxo_table(&self, cx: &mut Context<'_, Self>) {
        let rows = match self.chain_states.get(&self.selected_chain) {
            Some(ChainUtxoState::Ready { snapshot, .. }) => display_rows_from_output(
                snapshot,
                self.tx_search_query.as_ref(),
                self.show_spent_utxos,
            ),
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
        self.sync_utxo_table(cx);
        if matches!(
            self.chain_states.get(&chain_id),
            Some(ChainUtxoState::Ready { .. })
        ) {
            self.focus_utxo_table_on_render = true;
        }
        self.ensure_chain_load(chain_id, ChainLoadSource::Selection, cx);
        cx.notify();
    }

    fn toggle_spent_visibility(&mut self, cx: &mut Context<'_, Self>) {
        self.show_spent_utxos = !self.show_spent_utxos;
        self.sync_utxo_table(cx);
        cx.notify();
    }

    fn repair_wallet_cache_from_input(&mut self, cx: &mut Context<'_, Self>) -> bool {
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
        if !self.focus_utxo_table_on_render || self.active_activity != Activity::Wallet {
            return;
        }
        if !matches!(
            self.chain_states.get(&self.selected_chain),
            Some(ChainUtxoState::Ready { .. })
        ) {
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

    fn enter_view_unlocked(&mut self, session: DesktopViewSession, cx: &mut Context<'_, Self>) {
        self.view_session = Some(Arc::new(session));
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

    fn lock_vault(&mut self, cx: &mut Context<'_, Self>) {
        if let Some(store) = self.session_store.get().cloned() {
            self.runtime.spawn(async move {
                store.shutdown().await;
            });
        }
        self.view_session = None;
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
                "Wallet",
                self.active_activity == Activity::Wallet,
                false,
                {
                    let root = root.clone();
                    move |_event, _window, cx| {
                        root.update(cx, |root, cx| {
                            root.active_activity = Activity::Wallet;
                            root.focus_utxo_table_on_render = true;
                            cx.notify();
                        });
                    }
                },
            ))
            .child(Self::render_activity_button(
                "activity-broadcaster",
                icons::robot_icon_path(),
                "Broadcaster monitor",
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
            .child(
                div()
                    .flex_1()
                    .min_w(px(0.0))
                    .min_h(px(0.0))
                    .p(px(12.0))
                    .child(self.render_utxo_body(root, window)),
            )
    }

    fn render_wallet_header(&self, root: &Entity<Self>) -> impl IntoElement {
        let lock_root = root.clone();
        let receive_address = self
            .view_session
            .as_ref()
            .and_then(|session| session.receive_address().ok());
        let (summary, totals) = match self.chain_states.get(&self.selected_chain) {
            Some(ChainUtxoState::Ready { snapshot, .. }) => {
                let counts = if snapshot.spent_count == 0 {
                    format!("{} unspent UTXOs", snapshot.unspent_count)
                } else {
                    format!(
                        "{} unspent · {} spent",
                        snapshot.unspent_count, snapshot.spent_count
                    )
                };
                (
                    counts,
                    render_totals_row(self.selected_chain, &snapshot.totals),
                )
            }
            Some(ChainUtxoState::Loading { progress }) => (loading_summary(*progress), None),
            Some(ChainUtxoState::Error(_)) => ("Failed to load UTXOs".to_string(), None),
            _ => ("Ready to load UTXOs".to_string(), None),
        };

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
            .child(self.render_chain_selector(root.clone()))
            .child(app_strong_text("Wallet UTXOs"))
            .child(app_muted_text(SharedString::from(summary)))
            .children(totals)
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
            Some(ChainUtxoState::Loading { .. })
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
            Some(ChainUtxoState::Loading { progress }) => loading_progress(*progress),
            Some(ChainUtxoState::Error(error)) => error_message(error.as_ref()),
            Some(ChainUtxoState::Ready { snapshot, .. }) if snapshot.utxo_count == 0 => {
                centered_message("No UTXOs found")
            }
            Some(ChainUtxoState::Ready { .. }) => div()
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
                    .child(app_input(&self.spend_password_input)),
            )
            .child(
                app_button("wallet-authorize-spend", "Authorize spend")
                    .xsmall()
                    .outline()
                    .p(px(12.0))
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

    fn navigate_utxo_table(&self, navigation: UtxoNavigation, cx: &mut Context<'_, Self>) {
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
}

impl Render for WalletRoot {
    fn render(&mut self, window: &mut Window, cx: &mut Context<'_, Self>) -> impl IntoElement {
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
            .child(self.render_activity_rail(root.clone()))
            .child(
                div()
                    .flex_1()
                    .h_full()
                    .min_w(px(0.0))
                    .min_h(px(0.0))
                    .child(self.render_workspace(root, window)),
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
    source_tx_hash: String,
    source_block_timestamp: u64,
    spent_tx_hash: Option<String>,
    token_address: String,
    is_spent: bool,
}

struct UtxoDelegate {
    rows: Arc<[UtxoDisplayRow]>,
    columns: [Column; 6],
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
            4 => tx_hash_cell(
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

fn centered_message(message: &'static str) -> gpui::Div {
    div()
        .size_full()
        .flex()
        .items_center()
        .justify_center()
        .text_color(rgb(theme::TEXT_SUBTLE))
        .child(message)
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

fn loading_progress(progress: Option<SyncProgressUpdate>) -> gpui::Div {
    let title = progress.map_or("Preparing wallet sync", |progress| progress.stage.label());
    let percent = progress.map_or(0, SyncProgressUpdate::percent);
    let detail = progress.map_or_else(
        || "Waiting for indexed sync progress...".to_string(),
        progress_detail,
    );
    let fill_width = relative(f32::from(percent) / 100.0);

    div()
        .size_full()
        .flex()
        .items_center()
        .justify_center()
        .child(
            div()
                .w(px(460.0))
                .flex()
                .flex_col()
                .gap_3()
                .p(px(18.0))
                .rounded_md()
                .bg(rgb(theme::SURFACE))
                .border_1()
                .border_color(rgb(theme::BORDER))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .child(
                            div()
                                .text_color(rgb(theme::TEXT))
                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                .child(title),
                        )
                        .child(div().flex_1())
                        .child(
                            div()
                                .text_color(rgb(theme::INFO))
                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                .child(SharedString::from(format!("{percent}%"))),
                        ),
                )
                .child(
                    div()
                        .h(px(9.0))
                        .w_full()
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
                        .text_color(rgb(theme::TEXT_MUTED))
                        .text_size(APP_TEXT_SIZE)
                        .child(SharedString::from(detail)),
                ),
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

struct FormattedTokenTotal {
    label: String,
    amount: String,
    icon_path: Option<PathBuf>,
}

fn render_totals_row(chain_id: u64, totals: &[TokenTotal]) -> Option<gpui::Div> {
    if totals.is_empty() {
        return None;
    }

    Some(
        div()
            .flex()
            .items_center()
            .gap_1()
            .text_size(APP_TEXT_SIZE)
            .text_color(rgb(theme::TEXT_MUTED))
            .child(app_muted_text("· Totals:"))
            .children(totals.iter().enumerate().map(move |(ix, total)| {
                let formatted = format_total_parts(chain_id, total);
                let label = SharedString::from(format!("{} {}", formatted.label, formatted.amount));
                let item = token_label_row(label, formatted.icon_path, px(14.0));
                if ix == 0 {
                    div().child(item)
                } else {
                    div().flex().items_center().gap_1().child("·").child(item)
                }
            })),
    )
}

#[cfg(test)]
fn format_total(chain_id: u64, total: &TokenTotal) -> String {
    let formatted = format_total_parts(chain_id, total);
    format!("{} {}", formatted.label, formatted.amount)
}

fn format_total_parts(chain_id: u64, total: &TokenTotal) -> FormattedTokenTotal {
    let Some(address) = parse_address(&total.token) else {
        return FormattedTokenTotal {
            label: total.token.clone(),
            amount: total.total.clone(),
            icon_path: None,
        };
    };
    let Some(token) = lookup_token(chain_id, &address) else {
        return FormattedTokenTotal {
            label: short_address(&address),
            amount: total.total.clone(),
            icon_path: None,
        };
    };
    let amount = U256::from_str_radix(&total.total, 10).map_or_else(
        |_| total.total.clone(),
        |value| format_token_amount(value, token.decimals),
    );
    FormattedTokenTotal {
        label: token.symbol.to_owned(),
        amount,
        icon_path: token_icon_path(chain_id, &address),
    }
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
        source_tx_hash: row.source_tx_hash.clone(),
        source_block_timestamp: row.source_block_timestamp,
        spent_tx_hash: row.spent_tx_hash.clone(),
        token_address: address.to_checksum(None),
        is_spent: row.is_spent,
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
    use std::path::PathBuf;

    use wallet_ops::{ListUtxosOutput, SyncProgressStage, SyncProgressUpdate, UtxoOutput};

    use super::{
        ChainLoadSource, SECONDS_PER_DAY, SECONDS_PER_HOUR, SECONDS_PER_MINUTE, SECONDS_PER_MONTH,
        SECONDS_PER_YEAR, WalletAppOptions, chain_load_overrides, display_rows_from_output,
        format_compact_age, format_total, loading_summary, parse_repair_cache_block,
        progress_detail,
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
            source_tx_hash: source_tx_hash.to_string(),
            source_block_number: 11,
            source_block_timestamp: 1_700_000_011,
            is_spent,
            spent_tx_hash: spent_tx_hash.map(str::to_string),
            spent_block_number: spent_tx_hash.map(|_| 21),
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
        };

        assert_eq!(format_total(1, &total), "USDC 1.23");
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
        let progress =
            SyncProgressUpdate::new(SyncProgressStage::SynchronizingCommitments, 100, 150, 300);

        assert_eq!(
            loading_summary(Some(progress)),
            "Synchronizing commitments · 25%"
        );
    }

    #[test]
    fn progress_detail_clamps_current_block() {
        let progress = SyncProgressUpdate::new(SyncProgressStage::IndexingUtxos, 100, 400, 300);

        assert_eq!(progress_detail(progress), "Block 300 of 300");
    }
}
