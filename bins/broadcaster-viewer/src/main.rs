mod cli;
mod pprof_server;

use broadcaster_monitor::{DEFAULT_EVENT_CAPACITY, event_channel, shared};
use broadcaster_monitor_waku::{
    DEFAULT_CLUSTER_ID, WakuViewerConfig, build_waku_client, spawn_workers,
};
use eyre::{Result, WrapErr};
use gpui::{App, Application};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};
use ui::logs::{DEFAULT_LOG_CAPACITY, LogStore, UiLogLayer};

use crate::cli::Options;

#[derive(Clone, Debug, Default, Eq, PartialEq, gpui::Action)]
#[action(no_json)]
struct Quit;

fn main() -> Result<()> {
    let opts = Options::from_args();

    // GPUI owns the main thread, so we can't use `#[tokio::main]`.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("broadcaster-viewer-worker")
        .build()
        .wrap_err("build tokio runtime")?;

    let monitor = shared();
    let logs = LogStore::new(DEFAULT_LOG_CAPACITY);
    let (event_tx, event_rx) = event_channel(DEFAULT_EVENT_CAPACITY);

    install_tracing(&opts, logs.clone())?;

    let chain_ids = opts.effective_chain_ids();
    let waku_config = WakuViewerConfig {
        chain_ids: chain_ids.clone(),
        cluster_id: opts.cluster_id,
        doh_endpoint: opts.doh_endpoint.clone(),
        max_peers: opts.max_peers,
        peer_connection_timeout: opts.peer_connection_timeout,
        nwaku_url: opts.nwaku_url.clone(),
    };

    tracing::info!(
        chains = ?chain_ids,
        cluster_id = waku_config.cluster_id.unwrap_or(DEFAULT_CLUSTER_ID),
        nwaku_url = opts.nwaku_url.as_deref().unwrap_or(""),
        "starting broadcaster-viewer"
    );

    // Hold an `EnterGuard` on the main thread so every subsequent call that
    // uses `tokio::spawn` (including `WakuNode::spawn` during waku client
    // construction) sees a running reactor, and so the runtime stays alive
    // across the GPUI event loop.
    let runtime_guard = runtime.enter();

    // Optional diagnostic pprof HTTP server. Off by default; only spawned
    // when `--pprof-listen <addr>` is passed on the command line.
    if let Some(addr) = opts.pprof_listen {
        runtime.spawn(async move {
            if let Err(error) = pprof_server::start(&addr).await {
                tracing::error!(%error, addr = %addr, "pprof server failed");
            }
        });
    }

    // Build the Waku client from CLI inputs (no broadcaster config file is
    // loaded) and spawn the background subscription workers.
    let waku = build_waku_client(&waku_config)?;
    let worker_monitor = monitor.clone();
    runtime.spawn(async move {
        if let Err(error) = spawn_workers(waku_config, waku, worker_monitor, event_tx).await {
            tracing::error!(%error, "viewer background workers failed to start");
        }
    });

    let application = Application::new();
    application.run(move |app: &mut App| {
        // Initialize gpui-component globals (theme, table key bindings,
        // menu/select/popover/etc. state). Must run before any of its
        // widgets render, otherwise `cx.theme()` reads an uninitialized
        // global.
        gpui_component::init(app);
        install_quit_behavior(app);
        broadcaster_monitor_gpui::open_monitor_window(
            app,
            monitor.clone(),
            event_rx,
            chain_ids,
            logs,
        );

        #[cfg(target_os = "macos")]
        app.activate(true);
    });

    drop(runtime_guard);
    drop(runtime);
    Ok(())
}

fn install_tracing(opts: &Options, logs: LogStore) -> Result<()> {
    let filter_directive = opts.effective_debug_level();
    let env_filter = EnvFilter::try_new(&filter_directive)
        .wrap_err_with(|| format!("parse tracing filter `{filter_directive}`"))?;

    let console_layer = fmt::layer()
        .with_target(true)
        .with_level(true)
        .with_writer(std::io::stderr);

    let viewer_layer = UiLogLayer::new(logs);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(console_layer)
        .with(viewer_layer)
        .try_init()
        .map_err(|error| eyre::eyre!("install tracing subscriber: {error}"))?;

    Ok(())
}

fn install_quit_behavior(app: &mut App) {
    app.on_action(|_: &Quit, cx| cx.quit());
    app.on_window_closed(|cx| {
        if cx.windows().is_empty() {
            cx.quit();
        }
    })
    .detach();

    #[cfg(target_os = "macos")]
    {
        app.bind_keys([gpui::KeyBinding::new("cmd-q", Quit, None)]);
        app.set_menus(vec![gpui::Menu {
            name: "Broadcaster Viewer".into(),
            items: vec![
                gpui::MenuItem::os_submenu("Services", gpui::SystemMenuType::Services),
                gpui::MenuItem::separator(),
                gpui::MenuItem::action("Quit Broadcaster Viewer", Quit),
            ],
        }]);
    }
}
