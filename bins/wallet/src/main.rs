// Hex color literals are intentionally written `0xRRGGBB` style.
#![allow(clippy::unreadable_literal)]

mod assets;
mod cli;
mod root;

use broadcaster_monitor::{DEFAULT_EVENT_CAPACITY, event_channel, shared};
use eyre::{Result, WrapErr};
use gpui::{App, Application};
use railgun_ui::DEFAULT_CHAINS;
use tracing::metadata::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};
use ui::logs::{DEFAULT_LOG_CAPACITY, LogStore, UiLogLayer};

use crate::assets::WalletAssets;
use crate::cli::Options;
use crate::root::{WalletAppOptions, install_utxo_navigation_bindings, open_wallet_window};

#[derive(Clone, Debug, Default, Eq, PartialEq, gpui::Action)]
#[action(no_json)]
struct Quit;

fn main() -> Result<()> {
    let opts = Options::from_args();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("wallet-worker")
        .build()
        .wrap_err("build tokio runtime")?;
    let runtime_handle = runtime.handle().clone();

    let monitor = shared();
    let logs = LogStore::new(DEFAULT_LOG_CAPACITY);
    let (event_tx, event_rx) = event_channel(DEFAULT_EVENT_CAPACITY);

    install_tracing(logs.clone())?;

    let chain_ids = DEFAULT_CHAINS.to_vec();
    let runtime_guard = runtime.enter();
    let wallet_options = WalletAppOptions::from(opts);
    let application = Application::new().with_assets(WalletAssets);
    application.run(move |app: &mut App| {
        gpui_component::init(app);
        ui::theme::apply_zenburn_component_theme(app);
        install_quit_behavior(app);
        install_utxo_navigation_bindings(app);
        open_wallet_window(
            app,
            wallet_options.clone(),
            runtime_handle.clone(),
            monitor.clone(),
            event_tx,
            event_rx,
            &chain_ids,
            logs,
        );

        #[cfg(target_os = "macos")]
        app.activate(true);
    });

    drop(runtime_guard);
    drop(runtime);
    Ok(())
}

fn install_tracing(logs: LogStore) -> Result<()> {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();
    let console_layer = fmt::layer()
        .with_target(true)
        .with_level(true)
        .with_writer(std::io::stderr);
    let ui_layer = UiLogLayer::new(logs);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(console_layer)
        .with(ui_layer)
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
            name: "RailOxide".into(),
            items: vec![
                gpui::MenuItem::os_submenu("Services", gpui::SystemMenuType::Services),
                gpui::MenuItem::separator(),
                gpui::MenuItem::action("Quit RailOxide", Quit),
            ],
        }]);
    }
}
