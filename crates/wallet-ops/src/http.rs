use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;

use arti_client::TorClient;
use arti_client::config::TorClientConfigBuilder;
use arti_client::status::BootstrapStatus;
use eyre::{Result, WrapErr, eyre};
use reqwest::Url;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tor_rtcompat::PreferredRuntime;

const ARTI_DIR: &str = "arti";
const ARTI_STATE_DIR: &str = "state";
const ARTI_CACHE_DIR: &str = "cache";
const TOR_STATE_RESET_MARKER_FILE: &str = ".reset-tor-state";
const SOCKS_VERSION: u8 = 0x05;
const SOCKS_NO_AUTH: u8 = 0x00;
const SOCKS_NO_ACCEPTABLE_METHODS: u8 = 0xff;
const SOCKS_CMD_CONNECT: u8 = 0x01;
const SOCKS_ADDR_IPV4: u8 = 0x01;
const SOCKS_ADDR_DOMAIN: u8 = 0x03;
const SOCKS_ADDR_IPV6: u8 = 0x04;
const SOCKS_REPLY_SUCCEEDED: u8 = 0x00;
const SOCKS_REPLY_GENERAL_FAILURE: u8 = 0x01;
const SOCKS_REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const SOCKS_REPLY_ADDR_NOT_SUPPORTED: u8 = 0x08;
const TOR_BOOTSTRAP_PROGRESS_INTERVAL: Duration = Duration::from_millis(250);
const SOCKS_ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

pub type WalletTorClient = TorClient<PreferredRuntime>;
pub type WalletTorClientProvider = Arc<dyn Fn() -> Option<WalletTorClient> + Send + Sync>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalletNetworkMode {
    Tor,
    Proxy,
    Direct,
}

impl WalletNetworkMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tor => "tor",
            Self::Proxy => "proxy",
            Self::Direct => "direct",
        }
    }

    #[must_use]
    pub const fn status_label(self) -> &'static str {
        match self {
            Self::Tor => "Tor",
            Self::Proxy => "Proxy mode",
            Self::Direct => "Direct mode",
        }
    }
}

impl fmt::Display for WalletNetworkMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for WalletNetworkMode {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "tor" => Ok(Self::Tor),
            "proxy" => Ok(Self::Proxy),
            "direct" => Ok(Self::Direct),
            other => Err(format!(
                "unsupported network mode {other:?}; expected tor, proxy, or direct"
            )),
        }
    }
}

pub struct WalletNetworkConfig<'a> {
    pub network_mode: Option<WalletNetworkMode>,
    pub proxy: Option<&'a Url>,
    pub data_dir: &'a Path,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalletNetworkProgressStage {
    ResolvingMode,
    ConfiguringNetwork,
    PreparingTorStorage,
    BootstrappingTor,
    StartingTorBridge,
    Ready,
}

impl WalletNetworkProgressStage {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ResolvingMode => "Resolving network mode",
            Self::ConfiguringNetwork => "Configuring network",
            Self::PreparingTorStorage => "Preparing Tor storage",
            Self::BootstrappingTor => "Bootstrapping Tor",
            Self::StartingTorBridge => "Starting Tor bridge",
            Self::Ready => "Network ready",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalletNetworkProgress {
    pub mode: Option<WalletNetworkMode>,
    pub stage: WalletNetworkProgressStage,
    pub percent: Option<u8>,
    pub detail: Arc<str>,
}

impl WalletNetworkProgress {
    #[must_use]
    pub fn initial() -> Self {
        Self::new(
            None,
            WalletNetworkProgressStage::ResolvingMode,
            None,
            "Preparing wallet network",
        )
    }

    #[must_use]
    pub fn new(
        mode: Option<WalletNetworkMode>,
        stage: WalletNetworkProgressStage,
        percent: Option<u8>,
        detail: impl Into<Arc<str>>,
    ) -> Self {
        Self {
            mode,
            stage,
            percent,
            detail: detail.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalletNetworkHealthState {
    Ready,
    Reconnecting,
    Degraded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalletNetworkHealth {
    pub mode: WalletNetworkMode,
    pub state: WalletNetworkHealthState,
    pub detail: Arc<str>,
}

impl WalletNetworkHealth {
    #[must_use]
    pub fn new(
        mode: WalletNetworkMode,
        state: WalletNetworkHealthState,
        detail: impl Into<Arc<str>>,
    ) -> Self {
        Self {
            mode,
            state,
            detail: detail.into(),
        }
    }

    #[must_use]
    pub const fn label(&self) -> &'static str {
        match (self.mode, self.state) {
            (WalletNetworkMode::Tor, WalletNetworkHealthState::Ready) => "Tor",
            (WalletNetworkMode::Tor, WalletNetworkHealthState::Reconnecting) => "Tor reconnecting",
            (WalletNetworkMode::Tor, WalletNetworkHealthState::Degraded) => "Tor degraded",
            (WalletNetworkMode::Proxy, _) => "Proxy mode",
            (WalletNetworkMode::Direct, _) => "Direct mode",
        }
    }
}

/// Shared wallet network context built once from the selected privacy mode and
/// passed into wallet operations that issue network requests.
#[derive(Clone)]
pub struct HttpContext {
    /// Async HTTP client for reqwest and alloy usage.
    pub client: reqwest::Client,
    /// Proxy URL for components that build their own client, such as the
    /// blocking artifact downloader. In Tor mode this is the internal SOCKS
    /// bridge URL, not a user-supplied external proxy.
    pub proxy_url: Option<Url>,
    pub user_proxy_url: Option<Url>,
    mode: WalletNetworkMode,
    arti_client: Option<WalletTorClient>,
    arti_state_dir: Option<PathBuf>,
    arti_cache_dir: Option<PathBuf>,
    socks_bridge: Option<Arc<ArtiSocksBridge>>,
    fail_closed: bool,
}

impl HttpContext {
    #[must_use]
    pub const fn network_mode(&self) -> WalletNetworkMode {
        self.mode
    }

    #[must_use]
    pub const fn fail_closed(&self) -> bool {
        self.fail_closed
    }

    #[must_use]
    pub const fn network_status_label(&self) -> &'static str {
        self.mode.status_label()
    }

    #[must_use]
    pub fn network_status_detail(&self) -> String {
        self.network_health().detail.to_string()
    }

    #[must_use]
    pub fn network_health(&self) -> WalletNetworkHealth {
        match self.mode {
            WalletNetworkMode::Tor => self.tor_network_health(),
            WalletNetworkMode::Proxy | WalletNetworkMode::Direct => WalletNetworkHealth::new(
                self.mode,
                WalletNetworkHealthState::Ready,
                self.configured_network_status_detail(),
            ),
        }
    }

    fn configured_network_status_detail(&self) -> String {
        match self.mode {
            WalletNetworkMode::Tor => match self.proxy_url.as_ref() {
                Some(proxy) => format!(
                    "Ready. HTTP/RPC session #{} is routed through {proxy}",
                    self.tor_session_generation()
                ),
                None => "HTTP bridge is unavailable".to_string(),
            },
            WalletNetworkMode::Proxy => match self.user_proxy_url.as_ref() {
                Some(proxy) => format!("HTTP is routed through {proxy}"),
                None => "Missing proxy URL".to_string(),
            },
            WalletNetworkMode::Direct => {
                "Not Tor-protected; outbound requests use the network directly".to_string()
            }
        }
    }

    fn tor_network_health(&self) -> WalletNetworkHealth {
        let Some(arti_client) = self.arti_client() else {
            return WalletNetworkHealth::new(
                WalletNetworkMode::Tor,
                WalletNetworkHealthState::Degraded,
                "Degraded. Tor client is unavailable",
            );
        };

        self.tor_network_health_for_status(&arti_client.bootstrap_status())
    }

    fn tor_network_health_for_status(&self, status: &BootstrapStatus) -> WalletNetworkHealth {
        if status.ready_for_traffic() {
            return WalletNetworkHealth::new(
                WalletNetworkMode::Tor,
                WalletNetworkHealthState::Ready,
                self.configured_network_status_detail(),
            );
        }

        let (state, prefix) = if status.blocked().is_some() {
            (WalletNetworkHealthState::Degraded, "Degraded")
        } else {
            (WalletNetworkHealthState::Reconnecting, "Reconnecting")
        };

        WalletNetworkHealth::new(WalletNetworkMode::Tor, state, format!("{prefix}. {status}"))
    }

    #[must_use]
    pub fn arti_client(&self) -> Option<WalletTorClient> {
        if let Some(socks_bridge) = self.socks_bridge.as_ref() {
            match socks_bridge.active_client() {
                Ok(client) => return Some(client),
                Err(error) => {
                    tracing::warn!(%error, "failed to read active Tor session client");
                }
            }
        }
        self.arti_client.clone()
    }

    #[must_use]
    pub fn arti_client_provider(&self) -> Option<WalletTorClientProvider> {
        if let Some(socks_bridge) = self.socks_bridge.as_ref() {
            let active_client = Arc::clone(&socks_bridge.active_client);
            return Some(Arc::new(move || {
                active_client.read().ok().map(|client| client.clone())
            }));
        }

        let arti_client = self.arti_client.clone()?;
        Some(Arc::new(move || Some(arti_client.clone())))
    }

    pub fn start_new_tor_session(&self) -> Result<u64> {
        if self.mode != WalletNetworkMode::Tor {
            return Err(eyre!("new Tor session is only available in Tor mode"));
        }
        let socks_bridge = self
            .socks_bridge
            .as_ref()
            .ok_or_else(|| eyre!("new Tor session requires the internal SOCKS bridge"))?;
        socks_bridge.new_isolated_session()
    }

    #[must_use]
    pub fn tor_session_generation(&self) -> u64 {
        self.socks_bridge
            .as_ref()
            .map_or(0, |socks_bridge| socks_bridge.session_generation())
    }

    #[must_use]
    pub fn arti_state_dir(&self) -> Option<&Path> {
        self.arti_state_dir.as_deref()
    }

    #[must_use]
    pub fn arti_cache_dir(&self) -> Option<&Path> {
        self.arti_cache_dir.as_deref()
    }

    #[must_use]
    pub const fn has_internal_socks_bridge(&self) -> bool {
        self.socks_bridge.is_some()
    }

    #[cfg(test)]
    pub(crate) fn direct_for_tests() -> Self {
        Self {
            client: reqwest::Client::new(),
            proxy_url: None,
            user_proxy_url: None,
            mode: WalletNetworkMode::Direct,
            arti_client: None,
            arti_state_dir: None,
            arti_cache_dir: None,
            socks_bridge: None,
            fail_closed: false,
        }
    }
}

/// Compatibility constructor for non-wallet call sites. Wallet binaries should
/// use [`build_wallet_network_context`] so the default is built-in Tor.
pub fn build_http_client(proxy: Option<&Url>) -> Result<HttpContext> {
    let mode = if proxy.is_some() {
        WalletNetworkMode::Proxy
    } else {
        WalletNetworkMode::Direct
    };
    build_reqwest_context(mode, proxy.cloned(), proxy.cloned(), None, None, None, None)
}

pub fn request_tor_state_reset(data_dir: &Path) -> Result<PathBuf> {
    std::fs::create_dir_all(data_dir)
        .wrap_err_with(|| format!("create wallet data directory {}", data_dir.display()))?;
    let marker_path = tor_state_reset_marker_path(data_dir);
    std::fs::write(
        &marker_path,
        b"Reset built-in Tor state on next wallet startup. Wallet data is not deleted.\n",
    )
    .wrap_err_with(|| format!("write Tor state reset marker {}", marker_path.display()))?;
    Ok(marker_path)
}

pub async fn build_wallet_network_context(config: WalletNetworkConfig<'_>) -> Result<HttpContext> {
    build_wallet_network_context_inner(config, None).await
}

pub async fn build_wallet_network_context_with_progress(
    config: WalletNetworkConfig<'_>,
    progress_tx: watch::Sender<WalletNetworkProgress>,
) -> Result<HttpContext> {
    build_wallet_network_context_inner(config, Some(progress_tx)).await
}

async fn build_wallet_network_context_inner(
    config: WalletNetworkConfig<'_>,
    progress_tx: Option<watch::Sender<WalletNetworkProgress>>,
) -> Result<HttpContext> {
    let mode = resolve_wallet_network_mode(config.network_mode, config.proxy)?;
    send_network_progress(
        progress_tx.as_ref(),
        WalletNetworkProgress::new(
            Some(mode),
            WalletNetworkProgressStage::ResolvingMode,
            Some(0),
            format!("Using {} network mode", mode.as_str()),
        ),
    );
    match mode {
        WalletNetworkMode::Tor => build_tor_context(config.data_dir, progress_tx.as_ref()).await,
        WalletNetworkMode::Proxy => {
            send_network_progress(
                progress_tx.as_ref(),
                WalletNetworkProgress::new(
                    Some(WalletNetworkMode::Proxy),
                    WalletNetworkProgressStage::ConfiguringNetwork,
                    Some(50),
                    "Configuring proxy-routed wallet HTTP client",
                ),
            );
            let context = build_reqwest_context(
                WalletNetworkMode::Proxy,
                config.proxy.cloned(),
                config.proxy.cloned(),
                None,
                None,
                None,
                None,
            )?;
            send_network_ready(progress_tx.as_ref(), &context);
            Ok(context)
        }
        WalletNetworkMode::Direct => {
            send_network_progress(
                progress_tx.as_ref(),
                WalletNetworkProgress::new(
                    Some(WalletNetworkMode::Direct),
                    WalletNetworkProgressStage::ConfiguringNetwork,
                    Some(50),
                    "Configuring direct wallet HTTP client",
                ),
            );
            let context = build_reqwest_context(
                WalletNetworkMode::Direct,
                None,
                None,
                None,
                None,
                None,
                None,
            )?;
            send_network_ready(progress_tx.as_ref(), &context);
            Ok(context)
        }
    }
}

pub fn resolve_wallet_network_mode(
    network_mode: Option<WalletNetworkMode>,
    proxy: Option<&Url>,
) -> Result<WalletNetworkMode> {
    match (network_mode, proxy) {
        (None, None) => Ok(WalletNetworkMode::Tor),
        (None | Some(WalletNetworkMode::Proxy), Some(_)) => Ok(WalletNetworkMode::Proxy),
        (Some(WalletNetworkMode::Proxy), None) => Err(eyre!(
            "--network-mode proxy requires --proxy <url> so proxy routing can fail closed"
        )),
        (Some(WalletNetworkMode::Tor), Some(_)) => Err(eyre!(
            "--network-mode tor cannot be combined with --proxy; omit --proxy to use built-in Tor"
        )),
        (Some(WalletNetworkMode::Direct), Some(_)) => Err(eyre!(
            "--network-mode direct cannot be combined with --proxy; remove --proxy or select --network-mode proxy"
        )),
        (Some(mode), None) => Ok(mode),
    }
}

async fn build_tor_context(
    data_dir: &Path,
    progress_tx: Option<&watch::Sender<WalletNetworkProgress>>,
) -> Result<HttpContext> {
    let arti_base = data_dir.join(ARTI_DIR);
    let state_dir = arti_base.join(ARTI_STATE_DIR);
    let cache_dir = arti_base.join(ARTI_CACHE_DIR);
    send_network_progress(
        progress_tx,
        WalletNetworkProgress::new(
            Some(WalletNetworkMode::Tor),
            WalletNetworkProgressStage::PreparingTorStorage,
            Some(5),
            format!("Preparing Arti state under {}", arti_base.display()),
        ),
    );
    consume_requested_tor_state_reset(data_dir, &arti_base)?;
    std::fs::create_dir_all(&state_dir)
        .wrap_err_with(|| format!("create Arti state directory {}", state_dir.display()))?;
    std::fs::create_dir_all(&cache_dir)
        .wrap_err_with(|| format!("create Arti cache directory {}", cache_dir.display()))?;

    tracing::info!(
        state_dir = %state_dir.display(),
        cache_dir = %cache_dir.display(),
        "bootstrapping built-in Tor network context"
    );
    let tor_config = TorClientConfigBuilder::from_directories(&state_dir, &cache_dir)
        .build()
        .wrap_err("build Arti client config")?;
    send_network_progress(
        progress_tx,
        WalletNetworkProgress::new(
            Some(WalletNetworkMode::Tor),
            WalletNetworkProgressStage::BootstrappingTor,
            Some(10),
            "Starting Arti bootstrap",
        ),
    );
    let arti_client = TorClient::builder()
        .config(tor_config)
        .create_unbootstrapped_async()
        .await
        .wrap_err("create unbootstrapped Arti client")?;
    bootstrap_tor_client(&arti_client, progress_tx).await?;
    send_network_progress(
        progress_tx,
        WalletNetworkProgress::new(
            Some(WalletNetworkMode::Tor),
            WalletNetworkProgressStage::StartingTorBridge,
            Some(95),
            "Starting internal Arti SOCKS bridge",
        ),
    );
    let socks_bridge = Arc::new(
        ArtiSocksBridge::start(arti_client.clone())
            .await
            .wrap_err("start internal Arti SOCKS bridge")?,
    );
    let proxy_url = Url::parse(&format!("socks5h://{}", socks_bridge.local_addr()))
        .wrap_err("build internal Arti SOCKS proxy URL")?;

    tracing::info!(proxy_url = %proxy_url, "built-in Tor network context ready");
    let context = build_reqwest_context(
        WalletNetworkMode::Tor,
        Some(proxy_url),
        None,
        Some(arti_client),
        Some(state_dir),
        Some(cache_dir),
        Some(socks_bridge),
    )?;
    send_network_ready(progress_tx, &context);
    Ok(context)
}

fn tor_state_reset_marker_path(data_dir: &Path) -> PathBuf {
    data_dir.join(TOR_STATE_RESET_MARKER_FILE)
}

fn consume_requested_tor_state_reset(data_dir: &Path, arti_base: &Path) -> Result<()> {
    let marker_path = tor_state_reset_marker_path(data_dir);
    if !marker_path
        .try_exists()
        .wrap_err_with(|| format!("check Tor state reset marker {}", marker_path.display()))?
    {
        return Ok(());
    }

    tracing::warn!(
        marker_path = %marker_path.display(),
        arti_dir = %arti_base.display(),
        "resetting built-in Tor state before startup"
    );
    if arti_base
        .try_exists()
        .wrap_err_with(|| format!("check Arti directory {}", arti_base.display()))?
    {
        std::fs::remove_dir_all(arti_base)
            .wrap_err_with(|| format!("remove Arti directory {}", arti_base.display()))?;
    }
    std::fs::remove_file(&marker_path)
        .wrap_err_with(|| format!("remove Tor state reset marker {}", marker_path.display()))?;
    Ok(())
}

async fn bootstrap_tor_client(
    arti_client: &WalletTorClient,
    progress_tx: Option<&watch::Sender<WalletNetworkProgress>>,
) -> Result<()> {
    let mut ticker = tokio::time::interval(TOR_BOOTSTRAP_PROGRESS_INTERVAL);
    let bootstrap = arti_client.bootstrap();
    tokio::pin!(bootstrap);
    loop {
        tokio::select! {
            result = &mut bootstrap => {
                result.wrap_err("bootstrap built-in Tor")?;
                send_network_progress(
                    progress_tx,
                    WalletNetworkProgress::new(
                        Some(WalletNetworkMode::Tor),
                        WalletNetworkProgressStage::BootstrappingTor,
                        Some(90),
                        "Tor bootstrap complete",
                    ),
                );
                return Ok(());
            }
            _ = ticker.tick() => {
                let status = arti_client.bootstrap_status();
                send_network_progress(
                    progress_tx,
                    WalletNetworkProgress::new(
                        Some(WalletNetworkMode::Tor),
                        WalletNetworkProgressStage::BootstrappingTor,
                        Some(tor_bootstrap_percent(status.as_frac())),
                        status.to_string(),
                    ),
                );
            }
        }
    }
}

fn send_network_ready(
    progress_tx: Option<&watch::Sender<WalletNetworkProgress>>,
    context: &HttpContext,
) {
    send_network_progress(
        progress_tx,
        WalletNetworkProgress::new(
            Some(context.network_mode()),
            WalletNetworkProgressStage::Ready,
            Some(100),
            context.network_status_detail(),
        ),
    );
}

fn send_network_progress(
    progress_tx: Option<&watch::Sender<WalletNetworkProgress>>,
    progress: WalletNetworkProgress,
) {
    if let Some(progress_tx) = progress_tx {
        let _ = progress_tx.send(progress);
    }
}

fn tor_bootstrap_percent(frac: f32) -> u8 {
    let raw = rounded_percent(frac);
    let scaled = 10_u16 + (u16::from(raw) * 80 / 100);
    u8::try_from(scaled).unwrap_or(90)
}

fn rounded_percent(frac: f32) -> u8 {
    let rounded = (frac.clamp(0.0, 1.0) * 100.0).round();
    let mut percent = 0_u8;
    while f32::from(percent) < rounded && percent < 100 {
        percent += 1;
    }
    percent
}

fn build_reqwest_context(
    mode: WalletNetworkMode,
    proxy_url: Option<Url>,
    user_proxy_url: Option<Url>,
    arti_client: Option<WalletTorClient>,
    arti_state_dir: Option<PathBuf>,
    arti_cache_dir: Option<PathBuf>,
    socks_bridge: Option<Arc<ArtiSocksBridge>>,
) -> Result<HttpContext> {
    let mut builder = reqwest::Client::builder();
    if let Some(proxy_url) = &proxy_url {
        tracing::info!(network_mode = %mode, %proxy_url, "routing wallet HTTP traffic through proxy");
        let proxy = reqwest::Proxy::all(proxy_url.as_str())
            .wrap_err_with(|| format!("invalid proxy URL {proxy_url}"))?;
        builder = builder.proxy(proxy);
    }
    if mode == WalletNetworkMode::Tor {
        builder = builder.pool_max_idle_per_host(0);
    }
    if mode == WalletNetworkMode::Direct {
        tracing::warn!(
            "wallet direct network mode selected; outbound requests are not Tor-protected"
        );
    }
    let client = builder.build().wrap_err("build HTTP client")?;
    Ok(HttpContext {
        client,
        proxy_url,
        user_proxy_url,
        mode,
        arti_client,
        arti_state_dir,
        arti_cache_dir,
        socks_bridge,
        fail_closed: mode != WalletNetworkMode::Direct,
    })
}

struct ArtiSocksBridge {
    local_addr: SocketAddr,
    active_client: Arc<RwLock<WalletTorClient>>,
    session_generation: AtomicU64,
    shutdown_tx: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl ArtiSocksBridge {
    async fn start(arti_client: WalletTorClient) -> Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .wrap_err("bind internal Arti SOCKS bridge")?;
        let local_addr = listener
            .local_addr()
            .wrap_err("read internal Arti SOCKS bridge address")?;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let active_client = Arc::new(RwLock::new(arti_client));
        let task = tokio::spawn(run_arti_socks_bridge(
            listener,
            Arc::clone(&active_client),
            shutdown_rx,
        ));
        Ok(Self {
            local_addr,
            active_client,
            session_generation: AtomicU64::new(1),
            shutdown_tx,
            task,
        })
    }

    const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    fn active_client(&self) -> Result<WalletTorClient> {
        self.active_client
            .read()
            .map(|client| client.clone())
            .map_err(|_| eyre!("active Tor session client lock is poisoned"))
    }

    fn new_isolated_session(&self) -> Result<u64> {
        let isolated_client = self.active_client()?.isolated_client();
        let mut active_client = self
            .active_client
            .write()
            .map_err(|_| eyre!("active Tor session client lock is poisoned"))?;
        *active_client = isolated_client;
        Ok(self.session_generation.fetch_add(1, Ordering::Relaxed) + 1)
    }

    fn session_generation(&self) -> u64 {
        self.session_generation.load(Ordering::Relaxed)
    }
}

impl Drop for ArtiSocksBridge {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        self.task.abort();
    }
}

async fn run_arti_socks_bridge(
    listener: TcpListener,
    active_client: Arc<RwLock<WalletTorClient>>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, peer_addr)) => {
                        let arti_client = match active_client.read() {
                            Ok(arti_client) => arti_client.clone(),
                            Err(error) => {
                                tracing::warn!(%peer_addr, %error, "active Tor session client lock is poisoned");
                                continue;
                            }
                        };
                        tokio::spawn(async move {
                            if let Err(error) = handle_socks_connection(stream, arti_client).await {
                                tracing::debug!(%peer_addr, %error, "internal Arti SOCKS connection failed");
                            }
                        });
                    }
                    Err(error) => {
                        tracing::warn!(%error, "internal Arti SOCKS accept failed; retrying");
                        if !wait_after_socks_accept_error(&mut shutdown_rx).await {
                            break;
                        }
                    }
                }
            }
        }
    }
}

async fn wait_after_socks_accept_error(shutdown_rx: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        changed = shutdown_rx.changed() => changed.is_ok() && !*shutdown_rx.borrow(),
        () = tokio::time::sleep(SOCKS_ACCEPT_ERROR_BACKOFF) => true,
    }
}

async fn handle_socks_connection(
    mut inbound: TcpStream,
    arti_client: WalletTorClient,
) -> Result<()> {
    negotiate_socks_no_auth(&mut inbound).await?;
    let target = read_socks_connect_target(&mut inbound).await?;
    let outbound = match arti_client
        .connect((target.host.as_str(), target.port))
        .await
    {
        Ok(outbound) => outbound,
        Err(error) => {
            send_socks_reply(&mut inbound, SOCKS_REPLY_GENERAL_FAILURE).await?;
            return Err(eyre!(
                "connect to {}:{} over Arti: {error}",
                target.host,
                target.port
            ));
        }
    };
    send_socks_reply(&mut inbound, SOCKS_REPLY_SUCCEEDED).await?;
    let mut outbound = outbound;
    tokio::io::copy_bidirectional(&mut inbound, &mut outbound)
        .await
        .wrap_err("relay SOCKS stream through Arti")?;
    Ok(())
}

async fn negotiate_socks_no_auth(inbound: &mut TcpStream) -> Result<()> {
    let mut header = [0_u8; 2];
    inbound
        .read_exact(&mut header)
        .await
        .wrap_err("read SOCKS greeting")?;
    if header[0] != SOCKS_VERSION {
        return Err(eyre!("unsupported SOCKS version {}", header[0]));
    }
    let mut methods = vec![0_u8; usize::from(header[1])];
    inbound
        .read_exact(&mut methods)
        .await
        .wrap_err("read SOCKS auth methods")?;
    if !methods.contains(&SOCKS_NO_AUTH) {
        inbound
            .write_all(&[SOCKS_VERSION, SOCKS_NO_ACCEPTABLE_METHODS])
            .await
            .wrap_err("write SOCKS auth rejection")?;
        return Err(eyre!("SOCKS client did not offer no-auth mode"));
    }
    inbound
        .write_all(&[SOCKS_VERSION, SOCKS_NO_AUTH])
        .await
        .wrap_err("write SOCKS auth selection")?;
    Ok(())
}

struct SocksTarget {
    host: String,
    port: u16,
}

async fn read_socks_connect_target(inbound: &mut TcpStream) -> Result<SocksTarget> {
    let mut header = [0_u8; 4];
    inbound
        .read_exact(&mut header)
        .await
        .wrap_err("read SOCKS connect header")?;
    if header[0] != SOCKS_VERSION {
        send_socks_reply(inbound, SOCKS_REPLY_GENERAL_FAILURE).await?;
        return Err(eyre!("unsupported SOCKS request version {}", header[0]));
    }
    if header[1] != SOCKS_CMD_CONNECT {
        send_socks_reply(inbound, SOCKS_REPLY_COMMAND_NOT_SUPPORTED).await?;
        return Err(eyre!("unsupported SOCKS command {}", header[1]));
    }
    let host = match header[3] {
        SOCKS_ADDR_IPV4 => {
            let mut addr = [0_u8; 4];
            inbound
                .read_exact(&mut addr)
                .await
                .wrap_err("read SOCKS IPv4 address")?;
            Ipv4Addr::from(addr).to_string()
        }
        SOCKS_ADDR_DOMAIN => {
            let len = inbound
                .read_u8()
                .await
                .wrap_err("read SOCKS domain length")?;
            let mut domain = vec![0_u8; usize::from(len)];
            inbound
                .read_exact(&mut domain)
                .await
                .wrap_err("read SOCKS domain")?;
            String::from_utf8(domain).wrap_err("SOCKS domain is not UTF-8")?
        }
        SOCKS_ADDR_IPV6 => {
            let mut addr = [0_u8; 16];
            inbound
                .read_exact(&mut addr)
                .await
                .wrap_err("read SOCKS IPv6 address")?;
            Ipv6Addr::from(addr).to_string()
        }
        other => {
            send_socks_reply(inbound, SOCKS_REPLY_ADDR_NOT_SUPPORTED).await?;
            return Err(eyre!("unsupported SOCKS address type {other}"));
        }
    };
    let port = inbound
        .read_u16()
        .await
        .wrap_err("read SOCKS target port")?;
    Ok(SocksTarget { host, port })
}

async fn send_socks_reply(inbound: &mut TcpStream, reply: u8) -> Result<()> {
    inbound
        .write_all(&[
            SOCKS_VERSION,
            reply,
            0x00,
            SOCKS_ADDR_IPV4,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ])
        .await
        .wrap_err("write SOCKS reply")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn proxy_url() -> Url {
        Url::parse("socks5h://127.0.0.1:9050").expect("valid proxy URL")
    }

    fn test_data_dir(name: &str) -> PathBuf {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "wallet-ops-{name}-{}-{timestamp}",
            std::process::id()
        ))
    }

    #[test]
    fn default_wallet_network_mode_is_tor() {
        assert_eq!(
            resolve_wallet_network_mode(None, None).expect("mode"),
            WalletNetworkMode::Tor
        );
    }

    #[test]
    fn proxy_without_explicit_mode_implies_proxy_mode() {
        let proxy = proxy_url();
        assert_eq!(
            resolve_wallet_network_mode(None, Some(&proxy)).expect("mode"),
            WalletNetworkMode::Proxy
        );
    }

    #[test]
    fn explicit_proxy_requires_proxy_url() {
        assert!(
            resolve_wallet_network_mode(Some(WalletNetworkMode::Proxy), None)
                .expect_err("proxy URL required")
                .to_string()
                .contains("requires --proxy")
        );
    }

    #[test]
    fn proxy_conflicts_with_tor_and_direct_modes() {
        let proxy = proxy_url();
        assert!(resolve_wallet_network_mode(Some(WalletNetworkMode::Tor), Some(&proxy)).is_err());
        assert!(
            resolve_wallet_network_mode(Some(WalletNetworkMode::Direct), Some(&proxy)).is_err()
        );
    }

    #[test]
    fn direct_network_health_is_ready() {
        let health = HttpContext::direct_for_tests().network_health();
        assert_eq!(health.mode, WalletNetworkMode::Direct);
        assert_eq!(health.state, WalletNetworkHealthState::Ready);
        assert_eq!(health.label(), "Direct mode");
    }

    #[test]
    fn proxy_network_health_is_ready() {
        let proxy = proxy_url();
        let context = build_reqwest_context(
            WalletNetworkMode::Proxy,
            Some(proxy.clone()),
            Some(proxy),
            None,
            None,
            None,
            None,
        )
        .expect("proxy context");
        let health = context.network_health();
        assert_eq!(health.mode, WalletNetworkMode::Proxy);
        assert_eq!(health.state, WalletNetworkHealthState::Ready);
        assert_eq!(health.label(), "Proxy mode");
    }

    #[test]
    fn tor_network_health_without_client_is_degraded() {
        let context = build_reqwest_context(
            WalletNetworkMode::Tor,
            Some(proxy_url()),
            None,
            None,
            None,
            None,
            None,
        )
        .expect("tor context");
        let health = context.network_health();
        assert_eq!(health.mode, WalletNetworkMode::Tor);
        assert_eq!(health.state, WalletNetworkHealthState::Degraded);
        assert_eq!(health.label(), "Tor degraded");
        assert!(health.detail.contains("unavailable"));
    }

    #[test]
    fn start_new_tor_session_requires_tor_mode() {
        let error = HttpContext::direct_for_tests()
            .start_new_tor_session()
            .expect_err("direct mode cannot start Tor sessions");
        assert!(error.to_string().contains("only available in Tor mode"));
    }

    #[test]
    fn start_new_tor_session_requires_internal_socks_bridge() {
        let context = build_reqwest_context(
            WalletNetworkMode::Tor,
            Some(proxy_url()),
            None,
            None,
            None,
            None,
            None,
        )
        .expect("tor context");
        assert_eq!(context.tor_session_generation(), 0);
        let error = context
            .start_new_tor_session()
            .expect_err("Tor sessions require the internal SOCKS bridge");
        assert!(error.to_string().contains("internal SOCKS bridge"));
    }

    #[test]
    fn socks_accept_error_retry_continues_without_shutdown() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let (_shutdown_tx, mut shutdown_rx) = watch::channel(false);
            let should_continue = tokio::time::timeout(
                SOCKS_ACCEPT_ERROR_BACKOFF * 2,
                wait_after_socks_accept_error(&mut shutdown_rx),
            )
            .await
            .expect("accept error backoff returns");
            assert!(should_continue);
        });
    }

    #[test]
    fn socks_accept_error_retry_stops_on_shutdown() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
            shutdown_tx.send(true).expect("send shutdown");
            let should_continue = tokio::time::timeout(
                SOCKS_ACCEPT_ERROR_BACKOFF * 2,
                wait_after_socks_accept_error(&mut shutdown_rx),
            )
            .await
            .expect("shutdown returns");
            assert!(!should_continue);
        });
    }

    #[test]
    fn request_tor_state_reset_creates_marker() {
        let data_dir = test_data_dir("reset-marker");
        let marker = request_tor_state_reset(&data_dir).expect("request Tor reset");
        assert_eq!(marker, tor_state_reset_marker_path(&data_dir));
        let marker_text = std::fs::read_to_string(&marker).expect("read marker");
        assert!(marker_text.contains("Reset built-in Tor state"));
        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[test]
    fn consume_requested_tor_state_reset_removes_only_arti_and_marker() {
        let data_dir = test_data_dir("reset-consume");
        let arti_base = data_dir.join(ARTI_DIR);
        let wallet_file = data_dir.join("wallet.db");
        std::fs::create_dir_all(arti_base.join(ARTI_STATE_DIR)).expect("create Arti state");
        std::fs::write(arti_base.join(ARTI_STATE_DIR).join("state"), b"state")
            .expect("write Arti state");
        std::fs::write(&wallet_file, b"wallet").expect("write wallet file");
        let marker = request_tor_state_reset(&data_dir).expect("request Tor reset");

        consume_requested_tor_state_reset(&data_dir, &arti_base).expect("consume Tor reset");

        assert!(!marker.exists());
        assert!(!arti_base.exists());
        assert_eq!(
            std::fs::read(&wallet_file).expect("read wallet file"),
            b"wallet"
        );
        let _ = std::fs::remove_dir_all(&data_dir);
    }
}
