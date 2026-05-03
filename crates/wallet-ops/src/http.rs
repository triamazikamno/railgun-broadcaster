use eyre::{Result, WrapErr};
use reqwest::Url;

/// Shared HTTP context built once from an optional proxy and passed into wallet
/// operations that issue network requests.
#[derive(Clone)]
pub struct HttpContext {
    /// Async HTTP client for reqwest and alloy usage.
    pub client: reqwest::Client,
    /// Proxy URL for components that build their own client, such as the
    /// blocking artifact downloader.
    pub proxy_url: Option<Url>,
}

pub fn build_http_client(proxy: Option<&Url>) -> Result<HttpContext> {
    let mut builder = reqwest::Client::builder();
    if let Some(proxy_url) = proxy {
        tracing::info!(%proxy_url, "routing all HTTP traffic through proxy");
        let p = reqwest::Proxy::all(proxy_url.as_str())
            .wrap_err_with(|| format!("invalid proxy URL {proxy_url}"))?;
        builder = builder.proxy(p);
    }
    let client = builder.build().wrap_err("build HTTP client")?;
    Ok(HttpContext {
        client,
        proxy_url: proxy.cloned(),
    })
}
