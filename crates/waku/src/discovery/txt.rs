use super::error::DnsResolveError;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub(super) struct TxtResolver {
    doh_endpoint: String,
    http: Client,
    system: hickory_resolver::TokioResolver,
    cache: Arc<Mutex<HashMap<String, Vec<String>>>>,
}

impl TxtResolver {
    pub(super) fn new(doh_endpoint: String) -> Result<Self, DnsResolveError> {
        let http = Client::builder()
            .user_agent("waku-rust")
            .build()
            .map_err(DnsResolveError::HttpClient)?;

        let system = hickory_resolver::TokioResolver::builder_tokio()?.build();

        Ok(Self {
            doh_endpoint,
            http,
            system,
            cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub(super) async fn resolve_txt(&self, domain: &str) -> Result<Vec<String>, DnsResolveError> {
        if let Some(cached) = self.cache.lock().await.get(domain).cloned() {
            return Ok(cached);
        }

        let res = match self.resolve_txt_doh(domain).await {
            Ok(v) if !v.is_empty() => v,
            _ => self.resolve_txt_system(domain).await?,
        };

        self.cache
            .lock()
            .await
            .insert(domain.to_string(), res.clone());

        Ok(res)
    }

    async fn resolve_txt_system(&self, domain: &str) -> Result<Vec<String>, DnsResolveError> {
        let response = self.system.txt_lookup(domain).await.map_err(|source| {
            DnsResolveError::SystemLookup {
                domain: domain.to_string(),
                source,
            }
        })?;

        Ok(response
            .iter()
            .flat_map(hickory_resolver::proto::rr::rdata::TXT::txt_data)
            .map(|part| String::from_utf8_lossy(part).into_owned())
            .collect())
    }

    async fn resolve_txt_doh(&self, domain: &str) -> Result<Vec<String>, DnsResolveError> {
        #[derive(Debug, Deserialize)]
        struct DnsJsonAnswer {
            data: String,
        }

        #[derive(Debug, Deserialize)]
        struct DnsJsonResponse {
            #[serde(rename = "Answer")]
            answer: Option<Vec<DnsJsonAnswer>>,
        }

        let resp = self
            .http
            .get(&self.doh_endpoint)
            .query(&[("name", domain), ("type", "TXT")])
            .header("accept", "application/dns-json")
            .send()
            .await
            .map_err(DnsResolveError::DohRequest)?;

        let status = resp.status();
        if !status.is_success() {
            return Ok(Vec::new());
        }

        let parsed: DnsJsonResponse = resp.json().await.map_err(DnsResolveError::DohParse)?;

        Ok(parsed
            .answer
            .unwrap_or_default()
            .into_iter()
            .map(|ans| normalize_doh_txt_data(&ans.data))
            .collect())
    }
}

fn normalize_doh_txt_data(s: &str) -> String {
    // Cloudflare DoH JSON encodes TXT as a single string like:
    // "\"part1\" \"part2\"" -> which becomes "part1" "part2" after JSON parsing.
    // We extract and concatenate all quoted chunks.
    let quoted: String = s
        .split('"')
        .enumerate()
        .filter_map(|(i, part)| (i % 2 == 1).then_some(part))
        .collect();

    if quoted.is_empty() {
        s.to_string()
    } else {
        quoted
    }
}
