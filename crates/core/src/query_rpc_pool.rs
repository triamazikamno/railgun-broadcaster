use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use alloy::providers::{Provider, ProviderBuilder};
use alloy_provider::DynProvider;
use rand::prelude::IndexedRandom;
use url::Url;

#[derive(Clone)]
pub struct ProviderHandle {
    pub index: usize,
    pub url: Url,
    pub provider: DynProvider,
}

struct ProviderEntry {
    url: Url,
    provider: DynProvider,
}

pub struct QueryRpcPool {
    providers: Vec<ProviderEntry>,
    cooldown: Duration,
    cooldowns: Mutex<HashMap<usize, Instant>>,
}

impl QueryRpcPool {
    #[must_use]
    pub fn new(urls: Vec<Url>, cooldown: Duration) -> Self {
        let providers = urls
            .into_iter()
            .map(|url| ProviderEntry {
                provider: ProviderBuilder::new().connect_http(url.clone()).erased(),
                url,
            })
            .collect();
        Self {
            providers,
            cooldown,
            cooldowns: Mutex::new(HashMap::new()),
        }
    }

    #[must_use]
    pub fn random_provider(&self) -> Option<ProviderHandle> {
        if self.providers.is_empty() {
            return None;
        }

        let now = Instant::now();
        let mut cooldowns = self
            .cooldowns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cooldowns.retain(|_, until| *until > now);

        let available: Vec<usize> = (0..self.providers.len())
            .filter(|index| !cooldowns.contains_key(index))
            .collect();
        let index = *available.choose(&mut rand::rng())?;
        Some(self.handle(index))
    }

    pub fn mark_bad_provider(&self, handle: &ProviderHandle) {
        let until = Instant::now() + self.cooldown;
        let mut cooldowns = self
            .cooldowns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cooldowns.insert(handle.index, until);
    }

    fn handle(&self, index: usize) -> ProviderHandle {
        let entry = &self.providers[index];
        ProviderHandle {
            index,
            url: entry.url.clone(),
            provider: entry.provider.clone(),
        }
    }
}
