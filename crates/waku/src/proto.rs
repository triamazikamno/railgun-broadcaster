#[allow(
    clippy::derive_partial_eq_without_eq,
    clippy::doc_markdown,
    clippy::must_use_candidate,
    clippy::missing_const_for_fn
)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/_.rs"));
}

use ahash::AHasher;
pub use generated::*;
use std::hash::{Hash, Hasher};

pub mod message {
    pub use super::{RateLimitProof, WakuMessage};
}

pub mod light_push {
    pub use super::{LightPushRequestV3, LightPushResponseV3, PushRequest, PushResponse, PushRpc};
}

pub mod peer_exchange {
    pub use super::{PeerExchangeQuery, PeerExchangeResponse, PeerExchangeRpc, PeerInfo};
}

pub mod metadata {
    pub use super::{WakuMetadataRequest, WakuMetadataResponse};
}

pub mod filter {
    pub use super::{
        FilterSubscribeRequest, FilterSubscribeResponse, MessagePush, filter_subscribe_request,
    };
}

pub trait HashKey {
    fn hash_key(&self) -> u64;
}

impl HashKey for WakuMessage {
    fn hash_key(&self) -> u64 {
        let mut hasher = AHasher::default();
        self.content_topic.hash(&mut hasher);
        self.payload.hash(&mut hasher);
        hasher.finish()
    }
}
