use alloy::primitives::ChainId;

#[derive(Debug, serde::Deserialize)]
pub struct Message {
    #[serde(rename = "contentTopic")]
    pub content_topic: String,
    pub payload: String,
}

pub enum ContentTopic {
    Fees(),
    Pong,
    TransactResponse(),
    Transact(ChainId),
    Unknown(String),
    Noop,
}

impl From<String> for ContentTopic {
    fn from(value: String) -> Self {
        if value.ends_with("/proto") {
            return Self::Noop;
        }
        if !value.starts_with("/railgun/v2/") {
            return Self::Unknown(value);
        }

        if value.ends_with("-fees/json") {
            if extract_chain_id_from_fees_topic(&value).is_some() {
                return Self::Fees();
            }
        } else if value.ends_with("-transact-response/json") {
            if extract_chain_id_from_fees_topic(&value).is_some() {
                return Self::TransactResponse();
            }
        } else if value.ends_with("encrypted-metrics-pong/json") {
            return Self::Pong;
        } else if value.ends_with("-transact/json")
            && let Some(chain_id) = extract_chain_id_from_fees_topic(&value)
        {
            return Self::Transact(chain_id);
        }
        Self::Unknown(value)
    }
}

fn extract_chain_id_from_fees_topic(topic: &str) -> Option<ChainId> {
    topic
        .split('-')
        .collect::<Vec<&str>>()
        .get(1)
        .and_then(|s| s.parse::<ChainId>().ok())
}
