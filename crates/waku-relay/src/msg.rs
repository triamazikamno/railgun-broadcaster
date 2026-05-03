use alloy::primitives::ChainId;

const RAILGUN_TOPIC_PREFIX: &str = "/railgun/v2/0-";
const FEES_TOPIC_SUFFIX: &str = "-fees/json";
const TRANSACT_TOPIC_SUFFIX: &str = "-transact/json";
const TRANSACT_RESPONSE_TOPIC_SUFFIX: &str = "-transact-response/json";

#[derive(Debug, serde::Deserialize)]
pub struct Message {
    #[serde(rename = "contentTopic")]
    pub content_topic: String,
    pub payload: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentTopic {
    Fees(ChainId),
    Pong,
    TransactResponse,
    Transact(ChainId),
    Unknown(String),
    Noop,
}

impl ContentTopic {
    #[must_use]
    pub fn fees_topic(chain_id: ChainId) -> String {
        format!("{RAILGUN_TOPIC_PREFIX}{chain_id}{FEES_TOPIC_SUFFIX}")
    }

    #[must_use]
    pub fn transact_topic(chain_id: ChainId) -> String {
        format!("{RAILGUN_TOPIC_PREFIX}{chain_id}{TRANSACT_TOPIC_SUFFIX}")
    }

    #[must_use]
    pub fn transact_response_topic(chain_id: ChainId) -> String {
        format!("{RAILGUN_TOPIC_PREFIX}{chain_id}{TRANSACT_RESPONSE_TOPIC_SUFFIX}")
    }

    #[must_use]
    pub fn parse(value: &str) -> Self {
        if value.ends_with("/proto") {
            return Self::Noop;
        }
        if !value.starts_with("/railgun/v2/") {
            return Self::Unknown(value.to_string());
        }

        if let Some(chain_id) = extract_chain_id(value, FEES_TOPIC_SUFFIX) {
            return Self::Fees(chain_id);
        }
        if extract_chain_id(value, TRANSACT_RESPONSE_TOPIC_SUFFIX).is_some() {
            return Self::TransactResponse;
        }
        if value.ends_with("encrypted-metrics-pong/json") {
            return Self::Pong;
        }
        if let Some(chain_id) = extract_chain_id(value, TRANSACT_TOPIC_SUFFIX) {
            return Self::Transact(chain_id);
        }
        Self::Unknown(value.to_string())
    }
}

impl From<String> for ContentTopic {
    fn from(value: String) -> Self {
        Self::parse(&value)
    }
}

fn extract_chain_id(topic: &str, suffix: &str) -> Option<ChainId> {
    topic
        .strip_prefix(RAILGUN_TOPIC_PREFIX)?
        .strip_suffix(suffix)?
        .parse::<ChainId>()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::ContentTopic;

    #[test]
    fn builders_parse_round_trip() {
        assert_eq!(
            ContentTopic::parse(&ContentTopic::fees_topic(1)),
            ContentTopic::Fees(1)
        );
        assert_eq!(
            ContentTopic::parse(&ContentTopic::transact_topic(42161)),
            ContentTopic::Transact(42161)
        );
        assert_eq!(
            ContentTopic::parse(&ContentTopic::transact_response_topic(137)),
            ContentTopic::TransactResponse
        );
    }

    #[test]
    fn parser_classifies_non_broadcaster_topics() {
        assert_eq!(
            ContentTopic::parse("/waku/2/rs/5/1/proto"),
            ContentTopic::Noop
        );
        assert_eq!(
            ContentTopic::parse("/railgun/v2/encrypted-metrics-pong/json"),
            ContentTopic::Pong
        );
        assert_eq!(
            ContentTopic::parse("/other/v2/0-1-fees/json"),
            ContentTopic::Unknown("/other/v2/0-1-fees/json".to_string())
        );
    }

    #[test]
    fn parser_rejects_malformed_railgun_topics() {
        assert!(matches!(
            ContentTopic::parse("/railgun/v2/0--fees/json"),
            ContentTopic::Unknown(_)
        ));
        assert!(matches!(
            ContentTopic::parse("/railgun/v2/0-1-extra-fees/json"),
            ContentTopic::Unknown(_)
        ));
        assert!(matches!(
            ContentTopic::parse("/railgun/v2/0-NaN-transact/json"),
            ContentTopic::Unknown(_)
        ));
    }
}
