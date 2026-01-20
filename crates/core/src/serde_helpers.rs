pub mod decimal_map {
    use alloy::primitives::{Address, U256};
    use serde::{Deserialize, Deserializer, Serializer};
    use std::collections::HashMap;

    pub fn serialize<S>(map: &HashMap<Address, U256>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeMap;
        let mut ser_map = serializer.serialize_map(Some(map.len()))?;
        for (k, v) in map {
            ser_map.serialize_entry(k, &v.to_string())?;
        }
        ser_map.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<Address, U256>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let map: HashMap<Address, String> = HashMap::deserialize(deserializer)?;
        map.into_iter()
            .map(|(k, v)| {
                v.parse::<U256>()
                    .map(|u| (k, u))
                    .map_err(serde::de::Error::custom)
            })
            .collect()
    }
}

pub mod checksum_address {
    use alloy::primitives::Address;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(address: &Address, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&address.to_checksum(None))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Address, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

pub mod hex_string {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

pub mod hex_array32 {
    use serde::{Deserializer, de};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;

        impl de::Visitor<'_> for Visitor {
            type Value = [u8; 32];

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a 64-character hex string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let bytes = hex::decode(v).map_err(E::custom)?;
                let len = bytes.len();
                bytes
                    .try_into()
                    .map_err(|_| E::custom(format!("expected 32 bytes, got {len}")))
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}
