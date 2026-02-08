use alloy::primitives::U256;
use serde::Deserializer;
use serde::de::{self, Visitor};
use std::fmt;

pub(crate) mod ether_value {
    use super::{Deserializer, U256, Visitor, de, fmt};
    use alloy_dyn_abi::{DynSolType, DynSolValue};

    pub(crate) fn parse_ether_value(value: &str) -> Result<U256, String> {
        if let Some(hex) = value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
        {
            return U256::from_str_radix(hex, 16).map_err(|err| err.to_string());
        }

        let value = DynSolType::Uint(256)
            .coerce_str(value)
            .map_err(|err| err.to_string())?;

        match value {
            DynSolValue::Uint(value, _) => Ok(value),
            _ => Err("could not parse ether value from string".to_string()),
        }
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<U256, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(U256Visitor)
    }

    pub(crate) fn deserialize_opt<'de, D>(deserializer: D) -> Result<Option<U256>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_option(U256OptionVisitor)
    }

    struct U256Visitor;

    #[allow(clippy::elidable_lifetime_names)]
    impl<'de> Visitor<'de> for U256Visitor {
        type Value = U256;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a wei integer or string like 1gwei or 0.1eth")
        }

        fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if value < 0 {
                return Err(E::custom("value must be non-negative"));
            }
            let value = u64::try_from(value).map_err(|_| E::custom("value out of range"))?;
            Ok(U256::from(value))
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(U256::from(value))
        }

        fn visit_u128<E>(self, value: u128) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(U256::from(value))
        }

        fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Err(E::custom("decimal values require a unit, like 0.1eth"))
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            parse_ether_value(value).map_err(E::custom)
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.visit_str(&value)
        }
    }

    struct U256OptionVisitor;

    #[allow(clippy::elidable_lifetime_names)]
    impl<'de> Visitor<'de> for U256OptionVisitor {
        type Value = Option<U256>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("an optional wei integer or string like 1gwei or 0.1eth")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserialize(deserializer).map(Some)
        }
    }
}
