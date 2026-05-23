use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use thiserror::Error;

use crate::poi::{PoiEventType, SignedBlockedShield, SignedPoiEvent};

pub fn verify_poi_event(event: &SignedPoiEvent, list_key: &[u8; 32]) -> Result<(), VerifyError> {
    verify_signature(
        list_key,
        &event.signature,
        &canonical_poi_event_message(event),
    )
}

pub fn verify_blocked_shield(
    record: &SignedBlockedShield,
    list_key: &[u8; 32],
) -> Result<(), VerifyError> {
    verify_signature(
        list_key,
        &record.signature,
        &canonical_blocked_shield_message(record),
    )
}

#[must_use]
pub fn canonical_poi_event_message(event: &SignedPoiEvent) -> Vec<u8> {
    format!(
        r#"{{"index":{},"blindedCommitment":"{}","type":"{}"}}"#,
        event.index,
        event.blinded_commitment,
        event_type_str(event.event_type)
    )
    .into_bytes()
}

#[must_use]
pub fn canonical_blocked_shield_message(record: &SignedBlockedShield) -> Vec<u8> {
    let mut message = format!(
        r#"{{"commitmentHash":"{}","blindedCommitment":"{}""#,
        record.commitment_hash, record.blinded_commitment
    );
    if let Some(reason) = &record.block_reason {
        message.push(',');
        message.push_str(r#""blockReason":"#);
        let encoded = serde_json::to_string(reason).unwrap_or_else(|_| "\"\"".to_string());
        message.push_str(&encoded);
    }
    message.push('}');
    message.into_bytes()
}

fn verify_signature(
    list_key: &[u8; 32],
    signature_hex: &str,
    message: &[u8],
) -> Result<(), VerifyError> {
    let public_key = VerifyingKey::from_bytes(list_key).map_err(VerifyError::PublicKey)?;
    let signature_bytes = decode_hex(signature_hex).map_err(VerifyError::SignatureHex)?;
    let signature = Signature::from_slice(&signature_bytes).map_err(VerifyError::Signature)?;
    public_key
        .verify(message, &signature)
        .map_err(VerifyError::Signature)
}

const fn event_type_str(event_type: PoiEventType) -> &'static str {
    match event_type {
        PoiEventType::Shield => "Shield",
        PoiEventType::Transact => "Transact",
        PoiEventType::Unshield => "Unshield",
        PoiEventType::LegacyTransact => "LegacyTransact",
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value))
}

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("invalid ed25519 public key")]
    PublicKey(#[source] ed25519_dalek::SignatureError),
    #[error("invalid signature hex")]
    SignatureHex(#[source] hex::FromHexError),
    #[error("ed25519 signature verification failed")]
    Signature(#[source] ed25519_dalek::SignatureError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const ACTIVE_LIST_KEY: [u8; 32] = [
        0xef, 0xc6, 0xdd, 0xb5, 0x9c, 0x09, 0x8a, 0x13, 0xfb, 0x2b, 0x61, 0x8f, 0xda, 0xe9, 0x4c,
        0x1c, 0x3a, 0x80, 0x7a, 0xbc, 0x8f, 0xb1, 0x83, 0x7c, 0x93, 0x62, 0x0c, 0x91, 0x43, 0xee,
        0x9e, 0x88,
    ];

    const SYNTHETIC_NO_REASON_LIST_KEY: [u8; 32] = [
        0xea, 0x4a, 0x6c, 0x63, 0xe2, 0x9c, 0x52, 0x0a, 0xbe, 0xf5, 0x50, 0x7b, 0x13, 0x2e, 0xc5,
        0xf9, 0x95, 0x47, 0x76, 0xae, 0xbe, 0xbe, 0x7b, 0x92, 0x42, 0x1e, 0xea, 0x69, 0x14, 0x46,
        0xd2, 0x2c,
    ];

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7_u8; 32])
    }

    fn signed_event(event_type: PoiEventType) -> SignedPoiEvent {
        let signing_key = signing_key();
        let mut event = SignedPoiEvent {
            index: 42,
            blinded_commitment:
                "0x1111111111111111111111111111111111111111111111111111111111111111".to_string(),
            signature: String::new(),
            event_type,
        };
        event.signature = hex::encode(
            signing_key
                .sign(&canonical_poi_event_message(&event))
                .to_bytes(),
        );
        event
    }

    fn signed_blocked_shield(block_reason: Option<&str>) -> SignedBlockedShield {
        let signing_key = signing_key();
        let mut record = SignedBlockedShield {
            commitment_hash: "0x2222222222222222222222222222222222222222222222222222222222222222"
                .to_string(),
            blinded_commitment:
                "0x3333333333333333333333333333333333333333333333333333333333333333".to_string(),
            block_reason: block_reason.map(ToString::to_string),
            signature: String::new(),
        };
        record.signature = hex::encode(
            signing_key
                .sign(&canonical_blocked_shield_message(&record))
                .to_bytes(),
        );
        record
    }

    fn live_event(
        index: u64,
        blinded_commitment: &str,
        signature: &str,
        event_type: PoiEventType,
    ) -> SignedPoiEvent {
        SignedPoiEvent {
            index,
            blinded_commitment: blinded_commitment.to_string(),
            signature: signature.to_string(),
            event_type,
        }
    }

    fn live_blocked_shield_with_reason() -> SignedBlockedShield {
        SignedBlockedShield {
            commitment_hash: "0x23d834c86bb91d6b5afa4049192319c548719defa2e50020525b0c08847a3882"
                .to_string(),
            blinded_commitment:
                "0x000a34944d802f6869f8e71a146dc14db1fb5a49b0116dc33170e74596e32f6c"
                    .to_string(),
            block_reason: Some("Address is blacklisted".to_string()),
            signature: "e31b1d36eb0997164611ada586b9c530c3bbf3668ac759dac9d2d3b76ad3006c125fd4ae38c10ea607cf892f5f8134dc348ff59733669fc52e4e07dc0db63905"
                .to_string(),
        }
    }

    fn synthetic_blocked_shield_without_reason() -> SignedBlockedShield {
        SignedBlockedShield {
            commitment_hash: "0x2222222222222222222222222222222222222222222222222222222222222222"
                .to_string(),
            blinded_commitment:
                "0x3333333333333333333333333333333333333333333333333333333333333333"
                    .to_string(),
            block_reason: None,
            signature: "d6af83166868a93f3f3702f30ccf36a343193613925c3817752339b938eba3c6796adf2652544be5c0fc027025c889340fcdd3762313a66398f970d37a67ae03"
                .to_string(),
        }
    }

    #[test]
    fn poi_event_canonical_message_uses_required_field_order() {
        let event = signed_event(PoiEventType::Shield);

        assert_eq!(
            canonical_poi_event_message(&event),
            br#"{"index":42,"blindedCommitment":"0x1111111111111111111111111111111111111111111111111111111111111111","type":"Shield"}"#
        );
    }

    #[test]
    fn blocked_shield_canonical_message_omits_absent_reason() {
        let record = signed_blocked_shield(None);

        assert_eq!(
            canonical_blocked_shield_message(&record),
            br#"{"commitmentHash":"0x2222222222222222222222222222222222222222222222222222222222222222","blindedCommitment":"0x3333333333333333333333333333333333333333333333333333333333333333"}"#
        );
    }

    #[test]
    fn verifies_signed_poi_event() {
        let signing_key = signing_key();
        let event = signed_event(PoiEventType::Transact);

        verify_poi_event(&event, signing_key.verifying_key().as_bytes()).expect("valid signature");
    }

    #[test]
    fn verifies_signed_blocked_shields_with_and_without_reason() {
        let signing_key = signing_key();

        verify_blocked_shield(
            &signed_blocked_shield(Some("blocked for fixture")),
            signing_key.verifying_key().as_bytes(),
        )
        .expect("valid signature with reason");
        verify_blocked_shield(
            &signed_blocked_shield(None),
            signing_key.verifying_key().as_bytes(),
        )
        .expect("valid signature without reason");
    }

    #[test]
    fn verifies_live_upstream_poi_event_golden_vectors() {
        let events = [
            live_event(
                1,
                "0x2a091023e8878f43fda97bc809ba4bd9557e60cf829d63df107d6451693438d2",
                "99cb342afb3ebc952119d93552647d5f2d3d8867c5797745e461bd42e48fa7974cfbd1af863cb68523a3bc318f6e70acd6dadc7d1aa0641aabde1332ace3580a",
                PoiEventType::Shield,
            ),
            live_event(
                56671,
                "0x248876898f205ab41247679a1f7399df0f54541f02c6a915d79f4545aa759db2",
                "c8fe4df09afdec636d2a611a6fa61ffda87f62bf71637df3e35e0e247cff23db715fd75d73f047953a0b3992a9c0f7270a6efe4751e63c76567f252980944e00",
                PoiEventType::Transact,
            ),
            live_event(
                0,
                "0x17742644f64a17b601fc4aab4be04c4d0d8d730a23fcb27463b6e8c13020f20f",
                "0bbfe679b12a186df95e92f263903757207fbea882ac00108beb677fdd6851d8f3705aadf94b65a3ce8e84b12eaa499cd5041ae70d3ebac7e7e9361af1bae900",
                PoiEventType::Unshield,
            ),
            live_event(
                10000,
                "0x0cdbe4c20aafe718939c65d56d7a2346d9ed239ed84ce4de08453a8acae08446",
                "6bc2d333ce7c40cfb28cb6b06a1ce5365919fe40cf6c3448ba19bbc3b1d137880974567186454fb9fb48bc864ff818686bcdaf83e8fbbb9ad18c6dafe2f68600",
                PoiEventType::LegacyTransact,
            ),
        ];

        for event in events {
            verify_poi_event(&event, &ACTIVE_LIST_KEY).expect("valid live upstream signature");
        }
    }

    #[test]
    fn verifies_blocked_shield_golden_vectors() {
        verify_blocked_shield(&live_blocked_shield_with_reason(), &ACTIVE_LIST_KEY)
            .expect("valid live upstream blocked-shield signature with reason");

        verify_blocked_shield(
            &synthetic_blocked_shield_without_reason(),
            &SYNTHETIC_NO_REASON_LIST_KEY,
        )
        .expect("valid synthetic blocked-shield signature without reason");
    }

    #[test]
    fn swapped_poi_event_field_order_fails_verification() {
        let event = live_event(
            1,
            "0x2a091023e8878f43fda97bc809ba4bd9557e60cf829d63df107d6451693438d2",
            "99cb342afb3ebc952119d93552647d5f2d3d8867c5797745e461bd42e48fa7974cfbd1af863cb68523a3bc318f6e70acd6dadc7d1aa0641aabde1332ace3580a",
            PoiEventType::Shield,
        );
        let blinded_commitment = &event.blinded_commitment;
        let index = event.index;
        let event_type = event_type_str(event.event_type);
        let swapped_message = format!(
            r#"{{"blindedCommitment":"{blinded_commitment}","index":{index},"type":"{event_type}"}}"#
        );

        assert!(matches!(
            verify_signature(
                &ACTIVE_LIST_KEY,
                &event.signature,
                swapped_message.as_bytes()
            ),
            Err(VerifyError::Signature(_))
        ));
    }
}
