use super::{
    ESTIMATE_GAS_FAILED_RESPONSE_MESSAGE, build_transact_error_response,
    transact_estimate_gas_error_message,
};
use alloy::transports::{RpcError, TransportErrorKind};
use broadcaster_core::transact_response::DecryptedTransactResponse;

#[test]
fn transact_error_response_roundtrips_error_message() {
    let shared_key = [7u8; 32];
    let message = "estimate gas failed: RailgunSmartWallet: Gas price too low";

    let encrypted =
        build_transact_error_response(&shared_key, message).expect("build error response");
    let decrypted = DecryptedTransactResponse::try_decrypt_message(&shared_key, &encrypted)
        .expect("decrypt error response")
        .expect("decrypted response payload");

    assert_eq!(
        decrypted,
        DecryptedTransactResponse::Error(message.to_string())
    );
}

#[test]
fn estimate_gas_response_uses_rpc_error_message() {
    let parse_error = serde_json::from_str::<serde_json::Value>("{")
        .expect_err("invalid JSON should fail to parse");
    let error = RpcError::<TransportErrorKind>::deser_err(
        parse_error,
        r#"{"code":3,"message":"execution reverted: RailgunSmartWallet: Gas price too low"}"#,
    );

    assert_eq!(
        transact_estimate_gas_error_message(&error),
        "Estimate gas failed: execution reverted: RailgunSmartWallet: Gas price too low"
    );
}

#[test]
fn estimate_gas_response_hides_transport_error_details() {
    let error = TransportErrorKind::custom_str("network error contacting http://secret-rpc");

    assert_eq!(
        transact_estimate_gas_error_message(&error),
        ESTIMATE_GAS_FAILED_RESPONSE_MESSAGE
    );
}
