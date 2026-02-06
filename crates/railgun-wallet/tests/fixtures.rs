use std::collections::BTreeMap;
use std::fs;
use std::future::Future;
use std::str::FromStr;
use std::sync::OnceLock;

use alloy::primitives::{Address, Bytes, FixedBytes, U256, Uint};
use merkletree::tree::{MerkleForest, MerkleTreeUpdate};
use railgun_wallet::artifacts::ArtifactSource;
use railgun_wallet::keys::EddsaSignature;
use railgun_wallet::notes::{Note, note_public_key};
use railgun_wallet::prover::{ProverError, ProverService, WitnessInputs};
use railgun_wallet::public_spending_key;
use railgun_wallet::tx::{
    PrivateInputs, PublicInputs, TransactionBuilder, UnshieldMode, UnshieldPlan, UnshieldRequest,
};
use railgun_wallet::{Utxo, WalletKeys};
use serde::Deserialize;

use broadcaster_core::contracts::railgun::{BoundParams, CommitmentCiphertext};
use broadcaster_core::crypto::poseidon::poseidon;
use broadcaster_core::crypto::railgun::Address as RailgunAddress;

#[derive(Debug, Deserialize)]
struct Fixture {
    #[serde(rename = "privateKey")]
    private_key: String,
    mnemonic: String,
    #[serde(rename = "mnemonicIndex")]
    mnemonic_index: u32,
    address: String,
    #[serde(rename = "boundParams")]
    bound_params: BoundParamsFixture,
    #[serde(rename = "boundParamsHash")]
    bound_params_hash: String,
    #[serde(rename = "publicInputs")]
    public_inputs: PublicInputsFixture,
    #[serde(rename = "privateInputs")]
    private_inputs: PrivateInputsFixture,
    signature: Vec<String>,
    message: String,
    #[serde(rename = "formattedInputs")]
    formatted_inputs: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct BoundParamsFixture {
    #[serde(rename = "treeNumber")]
    tree_number: String,
    #[serde(rename = "minGasPrice")]
    min_gas_price: String,
    unshield: String,
    #[serde(rename = "chainID")]
    chain_id: String,
    #[serde(rename = "adaptContract")]
    adapt_contract: String,
    #[serde(rename = "adaptParams")]
    adapt_params: String,
    #[serde(rename = "commitmentCiphertext")]
    commitment_ciphertext: Vec<CommitmentCiphertextFixture>,
}

#[derive(Debug, Deserialize)]
struct CommitmentCiphertextFixture {
    ciphertext: Vec<String>,
    #[serde(rename = "blindedSenderViewingKey")]
    blinded_sender_viewing_key: String,
    #[serde(rename = "blindedReceiverViewingKey")]
    blinded_receiver_viewing_key: String,
    #[serde(rename = "annotationData")]
    annotation_data: String,
    memo: String,
}

#[derive(Debug, Deserialize)]
struct PublicInputsFixture {
    #[serde(rename = "merkleRoot")]
    merkle_root: String,
    #[serde(rename = "boundParamsHash")]
    bound_params_hash: String,
    nullifiers: Vec<String>,
    #[serde(rename = "commitmentsOut")]
    commitments_out: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct PrivateInputsFixture {
    #[serde(rename = "tokenAddress")]
    token_address: String,
    #[serde(rename = "publicKey")]
    public_key: Vec<String>,
    #[serde(rename = "randomIn")]
    random_in: Vec<String>,
    #[serde(rename = "valueIn")]
    value_in: Vec<String>,
    #[serde(rename = "pathElements")]
    path_elements: Vec<String>,
    #[serde(rename = "leavesIndices")]
    leaves_indices: Vec<String>,
    #[serde(rename = "nullifyingKey")]
    nullifying_key: String,
    #[serde(rename = "npkOut")]
    npk_out: Vec<String>,
    #[serde(rename = "valueOut")]
    value_out: Vec<String>,
}

fn load_fixture() -> Fixture {
    let path = format!(
        "{}/tests/fixtures/railgun-fixtures.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let data = fs::read_to_string(path).expect("read fixture json");
    serde_json::from_str(&data).expect("parse fixture json")
}

fn with_runtime<F>(future: F) -> F::Output
where
    F: Future,
{
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    let runtime = RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
    });
    runtime.block_on(future)
}

fn build_valid_unshield_plan() -> UnshieldPlan {
    static PLAN: OnceLock<UnshieldPlan> = OnceLock::new();
    PLAN.get_or_init(|| {
        with_runtime(async {
            let wallet = WalletKeys::from_mnemonic(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                0,
            )
            .expect("valid mnemonic");
            let token_address = Address::ZERO;
            let note_random = [7u8; 16];
            let note = Note {
                token_hash: U256::from_be_slice(token_address.as_slice()),
                value: U256::from(10),
                random: note_random,
                npk: note_public_key(wallet.viewing.master_public_key, note_random),
            };
            let utxo = Utxo {
                note: note.clone(),
                tree: 0,
                position: 0,
            };
            let mut forest = MerkleForest::new();
            forest
                .insert_leaf(MerkleTreeUpdate {
                    tree_number: 0,
                    tree_position: 0,
                    hash: note.commitment(),
                })
                .expect("insert leaf");
            forest.compute_roots();

            let builder = TransactionBuilder {
                chain_type: 0,
                chain_id: 1,
                railgun_contract: Address::ZERO,
                relay_adapt_contract: Address::ZERO,
            };
            let request = UnshieldRequest {
                token_address,
                amount: U256::from(5),
                recipient: Address::ZERO,
                mode: UnshieldMode::Token,
                verify_proof: true,
                spend_up_to: false,
            };
            let prover = ProverService::new(ArtifactSource::default());
            builder
                .build_unshield_plan(&wallet, &forest, &[utxo], request, &prover)
                .await
                .expect("build unshield plan")
        })
    })
    .clone()
}

#[test]
fn hash_bound_params_matches_js() {
    let fixture = load_fixture();
    let bound_params = bound_params_from_fixture(&fixture.bound_params);
    let expected = u256_from_hex(&fixture.bound_params_hash);
    let actual = bound_params.hash();
    assert_eq!(actual, expected);
}

#[test]
fn sign_poseidon_matches_js() {
    let fixture = load_fixture();
    let public_inputs = public_inputs_from_fixture(&fixture.public_inputs);
    let message = poseidon(public_inputs.signature_message());
    let expected_message = u256_from_hex(&fixture.message);
    assert_eq!(message, expected_message);
    let private_key = hex_to_bytes_32(&fixture.private_key);
    let signature = EddsaSignature::new(&private_key, message);
    let expected = fixture
        .signature
        .iter()
        .map(|v| u256_from_hex(v))
        .collect::<Vec<_>>();
    assert_eq!(signature.r8[0], expected[0]);
    assert_eq!(signature.r8[1], expected[1]);
    assert_eq!(signature.s, expected[2]);
}

#[test]
fn public_spending_key_matches_js() {
    let fixture = load_fixture();
    let private_key = hex_to_bytes_32(&fixture.private_key);
    let expected = fixture
        .private_inputs
        .public_key
        .iter()
        .map(|v| u256_from_hex(v))
        .collect::<Vec<_>>();
    let actual = public_spending_key(&private_key);
    assert_eq!(actual[0], expected[0]);
    assert_eq!(actual[1], expected[1]);
}

#[test]
fn address_from_mnemonic_matches_js() {
    let fixture = load_fixture();
    let keys = WalletKeys::from_mnemonic(&fixture.mnemonic, fixture.mnemonic_index)
        .expect("valid mnemonic");
    let data = keys.address_data();
    let address =
        RailgunAddress::try_from_parts(data.master_public_key, data.viewing_public_key, None)
            .expect("encode address")
            .to_string();
    assert_eq!(address, fixture.address);
}

#[test]
fn witness_inputs_matches_js() {
    let fixture = load_fixture();
    let public_inputs = public_inputs_from_fixture(&fixture.public_inputs);
    let private_inputs = private_inputs_from_fixture(&fixture.private_inputs);
    let signature = [
        u256_from_hex(&fixture.signature[0]),
        u256_from_hex(&fixture.signature[1]),
        u256_from_hex(&fixture.signature[2]),
    ];
    let formatted = WitnessInputs::new(&public_inputs, &private_inputs, &signature);
    assert_eq!(formatted.to_hex_map(), fixture.formatted_inputs);
}

#[test]
fn proof_verification_succeeds() {
    build_valid_unshield_plan();
}

#[test]
fn proof_verification_fails_for_invalid_signature() {
    let plan = build_valid_unshield_plan();
    let mut signature = plan.signature;
    signature[0] += U256::ONE;

    let prover = ProverService::new(ArtifactSource::default());
    let result = with_runtime(prover.prove_unshield(
        &plan.public_inputs,
        &plan.private_inputs,
        &signature,
        true,
    ));
    let err = match result {
        Ok(_) => panic!("invalid proof should fail verification"),
        Err(err) => err,
    };
    match err {
        ProverError::InvalidProof | ProverError::Verify(_) => {}
        other => panic!("unexpected error: {other}"),
    }
}

fn bound_params_from_fixture(fixture: &BoundParamsFixture) -> BoundParams {
    let ciphertext = fixture
        .commitment_ciphertext
        .iter()
        .map(|cipher| CommitmentCiphertext {
            ciphertext: fixed_bytes_4(&cipher.ciphertext),
            blindedSenderViewingKey: fixed_bytes_32(&cipher.blinded_sender_viewing_key),
            blindedReceiverViewingKey: fixed_bytes_32(&cipher.blinded_receiver_viewing_key),
            annotationData: parse_bytes(&cipher.annotation_data),
            memo: parse_bytes(&cipher.memo),
        })
        .collect();

    BoundParams {
        treeNumber: u16_from_hex(&fixture.tree_number),
        minGasPrice: Uint::<72, 2>::from(u64_from_hex(&fixture.min_gas_price)),
        unshield: u8_from_hex(&fixture.unshield),
        chainID: u64_from_hex(&fixture.chain_id),
        adaptContract: Address::from_str(&fixture.adapt_contract).unwrap(),
        adaptParams: fixed_bytes_32(&fixture.adapt_params),
        commitmentCiphertext: ciphertext,
    }
}

fn public_inputs_from_fixture(fixture: &PublicInputsFixture) -> PublicInputs {
    PublicInputs {
        merkle_root: u256_from_hex(&fixture.merkle_root),
        bound_params_hash: u256_from_hex(&fixture.bound_params_hash),
        nullifiers: fixture
            .nullifiers
            .iter()
            .map(|v| u256_from_hex(v))
            .collect(),
        commitments_out: fixture
            .commitments_out
            .iter()
            .map(|v| u256_from_hex(v))
            .collect(),
    }
}

fn private_inputs_from_fixture(fixture: &PrivateInputsFixture) -> PrivateInputs {
    let public_key = [
        u256_from_hex(&fixture.public_key[0]),
        u256_from_hex(&fixture.public_key[1]),
    ];
    PrivateInputs {
        token_address: u256_from_hex(&fixture.token_address),
        random_in: fixture.random_in.iter().map(|v| u256_from_hex(v)).collect(),
        value_in: fixture.value_in.iter().map(|v| u256_from_hex(v)).collect(),
        path_elements: fixture
            .path_elements
            .iter()
            .map(|v| u256_from_hex(v))
            .collect(),
        leaves_indices: fixture
            .leaves_indices
            .iter()
            .map(|v| u256_from_hex(v))
            .collect(),
        value_out: fixture.value_out.iter().map(|v| u256_from_hex(v)).collect(),
        public_key,
        npk_out: fixture.npk_out.iter().map(|v| u256_from_hex(v)).collect(),
        nullifying_key: u256_from_hex(&fixture.nullifying_key),
    }
}

fn hex_to_bytes_32(value: &str) -> [u8; 32] {
    let bytes = hex::decode(normalize_hex(value)).expect("hex decode");
    let mut out = [0u8; 32];
    let start = out.len().saturating_sub(bytes.len());
    out[start..].copy_from_slice(&bytes);
    out
}

fn fixed_bytes_32(value: &str) -> FixedBytes<32> {
    FixedBytes::from(hex_to_bytes_32(value))
}

fn fixed_bytes_4(values: &[String]) -> [FixedBytes<32>; 4] {
    [
        fixed_bytes_32(&values[0]),
        fixed_bytes_32(&values[1]),
        fixed_bytes_32(&values[2]),
        fixed_bytes_32(&values[3]),
    ]
}

fn parse_bytes(value: &str) -> Bytes {
    if value == "0x" {
        return Bytes::new();
    }
    let bytes = hex::decode(normalize_hex(value)).expect("bytes decode");
    bytes.into()
}

fn u256_from_hex(value: &str) -> U256 {
    let bytes = hex::decode(normalize_hex(value)).expect("hex decode");
    U256::from_be_slice(&bytes)
}

fn u16_from_hex(value: &str) -> u16 {
    u16::from_str_radix(strip_0x(value), 16).expect("parse u16")
}

fn u64_from_hex(value: &str) -> u64 {
    u64::from_str_radix(strip_0x(value), 16).expect("parse u64")
}

fn u8_from_hex(value: &str) -> u8 {
    u8::from_str_radix(strip_0x(value), 16).expect("parse u8")
}

fn strip_0x(value: &str) -> &str {
    value.strip_prefix("0x").unwrap_or(value)
}

fn normalize_hex(value: &str) -> String {
    let raw = strip_0x(value);
    if raw.len() % 2 == 1 {
        format!("0{raw}")
    } else {
        raw.to_string()
    }
}
