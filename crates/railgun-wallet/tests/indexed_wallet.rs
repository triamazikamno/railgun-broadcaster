use alloy::primitives::{Address, FixedBytes, U256, Uint};
use alloy::sol_types::SolCall;
use broadcaster_core::contracts::railgun::{LegacyCommitmentPreimage, TokenData, shieldCall};
use broadcaster_core::contracts::shield::build_shield_calldata;
use broadcaster_core::crypto::aes_gcm::encrypt_in_place_16b_iv;
use broadcaster_core::crypto::shared_key::shared_symmetric_key_legacy;
use broadcaster_core::notes::Note;
use broadcaster_core::notes::note_public_key;
use merkletree::wallet::{
    IndexedLegacyEncryptedCommitmentInput, IndexedLegacyGeneratedCommitmentInput,
    IndexedNullifierInput, IndexedShieldCommitmentInput, IndexedTransactCommitmentInput,
    parse_indexed_wallet_delta,
};
use railgun_wallet::{NoteCiphertext, UtxoSource, ViewingKeyData};

fn scan_keys(seed: u8) -> ViewingKeyData {
    ViewingKeyData::from_spending_public_key(
        [seed; 32],
        [U256::from(seed), U256::from(seed.saturating_add(1))],
    )
}

fn parse_delta(
    transact: &[IndexedTransactCommitmentInput],
    shield: &[IndexedShieldCommitmentInput],
    legacy_encrypted: &[IndexedLegacyEncryptedCommitmentInput],
    legacy_generated: &[IndexedLegacyGeneratedCommitmentInput],
    nullifiers: &[IndexedNullifierInput],
    keys: &ViewingKeyData,
) -> merkletree::wallet::WalletLogDelta {
    parse_indexed_wallet_delta(
        transact,
        shield,
        legacy_encrypted,
        legacy_generated,
        nullifiers,
        keys,
    )
}

fn source(byte: u8) -> UtxoSource {
    UtxoSource {
        tx_hash: FixedBytes::from([byte; 32]),
        block_number: u64::from(byte),
    }
}

#[test]
fn indexed_transact_commitment_decrypts_wallet_utxo() {
    let keys = scan_keys(7);
    let address = keys.address_data();
    let note = Note::new_change(
        keys.master_public_key,
        Address::ZERO,
        U256::from(42_u8),
        [9u8; 16],
    );
    let ciphertext =
        NoteCiphertext::try_from_note(&note, &address, &address, &keys.viewing_private_key)
            .expect("encrypt note");
    let input = IndexedTransactCommitmentInput {
        tree_number: 2,
        tree_position: 11,
        hash: note.commitment(),
        ciphertext: ciphertext.ciphertext,
        blinded_sender_viewing_key: ciphertext.blinded_sender_viewing_key,
        memo: ciphertext.memo,
        source: source(1),
    };

    let delta = parse_delta(&[input], &[], &[], &[], &[], &keys);

    assert_eq!(delta.utxos.len(), 1);
    assert_eq!(delta.utxos[0].tree, 2);
    assert_eq!(delta.utxos[0].position, 11);
    assert_eq!(delta.utxos[0].note.commitment(), note.commitment());
    assert_eq!(delta.utxos[0].source, source(1));
}

#[test]
fn indexed_transact_commitment_ignores_undecryptable_utxo() {
    let keys = scan_keys(7);
    let other_keys = scan_keys(11);
    let address = keys.address_data();
    let note = Note::new_change(
        keys.master_public_key,
        Address::ZERO,
        U256::from(42_u8),
        [9u8; 16],
    );
    let ciphertext =
        NoteCiphertext::try_from_note(&note, &address, &address, &keys.viewing_private_key)
            .expect("encrypt note");
    let input = IndexedTransactCommitmentInput {
        tree_number: 2,
        tree_position: 11,
        hash: note.commitment(),
        ciphertext: ciphertext.ciphertext,
        blinded_sender_viewing_key: ciphertext.blinded_sender_viewing_key,
        memo: ciphertext.memo,
        source: source(1),
    };

    let delta = parse_delta(&[input], &[], &[], &[], &[], &other_keys);

    assert!(delta.utxos.is_empty());
}

#[test]
fn indexed_shield_commitment_decrypts_wallet_utxo() {
    let keys = scan_keys(7);
    let amount = U256::from(55_u8);
    let calldata = build_shield_calldata(
        keys.master_public_key,
        &keys.viewing_public_key,
        Address::ZERO,
        amount,
        &[3u8; 32],
    )
    .expect("shield calldata");
    let call = shieldCall::abi_decode(&calldata).expect("decode shield call");
    let request = call
        ._shieldRequests
        .into_iter()
        .next()
        .expect("shield request");
    let input = IndexedShieldCommitmentInput {
        tree_number: 4,
        tree_position: 15,
        preimage: request.preimage,
        shield_ciphertext: request.ciphertext,
        source: source(3),
    };

    let delta = parse_delta(&[], &[input], &[], &[], &[], &keys);

    assert_eq!(delta.utxos.len(), 1);
    assert_eq!(delta.utxos[0].tree, 4);
    assert_eq!(delta.utxos[0].position, 15);
    assert_eq!(delta.utxos[0].note.value, amount);
    assert_eq!(delta.utxos[0].note.token_hash, U256::ZERO);
    assert_eq!(delta.utxos[0].source, source(3));
}

#[test]
fn indexed_nullifier_converts_to_spent_marker() {
    let keys = scan_keys(7);
    let input = IndexedNullifierInput {
        tree_number: 3,
        nullifier: U256::from(99_u8),
        source: source(2),
    };

    let delta = parse_delta(&[], &[], &[], &[], &[input], &keys);

    assert!(delta.utxos.is_empty());
    assert_eq!(delta.nullifiers.len(), 1);
    assert_eq!(delta.nullifiers[0].tree, 3);
    assert_eq!(delta.nullifiers[0].nullifier, U256::from(99_u8));
    assert_eq!(delta.nullifiers[0].source, source(2));
}

#[test]
fn indexed_legacy_encrypted_commitment_decrypts_wallet_utxo() {
    let keys = scan_keys(7);
    let note = Note::new_change(
        keys.master_public_key,
        Address::ZERO,
        U256::from(42_u8),
        [9u8; 16],
    );
    let shared_key =
        shared_symmetric_key_legacy(&keys.viewing_private_key, &keys.viewing_public_key)
            .expect("legacy shared key");
    let mut pt = Vec::new();
    pt.extend_from_slice(&keys.master_public_key.to_be_bytes::<32>());
    pt.extend_from_slice(&note.token_hash.to_be_bytes::<32>());
    pt.extend_from_slice(&note.random);
    let value_bytes = note.value.to_be_bytes::<32>();
    pt.extend_from_slice(&value_bytes[16..]);
    let iv_tag = encrypt_in_place_16b_iv(&shared_key, &mut pt).expect("encrypt legacy note");
    let input = IndexedLegacyEncryptedCommitmentInput {
        tree_number: 2,
        tree_position: 11,
        hash: note.commitment(),
        ciphertext: [
            FixedBytes::from(iv_tag),
            FixedBytes::from(<[u8; 32]>::try_from(&pt[0..32]).unwrap()),
            FixedBytes::from(<[u8; 32]>::try_from(&pt[32..64]).unwrap()),
            FixedBytes::from(<[u8; 32]>::try_from(&pt[64..96]).unwrap()),
        ],
        ephemeral_keys: [FixedBytes::from(keys.viewing_public_key), FixedBytes::ZERO],
        memo: Vec::new(),
        source: source(4),
    };

    let delta = parse_delta(&[], &[], &[input], &[], &[], &keys);

    assert_eq!(delta.utxos.len(), 1);
    assert_eq!(delta.utxos[0].tree, 2);
    assert_eq!(delta.utxos[0].position, 11);
    assert_eq!(delta.utxos[0].note.commitment(), note.commitment());
    assert_eq!(delta.utxos[0].source, source(4));
}

#[test]
fn indexed_legacy_generated_commitment_decrypts_wallet_utxo() {
    let keys = scan_keys(7);
    let random = [8u8; 16];
    let npk = note_public_key(keys.master_public_key, random);
    let mut encrypted_random = random.to_vec();
    let iv_tag = encrypt_in_place_16b_iv(&keys.viewing_private_key, &mut encrypted_random)
        .expect("encrypt legacy random");
    let preimage = LegacyCommitmentPreimage {
        npk,
        token: TokenData {
            tokenType: 0,
            tokenAddress: Address::ZERO,
            tokenSubID: U256::ZERO,
        },
        value: Uint::<120, 2>::from(77_u128),
    };
    let input = IndexedLegacyGeneratedCommitmentInput {
        tree_number: 3,
        tree_position: 12,
        preimage,
        encrypted_random: (
            FixedBytes::from(iv_tag),
            FixedBytes::from(<[u8; 16]>::try_from(encrypted_random.as_slice()).unwrap()),
        ),
        source: source(5),
    };

    let delta = parse_delta(&[], &[], &[], &[input], &[], &keys);

    assert_eq!(delta.utxos.len(), 1);
    assert_eq!(delta.utxos[0].tree, 3);
    assert_eq!(delta.utxos[0].position, 12);
    assert_eq!(delta.utxos[0].note.random, random);
    assert_eq!(delta.utxos[0].note.npk, npk);
    assert_eq!(delta.utxos[0].note.value, U256::from(77_u8));
    assert_eq!(delta.utxos[0].source, source(5));
}
