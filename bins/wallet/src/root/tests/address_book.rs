use crate::root::address_book::{
    AddressBookDetectedType, AddressBookEntryKind, address_book_detected_type,
    address_book_entry_matches_search, address_book_entry_validation_message,
};

const RAILGUN_ADDRESS: &str = "0zk1qy4v02p5zkq0zfpaxhz79j5tslrv8c44d80d8jr2fuecrtxlp8lemrv7j6fe3z53ll0jm7u592n0hr8elesd0xzv6y9jpdvsyln80m95jcxhvnmagfqg5p6e9mp";
const PUBLIC_ADDRESS: &str = "0x1111111111111111111111111111111111111111";

#[test]
fn address_book_type_detection_uses_recipient_prefixes() {
    assert_eq!(
        address_book_detected_type(RAILGUN_ADDRESS),
        AddressBookDetectedType::Private
    );
    assert_eq!(
        address_book_detected_type(PUBLIC_ADDRESS),
        AddressBookDetectedType::Public
    );
    assert_eq!(
        address_book_detected_type("not-an-address"),
        AddressBookDetectedType::Unknown
    );
}

#[test]
fn address_book_validation_rejects_invalid_and_type_switched_values() {
    assert_eq!(
        address_book_entry_validation_message(None, "Alice", RAILGUN_ADDRESS),
        None
    );
    assert_eq!(
        address_book_entry_validation_message(None, "Bob", PUBLIC_ADDRESS),
        None
    );
    assert_eq!(
        address_book_entry_validation_message(None, "  ", PUBLIC_ADDRESS),
        Some("Enter a label")
    );
    assert_eq!(
        address_book_entry_validation_message(None, "Bob", "not-an-address"),
        Some("Enter a 0zk private recipient or 0x public EVM address")
    );
    assert_eq!(
        address_book_entry_validation_message(None, "Alice", "0zk-invalid"),
        Some("Enter a valid private 0zk recipient")
    );
    assert_eq!(
        address_book_entry_validation_message(
            Some(AddressBookEntryKind::Private),
            "Alice",
            PUBLIC_ADDRESS,
        ),
        Some("Private address-book entries must use a 0zk recipient")
    );
    assert_eq!(
        address_book_entry_validation_message(
            Some(AddressBookEntryKind::Public),
            "Bob",
            RAILGUN_ADDRESS,
        ),
        Some("Public address-book entries must use a 0x EVM address")
    );
}

#[test]
fn address_book_search_matches_label_and_full_address_case_insensitively() {
    assert!(address_book_entry_matches_search(
        "Alice Savings",
        PUBLIC_ADDRESS,
        "savings",
    ));
    assert!(address_book_entry_matches_search(
        "Alice Savings",
        PUBLIC_ADDRESS,
        "1111111111",
    ));
    assert!(address_book_entry_matches_search(
        "Mixed Case",
        PUBLIC_ADDRESS,
        "mixed case",
    ));
    assert!(!address_book_entry_matches_search(
        "Alice Savings",
        PUBLIC_ADDRESS,
        "charlie",
    ));
}
