//! Byte-identity of the bech32 encoding against the Go age CLI.
//!
//! Issue #11 replaced two hand-rolled `bech32::Checksum` impls (`CODE_LENGTH =
//! 8192`) with secure-gate's derived code length (1959). The claim that
//! justifies that change is that the code length is a *length gate* — it never
//! enters the checksum computation, so the encoded output is byte-identical at
//! any sufficient value.
//!
//! These fixtures were produced by the **Go age CLI v1.3.1**, so they are
//! cross-implementation evidence rather than a self-round-trip: if our encoder
//! drifted, matching them would be impossible regardless of what our own
//! decoder does.
//!
//! Deliberately not `#[ignore]`d — the fixtures are checked in, so this needs no
//! external binary and must run on every `cargo test`.

use age_pq_keys::{HybridIdentity, HybridRecipient};

const RECIPIENT_FIXTURE: &str = include_str!("data/age_cli_pq_recipient.key");
const IDENTITY_FIXTURE: &str = include_str!("data/age_cli_pq_identity.key");

fn recipient_fixture() -> &'static str {
    RECIPIENT_FIXTURE
        .lines()
        .find(|l| l.starts_with("age1pq"))
        .expect("fixture holds an age1pq recipient")
        .trim()
}

fn identity_fixture() -> &'static str {
    IDENTITY_FIXTURE
        .lines()
        .find(|l| l.to_ascii_uppercase().starts_with("AGE-SECRET-KEY-PQ-"))
        .expect("fixture holds a native identity")
        .trim()
}

/// Parse the Go CLI's own recipient and re-encode it. Any drift in HRP,
/// checksum constants, character set or case shows up as a mismatch.
#[test]
fn recipient_reencodes_byte_identically_to_the_go_cli() {
    let go = recipient_fixture();
    let ours = HybridRecipient::parse(go)
        .expect("the Go CLI's recipient must parse")
        .to_string();
    assert_eq!(go, ours, "recipient encoding drifted from the Go age CLI");
}

/// Same for the private-key side, which is additionally uppercased.
#[test]
fn identity_reencodes_byte_identically_to_the_go_cli() {
    let go = identity_fixture();
    let ours = HybridIdentity::parse(go)
        .expect("the Go CLI's identity must parse")
        .to_string();
    assert_eq!(go, ours, "identity encoding drifted from the Go age CLI");
}

/// The identity fixture is uppercase, so a `Case::Lower` slip would be caught
/// above. Assert the property directly too, since it is the one that silently
/// produces something Go refuses to load.
#[test]
fn identity_encoding_is_uppercase() {
    let ours = HybridIdentity::parse(identity_fixture())
        .unwrap()
        .to_string();
    assert_eq!(ours, ours.to_ascii_uppercase());
    assert!(ours.starts_with("AGE-SECRET-KEY-PQ-1"));
}

/// The recipient is lowercase; the mirror-image slip.
#[test]
fn recipient_encoding_is_lowercase() {
    let ours = HybridRecipient::parse(recipient_fixture())
        .unwrap()
        .to_string();
    assert_eq!(ours, ours.to_ascii_lowercase());
    assert!(ours.starts_with("age1pq1"));
}

/// The derived code length must actually cover the real key, with the fixture
/// as the witness. If `bech32_code_length` or the key size ever changes such
/// that 1959 is wrong, this fails rather than the encoder silently rejecting
/// every recipient.
#[test]
fn derived_code_length_matches_the_real_encoding_length() {
    assert_eq!(
        recipient_fixture().len(),
        1959,
        "the Go CLI's recipient is not the length the code length was derived for"
    );
}

/// `HybridRecipient::pub_key` used to be a `pub` field with no validation,
/// which made the `expect` in `to_string()` reachable by assigning a longer
/// vector. It is private now and `from_bytes` is the only way in, so the
/// invariant is enforced rather than assumed. See DECIDE-14.
#[test]
fn from_bytes_rejects_a_wrong_length_recipient() {
    for len in [0usize, 1215, 1217, 4096] {
        assert!(
            HybridRecipient::from_bytes(vec![0u8; len]).is_err(),
            "{len}-byte input must be rejected"
        );
    }
}

/// The all-zero recipient is accepted by `from_bytes`, **deliberately**, and
/// this is the test that says so.
///
/// It used to be a trailing line inside
/// `from_bytes_rejects_a_wrong_length_recipient`, whose name gives no hint that
/// it also pins the parse/wrap stage split — one tidy-up away from being lost
/// with nothing to notice.
///
/// Two independent reasons it must pass:
///
/// * An all-zero ML-KEM half is a *canonical* `ByteEncode_12` output (every
///   coefficient is 0 < q), so it passes the FIPS 203 section 7.2 check that
///   `from_bytes` applies.
/// * The X25519 half is the low-order all-zero point, and that is checked at
///   **wrap** time, not parse time, because that is where age checks it. The
///   staging is pinned against the real CLI by
///   `differential_age_go.rs::go_stages_the_encapsulation_key_checks_where_we_do`.
#[test]
fn from_bytes_accepts_an_all_zero_key_because_the_curve_check_belongs_to_wrap() {
    assert!(HybridRecipient::from_bytes(vec![0u8; 1216]).is_ok());
}
