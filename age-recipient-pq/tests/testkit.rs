//! C2SP CCTV age test-vector conformance harness (hybrid / post-quantum subset).
//!
//! Vectors are the 19 `hybrid_*` / `armor_hybrid` files from the C2SP CCTV age
//! testkit, as vendored by rage. They drive a full `age` file decryption through
//! this crate's [`HybridIdentity`], which is the same path official age and rage
//! exercise, so a divergence here is a real interoperability or validation bug.
//!
//! Upstream stores `armor_hybrid` and `hybrid_multiple_recipients` with their age
//! file bytes zlib-compressed (`compressed: zlib`). Both are stored decompressed
//! here, with that header line dropped, so the harness needs no `flate2`
//! dependency. The age file bytes under test are byte-identical either way.

use age::armor::ArmoredReader;
use age::{DecryptError, Identity};
use age_recipient_pq::HybridIdentity;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs;
use std::io::Read;
use std::str::FromStr;

const VECTOR_DIR: &str = "tests/data/testkit";

const VECTORS: &[&str] = &[
    "armor_hybrid",
    "hybrid",
    "hybrid_and_x25519",
    "hybrid_bad_tag",
    "hybrid_currupted_enc_mlkem",
    "hybrid_currupted_enc_x25519",
    "hybrid_extra_argument",
    "hybrid_grease",
    "hybrid_identity",
    "hybrid_long_file_key",
    "hybrid_long_share",
    "hybrid_low_order",
    "hybrid_multiple_recipients",
    "hybrid_no_match",
    "hybrid_not_canonical_body",
    "hybrid_not_canonical_enc",
    "hybrid_short_share",
    "hybrid_uppercase",
    "hybrid_x25519_arg",
];

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Expect {
    Success,
    ArmorFailure,
    HeaderFailure,
    HmacFailure,
    NoMatch,
    PayloadFailure,
}

struct TestFile {
    expect: Expect,
    payload_sha256: Option<[u8; 32]>,
    identities: Vec<String>,
    comment: Option<String>,
    age_file: Vec<u8>,
}

fn hex_decode(s: &str) -> Vec<u8> {
    let c: String = s.split_whitespace().collect();
    (0..c.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&c[i..i + 2], 16).unwrap())
        .collect()
}

impl TestFile {
    fn parse(name: &str) -> Self {
        let raw = fs::read(format!("{VECTOR_DIR}/{name}")).expect("vector file");
        let split = raw
            .windows(2)
            .position(|w| w == b"\n\n")
            .expect("blank line terminating vector header");
        let header = String::from_utf8(raw[..split].to_vec()).expect("utf-8 header");
        let age_file = raw[split + 2..].to_vec();

        let mut expect = None;
        let mut payload_sha256 = None;
        let mut identities = vec![];
        let mut comment = None;

        for line in header.lines() {
            let (prefix, data) = match line.split_once(':') {
                Some((p, d)) => (p.trim(), d.trim()),
                None => panic!("malformed header line {line:?} in {name}"),
            };
            match prefix {
                "expect" => {
                    expect = Some(match data {
                        "success" => Expect::Success,
                        "armor failure" => Expect::ArmorFailure,
                        "header failure" => Expect::HeaderFailure,
                        "HMAC failure" => Expect::HmacFailure,
                        "no match" => Expect::NoMatch,
                        "payload failure" => Expect::PayloadFailure,
                        e => panic!("unknown expectation {e:?} in {name}"),
                    })
                }
                "payload" => {
                    payload_sha256 = Some(hex_decode(data).try_into().expect("32-byte sha256"))
                }
                "identity" => identities.push(data.to_owned()),
                "comment" => comment = Some(data.to_owned()),
                // `file key` is the expected plaintext file key; this harness checks
                // the decrypted payload instead, which subsumes it.
                "file key" | "armored" | "passphrase" => {}
                p => panic!("unknown testkit metadata {p:?} in {name}"),
            }
        }

        TestFile {
            expect: expect.expect("expect field"),
            payload_sha256,
            identities,
            comment,
            age_file,
        }
    }

    fn identities(&self) -> Vec<Box<dyn Identity>> {
        self.identities
            .iter()
            .map(|s| {
                age::x25519::Identity::from_str(s)
                    .map(|i| Box::new(i) as Box<dyn Identity>)
                    .or_else(|_| {
                        HybridIdentity::parse(s)
                            .map(|i| Box::new(i) as Box<dyn Identity>)
                            .map_err(|_| "unparseable identity")
                    })
                    .expect("identity parses as x25519 or hybrid")
            })
            .collect()
    }
}

/// Classifies what actually happened, in the same vocabulary as `Expect`.
fn actual_outcome(f: &TestFile) -> Result<Expect, String> {
    let ids = f.identities();
    let decryptor = match age::Decryptor::new(ArmoredReader::new(&f.age_file[..])) {
        Ok(d) => d,
        Err(e) => return Ok(classify(e)),
    };
    let mut reader = match decryptor.decrypt(ids.iter().map(|i| i.as_ref())) {
        Ok(r) => r,
        Err(e) => return Ok(classify(e)),
    };
    let mut payload = vec![];
    match reader.read_to_end(&mut payload) {
        Ok(_) => {
            if let Some(want) = f.payload_sha256 {
                let got = Sha256::digest(&payload);
                if got[..] != want[..] {
                    return Err(format!(
                        "decrypted, but payload sha256 {} != expected {}",
                        hex_encode(&got),
                        hex_encode(&want)
                    ));
                }
            }
            Ok(Expect::Success)
        }
        Err(_) => Ok(Expect::PayloadFailure),
    }
}

fn classify(e: DecryptError) -> Expect {
    match e {
        DecryptError::InvalidHeader | DecryptError::UnknownFormat => Expect::HeaderFailure,
        DecryptError::ExcessiveWork { .. } => Expect::HeaderFailure,
        DecryptError::InvalidMac => Expect::HmacFailure,
        DecryptError::NoMatchingKeys | DecryptError::DecryptionFailed => Expect::NoMatch,
        DecryptError::Io(_) => Expect::HeaderFailure,
        _ => Expect::HeaderFailure,
    }
}

fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

#[test]
fn cctv_hybrid_vectors() {
    let mut failures = vec![];
    let mut passed = 0usize;

    for name in VECTORS {
        let f = TestFile::parse(name);
        let want = f.expect;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| actual_outcome(&f)));

        let line = match result {
            Ok(Ok(got)) if got == want => {
                passed += 1;
                continue;
            }
            Ok(Ok(got)) => format!("expected {want:?}, got {got:?}"),
            Ok(Err(detail)) => detail,
            Err(_) => "panicked".to_owned(),
        };
        let comment = f.comment.as_deref().unwrap_or("");
        failures.push(format!("  {name}: {line}\n      ({comment})"));
    }

    if !failures.is_empty() {
        panic!(
            "\n{} of {} CCTV hybrid vectors failed ({} passed):\n{}\n",
            failures.len(),
            VECTORS.len(),
            passed,
            failures.join("\n")
        );
    }
}
