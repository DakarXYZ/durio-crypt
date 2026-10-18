//! Vectors shared with the Kotlin and JS tests (`fixtures/`): the SAS emoji
//! table and SAS byte → code vectors (CR-11). `DUMP_FIXTURES=1` rewrites
//! them; otherwise the committed files are checked.

use std::path::PathBuf;

use matrix_sdk_crypto::vodozemac::sas::Sas;
use serde_json::{Value, json};
use stoat_crypto::SAS_EMOJI;

fn path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(rel)
}

fn check_or_dump(rel: &str, value: &Value) {
    let text = serde_json::to_string_pretty(value).unwrap() + "\n";
    if std::env::var_os("DUMP_FIXTURES").is_some() {
        std::fs::write(path(rel), text).unwrap();
    } else {
        let committed = std::fs::read_to_string(path(rel)).unwrap().replace("\r\n", "\n");
        assert_eq!(committed, text, "{rel} is stale: DUMP_FIXTURES=1");
    }
}

/// Spec: first 42 bits of 6 bytes → 7 × 6 bits
fn emoji_indices(b: &[u8; 6]) -> [u8; 7] {
    let n = b.iter().fold(0u64, |acc, x| acc << 8 | u64::from(*x));
    std::array::from_fn(|i| ((n >> (42 - 6 * i)) & 63) as u8)
}

/// Spec: first 5 bytes → 3 × 13 bits, each + 1000
fn decimals(b: &[u8; 6]) -> [u16; 3] {
    let n = b[..5].iter().fold(0u64, |acc, x| acc << 8 | u64::from(*x));
    std::array::from_fn(|i| ((n >> (27 - 13 * i)) & 0x1fff) as u16 + 1000)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn sas_emoji_table() {
    let table: Vec<Value> = SAS_EMOJI
        .iter()
        .enumerate()
        .map(|(i, (symbol, description))| json!({ "index": i, "symbol": symbol, "description": description }))
        .collect();
    check_or_dump(
        "sas/emoji.json",
        &json!({
            "note": "Matrix sas-emoji.json: index → symbol, English description (translation key)",
            "emoji": table,
        }),
    );
}

#[test]
fn sas_byte_vectors() {
    let inputs: [[u8; 6]; 6] = [
        [0; 6],
        [0xff; 6],
        [0x01, 0x23, 0x45, 0x67, 0x89, 0xab],
        [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54],
        [0x80, 0x00, 0x00, 0x00, 0x00, 0x01],
        [0x3c, 0x5a, 0x96, 0x0f, 0xf0, 0x69],
    ];
    let vectors: Vec<Value> = inputs
        .iter()
        .map(|b| json!({ "bytes": hex(b), "emoji": emoji_indices(b), "decimals": decimals(b) }))
        .collect();
    check_or_dump(
        "sas/vectors.json",
        &json!({
            "note": "SAS bytes (HKDF output, hex) → 7 emoji indices (first 42 bits) and 3 decimals (first 39 bits, +1000)",
            "vectors": vectors,
        }),
    );
}

/// The spec functions above are what vodozemac computes in a real exchange
#[test]
fn sas_vectors_match_vodozemac() {
    for _ in 0..32 {
        let (a, b) = (Sas::new(), Sas::new());
        let b_key = b.public_key();
        let a = a.diffie_hellman(b_key).unwrap();
        let bytes = a.bytes("MATRIX_KEY_VERIFICATION_SAS|test");
        assert_eq!(emoji_indices(bytes.as_bytes()), bytes.emoji_indices());
        let (x, y, z) = bytes.decimals();
        assert_eq!(decimals(bytes.as_bytes()), [x, y, z]);
    }
}
