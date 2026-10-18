//! Megolm plaintext / payload v1 parsing and padding never panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use stoat_crypto_proto::MegolmPlaintext;

fuzz_target!(|data: &[u8]| {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else { return };
    if let Ok(plaintext) = MegolmPlaintext::from_value(&value) {
        if let Ok(padded) = plaintext.content.to_padded_value() {
            let len = serde_json::to_vec(&padded).unwrap().len();
            assert_eq!(len % stoat_crypto_proto::payload::PAD_BLOCK, 0);
        }
    }
});
