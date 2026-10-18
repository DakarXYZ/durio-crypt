//! Envelope v1 parsing never panics; whatever parses re-validates and round-trips.
#![no_main]

use libfuzzer_sys::fuzz_target;
use stoat_crypto_proto::EncryptedEnvelope;

fuzz_target!(|data: &[u8]| {
    let Ok(json) = std::str::from_utf8(data) else { return };
    if let Ok(envelope) = EncryptedEnvelope::from_json(json) {
        envelope.validate().expect("parsed envelope is valid");
        assert_eq!(EncryptedEnvelope::from_value(&envelope.to_value()).as_ref(), Ok(&envelope));
    }
});
