//! Recovery key input never panics; a decoded key re-encodes to itself.
#![no_main]

use libfuzzer_sys::fuzz_target;
use stoat_crypto_proto::recovery_key;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else { return };
    let shaped = recovery_key::looks_like_recovery_key(input);
    match recovery_key::decode(input) {
        Ok(key) => {
            assert!(shaped);
            let text = recovery_key::encode(&key);
            assert_eq!(*recovery_key::decode(&text).expect("own encoding decodes"), *key);
        }
        Err(recovery_key::RecoveryKeyError::Typo) => assert!(shaped),
        Err(recovery_key::RecoveryKeyError::NotAKey) => assert!(!shaped),
    }
});
