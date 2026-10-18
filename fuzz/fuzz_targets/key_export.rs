//! Key export armor (CR-21, review O-7): never panics; an accepted file has
//! sane rounds and its normalized form parses to itself.
#![no_main]

use libfuzzer_sys::fuzz_target;
use stoat_crypto_proto::key_export;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else { return };
    if let Ok(file) = key_export::parse(input) {
        assert!((1..=key_export::MAX_ROUNDS).contains(&file.rounds));
        let again = key_export::parse(&file.armored).expect("normalized form parses");
        assert_eq!(again, file);
    }
});
