//! `/e2ee/*` bodies and the identifier mapping never panic on hostile input.
#![no_main]

use libfuzzer_sys::fuzz_target;
use stoat_crypto_proto::{api, ids};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    if let Some(ulid) = ids::user_ulid(text) {
        assert_eq!(ids::user_id(&ulid).as_deref(), Ok(text));
    }
    let _ = ids::channel_ulid(text);
    let _ = serde_json::from_str::<api::ToDeviceFetchResponse>(text);
    let _ = serde_json::from_str::<api::KeysQueryResponse>(text);
    let _ = serde_json::from_str::<api::KeysClaimResponse>(text);
    let _ = serde_json::from_str::<api::KeysBackup>(text);
});
