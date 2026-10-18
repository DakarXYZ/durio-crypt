//! CR-20, identifiers: Stoat ULIDs ↔ the ruma ids `OlmMachine` needs (C15).
//! String rules live in `stoat_crypto_proto::ids`; this module only wraps them
//! into ruma types. Nothing here is public API: ruma never leaves the crate.

use ruma::{OwnedDeviceId, OwnedRoomId, OwnedUserId, RoomId, UserId};
use stoat_crypto_proto::ids;

use crate::error::{CryptoError, Result};

/// `01J…` → `@01j…:stoat.invalid`
pub(crate) fn user_id(ulid: &str) -> Result<OwnedUserId> {
    let s = ids::user_id(ulid).map_err(|_| CryptoError::InvalidId)?;
    UserId::parse(s).map_err(|_| CryptoError::InvalidId)
}

/// `01J…` → `!01j…:stoat.invalid`
pub(crate) fn room_id(channel_ulid: &str) -> Result<OwnedRoomId> {
    let s = ids::room_id(channel_ulid).map_err(|_| CryptoError::InvalidId)?;
    RoomId::parse(s).map_err(|_| CryptoError::InvalidId)
}

/// Session ULID as is
pub(crate) fn device_id(session_ulid: &str) -> Result<OwnedDeviceId> {
    ids::device_id(session_ulid)
        .map(OwnedDeviceId::from)
        .map_err(|_| CryptoError::InvalidId)
}

/// `@01j…:stoat.invalid` → `01J…`; `None` for anything that is not ours
pub(crate) fn user_ulid(user_id: &UserId) -> Option<String> {
    ids::user_ulid(user_id.as_str())
}

/// `!01j…:stoat.invalid` → `01J…`
pub(crate) fn channel_ulid(room_id: &RoomId) -> Option<String> {
    ids::channel_ulid(room_id.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Table of the C15 mapping (CR-20: every mapping table-tested)
    #[test]
    fn table() {
        let cases = [
            (
                "01KAAAAAAAAAAAAAAAAAAAAAAA",
                "@01kaaaaaaaaaaaaaaaaaaaaaaa:stoat.invalid",
                "!01kaaaaaaaaaaaaaaaaaaaaaaa:stoat.invalid",
            ),
            (
                "01JABCDEFGHJKMNPQRSTVWXYZ0",
                "@01jabcdefghjkmnpqrstvwxyz0:stoat.invalid",
                "!01jabcdefghjkmnpqrstvwxyz0:stoat.invalid",
            ),
        ];
        for (ulid, user, room) in cases {
            let u = user_id(ulid).unwrap();
            assert_eq!(u.as_str(), user);
            // lowercase local part is "fully conforming" for ruma, not historical
            assert!(!u.is_historical());
            assert_eq!(user_ulid(&u).as_deref(), Some(ulid));
            let r = room_id(ulid).unwrap();
            assert_eq!(r.as_str(), room);
            assert_eq!(channel_ulid(&r).as_deref(), Some(ulid));
            assert_eq!(device_id(ulid).unwrap().as_str(), ulid);
        }
    }

    #[test]
    fn rejects() {
        for bad in [
            "",
            "x",
            "01KAAAAAAAAAAAAAAAAAAAAAA:",
            "@01kaaaaaaaaaaaaaaaaaaaaaaa:stoat.invalid",
        ] {
            assert_eq!(user_id(bad), Err(CryptoError::InvalidId), "{bad}");
            assert_eq!(room_id(bad), Err(CryptoError::InvalidId), "{bad}");
            assert_eq!(device_id(bad), Err(CryptoError::InvalidId), "{bad}");
        }
        let foreign = UserId::parse("@alice:example.org").unwrap();
        assert_eq!(user_ulid(&foreign), None);
        let foreign = RoomId::parse("!abc:example.org").unwrap();
        assert_eq!(channel_ulid(&foreign), None);
    }
}
