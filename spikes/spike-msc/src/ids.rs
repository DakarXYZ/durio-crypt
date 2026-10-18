//! Identifier mapping between Stoat (ULID) and the Matrix-shaped IDs that
//! `matrix-sdk-crypto` requires (decision C15).
//!
//! * user:    `@{lower(ulid)}:stoat.invalid`
//! * channel: `!{lower(channel_ulid)}:stoat.invalid`
//! * device:  session ULID as is (DeviceId is an opaque string)
//!
//! The server name is a constant (RFC 6761 `.invalid`) so moving an instance to
//! another domain never changes the `user_id` inside signed device keys.

use ruma::{OwnedDeviceId, OwnedRoomId, OwnedUserId, RoomId, UserId};

pub const SERVER_NAME: &str = "stoat.invalid";

pub fn user_id(ulid: &str) -> OwnedUserId {
    UserId::parse(format!("@{}:{SERVER_NAME}", ulid.to_ascii_lowercase())).expect("ULID always forms a valid localpart")
}

pub fn room_id(channel_ulid: &str) -> OwnedRoomId {
    RoomId::parse(format!("!{}:{SERVER_NAME}", channel_ulid.to_ascii_lowercase()))
        .expect("ULID always forms a valid room id")
}

pub fn device_id(session_ulid: &str) -> OwnedDeviceId {
    session_ulid.into()
}

/// `@01j…:stoat.invalid` → `01J…`. Returns `None` for foreign server names.
pub fn user_ulid(user_id: &UserId) -> Option<String> {
    (user_id.server_name().as_str() == SERVER_NAME).then(|| user_id.localpart().to_ascii_uppercase())
}

pub fn channel_ulid(room_id: &RoomId) -> Option<String> {
    let s = room_id.as_str();
    let rest = s.strip_prefix('!')?;
    let (local, server) = rest.split_once(':')?;
    (server == SERVER_NAME).then(|| local.to_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let u = "01JABCDEFGHJKMNPQRSTVWXYZ0";
        let uid = user_id(u);
        assert_eq!(uid.as_str(), "@01jabcdefghjkmnpqrstvwxyz0:stoat.invalid");
        // lower-case localpart is "fully conforming" for ruma (no historical id)
        assert!(!uid.is_historical());
        assert_eq!(user_ulid(&uid).unwrap(), u);
        let rid = room_id(u);
        assert_eq!(channel_ulid(&rid).unwrap(), u);
        assert_eq!(device_id(u).as_str(), u);
    }
}
