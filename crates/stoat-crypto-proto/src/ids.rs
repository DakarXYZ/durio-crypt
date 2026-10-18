//! Identifier mapping between Stoat ULIDs and the Matrix-shaped identifiers in
//! `/e2ee/*` bodies and inside signed key objects (decision C15).
//!
//! * user: `@{lower(ulid)}:stoat.invalid`
//! * channel (room): `!{lower(ulid)}:stoat.invalid`
//! * device: the session ULID as is
//!
//! The server name is a constant (RFC 6761 `.invalid`) so moving an instance to
//! another domain never changes the `user_id` inside signed device keys.
//! Parsing accepts only the canonical lowercase form — the same rule as the
//! backend (`revolt_models::v0::user_id_from_e2ee`).

use thiserror::Error;

/// Server name of every Matrix-shaped identifier
pub const SERVER_NAME: &str = "stoat.invalid";

/// Length of a ULID in its text form
pub const ULID_LEN: usize = 26;

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum IdError {
    /// Not a 26-character alphanumeric ULID
    #[error("not a ULID")]
    NotUlid,
}

/// Whether `s` looks like a ULID: 26 ASCII alphanumerics
///
/// Crockford's alphabet is not enforced: the backend does not enforce it
/// either, and the check only guards the identifier grammar.
pub fn is_ulid(s: &str) -> bool {
    s.len() == ULID_LEN && s.bytes().all(|b| b.is_ascii_alphanumeric())
}

fn matrix_id(sigil: char, ulid: &str) -> Result<String, IdError> {
    if !is_ulid(ulid) {
        return Err(IdError::NotUlid);
    }
    Ok(format!("{sigil}{}:{SERVER_NAME}", ulid.to_ascii_lowercase()))
}

/// `01J…` → `@01j…:stoat.invalid`
pub fn user_id(ulid: &str) -> Result<String, IdError> {
    matrix_id('@', ulid)
}

/// `01J…` → `!01j…:stoat.invalid`
pub fn room_id(channel_ulid: &str) -> Result<String, IdError> {
    matrix_id('!', channel_ulid)
}

/// Device ids are session ULIDs as is
pub fn device_id(session_ulid: &str) -> Result<String, IdError> {
    if !is_ulid(session_ulid) {
        return Err(IdError::NotUlid);
    }
    Ok(session_ulid.to_owned())
}

fn parse(id: &str, sigil: char) -> Option<String> {
    let local = id.strip_prefix(sigil)?.strip_suffix(SERVER_NAME)?.strip_suffix(':')?;
    (local.len() == ULID_LEN && local.bytes().all(|b| b.is_ascii_digit() || b.is_ascii_lowercase()))
        .then(|| local.to_ascii_uppercase())
}

/// `@01j…:stoat.invalid` → `01J…`; `None` for foreign servers and non-canonical forms
pub fn user_ulid(matrix_user_id: &str) -> Option<String> {
    parse(matrix_user_id, '@')
}

/// `!01j…:stoat.invalid` → `01J…`; `None` for foreign servers and non-canonical forms
pub fn channel_ulid(matrix_room_id: &str) -> Option<String> {
    parse(matrix_room_id, '!')
}

#[cfg(test)]
mod tests {
    use super::*;

    const U: &str = "01KAAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn roundtrip() {
        let user = user_id(U).unwrap();
        assert_eq!(user, "@01kaaaaaaaaaaaaaaaaaaaaaaa:stoat.invalid");
        assert_eq!(user_ulid(&user).as_deref(), Some(U));
        let room = room_id(U).unwrap();
        assert_eq!(room, "!01kaaaaaaaaaaaaaaaaaaaaaaa:stoat.invalid");
        assert_eq!(channel_ulid(&room).as_deref(), Some(U));
        assert_eq!(device_id(U).unwrap(), U);
        // lowercase input is accepted and normalised
        assert_eq!(user_id(&U.to_ascii_lowercase()).unwrap(), user);
    }

    /// Same table as the backend test `matrix_ids`
    #[test]
    fn parse_is_strict() {
        for bad in [
            "@01KAAAAAAAAAAAAAAAAAAAAAAA:stoat.invalid",
            "@01kaaaaaaaaaaaaaaaaaaaaaaa:example.com",
            "@01kaaaaaaaaaaaaaaaaaaaaaa:stoat.invalid",
            "!01kaaaaaaaaaaaaaaaaaaaaaaa:stoat.invalid",
            "@01kaaaaaaaaaaaaaaaaaaaaaaastoat.invalid",
            "@01kaaaaaaaaaaaaaaaaaaaaa-a:stoat.invalid",
            "",
        ] {
            assert_eq!(user_ulid(bad), None, "{bad}");
        }
        assert_eq!(channel_ulid("@01kaaaaaaaaaaaaaaaaaaaaaaa:stoat.invalid"), None);
    }

    #[test]
    fn rejects_non_ulids() {
        for bad in [
            "",
            "short",
            "01KAAAAAAAAAAAAAAAAAAAAAA:",
            "01KAAAAAAAAAAAAAAAAAAAAAAAA",
            "01KAAAAAAAAAAAAAAAAAAAAA@A",
        ] {
            assert_eq!(user_id(bad), Err(IdError::NotUlid), "{bad}");
            assert_eq!(room_id(bad), Err(IdError::NotUlid), "{bad}");
            assert_eq!(device_id(bad), Err(IdError::NotUlid), "{bad}");
        }
    }
}
