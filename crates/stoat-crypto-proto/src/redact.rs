use std::fmt;

/// Printed in `Debug` output instead of secret material (ciphertext, plaintext, keys)
pub(crate) struct Redacted;

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}
