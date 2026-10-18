//! E2EE events on the Stoat WebSocket (bonfire, BE-09).
//!
//! Both are doorbells: no secret content travels over the socket.
//! `E2eeToDevice` is sent only to the socket of the recipient session; a
//! missed doorbell is not repeated — clients fetch the mailbox after `Ready`.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum E2eeEvent {
    /// A to-device message is waiting in the mailbox
    E2eeToDevice {
        /// Mailbox message id
        id: String,
        /// Recipient device (session ULID)
        recipient_device: String,
        /// Matrix-shaped id of the sending user
        sender: String,
        /// Sending device
        sender_device: String,
        /// Event type of the message (`type` is the event tag)
        event_type: String,
    },
    /// Devices of a user changed: their keys must be queried again.
    /// `user` is a Stoat ULID (this is a Stoat event).
    E2eeDeviceListUpdate { user: String },
}
