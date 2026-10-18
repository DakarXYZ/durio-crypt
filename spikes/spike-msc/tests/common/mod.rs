#![allow(dead_code)]

use spike_msc::client::Client;
use spike_msc::fakeserver::{FakeServer, Server, StoredMessage};
use spike_msc::payload::PayloadV1;

/// Deterministic ULID-shaped ids for readable tests: `ulid("A")` → `01KAAAAA…`.
pub fn ulid(tag: &str) -> String {
    let t = tag.to_ascii_uppercase();
    format!("01K{}", t.repeat(23 / t.len() + 1)).chars().take(26).collect()
}

pub fn dev(tag: &str) -> String {
    format!("01KD{}", tag.to_ascii_uppercase().repeat(22))
        .chars()
        .take(26)
        .collect()
}

pub fn server() -> Server {
    FakeServer::new()
}

/// Session ULIDs are globally unique (device id = session id).
/// Log in + upload device keys / OTKs.
pub async fn login(server: &Server, user: &str, device: &str) -> Client {
    let mut c = Client::open_memory(server, &ulid(user), &dev(&format!("{user}{device}")))
        .await
        .unwrap();
    c.sync().await.unwrap();
    c
}

pub fn text(t: &str) -> PayloadV1 {
    PayloadV1 {
        v: 1,
        content: Some(t.to_owned()),
        client_nonce: "AAAAAAAAAAAAAAAAAAAAAA".into(),
        ts: 1_760_700_000_000,
        ..Default::default()
    }
}

pub fn channel(server: &Server, name: &str, users: &[&str]) -> String {
    let id = ulid(name);
    let members: Vec<String> = users.iter().map(|u| ulid(u)).collect();
    let refs: Vec<&str> = members.iter().map(String::as_str).collect();
    server.lock().unwrap().channel_set_members(&id, &refs);
    id
}

pub fn messages(server: &Server, channel: &str) -> Vec<StoredMessage> {
    server.lock().unwrap().channel_messages(channel)
}

pub fn last(server: &Server, channel: &str) -> StoredMessage {
    messages(server, channel).pop().unwrap()
}

pub async fn sync_all(clients: &mut [&mut Client]) {
    for _ in 0..3 {
        for c in clients.iter_mut() {
            c.sync().await.unwrap();
        }
    }
}
