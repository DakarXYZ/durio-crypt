//! What `scripts/testkit-backend.sh check` looks for in Mongo and MinIO:
//! per scenario, the channels with a plaintext marker that must not appear
//! in any stored message, and the files with the hash of their plaintext.

use serde::Serialize;

use crate::Config;

#[derive(Debug, Default, Serialize)]
pub struct Evidence {
    pub messages: Vec<MessageEvidence>,
    pub files: Vec<FileEvidence>,
}

#[derive(Debug, Serialize)]
pub struct MessageEvidence {
    pub channel: String,
    /// A substring of every plaintext sent in the channel
    pub marker: String,
}

#[derive(Debug, Serialize)]
pub struct FileEvidence {
    /// autumn id
    pub id: String,
    /// hex SHA-256 of the plaintext (autumn names objects by the hash of the upload)
    pub plaintext_sha256: String,
}

impl Evidence {
    pub fn message(&mut self, channel: &str, marker: &str) {
        self.messages.push(MessageEvidence {
            channel: channel.to_owned(),
            marker: marker.to_owned(),
        });
    }

    pub fn file(&mut self, id: &str, plaintext_sha256: &str) {
        self.files.push(FileEvidence {
            id: id.to_owned(),
            plaintext_sha256: plaintext_sha256.to_owned(),
        });
    }

    /// `<out>/evidence/<scenario>.json`, if an output directory is set
    pub fn save(&self, config: &Config, scenario: &str) {
        let Some(out) = &config.out else { return };
        let dir = out.join("evidence");
        let _ = std::fs::create_dir_all(&dir);
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(dir.join(format!("{scenario}.json")), json);
        }
    }
}
