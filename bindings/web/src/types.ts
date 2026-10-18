// Records of @durio/stoat-crypto: the shapes of the Android FFI records
// (crates/stoat-crypto-ffi/src/types.rs) in camelCase. Strings for enums, `type`
// for sum types, `null` for absent values, numbers (never BigInt). Bodies,
// payload, envelope and EncryptedFile are JSON strings as on Android.
//
// Never log DecryptResult / DecryptedMessage (plaintext, attachment keys),
// RecoverySetup (recovery key), EncryptedAttachment.fileJson or KeyExport.

/** Where the account's crypto state lives (one store per account and server). */
export type StoreConfig =
  | { kind: "memory" }
  | {
      kind: "indexedDb";
      /** accountKey of 00-architecture §6: names the databases and the Web Lock */
      accountKey: string;
      /** 32 raw bytes from Electron `safeStorage` (no PBKDF2); zero your copy after the call */
      key: Uint8Array;
    };

export interface IdentityKeys {
  curve25519: string;
  ed25519: string;
}

/** `GET /` → `features.e2ee` */
export interface ServerLimits {
  maxToDeviceBatch: number;
  maxRequestBytes: number;
}

/** Delays of the core's policies (tests shorten them) */
export interface Timing {
  keyRequestDelayMs: number;
  toDeviceRetryMs: number;
  toDeviceRetryAttempts: number;
  /** First delay after a failed own request, doubled per failure (default 1000) */
  ownRetryMs?: number;
}

export type RequestKind =
  | "KeysUpload"
  | "KeysQuery"
  | "KeysClaim"
  | "ToDevice"
  | "BackupVersionCreate"
  | "BackupKeys"
  | "SecretPut";

/**
 * HTTP request to perform: `method` `path` (relative to the API root) with the JSON
 * `body`; then exactly one `markRequestSent` or `markRequestFailed` with `id`, `kind`.
 */
export interface OutgoingRequest {
  id: string;
  kind: RequestKind;
  method: string;
  path: string;
  body: string;
}

export interface UndeliveredDevice {
  userId: string;
  deviceId: string;
  attempts: number;
  gaveUp: boolean;
}

/** A Megolm session arrived: re-decrypt messages of `channelId` waiting for it */
export interface RoomKeyInfo {
  channelId: string;
  sessionId: string;
}

export interface ToDeviceResult {
  /** Messages in the page: fetch again while it equals the `limit` */
  fetched: number;
  /** Send in `POST /e2ee/to_device/ack` (≤ 100 per call), then `markAckSent` */
  ackIds: string[];
  roomKeys: RoomKeyInfo[];
  processed: number;
  skippedDuplicates: number;
  undecryptable: number;
  /** Verification flows that changed: re-read their state */
  verifications: string[];
}

/** From `Channel.encryption`; absent = library defaults (1 week / 100 messages) */
export interface ChannelEncryptionSettings {
  rotationPeriodMs?: number | null;
  rotationPeriodMsgs?: number | null;
}

/** An encrypted channel message as the client got it from the server */
export interface IncomingEncryptedMessage {
  messageId: string;
  channelId: string;
  /** Author ULID as the server claims it */
  author: string;
  /** The message's `encrypted` object, as JSON */
  envelopeJson: string;
  /** The message's open `replies` */
  replies: string[];
  /** Server timestamp, milliseconds */
  timestamp: number;
}

/** UI shield */
export type Verification = "Verified" | "Unverified" | "UnknownDevice" | "Unauthenticated" | "Mismatch";

/** A decrypted message. `payloadJson` is plaintext: never log it. */
export interface DecryptedMessage {
  /** Payload v1 JSON (without padding) */
  payloadJson: string;
  senderUser: string;
  senderDevice: string | null;
  verification: Verification;
  sessionId: string;
  messageIndex: number;
  isReplay: boolean;
  staleEdit: boolean;
  editMismatch: boolean;
  replyMismatch: boolean;
  /** Nothing suspicious: show as a normal message (the shield still applies) */
  isClean: boolean;
}

export type WithheldReason = "Blocked" | "Unverified" | "Unauthorised" | "Unavailable" | "NoOlmSession" | "Other";

/** The exact cause */
export type DecryptError =
  | "MissingRoomKey"
  | "Withheld"
  | "UnknownAlgorithm"
  | "UnsupportedVersion"
  | "ChannelMismatch"
  | "SenderMismatch"
  | "Corrupted"
  | "Internal";

/** What the UI shows */
export type DecryptFailureKind =
  /** "Waiting for the key…": decrypt again on `ToDeviceResult.roomKeys` */
  | "WaitingForKey"
  | "Withheld"
  /** "Update the app" */
  | "UpdateApp"
  /** Tampered with by the server: never show as text */
  | "Suspicious"
  | "Broken"
  /** Store failure: try again later */
  | "RetryLater";

/** A failure is a value, not an exception */
export type DecryptResult =
  | { type: "Decrypted"; message: DecryptedMessage }
  | {
      type: "Failed";
      error: DecryptError;
      kind: DecryptFailureKind;
      withheldReason: WithheldReason | null;
      /** Stable code (diagnostics) */
      code: string;
    };

export type Trust = "Verified" | "Unverified" | "Blocked";

export interface DeviceInfo {
  userId: string;
  deviceId: string;
  curve25519: string | null;
  ed25519: string | null;
  trust: Trust;
  deleted: boolean;
}

/** Show `recoveryKey` once (`null` on a rotation), then run `request` */
export interface RecoverySetup {
  recoveryKey: string | null;
  request: OutgoingRequest;
}

/** Bodies of the four restore `GET`s, as the server returned them */
export interface RecoverySecrets {
  defaultKey: string;
  keyDescription: string;
  backupSecret: string;
  backupVersion: string;
}

export interface BackupStatus {
  version: string | null;
  enabled: boolean;
  recoverySetUp: boolean;
  outdated: boolean;
  keysTotal: number;
  keysBackedUp: number;
}

export interface RestoreProgress {
  done: number;
  total: number;
  imported: number;
  failed: number;
  finished: boolean;
}

/** A key export file (CR-21): save `data` as text. Not for logs either. */
export interface KeyExport {
  data: string;
  sessions: number;
}

export interface KeyImportResult {
  total: number;
  imported: number;
  /** Sessions of non-Stoat rooms (another Matrix client's export), left out */
  skipped: number;
  roomKeys: RoomKeyInfo[];
}

export type RecoveryKeyCheck = "Valid" | "Typo" | "NotAKey";

export interface SasEmoji {
  /** 0..64, index into the emoji table (and the translations) */
  index: number;
  symbol: string;
  /** English description = translation key */
  description: string;
}

export type CancelReason = "User" | "Timeout" | "Mismatch" | "AcceptedElsewhere" | "Other";

/** What the verification screen shows */
export type SasState =
  | { type: "Requested" }
  /** `accept()` or `cancel()` */
  | { type: "Incoming" }
  /** Either side may `start()` */
  | { type: "Ready" }
  | { type: "Started" }
  /** Compare, then `confirm()` or `mismatch()` */
  | { type: "ShowCodes"; emoji: SasEmoji[]; decimals: number[] }
  | { type: "Confirmed" }
  /** The device is verified */
  | { type: "Done" }
  | { type: "Cancelled"; reason: CancelReason; code: string; byUs: boolean };

/** A small blob in one call; `fileJson` holds the key: never log it */
export interface EncryptedAttachment {
  ciphertext: Uint8Array;
  fileJson: string;
}

/** `encryptBlob`: upload `blob`, put `fileJson` into the payload */
export interface EncryptedBlob {
  blob: Blob;
  fileJson: string;
  size: number;
}

export interface CoreInfo {
  coreVersion: string;
  payloadVersion: number;
  attachmentChunkSize: number;
}
