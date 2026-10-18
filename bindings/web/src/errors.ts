// Errors of @durio/stoat-crypto. `code` = the variant name of the Android FFI's
// CryptoError (Kotlin `CryptoException.<Code>`), the message is the core's fixed text:
// no keys, plaintext or input (CR-16). A failed decryption is a value, not an error.

export type StoatCryptoErrorCode =
  // core (crates/stoat-crypto/src/error.rs), same names as the FFI
  | "StoreLocked"
  | "StoreMismatch"
  | "Store"
  | "InvalidId"
  | "InvalidResponse"
  | "DeviceKeysConflict"
  | "UnknownChannel"
  | "RoomKeyNotShared"
  | "PayloadTooLarge"
  | "InvalidPayload"
  | "UnknownDevice"
  | "VerificationNotActive"
  | "MfaRequired"
  | "BackupVersionChanged"
  | "NoBackup"
  | "NoRecovery"
  | "RecoveryKeyTypo"
  | "WrongRecoveryKey"
  | "BackupKeyMismatch"
  | "InvalidRecoveryData"
  | "InvalidAttachment"
  | "AttachmentHashMismatch"
  | "PassphraseRequired"
  | "InvalidKeyFile"
  | "WrongPassphrase"
  | "RequestRejected"
  | "Internal"
  // bindings
  | "InvalidInput"
  | "AlreadyFinished"
  /** The wasm instance trapped (panic = abort): terminate the worker, start a new one */
  | "Panic"
  // worker
  /** No machine is open in this worker (`open` first) */
  | "NotOpen"
  /** The worker was terminated or closed; pending calls fail with this */
  | "WorkerClosed";

export class StoatCryptoError extends Error {
  readonly code: StoatCryptoErrorCode;

  constructor(code: StoatCryptoErrorCode, message: string) {
    super(message);
    this.name = "StoatCryptoError";
    this.code = code;
  }
}

/** Wire form (structured clone drops custom fields of an Error) */
export interface ErrorInfo {
  code: StoatCryptoErrorCode;
  message: string;
}

export function isStoatCryptoError(e: unknown): e is { name: "StoatCryptoError"; code: StoatCryptoErrorCode; message: string } {
  return (
    typeof e === "object" &&
    e !== null &&
    (e as { name?: unknown }).name === "StoatCryptoError" &&
    typeof (e as { code?: unknown }).code === "string"
  );
}
