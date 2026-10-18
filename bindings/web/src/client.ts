// Page side of @durio/stoat-crypto: `StoatCrypto` drives one crypto worker (= one account
// on one server) over the RPC. Every method is async; the API is the Android FFI's
// (`stoat-crypto-ffi`) in camelCase, the host contract is the core's (crate docs of
// `stoat-crypto`: open → limits → request passes, mailbox + ack, prepareSend → encrypt …).
//
// Secrets (store key, passphrases, recovery key) go to the worker as a fresh copy that
// is transferred, so the page keeps none; zero the arrays you passed in yourself.

import { StoatCryptoError } from "./errors.js";
import { type Endpoint, RpcClient } from "./rpc.js";
import type {
  BackupStatus,
  ChannelEncryptionSettings,
  CoreInfo,
  DecryptResult,
  DeviceInfo,
  EncryptedAttachment,
  EncryptedBlob,
  IdentityKeys,
  IncomingEncryptedMessage,
  KeyExport,
  KeyImportResult,
  OutgoingRequest,
  RecoveryKeyCheck,
  RecoverySecrets,
  RecoverySetup,
  RequestKind,
  RestoreProgress,
  SasEmoji,
  SasState,
  ServerLimits,
  StoreConfig,
  Timing,
  ToDeviceResult,
  UndeliveredDevice,
} from "./types.js";

/** UTF-8 bytes for the worker, in a buffer of their own (transferred) */
function secret(input: string | Uint8Array): Uint8Array<ArrayBuffer> {
  return typeof input === "string" ? new TextEncoder().encode(input) : new Uint8Array(input);
}

/** A copy whose buffer can be transferred */
function own(data: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(data);
}

interface SasInfo {
  handle: number;
  flowId: string;
  otherUserId: string;
  isSelfVerification: boolean;
}

/** One crypto worker. `start` it, `open` the account's machine, `terminate` on sign-out. */
export class StoatCrypto {
  private constructor(
    private readonly rpc: RpcClient,
    readonly info: CoreInfo,
    private readonly worker: Worker | null,
  ) {}

  /**
   * Wrap a module worker running `serveCryptoWorker()` (or any endpoint) and load the
   * wasm in it. `new Worker(new URL("./e2ee.worker.ts", import.meta.url), {type: "module"})`.
   */
  static async start(worker: Worker | Endpoint): Promise<StoatCrypto> {
    const rpc = new RpcClient(worker);
    const isWorker = typeof Worker !== "undefined" && worker instanceof Worker;
    if (isWorker) {
      // an uncaught error of the worker (failed wasm load, trap): no call is answered
      worker.addEventListener("error", () => rpc.close({ code: "Panic", message: "the crypto worker failed" }));
    }
    const info = await rpc.call<CoreInfo>("init");
    return new StoatCrypto(rpc, info, isWorker ? worker : null);
  }

  #m<T>(method: string, ...args: unknown[]): Promise<T> {
    return this.rpc.call<T>("call", [method, args]);
  }

  // ------------------------------------------------------------- lifecycle

  /**
   * Open (or create) the state of `userId` on this device (session id). An IndexedDB
   * store is opened only under the Web Lock `durio-e2ee:<accountKey>`: `StoreLocked`
   * while another window or worker holds it ("encryption is active in another window").
   */
  open(userId: string, deviceId: string, store: StoreConfig): Promise<void> {
    if (store.kind !== "indexedDb") return this.rpc.call("open", [userId, deviceId, store]);
    const key = own(store.key);
    return this.rpc.call("open", [userId, deviceId, { ...store, key }], [key.buffer]);
  }

  /** Free the machine and its handles, release the lock (the worker stays usable) */
  close(): Promise<void> {
    return this.rpc.call("close");
  }

  /** Delete the IndexedDB store of a signed-out account (machine closed everywhere) */
  destroyStore(accountKey: string): Promise<void> {
    return this.rpc.call("destroyStore", [accountKey]);
  }

  /** Stop the worker (releases the lock); pending calls fail with `WorkerClosed` */
  terminate(): void {
    this.worker?.terminate();
    this.rpc.close();
  }

  identityKeys(): Promise<IdentityKeys> {
    return this.#m("identityKeys");
  }

  // -------------------------------------------------------------- requests

  setServerLimits(limits: ServerLimits): Promise<void> {
    return this.#m("setServerLimits", limits);
  }

  setTiming(timing: Timing): Promise<void> {
    return this.#m("setTiming", timing);
  }

  /** The request pass: run each id once (keep a set of ids in flight) */
  outgoingRequests(): Promise<OutgoingRequest[]> {
    return this.#m("outgoingRequests");
  }

  /** 2xx: `body` = the response JSON ("" for 204) */
  markRequestSent(id: string, kind: RequestKind, body: string): Promise<void> {
    return this.#m("markRequestSent", id, kind, body);
  }

  /** Non-2xx (0: no response). `MfaRequired`, `BackupVersionChanged`, `DeviceKeysConflict`, `RequestRejected` need the UI */
  markRequestFailed(id: string, kind: RequestKind, status: number): Promise<void> {
    return this.#m("markRequestFailed", id, kind, status);
  }

  /** When to run a request pass without another event (`null`: nothing scheduled) */
  wakeupInMs(): Promise<number | null> {
    return this.#m("wakeupInMs");
  }

  undeliveredDevices(): Promise<UndeliveredDevice[]> {
    return this.#m("undeliveredDevices");
  }

  // --------------------------------------------------------------- mailbox

  /** `GET /e2ee/to_device?limit=N` body → ack ids, room keys, changed verifications */
  receiveToDevice(body: string): Promise<ToDeviceResult> {
    return this.#m("receiveToDevice", body);
  }

  markAckSent(ackIds: string[]): Promise<void> {
    return this.#m("markAckSent", ackIds);
  }

  receiveDeviceListUpdate(users: string[]): Promise<void> {
    return this.#m("receiveDeviceListUpdate", users);
  }

  receiveReconnect(): Promise<void> {
    return this.#m("receiveReconnect");
  }

  /** `GET /e2ee/keys/count` body */
  receiveOtkCounts(body: string): Promise<void> {
    return this.#m("receiveOtkCounts", body);
  }

  // -------------------------------------------------------------- channels

  setChannelMembers(channelId: string, members: string[], settings?: ChannelEncryptionSettings): Promise<void> {
    return this.#m("setChannelMembers", channelId, members, settings ?? null);
  }

  /** Requests to run before `encrypt`; loop until empty */
  prepareSend(channelId: string): Promise<OutgoingRequest[]> {
    return this.#m("prepareSend", channelId);
  }

  /** Payload v1 JSON → envelope JSON (`RoomKeyNotShared` → back to `prepareSend`) */
  encrypt(channelId: string, payloadJson: string): Promise<string> {
    return this.#m("encrypt", channelId, payloadJson);
  }

  invalidateOutboundSession(channelId: string): Promise<void> {
    return this.#m("invalidateOutboundSession", channelId);
  }

  decrypt(message: IncomingEncryptedMessage): Promise<DecryptResult> {
    return this.#m("decrypt", message);
  }

  /** A history page: results in input order */
  decryptBatch(messages: IncomingEncryptedMessage[]): Promise<DecryptResult[]> {
    return this.#m("decryptBatch", messages);
  }

  // --------------------------------------------------------------- devices

  devices(userId: string): Promise<DeviceInfo[]> {
    return this.#m("devices", userId);
  }

  /** `Unverified` (reset) or `Blocked`; `Verified` comes from SAS only (review O-3) */
  setDeviceTrust(userId: string, deviceId: string, trust: "Unverified" | "Blocked"): Promise<void> {
    return this.#m("setDeviceTrust", userId, deviceId, trust);
  }

  // ---------------------------------------------------------- verification

  async requestVerification(userId: string, deviceId: string): Promise<SasFlow> {
    return new SasFlow(this.rpc, await this.rpc.call<SasInfo>("requestVerification", [userId, deviceId]));
  }

  /** The flow of an id from `ToDeviceResult.verifications` */
  async verification(flowId: string): Promise<SasFlow | null> {
    const info = await this.rpc.call<SasInfo | null>("verification", [flowId]);
    return info && new SasFlow(this.rpc, info);
  }

  async verifications(): Promise<SasFlow[]> {
    return (await this.rpc.call<SasInfo[]>("verifications")).map((i) => new SasFlow(this.rpc, i));
  }

  // ---------------------------------------------------------------- backup

  createRecovery(passphrase?: string | Uint8Array): Promise<RecoverySetup> {
    if (passphrase === undefined) return this.rpc.call("createRecovery", [null]);
    const p = secret(passphrase);
    return this.rpc.call("createRecovery", [p], [p.buffer]);
  }

  rotateBackup(): Promise<RecoverySetup> {
    return this.#m("rotateBackup");
  }

  /** Recovery key or passphrase + the four GET bodies → the backup version */
  unlockBackup(input: string | Uint8Array, secrets: RecoverySecrets): Promise<string> {
    const i = secret(input);
    return this.rpc.call("unlockBackup", [i, secrets], [i.buffer]);
  }

  async restoreBackup(keysBody: string): Promise<BackupRestore> {
    return new BackupRestore(this.rpc, await this.rpc.call<number>("restoreBackup", [keysBody]));
  }

  backupStatus(): Promise<BackupStatus> {
    return this.#m("backupStatus");
  }

  disableBackup(): Promise<void> {
    return this.#m("disableBackup");
  }

  // ------------------------------------------------------------ key export

  /** Seconds of PBKDF2; the worker answers nothing else meanwhile */
  exportRoomKeys(passphrase: string | Uint8Array, channelIds: string[] = []): Promise<KeyExport> {
    const p = secret(passphrase);
    return this.rpc.call("exportRoomKeys", [p, channelIds], [p.buffer]);
  }

  importRoomKeys(file: string, passphrase: string | Uint8Array): Promise<KeyImportResult> {
    const p = secret(passphrase);
    return this.rpc.call("importRoomKeys", [file, p], [p.buffer]);
  }

  /** JSON without secrets for "Send report" (CR-22) */
  debugReport(): Promise<string> {
    return this.#m("debugReport");
  }

  // ----------------------------------------------------------- attachments

  /** Encrypt a file in the worker; upload `blob`, put `fileJson` into the payload */
  encryptBlob(blob: Blob): Promise<EncryptedBlob> {
    return this.rpc.call("encryptBlob", [blob]);
  }

  /** Verify the hash of the downloaded blob, then decrypt (`AttachmentHashMismatch`: show nothing) */
  decryptBlob(blob: Blob, fileJson: string, contentType?: string): Promise<Blob> {
    return this.rpc.call("decryptBlob", [blob, fileJson, contentType]);
  }

  async attachmentEncryptor(): Promise<AttachmentEncryptor> {
    return new AttachmentEncryptor(this.rpc, await this.rpc.call<number>("attachmentEncryptor"));
  }

  async attachmentVerifier(fileJson: string): Promise<AttachmentVerifier> {
    return new AttachmentVerifier(this.rpc, await this.rpc.call<number>("attachmentVerifier", [fileJson]));
  }

  /** Small blobs (thumbnails) in one call */
  encryptAttachment(data: Uint8Array): Promise<EncryptedAttachment> {
    const d = own(data);
    return this.rpc.call("encryptAttachment", [d], [d.buffer]);
  }

  decryptAttachment(ciphertext: Uint8Array, fileJson: string): Promise<Uint8Array> {
    const c = own(ciphertext);
    return this.rpc.call("decryptAttachment", [c, fileJson], [c.buffer]);
  }

  // ------------------------------------------------------------- utilities

  recoveryKeyCheck(input: string | Uint8Array): Promise<RecoveryKeyCheck> {
    const i = secret(input);
    return this.rpc.call("recoveryKeyCheck", [i], [i.buffer]);
  }

  /** Payload v1 JSON of a text message (`clientNonce` = the send request's `nonce`) */
  textPayload(content: string, clientNonce: string, ts: number): Promise<string> {
    return this.rpc.call("textPayload", [content, clientNonce, ts]);
  }

  /** autumn ids for the open `attachments` of the send request (files and thumbnails) */
  payloadFileIds(payloadJson: string): Promise<string[]> {
    return this.rpc.call("payloadFileIds", [payloadJson]);
  }

  sasEmojiTable(): Promise<SasEmoji[]> {
    return this.rpc.call("sasEmojiTable");
  }
}

/** A worker-side object; `free()` it when done (calls after that: `AlreadyFinished`) */
abstract class Handle {
  constructor(
    protected readonly rpc: RpcClient,
    readonly handle: number,
  ) {}

  protected h<T>(method: string, args: unknown[] = [], transfer: Transferable[] = []): Promise<T> {
    return this.rpc.call<T>("handle", [this.handle, method, args], transfer);
  }

  free(): Promise<void> {
    return this.rpc.call("free", [this.handle]);
  }
}

/** One SAS flow (CR-11): re-read `state()` after every mailbox pass and every action */
export class SasFlow extends Handle {
  readonly flowId: string;
  /** The other user (ULID); our own for a self-verification */
  readonly otherUserId: string;
  readonly isSelfVerification: boolean;

  constructor(rpc: RpcClient, info: SasInfo) {
    super(rpc, info.handle);
    this.flowId = info.flowId;
    this.otherUserId = info.otherUserId;
    this.isSelfVerification = info.isSelfVerification;
  }

  state(): Promise<SasState> {
    return this.h("state");
  }

  otherDeviceId(): Promise<string | null> {
    return this.h<string | undefined>("otherDeviceId").then((d) => d ?? null);
  }

  accept(): Promise<void> {
    return this.h("accept");
  }

  start(): Promise<void> {
    return this.h("start");
  }

  confirm(): Promise<void> {
    return this.h("confirm");
  }

  /** The codes differ: possible attack, nobody becomes verified */
  mismatch(): Promise<void> {
    return this.h("mismatch");
  }

  cancel(): Promise<void> {
    return this.h("cancel");
  }
}

/** Backup restore in batches (CR-12): `next()` until `finished` */
export class BackupRestore extends Handle {
  progress(): Promise<RestoreProgress> {
    return this.h("progress");
  }

  /** Up to `max` sessions (0 = the default batch) */
  next(max = 0): Promise<RestoreProgress> {
    return this.h("next", [max]);
  }
}

/** Streamed upload encryption; `finish()` gives the `EncryptedFile` JSON and frees it */
export class AttachmentEncryptor extends Handle {
  update(chunk: Uint8Array): Promise<Uint8Array> {
    const c = own(chunk);
    return this.h("update", [c], [c.buffer]);
  }

  size(): Promise<number> {
    return this.h("size");
  }

  finish(): Promise<string> {
    return this.h("finish");
  }
}

/** First pass over a download: hash; `finish()` → the decryptor for the second pass */
export class AttachmentVerifier extends Handle {
  update(chunk: Uint8Array): Promise<void> {
    const c = own(chunk);
    return this.h("update", [c], [c.buffer]);
  }

  async finish(): Promise<AttachmentDecryptor> {
    return new AttachmentDecryptor(this.rpc, await this.h<number>("finish"));
  }
}

export class AttachmentDecryptor extends Handle {
  update(chunk: Uint8Array): Promise<Uint8Array> {
    const c = own(chunk);
    return this.h("update", [c], [c.buffer]);
  }
}

export { StoatCryptoError };
