// Worker side of @durio/stoat-crypto: the wasm module and ONE CryptoMachine (one
// worker per account, 50-web-sdk decision 3). The page talks to it through
// `StoatCrypto` (client.ts). In the app's worker file:
//
//   import { serveCryptoWorker } from "@durio/stoat-crypto/worker";
//   serveCryptoWorker();
//
// The wasm is loaded lazily on the first call (`import()` of the wasm-bindgen glue, then
// `instantiateStreaming` of the .wasm next to it — needs `Content-Type: application/wasm`,
// else it falls back to `instantiate`).
//
// Single writer (CR-17, Q28): an IndexedDB store is opened only while this worker holds
// the Web Lock `durio-e2ee:<accountKey>` (`ifAvailable`: another holder → `StoreLocked`).
// The lock is released on `close`, on a trap and when the worker is terminated.

import { StoatCryptoError, type ErrorInfo } from "./errors.js";
import { lockName, storeName } from "./names.js";
import { type Endpoint, serve, transfer } from "./rpc.js";
import type { StoreConfig } from "./types.js";
import type * as Wasm from "./wasm/stoat_crypto_wasm.js";

type WasmModule = typeof Wasm;
interface Freeable {
  free(): void;
}

export interface WorkerOptions {
  /** Defaults to the worker's global scope */
  endpoint?: Endpoint;
  /** Loads and initialises the wasm module (tests in Node pass `initSync`) */
  load?: () => Promise<WasmModule>;
}

const MACHINE_METHODS = new Set([
  "identityKeys", "setServerLimits", "setTiming", "outgoingRequests", "markRequestSent", "markRequestFailed",
  "wakeupInMs", "undeliveredDevices", "receiveToDevice", "markAckSent", "receiveDeviceListUpdate",
  "receiveReconnect", "receiveOtkCounts", "setChannelMembers", "prepareSend", "encrypt",
  "invalidateOutboundSession", "decrypt", "decryptBatch", "devices", "setDeviceTrust", "rotateBackup",
  "backupStatus", "disableBackup", "debugReport",
]);
// methods per handle kind; `finish` of a verifier returns a new handle
const HANDLE_METHODS: Record<string, Set<string>> = {
  sas: new Set(["state", "otherDeviceId", "accept", "start", "confirm", "mismatch", "cancel"]),
  restore: new Set(["progress", "next"]),
  encryptor: new Set(["update", "size", "finish"]),
  verifier: new Set(["update", "finish"]),
  decryptor: new Set(["update"]),
};

const defaultLoad = async (): Promise<WasmModule> => {
  const wasm = await import("./wasm/stoat_crypto_wasm.js");
  await wasm.default();
  return wasm;
};

/** Zero the worker's copy of a secret after the call (the page transferred it) */
function wipe(...arrays: unknown[]): void {
  for (const a of arrays) if (a instanceof Uint8Array) a.fill(0);
}

function bytes(v: unknown): Uint8Array {
  if (v instanceof Uint8Array) return v;
  throw new StoatCryptoError("InvalidInput", "invalid input: expected a Uint8Array");
}

export function serveCryptoWorker(options: WorkerOptions = {}): void {
  const endpoint = options.endpoint ?? (globalThis as unknown as Endpoint);
  const load = options.load ?? defaultLoad;
  let wasm: Promise<WasmModule> | null = null;
  let machine: Wasm.CryptoMachine | null = null;
  let releaseLock: (() => void) | null = null;
  let poisoned = false;
  const handles = new Map<number, { kind: string; obj: Freeable }>();
  let nextHandle = 1;

  const module = () => (wasm ??= load());
  const open = (): Wasm.CryptoMachine => {
    if (!machine) throw new StoatCryptoError("NotOpen", "no crypto machine is open in this worker");
    return machine;
  };
  const addHandle = (kind: string, obj: Freeable) => {
    const handle = nextHandle++;
    handles.set(handle, { kind, obj });
    return handle;
  };
  const sas = (h: Wasm.SasHandle | undefined) =>
    h && {
      handle: addHandle("sas", h),
      flowId: h.flowId(),
      otherUserId: h.otherUserId(),
      isSelfVerification: h.isSelfVerification(),
    };
  const freeHandle = (handle: number) => {
    handles.get(handle)?.obj.free();
    handles.delete(handle);
  };
  const release = () => {
    for (const { obj } of handles.values()) obj.free();
    handles.clear();
    machine?.free();
    machine = null;
    releaseLock?.();
    releaseLock = null;
  };

  /** Hold `name` until released; `null` when another context holds it */
  const takeLock = async (name: string): Promise<(() => void) | null> => {
    const locks = (globalThis.navigator as Navigator | undefined)?.locks;
    if (!locks) throw new StoatCryptoError("Store", "crypto store error during lock (no Web Locks)");
    return new Promise((resolve, reject) => {
      locks
        .request(name, { mode: "exclusive", ifAvailable: true }, (lock) => {
          if (!lock) return resolve(null);
          return new Promise<void>((done) => resolve(done));
        })
        .catch(reject);
    });
  };

  const deleteDatabase = (name: string) =>
    new Promise<void>((resolve, reject) => {
      const r = indexedDB.deleteDatabase(name);
      r.onsuccess = () => resolve();
      r.onerror = () => reject(new StoatCryptoError("Store", "crypto store error during delete store"));
      // another connection is still open (a leaked machine): the delete waits for it
      r.onblocked = () => reject(new StoatCryptoError("StoreLocked", "the crypto store is open in another instance"));
    });

  const PANIC: ErrorInfo = { code: "Panic", message: "internal crypto error (panic): start a new crypto worker" };
  const poison = () => {
    poisoned = true;
    releaseLock?.();
    releaseLock = null;
  };
  // panic = "abort": the instance is unusable from here on (CR-14). A trap inside a
  // call rejects that call; a trap in a wasm task (an async call's later poll) is an
  // uncaught error of the worker: fail every call of the page then
  const onError = (e: unknown): ErrorInfo | null => {
    if (!poisoned && !(e instanceof WebAssembly.RuntimeError)) return null;
    poison();
    return PANIC;
  };
  const scope = globalThis as unknown as Partial<Pick<EventTarget, "addEventListener">>;
  scope.addEventListener?.("error", (event) => {
    if (!((event as ErrorEvent).error instanceof WebAssembly.RuntimeError)) return;
    poison();
    endpoint.postMessage({ fatal: PANIC }, []);
  });
  const guard =
    <A extends unknown[]>(f: (...args: A) => unknown) =>
    (...args: A) => {
      if (poisoned) throw new WebAssembly.RuntimeError("poisoned");
      return f(...args);
    };

  serve(
    endpoint,
    Object.fromEntries(
      Object.entries({
        async init() {
          const w = await module();
          return { coreVersion: w.coreVersion(), payloadVersion: w.payloadVersion(), attachmentChunkSize: w.attachmentChunkSize() };
        },

        async open(userId: string, deviceId: string, store: StoreConfig) {
          const w = await module();
          if (machine) throw new StoatCryptoError("StoreLocked", "the crypto store is open in another instance");
          if (store?.kind !== "indexedDb") return void (machine = await w.CryptoMachine.open(userId, deviceId, store));
          try {
            const release = await takeLock(lockName(store.accountKey));
            if (!release) throw new StoatCryptoError("StoreLocked", "the crypto store is open in another instance");
            releaseLock = release;
            const config = { kind: "indexedDb", name: storeName(store.accountKey), key: bytes(store.key) };
            machine = await w.CryptoMachine.open(userId, deviceId, config);
          } catch (e) {
            releaseLock?.();
            releaseLock = null;
            throw e;
          } finally {
            wipe(store.key);
          }
        },

        close() {
          release();
        },

        /** Delete the IndexedDB store of a signed-out account (not while open anywhere) */
        async destroyStore(accountKey: string) {
          const w = await module();
          if (machine) throw new StoatCryptoError("StoreLocked", "the crypto store is open in another instance");
          const done = await takeLock(lockName(accountKey));
          if (!done) throw new StoatCryptoError("StoreLocked", "the crypto store is open in another instance");
          try {
            for (const name of w.indexeddbNames(storeName(accountKey))) await deleteDatabase(name);
          } finally {
            done();
          }
        },

        call(method: string, args: unknown[]) {
          if (!MACHINE_METHODS.has(method)) throw new StoatCryptoError("InvalidInput", "unknown method");
          const m = open() as unknown as Record<string, (...a: unknown[]) => unknown>;
          return m[method].apply(m, args);
        },

        async requestVerification(userId: string, deviceId: string) {
          return sas(await open().requestVerification(userId, deviceId));
        },
        verification(flowId: string) {
          return sas(open().verification(flowId)) ?? null;
        },
        verifications() {
          return open().verifications().map(sas);
        },
        async restoreBackup(keysBody: string) {
          return addHandle("restore", await open().restoreBackup(keysBody));
        },
        async createRecovery(passphrase: Uint8Array | null) {
          try {
            return await open().createRecovery(passphrase == null ? undefined : bytes(passphrase));
          } finally {
            wipe(passphrase);
          }
        },
        async unlockBackup(input: Uint8Array, secrets: unknown) {
          try {
            return await open().unlockBackup(bytes(input), secrets);
          } finally {
            wipe(input);
          }
        },
        async exportRoomKeys(passphrase: Uint8Array, channelIds: string[]) {
          try {
            return await open().exportRoomKeys(bytes(passphrase), channelIds);
          } finally {
            wipe(passphrase);
          }
        },
        async importRoomKeys(file: string, passphrase: Uint8Array) {
          try {
            return await open().importRoomKeys(file, bytes(passphrase));
          } finally {
            wipe(passphrase);
          }
        },

        async handle(handle: number, method: string, args: unknown[]) {
          const h = handles.get(handle);
          if (!h || !HANDLE_METHODS[h.kind]?.has(method)) throw new StoatCryptoError("AlreadyFinished", "the object is already finished");
          const obj = h.obj as unknown as Record<string, (...a: unknown[]) => unknown>;
          const value = await obj[method].apply(obj, args);
          // one-shot objects: `finish` ends the handle (a verifier's gives the decryptor)
          if (method === "finish") freeHandle(handle);
          if (h.kind === "verifier" && method === "finish") return addHandle("decryptor", value as Freeable);
          if (value instanceof Uint8Array) return transfer(value, [value.buffer]);
          return value;
        },
        free(handle: number) {
          freeHandle(handle);
        },

        // ---------------------------------------------------- no machine needed
        async attachmentEncryptor() {
          return addHandle("encryptor", new (await module()).AttachmentEncryptor());
        },
        async attachmentVerifier(fileJson: string) {
          return addHandle("verifier", new (await module()).AttachmentVerifier(fileJson));
        },
        async encryptAttachment(data: Uint8Array) {
          const r = (await module()).encryptAttachment(bytes(data)) as { ciphertext: Uint8Array; fileJson: string };
          return transfer(r, [r.ciphertext.buffer]);
        },
        async decryptAttachment(ciphertext: Uint8Array, fileJson: string) {
          const plain = (await module()).decryptAttachment(bytes(ciphertext), fileJson);
          return transfer(plain, [plain.buffer]);
        },
        /** Encrypt a whole file chunk by chunk inside the worker (WEB-06) */
        async encryptBlob(blob: Blob) {
          const w = await module();
          const enc = new w.AttachmentEncryptor();
          try {
            const parts: BlobPart[] = [];
            for await (const chunk of chunks(blob, w.attachmentChunkSize())) parts.push(enc.update(chunk) as Uint8Array<ArrayBuffer>);
            const size = enc.size();
            return { blob: new Blob(parts, { type: "application/octet-stream" }), fileJson: enc.finish(), size };
          } finally {
            enc.free();
          }
        },
        /** Verify the hash of the whole blob, then decrypt it (CR-10: never before) */
        async decryptBlob(blob: Blob, fileJson: string, type = "application/octet-stream") {
          const w = await module();
          const size = w.attachmentChunkSize();
          const verifier = new w.AttachmentVerifier(fileJson);
          let dec: Wasm.AttachmentDecryptor | undefined;
          try {
            for await (const chunk of chunks(blob, size)) verifier.update(chunk);
            dec = verifier.finish();
            const parts: BlobPart[] = [];
            for await (const chunk of chunks(blob, size)) parts.push(dec.update(chunk) as Uint8Array<ArrayBuffer>);
            return new Blob(parts, { type });
          } finally {
            verifier.free();
            dec?.free();
          }
        },
        async recoveryKeyCheck(input: Uint8Array) {
          try {
            return (await module()).recoveryKeyCheck(bytes(input));
          } finally {
            wipe(input);
          }
        },
        async textPayload(content: string, clientNonce: string, ts: number) {
          return (await module()).textPayload(content, clientNonce, ts);
        },
        async payloadFileIds(payloadJson: string) {
          return (await module()).payloadFileIds(payloadJson);
        },
        async sasEmojiTable() {
          return (await module()).sasEmojiTable();
        },
      }).map(([name, f]) => [name, guard(f as (...a: unknown[]) => unknown)]),
    ),
    onError,
  );
}

/** The blob in pieces of `size` bytes */
async function* chunks(blob: Blob, size: number): AsyncGenerator<Uint8Array> {
  for (let at = 0; at < blob.size; at += size) {
    yield new Uint8Array(await blob.slice(at, at + size).arrayBuffer());
  }
}
