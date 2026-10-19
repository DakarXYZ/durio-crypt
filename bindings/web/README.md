# @durio/stoat-crypto — the crypto core for for-web (CR-14)

The dur.io crypto core (`crates/stoat-crypto`: matrix-sdk-crypto 0.19.1 behind our adapter) as wasm in a
dedicated Web Worker, for for-web packaged inside the Windows client (O3: there is no browser web client).
Same API and behaviour as the Android AAR (`crates/stoat-crypto-ffi`); version = version of the Rust crates.

- `@durio/stoat-crypto` — page side: `StoatCrypto` (typed RPC client), types, `StoatCryptoError`. Never loads
  the wasm.
- `@durio/stoat-crypto/worker` — worker side: `serveCryptoWorker()`; loads the wasm lazily (`import()` of the
  wasm-bindgen glue on the first call).

## Build

```bash
scripts/build-wasm.sh all      # tools + build + test; on a Windows dev host it runs itself in Docker
scripts/build-wasm.sh build    # → bindings/web/dist/ (+ dist/wasm/*.sha256), bindings/web/build/durio-stoat-crypto-<v>.tgz(.sha256)
scripts/build-wasm.sh test     # wasm-bindgen-test in Node (crates/stoat-crypto-wasm/tests) + node --test test/
scripts/build-wasm.sh analyze  # twiggy top of a build with the name section
```

Pipeline (C25, no wasm-pack): `cargo build --profile release-wasm --target wasm32-unknown-unknown -p
stoat-crypto-wasm` (fat LTO, `opt-level = "z"`, `panic = "abort"`) → `wasm-bindgen 0.2.129 --target web` (CLI =
crate version, pinned) → `wasm-opt -Oz --strip-debug` (binaryen 123) → `scripts/check-wasm-size.sh` → `tsc` →
`npm pack`. Tools are downloaded with pinned SHA-256 (`build-wasm.sh tools`). getrandom: the wasm graph has
getrandom 0.4 (vodozemac, ruma, …) with `wasm_js` enabled through `matrix-sdk-crypto/js` → `vodozemac/wasm_js`;
0.3 is not in it, so no `--cfg getrandom_backend` is needed. vodozemac keeps `precomputed-tables` (a default
feature matrix-sdk-crypto does not turn off).

## Size

0.2.1 (2026-10-19), `stoat_crypto_wasm_bg.wasm` after `wasm-opt -Oz --strip-debug`:

| Artifact | raw | gzip -9 | Limit (`check-wasm-size.sh`) | Budget C23 |
| --- | --- | --- | --- | --- |
| `stoat_crypto_wasm_bg.wasm` (core + IndexedDB store) | 3 784 786 | 1 423 479 (1.36 MiB) | raw 3 968 000, gzip 1 494 000 (+5 %) | ≤ 3 MiB gzip ✅ |
| `stoat_crypto_wasm.js` (wasm-bindgen glue) | 88 463 | — | — | — |
| npm tarball | 1 471 761 | — | — | — |

Reference: Element's `matrix-sdk-crypto-wasm` is 2.10 MB gzip; the CR-01 probe (part of the library reachable,
IndexedDB) was 0.94 MB gzip — the real surface adds SAS, backup and secret storage, key export, our adapter and
the IndexedDB migrations. `twiggy` (`build-wasm.sh analyze`, before wasm-opt): no dominator worth cutting —
a long tail of async state machines (largest: `matrix-sdk-indexeddb` schema migrations 41 KB, our
`decrypt_one` 27 KB, `OlmMachine::decrypt_room_event_inner` 14 KB), static data 318 KB (curve25519
precomputed tables, SAS emoji, …). `precomputed-tables` stays: matrix-sdk-crypto depends on vodozemac with
default features, so turning it off needs a patched dependency (not worth ~40 KB under the budget).

## Using it in for-web (WEB-03)

```ts
// packages/client/components/client/e2ee/e2ee.worker.ts
import { serveCryptoWorker } from "@durio/stoat-crypto/worker";
serveCryptoWorker();

// page side, after login into an account with E2EE (lazy)
import { StoatCrypto, StoatCryptoError } from "@durio/stoat-crypto";
const worker = new Worker(new URL("./e2ee.worker.ts", import.meta.url), { type: "module" });
const crypto = await StoatCrypto.start(worker);
try {
  await crypto.open(userId, sessionId, { kind: "indexedDb", accountKey, key }); // key: 32 bytes from safeStorage
} catch (e) {
  if (e instanceof StoatCryptoError && e.code === "StoreLocked") { /* "encryption is active in another window" */ }
}
key.fill(0);
```

- Vite: `worker: { format: "es" }`; `optimizeDeps: { exclude: ["@durio/stoat-crypto"] }` so the glue's
  `new URL("stoat_crypto_wasm_bg.wasm", import.meta.url)` is kept and the `.wasm` lands in `assets/` with a hash.
  The `.wasm` needs `Content-Type: application/wasm` for `instantiateStreaming` (the Electron `protocol.handle`,
  D2); otherwise the glue falls back to `instantiate(arrayBuffer)`. CSP: `script-src 'wasm-unsafe-eval'` (WEB-11).
- One worker per account; one machine per worker. The worker holds the Web Lock `durio-e2ee:<accountKey>` while
  the IndexedDB store `durio-e2ee-<accountKey>` is open (`isAccountLocked(accountKey)` for the UI). No `@` in the
  names: for-web's sign-out cleanup deletes `@…` databases.
- Sign-out: `close()`, then `destroyStore(accountKey)`, then `terminate()`.
- A `Panic` error (wasm trap, `panic = "abort"`) means the instance is gone: `terminate()` and start a new worker.
- `exportRoomKeys` / `importRoomKeys` / `unlockBackup` / `createRecovery(passphrase)` run seconds of PBKDF2 in
  the worker; other calls wait meanwhile (one thread).
- Never log `DecryptResult`, `DecryptedMessage.payloadJson`, `RecoverySetup.recoveryKey`, `fileJson`, `KeyExport`.

### Depending on it

- **Development** (sibling clones in the workspace): build here, then in `for-web/packages/client`
  `pnpm add file:../../../stoat-crypto/bindings/web/build/durio-stoat-crypto-<v>.tgz` (pnpm records the
  tarball's integrity). For quick iteration on the TS side `link:../../../stoat-crypto/bindings/web` works too
  (needs `dist/` built and `server.fs.allow` for the wasm).
- **CI / releases**: the tarball of the GitHub Release of tag `v<version>` (`wasm.yml`):
  `"@durio/stoat-crypto": "https://github.com/DakarXYZ/durio-crypt/releases/download/v<v>/durio-stoat-crypto-<v>.tgz"`;
  the lockfile pins its integrity, compare it with the release's `.sha256`. Publishing to the npm registry
  (scope `@durio`) is wired in `wasm.yml` but off (`vars.NPM_PUBLISH`), a deploy step.

## API

Host contract — order of calls, request passes, ids in flight, mailbox and ack, send loop, SAS, backup,
attachments, the lock — is in `crates/stoat-crypto/src/lib.rs`. All methods return promises.

| `StoatCrypto` | Notes |
| --- | --- |
| `static start(worker)` → `info {coreVersion, payloadVersion, attachmentChunkSize}` | loads the wasm |
| `open(userId, deviceId, {kind: "indexedDb", accountKey, key} \| {kind: "memory"})`, `close()`, `destroyStore(accountKey)`, `terminate()` | `StoreLocked`: lock held elsewhere, or a machine is already open in this worker |
| `identityKeys()`, `setServerLimits({maxToDeviceBatch, maxRequestBytes})`, `setTiming({…})` | |
| `outgoingRequests()` → `{id, kind, method, path, body}[]`, `markRequestSent(id, kind, body)`, `markRequestFailed(id, kind, status)`, `wakeupInMs()`, `undeliveredDevices()` | |
| `receiveToDevice(body)` → `{fetched, ackIds, roomKeys, processed, skippedDuplicates, undecryptable, verifications}`, `markAckSent(ids)`, `receiveDeviceListUpdate(users)`, `receiveReconnect()`, `receiveOtkCounts(body)` | |
| `setChannelMembers(channelId, members, settings?)`, `prepareSend(channelId)`, `encrypt(channelId, payloadJson)` → envelope JSON, `invalidateOutboundSession(channelId)` | `textPayload(content, nonce, ts)`, `payloadFileIds(payloadJson)` |
| `decrypt(msg)`, `decryptBatch(msgs)` → `{type: "Decrypted", message} \| {type: "Failed", error, kind, withheldReason, code}` | `msg = {messageId, channelId, author, envelopeJson, replies, timestamp}` |
| `devices(userId)`, `setDeviceTrust(userId, deviceId, "Unverified" \| "Blocked")` | `Verified` only from SAS (O-3): refused with `InvalidInput` |
| `requestVerification(userId, deviceId)`, `verification(flowId)`, `verifications()` → `SasFlow {flowId, otherUserId, isSelfVerification, state(), otherDeviceId(), accept(), start(), confirm(), mismatch(), cancel(), free()}` | `state()`: `{type: "Requested" \| "Incoming" \| "Ready" \| "Started" \| "ShowCodes" (emoji, decimals) \| "Confirmed" \| "Done" \| "Cancelled" (reason, code, byUs)}`; `sasEmojiTable()` |
| `createRecovery(passphrase?)`, `rotateBackup()`, `unlockBackup(input, secrets)`, `restoreBackup(body)` → `BackupRestore {progress(), next(max), free()}`, `backupStatus()`, `disableBackup()`, `recoveryKeyCheck(input)` | secrets: `string \| Uint8Array` |
| `exportRoomKeys(passphrase, channelIds?)` → `{data, sessions}`, `importRoomKeys(file, passphrase)` → `{total, imported, skipped, roomKeys}`, `debugReport()` | |
| `encryptBlob(blob)` → `{blob, fileJson, size}`, `decryptBlob(blob, fileJson, type?)` → `Blob` (hash checked first); `attachmentEncryptor()`, `attachmentVerifier(fileJson)` → handles; `encryptAttachment(bytes)`, `decryptAttachment(bytes, fileJson)` | |

Errors: `StoatCryptoError {code}` — the FFI's codes (`StoreLocked`, `MfaRequired`, `BackupVersionChanged`,
`WrongPassphrase`, `InvalidKeyFile`, `PassphraseRequired`, `RequestRejected`, …, `InvalidInput`,
`AlreadyFinished`, `Panic`) plus `NotOpen` and `WorkerClosed`; messages are fixed texts without input.
