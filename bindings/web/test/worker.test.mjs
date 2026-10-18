// The package as for-web uses it: StoatCrypto (page) ↔ RPC ↔ serveCryptoWorker (worker)
// with the real release wasm. Node has no Web Worker: a MessageChannel stands in for the
// worker boundary (structured clone and transfers behave the same), the wasm is
// instantiated with initSync. The scenarios with a server are the wasm-bindgen tests
// (crates/stoat-crypto-wasm/tests/web.rs). Run: node --test test/*.test.mjs (after the build).

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { after, test } from "node:test";

import { StoatCrypto, StoatCryptoError, isStoatCryptoError, lockName, storeName } from "../dist/index.js";
import { serveCryptoWorker } from "../dist/worker.js";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const wasmBytes = readFileSync(new URL("../dist/wasm/stoat_crypto_wasm_bg.wasm", import.meta.url));
const load = async () => {
  const wasm = await import("../dist/wasm/stoat_crypto_wasm.js");
  wasm.initSync({ module: wasmBytes });
  return wasm;
};

const ports = [];
after(() => ports.forEach((p) => p.close()));

/** A "worker" on the other end of a MessageChannel */
async function start() {
  const { port1, port2 } = new MessageChannel();
  ports.push(port1, port2);
  serveCryptoWorker({ endpoint: port2, load });
  return { crypto: await StoatCrypto.start(port1), port: port1 };
}

const ulid = (tag) => `01K${tag.repeat(26)}`.slice(0, 26);
const dev = (tag) => `01KD${tag.repeat(26)}`.slice(0, 26);

async function rejects(promise, code) {
  const e = await promise.then(
    () => assert.fail(`resolved, expected ${code}`),
    (e) => e,
  );
  assert.ok(e instanceof StoatCryptoError, `not a StoatCryptoError: ${e}`);
  assert.ok(isStoatCryptoError(e));
  assert.equal(e.code, code, e.message);
  return e;
}

test("start loads the wasm lazily and reports the core version", async () => {
  const { crypto } = await start();
  assert.equal(crypto.info.coreVersion, pkg.version);
  assert.equal(crypto.info.payloadVersion, 1);
  assert.ok(crypto.info.attachmentChunkSize > 0);
});

test("machine lifecycle and the request pass", async () => {
  const { crypto } = await start();
  await rejects(crypto.identityKeys(), "NotOpen");
  await crypto.open(ulid("A"), dev("A1"), { kind: "memory" });
  // one machine per worker
  await rejects(crypto.open(ulid("A"), dev("A1"), { kind: "memory" }), "StoreLocked");

  const keys = await crypto.identityKeys();
  assert.match(keys.ed25519, /^[A-Za-z0-9+/]{43}$/);
  await crypto.setServerLimits({ maxToDeviceBatch: 1000, maxRequestBytes: 4194304 });
  await crypto.setTiming({ keyRequestDelayMs: 0, toDeviceRetryMs: 1000, toDeviceRetryAttempts: 3 });
  const reqs = await crypto.outgoingRequests();
  const upload = reqs.find((r) => r.kind === "KeysUpload");
  assert.ok(upload, JSON.stringify(reqs.map((r) => r.kind)));
  assert.equal(typeof upload.body, "string");
  // in flight: the same id again
  assert.ok((await crypto.outgoingRequests()).some((r) => r.id === upload.id));
  await crypto.markRequestFailed(upload.id, upload.kind, 503);
  const wake = await crypto.wakeupInMs();
  assert.ok(wake === null || typeof wake === "number");
  assert.deepEqual(await crypto.undeliveredDevices(), []);
  assert.deepEqual(await crypto.verifications(), []);
  assert.equal(await crypto.verification("nope"), null);
  const report = JSON.parse(await crypto.debugReport());
  assert.equal(typeof report, "object");

  await crypto.close();
  await rejects(crypto.identityKeys(), "NotOpen");
  // the worker is reusable after close
  await crypto.open(ulid("B"), dev("B1"), { kind: "memory" });
  assert.notEqual((await crypto.identityKeys()).ed25519, keys.ed25519);
});

test("errors keep the FFI codes and never quote the input", async () => {
  const { crypto } = await start();
  await rejects(crypto.open("not-a-ulid", dev("A1"), { kind: "memory" }), "InvalidId");
  await rejects(crypto.open(ulid("A"), dev("A1"), { kind: "sqlite" }), "InvalidInput");
  await rejects(crypto.open(ulid("A"), dev("A1"), { kind: "indexedDb", accountKey: "a/b", key: new Uint8Array(32) }), "InvalidInput");
  await crypto.open(ulid("A"), dev("A1"), { kind: "memory" });

  const secret = "hunter2-SECRET-91c";
  const errors = [
    await rejects(crypto.receiveToDevice(secret), "InvalidResponse"),
    await rejects(crypto.encrypt(ulid("C"), `{"v":1,"content":"${secret}"}`), "InvalidPayload"),
    await rejects(crypto.encrypt(ulid("C"), await crypto.textPayload(secret, "AAAAAAAAAAAAAAAAAAAAAA", 1)), "UnknownChannel"),
    await rejects(crypto.importRoomKeys(secret, secret), "InvalidKeyFile"),
    await rejects(crypto.exportRoomKeys(""), "PassphraseRequired"),
    await rejects(crypto.markRequestSent(secret, secret, secret), "InvalidInput"),
    // O-3: not even a cast gets Verified through
    await rejects(crypto.setDeviceTrust(ulid("B"), dev("B1"), "Verified"), "InvalidInput"),
    await rejects(crypto.requestVerification(ulid("B"), dev("B1")), "UnknownDevice"),
    await rejects(crypto.rotateBackup(), "NoRecovery"),
    await rejects(crypto.decrypt({ messageId: secret }), "InvalidInput"),
  ];
  for (const e of errors) {
    assert.equal(e.name, "StoatCryptoError");
    assert.ok(!e.message.includes(secret), e.message);
  }
  // a method the worker does not expose
  await rejects(crypto.rpc.call("call", ["free", []]), "InvalidInput");
  await rejects(crypto.rpc.call("__proto__", []), "InvalidInput");

  // a decryption failure is a value
  const envelope = JSON.stringify({ v: 2, algorithm: "x", session_id: "s", device_id: "d", ciphertext: "c" });
  const r = await crypto.decrypt({ messageId: ulid("M"), channelId: ulid("C"), author: ulid("B"), envelopeJson: envelope, replies: [], timestamp: 1 });
  assert.equal(r.type, "Failed");
  assert.equal(r.kind, "UpdateApp");
});

test("key export, import and recovery with secrets transferred, not shared", async () => {
  const { crypto } = await start();
  await crypto.open(ulid("A"), dev("A1"), { kind: "memory" });
  const passphrase = new TextEncoder().encode("pass phrase");
  const exported = await crypto.exportRoomKeys(passphrase);
  assert.equal(exported.sessions, 0);
  assert.match(exported.data, /BEGIN MEGOLM SESSION DATA/);
  // the caller's array is untouched (a copy went to the worker); zeroing it is the caller's job
  assert.equal(new TextDecoder().decode(passphrase), "pass phrase");
  await rejects(crypto.importRoomKeys(exported.data, "wrong"), "WrongPassphrase");
  const imported = await crypto.importRoomKeys(exported.data, passphrase);
  assert.deepEqual(imported, { total: 0, imported: 0, skipped: 0, roomKeys: [] });

  const setup = await crypto.createRecovery();
  assert.equal(typeof setup.recoveryKey, "string");
  assert.equal(setup.request.kind, "BackupVersionCreate");
  assert.equal(await crypto.recoveryKeyCheck(setup.recoveryKey), "Valid");
  assert.equal(await crypto.recoveryKeyCheck("correct horse"), "NotAKey");
  const status = await crypto.backupStatus();
  assert.equal(typeof status.keysTotal, "number");
});

test("attachments: blobs, streams and one-shot", async () => {
  const { crypto } = await start();
  const data = new Uint8Array(300_000).map((_, i) => i % 251);
  const enc = await crypto.encryptBlob(new Blob([data]));
  assert.equal(enc.size, data.length);
  assert.equal(enc.blob.size, data.length);
  const plain = await crypto.decryptBlob(enc.blob, enc.fileJson, "image/png");
  assert.equal(plain.type, "image/png");
  assert.deepEqual(new Uint8Array(await plain.arrayBuffer()), data);
  // a swapped blob is never decrypted
  const swapped = new Uint8Array(await enc.blob.arrayBuffer());
  swapped[0] ^= 1;
  await rejects(crypto.decryptBlob(new Blob([swapped]), enc.fileJson), "AttachmentHashMismatch");
  await rejects(crypto.decryptBlob(enc.blob, "{}"), "InvalidAttachment");

  // the same through handles, chunk by chunk
  const e = await crypto.attachmentEncryptor();
  const parts = [];
  for (let at = 0; at < data.length; at += 65536) parts.push(await e.update(data.subarray(at, at + 65536)));
  assert.equal(await e.size(), data.length);
  const fileJson = await e.finish();
  await rejects(e.update(new Uint8Array(1)), "AlreadyFinished");
  const v = await crypto.attachmentVerifier(fileJson);
  for (const p of parts) await v.update(p);
  const d = await v.finish();
  const out = [];
  for (const p of parts) out.push(await d.update(p));
  await d.free();
  assert.deepEqual(new Uint8Array(await new Blob(out).arrayBuffer()), data);
  // the caller's chunk was copied, not detached
  assert.equal(data.length, 300_000);

  const thumb = await crypto.encryptAttachment(new TextEncoder().encode("thumbnail"));
  assert.ok(thumb.ciphertext instanceof Uint8Array);
  assert.equal(new TextDecoder().decode(await crypto.decryptAttachment(thumb.ciphertext, thumb.fileJson)), "thumbnail");
  const payload = JSON.stringify({
    v: 1, client_nonce: "AAAAAAAAAAAAAAAAAAAAAA", ts: 1,
    attachments: [{ id: "F1", name: "a.png", content_type: "image/png", size: 9, metadata: { type: "Image", width: 1, height: 1 }, file: JSON.parse(thumb.fileJson) }],
  });
  assert.deepEqual(await crypto.payloadFileIds(payload), ["F1"]);
  assert.equal((await crypto.sasEmojiTable()).length, 64);
});

test("IndexedDB stores need the Web Lock; names per accountKey", async () => {
  assert.equal(storeName("k1"), "durio-e2ee-k1");
  assert.equal(lockName("k1"), "durio-e2ee:k1");
  assert.throws(() => storeName("@k"), StoatCryptoError);
  const { crypto } = await start();
  const key = new Uint8Array(32).fill(7);
  const open = crypto.open(ulid("A"), dev("A1"), { kind: "indexedDb", accountKey: "k1", key });
  if (!globalThis.navigator?.locks) {
    // Node 22: no Web Locks (and no IndexedDB) — the worker refuses rather than open unlocked
    await rejects(open, "Store");
  } else {
    await open.catch(() => {});
  }
  assert.equal(key[0], 7, "the caller's key is copied, the worker wipes its own");
});

test("a closed client fails every call", async () => {
  const { crypto, port } = await start();
  crypto.terminate();
  await rejects(crypto.identityKeys(), "WorkerClosed");
  port.close();
});
