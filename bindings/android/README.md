# stoat-crypto — Android AAR (CR-13)

`io.github.dakarxyz.durio:stoat-crypto:<version>` — the dur.io crypto core (`crates/stoat-crypto`, matrix-sdk-crypto
0.19.1 behind our adapter) as an Android library: `libstoat_crypto_ffi.so` for `arm64-v8a`, `armeabi-v7a`, `x86_64`
plus the UniFFI Kotlin bindings (package `uniffi.stoat_crypto`). Version = version of the Rust crates.

## Build

```bash
scripts/build-aar.sh all      # CI / Linux with Rust + cargo-ndk + NDK r28c + JDK 21 + Android SDK 37
scripts/daar.sh               # Windows dev host: the same in Docker (rust image + durio-android-build)
```

Steps (`scripts/build-aar.sh`):

1. `native` — `cargo ndk --platform 26 build --profile release-android -p stoat-crypto-ffi` for the three ABIs →
   `src/main/jniLibs/<abi>/`; `scripts/check-so-size.sh` (size limits, 16 KB `LOAD` alignment); host build of the
   library → `build/host/` and `uniffi-bindgen` (binary of `crates/stoat-crypto-ffi`, same uniffi 0.32.2) →
   `src/main/kotlin/` (generated, not committed).
2. `gradle` — JVM unit tests (`src/test` + `src/sharedTest`) against the host library through
   `jna.library.path`; `assembleRelease`; the instrumented test APK (`src/androidTest`, compiled only — needs an
   emulator to run: `./gradlew connectedAndroidTest`); maven layout in `build/maven/`; the AAR and its SHA-256 in
   `build/dist/`.

Release: tag `vX.Y.Z` in `durio-crypt` → `.github/workflows/aar-release.yml` builds the same and attaches
`stoat-crypto-X.Y.Z.aar`, `.aar.sha256` and `.pom` to the GitHub Release (60-deploy §2.1).

## Contents and size

AAR 0.2.0 (2026-10-18, + key export/import, `debug_report`, own-request backoff): 11.8 MB (11 826 861 bytes; 0.1.0: 11.6 MB) — `jni/{arm64-v8a,armeabi-v7a,x86_64}/libstoat_crypto_ffi.so`, `classes.jar`
(bindings, 0.4 MB), `proguard.txt` (= `consumer-rules.pro`), `AndroidManifest.xml`.

| ABI | stripped | gzip -9 | limit (`check-so-size.sh`) | `LOAD` alignment |
| --- | --- | --- | --- | --- |
| arm64-v8a | 10 243 720 | 3 831 304 | 10 590 000 | 0x4000 |
| armeabi-v7a | 6 599 512 | 3 374 920 | 6 821 000 | 0x1000 (32-bit: no 16 KB devices) |
| x86_64 | 11 253 120 | 4 197 273 | 11 626 000 | 0x4000 |

Limits unchanged since 0.1.0 (measured then: arm64 10 086 040, armeabi-v7a 6 495 560, x86_64 11 072 176 stripped);
0.2.0 is +1.6 % on each ABI.

Profile `release-android` = release (fat LTO, one codegen unit, `strip`, `panic = "unwind"`) with `opt-level =
"s"`. arm64 measured: `opt-level = 3` → 11.72 MB stripped / 5.25 MB gzip; `"s"` → 10.09 / 3.77; `"z"` → 9.33 /
4.07. `"s"` is chosen (plan: not `z`; smallest download, `z` saves 0.75 MB on disk only). Within the C23 budget
(≤ 12 MB stripped), but twice the CR-01 probe (5.26 MB): the probe reached only part of the library, the real
surface pulls SAS, backup, secret storage and our adapter in, and `panic = "unwind"` keeps unwind tables
(`.eh_frame` ≈ 1.6 MB) for the panic fence. The APK ships one ABI per split (AN-41), so the download cost
is the gzip column of one ABI.

## Using it from for-android (stage 4, AN-20)

Module `:core:crypto` (Android library) depends on the AAR; the app never sees UniFFI types outside it.

**Dependencies.** The AAR comes without transitive metadata from GitHub Releases, so the module declares what the
bindings need itself:

```kotlin
dependencies {
    implementation("io.github.dakarxyz.durio:stoat-crypto:0.2.0@aar")
    implementation("net.java.dev.jna:jna:5.17.0@aar")          // libjnidispatch.so for every ABI; no JNA JAR
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
}
```

**Release: GitHub Release + SHA-256 pin (Q36).** `settings.gradle.kts` (repositories only in settings,
`FAIL_ON_PROJECT_REPOS`):

```kotlin
dependencyResolutionManagement {
    repositories {
        // …
        ivy {
            name = "durio-crypt"
            url = uri("https://github.com/DakarXYZ/durio-crypt/releases/download")
            patternLayout { artifact("v[revision]/[module]-[revision].[ext]") }
            metadataSources { artifact() }
            content { includeModule("io.github.dakarxyz.durio", "stoat-crypto") }
        }
    }
}
```

and the checksum from `stoat-crypto-<v>.aar.sha256` in `gradle/verification-metadata.xml`:

```xml
<component group="io.github.dakarxyz.durio" name="stoat-crypto" version="0.2.0">
   <artifact name="stoat-crypto-0.2.0.aar">
      <sha256 value="<sha256 from the release>" origin="durio-crypt release v0.2.0"/>
   </artifact>
</component>
```

(`./gradlew --write-verification-metadata sha256 help` writes the entry; compare it with the `.sha256` file of
the release before committing.)

**Development against a local build.** `scripts/daar.sh` (or `build-aar.sh all`) publishes to
`stoat-crypto/bindings/android/build/maven`; point for-android at it for the session:

```kotlin
// settings.gradle.kts, only while developing the core
maven {
    name = "stoat-crypto-local"
    url = uri("../stoat-crypto/bindings/android/build/maven")
    content { includeModule("io.github.dakarxyz.durio", "stoat-crypto") }
}
```

with version `<version>` of `Cargo.toml` (a `-dev` suffix is not added: bump the crate version for every AAR
that leaves the machine). `includeBuild` is not used: the module needs the Rust step first, Gradle alone cannot
build it.

**R8.** `consumer-rules.pro` ships in the AAR (JNA reflection, `uniffi.stoat_crypto.**`); the app adds nothing.
Test the minified build (AN-20).

**ABIs** come from the app's ABI splits (AN-41); `jniLibs.useLegacyPackaging = false` keeps the `.so`
uncompressed and 16 KB aligned (`zipalign -c -P 16 -v 4 app.apk`).

**JVM unit tests in for-android** cannot load the Android `.so`: fake the `E2ee` facade (main path), or use
the host library from `scripts/build-aar.sh native` (`build/host/libstoat_crypto_ffi.so`, linux-x86-64) with
`systemProperty("jna.library.path", …)` and the JNA JAR as `testImplementation`, as this module's own tests do.

## Kotlin API (summary)

Host contract — order of calls, request passes, ids in flight, mailbox, ack, send loop, SAS, backup,
attachments — is documented in `crates/stoat-crypto/src/lib.rs`; the bindings only change shapes.

| Kotlin | Notes |
| --- | --- |
| `CryptoMachine.open(userId, deviceId, StoreConfig)` (suspend) | `StoreConfig.Sqlite(path, key: ByteArray(32))` — key from the Keystore-wrapped master key; zero the array after the call. One per account+server per process (`CryptoException.StoreLocked`). `close()` on logout/switch |
| `outgoingRequests()`, `markRequestSent(id, kind, body)`, `markRequestFailed(id, kind, status)` | `OutgoingRequest(id, kind, method, path, body)`; bodies are JSON strings; `wakeupInMs()` → schedule the next pass (the core has no timers) |
| `receiveToDevice(body)` → `ToDeviceResult(fetched, ackIds, roomKeys, …, verifications)` | `body` = `GET /e2ee/to_device` response; then `POST …/ack` and `markAckSent(ids)`; fetch again while `fetched == limit` |
| `receiveDeviceListUpdate(users)`, `receiveReconnect()`, `receiveOtkCounts(body)`, `setServerLimits(…)` | socket events, `GET /e2ee/keys/count`, `GET /` limits |
| `setChannelMembers(channel, members, settings)`, `prepareSend(channel)`, `encrypt(channel, payloadJson)` → envelope JSON | payload v1 JSON (`textPayload(…)` helper, `payloadFileIds(…)` for the open `attachments`) |
| `decrypt(msg)` / `decryptBatch(msgs)` → `DecryptResult.Decrypted(message)` / `.Failed(error, kind, code)` | a failure is a value; `message.payloadJson` is plaintext — never log a `DecryptedMessage` (data-class `toString()` prints it) |
| `devices(user)`, `setDeviceTrust(…)`, `requestVerification(…)` / `verification(flowId)` → `SasHandle` | `SasHandle.state()`: `Requested`, `Incoming`, `Ready`, `Started`, `ShowCodes(emoji, decimals)`, `Confirmed`, `Done`, `Cancelled(reason, code, byUs)`; `sasEmojiTable()` |
| `createRecovery(passphrase: ByteArray?)` → `RecoverySetup(recoveryKey, request)`, `rotateBackup()`, `unlockBackup(input: ByteArray, RecoverySecrets)`, `restoreBackup(body)` → `BackupRestore.next(max)`, `backupStatus()`, `disableBackup()` | `recoveryKey` is shown once; `CryptoException.MfaRequired` → same request with `x-mfa-ticket`; `BackupVersionChanged`; `recoveryKeyCheck(bytes)` for the input field |
| `AttachmentEncryptor().update(chunk)…finish()` → `EncryptedFile` JSON; `AttachmentVerifier(fileJson).update(chunk)…finish()` → `AttachmentDecryptor.update(chunk)`; `encryptAttachment` / `decryptAttachment` for small blobs | never decode plaintext before `AttachmentVerifier.finish()` succeeded |
| `destroyStore(StoreConfig)` | after `close()` of every object of that machine |

Errors: `CryptoException.<Code>` (one subclass per core code: `StoreLocked`, `MfaRequired`, `BackupVersionChanged`,
`RoomKeyNotShared`, …, `Panic`), messages fixed and free of keys or text. Every export runs behind a panic fence;
a Rust panic is `CryptoException.Panic`, not a crash. Coroutine cancellation does not stop the Rust side: the
operation finishes and stores its result.

Objects are `AutoCloseable` (`use { }`): `CryptoMachine`, `SasHandle`, `BackupRestore` and the attachment streams.
A `SasHandle` or `BackupRestore` keeps its machine (and the store lock) alive until closed. No cleaner on API < 33
(`android_cleaner = false`, minSdk 26): close explicitly.

Secrets: store key, recovery key input and passphrase are `ByteArray`; the core wipes its copies, the caller does
`fill(0)` — best effort, the JVM may have copied them. Threads: one tokio runtime (2 workers + SQLite blocking
pool) inside the library; suspend calls do not block the calling thread.
