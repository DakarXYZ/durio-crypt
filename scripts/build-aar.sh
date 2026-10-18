#!/usr/bin/env bash
# CR-13: the Android AAR of the crypto core. Each step runs where its tools are
# (CI: one runner with both; Windows dev host: scripts/daar.sh runs them in Docker).
#
#   scripts/build-aar.sh native   # Rust: cargo ndk (3 ABIs) → src/main/jniLibs, size check,
#                                 # host library + uniffi-bindgen → src/main/kotlin, build/host
#   scripts/build-aar.sh gradle   # JDK + Android SDK: JVM tests against the host library,
#                                 # AAR, instrumented test APK, local maven repo, SHA-256
#   scripts/build-aar.sh all
#
# Output: bindings/android/build/dist/stoat-crypto-<version>.aar (+ .sha256),
#         bindings/android/build/maven (maven layout for for-android).
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)
A=$ROOT/bindings/android
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
PROFILE=${STOAT_AAR_PROFILE:-release-android}

native() {
    rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android >/dev/null
    rm -rf "$A/src/main/jniLibs" "$A/src/main/kotlin"
    # minSdk 26 as the app; NDK r28+ links with 16 KB pages by default
    cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 --platform 26 -o "$A/src/main/jniLibs" \
        build --locked --profile "$PROFILE" -p stoat-crypto-ffi
    scripts/check-so-size.sh "$A/src/main/jniLibs"

    # bindings come from the host build (same metadata as the Android ones);
    # the host library also runs the JVM unit tests of the module
    cargo build --locked -p stoat-crypto-ffi --lib
    mkdir -p "$A/build/host"
    cp target/debug/libstoat_crypto_ffi.so "$A/build/host/"
    cargo run --locked -q -p stoat-crypto-ffi --features bindgen --bin uniffi-bindgen -- \
        generate --library "$A/build/host/libstoat_crypto_ffi.so" --language kotlin \
        --out-dir "$A/src/main/kotlin" --no-format
}

gradle() {
    cd "$A"
    ./gradlew --no-daemon --stacktrace \
        -PstoatCrypto.version="$VERSION" -PstoatCrypto.hostLibDir="$A/build/host" \
        testDebugUnitTest assembleRelease assembleDebugAndroidTest publishReleasePublicationToLocalRepository
    mkdir -p build/dist
    AAR=build/dist/stoat-crypto-$VERSION.aar
    cp build/outputs/aar/stoat-crypto-release.aar "$AAR"
    (cd build/dist && sha256sum "stoat-crypto-$VERSION.aar" > "stoat-crypto-$VERSION.aar.sha256")
    unzip -l "$AAR" | grep -E '\.so$|classes\.jar|proguard\.txt|AndroidManifest'
    cat "build/dist/stoat-crypto-$VERSION.aar.sha256"
}

case ${1:-} in
native) native ;;
gradle) gradle ;;
all) native && gradle ;;
*) sed -n '2,13p' "$0"; exit 2 ;;
esac
