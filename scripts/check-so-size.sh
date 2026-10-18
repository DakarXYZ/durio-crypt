#!/usr/bin/env bash
# CR-13 / ADR 0001: size gate of the Android libraries. Limits = stripped size
# measured when the threshold was last set + 5 %; raise them in a reviewed
# commit (with the new measurement in bindings/android/README.md), never to
# make CI green silently. Budget (C23): arm64 ≤ 12 MB stripped.
# Also checks the 16 KB page alignment of every LOAD segment of the 64-bit ABIs
# (Android 15+ devices with 16 KB pages are 64-bit only).
#   scripts/check-so-size.sh <jniLibs dir>
set -euo pipefail
DIR=${1:?jniLibs dir}
NDK=${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}
BIN=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin
LIB=libstoat_crypto_ffi.so

limit() {
    case $1 in
    arm64-v8a) echo 10590000 ;;   # 10 086 040 (2026-10-18) + 5 %
    armeabi-v7a) echo 6821000 ;;  # 6 495 560 + 5 %
    x86_64) echo 11626000 ;;     # 11 072 176 + 5 %
    *) echo "unknown ABI $1" >&2; exit 1 ;;
    esac
}

fail=0
for abi in arm64-v8a armeabi-v7a x86_64; do
    so=$DIR/$abi/$LIB
    [ -f "$so" ] || { echo "missing $so" >&2; exit 1; }
    tmp=$(mktemp)
    "$BIN/llvm-strip" --strip-all -o "$tmp" "$so"
    size=$(stat -c%s "$tmp")
    gz=$(gzip -9c "$tmp" | wc -c)
    rm -f "$tmp"
    max=$(limit "$abi")
    align=$("$BIN/llvm-readelf" -lW "$so" | awk '/LOAD/ {print $NF}' | sort -u | tr '\n' ' ')
    printf '%-12s stripped=%9d gzip=%9d limit=%9d align=%s\n' "$abi" "$size" "$gz" "$max" "$align"
    if [ "$size" -gt "$max" ]; then
        echo "  over the limit by $((size - max)) bytes" >&2
        fail=1
    fi
    [ "$abi" = armeabi-v7a ] && continue
    for a in $align; do
        if [ $((a)) -lt 16384 ]; then
            echo "  LOAD segment aligned to $a, need 0x4000 (16 KB pages)" >&2
            fail=1
        fi
    done
done
exit $fail
