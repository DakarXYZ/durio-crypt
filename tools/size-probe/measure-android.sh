#!/usr/bin/env bash
# Android arm64 .so size (opt-level=z, fat LTO, codegen-units=1, strip). NDK r28c cached in /tools.
set -euo pipefail
export PATH=/tools/bin:$PATH
NDK=/tools/android-ndk-r28c
if [ ! -d $NDK ]; then
  apt-get -qq update >/dev/null && apt-get -qq install -y unzip >/dev/null
  curl -sL -o /tmp/ndk.zip https://dl.google.com/android/repository/android-ndk-r28c-linux.zip
  unzip -q /tmp/ndk.zip -d /tools && rm /tmp/ndk.zip
fi
command -v cargo-ndk >/dev/null || cargo install --locked --root /tools cargo-ndk --version 4.1.2
rustup target add aarch64-linux-android >/dev/null
export ANDROID_NDK_HOME=$NDK
OUT=/work/target-size/android
mkdir -p $OUT
STRIP=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip
for FEAT in native "native,sqlite"; do
  NAME=${FEAT//,/-}
  cargo ndk -t arm64-v8a --platform 26 build -q --release --no-default-features --features "$FEAT"
  SO=target/aarch64-linux-android/release/libsize_probe.so
  cp $SO $OUT/$NAME.so && $STRIP --strip-all $OUT/$NAME.so
  echo "$NAME stripped=$(stat -c%s $OUT/$NAME.so) gzip9=$(gzip -9c $OUT/$NAME.so | wc -c)"
  $NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-readelf -lW $OUT/$NAME.so | awk '/LOAD/{print "  LOAD align", $NF; exit}'
done
