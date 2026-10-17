#!/usr/bin/env bash
# Runs inside rust:1.96.1-bookworm (see scripts/dcargo.sh-like invocation in docs/spike-report.md).
# Tools are cached in /tools (named volume).
set -euo pipefail
export PATH=/tools/bin:$PATH
rustup target add wasm32-unknown-unknown >/dev/null
if ! command -v wasm-bindgen >/dev/null; then
  mkdir -p /tools/bin
  curl -sL https://github.com/wasm-bindgen/wasm-bindgen/releases/download/0.2.129/wasm-bindgen-0.2.129-x86_64-unknown-linux-musl.tar.gz | tar xz -C /tmp
  cp /tmp/wasm-bindgen-0.2.129-x86_64-unknown-linux-musl/wasm-bindgen /tools/bin/
fi
if ! command -v wasm-opt >/dev/null; then
  V=version_123
  curl -sL "https://github.com/WebAssembly/binaryen/releases/download/$V/binaryen-$V-x86_64-linux.tar.gz" | tar xz -C /tmp
  cp -r /tmp/binaryen-$V/bin/* /tools/bin/ && cp -r /tmp/binaryen-$V/lib /tools/ 2>/dev/null || true
fi
apt-get -qq update >/dev/null && apt-get -qq install -y brotli >/dev/null || true
export RUSTFLAGS='--cfg getrandom_backend="wasm_js"'
OUT=/work/target-size/wasm
mkdir -p $OUT
for FEAT in wasm "wasm,indexeddb"; do
  NAME=${FEAT//,/-}
  cargo build -q --profile release-wasm --target wasm32-unknown-unknown --no-default-features --features "$FEAT"
  wasm-bindgen --target web --out-dir $OUT/$NAME target/wasm32-unknown-unknown/release-wasm/size_probe.wasm
  RAW=$OUT/$NAME/size_probe_bg.wasm
  wasm-opt -Oz --strip-debug --enable-bulk-memory --enable-nontrapping-float-to-int --enable-sign-ext --enable-mutable-globals --enable-reference-types -o $OUT/$NAME/opt.wasm $RAW
  echo "$NAME raw=$(stat -c%s $RAW) opt=$(stat -c%s $OUT/$NAME/opt.wasm) gzip9=$(gzip -9c $OUT/$NAME/opt.wasm | wc -c) brotli=$(brotli -c -q 11 $OUT/$NAME/opt.wasm 2>/dev/null | wc -c)"
done
