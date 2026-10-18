#!/usr/bin/env bash
# CR-14: the npm package @durio/stoat-crypto (bindings/web) — wasm of the crypto
# core + the Web Worker RPC. No wasm-pack (C25): cargo → wasm-bindgen (CLI of the
# crate's exact version) → wasm-opt → tsc.
#
#   scripts/build-wasm.sh tools     # wasm32 target, wasm-bindgen(-test-runner) 0.2.129,
#                                   # binaryen 123, Node 22 into $WASM_TOOLS (pinned SHA-256)
#   scripts/build-wasm.sh build     # release wasm → bindings/web/dist (+ size gate), tsc,
#                                   # npm pack → bindings/web/build/*.tgz + .sha256
#   scripts/build-wasm.sh test      # wasm-bindgen-test in Node, then the JS tests of the
#                                   # package (worker RPC over MessageChannel, real wasm)
#   scripts/build-wasm.sh analyze   # twiggy top of a build with the name section kept
#   scripts/build-wasm.sh all       # tools build test
#
# Without cargo on PATH (Windows dev host) the script re-runs itself in the pinned rust
# image (scripts/dcargo.sh; tools in the durio-tools volume, 6 GB, -j 3).
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)

if ! command -v cargo >/dev/null 2>&1; then
    export DCARGO_DOCKER_ARGS="${DCARGO_DOCKER_ARGS:---memory 6g}"
    export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-3}"
    exec scripts/dcargo.sh env WASM_TOOLS=/tools scripts/build-wasm.sh "$@"
fi

WEB=$ROOT/bindings/web
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
TOOLS=${WASM_TOOLS:-$ROOT/target/wasm-tools}
export PATH=$TOOLS/bin:$TOOLS/node/bin:$PATH
TARGET=wasm32-unknown-unknown
PROFILE=release-wasm
WASM=target/$TARGET/$PROFILE/stoat_crypto_wasm.wasm

WASM_BINDGEN=0.2.129
WASM_BINDGEN_SHA=82d12bb940e2d4e72e0d5605387fc1b8ca179044e012b620f0ce4e7440e8320e
BINARYEN=version_123
BINARYEN_SHA=e959f2170af4c20c552e9de3a0253704d6a9d2766e8fdb88e4d6ac4bae9388fe
NODE=v22.12.0
NODE_SHA=22982235e1b71fa8850f82edd09cdae7e3f32df1764a9ec298c72d25ef2c164f
# features rustc 1.96 enables for wasm32-unknown-unknown (wasm-opt must accept them)
WASM_OPT_FEATURES=(--enable-bulk-memory --enable-nontrapping-float-to-int --enable-sign-ext
    --enable-mutable-globals --enable-reference-types --enable-multivalue)

fetch() { # url sha256 file
    curl -fsSL -o "$3" "$1"
    echo "$2  $3" | sha256sum -c --quiet -
}

tools() {
    rustup target add $TARGET >/dev/null
    mkdir -p "$TOOLS/bin"
    local tmp
    tmp=$(mktemp -d)
    if [ "$(wasm-bindgen --version 2>/dev/null)" != "wasm-bindgen $WASM_BINDGEN" ] ||
        ! command -v wasm-bindgen-test-runner >/dev/null; then
        local name=wasm-bindgen-$WASM_BINDGEN-x86_64-unknown-linux-musl
        fetch "https://github.com/wasm-bindgen/wasm-bindgen/releases/download/$WASM_BINDGEN/$name.tar.gz" \
            $WASM_BINDGEN_SHA "$tmp/wb.tgz"
        tar xzf "$tmp/wb.tgz" -C "$tmp"
        cp "$tmp/$name/wasm-bindgen" "$tmp/$name/wasm-bindgen-test-runner" "$TOOLS/bin/"
    fi
    if [ "$(wasm-opt --version 2>/dev/null)" != "wasm-opt version 123 ($BINARYEN)" ]; then
        fetch "https://github.com/WebAssembly/binaryen/releases/download/$BINARYEN/binaryen-$BINARYEN-x86_64-linux.tar.gz" \
            $BINARYEN_SHA "$tmp/binaryen.tgz"
        tar xzf "$tmp/binaryen.tgz" -C "$tmp"
        cp -r "$tmp/binaryen-$BINARYEN/bin/." "$TOOLS/bin/"
        cp -r "$tmp/binaryen-$BINARYEN/lib" "$TOOLS/" 2>/dev/null || true
    fi
    if [ "$(node --version 2>/dev/null)" != "$NODE" ]; then
        fetch "https://nodejs.org/dist/$NODE/node-$NODE-linux-x64.tar.xz" $NODE_SHA "$tmp/node.txz"
        rm -rf "$TOOLS/node" && mkdir -p "$TOOLS/node"
        tar xJf "$tmp/node.txz" -C "$TOOLS/node" --strip-components=1
    fi
    rm -rf "$tmp"
    wasm-bindgen --version && wasm-opt --version && echo "node $(node --version)"
}

build() {
    cargo build --locked --target $TARGET --profile $PROFILE -p stoat-crypto-wasm
    # the generated glue goes into src/wasm (gitignored) so tsc sees its types, then dist/wasm
    rm -rf "$WEB/src/wasm" "$WEB/dist"
    wasm-bindgen --target web --out-dir "$WEB/src/wasm" --out-name stoat_crypto_wasm "$WASM"
    local bg=$WEB/src/wasm/stoat_crypto_wasm_bg.wasm
    wasm-opt -Oz --strip-debug "${WASM_OPT_FEATURES[@]}" -o "$bg.opt" "$bg"
    mv "$bg.opt" "$bg"
    scripts/check-wasm-size.sh "$bg"

    cd "$WEB"
    npm ci --no-audit --no-fund
    npx tsc -p tsconfig.json
    mkdir -p dist/wasm
    cp src/wasm/stoat_crypto_wasm.js src/wasm/stoat_crypto_wasm.d.ts src/wasm/stoat_crypto_wasm_bg.wasm dist/wasm/
    [ -d src/wasm/snippets ] && cp -r src/wasm/snippets dist/wasm/
    (cd dist/wasm && sha256sum stoat_crypto_wasm_bg.wasm >stoat_crypto_wasm_bg.wasm.sha256)
    test "$(node -p 'require("./package.json").version')" = "$VERSION" ||
        { echo "bindings/web/package.json version != $VERSION" >&2; exit 1; }
    mkdir -p build
    npm pack --silent --pack-destination build >/dev/null
    local tgz=durio-stoat-crypto-$VERSION.tgz
    (cd build && sha256sum "$tgz" >"$tgz.sha256" && cat "$tgz.sha256")
}

test_wasm() {
    # wasm-bindgen-test in Node (headless Chrome is not in the image; the JS tests below
    # cover the worker path). Debug build: the tests run PBKDF2 with sha2 at opt-level 3.
    CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner \
        WASM_BINDGEN_TEST_TIMEOUT=${WASM_BINDGEN_TEST_TIMEOUT:-300} \
        cargo test --locked --target $TARGET -p stoat-crypto-wasm
    [ -f "$WEB/dist/index.js" ] || { echo "run 'build' first for the JS tests" >&2; exit 1; }
    cd "$WEB" && node --test test/*.test.mjs
}

analyze() {
    command -v twiggy >/dev/null || cargo install --locked --root "$TOOLS" twiggy --version 0.7.0
    # keep the name section (the release profile strips it); same code otherwise
    CARGO_PROFILE_RELEASE_WASM_STRIP=none CARGO_TARGET_DIR=target/wasm-names \
        cargo build --locked --target $TARGET --profile $PROFILE -p stoat-crypto-wasm
    local out=target/wasm-names/bindgen
    wasm-bindgen --target web --keep-debug --out-dir $out target/wasm-names/$TARGET/$PROFILE/stoat_crypto_wasm.wasm
    wasm-opt -Oz --debuginfo "${WASM_OPT_FEATURES[@]}" -o $out/opt.wasm $out/stoat_crypto_wasm_bg.wasm
    twiggy top -n 30 $out/opt.wasm
    twiggy garbage $out/opt.wasm | head -5 || true
}

case ${1:-} in
tools) tools ;;
build) build ;;
test) test_wasm ;;
analyze) analyze ;;
all) tools && build && test_wasm ;;
*) sed -n '2,17p' "$0"; exit 2 ;;
esac
