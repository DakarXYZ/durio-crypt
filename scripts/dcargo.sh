#!/usr/bin/env bash
# Run cargo (or any command) inside the pinned rust image.
# Registry and target dir live in named docker volumes so rebuilds are incremental.
# Usage: scripts/dcargo.sh cargo test -p spike-msc
# /tools (volume durio-tools): cargo-ndk, cargo-deny, NDK r28c (/tools/android-ndk-r28c).
# DCARGO_DOCKER_ARGS: extra `docker run` arguments (e.g. `--network durio-test -e STOAT_API=...`).
set -euo pipefail
IMAGE="${DURIO_RUST_IMAGE:-rust:1.96.1-bookworm}"
ROOT="$(cd "$(dirname "$0")/.." && (pwd -W 2>/dev/null || pwd))"
# shellcheck disable=SC2086
MSYS_NO_PATHCONV=1 exec docker run --rm ${DOCKER_TTY:-} ${DCARGO_DOCKER_ARGS:-} \
  -v "${ROOT}:/work" \
  -v durio-cargo-registry:/usr/local/cargo/registry \
  -v durio-cargo-git:/usr/local/cargo/git \
  -v durio-target:/work/target \
  -v durio-rustup:/usr/local/rustup \
  -v durio-tools:/tools \
  -e CARGO_TERM_COLOR=never \
  -e CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" \
  -e ANDROID_NDK_HOME=/tools/android-ndk-r28c \
  -e PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/tools/bin \
  -w /work \
  "${IMAGE}" "$@"
