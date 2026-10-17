#!/usr/bin/env bash
# Run cargo (or any command) inside the pinned rust image.
# Registry and target dir live in named docker volumes so rebuilds are incremental.
# Usage: scripts/dcargo.sh cargo test -p spike-msc
set -euo pipefail
IMAGE="${DURIO_RUST_IMAGE:-rust:1.96.1-bookworm}"
ROOT="$(cd "$(dirname "$0")/.." && (pwd -W 2>/dev/null || pwd))"
MSYS_NO_PATHCONV=1 exec docker run --rm ${DOCKER_TTY:-} \
  -v "${ROOT}:/work" \
  -v durio-cargo-registry:/usr/local/cargo/registry \
  -v durio-cargo-git:/usr/local/cargo/git \
  -v durio-target:/work/target \
  -v durio-rustup:/usr/local/rustup \
  -e CARGO_TERM_COLOR=never \
  -e CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" \
  -w /work \
  "${IMAGE}" "$@"
