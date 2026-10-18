#!/usr/bin/env bash
# Digest of the contract v1 vectors shared with the backend (CR-03): fixtures/api
# and fixtures/envelope are copied byte for byte to
# stoatchat/crates/core/models/tests/fixtures/e2ee/.
#
#   scripts/fixtures-digest.sh             print the digest list
#   scripts/fixtures-digest.sh --write     update fixtures/SHA256SUMS
#   scripts/fixtures-digest.sh --check     fail if fixtures differ from SHA256SUMS
#   scripts/fixtures-digest.sh --backend <stoatchat>   fail if the backend copy differs
set -euo pipefail

if [ "${1:-}" = "--backend" ]; then
  copy="$(cd "${2:?path to stoatchat}" && pwd)/crates/core/models/tests/fixtures/e2ee"
fi
cd "$(dirname "$0")/../fixtures"

digest() {
  # sha256sum on Windows marks binary mode with `*`; normalise to the Linux form
  find api envelope -type f -name '*.json' | LC_ALL=C sort | xargs sha256sum | sed 's/ [ *]/  /'
}

case "${1:-}" in
  --write) digest > SHA256SUMS ;;
  --check) diff -u SHA256SUMS <(digest) ;;
  --backend) diff -u <(digest) <(cd "$copy" && digest) ;;
  "") digest ;;
  *) echo "unknown option: $1" >&2; exit 2 ;;
esac
