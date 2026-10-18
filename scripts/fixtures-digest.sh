#!/usr/bin/env bash
# Digest of the contract v1 vectors shared with the backend (CR-03): fixtures/api
# and fixtures/envelope are copied byte for byte to
# stoatchat/crates/core/models/tests/fixtures/e2ee/.
#
# The other vectors (backup/, sas/, payload/, ws/) are shared with the Kotlin
# and JS tests and are listed in SHA256SUMS too.
#
#   scripts/fixtures-digest.sh             print the digest list
#   scripts/fixtures-digest.sh --write     update fixtures/SHA256SUMS
#   scripts/fixtures-digest.sh --check     fail if fixtures differ from SHA256SUMS
#   scripts/fixtures-digest.sh --backend <stoatchat>   fail if the backend copy
#                                          of api/ and envelope/ differs
set -euo pipefail

if [ "${1:-}" = "--backend" ]; then
  copy="$(cd "${2:?path to stoatchat}" && pwd)/crates/core/models/tests/fixtures/e2ee"
fi
cd "$(dirname "$0")/../fixtures"

digest() {
  # sha256sum on Windows marks binary mode with `*`; normalise to the Linux form
  local dirs=("$@")
  [ $# -gt 0 ] || dirs=(api envelope)
  find "${dirs[@]}" -type f -name '*.json' | LC_ALL=C sort | xargs sha256sum | sed 's/ [ *]/  /'
}

# every JSON vector (the store snapshots are binary and checked by their test)
all() {
  digest api backup envelope payload sas ws
}

case "${1:-}" in
  --write) all > SHA256SUMS ;;
  --check) diff -u SHA256SUMS <(all) ;;
  --backend) diff -u <(digest) <(cd "$copy" && digest) ;;
  "") all ;;
  *) echo "unknown option: $1" >&2; exit 2 ;;
esac
