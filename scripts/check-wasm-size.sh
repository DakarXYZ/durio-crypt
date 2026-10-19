#!/usr/bin/env bash
# CR-14 / C23: size gate of the web wasm (after wasm-opt -Oz --strip-debug). Limits =
# size measured when the threshold was last set + 5 %; raise them in a reviewed commit
# (with the new measurement in bindings/web/README.md), never to make CI green silently.
# Budget (C23): ≤ 3 MB gzip.
#   scripts/check-wasm-size.sh <stoat_crypto_wasm_bg.wasm>
set -euo pipefail
WASM=${1:?wasm file}
BUDGET_GZIP=3145728        # C23: 3 MiB gzip
LIMIT_RAW=3968000          # 3 779 022 (2026-10-18, 0.2.0) + 5 %
LIMIT_GZIP=1494000         # 1 422 205 + 5 %

raw=$(stat -c%s "$WASM")
gz=$(gzip -9c "$WASM" | wc -c)
printf 'wasm raw=%d gzip9=%d limit_raw=%d limit_gzip=%d budget_gzip=%d\n' \
    "$raw" "$gz" "$LIMIT_RAW" "$LIMIT_GZIP" "$BUDGET_GZIP"
fail=0
if [ "$gz" -gt "$BUDGET_GZIP" ]; then
    echo "  over the C23 budget by $((gz - BUDGET_GZIP)) bytes gzip" >&2
    fail=1
fi
if [ "$LIMIT_RAW" -gt 0 ] && [ "$raw" -gt "$LIMIT_RAW" ]; then
    echo "  over the raw limit by $((raw - LIMIT_RAW)) bytes" >&2
    fail=1
fi
if [ "$LIMIT_GZIP" -gt 0 ] && [ "$gz" -gt "$LIMIT_GZIP" ]; then
    echo "  over the gzip limit by $((gz - LIMIT_GZIP)) bytes" >&2
    fail=1
fi
exit $fail
