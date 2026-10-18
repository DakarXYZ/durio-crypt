#!/usr/bin/env bash
# scripts/build-aar.sh on a Windows dev host (Git Bash): the Rust step in the
# pinned rust image (scripts/dcargo.sh), the Gradle step in durio-android-build
# (tools/android-build in the workspace) with the shared Gradle and SDK volumes.
#   scripts/daar.sh [native|gradle|all]
set -euo pipefail
cd "$(dirname "$0")/.."
STEP=${1:-all}
if [ "$STEP" = native ] || [ "$STEP" = all ]; then
    scripts/dcargo.sh scripts/build-aar.sh native
fi
if [ "$STEP" = gradle ] || [ "$STEP" = all ]; then
    MSYS_NO_PATHCONV=1 docker run --rm \
        -v "$(pwd -W 2>/dev/null || pwd):/work" \
        -v durio-gradle-cache:/root/.gradle \
        -v durio-android-sdk:/opt/android-sdk \
        -w /work durio-android-build:latest scripts/build-aar.sh gradle
fi
