#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

ITERATIONS="${1:-100}"

cmake -S "$PROJECT_ROOT" -B "$PROJECT_ROOT/build" -DBUILD_TESTING=ON -DRANDOMIZED_ITERATIONS="$ITERATIONS"
cmake --build "$PROJECT_ROOT/build" -j2

ctest --test-dir "$PROJECT_ROOT/build" --progress