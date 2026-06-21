#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cmake -S "$PROJECT_ROOT" -B "$PROJECT_ROOT/build" -DBUILD_TESTING=ON >/dev/null
cmake --build "$PROJECT_ROOT/build" >/dev/null

ctest --test-dir "$PROJECT_ROOT/build" --progress