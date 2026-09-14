#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

TARGET="${1:?usage: fuzz.sh <fuzz_packet|fuzz_dns|fuzz_http|fuzz_pcap_header|fuzz_capture|fuzz_address> [seconds, 0 = replay seeds and regressions only]}"
SECONDS_TO_RUN="${2:-60}"
shift $(( $# > 1 ? 2 : 1 ))

BUILD="$PROJECT_ROOT/build-fuzz"
cmake -S "$PROJECT_ROOT" -B "$BUILD" -DCMAKE_CXX_COMPILER="${CXX:-clang++}" -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_FUZZERS=ON -DBUILD_TESTING=OFF > /dev/null
cmake --build "$BUILD" -j --target "$TARGET" fuzz_seeds

mkdir -p "$BUILD/corpus/$TARGET" "$BUILD/crashes"
rm -rf "$BUILD/seeds/$TARGET"
"$BUILD/fuzz/fuzz_seeds" unpack "$BUILD/seeds" --target "$TARGET" --seeds "$PROJECT_ROOT/fuzz/seeds.txt"
DICT=()
[ -f "$PROJECT_ROOT/fuzz/dicts/$TARGET.dict" ] && DICT=("-dict=$PROJECT_ROOT/fuzz/dicts/$TARGET.dict")

if [ "$SECONDS_TO_RUN" = "0" ]; then
    exec "$BUILD/fuzz/$TARGET" -runs=0 "$@" "$BUILD/seeds/$TARGET" "$PROJECT_ROOT/fuzz/regressions/$TARGET"
fi

"$BUILD/fuzz/$TARGET" "${DICT[@]}" \
    -max_total_time="$SECONDS_TO_RUN" -rss_limit_mb=2048 -timeout=10 -print_final_stats=1 \
    -artifact_prefix="$BUILD/crashes/" "$@" \
    "$BUILD/corpus/$TARGET" "$BUILD/seeds/$TARGET" "$PROJECT_ROOT/fuzz/regressions/$TARGET"
