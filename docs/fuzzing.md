## Running locally

libFuzzer needs Clang and its runtime:

```bash
sudo apt install clang llvm libclang-rt-21-dev
```

```bash
./scripts/fuzz.sh fuzz_capture 300          # target, seconds, then any extra libFuzzer flags
```

The script configures `build-fuzz/` with `-DBUILD_FUZZERS=ON`, builds the target and the `fuzz_seeds` tool, and unpacks the target's seeds from `fuzz/seeds.txt` into `build-fuzz/seeds/<target>`. It then fuzzes against those seeds and `fuzz/regressions/<target>`, using `fuzz/dicts/<target>.dict` as the dictionary when one exists. New coverage-increasing inputs are saved to `build-fuzz/corpus/<target>` and crashes to `build-fuzz/crashes/`.

Passing `0` seconds only replays the seeds and regressions once (libFuzzer's `-runs=0`) and exits non-zero if any of them crashes:

```bash
./scripts/fuzz.sh fuzz_capture 0
```

To run the unit tests under sanitizers (GCC or Clang):

```bash
cmake -S . -B build-asan -DBUILD_TESTING=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo -DPCAP_SANITIZE=address,undefined
cmake --build build-asan -j
ctest --test-dir build-asan --output-on-failure
```

## Seeds and regressions

- `fuzz/seeds.txt` holds the seeds for every target in one text file, one per line: `<target> <name> <base64 bytes>`. `fuzz_seeds generate` (built from `fuzz/fuzz_seeds.cpp` by test and fuzz builds) rebuilds it from `samples/smallFlows.pcap` plus hand-built VLAN and IPv6 frames that the sample capture doesn't contain; `fuzz_seeds unpack DIR [--target T]` writes them out as the one-file-per-input folders libFuzzer needs.
- `fuzz/regressions/<target>/` holds every input that ever crashed a target (or triggered a resource bug), minimized.
- The harnesses only build with `BUILD_FUZZERS` (Clang). Regression inputs are replayed under ASan and UBSan by the CI fuzz jobs. GCC, MSVC and AppleClang builds are protected only by unit tests, which most fixes have.
- Sanitizer and fuzzer build trees keep their `analyzer` in `<build>/src/`. Only a normal build writes the project-root `analyzer`, so an instrumented binary can't silently replace it.

### When a fuzzer finds a crash

1. Reproduce it with `./build-fuzz/fuzz/<target> path/to/crash-<hash>`. In CI, download the `crashes-<target>` artifact from the failed run.
2. Minimize it with `./build-fuzz/fuzz/<target> -minimize_crash=1 -runs=100000 crash-<hash>`.
3. Fix the parser. Follow the parser convention: check lengths before `memcpy`, return a `ParseError`, never throw.
4. Copy the minimized input to `fuzz/regressions/<target>/<short-bug-name>`, add a unit test where practical, and add a row to the table below.

## CI

`.github/workflows/ci.yml` has three jobs:

- **build-and-test** (Linux GCC/Clang, Windows MSVC, macOS): unit tests.
- **sanitizers**: Clang, `-DPCAP_SANITIZE=address,undefined`, 200 randomized iterations per test.
- **fuzz**: one matrix entry per target. First replays the seeds and regressions once under ASan/UBSan, then fuzzes for 60 s on push/PR and 15 min on the nightly schedule. The corpus each run discovers is kept with `actions/cache`, so coverage builds up across runs without committing hundreds of files. Crashing inputs are uploaded as artifacts.

## Findings

Bugs fixed after fuzzing, oldest first. Impact was measured on Release builds before and after each fix.

| # | Area | Found by | Bug | Impact | Regression |
|---|---|---|---|---|---|
| 1 | `ip::v4::parse` | `fuzz_packet`, `fuzz_capture` | `total_length` below the header length underflowed the payload length. | Out-of-bounds reads; a 153-byte crafted `.pcap` aborts the whole run. | `ipv4-total-length-below-ihl`, `reassembler-ipv4-total-length-below-ihl`, `IPV4.RejectsTotalLengthBelowHeaderLength` |
| 2 | ARP printers | `fuzz_packet` | Always read 6/4-byte addresses, ignoring `hlen`/`plen`. | Overread in `--packets` output. | `arp-print-mac-short-hlen`, `arp-print-ip-short-plen`, `ARP.PrintsShortAddressesWithinDeclaredLengths` |
| 3 | `dns::parse` | `fuzz_dns` running unusually slowly | Resized record lists from header counts before checking the bytes exist. | DoS: a 1.4 MB crafted capture takes 6.6 s instead of ~0 s. | `counts-exceed-message-length`, `DNS.RejectsCountsLargerThanMessageWithoutAllocating` |
| 4 | `ip::v6::printIp` | `fuzz_dns`, after fix 3 | Checked the next group before the bounds check; dropped a trailing `::`. | 2-byte overread and wrong text for addresses ending in zeros. | `v6-print-overread-trailing-zero-group`, `aaaa-record-ending-in-zero-group`, `IPV6.PrintIpCompressesTrailingZerosWithinBounds` |
| 5 | `ip::v6::addressFromString` | `fuzz_address` | Read the hex digit once, then consumed the rest of the string. | `--src-ip`/`--dst-ip` rejected almost every IPv6 address. | `v6-parse-rejects-hex-groups`, `IPV6.AddressFromStringParsesHexGroups` |
| 6 | `ip::v4::addressFromString` | `fuzz_address` | Treated a `0` octet as empty. | `--src-ip 10.0.0.1` was rejected. | `v4-parse-rejects-zero-octet` |

Regression files live in `fuzz/regressions/<target>/`.
