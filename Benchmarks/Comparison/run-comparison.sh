#!/usr/bin/env bash
#
# Runs all comparison sides (JWSETKit, jwt-kit, jose-swift, airsidemobile/JOSESwift, EUDI SD-JWT)
# consecutively in one invocation, so every framework's numbers are captured back-to-back on the same
# machine in the same thermal state. The sides are separate SwiftPM packages (jwt-kit, jose-swift, and
# the jose-swift-based EUDI lib pull conflicting swift-crypto / BoringSSL configurations that cannot
# co-resolve in one package), so they cannot run in a single `swift package benchmark` process — this
# script is the closest valid equivalent. The airsidemobile/JOSESwift side is Apple-only (SecKey), so
# on Linux it simply fails to build and is skipped (`|| true`).
#
# Usage:  Benchmarks/Comparison/run-comparison.sh
#
# Notes:
#   - This comparison measures TIME, so it disables package-benchmark's malloc instrumentation for
#     EVERY side (BENCHMARK_DISABLE_JEMALLOC=true, exported below). That removes the interposer's
#     per-allocation counting overhead from the timed region and puts all frameworks on the same
#     system allocator, so the time columns are measured under identical conditions. Malloc metrics
#     are not cross-framework comparable anyway (see Benchmarks/README.md) and are captured in the
#     Regression suite instead. It is also mandatory for the airsidemobile/JOSESwift side, whose
#     Security-framework (SecKey) allocator aborts under jemalloc interposition (SIGABRT in
#     Security::TrackingAllocator).
#   - Only the p50 *time* columns are cross-framework comparable (see Benchmarks/README.md). Re-run
#     the WHOLE script to refresh: comparing one side from this run against another from a different
#     run reintroduces session drift, which is largest on crypto-bound rows (RS256, ML-DSA, JWE).

set -euo pipefail

# Disable malloc instrumentation for all sides — see the note above.
export BENCHMARK_DISABLE_JEMALLOC=true

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for side in jwsetkit-side jwtkit-side joseswift-side airside-side eudi-side; do
    echo "=============================================================="
    echo " $side"
    echo "=============================================================="
    # `--disable-sandbox` is a SwiftPM option and must precede the `benchmark` subcommand; the
    # BenchmarkPlugin needs it to spawn the benchmark executable. Extra args ("$@") pass through to
    # the plugin (e.g. --filter, --no-progress). `|| true` so one side failing doesn't abort the rest.
    swift package --package-path "$DIR/$side" --disable-sandbox benchmark "$@" || true
done
