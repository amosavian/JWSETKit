#!/usr/bin/env bash
#
# Runs all comparison sides (JWSETKit, jwt-kit, jose-swift, EUDI SD-JWT) consecutively in one
# invocation, so every framework's numbers are captured back-to-back on the same machine in the same
# thermal state. The sides are separate SwiftPM packages (jwt-kit, jose-swift, and the jose-swift-
# based EUDI lib pull conflicting swift-crypto / BoringSSL configurations that cannot co-resolve in
# one package), so they cannot run in a single `swift package benchmark` process — this script is the
# closest valid equivalent.
#
# Usage:  Benchmarks/Comparison/run-comparison.sh
#
# Notes:
#   - Requires jemalloc for malloc metrics (brew install jemalloc / apt-get install libjemalloc-dev).
#   - Only the p50 *time* columns are cross-framework comparable (see Benchmarks/README.md). Re-run
#     the WHOLE script to refresh: comparing one side from this run against another from a different
#     run reintroduces session drift, which is largest on crypto-bound rows (RS256, ML-DSA, JWE).

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for side in jwsetkit-side jwtkit-side joseswift-side eudi-side; do
    echo "=============================================================="
    echo " $side"
    echo "=============================================================="
    # `--disable-sandbox` is a SwiftPM option and must precede the `benchmark` subcommand; the
    # BenchmarkPlugin needs it to spawn the benchmark executable. Extra args ("$@") pass through to
    # the plugin (e.g. --filter, --no-progress). `|| true` so one side failing doesn't abort the rest.
    swift package --package-path "$DIR/$side" --disable-sandbox benchmark "$@" || true
done
