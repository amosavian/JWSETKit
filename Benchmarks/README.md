# JWSETKit Benchmarks

Reproducible performance benchmarks built on [package-benchmark](https://github.com/ordo-one/package-benchmark).

**In short:** JWSETKit is the most capable Swift JOSE library *and* competitive on speed — at parity
with the fastest (jwt-kit) on ES256/RS256 since they share the same crypto backends, and ahead on
HS256, JWE, and SD-JWT. Run the suite yourself with the commands below; always re-measure on your own
hardware before drawing conclusions.

The benchmarks are **two standalone SwiftPM packages**, separate from the library so competitor
dependencies never enter JWSETKit's resolution graph:

- `Benchmarks/Regression/` — JWSETKit's own performance, no competitor dependencies.
- `Benchmarks/Comparison/` — opt-in head-to-head vs other Swift JOSE libraries.

## Prerequisites

`package-benchmark` uses **jemalloc** for its malloc / memory metrics:

- macOS: `brew install jemalloc`
- Linux: `apt-get install -y libjemalloc-dev`

To run without jemalloc (disables only the malloc metrics), prefix any command with
`BENCHMARK_DISABLE_JEMALLOC=true`.

## Running

### JWSETKit's own performance

Self-contained; depends on JWSETKit with **no traits**, so it builds only the crypto core (fast).

```bash
swift package --package-path Benchmarks/Regression benchmark                  # all targets
swift package --package-path Benchmarks/Regression benchmark --target Signing # one target
```

| Target | Covers |
|---|---|
| `Signing` | JWS/JWT sign + verify: HS256, RS256, ES256, EdDSA |
| `Serialization` | compact encode/decode, base64url round-trip, claim field access |
| `Encryption` | JWE encrypt + decrypt: RSA-OAEP-256, ECDH-ES, both with A256GCM |
| `Advanced` | SD-JWT issue / present / present-with-key-binding; ML-DSA-65 (macOS 26+) |
| `Profiling` | stage-by-stage decomposition of each pipeline (for contributors) |

Before/after comparison on a local change:

```bash
swift package --package-path Benchmarks/Regression benchmark baseline update main
# ...make changes...
swift package --package-path Benchmarks/Regression benchmark baseline compare main
```

### Head-to-head vs other libraries (opt-in)

Each competitor is its **own** SwiftPM package under `Benchmarks/Comparison/`, because jwt-kit,
jose-swift, and the jose-swift-based EUDI SD-JWT library pull conflicting swift-crypto / BoringSSL
configurations that cannot co-resolve in one package. Run **all sides back-to-back** so every
framework is measured on the same machine in the same thermal state:

```bash
Benchmarks/Comparison/run-comparison.sh
```

Or run a single side (only compare columns captured in the **same** consecutive run):

```bash
swift package --package-path Benchmarks/Comparison/jwsetkit-side  benchmark
swift package --package-path Benchmarks/Comparison/jwtkit-side    benchmark
swift package --package-path Benchmarks/Comparison/joseswift-side benchmark
swift package --package-path Benchmarks/Comparison/eudi-side      benchmark   # SD-JWT only
```

## How JWSETKit compares

### Capability

| Feature | JWSETKit | jwt-kit | jose-swift | JOSESwift |
|---|---|---|---|---|
| JWS / JWT sign+verify (HS/RS/ES/EdDSA) | ✅ | ✅ | ✅ | ✅ |
| Compact parse / serialize | ✅ | ✅ | ✅ | ✅ |
| ML-DSA-65/87 (post-quantum) | ✅ | ✅ (macOS 26+) | ❌ | ❌ |
| JWE encrypt / decrypt | ✅ | ❌ | ✅ | ⚠️ partial |
| SD-JWT | ✅ | ❌ | ⚠️ partial | ❌ |
| DPoP · HPKE · COSE-ready | ✅ | ❌ | ❌ | ❌ |

SD-JWT is additionally compared against the **EUDI reference library**
(`eu-digital-identity-wallet/eudi-lib-sdjwt-swift`, built on jose-swift), which implements only
SD-JWT and so isn't in the matrix above.

### Sample results

Apple silicon, release build, p50, **µs (lower is better)** — **illustrative only**. Each table
below is from one consecutive run, so its columns are mutually comparable; numbers across *different*
runs are not (wall-clock swings ±10–20 % with thermal state and background load, most on crypto-bound
rows). Re-run on your own hardware.

All frameworks encode the **same realistic ~14-claim OIDC ID token**, and the `verify-*` rows resolve
the verifying key once and reuse it (the real JWKS pattern), so the rows are size- and usage-matched.

**Signatures** (every library supports these):

| Workload | JWSETKit | jwt-kit | jose-swift |
|---|---|---|---|
| sign-ES256 | 169 | **168** | 329 |
| verify-ES256 | 154 | **149** | 399 |
| sign-HS256 | **28** | 28 | 53 |
| verify-HS256 | **40** | 48 | 271 |
| sign-RS256 | **585** | 592 | 69000 |
| verify-RS256 | 56 | **52** | 1853 |
| sign-MLDSA65 | **694** | 738 | — |
| verify-MLDSA65 | **145** | 147 | — |

ES256/RS256 sit at parity with jwt-kit because both use swift-crypto's BoringSSL backend. JWSETKit
uses it whenever `CryptoExtras` is available: always on Linux, and on Darwin when the **`X509` trait**
is enabled (which this comparison sets). Without `X509`, Darwin falls back to Apple `SecKey`
(≈1110 µs RS256 sign) — enable `X509` for the faster RSA path on Apple platforms.

**JWE** (JWSETKit and jose-swift only):

| Workload | JWSETKit | jose-swift |
|---|---|---|
| jwe-encrypt-ECDHES-A256GCM | **582** | 721 |
| jwe-decrypt-ECDHES-A256GCM | **230** | 345 |
| jwe-encrypt-RSAOAEP-A256GCM | **48** | 55 |
| jwe-decrypt-RSAOAEP-A256GCM | **926** | 1389 |

**SD-JWT** — JWSETKit vs the EUDI reference library. Both issue and verify a ~14-claim token with two
selectively-disclosable claims and two decoy digests (ES256):

| Workload | JWSETKit | EUDI |
|---|---|---|
| sdjwt-issue | **213** | 655 |
| sdjwt-verify | **209** | 506 |

EUDI inherits jose-swift's signing cost, so JWSETKit issues ≈3× and verifies ≈2.4× faster.

## Reading the numbers

- **Compare only within one run, on one machine.** Wall-clock varies with thermal state and load,
  often by more than the gap between adjacent rows. To refresh the comparison, re-run the whole
  `run-comparison.sh`.
- **Times are comparable across libraries; allocation counts are not.** jwt-kit's API and
  jose-swift's `verify` are `async`; the concurrency runtime's own allocations get counted alongside
  the code under test (package-benchmark flags these as "false memory leaks"). The timed region still
  brackets the `await` correctly, so the **time** figures are sound. Allocation metrics are only
  meaningful for JWSETKit's synchronous `Regression` suite.
- The comparison covers only the workloads every listed library supports — not the ❌ / ⚠️ cells.
- ML-DSA (post-quantum, macOS 26+) is the noisiest row; `sign-MLDSA65` swings run-to-run for both
  sides. Re-measure before concluding.
