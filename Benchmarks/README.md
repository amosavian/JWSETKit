# JWSETKit Benchmarks

Reproducible performance benchmarks built on [package-benchmark](https://github.com/ordo-one/package-benchmark).

**In short:** JWSETKit is the most capable Swift JOSE library *and* competitive on speed — at parity
with the fastest (jwt-kit) on ES256/RS256 since they share the same crypto backends, and ahead of
jose-swift on HS256, JWE, and SD-JWT. The Apple-only airsidemobile/JOSESwift wins HS256 and keeps pace
on ES256 through lean `SecKey` paths, but supports far less — no Linux, SD-JWT, or post-quantum, a
`SecKey` RS256 sign ~2× slower, and an ECDH-ES encrypt ~5× slower. Run the suite yourself with the
commands below; always re-measure on your own hardware before drawing conclusions.

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

To run a single side the same way (only compare
columns captured in the **same** consecutive run):

```bash
swift package --package-path Benchmarks/Comparison/jwsetkit-side  benchmark
swift package --package-path Benchmarks/Comparison/jwtkit-side    benchmark
swift package --package-path Benchmarks/Comparison/joseswift-side benchmark   # beatt83/jose-swift
swift package --package-path Benchmarks/Comparison/airside-side   benchmark   # airsidemobile/JOSESwift
swift package --package-path Benchmarks/Comparison/eudi-side      benchmark   # SD-JWT only
```

The airsidemobile library is **Apple-only** — it runs every signature, verification and
RSA operation through the Security framework (`SecKey`).

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

**Signatures**:

| Workload | JWSETKit | jwt-kit | jose-swift | JOSESwift |
| --- | --- | --- | --- | --- |
| sign-ES256 | 178 | **172** | 335 | 176 |
| verify-ES256 | 162 | **156** | 410 | 157 |
| sign-HS256 | 31 | 30 | 58 | **27** |
| verify-HS256 | 44 | 53 | 280 | **39** |
| sign-RS256 | 613 | **593** | 69000 | 1109 |
| verify-RS256 | 62 | **56** | 1872 | 72 |
| sign-MLDSA65 | 792 | **785** | — | — |
| verify-MLDSA65 | **161** | **161** | — | — |

Without `X509`, JWSETKit on Darwin falls back to Apple `SecKey` (≈1110 µs RS256 sign) — enable `X509`
for the faster RSA path on Apple platforms.

**JWE**:

| Workload | JWSETKit | jose-swift | JOSESwift |
| --- | --- | --- | --- |
| jwe-encrypt-ECDHES-A256GCM | **596** | 748 | 3258 |
| jwe-decrypt-ECDHES-A256GCM | 251 | 358 | **218** |
| jwe-encrypt-RSAOAEP-A256GCM | 51 | 60 | **49** |
| jwe-decrypt-RSAOAEP-A256GCM | 1144 | 1407 | **1121** |

**SD-JWT**:
Issue and verify a ~14-claim token with two selectively-disclosable claims
and two decoy digests (ES256):

| Workload | JWSETKit | EUDI |
| --- | --- | --- |
| sdjwt-issue | **203** | 558 |
| sdjwt-verify | **198** | 509 |

EUDI inherits jose-swift's signing cost, so JWSETKit issues and verifies ~2 to ~3 times faster.

## Reading the numbers

- **Compare only within one run, on one machine.** Wall-clock varies with thermal state and load,
  often by more than the gap between adjacent rows. To refresh the comparison, re-run the whole
  `run-comparison.sh`.
- **Only time is measured; malloc metrics are off for every side.** The comparison runs
  `BENCHMARK_DISABLE_JEMALLOC=true` throughout (see *Running*), so no allocation counting perturbs the
  timed region and all frameworks share one allocator. Allocation figures live in JWSETKit's
  `Regression` suite instead.
- The comparison covers only the workloads every listed library supports — not the ❌ / ⚠️ cells.
- ML-DSA (post-quantum, macOS 26+) is the noisiest row; `sign-MLDSA65` swings run-to-run for both
  sides. Re-measure before concluding.
- **JOSESwift (airsidemobile) is Apple-only and `SecKey`-backed.** Every EC/RSA operation runs through
  the Security framework, which is why its RS256 sign matches JWSETKit's non-`X509` `SecKey` figure.
