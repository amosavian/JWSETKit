import Benchmark
import BenchmarkSupport
import Foundation
import JWSETKit

let benchmarks: @Sendable () -> Void = {
    // MARK: SD-JWT (RFC 9901) — pure crypto, always available.

    Benchmark("sdjwt-issue") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(JSONWebSelectiveDisclosureToken(
                claims: Fixtures.sdClaims,
                concealedPaths: Fixtures.sdConcealedPaths,
                decoyCount: 2,
                using: Fixtures.es256PrivateKey
            ))
        }
    }
    // Present a subset of disclosures from a pre-issued SD-JWT (disclosure selection only).
    Benchmark("sdjwt-present") { benchmark in
        let selected = Array(Fixtures.issuedSDJWT.disclosures.prefix(1))
        for _ in benchmark.scaledIterations {
            blackHole(Fixtures.issuedSDJWT.presenting(disclosures: selected))
        }
    }
    // Full holder presentation WITH key binding: select a subset, then mint a KB-JWT — computes the
    // `sd_hash` over the presentation, then ES256-signs it. The signature dominates; this is the
    // realistic holder path (`sdjwt-present` above times only the cheap disclosure filter). Reuses
    // the issuer key as the holder key (cost-identical; the fixture has no `cnf` to match).
    Benchmark("sdjwt-present-kb") { benchmark in
        let selected = Array(Fixtures.issuedSDJWT.disclosures.prefix(1))
        for _ in benchmark.scaledIterations {
            let presented = Fixtures.issuedSDJWT.presenting(disclosures: selected)
            try blackHole(presented.withKeyBinding(
                using: Fixtures.es256PrivateKey,
                nonce: "fixed-nonce-1234",
                audience: "https://verifier.example.com"
            ))
        }
    }

    // MARK: ML-DSA-65 — registered only where the platform supports it, so it is absent

    // from the report (never failing) on older OSes.
    if #available(macOS 26, iOS 26, tvOS 26, watchOS 26, visionOS 26, *) {
        let mldsaKey = try! JSONWebMLDSAPrivateKey(algorithm: JSONWebSignatureAlgorithm.mldsa65Signature)
        let signedMLDSA = try! String(JSONWebToken(payload: Fixtures.claims, using: mldsaKey))

        Benchmark("sign-MLDSA65") { benchmark in
            for _ in benchmark.scaledIterations {
                try blackHole(String(JSONWebToken(payload: Fixtures.claims, using: mldsaKey)))
            }
        }
        Benchmark("verify-MLDSA65") { benchmark in
            for _ in benchmark.scaledIterations {
                let jwt = try JSONWebToken(from: signedMLDSA)
                try jwt.verifySignature(using: mldsaKey.publicKey)
                blackHole(jwt)
            }
        }
    }
}
