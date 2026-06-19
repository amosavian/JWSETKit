import Benchmark
import BenchmarkSupport
import Foundation
import JWSETKit

let benchmarks: @Sendable () -> Void = {
    // Sign: build a JWT and serialize to compact.
    Benchmark("sign-HS256") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(String(JSONWebToken(payload: Fixtures.claims, using: Fixtures.hs256Key)))
        }
    }
    Benchmark("sign-RS256") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(String(JSONWebToken(payload: Fixtures.claims, using: Fixtures.rs256PrivateKey)))
        }
    }
    Benchmark("sign-ES256") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(String(JSONWebToken(payload: Fixtures.claims, using: Fixtures.es256PrivateKey)))
        }
    }
    Benchmark("sign-EdDSA") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(String(JSONWebToken(payload: Fixtures.claims, using: Fixtures.ed25519PrivateKey)))
        }
    }

    // Verify: parse a pre-signed compact token and verify its signature. A verifier holds the public
    // key (loaded once, e.g. from a JWKS) and verifies many tokens with it — it never holds the
    // private key — so the verifying keys are resolved ONCE here and reused across the loop. This is
    // both the realistic deployment pattern and what exercises the materialized-key cache (warm after
    // the first verify); re-deriving `.publicKey` per iteration would instead measure key materialization.
    let es256Public = Fixtures.es256PrivateKey.publicKey
    let rs256Public = Fixtures.rs256PrivateKey.publicKey
    let ed25519Public = Fixtures.ed25519PrivateKey.publicKey
    Benchmark("verify-HS256") { benchmark in
        for _ in benchmark.scaledIterations {
            let jwt = try JSONWebToken(from: Fixtures.signedHS256)
            try jwt.verifySignature(using: Fixtures.hs256Key)
            blackHole(jwt)
        }
    }
    Benchmark("verify-RS256") { benchmark in
        for _ in benchmark.scaledIterations {
            let jwt = try JSONWebToken(from: Fixtures.signedRS256)
            try jwt.verifySignature(using: rs256Public)
            blackHole(jwt)
        }
    }
    Benchmark("verify-ES256") { benchmark in
        for _ in benchmark.scaledIterations {
            let jwt = try JSONWebToken(from: Fixtures.signedES256)
            try jwt.verifySignature(using: es256Public)
            blackHole(jwt)
        }
    }
    Benchmark("verify-EdDSA") { benchmark in
        for _ in benchmark.scaledIterations {
            let jwt = try JSONWebToken(from: Fixtures.signedEd25519)
            try jwt.verifySignature(using: ed25519Public)
            blackHole(jwt)
        }
    }
}
