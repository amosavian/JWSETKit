import Benchmark
import BenchmarkSupport
import Foundation
import JWSETKit

let benchmarks: @Sendable () -> Void = {
    // Compact encode of an already-signed token — measures representation building, not signing.
    Benchmark("compact-encode") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(String(Fixtures.signedJWT))
        }
    }
    // Compact decode — parse a compact token back into a JWS.
    Benchmark("compact-decode") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(JSONWebToken(from: Fixtures.signedES256))
        }
    }
    Benchmark("base64url-encode") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(Fixtures.rawBlob.urlBase64EncodedString())
        }
    }
    Benchmark("base64url-decode") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(Data(urlBase64Encoded: Fixtures.base64urlString))
        }
    }
    Benchmark("claims-field-access") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(Fixtures.claims.subject)
            blackHole(Fixtures.claims.issuer)
            blackHole(Fixtures.claims.audience)
        }
    }
}
