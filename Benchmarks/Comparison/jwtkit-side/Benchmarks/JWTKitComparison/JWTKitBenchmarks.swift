import _CryptoExtras
import Benchmark
import Crypto
import Foundation
@_spi(PostQuantum) import JWTKit

// Matching workload on vapor/jwt-kit. jwt-kit's API is `async`; the measured closures are
// native `async` benchmarks (package-benchmark `await`s them within the timed region), so the
// time figures are directly comparable. `runBlocking` is used only for one-time token setup
// outside the measured loop.
//
// jwt-kit has no JWE / SD-JWT and no unverified-decode (parse-without-verify) API, so those
// comparison rows are JWSETKit-only — see the matrix in ../../README.md.

/// A realistic OIDC ID token (~14 claims), matched byte-for-byte with the JWSETKit side's claim set
/// so the cross-library sign/verify rows stay apples-to-apples. Registered claims use jwt-kit's
/// native claim types; identity/custom claims are plain Codable fields with snake_case JSON keys.
struct BenchPayload: JWTPayload {
    var sub: SubjectClaim
    var iss: IssuerClaim
    var aud: AudienceClaim
    var exp: ExpirationClaim
    var iat: IssuedAtClaim
    var nbf: NotBeforeClaim
    var jti: IDClaim
    var name: String
    var givenName: String
    var familyName: String
    var preferredUsername: String
    var email: String
    var emailVerified: Bool
    var roles: [String]

    enum CodingKeys: String, CodingKey {
        case sub, iss, aud, exp, iat, nbf, jti, name, email, roles
        case givenName = "given_name"
        case familyName = "family_name"
        case preferredUsername = "preferred_username"
        case emailVerified = "email_verified"
    }

    func verify(using _: some JWTAlgorithm) throws {}
}

/// Static key material shared across all comparison libraries (see ../../../StaticKeys.md), here
/// as PEM (jwt-kit's native key types import PEM, preserving its swift-crypto / BoringSSL backend).
/// Same EC P-256 and RSA-2048 keys the other sides use — so RSA/EC timings are comparable.
private let ecPEM = """
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg7LfJ2Rf6FF4grHpp
vs3hJLzkrOAVg/kdnKgg5MMYmauhRANCAASVqjqGxFRJzggIxXxRJKT787rh2/O7
A1jwm5a9E4FkLAqc6YBrMIjAsrEbEh5KwCd31gH+PW5jULKjWxqim/fr
-----END PRIVATE KEY-----
"""
private let rsaPEM = """
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDivWa2Gx4zC3yg
+P+dxUM7tmtsmfbV2jqbGuKshjvftuhWDHeMnsK5L5MRhXspdZOTtkpHhqhH9QG0
LSj+fuYjGSVauBy/hMHIIvcs9E8UojzOybC3QZlhwUbgWO6XrwRHtdQELyBr2vA7
9G3H4lxf2TsD0QRHXYEW+C/ahQvtyOkUtce0qoKo6br34tYO2BsfgTSUDE4a5xCW
HO/t8cT7gJo1Co3Sm0PVJe0M9yCtaX504Tw8CPREFCQoitUPQcmKWnZK6CobSuow
32IPWjLLi1UAQo0+WTKXnkZH5MKSA6iZgdbcr/TpGb2PUPaUmgasTiBBXAUXuvwk
SXjRWfNdAgMBAAECggEAPFu7CeMyKNh39soSEce/XBf1hNV/lfIgA8YmbVLWgXlJ
ZA6xjGd+4pk9hz6HSMQZ4wp1v5CjH3SjXXlgHk9dqB47iWjVjk4i38ofDoKCwrVl
ho6+UipOUG2JFpPV/98BPq2yoOKCuPNxXCR3TOx/Nqy3Pw7XGsBTau/qnTspr8R5
k90rC0njigwRU3HCuKK5lGuvdHruszScAf/fXi0hASdGaJJIcFjr6SJLJD7CfuNc
RiGNvxExzoSLWurfbBsKWco0Wi3lv3TsT5vaXCVhYKplVdlZkYgVX6wLXi56ZkYm
pFgV/zWfRAYxk+DcEAulq9DvtzpGXKt38fGUL6kR6QKBgQD7f1Omc5tBSYgVqvqS
yXhcKGFNgH6WctmPUWqM/1HfhvkkLDzd9Xz8oBKLflF3jRhKt4I1MUgF2QWJJo3m
5eB07r/MtGnYed9FWC2XMaFOlWLJqbVt8eZ/VeK/lD1gu4ahMj+zG3RygqvFJd2J
IH5l73PyDlQ262GpVhKYbRsKYwKBgQDmzJrQ+0HPLn5x63T7ihXJXfC+IkfLOrae
Mj0m08sjMthKg5WHrXAJfQEBYHwQZ+19rI64JXI8wF2cgyxZ6XvEHe3ccRnN1ulX
8psqc5rRKgqFhg4dLDM1NkQf3TZij3z8cwuiz7Ta6wBGRTM3NKmWPTXPlHcKB1gN
b6m91MaXPwKBgQCNF8a3KD5ep0EIXu7KsOqsUR8dmsvp3a7+f3+WcJrfG1rkl0ji
gRnIpIki5xAPUQHi0QbkjqxIU5OOeSm88xQ0pcjGsCR9hQnkXm7dVsOXUamlV2do
sgBNScK3FhRFE4+ZGZaxBeMTZwm0xeR+TNN8npTepHlMgks89APkrbkw3wKBgBqm
5fncCe1y4QcmuYuSlpF6V6KdMs01KoF6K7WgH4UhCfkQ2OOiE54E4WjXS3xZhANP
Oevp5xc835KDU0vOuowbKKycIu6yMqAFVAXC883TnQNuR5L217L9YUCMuwsGpthA
MMfMVIYzPQTgWNm3Kx4+U0h1TInL708d5ewV9hjhAoGBAMKqHITIGF4biHEOfJOG
7GtclS+INU1fkGSrLghkw2Yn+ZfFh9R5UiP7PBxQErS/3ZfLHoCifj4LDWASIN9h
T7X5BgC9Dtx7gwan1GFqXTJnPsLVgL9vODgfbQQbWmPKmH/1dXEKn4Z5WM+dkupu
oR3h11DWOzwCMlgFnX/UhXAi
-----END PRIVATE KEY-----
"""
private let hmacSecret = "benchmark-hmac-secret-benchmark-hmac-secret-0123"

let benchmarks: @Sendable () -> Void = {
    let payload = BenchPayload(
        sub: "248289761001",
        iss: "https://issuer.example.com",
        aud: .init(value: ["https://api.example.com"]),
        exp: .init(value: Date(timeIntervalSince1970: 2_524_608_000)), // far-future so verify never fails on expiry
        iat: .init(value: Date(timeIntervalSince1970: 1_700_000_000)),
        nbf: .init(value: Date(timeIntervalSince1970: 1_700_000_000)),
        jti: "id-1f1a2b3c4d5e6f70",
        name: "Jane Q. Public",
        givenName: "Jane",
        familyName: "Public",
        preferredUsername: "j.public",
        email: "jane.public@example.com",
        emailVerified: true,
        roles: ["admin", "editor", "viewer"]
    )

    // One key collection per algorithm; each signs its own token for the verify rows.
    let esKeys = JWTKeyCollection()
    let rsKeys = JWTKeyCollection()
    let hsKeys = JWTKeyCollection()

    let (esToken, rsToken, hsToken): (String, String, String) = runBlocking {
        try await esKeys.add(ecdsa: ES256PrivateKey(pem: ecPEM))
        try await rsKeys.add(rsa: Insecure.RSA.PrivateKey(pem: rsaPEM), digestAlgorithm: .sha256)
        await hsKeys.add(hmac: HMACKey(from: hmacSecret), digestAlgorithm: .sha256)
        return try await (
            esKeys.sign(payload),
            rsKeys.sign(payload),
            hsKeys.sign(payload)
        )
    }

    // MARK: classical signatures

    Benchmark("jwtkit-sign-ES256") { b in
        for _ in b.scaledIterations {
            try await blackHole(esKeys.sign(payload))
        }
    }
    Benchmark("jwtkit-verify-ES256") { b in
        for _ in b.scaledIterations {
            try await blackHole(esKeys.verify(esToken, as: BenchPayload.self))
        }
    }
    Benchmark("jwtkit-sign-RS256") { b in
        for _ in b.scaledIterations {
            try await blackHole(rsKeys.sign(payload))
        }
    }
    Benchmark("jwtkit-verify-RS256") { b in
        for _ in b.scaledIterations {
            try await blackHole(rsKeys.verify(rsToken, as: BenchPayload.self))
        }
    }
    Benchmark("jwtkit-sign-HS256") { b in
        for _ in b.scaledIterations {
            try await blackHole(hsKeys.sign(payload))
        }
    }
    Benchmark("jwtkit-verify-HS256") { b in
        for _ in b.scaledIterations {
            try await blackHole(hsKeys.verify(hsToken, as: BenchPayload.self))
        }
    }

    if #available(macOS 26, iOS 26, tvOS 26, watchOS 26, visionOS 26, *) {
        let mldsaKeys = JWTKeyCollection()
        let mldsaToken: String = runBlocking {
            try await mldsaKeys.add(mldsa: MLDSA65PrivateKey(backing: MLDSA65.PrivateKey()))
            return try await mldsaKeys.sign(payload)
        }
        Benchmark("jwtkit-sign-MLDSA65") { b in
            for _ in b.scaledIterations {
                try await blackHole(mldsaKeys.sign(payload))
            }
        }
        Benchmark("jwtkit-verify-MLDSA65") { b in
            for _ in b.scaledIterations {
                try await blackHole(mldsaKeys.verify(mldsaToken, as: BenchPayload.self))
            }
        }
    }
}

/// Bridges jwt-kit's async API into the synchronous setup phase (one-time token signing only;
/// the measured benchmarks use native `async` closures).
func runBlocking<T: Sendable>(_ operation: @escaping @Sendable () async throws -> T) -> T {
    let semaphore = DispatchSemaphore(value: 0)
    let box = ResultBox<T>()
    Task {
        do {
            box.result = try await .success(operation())
        } catch {
            box.result = .failure(error)
        }
        semaphore.signal()
    }
    semaphore.wait()
    return try! box.result!.get()
}

final class ResultBox<T>: @unchecked Sendable {
    var result: Result<T, Error>?
}
