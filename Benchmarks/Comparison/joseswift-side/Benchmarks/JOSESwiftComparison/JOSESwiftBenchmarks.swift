import Benchmark
import Crypto
import CryptoSwift
import Foundation
import JSONWebEncryption
import JSONWebKey
import JSONWebSignature
import JSONWebToken

/// jose-swift (beatt83) side of the comparison.
///
/// - Signatures: `JWT.signed(...)` is synchronous; `JWT.verify(...)` is `async` — the verify rows
///   are native `async` benchmark closures (package-benchmark `await`s them within the timed
///   region), so the figures are directly comparable.
/// - JWE encrypt + decrypt (ECDH-ES and RSA-OAEP-256, both with A256GCM): fully synchronous.
///   ECDH-ES uses a CryptoKit P256 key (identical backend to JWSETKit). RSA uses jose-swift's
///   CryptoSwift-backed `RSA` type, whereas JWSETKit uses SecKey / swift-crypto — note the
///   differing RSA backend (../../README.md).
/// A realistic OIDC ID token (~14 claims), matched with the JWSETKit / jwt-kit sides so all three
/// encode the same payload. `JWTRegisteredFieldsClaims` only models the 7 registered claims; the
/// identity + custom claims are added as plain `Codable` fields (jose-swift's `JWT.signed` encodes
/// the payload via its synthesized `Encodable`, so extra fields just serialize alongside).
struct BenchPayload: JWTRegisteredFieldsClaims, Codable {
    var iss: String?
    var sub: String?
    var aud: [String]?
    var exp: Date?
    var nbf: Date?
    var iat: Date?
    var jti: String?
    var name: String?
    var givenName: String?
    var familyName: String?
    var preferredUsername: String?
    var email: String?
    var emailVerified: Bool?
    var roles: [String]?
    func validateExtraClaims() throws {}

    enum CodingKeys: String, CodingKey {
        case iss, sub, aud, exp, nbf, iat, jti, name, email, roles
        case givenName = "given_name"
        case familyName = "family_name"
        case preferredUsername = "preferred_username"
        case emailVerified = "email_verified"
    }
}

/// Fixed key material shared across all comparison libraries (see ../../../StaticKeys.md). Decoded
/// from the same JWK JSON the other sides use, so RSA/EC timings are reproducible and comparable.
enum StaticKeys {
    static let ecP256JSON = Data(#"{"kty":"EC","x":"lao6hsRUSc4ICMV8USSk-_O64dvzuwNY8JuWvROBZCw","y":"CpzpgGswiMCysRsSHkrAJ3fWAf49bmNQsqNbGqKb9-s","crv":"P-256","d":"7LfJ2Rf6FF4grHppvs3hJLzkrOAVg_kdnKgg5MMYmas"}"#.utf8)
    static let rsa2048JSON = Data(#"{"kty":"RSA","qi":"AMKqHITIGF4biHEOfJOG7GtclS-INU1fkGSrLghkw2Yn-ZfFh9R5UiP7PBxQErS_3ZfLHoCifj4LDWASIN9hT7X5BgC9Dtx7gwan1GFqXTJnPsLVgL9vODgfbQQbWmPKmH_1dXEKn4Z5WM-dkupuoR3h11DWOzwCMlgFnX_UhXAi","e":"AQAB","n":"AOK9ZrYbHjMLfKD4_53FQzu2a2yZ9tXaOpsa4qyGO9-26FYMd4yewrkvkxGFeyl1k5O2SkeGqEf1AbQtKP5-5iMZJVq4HL-Ewcgi9yz0TxSiPM7JsLdBmWHBRuBY7pevBEe11AQvIGva8Dv0bcfiXF_ZOwPRBEddgRb4L9qFC-3I6RS1x7Sqgqjpuvfi1g7YGx-BNJQMThrnEJYc7-3xxPuAmjUKjdKbQ9Ul7Qz3IK1pfnThPDwI9EQUJCiK1Q9ByYpadkroKhtK6jDfYg9aMsuLVQBCjT5ZMpeeRkfkwpIDqJmB1tyv9OkZvY9Q9pSaBqxOIEFcBRe6_CRJeNFZ810","p":"APt_U6Zzm0FJiBWq-pLJeFwoYU2AfpZy2Y9Raoz_Ud-G-SQsPN31fPygEot-UXeNGEq3gjUxSAXZBYkmjebl4HTuv8y0adh530VYLZcxoU6VYsmptW3x5n9V4r-UPWC7hqEyP7MbdHKCq8Ul3YkgfmXvc_IOVDbrYalWEphtGwpj","dq":"Gqbl-dwJ7XLhBya5i5KWkXpXop0yzTUqgXortaAfhSEJ-RDY46ITngThaNdLfFmEA0856-nnFzzfkoNTS866jBsorJwi7rIyoAVUBcLzzdOdA25HkvbXsv1hQIy7Cwam2EAwx8xUhjM9BOBY2bcrHj5TSHVMicvvTx3l7BX2GOE","d":"PFu7CeMyKNh39soSEce_XBf1hNV_lfIgA8YmbVLWgXlJZA6xjGd-4pk9hz6HSMQZ4wp1v5CjH3SjXXlgHk9dqB47iWjVjk4i38ofDoKCwrVlho6-UipOUG2JFpPV_98BPq2yoOKCuPNxXCR3TOx_Nqy3Pw7XGsBTau_qnTspr8R5k90rC0njigwRU3HCuKK5lGuvdHruszScAf_fXi0hASdGaJJIcFjr6SJLJD7CfuNcRiGNvxExzoSLWurfbBsKWco0Wi3lv3TsT5vaXCVhYKplVdlZkYgVX6wLXi56ZkYmpFgV_zWfRAYxk-DcEAulq9DvtzpGXKt38fGUL6kR6Q","dp":"AI0XxrcoPl6nQQhe7sqw6qxRHx2ay-ndrv5_f5Zwmt8bWuSXSOKBGcikiSLnEA9RAeLRBuSOrEhTk455KbzzFDSlyMawJH2FCeRebt1Ww5dRqaVXZ2iyAE1JwrcWFEUTj5kZlrEF4xNnCbTF5H5M03yelN6keUyCSzz0A-StuTDf","q":"AObMmtD7Qc8ufnHrdPuKFcld8L4iR8s6tp4yPSbTyyMy2EqDlYetcAl9AQFgfBBn7X2sjrglcjzAXZyDLFnpe8Qd7dxxGc3W6VfymypzmtEqCoWGDh0sMzU2RB_dNmKPfPxzC6LPtNrrAEZFMzc0qZY9Nc-UdwoHWA1vqb3Uxpc_"}"#.utf8)
    static let hmac = Data("benchmark-hmac-secret-benchmark-hmac-secret-0123".utf8)
}

let benchmarks: @Sendable () -> Void = {
    // The same realistic ~14-claim OIDC ID token the JWSETKit / jwt-kit sides encode — now fully
    // size-matched across all three frameworks.
    let payload = BenchPayload(
        iss: "https://issuer.example.com",
        sub: "248289761001",
        aud: ["https://api.example.com"],
        exp: Date(timeIntervalSince1970: 2_524_608_000), // far-future so verify never fails on expiry
        nbf: Date(timeIntervalSince1970: 1_700_000_000),
        iat: Date(timeIntervalSince1970: 1_700_000_000),
        jti: "id-1f1a2b3c4d5e6f70",
        name: "Jane Q. Public",
        givenName: "Jane",
        familyName: "Public",
        preferredUsername: "j.public",
        email: "jane.public@example.com",
        emailVerified: true,
        roles: ["admin", "editor", "viewer"]
    )

    let key = try! JSONDecoder().decode(JWK.self, from: StaticKeys.ecP256JSON)

    let signed = try! JWT.signed(
        payload: payload,
        protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES256),
        key: key
    ).jwtString

    Benchmark("joseswift-sign-ES256") { b in
        for _ in b.scaledIterations {
            try blackHole(JWT.signed(
                payload: payload,
                protectedHeader: DefaultJWSHeaderImpl(algorithm: .ES256),
                key: key
            ).jwtString)
        }
    }
    Benchmark("joseswift-verify-ES256") { b in
        for _ in b.scaledIterations {
            // Return the payload Data (Sendable) rather than the non-Sendable JWT itself.
            try await blackHole(JWT.verify(jwtString: signed, senderKey: key).payload)
        }
    }

    // RS256 — same static RSA-2048 JWK as the other sides (jose-swift decodes it to its
    // CryptoSwift-backed RSA internally; note the differing RSA backend, ../../README.md).
    let rsaKey = try! JSONDecoder().decode(JWK.self, from: StaticKeys.rsa2048JSON)
    let signedRS256 = try! JWT.signed(
        payload: payload,
        protectedHeader: DefaultJWSHeaderImpl(algorithm: .RS256),
        key: rsaKey
    ).jwtString

    Benchmark("joseswift-sign-RS256") { b in
        for _ in b.scaledIterations {
            try blackHole(JWT.signed(
                payload: payload,
                protectedHeader: DefaultJWSHeaderImpl(algorithm: .RS256),
                key: rsaKey
            ).jwtString)
        }
    }
    let rsaVerifyKey = UncheckedBox(rsaKey)
    Benchmark("joseswift-verify-RS256") { b in
        for _ in b.scaledIterations {
            try await blackHole(JWT.verify(jwtString: signedRS256, senderKey: rsaVerifyKey.value).payload)
        }
    }

    // HS256 — symmetric key from fixed bytes.
    let hmacKey = SymmetricKey(data: StaticKeys.hmac)
    let signedHS256 = try! JWT.signed(
        payload: payload,
        protectedHeader: DefaultJWSHeaderImpl(algorithm: .HS256),
        key: hmacKey
    ).jwtString

    Benchmark("joseswift-sign-HS256") { b in
        for _ in b.scaledIterations {
            try blackHole(JWT.signed(
                payload: payload,
                protectedHeader: DefaultJWSHeaderImpl(algorithm: .HS256),
                key: hmacKey
            ).jwtString)
        }
    }
    Benchmark("joseswift-verify-HS256") { b in
        for _ in b.scaledIterations {
            try await blackHole(JWT.verify(jwtString: signedHS256, senderKey: hmacKey).payload)
        }
    }

    // MARK: JWE (synchronous on both encrypt and decrypt — no async bridge)

    let plaintext = Data("the quick brown fox jumps over the lazy dog".utf8)

    // ECDH-ES / A256GCM — the same static P-256 JWK (`key`); same curve material serves key
    // agreement.
    let encryptedECDH = try! JWE(
        payload: plaintext,
        keyManagementAlg: .ecdhES,
        encryptionAlgorithm: .a256GCM,
        recipientKey: key
    ).compactSerialization

    Benchmark("joseswift-jwe-encrypt-ECDHES-A256GCM") { b in
        for _ in b.scaledIterations {
            try blackHole(JWE(
                payload: plaintext,
                keyManagementAlg: .ecdhES,
                encryptionAlgorithm: .a256GCM,
                recipientKey: key
            ).compactSerialization)
        }
    }
    Benchmark("joseswift-jwe-decrypt-ECDHES-A256GCM") { b in
        for _ in b.scaledIterations {
            try blackHole(JWE.decrypt(compactString: encryptedECDH, recipientKey: key))
        }
    }

    // RSA-OAEP-256 / A256GCM — reuses the same static RSA-2048 JWK (`rsaKey`).
    let encryptedRSA = try! JWE(
        payload: plaintext,
        keyManagementAlg: .rsaOAEP256,
        encryptionAlgorithm: .a256GCM,
        recipientKey: rsaKey
    ).compactSerialization

    Benchmark("joseswift-jwe-encrypt-RSAOAEP-A256GCM") { b in
        for _ in b.scaledIterations {
            try blackHole(JWE(
                payload: plaintext,
                keyManagementAlg: .rsaOAEP256,
                encryptionAlgorithm: .a256GCM,
                recipientKey: rsaKey
            ).compactSerialization)
        }
    }
    Benchmark("joseswift-jwe-decrypt-RSAOAEP-A256GCM") { b in
        for _ in b.scaledIterations {
            try blackHole(JWE.decrypt(compactString: encryptedRSA, recipientKey: rsaKey))
        }
    }
}

/// Wraps a non-`Sendable` value (CryptoSwift's `RSA`) so it can be captured by the `@Sendable`
/// async verify closure. Verify is read-only — no actual mutation or data race.
struct UncheckedBox<T>: @unchecked Sendable {
    let value: T
    init(_ value: T) {
        self.value = value
    }
}
