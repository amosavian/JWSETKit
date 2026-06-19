import Benchmark
import Crypto
import Foundation
import JWSETKit

/// Fixed key material shared across all comparison libraries (see ../../../StaticKeys.md). Using
/// static keys (vs generating per run) keeps RSA/EC timings reproducible and comparable, and means
/// no key-generation cost leaks into the measured setup.
enum StaticKeys {
    static let ecP256 = Data(#"{"kty":"EC","x":"lao6hsRUSc4ICMV8USSk-_O64dvzuwNY8JuWvROBZCw","y":"CpzpgGswiMCysRsSHkrAJ3fWAf49bmNQsqNbGqKb9-s","crv":"P-256","d":"7LfJ2Rf6FF4grHppvs3hJLzkrOAVg_kdnKgg5MMYmas"}"#.utf8)
    static let rsa2048 = Data(#"{"kty":"RSA","qi":"AMKqHITIGF4biHEOfJOG7GtclS-INU1fkGSrLghkw2Yn-ZfFh9R5UiP7PBxQErS_3ZfLHoCifj4LDWASIN9hT7X5BgC9Dtx7gwan1GFqXTJnPsLVgL9vODgfbQQbWmPKmH_1dXEKn4Z5WM-dkupuoR3h11DWOzwCMlgFnX_UhXAi","e":"AQAB","n":"AOK9ZrYbHjMLfKD4_53FQzu2a2yZ9tXaOpsa4qyGO9-26FYMd4yewrkvkxGFeyl1k5O2SkeGqEf1AbQtKP5-5iMZJVq4HL-Ewcgi9yz0TxSiPM7JsLdBmWHBRuBY7pevBEe11AQvIGva8Dv0bcfiXF_ZOwPRBEddgRb4L9qFC-3I6RS1x7Sqgqjpuvfi1g7YGx-BNJQMThrnEJYc7-3xxPuAmjUKjdKbQ9Ul7Qz3IK1pfnThPDwI9EQUJCiK1Q9ByYpadkroKhtK6jDfYg9aMsuLVQBCjT5ZMpeeRkfkwpIDqJmB1tyv9OkZvY9Q9pSaBqxOIEFcBRe6_CRJeNFZ810","p":"APt_U6Zzm0FJiBWq-pLJeFwoYU2AfpZy2Y9Raoz_Ud-G-SQsPN31fPygEot-UXeNGEq3gjUxSAXZBYkmjebl4HTuv8y0adh530VYLZcxoU6VYsmptW3x5n9V4r-UPWC7hqEyP7MbdHKCq8Ul3YkgfmXvc_IOVDbrYalWEphtGwpj","dq":"Gqbl-dwJ7XLhBya5i5KWkXpXop0yzTUqgXortaAfhSEJ-RDY46ITngThaNdLfFmEA0856-nnFzzfkoNTS866jBsorJwi7rIyoAVUBcLzzdOdA25HkvbXsv1hQIy7Cwam2EAwx8xUhjM9BOBY2bcrHj5TSHVMicvvTx3l7BX2GOE","d":"PFu7CeMyKNh39soSEce_XBf1hNV_lfIgA8YmbVLWgXlJZA6xjGd-4pk9hz6HSMQZ4wp1v5CjH3SjXXlgHk9dqB47iWjVjk4i38ofDoKCwrVlho6-UipOUG2JFpPV_98BPq2yoOKCuPNxXCR3TOx_Nqy3Pw7XGsBTau_qnTspr8R5k90rC0njigwRU3HCuKK5lGuvdHruszScAf_fXi0hASdGaJJIcFjr6SJLJD7CfuNcRiGNvxExzoSLWurfbBsKWco0Wi3lv3TsT5vaXCVhYKplVdlZkYgVX6wLXi56ZkYmpFgV_zWfRAYxk-DcEAulq9DvtzpGXKt38fGUL6kR6Q","dp":"AI0XxrcoPl6nQQhe7sqw6qxRHx2ay-ndrv5_f5Zwmt8bWuSXSOKBGcikiSLnEA9RAeLRBuSOrEhTk455KbzzFDSlyMawJH2FCeRebt1Ww5dRqaVXZ2iyAE1JwrcWFEUTj5kZlrEF4xNnCbTF5H5M03yelN6keUyCSzz0A-StuTDf","q":"AObMmtD7Qc8ufnHrdPuKFcld8L4iR8s6tp4yPSbTyyMy2EqDlYetcAl9AQFgfBBn7X2sjrglcjzAXZyDLFnpe8Qd7dxxGc3W6VfymypzmtEqCoWGDh0sMzU2RB_dNmKPfPxzC6LPtNrrAEZFMzc0qZY9Nc-UdwoHWA1vqb3Uxpc_"}"#.utf8)
    static let hmac = Data("benchmark-hmac-secret-benchmark-hmac-secret-0123".utf8)
}

/// JWSETKit side of the cross-library comparison. Classical signature rows + compact parse are
/// the apples-to-apples workloads every library supports; the jwe-* / sdjwt-* rows are JWSETKit
/// differentiators with no jwt-kit / JOSESwift equivalent (noted asymmetric in README).
let benchmarks: @Sendable () -> Void = {
    // Static keys imported once from fixed JWK material. EC/RSA keys carry a `kid`, matching real
    // JWKS-issued keys (and exercising the keyset's lazy-thumbprint path). `SymmetricKey` (HS256)
    // cannot carry a `kid`.
    var es256 = try! JSONWebECPrivateKey(importing: StaticKeys.ecP256, format: .jwk)
    es256.keyId = "es256-key"
    var rs256 = try! JSONWebRSAPrivateKey(importing: StaticKeys.rsa2048, format: .jwk)
    rs256.keyId = "rs256-key"
    let hs256 = SymmetricKey(data: StaticKeys.hmac)
    var rsaOAEP = try! JSONWebRSAPrivateKey(importing: StaticKeys.rsa2048, format: .jwk)
    rsaOAEP.keyId = "rsaoaep-key"

    // Claims — a realistic OIDC ID token (~14 claims). MUST stay byte-for-byte matched with the
    // jwt-kit side's `BenchPayload` so the cross-library sign/verify rows are apples-to-apples.
    var claims = JSONWebTokenClaims(storage: .init())
    claims.subject = "248289761001"
    claims.issuer = "https://issuer.example.com"
    claims.audience = ["https://api.example.com"]
    claims.issuedAt = Date(timeIntervalSince1970: 1_700_000_000)
    claims.expiry = Date(timeIntervalSince1970: 2_524_608_000) // far-future so verify never fails on expiry
    claims.notBefore = Date(timeIntervalSince1970: 1_700_000_000)
    claims.jwtId = "id-1f1a2b3c4d5e6f70"
    claims.name = "Jane Q. Public"
    claims.givenName = "Jane"
    claims.familyName = "Public"
    claims.preferredUsername = "j.public"
    claims.email = "jane.public@example.com"
    claims.storage["email_verified"] = true
    claims.storage["roles"] = ["admin", "editor", "viewer"]

    // Pre-built tokens for verify / parse / decrypt
    let signedES256 = try! String(JSONWebToken(payload: claims, using: es256))
    let signedRS256 = try! String(JSONWebToken(payload: claims, using: rs256))
    let signedHS256 = try! String(JSONWebToken(payload: claims, using: hs256))
    // Verifying keys resolved once and reused (the JWKS pattern: load a key, verify many tokens) —
    // matches jwt-kit's `JWTKeyCollection`, which materializes its native key once at `add`. The
    // computed `.publicKey` returns a fresh value with a cold cache, so hoisting it out of the loop
    // is both realistic and apples-to-apples; otherwise the row measures per-call re-materialization.
    let es256Public = es256.publicKey
    let rs256Public = rs256.publicKey
    // Recipient public keys for JWE also resolved once (a recipient key is loaded once, then used
    // to encrypt many messages) — matches jose-swift, which holds its `rsaKey`/EC `key` JWK across
    // the loop. Re-deriving `.publicKey` inside the loop would instead measure per-call key
    // materialization (the cold `encryptingKeyCache`), not the wrap+seal throughput.
    let rsaOAEPPublic = rsaOAEP.publicKey
    let plaintext = Data("the quick brown fox jumps over the lazy dog".utf8)
    let encryptedJWE = try! String(JSONWebEncryption(
        content: plaintext,
        keyEncryptingAlgorithm: .rsaEncryptionOAEPSHA256,
        keyEncryptionKey: rsaOAEP.publicKey,
        contentEncryptionAlgorithm: .aesEncryptionGCM256
    ))
    var ecdh = try! JSONWebECPrivateKey(importing: StaticKeys.ecP256, format: .jwk)
    ecdh.keyId = "ecdh-key"
    // Recipient EC public key resolved once and reused (the realistic "encrypt many to one
    // recipient" path, matching jose-swift which holds its EC key across the loop) — warms the
    // cached CryptoKit key-agreement materialization, as the RSA-OAEP recipient row does.
    let ecdhPublic = ecdh.publicKey
    let encryptedECDH = try! String(JSONWebEncryption(
        content: plaintext,
        keyEncryptingAlgorithm: .ecdhEphemeralStatic,
        keyEncryptionKey: ecdh.publicKey,
        contentEncryptionAlgorithm: .aesEncryptionGCM256
    ))

    // SD-JWT claims with concealable custom fields
    var sdClaims = claims
    sdClaims.storage["email"] = "user@example.com"
    sdClaims.storage["phone_number"] = "+1-555-0100"
    let sdConcealed: Set<JSONPointer> = ["/email", "/phone_number"]
    // Pre-issued SD-JWT (compact serialization) for the verify row — same shape the issue row
    // produces (2 disclosures + 2 decoys, ES256). Each side verifies a token it issued itself.
    let signedSDJWT = try! String(JSONWebSelectiveDisclosureToken(
        claims: sdClaims, concealedPaths: sdConcealed, decoyCount: 2, using: es256
    ))

    // MARK: classical signatures (apples-to-apples)

    Benchmark("jwsetkit-sign-ES256") { b in
        for _ in b.scaledIterations {
            try blackHole(String(JSONWebToken(payload: claims, using: es256)))
        }
    }
    Benchmark("jwsetkit-verify-ES256") { b in
        for _ in b.scaledIterations {
            let jwt = try JSONWebToken(from: signedES256)
            try jwt.verifySignature(using: es256Public)
            blackHole(jwt)
        }
    }
    Benchmark("jwsetkit-sign-RS256") { b in
        for _ in b.scaledIterations {
            try blackHole(String(JSONWebToken(payload: claims, using: rs256)))
        }
    }
    Benchmark("jwsetkit-verify-RS256") { b in
        for _ in b.scaledIterations {
            let jwt = try JSONWebToken(from: signedRS256)
            try jwt.verifySignature(using: rs256Public)
            blackHole(jwt)
        }
    }
    Benchmark("jwsetkit-sign-HS256") { b in
        for _ in b.scaledIterations {
            try blackHole(String(JSONWebToken(payload: claims, using: hs256)))
        }
    }
    Benchmark("jwsetkit-verify-HS256") { b in
        for _ in b.scaledIterations {
            let jwt = try JSONWebToken(from: signedHS256)
            try jwt.verifySignature(using: hs256)
            blackHole(jwt)
        }
    }

    // MARK: compact parse (decode only, no signature check)

    Benchmark("jwsetkit-compact-parse") { b in
        for _ in b.scaledIterations {
            try blackHole(JSONWebToken(from: signedES256))
        }
    }

    // MARK: key (de)serialization — import JWK → key, export key → JWK

    Benchmark("jwsetkit-key-import-EC") { b in
        for _ in b.scaledIterations {
            try blackHole(JSONWebECPrivateKey(importing: StaticKeys.ecP256, format: .jwk))
        }
    }
    Benchmark("jwsetkit-key-import-RSA") { b in
        for _ in b.scaledIterations {
            try blackHole(JSONWebRSAPrivateKey(importing: StaticKeys.rsa2048, format: .jwk))
        }
    }
    Benchmark("jwsetkit-key-export-EC") { b in
        for _ in b.scaledIterations {
            try blackHole(es256.exportKey(format: .jwk))
        }
    }
    Benchmark("jwsetkit-key-export-RSA") { b in
        for _ in b.scaledIterations {
            try blackHole(rs256.exportKey(format: .jwk))
        }
    }

    // MARK: JWSETKit-only differentiators

    Benchmark("jwsetkit-jwe-encrypt-RSAOAEP-A256GCM") { b in
        for _ in b.scaledIterations {
            try blackHole(String(JSONWebEncryption(
                content: plaintext,
                keyEncryptingAlgorithm: .rsaEncryptionOAEPSHA256,
                keyEncryptionKey: rsaOAEPPublic,
                contentEncryptionAlgorithm: .aesEncryptionGCM256
            )))
        }
    }
    Benchmark("jwsetkit-jwe-decrypt-RSAOAEP-A256GCM") { b in
        for _ in b.scaledIterations {
            let jwe = try JSONWebEncryption(from: encryptedJWE)
            try blackHole(jwe.decrypt(using: rsaOAEP))
        }
    }
    Benchmark("jwsetkit-jwe-encrypt-ECDHES-A256GCM") { b in
        for _ in b.scaledIterations {
            try blackHole(String(JSONWebEncryption(
                content: plaintext,
                keyEncryptingAlgorithm: .ecdhEphemeralStatic,
                keyEncryptionKey: ecdhPublic,
                contentEncryptionAlgorithm: .aesEncryptionGCM256
            )))
        }
    }
    Benchmark("jwsetkit-jwe-decrypt-ECDHES-A256GCM") { b in
        for _ in b.scaledIterations {
            let jwe = try JSONWebEncryption(from: encryptedECDH)
            try blackHole(jwe.decrypt(using: ecdh))
        }
    }
    Benchmark("jwsetkit-sdjwt-issue") { b in
        for _ in b.scaledIterations {
            try blackHole(JSONWebSelectiveDisclosureToken(
                claims: sdClaims, concealedPaths: sdConcealed, decoyCount: 2, using: es256
            ))
        }
    }
    // Parse the compact serialization, verify the issuer signature, and validate the disclosure
    // digests — matched to EUDI's `SDJWTVerifier.verifyIssuance`.
    Benchmark("jwsetkit-sdjwt-verify") { b in
        for _ in b.scaledIterations {
            let sdjwt = try JSONWebSelectiveDisclosureToken(from: signedSDJWT)
            try sdjwt.jwt.verifySignature(using: es256Public)
            try sdjwt.validate(requireKeyBinding: false)
            blackHole(sdjwt)
        }
    }

    if #available(macOS 26, iOS 26, tvOS 26, watchOS 26, visionOS 26, *) {
        var mldsa = try! JSONWebMLDSAPrivateKey(algorithm: JSONWebSignatureAlgorithm.mldsa65Signature)
        mldsa.keyId = "mldsa-key"
        let signedMLDSA = try! String(JSONWebToken(payload: claims, using: mldsa))
        let mldsaPublic = mldsa.publicKey
        Benchmark("jwsetkit-sign-MLDSA65") { b in
            for _ in b.scaledIterations {
                try blackHole(String(JSONWebToken(payload: claims, using: mldsa)))
            }
        }
        Benchmark("jwsetkit-verify-MLDSA65") { b in
            for _ in b.scaledIterations {
                let jwt = try JSONWebToken(from: signedMLDSA)
                try jwt.verifySignature(using: mldsaPublic)
                blackHole(jwt)
            }
        }
    }
}
