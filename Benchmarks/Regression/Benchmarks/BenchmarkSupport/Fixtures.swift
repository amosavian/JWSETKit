import Crypto
import Foundation
import JWSETKit

/// Fixed key material (JWK JSON) shared with the Comparison suite, so RSA/EC timings are
/// reproducible run-to-run rather than depending on freshly-generated keys.
enum StaticKeys {
    static let ecP256 = Data(#"{"kty":"EC","x":"lao6hsRUSc4ICMV8USSk-_O64dvzuwNY8JuWvROBZCw","y":"CpzpgGswiMCysRsSHkrAJ3fWAf49bmNQsqNbGqKb9-s","crv":"P-256","d":"7LfJ2Rf6FF4grHppvs3hJLzkrOAVg_kdnKgg5MMYmas"}"#.utf8)
    static let ed25519 = Data(#"{"crv":"Ed25519","kty":"OKP","x":"jXLSxHwrMfnPXnWWhmPByHKmn7x56PhZha_YqojGpMg","d":"lqX5zCSjlD7hTdIHJwsQgSu_AZNcfZXftUZ8Tj94IgQ"}"#.utf8)
    static let rsa2048 = Data(#"{"kty":"RSA","qi":"AMKqHITIGF4biHEOfJOG7GtclS-INU1fkGSrLghkw2Yn-ZfFh9R5UiP7PBxQErS_3ZfLHoCifj4LDWASIN9hT7X5BgC9Dtx7gwan1GFqXTJnPsLVgL9vODgfbQQbWmPKmH_1dXEKn4Z5WM-dkupuoR3h11DWOzwCMlgFnX_UhXAi","e":"AQAB","n":"AOK9ZrYbHjMLfKD4_53FQzu2a2yZ9tXaOpsa4qyGO9-26FYMd4yewrkvkxGFeyl1k5O2SkeGqEf1AbQtKP5-5iMZJVq4HL-Ewcgi9yz0TxSiPM7JsLdBmWHBRuBY7pevBEe11AQvIGva8Dv0bcfiXF_ZOwPRBEddgRb4L9qFC-3I6RS1x7Sqgqjpuvfi1g7YGx-BNJQMThrnEJYc7-3xxPuAmjUKjdKbQ9Ul7Qz3IK1pfnThPDwI9EQUJCiK1Q9ByYpadkroKhtK6jDfYg9aMsuLVQBCjT5ZMpeeRkfkwpIDqJmB1tyv9OkZvY9Q9pSaBqxOIEFcBRe6_CRJeNFZ810","p":"APt_U6Zzm0FJiBWq-pLJeFwoYU2AfpZy2Y9Raoz_Ud-G-SQsPN31fPygEot-UXeNGEq3gjUxSAXZBYkmjebl4HTuv8y0adh530VYLZcxoU6VYsmptW3x5n9V4r-UPWC7hqEyP7MbdHKCq8Ul3YkgfmXvc_IOVDbrYalWEphtGwpj","dq":"Gqbl-dwJ7XLhBya5i5KWkXpXop0yzTUqgXortaAfhSEJ-RDY46ITngThaNdLfFmEA0856-nnFzzfkoNTS866jBsorJwi7rIyoAVUBcLzzdOdA25HkvbXsv1hQIy7Cwam2EAwx8xUhjM9BOBY2bcrHj5TSHVMicvvTx3l7BX2GOE","d":"PFu7CeMyKNh39soSEce_XBf1hNV_lfIgA8YmbVLWgXlJZA6xjGd-4pk9hz6HSMQZ4wp1v5CjH3SjXXlgHk9dqB47iWjVjk4i38ofDoKCwrVlho6-UipOUG2JFpPV_98BPq2yoOKCuPNxXCR3TOx_Nqy3Pw7XGsBTau_qnTspr8R5k90rC0njigwRU3HCuKK5lGuvdHruszScAf_fXi0hASdGaJJIcFjr6SJLJD7CfuNcRiGNvxExzoSLWurfbBsKWco0Wi3lv3TsT5vaXCVhYKplVdlZkYgVX6wLXi56ZkYmpFgV_zWfRAYxk-DcEAulq9DvtzpGXKt38fGUL6kR6Q","dp":"AI0XxrcoPl6nQQhe7sqw6qxRHx2ay-ndrv5_f5Zwmt8bWuSXSOKBGcikiSLnEA9RAeLRBuSOrEhTk455KbzzFDSlyMawJH2FCeRebt1Ww5dRqaVXZ2iyAE1JwrcWFEUTj5kZlrEF4xNnCbTF5H5M03yelN6keUyCSzz0A-StuTDf","q":"AObMmtD7Qc8ufnHrdPuKFcld8L4iR8s6tp4yPSbTyyMy2EqDlYetcAl9AQFgfBBn7X2sjrglcjzAXZyDLFnpe8Qd7dxxGc3W6VfymypzmtEqCoWGDh0sMzU2RB_dNmKPfPxzC6LPtNrrAEZFMzc0qZY9Nc-UdwoHWA1vqb3Uxpc_"}"#.utf8)
    static let hmac = Data("benchmark-hmac-secret-benchmark-hmac-secret-0123".utf8)
}

/// Shared, pre-built benchmark fixtures. Built once at first access so the cost of
/// key generation and payload construction is never measured inside a benchmark closure.
public enum Fixtures {
    /// A realistic OIDC ID-token claim set (~14 claims): the registered set every token carries
    /// (`sub`/`iss`/`aud`/`exp`/`iat`/`nbf`/`jti`) plus the identity claims a real login token
    /// includes (`name`/`given_name`/`family_name`/`preferred_username`/`email`/`email_verified`)
    /// and a custom authz claim (`roles`). Mirrors production JWT sizes far better than a 2–5 field
    /// stub, and exercises the storage encode/decode across String/Bool/Date/array values.
    public static let claims: JSONWebTokenClaims = {
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
        return claims
    }()

    // MARK: - Signing keys

    // Imported from fixed JWK material (see ../../../Comparison StaticKeys) so RSA/EC timings are
    // reproducible run-to-run, not dependent on freshly-generated keys.
    public static let es256PrivateKey = try! JSONWebECPrivateKey(importing: StaticKeys.ecP256, format: .jwk)
    public static let rs256PrivateKey = try! JSONWebRSAPrivateKey(importing: StaticKeys.rsa2048, format: .jwk)
    public static let ed25519PrivateKey = try! JSONWebECPrivateKey(importing: StaticKeys.ed25519, format: .jwk)
    public static let hs256Key = SymmetricKey(data: StaticKeys.hmac)

    // MARK: - Pre-signed compact tokens (verify must not pay for a sign)

    public static let signedES256 = try! String(JSONWebToken(payload: claims, using: es256PrivateKey))
    public static let signedRS256 = try! String(JSONWebToken(payload: claims, using: rs256PrivateKey))
    public static let signedEd25519 = try! String(JSONWebToken(payload: claims, using: ed25519PrivateKey))
    public static let signedHS256 = try! String(JSONWebToken(payload: claims, using: hs256Key))

    // MARK: - Serialization fixtures

    /// A fixed binary blob (256 bytes) for base64url round-trip measurement.
    public static let rawBlob = Data((0 ..< 256).map { UInt8($0 & 0xFF) })
    public static let base64urlString = rawBlob.urlBase64EncodedString()

    /// A pre-signed JWT object (not its string), reused by the compact-encode benchmark.
    public static let signedJWT = try! JSONWebToken(payload: claims, using: es256PrivateKey)

    // MARK: - JWE keys & fixtures

    public static let rsaOAEPPrivateKey = try! JSONWebRSAPrivateKey(importing: StaticKeys.rsa2048, format: .jwk)
    public static let ecdhPrivateKey = try! JSONWebECPrivateKey(importing: StaticKeys.ecP256, format: .jwk)

    /// Plaintext payload for the JWE benchmarks.
    public static let plaintext = Data("the quick brown fox jumps over the lazy dog".utf8)

    public static let encryptedRSAOAEP = try! String(JSONWebEncryption(
        content: plaintext,
        keyEncryptingAlgorithm: .rsaEncryptionOAEPSHA256,
        keyEncryptionKey: rsaOAEPPrivateKey.publicKey,
        contentEncryptionAlgorithm: .aesEncryptionGCM256
    ))
    public static let encryptedECDH = try! String(JSONWebEncryption(
        content: plaintext,
        keyEncryptingAlgorithm: .ecdhEphemeralStatic,
        keyEncryptionKey: ecdhPrivateKey.publicKey,
        contentEncryptionAlgorithm: .aesEncryptionGCM256
    ))

    // MARK: - SD-JWT fixtures

    /// Claims with custom, concealable fields (registered claims are "standard visible").
    public static let sdClaims: JSONWebTokenClaims = {
        var claims = Fixtures.claims
        claims.storage["email"] = "user@example.com"
        claims.storage["phone_number"] = "+1-555-0100"
        claims.storage["address"] = "1 Example Street"
        return claims
    }()

    /// Paths concealed in the SD-JWT benchmarks.
    public static let sdConcealedPaths: Set<JSONPointer> = ["/email", "/phone_number", "/address"]

    /// A pre-issued SD-JWT, reused by the present/disclose benchmark.
    public static let issuedSDJWT = try! JSONWebSelectiveDisclosureToken(
        claims: sdClaims,
        concealedPaths: sdConcealedPaths,
        decoyCount: 2,
        using: es256PrivateKey
    )
}
