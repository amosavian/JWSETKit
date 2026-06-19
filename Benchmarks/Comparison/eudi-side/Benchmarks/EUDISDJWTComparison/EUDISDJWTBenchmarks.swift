import Benchmark
import eudi_lib_sdjwt_swift
import Foundation
import JSONWebKey
import JSONWebSignature

/// EUDI SD-JWT (eu-digital-identity-wallet/eudi-lib-sdjwt-swift) side of the comparison.
///
/// The workload is matched to the JWSETKit `sdjwt-*` rows: a realistic ~14-claim OIDC token with
/// **two** selectively-disclosable claims (`email`, `phone_number`) and **two** decoy digests,
/// signed with ES256 over the same static P-256 key the other sides use.
///
/// - `issue` is `async` (`SDJWTIssuer.issue`), so its row is a native `async` benchmark closure.
/// - `verify` is synchronous (`SDJWTVerifier.verifyIssuance`): parses the compact serialization,
///   verifies the issuer signature, and checks the disclosures — matched to JWSETKit's
///   parse + `verifySignature` + `validate`. Each side verifies a token **it issued itself**
///   (structurally equivalent, same key/claims/decoys), matching the existing sign/verify rows.
enum StaticKeys {
    /// Same static P-256 JWK material as the other comparison sides (see ../../../StaticKeys.md).
    static let ecP256PrivateJSON = Data(#"{"kty":"EC","x":"lao6hsRUSc4ICMV8USSk-_O64dvzuwNY8JuWvROBZCw","y":"CpzpgGswiMCysRsSHkrAJ3fWAf49bmNQsqNbGqKb9-s","crv":"P-256","d":"7LfJ2Rf6FF4grHppvs3hJLzkrOAVg_kdnKgg5MMYmas"}"#.utf8)
    /// Public half only (no `d`) — the issuer key a verifier would hold.
    static let ecP256PublicJSON = Data(#"{"kty":"EC","x":"lao6hsRUSc4ICMV8USSk-_O64dvzuwNY8JuWvROBZCw","y":"CpzpgGswiMCysRsSHkrAJ3fWAf49bmNQsqNbGqKb9-s","crv":"P-256"}"#.utf8)
}

/// The SD-JWT claim set, byte-for-byte matched with the JWSETKit `sdjwt-*` payload: the ~14-claim
/// OIDC token kept plain, with `email`/`phone_number` made selectively disclosable.
@SDJWTBuilder
func buildSDClaims() -> SdElement {
    PlainClaim("iss", "https://issuer.example.com")
    PlainClaim("sub", "248289761001")
    PlainClaim("aud", ["https://api.example.com"])
    PlainClaim("iat", 1_700_000_000)
    PlainClaim("exp", 2_524_608_000)
    PlainClaim("nbf", 1_700_000_000)
    PlainClaim("jti", "id-1f1a2b3c4d5e6f70")
    PlainClaim("name", "Jane Q. Public")
    PlainClaim("given_name", "Jane")
    PlainClaim("family_name", "Public")
    PlainClaim("preferred_username", "j.public")
    PlainClaim("email_verified", true)
    PlainClaim("roles", ["admin", "editor", "viewer"])
    FlatDisclosedClaim("email", "user@example.com")
    FlatDisclosedClaim("phone_number", "+1-555-0100")
}

/// Issues one SD-JWT via the EUDI library and returns its compact serialization. `SDJWTIssuer.issue`
/// is `async`; this synchronously bridges a single issuance for verify-row setup (outside any timed
/// loop), so the `benchmarks` registration closure can stay synchronous like the other sides.
func issueSerializedSDJWT(privateKey: JWK) -> String {
    let box = UncheckedBox(privateKey)
    let result = UncheckedResultBox()
    let semaphore = DispatchSemaphore(value: 0)
    Task.detached {
        do {
            let signed = try await SDJWTIssuer.issue(
                issuersPrivateKey: box.value,
                header: DefaultJWSHeaderImpl(algorithm: .ES256),
                decoyConfiguration: .perObject(minimum: 2, maximum: 2),
                buildSDJWT: buildSDClaims
            )
            result.value = .success(signed.serialisation)
        } catch {
            result.value = .failure(error)
        }
        semaphore.signal()
    }
    semaphore.wait()
    return try! result.value!.get()
}

let benchmarks: @Sendable () -> Void = {
    let privateKey = try! JSONDecoder().decode(JWK.self, from: StaticKeys.ecP256PrivateJSON)
    let publicKey = try! JSONDecoder().decode(JWK.self, from: StaticKeys.ecP256PublicJSON)
    let issued = issueSerializedSDJWT(privateKey: privateKey)

    Benchmark("eudi-sdjwt-issue") { b in
        let key = UncheckedBox(privateKey)
        for _ in b.scaledIterations {
            try await blackHole(SDJWTIssuer.issue(
                issuersPrivateKey: key.value,
                header: DefaultJWSHeaderImpl(algorithm: .ES256),
                decoyConfiguration: .perObject(minimum: 2, maximum: 2),
                buildSDJWT: buildSDClaims
            ))
        }
    }

    Benchmark("eudi-sdjwt-verify") { b in
        for _ in b.scaledIterations {
            let verified = try SDJWTVerifier(serialisedString: issued)
                .verifyIssuance { jws in
                    try SignatureVerifier(signedJWT: jws, publicKey: publicKey)
                }
            try blackHole(verified.get())
        }
    }
}

/// Wraps a non-`Sendable` value (jose-swift's `JWK`) so the `@Sendable` async closures can capture
/// it. Issuance/verification are read-only over the key — no mutation, no data race.
struct UncheckedBox<T>: @unchecked Sendable {
    let value: T
    init(_ value: T) {
        self.value = value
    }
}

/// Mutable cross-actor result slot for the one-time synchronous issuance bridge.
final class UncheckedResultBox: @unchecked Sendable {
    var value: Result<String, Error>?
}
