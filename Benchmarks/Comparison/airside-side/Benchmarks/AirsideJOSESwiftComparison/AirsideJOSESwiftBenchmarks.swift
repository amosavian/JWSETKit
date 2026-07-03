import Benchmark
import Foundation
import JOSESwift
import Security

/// airsidemobile/JOSESwift side of the comparison — a DIFFERENT library from the beatt83 "jose-swift"
/// side (../joseswift-side/); the two share only the JOSE standards. JOSESwift is Apple-only: signing,
/// verifying and RSA key management run through the Security framework on `SecKey`, so this side does
/// NOT build on Linux and is absent from Linux comparison runs (../../README.md). Its whole API is
/// synchronous, so every measured closure is a plain (non-async) benchmark — like the JWSETKit and
/// jose-swift JWE rows, so the `time` figures are directly comparable.
///
/// JOSESwift has no JWT layer and no EdDSA / ML-DSA / SD-JWT, so those rows are JWSETKit-only. The
/// "JWT" signed here is the same realistic ~14-claim OIDC ID token JSON the other sides encode,
/// signed as a raw `Payload` so the sign/verify rows stay size-matched.
///
/// Key types differ by algorithm, and JOSESwift dictates which: its `Signer`/`Verifier` and RSA key
/// management are typed to `SecKey`, but its ECDH-ES key management is typed to its own JWK structs
/// `ECPublicKey`/`ECPrivateKey`. A `SecKey` is a toll-free-bridged CoreFoundation value, and
/// JOSESwift dispatches on key type with `type(of:) is …`, which never matches a native Swift type
/// for a CF value — so a `SecKey` is silently rejected there. Hence ECDH-ES is fed the JWK structs,
/// built from the same P-256 coordinates as the `SecKey`.

/// The ~14-claim OIDC ID token, matched with the JWSETKit / jwt-kit / jose-swift sides so all four
/// encode the same payload bytes. JOSESwift signs arbitrary data, so the claims are encoded once to
/// JSON `Data` and handed to `Payload` — snake_case keys match the other sides.
private struct BenchClaims: Encodable {
    let iss = "https://issuer.example.com"
    let sub = "248289761001"
    let aud = ["https://api.example.com"]
    let exp = 2_524_608_000 // far-future so a real verifier would not fail on expiry
    let nbf = 1_700_000_000
    let iat = 1_700_000_000
    let jti = "id-1f1a2b3c4d5e6f70"
    let name = "Jane Q. Public"
    let givenName = "Jane"
    let familyName = "Public"
    let preferredUsername = "j.public"
    let email = "jane.public@example.com"
    let emailVerified = true
    let roles = ["admin", "editor", "viewer"]

    enum CodingKeys: String, CodingKey {
        case iss, sub, aud, exp, nbf, iat, jti, name, email, roles
        case givenName = "given_name"
        case familyName = "family_name"
        case preferredUsername = "preferred_username"
        case emailVerified = "email_verified"
    }
}

/// The same static key material every comparison side uses. The EC P-256 key is carried both as its
/// X9.63 encoding (`0x04 || X || Y || d`, for the `SecKey` the signer needs) and as its raw JWK
/// coordinates (for the `ECPublicKey`/`ECPrivateKey` ECDH-ES needs); the RSA-2048 key as PKCS#1 DER.
/// All are the same JWK/PEM the other sides carry, so RSA/EC timings are reproducible and comparable.
/// Building the keys is one-time setup, done outside every measured loop.
private enum StaticKeys {
    static let ecP256X963 = Data(base64Encoded: "BJWqOobEVEnOCAjFfFEkpPvzuuHb87sDWPCblr0TgWQsCpzpgGswiMCysRsSHkrAJ3fWAf49bmNQsqNbGqKb9+vst8nZF/oUXiCsemm+zeEkvOSs4BWD+R2cqCDkwxiZqw==")!
    // JWK base64urlUInt coordinates of the same P-256 key (x, y, and the private scalar d).
    static let ecX = "lao6hsRUSc4ICMV8USSk-_O64dvzuwNY8JuWvROBZCw"
    static let ecY = "CpzpgGswiMCysRsSHkrAJ3fWAf49bmNQsqNbGqKb9-s"
    static let ecD = "7LfJ2Rf6FF4grHppvs3hJLzkrOAVg_kdnKgg5MMYmas"
    static let rsa2048PKCS1 = Data(base64Encoded: "MIIEpAIBAAKCAQEA4r1mthseMwt8oPj/ncVDO7ZrbJn21do6mxrirIY737boVgx3jJ7CuS+TEYV7KXWTk7ZKR4aoR/UBtC0o/n7mIxklWrgcv4TByCL3LPRPFKI8zsmwt0GZYcFG4Fjul68ER7XUBC8ga9rwO/Rtx+JcX9k7A9EER12BFvgv2oUL7cjpFLXHtKqCqOm69+LWDtgbH4E0lAxOGucQlhzv7fHE+4CaNQqN0ptD1SXtDPcgrWl+dOE8PAj0RBQkKIrVD0HJilp2SugqG0rqMN9iD1oyy4tVAEKNPlkyl55GR+TCkgOomYHW3K/06Rm9j1D2lJoGrE4gQVwFF7r8JEl40VnzXQIDAQABAoIBADxbuwnjMijYd/bKEhHHv1wX9YTVf5XyIAPGJm1S1oF5SWQOsYxnfuKZPYc+h0jEGeMKdb+Qox90o115YB5PXageO4lo1Y5OIt/KHw6CgsK1ZYaOvlIqTlBtiRaT1f/fAT6tsqDigrjzcVwkd0zsfzastz8O1xrAU2rv6p07Ka/EeZPdKwtJ44oMEVNxwriiuZRrr3R67rM0nAH/314tIQEnRmiSSHBY6+kiSyQ+wn7jXEYhjb8RMc6Ei1rq32wbClnKNFot5b907E+b2lwlYWCqZVXZWZGIFV+sC14uemZGJqRYFf81n0QGMZPg3BALpavQ77c6Rlyrd/HxlC+pEekCgYEA+39TpnObQUmIFar6ksl4XChhTYB+lnLZj1FqjP9R34b5JCw83fV8/KASi35Rd40YSreCNTFIBdkFiSaN5uXgdO6/zLRp2HnfRVgtlzGhTpViyam1bfHmf1Xiv5Q9YLuGoTI/sxt0coKrxSXdiSB+Ze9z8g5UNuthqVYSmG0bCmMCgYEA5sya0PtBzy5+cet0+4oVyV3wviJHyzq2njI9JtPLIzLYSoOVh61wCX0BAWB8EGftfayOuCVyPMBdnIMsWel7xB3t3HEZzdbpV/KbKnOa0SoKhYYOHSwzNTZEH902Yo98/HMLos+02usARkUzNzSplj01z5R3CgdYDW+pvdTGlz8CgYEAjRfGtyg+XqdBCF7uyrDqrFEfHZrL6d2u/n9/lnCa3xta5JdI4oEZyKSJIucQD1EB4tEG5I6sSFOTjnkpvPMUNKXIxrAkfYUJ5F5u3VbDl1GppVdnaLIATUnCtxYURROPmRmWsQXjE2cJtMXkfkzTfJ6U3qR5TIJLPPQD5K25MN8CgYAapuX53AntcuEHJrmLkpaReleinTLNNSqBeiu1oB+FIQn5ENjjohOeBOFo10t8WYQDTznr6ecXPN+Sg1NLzrqMGyisnCLusjKgBVQFwvPN050DbkeS9tey/WFAjLsLBqbYQDDHzFSGMz0E4FjZtysePlNIdUyJy+9PHeXsFfYY4QKBgQDCqhyEyBheG4hxDnyThuxrXJUviDVNX5Bkqy4IZMNmJ/mXxYfUeVIj+zwcUBK0v92Xyx6Aon4+Cw1gEiDfYU+1+QYAvQ7ce4MGp9Rhal0yZz7C1YC/bzg4H20EG1pjyph/9XVxCp+GeVjPnZLqbqEd4ddQ1js8AjJYBZ1/1IVwIg==")!
    static let hmac = Data("benchmark-hmac-secret-benchmark-hmac-secret-0123".utf8)
}

/// Builds a private `SecKey` from raw key bytes; the matching public key comes from
/// `SecKeyCopyPublicKey`. Force-unwrapped on purpose — a failure here is a fixture bug, not a
/// runtime condition, and it must surface before any measurement runs.
private func makePrivateSecKey(_ der: Data, keyType: CFString) -> SecKey {
    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateWithData(der as CFData, [
        kSecAttrKeyType: keyType,
        kSecAttrKeyClass: kSecAttrKeyClassPrivate,
    ] as CFDictionary, &error) else {
        fatalError("SecKeyCreateWithData failed: \(error!.takeRetainedValue())")
    }
    return key
}

let benchmarks: @Sendable () -> Void = {
    let payload = Payload(try! JSONEncoder().encode(BenchClaims()))

    let ecPrivate = makePrivateSecKey(StaticKeys.ecP256X963, keyType: kSecAttrKeyTypeECSECPrimeRandom)
    let ecPublic = SecKeyCopyPublicKey(ecPrivate)!
    let rsaPrivate = makePrivateSecKey(StaticKeys.rsa2048PKCS1, keyType: kSecAttrKeyTypeRSA)
    let rsaPublic = SecKeyCopyPublicKey(rsaPrivate)!

    // MARK: classical signatures — Signer/Verifier built once from the imported key (the real
    // key-reuse pattern), so only sign+serialize / parse+verify falls inside the measured loop.

    let esHeader = JWSHeader(algorithm: .ES256)
    let esSigner = Signer(signatureAlgorithm: .ES256, key: ecPrivate)!
    let esVerifier = Verifier(signatureAlgorithm: .ES256, key: ecPublic)!
    let esCompact = try! JWS(header: esHeader, payload: payload, signer: esSigner).compactSerializedString

    Benchmark("airside-sign-ES256") { b in
        for _ in b.scaledIterations {
            try blackHole(JWS(header: esHeader, payload: payload, signer: esSigner).compactSerializedString)
        }
    }
    Benchmark("airside-verify-ES256") { b in
        for _ in b.scaledIterations {
            try blackHole(JWS(compactSerialization: esCompact).validate(using: esVerifier).payload.data())
        }
    }

    let rsHeader = JWSHeader(algorithm: .RS256)
    let rsSigner = Signer(signatureAlgorithm: .RS256, key: rsaPrivate)!
    let rsVerifier = Verifier(signatureAlgorithm: .RS256, key: rsaPublic)!
    let rsCompact = try! JWS(header: rsHeader, payload: payload, signer: rsSigner).compactSerializedString

    Benchmark("airside-sign-RS256") { b in
        for _ in b.scaledIterations {
            try blackHole(JWS(header: rsHeader, payload: payload, signer: rsSigner).compactSerializedString)
        }
    }
    Benchmark("airside-verify-RS256") { b in
        for _ in b.scaledIterations {
            try blackHole(JWS(compactSerialization: rsCompact).validate(using: rsVerifier).payload.data())
        }
    }

    let hsHeader = JWSHeader(algorithm: .HS256)
    let hsSigner = Signer(signatureAlgorithm: .HS256, key: StaticKeys.hmac)!
    let hsVerifier = Verifier(signatureAlgorithm: .HS256, key: StaticKeys.hmac)!
    let hsCompact = try! JWS(header: hsHeader, payload: payload, signer: hsSigner).compactSerializedString

    Benchmark("airside-sign-HS256") { b in
        for _ in b.scaledIterations {
            try blackHole(JWS(header: hsHeader, payload: payload, signer: hsSigner).compactSerializedString)
        }
    }
    Benchmark("airside-verify-HS256") { b in
        for _ in b.scaledIterations {
            try blackHole(JWS(compactSerialization: hsCompact).validate(using: hsVerifier).payload.data())
        }
    }

    // MARK: JWE (synchronous on both encrypt and decrypt — no async bridge). Same two workloads and
    // static keys as the jose-swift side. RSA-OAEP-256 uses the RSA-2048 `SecKey`; ECDH-ES uses the
    // P-256 key as JOSESwift's `ECPublicKey`/`ECPrivateKey` JWK structs (see the note above). Both
    // wrap A256GCM content encryption.

    let plaintext = Payload(Data("the quick brown fox jumps over the lazy dog".utf8))

    let ecPublicJWK = ECPublicKey(crv: .P256, x: StaticKeys.ecX, y: StaticKeys.ecY)
    let ecPrivateJWK = try! ECPrivateKey(crv: ECCurveType.P256.rawValue, x: StaticKeys.ecX, y: StaticKeys.ecY, privateKey: StaticKeys.ecD)

    let ecdhHeader = JWEHeader(keyManagementAlgorithm: .ECDH_ES, contentEncryptionAlgorithm: .A256GCM)
    let ecdhEncrypter = Encrypter(keyManagementAlgorithm: .ECDH_ES, contentEncryptionAlgorithm: .A256GCM, encryptionKey: ecPublicJWK)!
    let ecdhDecrypter = Decrypter(keyManagementAlgorithm: .ECDH_ES, contentEncryptionAlgorithm: .A256GCM, decryptionKey: ecPrivateJWK)!
    let ecdhCompact = try! JWE(header: ecdhHeader, payload: plaintext, encrypter: ecdhEncrypter).compactSerializedString

    Benchmark("airside-jwe-encrypt-ECDHES-A256GCM") { b in
        for _ in b.scaledIterations {
            try blackHole(JWE(header: ecdhHeader, payload: plaintext, encrypter: ecdhEncrypter).compactSerializedString)
        }
    }
    Benchmark("airside-jwe-decrypt-ECDHES-A256GCM") { b in
        for _ in b.scaledIterations {
            try blackHole(JWE(compactSerialization: ecdhCompact).decrypt(using: ecdhDecrypter).data())
        }
    }

    let rsaJWEHeader = JWEHeader(keyManagementAlgorithm: .RSAOAEP256, contentEncryptionAlgorithm: .A256GCM)
    let rsaEncrypter = Encrypter(keyManagementAlgorithm: .RSAOAEP256, contentEncryptionAlgorithm: .A256GCM, encryptionKey: rsaPublic)!
    let rsaDecrypter = Decrypter(keyManagementAlgorithm: .RSAOAEP256, contentEncryptionAlgorithm: .A256GCM, decryptionKey: rsaPrivate)!
    let rsaCompact = try! JWE(header: rsaJWEHeader, payload: plaintext, encrypter: rsaEncrypter).compactSerializedString

    Benchmark("airside-jwe-encrypt-RSAOAEP-A256GCM") { b in
        for _ in b.scaledIterations {
            try blackHole(JWE(header: rsaJWEHeader, payload: plaintext, encrypter: rsaEncrypter).compactSerializedString)
        }
    }
    Benchmark("airside-jwe-decrypt-RSAOAEP-A256GCM") { b in
        for _ in b.scaledIterations {
            try blackHole(JWE(compactSerialization: rsaCompact).decrypt(using: rsaDecrypter).data())
        }
    }
}
