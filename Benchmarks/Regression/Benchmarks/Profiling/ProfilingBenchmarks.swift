import Benchmark
import BenchmarkSupport
import Crypto
import Foundation
import JWSETKit

/// Decomposition of the ES256 sign pipeline. `full-sign` is the same workload the comparison
/// runs; the `stage-*` rows isolate each step so the dominant cost (vs a minimal key-in-hand
/// signer like jwt-kit) is visible. `baseline-raw-cryptokit` is the theoretical floor: the
/// CryptoKit ECDSA call with zero JOSE machinery.
let benchmarks: @Sendable () -> Void = {
    let jwkKey = Fixtures.es256PrivateKey
    // Same key but WITH a `kid`: real JWKS-sourced keys carry a `kid`, and the keyset
    // optimization skips thumbprint computation in that case — so this row reflects the
    // common deployment path, while `stage-keyset-wrap-match` (keyless) is the worst case.
    var jwkKeyWithId = Fixtures.es256PrivateKey
    jwkKeyWithId.keyId = "bench-key-1"
    let claims = Fixtures.claims

    // Raw CryptoKit key + a representative signing input ("header.payload" bytes), built once.
    let rawKey = P256.Signing.PrivateKey()
    let header = JOSEHeader(algorithm: JSONWebSignatureAlgorithm.ecdsaSignatureP256SHA256, type: .jwt)
    let signingInput = Data("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJiZW5jaG1hcmstc3ViamVjdCJ9".utf8)

    // Full pipeline — identical to the comparison's jwsetkit-sign-ES256. Exercises the
    // single-key direct sign path (no JSONWebKeySet construction).
    Benchmark("full-sign") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(String(JSONWebToken(payload: claims, using: jwkKey)))
        }
    }

    // HS256 full sign/verify — crypto is ~6 µs, so these expose the shared JOSE pipeline
    // (keyset resolution, encode, assembly) that ES256/RS256 also pay but bury under crypto.
    let hsKey = Fixtures.hs256Key
    Benchmark("hs-full-sign") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(String(JSONWebToken(payload: claims, using: hsKey)))
        }
    }
    let hsSignedToken = try! String(JSONWebToken(payload: claims, using: hsKey))
    Benchmark("hs-full-verify") { benchmark in
        for _ in benchmark.scaledIterations {
            let jwt = try JSONWebToken(from: hsSignedToken)
            try jwt.verifySignature(using: hsKey)
            blackHole(jwt)
        }
    }

    // --- HS256 sign micro-decomposition (goal: close the gap to jwt-kit's ~17 µs). ---
    // hs-mb-build-token: construct+sign but skip the compact String() encode.
    Benchmark("hs-mb-build-token") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(JSONWebToken(payload: claims, using: hsKey))
        }
    }
    // hs-mb-string-encode: compact-encode a pre-built token.
    let hsPrebuilt = try! JSONWebToken(payload: claims, using: hsKey)
    Benchmark("hs-mb-string-encode") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(String(hsPrebuilt))
        }
    }
    // hs-mb-symmetrickey-storage: the cost of one SymmetricKey.storage materialization (the init
    // touches it several times via resolveAlgorithm + keyType check).
    Benchmark("hs-mb-symmetrickey-storage") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(hsKey.storage)
        }
    }
    // hs-mb-symmetrickey-keytype: SymmetricKey.keyType (goes through .storage).
    Benchmark("hs-mb-symmetrickey-keytype") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(hsKey.keyType)
        }
    }
    // hs-mb-resolve-algorithm-body: the AnyJSONWebKey(SymmetricKey) snapshot path — this is the
    // SLOW fallback (~7.7 µs / 17 mal from rebuilding SymmetricKey.storage). The real sign path does
    // NOT hit it: `resolveAlgorithm` takes the native `bitCount` fast path for SymmetricKey (a cast +
    // integer compare, no snapshot). Kept only to show what that fast path avoids.
    Benchmark("hs-mb-resolve-algorithm-body") { benchmark in
        for _ in benchmark.scaledIterations {
            let k = AnyJSONWebKey(hsKey)
            blackHole(k.algorithm)
            blackHole(k.keyType)
            blackHole(k.keyValue?.bitCount)
        }
    }
    // hs-mb-build-header: JOSEHeader(alg,typ) + updatedKeyId(.id) + wrap into signature header.
    Benchmark("hs-mb-build-header") { benchmark in
        for _ in benchmark.scaledIterations {
            let h = try JOSEHeader(algorithm: JSONWebSignatureAlgorithm.hmacSHA256, type: .jwt)
                .updatedKeyId(using: hsKey, strategy: .id)
            try blackHole(JSONWebSignatureHeader(protected: h, signature: .init()))
        }
    }
    // hs-mb-update-signature: keyset wrap + match + signedData + HMAC on a pre-built JWS.
    Benchmark("hs-mb-update-signature") { benchmark in
        for _ in benchmark.scaledIterations {
            var jws = hsPrebuilt
            try jws.updateSignature(using: hsKey)
            blackHole(jws)
        }
    }
    // Within update-signature: the raw HMAC via the JWK wrapper (key.signature path).
    let hsSigningInput = Data("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJiZW5jaG1hcmstc3ViamVjdCJ9".utf8)
    Benchmark("hs-mb-key-signature") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(hsKey.signature(hsSigningInput, using: .hmacSHA256))
        }
    }
    // Within update-signature: the keyset wrap the single-key sign path pays — the `[key]` array
    // alloc + construction into `.single`. (`firstMatch` is internal, measured via `sign-HS256`.)
    let hsHeaderValue = hsPrebuilt.signatures[0].protected.value
    Benchmark("hs-mb-keyset-match") { benchmark in
        for _ in benchmark.scaledIterations {
            let set = JSONWebKeySet(keys: [hsKey] as [any JSONWebKey])
            blackHole(set.matches(for: hsHeaderValue))
        }
    }
    Benchmark("hs-mb-keyset-construct-single") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(JSONWebKeySet(keys: [hsKey] as [any JSONWebKey]))
        }
    }
    // Typed-vs-dynamic claims encode — the one real asymmetry vs jwt-kit: it encodes a typed
    // struct (compiler-synthesized Codable, static dispatch); we encode dynamic storage.
    // Same two fields (sub/iss) both ways, same JSONEncoder.
    struct TypedClaims: Encodable { var sub: String; var iss: String }
    let typed = TypedClaims(sub: "benchmark-subject", iss: "https://issuer.example.com")
    let enc = JSONEncoder()
    var twoFieldClaims = JSONWebTokenClaims(storage: .init())
    twoFieldClaims.subject = "benchmark-subject"
    twoFieldClaims.issuer = "https://issuer.example.com"
    Benchmark("hs-mb-encode-typed-struct") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(enc.encode(typed))
        }
    }
    Benchmark("hs-mb-encode-dynamic-storage") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(enc.encode(twoFieldClaims))
        }
    }
    // Within update-signature: replicate signedData (header b64 + '.' + payload b64) and the
    // header dynamic-member reads it performs (storage.isEmpty, base64, critical).
    let hsProtected = hsPrebuilt.signatures[0].protected
    let hsPayload = hsPrebuilt.payload
    Benchmark("hs-mb-signed-data-replica") { benchmark in
        for _ in benchmark.scaledIterations {
            let protectedEncoded = !hsProtected.storage.isEmpty ? hsProtected.encoded.urlBase64EncodedData() : Data()
            let payloadEncoded = hsProtected.base64 == false && hsProtected.critical.contains("b64")
                ? hsPayload.encoded
                : hsPayload.encoded.urlBase64EncodedData()
            blackHole(protectedEncoded + Data(".".utf8) + payloadEncoded)
        }
    }
    // Just the three header dynamic-member reads signedData does (no base64).
    Benchmark("hs-mb-header-flag-reads") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(hsProtected.storage.isEmpty)
            blackHole(hsProtected.base64)
            blackHole(hsProtected.critical)
        }
    }

    // Single-key verify of a pre-signed token — exercises the single-key direct verify path.
    let signedToken = try! String(JSONWebToken(payload: claims, using: jwkKey))
    let publicKey = jwkKey.publicKey
    Benchmark("full-verify") { benchmark in
        for _ in benchmark.scaledIterations {
            let jwt = try JSONWebToken(from: signedToken)
            try jwt.verifySignature(using: publicKey)
            blackHole(jwt)
        }
    }

    // Glue decomposition of full-sign = stage-build-token + stage-string-encode.
    // stage-build-token: construct + sign the JWT but do NOT compact-encode to String.
    Benchmark("stage-build-token") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(JSONWebToken(payload: claims, using: jwkKey))
        }
    }
    // stage-string-encode: compact-encode a pre-built signed token to String (base64 + join).
    let prebuiltToken = try! JSONWebToken(payload: claims, using: jwkKey)
    Benchmark("stage-string-encode") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(String(prebuiltToken))
        }
    }
    // stage-verify-parse-only: parse the compact token to a JWT without verifying (decode cost).
    Benchmark("stage-verify-parse-only") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(JSONWebToken(from: signedToken))
        }
    }

    // Signing with a native CryptoKit key (no JWK storage to materialize from) — the
    // apples-to-apples path vs jwt-kit, which also holds a native key.
    Benchmark("full-sign-native") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(String(JSONWebToken(payload: claims, using: rawKey)))
        }
    }

    // End-to-end: import a JWK key from storage, then sign once. Counts the materialization
    // jwt-kit pays at `keys.add(...)`. The per-iteration `JSONWebECPrivateKey(storage:)` is a
    // fresh key, so the cache is cold every time — the worst case.
    let keyStorage = jwkKey.storage
    Benchmark("e2e-import-and-sign") { benchmark in
        for _ in benchmark.scaledIterations {
            let key = try JSONWebECPrivateKey(storage: keyStorage)
            try blackHole(String(JSONWebToken(payload: claims, using: key)))
        }
    }

    // Stage 1: encode claims through the generic JSONWebValueStorage → JSON (Codable) layer.
    Benchmark("stage-claims-encode") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(ProtectedJSONWebContainer(value: claims).encoded)
        }
    }
    // Apples-to-apples: the SAME 5-field claims encoded raw (JSONEncoder.encode) vs through the
    // ProtectedJSONWebContainer wrapper. The delta is the container's own per-construct overhead
    // (the `value` setter's `storage == .init()` empty-check + extra encode bookkeeping).
    let encRaw: JSONEncoder = {
        let e = JSONEncoder()
        e.outputFormatting = [.withoutEscapingSlashes]
        return e
    }()
    Benchmark("stage-claims-encode-raw") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(encRaw.encode(claims))
        }
    }
    // Same raw encode but allocating a FRESH JSONEncoder each iteration — mirrors what
    // `JSONEncoder.encoder` (a computed property) does inside `ProtectedJSONWebContainer.init(value:)`.
    Benchmark("stage-claims-encode-raw-freshencoder") { benchmark in
        for _ in benchmark.scaledIterations {
            let e = JSONEncoder()
            e.outputFormatting = [.withoutEscapingSlashes]
            try blackHole(e.encode(claims))
        }
    }

    // Nested-payload encode/decode: a claim set with arrays and nested objects (realistic for
    // `cnf`, `x5c`, or rich custom claims) — exercises AnyCodable's array/dict container path,
    // unlike the shallow `claims` above whose only collection is a 1-element `aud`.
    var nestedClaims = Fixtures.claims
    nestedClaims.storage["roles"] = ["admin", "editor", "viewer", "auditor"]
    nestedClaims.storage["groups"] = ["a", "b", "c", "d", "e", "f"]
    nestedClaims.storage["cnf"] = ["jwk": ["kty": "EC", "crv": "P-256", "x": "abc", "y": "def"]]
    nestedClaims.storage["address"] = ["street": "1 Example St", "city": "Town", "zip": "00000"]
    let nestedEncoded = try! ProtectedJSONWebContainer(value: nestedClaims).encoded
    Benchmark("stage-nested-encode") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(ProtectedJSONWebContainer(value: nestedClaims).encoded)
        }
    }
    Benchmark("stage-nested-decode") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(ProtectedJSONWebContainer<JSONWebTokenClaims>(encoded: nestedEncoded))
        }
    }

    // --- Parse decomposition: split the verify-parse into its sub-costs. ---
    // The three compact sections as raw base64url bytes (pre-split, measured once).
    let tokenSections = signedToken.components(separatedBy: ".")
    let protectedB64 = tokenSections[0]
    let payloadB64 = tokenSections[1]
    // stage-parse-base64: just the 3 base64url section decodes (no JSON decode).
    Benchmark("stage-parse-base64") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(Data(urlBase64Encoded: protectedB64, options: []))
            blackHole(Data(urlBase64Encoded: payloadB64, options: []))
        }
    }
    // stage-parse-header-decode: the protected-header JSON decode (ProtectedJSONWebContainer).
    let protectedData = Data(urlBase64Encoded: protectedB64, options: [])!
    Benchmark("stage-parse-header-decode") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(ProtectedJSONWebContainer<JOSEHeader>(encoded: protectedData))
        }
    }
    // stage-parse-payload-decode: the claims payload JSON decode.
    let payloadData = Data(urlBase64Encoded: payloadB64, options: [])!
    Benchmark("stage-parse-payload-decode") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(ProtectedJSONWebContainer<JSONWebTokenClaims>(encoded: payloadData))
        }
    }

    // --- Why is the dynamic payload decode the gap vs jwt-kit? AnyCodable.init(from:) probes types
    // with sequential `try?` decodes; every failed probe throws+catches a DecodingError. Decode the
    // SAME 14-claim payload as a statically-typed struct (jwt-kit's approach, zero failed probes)
    // and via JSONSerialization (native type detection, no Codable probing) to size that cost. ---
    struct TypedOIDCPayload: Decodable {
        var sub, iss, jti, name, given_name, family_name, preferred_username, email: String
        var aud: [String]
        var exp, iat, nbf: Double
        var email_verified: Bool
        var roles: [String]

        enum CodingKeys: String, CodingKey {
            case sub, iss, jti, name, given_name, family_name, preferred_username, email
            case aud, exp, iat, nbf, email_verified, roles
        }

        init(from decoder: any Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            self.sub = try c.decode(String.self, forKey: .sub)
            self.iss = try c.decode(String.self, forKey: .iss)
            self.jti = try c.decode(String.self, forKey: .jti)
            self.name = try c.decode(String.self, forKey: .name)
            self.given_name = try c.decode(String.self, forKey: .given_name)
            self.family_name = try c.decode(String.self, forKey: .family_name)
            self.preferred_username = try c.decode(String.self, forKey: .preferred_username)
            self.email = try c.decode(String.self, forKey: .email)
            // `aud` may be a single string or an array (RFC 7519 §4.1.3).
            if let single = try? c.decode(String.self, forKey: .aud) {
                self.aud = [single]
            } else {
                self.aud = try c.decode([String].self, forKey: .aud)
            }
            self.exp = try c.decode(Double.self, forKey: .exp)
            self.iat = try c.decode(Double.self, forKey: .iat)
            self.nbf = try c.decode(Double.self, forKey: .nbf)
            self.email_verified = try c.decode(Bool.self, forKey: .email_verified)
            self.roles = try c.decode([String].self, forKey: .roles)
        }
    }
    Benchmark("decode-payload-typed") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(JSONDecoder().decode(TypedOIDCPayload.self, from: payloadData))
        }
    }
    Benchmark("decode-payload-jsonserialization") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(JSONSerialization.jsonObject(with: payloadData, options: []))
        }
    }

    // Isolate the raw RSA-2048 private-key sign (SecKey backend on Darwin) to verify that
    // `sign-RS256`'s cost is the crypto, not JOSE overhead, and to compare backends honestly.
    let rsaSignKey = Fixtures.rs256PrivateKey
    let rsaSigningInput = Data("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJiZW5jaG1hcmstc3ViamVjdCJ9".utf8)
    Benchmark("stage-rsa2048-sign-raw") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(rsaSignKey.signature(rsaSigningInput, using: .rsaSignaturePKCS1v15SHA256))
        }
    }

    // Stage 2: encode the protected header through the same storage layer.
    Benchmark("stage-header-encode") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(ProtectedJSONWebContainer(value: header).encoded)
        }
    }

    // --- KeySet resolution scenarios (single key, kid, thumbprint, multi-key) ---
    // The sets are built ONCE (outside the closure) — we measure resolution, not construction.
    let singleKeylessSet = JSONWebKeySet(keys: [jwkKey] as [any JSONWebKey])
    let kidSet = JSONWebKeySet(keys: [jwkKeyWithId] as [any JSONWebKey])
    let kidHeader = { var h = header; h.keyId = "bench-key-1"; return h }()
    let jwkThumbprint = Data(try! jwkKey.thumbprint(format: .jwk, using: SHA256.self))
    let multiKeys: [any JSONWebKey] = (0 ..< 8).map { i in
        var k = try! JSONWebECPrivateKey(algorithm: JSONWebSignatureAlgorithm.ecdsaSignatureP256SHA256)
        k.keyId = "k\(i)"
        return k
    }
    let multiKeySet = JSONWebKeySet(keys: multiKeys)

    // Resolution: single keyless key, kid lookup, multi-key scan.
    Benchmark("keyset-single-matches") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(singleKeylessSet.matches(for: header))
        }
    }
    Benchmark("keyset-kid-matches") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(kidSet.matches(for: kidHeader))
        }
    }
    Benchmark("keyset-multi-matches") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(multiKeySet.matches(for: header))
        }
    }
    // Multi-key set + header carrying a matching `kid` — the realistic JWKS verify path. The kid-first
    // short-circuit returns the named key without building the algorithm-filtered candidate set.
    let multiKidHeader = { var h = header; h.keyId = "k3"; return h }()
    Benchmark("keyset-multi-kid-matches") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(multiKeySet.matches(for: multiKidHeader))
        }
    }
    // Thumbprint lookup — keyless key stays O(1) / 0-malloc.
    Benchmark("keyset-thumbprint-lookup") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(singleKeylessSet[thumbprint: jwkThumbprint])
        }
    }
    // Construction: a `kid` key no longer computes a thumbprint up front (lazy); a keyless key
    // still does (it is keyed by thumbprint). This is the cost paid per `updateSignature`/
    // `verifySignature(using: [key])` call when wrapping the key into a set.
    Benchmark("keyset-construct-keyless") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(JSONWebKeySet(keys: [jwkKey] as [any JSONWebKey]))
        }
    }
    Benchmark("keyset-construct-kid") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(JSONWebKeySet(keys: [jwkKeyWithId] as [any JSONWebKey]))
        }
    }

    // EC sign through the JWK wrapper — CACHED (materialized key reused). Compare to the
    // uncached RSA/MLDSA rows below to see what a per-type cache would remove.
    Benchmark("stage-jwk-ecdsa") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(jwkKey.signature(signingInput, using: .ecdsaSignatureP256SHA256))
        }
    }
    // RSA sign — UNCACHED: re-materializes the RSA key from JWK storage every call.
    let rsaKey = Fixtures.rs256PrivateKey
    Benchmark("stage-jwk-rsa") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(rsaKey.signature(signingInput, using: .rsaSignaturePKCS1v15SHA256))
        }
    }
    // HMAC sign — wraps raw bytes into a SymmetricKey (no expensive parse). Baseline for "cheap".
    let hmacKey = Fixtures.hs256Key
    Benchmark("stage-jwk-hmac") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(hmacKey.signature(signingInput, using: .hmacSHA256))
        }
    }
    // ML-DSA sign — UNCACHED: re-materializes the ML-DSA key every call (macOS 26+).
    if #available(macOS 26, iOS 26, tvOS 26, watchOS 26, visionOS 26, *) {
        let mldsaKey = try! JSONWebMLDSAPrivateKey(algorithm: JSONWebSignatureAlgorithm.mldsa65Signature)
        Benchmark("stage-jwk-mldsa") { benchmark in
            for _ in benchmark.scaledIterations {
                try blackHole(mldsaKey.signature(signingInput, using: .mldsa65Signature))
            }
        }
    }

    // Floor: raw CryptoKit ECDSA, no JOSE machinery at all.
    Benchmark("baseline-raw-cryptokit") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(rawKey.signature(for: SHA256.hash(data: signingInput)))
        }
    }

    // Floor: raw CryptoKit ECDSA *verify* — to see how much of full-verify is irreducible crypto.
    let rawSig = try! rawKey.signature(for: SHA256.hash(data: signingInput))
    let rawPub = rawKey.publicKey
    Benchmark("baseline-raw-cryptokit-verify") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(rawPub.isValidSignature(rawSig, for: SHA256.hash(data: signingInput)))
        }
    }

    // --- Verify decomposition: isolate the public-key verify (materialize + CryptoKit verify)
    // from parse and keyset wrap. `verify-jwk-ecdsa` is the EC public-key path that re-materializes
    // a P256.Signing.PublicKey from JWK storage every call (no cache, unlike the private signing key).
    let ecPublicKey = jwkKey.publicKey
    let ecSig = try! jwkKey.signature(signingInput, using: .ecdsaSignatureP256SHA256)
    Benchmark("verify-jwk-ecdsa") { benchmark in
        for _ in benchmark.scaledIterations {
            try ecPublicKey.verifySignature(ecSig, for: signingInput, using: .ecdsaSignatureP256SHA256)
        }
    }
    let rsaPublicKey = rsaKey.publicKey
    let rsaSig = try! rsaKey.signature(signingInput, using: .rsaSignaturePKCS1v15SHA256)
    Benchmark("verify-jwk-rsa") { benchmark in
        for _ in benchmark.scaledIterations {
            try rsaPublicKey.verifySignature(rsaSig, for: signingInput, using: .rsaSignaturePKCS1v15SHA256)
        }
    }

    // Held-key repeated verify vs fresh-key-each-time: the public-key materialization cache only
    // pays off when the SAME public-key value is reused (the JWKS-reuse case). `-cold` rebuilds the
    // public key from storage every iteration (cache always cold) — the gap is what the cache saves.
    let ecPubStorage = ecPublicKey.storage
    Benchmark("verify-ec-cold-publickey") { benchmark in
        for _ in benchmark.scaledIterations {
            let pub = try JSONWebECPublicKey(storage: ecPubStorage)
            try pub.verifySignature(ecSig, for: signingInput, using: .ecdsaSignatureP256SHA256)
        }
    }

    // --- JWE decomposition (ECDH-ES + RSA-OAEP, both A256GCM) ---
    // Full encrypt/decrypt mirror the comparison rows. `jwe-mb-parse-*` isolate the compact decode
    // (the same JSON-wrap path JWS used to pay), so the crypto vs. parse vs. header-merge split is
    // visible. ECDH-ES decrypt also pays ECDH agreement + Concat-KDF on top of the AEAD open.
    let rsaJWEKey = Fixtures.rsaOAEPPrivateKey
    let ecdhJWEKey = Fixtures.ecdhPrivateKey
    let encryptedRSA = Fixtures.encryptedRSAOAEP
    let encryptedECDH = Fixtures.encryptedECDH

    Benchmark("jwe-full-encrypt-rsaoaep") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(String(JSONWebEncryption(
                content: Fixtures.plaintext,
                keyEncryptingAlgorithm: .rsaEncryptionOAEPSHA256,
                keyEncryptionKey: rsaJWEKey.publicKey,
                contentEncryptionAlgorithm: .aesEncryptionGCM256
            )))
        }
    }
    // Held recipient key (warm `encryptingKeyCache`) — the realistic "encrypt many to one
    // recipient" path. The delta vs `jwe-full-encrypt-rsaoaep` (fresh `.publicKey` per call) is the
    // per-call SecKey re-materialization the cache removes.
    let rsaJWEPublic = rsaJWEKey.publicKey
    Benchmark("jwe-encrypt-rsaoaep-heldkey") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(String(JSONWebEncryption(
                content: Fixtures.plaintext,
                keyEncryptingAlgorithm: .rsaEncryptionOAEPSHA256,
                keyEncryptionKey: rsaJWEPublic,
                contentEncryptionAlgorithm: .aesEncryptionGCM256
            )))
        }
    }
    // Raw RSA-OAEP-256 wrap of a 32-byte CEK with the held (cached) public key — the irreducible
    // crypto floor. The delta vs `jwe-encrypt-rsaoaep-heldkey` is the JWE assembly (header encode,
    // CEK gen, AES-GCM seal, compact serialize).
    let cek32 = Data(repeating: 0x2B, count: 32)
    Benchmark("jwe-mb-rsa-wrap-heldkey") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(rsaJWEPublic.encrypt(cek32, using: JSONWebKeyEncryptionAlgorithm.rsaEncryptionOAEPSHA256))
        }
    }
    // JWE assembly sub-stages (no RSA): protected-header encode, CEK gen, AES-GCM seal.
    var jweHeader = JOSEHeader()
    jweHeader.algorithm = JSONWebKeyEncryptionAlgorithm.rsaEncryptionOAEPSHA256
    jweHeader.encryptionAlgorithm = .aesEncryptionGCM256
    jweHeader.type = .jwe
    Benchmark("jwe-mb-protected-encode") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(ProtectedJSONWebContainer(value: jweHeader).encoded)
        }
    }
    Benchmark("jwe-mb-cek-gen") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(JSONWebContentEncryptionAlgorithm.aesEncryptionGCM256.generateRandomKey())
        }
    }
    let cekKey = try! JSONWebContentEncryptionAlgorithm.aesEncryptionGCM256.generateRandomKey()
    let aadData = Data("eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIiwidHlwIjoiSldFIn0".utf8)
    Benchmark("jwe-mb-gcm-seal") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(cekKey.seal(Fixtures.plaintext, iv: Data?.none, authenticating: aadData, using: JSONWebContentEncryptionAlgorithm.aesEncryptionGCM256))
        }
    }
    // Full encrypt with `.direct` (CEK provided, no RSA wrap, no CEK gen) — isolates the pure JWE
    // assembly: header build+encode, seal, compact serialize, and all glue.
    Benchmark("jwe-mb-encrypt-direct") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(String(JSONWebEncryption(
                content: Fixtures.plaintext,
                keyEncryptingAlgorithm: .direct,
                keyEncryptionKey: nil,
                contentEncryptionAlgorithm: .aesEncryptionGCM256,
                contentEncryptionKey: cekKey
            )))
        }
    }
    let prebuiltDirectJWE = try! JSONWebEncryption(
        content: Fixtures.plaintext,
        keyEncryptingAlgorithm: .direct,
        keyEncryptionKey: nil,
        contentEncryptionAlgorithm: .aesEncryptionGCM256,
        contentEncryptionKey: cekKey
    )
    Benchmark("jwe-mb-compact-only") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(String(prebuiltDirectJWE))
        }
    }
    // The dynamic header reads the core init performs to dispatch (alg → enum, enc, zip).
    Benchmark("jwe-mb-header-reads") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(jweHeader.encryptionAlgorithm)
            blackHole(jweHeader.compressionAlgorithm)
        }
    }
    Benchmark("jwe-full-decrypt-rsaoaep") { benchmark in
        for _ in benchmark.scaledIterations {
            let jwe = try JSONWebEncryption(from: encryptedRSA)
            try blackHole(jwe.decrypt(using: rsaJWEKey))
        }
    }
    Benchmark("jwe-full-decrypt-ecdhes") { benchmark in
        for _ in benchmark.scaledIterations {
            let jwe = try JSONWebEncryption(from: encryptedECDH)
            try blackHole(jwe.decrypt(using: ecdhJWEKey))
        }
    }

    // Parse only — the compact JWE decode (JSON-wrap + JSONDecoder), no crypto.
    Benchmark("jwe-mb-parse-rsaoaep") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(JSONWebEncryption(from: encryptedRSA))
        }
    }
    Benchmark("jwe-mb-parse-ecdhes") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(JSONWebEncryption(from: encryptedECDH))
        }
    }

    // Decrypt of a pre-parsed JWE — isolates the crypto/header-merge cost from the parse.
    let parsedRSAJWE = try! JSONWebEncryption(from: encryptedRSA)
    let parsedECDHJWE = try! JSONWebEncryption(from: encryptedECDH)
    Benchmark("jwe-mb-decrypt-only-rsaoaep") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(parsedRSAJWE.decrypt(using: rsaJWEKey))
        }
    }
    Benchmark("jwe-mb-decrypt-only-ecdhes") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(parsedECDHJWE.decrypt(using: ecdhJWEKey))
        }
    }

    // --- ECDH-ES cost split: is decrypt-only (~330µs) the P256 primitive or our JWK→CryptoKit
    // re-materialization? `ecdh-raw-agreement` uses held native CryptoKit keys (the floor);
    // `ecdh-jwk-agreement` is our JWK path (re-materializes both keys from storage each call). ---
    let rawAgreePriv = P256.KeyAgreement.PrivateKey()
    let rawAgreePub = P256.KeyAgreement.PrivateKey().publicKey
    Benchmark("ecdh-raw-agreement") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(rawAgreePriv.sharedSecretFromKeyAgreement(with: rawAgreePub))
        }
    }
    let ecdhJWKPriv = Fixtures.ecdhPrivateKey
    let ecdhJWKPub = Fixtures.ecdhPrivateKey.publicKey
    Benchmark("ecdh-jwk-agreement") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(ecdhJWKPriv.sharedSecretFromKeyAgreement(with: ecdhJWKPub))
        }
    }
    // Just the key materialization from JWK storage (no agreement).
    let ecdhPrivStorage = ecdhJWKPriv.storage
    Benchmark("ecdh-jwk-materialize-priv") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(JSONWebECPrivateKey(storage: ecdhPrivStorage))
        }
    }

    // --- ECDH-ES ENCRYPT decomposition: the ephemeral private is fresh per message (uncacheable),
    // so encrypt pays a scalar-mult for keygen AND another when the agreement re-imports the
    // exported scalar (CryptoKit re-derives the public key). These rows size that double cost. ---
    // Raw CryptoKit KeyAgreement keygen — one scalar mult (the pubkey derivation), the floor.
    Benchmark("ecdh-raw-keyagreement-keygen") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(P256.KeyAgreement.PrivateKey())
        }
    }
    // Our ephemeral keygen (Signing key + JWK export) — what ecdhEsEncryptedKey generates per call.
    Benchmark("ecdh-ephemeral-keygen") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(JSONWebECPrivateKey(curve: .p256))
        }
    }
    // Cold-private agreement: fresh ephemeral each iteration (cache cold) × held public — mirrors
    // encrypt's agreement. Delta vs `ecdh-jwk-agreement` (warm private) is the re-import scalar mult.
    Benchmark("ecdh-coldpriv-agreement") { benchmark in
        for _ in benchmark.scaledIterations {
            let ephemeral = try JSONWebECPrivateKey(curve: .p256)
            try blackHole(ephemeral.sharedSecretFromKeyAgreement(with: ecdhJWKPub))
        }
    }

    // MARK: SD-JWT issue decomposition — attribute the ~297-malloc `sdjwt-issue` cost.

    // Full issue (same workload as Advanced `sdjwt-issue`): conceal 3 paths + 2 decoys + ES256 sign.
    Benchmark("sdjwt-full-issue") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(JSONWebSelectiveDisclosureToken(
                claims: Fixtures.sdClaims, concealedPaths: Fixtures.sdConcealedPaths,
                decoyCount: 2, using: Fixtures.es256PrivateKey
            ))
        }
    }
    // One disclosure construction (value JSON-encode + salt gen) — ×3 in the issue.
    Benchmark("sdjwt-mb-disclosure-create") { benchmark in
        for _ in benchmark.scaledIterations {
            try blackHole(JSONWebSelectiveDisclosure("email", value: "user@example.com"))
        }
    }
    // `.encoded` rebuild (fresh JSONEncoder + salt/key sub-encodes + Data concat) on an immutable
    // disclosure — recomputed by every `digest` call (append, list-init, validate, present).
    let sampleDisclosure = try! JSONWebSelectiveDisclosure("email", value: "user@example.com")
    Benchmark("sdjwt-mb-disclosure-encoded") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(sampleDisclosure.encoded)
        }
    }
    // `.digest` = SHA256 over `.encoded` — the per-disclosure hot call.
    Benchmark("sdjwt-mb-disclosure-digest") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(sampleDisclosure.digest(using: SHA256.self))
        }
    }
}
