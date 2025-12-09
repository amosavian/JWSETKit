//
//  SD-JWT.swift
//
//
//  Created by Amir Abbas Mousavian on 9/21/25.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto

/// SD-JWT represents a Selective Disclosure JSON Web Token combining a JWT with selective disclosures and optional key binding.
///
/// An SD-JWT consists of three main components:
/// - An issuer-signed JWT containing claims and disclosure digests
/// - A set of selective disclosures for privacy-preserving presentation
/// - An optional key binding JWT to bind the token to a holder's key
///
/// Example usage:
/// ```swift
/// let sdJWT = JSONWebSelectiveDisclosureToken(
///     jwt: issuerJWT,
///     disclosures: [disclosure1, disclosure2],
///     keyBinding: holderKeyBindingJWT
/// )
/// ```
public struct JSONWebSelectiveDisclosureToken: Hashable, Sendable {
    /// Protected payload containing the SD-JWT claims with selective disclosure metadata (`_sd`, `_sd_alg`).
    public var payload: ProtectedJSONWebContainer<JSONWebTokenClaims>
    
    /// Signature headers for the issuer JWT.
    public var signatures: [JSONWebSignatureHeader]
    
    /// Array of selective disclosures that can be revealed to verifiers.
    public var disclosures: [JSONWebSelectiveDisclosure]
    
    /// Optional key binding JWT for holder binding to prevent token replay.
    public var keyBinding: JSONWebToken?
    
    /// The issuer JWT containing the SD-JWT payload with selective disclosure metadata.
    public var jwt: JSONWebToken {
        get { JSONWebToken(signatures: signatures, payload: payload) }
        set {
            payload = newValue.payload
            signatures = newValue.signatures
        }
    }
    
    /// The disclosure list with hash algorithm extracted from the JWT payload.
    ///
    /// This computed property creates a `JSONWebSelectiveDisclosureList` using the hash algorithm
    /// specified in the JWT's `_sd_alg` field (defaults to SHA-256 if not present).
    ///
    /// - Throws: `CryptoKitError` if disclosure hashing fails.
    public var disclosureList: JSONWebSelectiveDisclosureList {
        get throws {
            let hashFunction = payload.disclosureHashAlgorithm?.hashFunction ?? SHA256.self
            return try JSONWebSelectiveDisclosureList(disclosures, hashFunction: hashFunction)
        }
    }
    
    /// Reconstructs the full payload by merging disclosures with the JWT payload.
    ///
    /// This property combines the base JWT payload with all disclosed claims,
    /// producing a complete claims object without selective disclosure markers.
    ///
    /// - Throws: Errors if disclosure list cannot be constructed or merged.
    public var disclosedPayload: JSONWebTokenClaims {
        get throws {
            try payload.value.disclosed(with: disclosureList)
        }
    }
    
    /// Returns all disclosure hashes from the payload, including nested objects.
    ///
    /// This property recursively traverses the entire payload structure to find all `_sd` arrays,
    /// as nested objects can have their own selective disclosures per RFC 9901.
    ///
    /// - Returns: A set of all disclosure hashes found at all nesting levels
    public var allDisclosureHashes: [Data] {
        payload.value.storage.collectAllDisclosureHashes()
    }
    
    /// Creates a new SD-JWT with the given components.
    ///
    /// - Parameters:
    ///   - jwt: The issuer JWT containing SD-JWT payload
    ///   - disclosures: Array of selective disclosures
    ///   - keyBinding: Optional key binding JWT
    public init(jwt: JSONWebToken, disclosures: [JSONWebSelectiveDisclosure], keyBinding: JSONWebToken? = nil) {
        self.payload = jwt.payload
        self.signatures = jwt.signatures
        self.disclosures = disclosures
        self.keyBinding = keyBinding
    }
    
    /// Validates the SD-JWT structure and components.
    ///
    /// Performs comprehensive validation including:
    /// - JWT signature and structure validation
    /// - Key binding JWT validation (if present)
    /// - Key binding requirement check (if `cnf` claim is present and `requireKeyBinding` is true)
    /// - Duplicate digest detection (RFC 9901 Section 7.1.9)
    /// - Orphan disclosure detection (RFC 9901 Section 7.1.10)
    ///
    /// - Parameter requireKeyBinding: If `true` (default), validates that key binding is present
    ///   when the `cnf` claim exists. Set to `false` for issuance-time validation where
    ///   key binding hasn't been added yet.
    ///
    /// - Throws: `JSONWebValidationError` if validation fails
    public func validate(requireKeyBinding: Bool = true) throws {
        try jwt.validate()
        try keyBinding?.validate()
        if requireKeyBinding, payload.confirmation?.key != nil {
            try verifyKeyBinding()
        }
        let allDisclosureHashes = allDisclosureHashes
        guard allDisclosureHashes.count == Set(allDisclosureHashes).count else {
            throw JSONWebValidationError.duplicateDisclosureDigest
        }
        guard try Set(disclosureList.hashes).isSubset(of: allDisclosureHashes) else {
            throw JSONWebValidationError.orphanDisclosure
        }
    }
}

// MARK: - Issuance

extension JSONWebSelectiveDisclosureToken {
    /// Creates an SD-JWT with claims concealed according to the disclosure policy.
    ///
    /// This initializer creates a signed SD-JWT where claims are selectively disclosable
    /// based on the provided policy. The resulting token contains:
    /// - A signed JWT with `_sd` array containing disclosure hashes
    /// - The `_sd_alg` claim indicating the hash algorithm used
    /// - An array of disclosures that can be selectively revealed
    ///
    /// Example:
    /// ```swift
    /// let sdJWT = try JSONWebSelectiveDisclosureToken(
    ///     claims: claims,
    ///     policy: .default,  // Conceals all non-standard claims
    ///     using: issuerKey
    /// )
    /// ```
    ///
    /// - Parameters:
    ///   - claims: The full JWT claims to include
    ///   - policy: Defines which claims should be selectively disclosable (default: `.default`)
    ///   - header: Custom JOSE header (default: empty, `typ` will be set to `sd+jwt`)
    ///   - algorithm: Signature algorithm (if nil, inferred from key)
    ///   - hashAlgorithm: Hash algorithm for disclosure digests (default: SHA-256)
    ///   - decoyCount: Number of decoy digests to add for privacy (default: random 0-4)
    ///   - signingKey: The issuer's signing key
    /// - Throws: `JSONWebKeyError` if key operations fail, `CryptoKitError` for cryptographic failures
    public init<SK: JSONWebSigningKey>(
        claims: JSONWebTokenClaims,
        policy: DisclosurePolicy = .default,
        header: JOSEHeader = .init(),
        algorithm: JSONWebSignatureAlgorithm? = nil,
        hashAlgorithm: any NamedHashFunction.Type = SHA256.self,
        decoyCount: Int = .random(in: 0 ... 4),
        using signingKey: SK
    ) throws {
        var finalClaims = claims
        let disclosureList = try finalClaims.conceal(policy: policy, using: hashAlgorithm)
        finalClaims.disclosureHashAlgorithm = hashAlgorithm.identifier
        try Self.addDecoys(count: decoyCount, to: &finalClaims, using: hashAlgorithm)
        
        var header = header
        if header.type == nil {
            header.type = .sdJWT
        }
        if header.algorithm == nil {
            guard let proposedAlgorithm = signingKey.resolveAlgorithm(algorithm) else {
                throw JSONWebKeyError.unknownAlgorithm
            }
            header.algorithm = proposedAlgorithm
        }
        try header.updateKeyId(using: signingKey, strategy: .id)
        
        var jwt = try JSONWebToken(
            signatures: [.init(protected: header, signature: .init())],
            payload: ProtectedJSONWebContainer(value: finalClaims)
        )
        try jwt.updateSignature(using: signingKey)
        
        self.init(jwt: jwt, disclosures: disclosureList.disclosures, keyBinding: nil)
    }
    
    /// Creates an SD-JWT with specific paths concealed.
    ///
    /// This is a convenience initializer that creates a disclosure policy from the given paths.
    /// Use this when you want explicit control over which claims are selectively disclosable.
    ///
    /// Example:
    /// ```swift
    /// let sdJWT = try JSONWebSelectiveDisclosureToken(
    ///     claims: claims,
    ///     concealedPaths: ["/email", "/phone_number", "/address"],
    ///     using: issuerKey
    /// )
    /// ```
    ///
    /// - Parameters:
    ///   - claims: The full JWT claims to include
    ///   - concealedPaths: JSON Pointer paths (RFC 6901) to claims that should be selectively disclosable
    ///   - header: Custom JOSE header (default: empty, `typ` will be set to `sd+jwt`)
    ///   - algorithm: Signature algorithm (if nil, inferred from key)
    ///   - hashAlgorithm: Hash algorithm for disclosure digests (default: SHA-256)
    ///   - decoyCount: Number of decoy digests to add for privacy (default: random 0-4)
    ///   - signingKey: The issuer's signing key
    /// - Throws: `JSONWebKeyError` if key operations fail, `CryptoKitError` for cryptographic failures
    public init<SK: JSONWebSigningKey>(
        claims: JSONWebTokenClaims,
        concealedPaths: Set<JSONPointer>,
        header: JOSEHeader = .init(),
        algorithm: JSONWebSignatureAlgorithm? = nil,
        hashAlgorithm: any NamedHashFunction.Type = SHA256.self,
        decoyCount: Int = .random(in: 0 ... 4),
        using signingKey: SK
    ) throws {
        try self.init(
            claims: claims,
            policy: .disclosable(concealedPaths),
            header: header,
            algorithm: algorithm,
            hashAlgorithm: hashAlgorithm,
            decoyCount: decoyCount,
            using: signingKey
        )
    }
    
    private static func addDecoys(
        count: Int,
        to claims: inout JSONWebTokenClaims,
        using hashAlgorithm: any HashFunction.Type
    ) throws {
        guard count > 0 else { return }
        
        var sdHashes: [String] = claims.disclosureHashes.map { $0.urlBase64EncodedString() }
        let existingHashesSet = Set(sdHashes)
        
        var newDecoys: [String] = []
        newDecoys.reserveCapacity(count)
        
        for _ in 0 ..< count {
            var decoyString: String
            repeat {
                let randomData = Data.random(length: 32)
                let decoyDigest = hashAlgorithm.hash(data: randomData).data
                decoyString = decoyDigest.urlBase64EncodedString()
            } while existingHashesSet.contains(decoyString) || newDecoys.contains(decoyString)
            
            newDecoys.append(decoyString)
            sdHashes.append(decoyString)
        }
        
        // Shuffle to hide original order (RFC 9901 recommendation)
        sdHashes.shuffle()
        claims.storage["_sd"] = sdHashes
    }
    
    /// Creates a presentation with only the specified disclosures.
    ///
    /// - Parameter selectedDisclosures: Array of disclosures to include in the presentation
    /// - Returns: A new SD-JWT containing only the selected disclosures
    public func presenting(disclosures selectedDisclosures: [JSONWebSelectiveDisclosure]) -> JSONWebSelectiveDisclosureToken {
        .init(
            jwt: jwt,
            disclosures: selectedDisclosures.filter(Set(disclosures).contains),
            keyBinding: keyBinding
        )
    }
    
    /// Creates a presentation with disclosures for the specified paths.
    ///
    /// This method traverses the payload to find disclosure hashes at each path's parent
    /// and matches them against the disclosure list.
    ///
    /// - Parameter paths: JSON Pointer paths to disclose
    /// - Returns: A new SD-JWT containing only disclosures for the specified paths
    public func presenting(paths: Set<JSONPointer>) throws -> JSONWebSelectiveDisclosureToken {
        let disclosureList = try disclosureList
        var selectedHashes = Set<Data>()

        for path in paths {
            guard let parentPath = path.parent, let lastComponent = path.last else { continue }

            if let index = lastComponent.intValue {
                // Array element: look for {"...": hash} marker at the index
                if let parentArray = payload.value.storage.value(at: parentPath) as? [Any],
                   parentArray.indices.contains(index),
                   let marker = parentArray[index] as? [String: Any],
                   marker.count == 1,
                   let hashValue = marker["..."]
                {
                    if let hashData = hashValue as? Data {
                        selectedHashes.insert(hashData)
                    } else if let hashString = hashValue as? String,
                              let hashData = Data(urlBase64Encoded: hashString)
                    {
                        selectedHashes.insert(hashData)
                    }
                }
            } else {
                // Object claim: look in parent's _sd array
                let sdArray: [String]?
                if parentPath.isRoot {
                    sdArray = payload.value.storage.storage["_sd"] as? [String]
                } else if let parentDict = payload.value.storage.value(at: parentPath) as? [String: Any] {
                    sdArray = parentDict["_sd"] as? [String]
                } else {
                    sdArray = nil
                }

                guard let sdArray else { continue }

                let key = lastComponent.stringValue
                // Find disclosure with matching key and hash in _sd
                for disclosure in disclosures where disclosure.key == key {
                    if let hash = disclosureList.hashes.first(where: { disclosureList[$0] == disclosure }),
                       sdArray.contains(hash.urlBase64EncodedString())
                    {
                        selectedHashes.insert(hash)
                    }
                }
            }
        }

        let selectedDisclosures = disclosures.filter { disclosure in
            guard let hash = try? disclosure.digest(using: disclosureList.hashFunction) else { return false }
            return selectedHashes.contains(hash)
        }

        return JSONWebSelectiveDisclosureToken(
            jwt: jwt,
            disclosures: selectedDisclosures,
            keyBinding: keyBinding
        )
    }
}

extension JSONWebSelectiveDisclosureToken {
    private func calculateSDHash() throws -> any Digest {
        let hashFunction = payload.disclosureHashAlgorithm?.hashFunction ?? SHA256.self
        let encoder = JSONEncoder.encoder
        encoder.userInfo[.sdJWTEncodedRepresentation] = JSONWebSelectiveDisclosureTokenRepresentation.compact
        let baseToken = JSONWebSelectiveDisclosureToken(jwt: jwt, disclosures: disclosures, keyBinding: nil)
        let compactData = try encoder.encode(baseToken)
        var compactString = String(decoding: compactData, as: UTF8.self)
        compactString = String(compactString.dropFirst().dropLast().dropLast())
        return hashFunction.hash(data: Data(compactString.utf8))
    }
    
    /// Creates an SD-JWT presentation with a key binding JWT as defined in RFC 9901 Section 4.3.
    ///
    /// The key binding JWT (KB-JWT) binds this SD-JWT presentation to the holder's key,
    /// preventing replay attacks. The KB-JWT contains:
    /// - `typ` header set to `"kb+jwt"`
    /// - `iat` claim with current timestamp
    /// - `aud` claim with the verifier's identifier
    /// - `nonce` claim with the verifier-provided nonce
    /// - `sd_hash` claim with the hash over the SD-JWT presentation
    ///
    /// - Parameters:
    ///   - holderKey: The holder's signing key for the KB-JWT.
    ///   - algorithm: Signature algorithm for the KB-JWT.
    ///   - nonce: Verifier-provided nonce for freshness, random bas64-url string when `nil` is provided..
    ///   - audience: The intended verifier's identifier.
    /// - Returns: A new SD-JWT with the key binding JWT attached.
    /// - Throws: Encoding or signing errors.
    public func withKeyBinding(
        using holderKey: some JSONWebSigningKey,
        algorithm: JSONWebSignatureAlgorithm? = nil,
        nonce: String? = nil,
        audience: String
    ) throws -> JSONWebSelectiveDisclosureToken {
        let nonce = nonce ?? Data.random(length: 12).urlBase64EncodedString()
        let kbClaims = try JSONWebTokenClaims {
            $0.issuedAt = Date()
            $0.audience = [audience]
            $0.nonce = nonce
            $0.selectiveDisclosureHash = try calculateSDHash().data
        }
        guard let resolvedAlgorithm = holderKey.resolveAlgorithm(algorithm) else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        let kbHeader = try JOSEHeader(algorithm: resolvedAlgorithm, type: .keyBindingJWT)
            .updatedKeyId(using: holderKey, strategy: .id)
        var kbJWT = try JSONWebToken(
            signatures: [.init(protected: kbHeader, signature: .init())],
            payload: ProtectedJSONWebContainer(value: kbClaims)
        )
        try kbJWT.updateSignature(using: holderKey)
        return JSONWebSelectiveDisclosureToken(
            jwt: jwt,
            disclosures: disclosures,
            keyBinding: kbJWT
        )
    }
    
    /// Verifies the key binding JWT per RFC 9901 Section 7.3.
    ///
    /// This method verifies:
    /// 1. KB-JWT algorithm is not `"none"` (RFC 9901 security requirement)
    /// 2. KB-JWT header `typ` is `"kb+jwt"`
    /// 3. KB-JWT signature using holder key from issuer JWT `cnf` claim
    /// 4. KB-JWT `iat` is within acceptable time window
    /// 5. KB-JWT `nonce` matches expected value (if provided)
    /// 6. KB-JWT `aud` matches expected audience (if provided)
    /// 7. KB-JWT `sd_hash` matches computed hash over the SD-JWT presentation
    ///
    /// - Parameters:
    ///   - expectedNonce: Expected nonce value (optional, but recommended).
    ///   - expectedAudience: Expected audience value (optional, but recommended).
    ///   - holderKeySet: Optional key set for holder key lookup. If nil, uses `cnf` claim from issuer JWT.
    /// - Throws: `JSONWebValidationError.invalidKeyBinding` on verification failure,
    ///   `CryptoKitError.authenticationFailure` if "none" algorithm is used.
    public func verifyKeyBinding(
        expectedNonce: String? = nil,
        expectedAudience: String? = nil,
        using holderKeySet: JSONWebKeySet? = nil
    ) throws {
        guard let keyBinding, let signature = keyBinding.signatures.first else {
            throw JSONWebValidationError.keyBindingRequired
        }
        // RFC 9901: "none" algorithm MUST NOT be used for KB-JWT
        guard signature.protected.algorithm != JSONWebSignatureAlgorithm.unsafeNone else {
            throw CryptoKitError.authenticationFailure
        }
        guard signature.protected.type == .keyBindingJWT else {
            throw JSONWebValidationError.invalidKeyBinding
        }
        try keyBinding.verifyDate()
        if let confirmation = payload.confirmation {
            try keyBinding.verifySignature(using: confirmation.matchKey(from: holderKeySet ?? .init()))
        }
        
        if let expectedNonce {
            guard keyBinding.payload.nonce == expectedNonce else {
                throw JSONWebValidationError.invalidKeyBinding
            }
        }
        if let expectedAudience {
            try keyBinding.verifyAudience(includes: expectedAudience)
        }
        guard try keyBinding.payload.selectiveDisclosureHash == calculateSDHash().data else {
            throw JSONWebValidationError.invalidKeyBinding
        }
    }
}
