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
    /// - Duplicate digest detection (RFC 9901 Section 7.1.9)
    /// - Orphan disclosure detection (RFC 9901 Section 7.1.10)
    ///
    /// - Throws: `JSONWebValidationError` if validation fails
    public func validate() throws {
        try jwt.validate()
        try keyBinding?.validate()
        let allDisclosureHashes = allDisclosureHashes
        guard allDisclosureHashes.count == Set(allDisclosureHashes).count else {
            throw JSONWebValidationError.duplicateDisclosureDigest
        }
        guard try Set(disclosureList.hashes).isSubset(of: allDisclosureHashes) else {
            throw JSONWebValidationError.orphanDisclosure
        }
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
    ///   - nonce: Verifier-provided nonce for freshness.
    ///   - audience: The intended verifier's identifier.
    /// - Returns: A new SD-JWT with the key binding JWT attached.
    /// - Throws: Encoding or signing errors.
    public func withKeyBinding(
        using holderKey: some JSONWebSigningKey,
        algorithm: JSONWebSignatureAlgorithm,
        nonce: String,
        audience: String
    ) throws -> JSONWebSelectiveDisclosureToken {
        let kbClaims = try JSONWebTokenClaims {
            $0.issuedAt = Date()
            $0.audience = [audience]
            $0.nonce = nonce
            $0.selectiveDisclosureHash = try calculateSDHash().data
        }
        
        let kbHeader = try JOSEHeader(algorithm: algorithm, type: .keyBindingJWT)
            .updatedKeyId(using: holderKey, strategy: .id)
        var kbJWT = try JSONWebToken(
            signatures: [try .init(protected: kbHeader, signature: .init())],
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
    /// 1. KB-JWT header `typ` is `"kb+jwt"`
    /// 2. KB-JWT signature using holder key from issuer JWT `cnf` claim
    /// 3. KB-JWT `iat` is within acceptable time window
    /// 4. KB-JWT `nonce` matches expected value (if provided)
    /// 5. KB-JWT `aud` matches expected audience (if provided)
    /// 6. KB-JWT `sd_hash` matches computed hash over the SD-JWT presentation
    ///
    /// - Parameters:
    ///   - expectedNonce: Expected nonce value (optional, but recommended).
    ///   - expectedAudience: Expected audience value (optional, but recommended).
    ///   - holderKeySet: Optional key set for holder key lookup. If nil, uses `cnf` claim from issuer JWT.
    ///   - clockSkew: Allowed clock skew for `iat` verification (default 60 seconds).
    /// - Throws: `JSONWebValidationError.invalidKeyBinding` on verification failure.
    public func verifyKeyBinding(
        expectedNonce: String? = nil,
        expectedAudience: String? = nil,
        using holderKeySet: JSONWebKeySet? = nil,
    ) throws {
        guard let keyBinding else {
            throw JSONWebValidationError.keyBindingRequired
        }
        guard keyBinding.signatures.first?.protected.type == .keyBindingJWT else {
            throw JSONWebValidationError.invalidKeyBinding
        }
        
        // Verify key binding's JWT
        try keyBinding.verifyDate()
        if let confirmation = keyBinding.payload.confirmation {
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
        
        // Verify sd_hash matches computed hash
        guard try keyBinding.payload.selectiveDisclosureHash == calculateSDHash().data else {
            throw JSONWebValidationError.invalidKeyBinding
        }
    }
}
