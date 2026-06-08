//
//  DPoP.swift
//
//
//  Created by Amir Abbas Mousavian.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto

/// Claims registered for an OAuth 2.0 DPoP proof JWT, per
/// [RFC 9449 §4.2](https://datatracker.ietf.org/doc/html/rfc9449#section-4.2).
public struct DPoPRegisteredParameters: JSONWebContainerParameters {
    /// Unique identifier for the DPoP proof JWT (`jti`).
    ///
    /// The value MUST be unique. It is used to mitigate proof replay.
    public var jwtId: String?
    
    /// Unique identifier for the DPoP proof JWT (`jti`), as a `UUID`.
    ///
    /// A `UUID`-typed view over the same `jti` claim as ``jwtId``.
    public var jwtUUID: UUID?
    
    /// The HTTP method of the request to which the proof is attached (`htm`).
    public var httpMethod: String?
    
    /// The HTTP target URI of the request, without query and fragment parts (`htu`).
    public var httpURL: URL?
    
    /// The time at which the proof was created (`iat`).
    public var issuedAt: Date?
    
    /// Hash of the access token (`ath`).
    ///
    /// The value is the SHA-256 hash of the ASCII encoding of the associated access
    /// token's value. Unlike the OpenID Connect `at_hash`, this is the *full* digest,
    /// not the left-most half.
    public var accessTokenHash: Data?
    
    /// A server-provided nonce (`nonce`).
    public var nonce: String?
    
    @_documentation(visibility: private)
    public static let keys: [SendablePartialKeyPath<Self>: String] = [
        \.jwtId: "jti", \.jwtUUID: "jti", \.httpMethod: "htm", \.httpURL: "htu",
        \.issuedAt: "iat", \.accessTokenHash: "ath", \.nonce: "nonce",
    ]
}

/// The claims payload of a DPoP proof JWT.
public struct DPoPClaims: MutableJSONWebContainer, Sendable {
    public var storage: JSONWebValueStorage
    
    public init(storage: JSONWebValueStorage) {
        self.storage = storage
    }
    
    /// Verifies the claims required of every DPoP proof are present, per
    /// [RFC 9449 §4.2](https://datatracker.ietf.org/doc/html/rfc9449#section-4.2): `jti`,
    /// `htm`, `htu`, and `iat`.
    ///
    /// - Throws: ``JSONWebValidationError/missingRequiredField(key:)`` if a required claim
    ///   is absent.
    public func validate() throws {
        try checkRequiredFields("jti", "htm", "htu", "iat")
    }
}

extension DPoPClaims: Expirable {
    /// Verifies the `iat` header using current date.
    ///
    /// - Parameters:
    ///   - currentDate: The date that headers will be check against. Default is current system date.
    public func verifyDate(_ currentDate: Date) throws {
        // swiftformat:disable:next redundantSelf
        if let issuedAt = self.issuedAt, currentDate < issuedAt {
            throw JSONWebValidationError.tokenInvalidBefore(notBefore: issuedAt)
        }
    }
}

extension DPoPClaims {
    @_documentation(visibility: private)
    @inlinable
    public subscript<T: JSONWebValueStorage.ValueType>(dynamicMember keyPath: SendableKeyPath<DPoPRegisteredParameters, T?>) -> T? {
        get {
            storage[stringKey(keyPath)]
        }
        set {
            storage[stringKey(keyPath)] = newValue
        }
    }
}

extension JSONPointer {
    public init(_ keyPath: SendablePartialKeyPath<DPoPRegisteredParameters>) {
        let key = DPoPRegisteredParameters.keys[keyPath] ?? keyPath.name.jsonWebKey
        self.init(key: key)
    }
}

/// An OAuth 2.0 DPoP proof JWT, per [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449).
///
/// A DPoP proof is a JWS whose protected header carries `typ: dpop+jwt` and the
/// proof's public key embedded as the `jwk` parameter. Its payload is a ``DPoPClaims``.
public typealias DPoPProof = JSONWebSignature<ProtectedJSONWebContainer<DPoPClaims>>

extension DPoPProof {
    /// Creates and signs a DPoP proof JWT for the given HTTP request.
    ///
    /// The proof's protected header carries `typ: dpop+jwt` and the signing key's public
    /// key embedded as `jwk`, per [RFC 9449 §4.2](https://datatracker.ietf.org/doc/html/rfc9449#section-4.2).
    ///
    /// - Parameters:
    ///   - method: The HTTP method of the request (`htm`), e.g. `"POST"`.
    ///   - url: The HTTP target URI of the request (`htu`). Query and fragment are removed,
    ///          per [RFC 9449 §4.3](https://datatracker.ietf.org/doc/html/rfc9449#section-4.3).
    ///   - accessToken: When provided, its SHA-256 hash is stored in `ath`. A leading
    ///     `"Bearer "` prefix is ignored.
    ///   - nonce: An optional server-provided `nonce`.
    ///   - algorithm: The asymmetric signature algorithm. If `nil`, it is inferred from
    ///     the key (which requires the key to carry an `alg`).
    ///   - issuedAt: The proof creation time (`iat`). Defaults to now.
    ///   - jwtId: The unique proof identifier (`jti`). Defaults to a random value.
    ///   - signingKey: The asymmetric key used to sign the proof.
    ///
    /// - Throws: `JSONWebKeyError.unknownAlgorithm` if the key's algorithm cannot be resolved.
    public init(
        method: String,
        url: URL,
        accessToken: String? = nil,
        nonce: String? = nil,
        algorithm: JSONWebSignatureAlgorithm? = nil,
        issuedAt: Date = .init(),
        jwtId: String = UUID().uuidString,
        using signingKey: some JSONWebSigningKey
    ) throws {
        guard let algorithm = signingKey.resolveAlgorithm(algorithm) else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        var header = JOSEHeader(algorithm: algorithm, type: .dpop)
        header.key = signingKey.publicKey
        
        var claims = DPoPClaims(storage: .init())
        claims.jwtId = jwtId
        claims.httpMethod = method
        claims.httpURL = url.normalizedHTU
        claims.issuedAt = issuedAt
        if let accessToken {
            claims.accessTokenHash = Self.accessTokenHash(accessToken)
        }
        if let nonce {
            claims.nonce = nonce
        }
        
        try self.init(
            signatures: [.init(protected: header, signature: .init())],
            payload: .init(value: claims)
        )
        try updateSignature(using: signingKey)
    }
    
    /// Verifies this DPoP proof against an incoming HTTP request, per
    /// [RFC 9449 §4.3](https://datatracker.ietf.org/doc/html/rfc9449#section-4.3).
    ///
    /// The proof's signature is verified using the public key embedded in its `jwk`
    /// header. This does **not** perform `jti` replay detection or enforce a maximum
    /// proof age; the caller reads ``DPoPClaims/jwtId`` / ``DPoPClaims/issuedAt`` and
    /// applies its own replay store and acceptable-age policy.
    ///
    /// - Parameters:
    ///   - method: The HTTP method of the request, compared to `htm` (case-sensitive, per RFC 7231).
    ///   - url: The HTTP target URI, compared to `htu` after normalization (scheme and
    ///     host lowercased, default port and userinfo dropped, query and fragment stripped).
    ///   - accessToken: When provided, the proof's `ath` must equal its SHA-256 hash.
    ///   - nonce: When provided, the proof's `nonce` must equal it.
    ///   - currentDate: The reference time used to reject future-dated proofs. Defaults to now.
    /// - Throws: A validation or crypto error when any check fails. This validates the proof
    ///   itself; it does **not** perform `jti` replay detection or enforce a maximum proof
    ///   age — the caller reads ``DPoPClaims/jwtId`` / ``DPoPClaims/issuedAt`` and applies its
    ///   own replay store and acceptable-age policy.
    public func verify(
        method: String,
        url: URL,
        accessToken: String? = nil,
        nonce: String? = nil,
        currentDate: Date = .init()
    ) throws {
        let header = header
        guard header.type == .dpop else {
            throw JSONWebValidationError.missingRequiredField(key: "typ")
        }
        try payload.value.validate()
        try payload.value.verifyDate(currentDate)
        
        // Verify key and signature.
        guard let algorithm = JSONWebSignatureAlgorithm(header.algorithm),
              algorithm != .unsafeNone, algorithm.keyType != JSONWebKeyType.symmetric
        else {
            throw JSONWebKeyError.operationNotAllowed
        }
        guard let publicKey = header.key, let validatingKey = publicKey as? any JSONWebValidatingKey else {
            throw JSONWebValidationError.missingRequiredField(key: "jwk")
        }
        guard !publicKey.isAsymmetricPrivateKey else {
            throw JSONWebKeyError.operationNotAllowed
        }
        try verifySignature(using: validatingKey)
        
        // Verify bindings.
        guard payload.httpMethod == method else {
            throw CryptoKitError.authenticationFailure
        }
        guard payload.httpURL?.normalizedHTU == url.normalizedHTU else {
            throw CryptoKitError.authenticationFailure
        }
        if let accessToken, payload.accessTokenHash != Self.accessTokenHash(accessToken) {
            throw CryptoKitError.authenticationFailure
        }
        
        // Verify nonce if applicable.
        if let nonce, payload.nonce != nonce {
            throw CryptoKitError.authenticationFailure
        }
    }
    
    /// The DPoP `ath` value for an access token: `SHA-256` over the token's ASCII octets,
    /// with any leading `Bearer`/`DPoP` authentication scheme removed.
    static func accessTokenHash(_ accessToken: String) -> Data {
        SHA256.hash(data: Data(accessToken.strippingAuthScheme().utf8)).data
    }
    
    /// Confirms that this proof's public key is the one bound to the given access token,
    /// per [RFC 9449 §6.1](https://datatracker.ietf.org/doc/html/rfc9449#section-6.1).
    ///
    /// The access token's `cnf.jkt` is compared to the SHA-256 JWK thumbprint of the
    /// proof's embedded public key, reusing the RFC 7800 confirmation machinery.
    ///
    /// - Parameter accessToken: The DPoP-bound access token whose `cnf` claim carries `jkt`.
    /// - Throws: `JSONWebValidationError.missingRequiredField` if the access token has no
    ///   `cnf`/`jwk`, or `JSONWebKeyError.operationNotAllowed` if the thumbprints differ.
    public func verifyBinding(accessToken: JSONWebToken) throws {
        guard let confirmation = accessToken.payload.confirmation else {
            throw JSONWebValidationError.missingRequiredField(key: "cnf")
        }
        guard let publicKey = header.key else {
            throw JSONWebValidationError.missingRequiredField(key: "jwk")
        }
        try confirmation.validateThumbprint(publicKey)
    }
}

extension URL {
    fileprivate var normalizedHTU: URL {
        // The HTTP target URI (`htu`) form used for DPoP comparison, per
        // [RFC 9449 §4.3](https://datatracker.ietf.org/doc/html/rfc9449#section-4.3): scheme and
        // host lowercased, the default port for the scheme dropped, userinfo and query and
        // fragment removed.
        guard var components = URLComponents(url: self, resolvingAgainstBaseURL: true) else {
            return self
        }
        let scheme = components.scheme?.lowercased()
        components.scheme = scheme
        components.host = components.host?.lowercased()
        components.user = nil
        components.password = nil
        components.query = nil
        components.fragment = nil
        components.dropDefaultPort()
        return components.url ?? self
    }
}

extension URLComponents {
    private static let defaultPorts: [String: Int] = [
        "http": 80, "https": 443
    ]
    
    fileprivate mutating func dropDefaultPort() {
        if let port = port, port == (scheme?.lowercased()).flatMap({ Self.defaultPorts[$0] }) {
            self.port = nil
        }
    }
}
