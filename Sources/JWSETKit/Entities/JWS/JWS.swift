//
//  JWS.swift
//
//
//  Created by Amir Abbas Mousavian on 9/8/23.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto

/// JWS represents digitally signed or MACed content using JSON data structures and `base64url` encoding.
@frozen
public struct JSONWebSignature<Payload: ProtectedWebContainer>: Hashable, Sendable {
    /// The "signatures" member value MUST be an array of JSON objects.
    ///
    /// Each object represents a signature or MAC over the JWS Payload and the JWS Protected Header.
    public var signatures: [JSONWebSignatureHeader]
    
    /// Combination of protected header and unprotected header.
    ///
    /// - Note: If a key exists in both protected and unprotected headers, value in protected
    ///     will be returned.
    public var header: JOSEHeader {
        guard let signature = signatures.first else {
            return .init()
        }
        return signature.mergedHeader
    }
    
    /// The "`payload`" member MUST be present and contain the value of JWS Payload.
    public var payload: Payload
    
    enum CodingKeys: String, CodingKey {
        case payload
        case signatures
    }
    
    /// Decodes a data that may contain either Base64URL encoded string of JWS or a Complete/Flattened JWS representation.
    ///
    /// - Parameter data: Either Base64URL encoded string of JWS or a JSON with Complete/Flattened JWS representation.
    public init<D: DataProtocol>(from data: D) throws {
        if data.starts(with: Data("ey".utf8)) {
            let container = Data("\"".utf8) + Data(data) + Data("\"".utf8)
            self = try JSONDecoder().decode(JSONWebSignature<Payload>.self, from: container)
        } else if data.starts(with: Data("{".utf8)) {
            self = try JSONDecoder().decode(JSONWebSignature<Payload>.self, from: Data(data))
        } else {
            throw DecodingError.dataCorrupted(.init(codingPath: [], debugDescription: "Invalid JWS."))
        }
    }
    
    /// Initializes JWS using Base64URL encoded String.
    ///
    /// - Parameter string: Base64URL encoded String.
    public init<S: StringProtocol>(from string: S) throws {
        try self.init(from: Data(string.utf8))
    }
    
    /// Initializes a new JWS with given payload and signature(s).
    ///
    /// - Parameters:
    ///   - signatures: An array of signatures and JOSE headers.
    ///   - payload: Protected payload data/object.
    public init(signatures: [JSONWebSignatureHeader], payload: Payload) {
        self.signatures = signatures
        self.payload = payload
    }
    
    /// Renews all signatures for protected header(s) using given key set.
    ///
    /// - Parameters:
    ///   - keySet: A `JSONWebKeySet` object contains keys that would be used for signing.
    public mutating func updateSignature(using keySet: JSONWebKeySet) throws {
        signatures = try signatures.map { header in
            let message = header.signedData(payload)
            let algorithm = JSONWebSignatureAlgorithm(header.protected.algorithm)
            let signature: Data
            if algorithm == .none {
                signature = .init()
            } else if let algorithm, let key = keySet.matches(for: header.protected.value).first as? any JSONWebSigningKey {
                signature = try key.signature(message, using: algorithm)
            } else {
                throw JSONWebKeyError.keyNotFound
            }
            return try JSONWebSignatureHeader(
                protected: header.protected.encoded,
                unprotected: header.unprotected,
                signature: signature
            )
        }
    }
    
    /// Renews all signatures for protected header(s) using given keys.
    ///
    /// This method finds appropriate key for the header using `kid` value in protected or unprotected header.
    ///
    /// - Parameters:
    ///   - keys: An array of `JSONWebSigningKey` that would be used for signing.
    public mutating func updateSignature<S>(using keys: S) throws where S: Sequence, S.Element: JSONWebSigningKey {
        try updateSignature(using: JSONWebKeySet(keys: keys))
    }
    
    /// Renews all signatures for protected header(s) using given keys.
    ///
    /// This method finds appropriate key for the header using `kid` value in protected or unprotected header.
    ///
    /// - Parameters:
    ///   - keys: An array of `JSONWebSigningKey` that would be used for signing.
    public mutating func updateSignature<S>(using keys: S) throws where S: Sequence<any JSONWebSigningKey> {
        try updateSignature(using: JSONWebKeySet(keys: .init(keys)))
    }
    
    /// Renews all signatures for protected header(s) using given key.
    ///
    /// - Parameters:
    ///   - key: A `JSONWebSigningKey` object that would be used for signing.
    public mutating func updateSignature(using key: some JSONWebSigningKey) throws {
        try updateSignature(using: [key])
    }
    
    /// Verifies all signatures in protected header(s) using given key set.
    ///
    /// - Parameters:
    ///   - key: A `JSONWebKeySet` object contains keys that would be used for validation.
    ///   - strict: Controls algorithm header validation behavior.
    ///     - `true` (default, **RECOMMENDED**): Only use algorithm from protected (signed) header.
    ///     - `false` (**INSECURE**): Allow algorithm from unprotected header when protected is "none".
    ///
    ///     **SECURITY WARNING**: Setting to `false` enables algorithm substitution attacks where an
    ///     attacker can control which algorithm is used for verification by modifying unprotected headers.
    ///     Only use in controlled environments where the JWS source is fully trusted and you understand
    ///     the security implications. See [RFC 8725 Section 3.1](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.1) for details.
    ///
    ///     **Default**: `true` (secure by default)
    public func verifySignature(using keySet: JSONWebKeySet, strict: Bool = true) throws {
        guard !signatures.isEmpty else {
            throw CryptoKitError.authenticationFailure
        }
        for signatureHeader in signatures {
            let message = signatureHeader.signedData(payload)
            var algorithm = JSONWebSignatureAlgorithm(signatureHeader.protected.algorithm)
            if !strict, algorithm == .none, let unprotected = signatureHeader.unprotected {
                algorithm = JSONWebSignatureAlgorithm(unprotected.algorithm)
            }
            if let algorithm, let key = keySet.matches(for: signatureHeader.protected.value).first as? any JSONWebValidatingKey {
                try key.verifySignature(signatureHeader.signature, for: message, using: algorithm)
                return
            }
        }
        throw JSONWebKeyError.keyNotFound
    }
    
    /// Verifies all signatures for protected header(s) using given keys.
    ///
    /// This method finds appropriate key for the header using `kid` value in protected or unprotected header.
    ///
    /// - Note: No signature algorithm (`alg`) may have been set to "`none`" otherwise
    ///     `JSONWebKeyError.operationNotAllowed` will be thrown.
    ///
    /// - Parameters:
    ///   - keys: An array of `JSONWebValidatingKey` that would be used for validation.
    ///   - strict: Controls algorithm header validation behavior.
    ///     - `true` (default, **RECOMMENDED**): Only use algorithm from protected (signed) header.
    ///     - `false` (**INSECURE**): Allow algorithm from unprotected header when protected is "none".
    ///
    ///     **SECURITY WARNING**: Setting to `false` enables algorithm substitution attacks. See main
    ///     `verifySignature(using:strict:)` documentation for details.
    public func verifySignature<S>(using keys: S, strict: Bool = true) throws where S: Sequence, S.Element: JSONWebValidatingKey {
        try verifySignature(using: JSONWebKeySet(keys: keys), strict: strict)
    }
    
    /// Verifies all signatures for protected header(s) using given keys.
    ///
    /// This method finds appropriate key for the header using `kid` value in protected or unprotected header.
    ///
    /// - Note: No signature algorithm (`alg`) may have been set to "`none`" otherwise
    ///     `JSONWebKeyError.operationNotAllowed` will be thrown.
    ///
    /// - Parameters:
    ///   - keys: An array of `JSONWebValidatingKey` that would be used for validation.
    ///   - strict: Controls algorithm header validation behavior.
    ///     - `true` (default, **RECOMMENDED**): Only use algorithm from protected (signed) header.
    ///     - `false` (**INSECURE**): Allow algorithm from unprotected header when protected is "none".
    ///
    ///     **SECURITY WARNING**: Setting to `false` enables algorithm substitution attacks. See main
    ///     `verifySignature(using:strict:)` documentation for details.
    public func verifySignature<S>(using keys: S, strict: Bool = true) throws where S: Sequence<any JSONWebValidatingKey> {
        try verifySignature(using: JSONWebKeySet(keys: .init(keys)), strict: strict)
    }
    
    /// Verifies all signatures in protected header(s) using given key.
    ///
    /// - Parameters:
    ///   - key: A `JSONWebValidatingKey` object that would be used for validation.
    ///   - strict: Controls algorithm header validation behavior.
    ///     - `true` (default, **RECOMMENDED**): Only use algorithm from protected (signed) header.
    ///     - `false` (**INSECURE**): Allow algorithm from unprotected header when protected is "none".
    ///
    ///     **SECURITY WARNING**: Setting to `false` enables algorithm substitution attacks. See main
    ///     `verifySignature(using:strict:)` documentation for details.
    public func verifySignature(using key: some JSONWebValidatingKey, strict: Bool = true) throws {
        try verifySignature(using: [key], strict: strict)
    }
    
    /// Validates contents and required fields if applicable.
    public func validate() throws {
        try signatures.forEach { try $0.protected.validate() }
        try payload.validate()
    }
}

extension JOSEHeader {
    /// Strategy for identifying keys in JWS headers.
    ///
    /// Determines how the key identifier (`kid`) parameter is set in the JWS header
    /// to help recipients identify which key to use for signature verification.
    public enum KeyIdStrategy: Hashable {
        /// Use the key's `keyId` property if available.
        ///
        /// This is the default strategy. If the signing key has a `keyId` property set,
        /// it will be used as the `kid` header parameter.
        case id

        /// Use a custom string as the key identifier.
        ///
        /// - Parameter String: The custom identifier to use as the `kid` header parameter.
        case customId(String)

        /// Use the key's thumbprint as the identifier.
        ///
        /// Calculates and uses the JWK thumbprint of the signing key as the `kid` header parameter.
        /// This provides a standardized way to identify keys based on their cryptographic properties.
        case thumbprint

        /// Use the key's `keyId` if available, otherwise fall back to thumbprint.
        ///
        /// First attempts to use the key's `keyId` property, and if that's not available,
        /// calculates and uses the key's thumbprint as the identifier.
        case idWithThumbprintFallback

        /// Embed the full public key in the header instead of using an identifier.
        ///
        /// Places the complete public key in the `jwk` header parameter rather than
        /// using a `kid` identifier. Recipients can use the embedded key directly
        /// without needing to look it up.
        case embedded
    }
    
    public mutating func updateKeyId<SK>(using signingKey: SK, strategy: KeyIdStrategy? = .idWithThumbprintFallback) throws where SK: JSONWebSigningKey {
        switch strategy {
        case .id:
            self.keyId = signingKey.keyId
        case .customId(let id):
            self.keyId = id
        case .thumbprint:
            self.keyId = try signingKey.thumbprintUri(format: .jwk, using: SHA256.self)
        case .idWithThumbprintFallback:
            self.keyId = try signingKey.keyId ?? signingKey.thumbprintUri(format: .jwk, using: SHA256.self)
        case .embedded:
            self.key = signingKey
        case .none:
            break
        }
    }
    
    public func updatedKeyId<SK>(using signingKey: SK, strategy: KeyIdStrategy? = .idWithThumbprintFallback) throws -> Self where SK: JSONWebSigningKey {
        var result = self
        try result.updateKeyId(using: signingKey, strategy: strategy)
        return result
    }
}

extension JSONWebSignature {
    /// Creates a new JWS/JWT with given protected payload then signs with given key.
    /// - Parameters:
    ///   - payload: JWS/JWT payload.
    ///   - algorithm: Sign and hash algorithm.
    ///   - signingKey: The key to sign the payload.
    public init<SK>(
        payload: Payload,
        algorithm: JSONWebSignatureAlgorithm,
        keyIdStrategy: JOSEHeader.KeyIdStrategy? = .id,
        using signingKey: SK
    ) throws where SK: JSONWebSigningKey {
        guard algorithm.keyType == signingKey.keyType else {
            throw JSONWebKeyError.operationNotAllowed
        }
        let header = try JOSEHeader(
            algorithm: algorithm,
            type: .jwt
        ).updatedKeyId(using: signingKey, strategy: keyIdStrategy)
        
        self.signatures = try [
            .init(protected: header, signature: .init()),
        ]
        self.payload = payload
        try updateSignature(using: signingKey)
    }
}

/// A JWS object that contains plain data.
public typealias JSONWebSignaturePlain = JSONWebSignature<ProtectedDataWebContainer>

extension JSONWebSignature where Payload == ProtectedDataWebContainer {
    /// Creates a new JWS/JWT with given payload then signs with given key.
    /// - Parameters:
    ///   - payload: JWS/JWT payload.
    ///   - algorithm: Sign and hash algorithm.
    ///   - signingKey: The key to sign the payload.
    public init<PD, SK>(
        payload: PD,
        algorithm: JSONWebSignatureAlgorithm,
        keyIdStrategy: JOSEHeader.KeyIdStrategy? = .id,
        using signingKey: SK
    ) throws where PD: Collection, PD.Element == UInt8, SK: JSONWebSigningKey {
        try self.init(payload: Payload(encoded: .init(payload)), algorithm: algorithm, keyIdStrategy: keyIdStrategy, using: signingKey)
    }
}

extension JSONWebSignature where Payload: TypedProtectedWebContainer {
    /// Creates a new JWS/JWT with given payload then signs with given key.
    /// - Parameters:
    ///   - payload: JWS/JWT payload.
    ///   - algorithm: Sign and hash algorithm.
    ///   - signingKey: The key to sign the payload.
    public init<SK>(
        payload: Payload.Container,
        algorithm: JSONWebSignatureAlgorithm,
        keyIdStrategy: JOSEHeader.KeyIdStrategy? = .id,
        using signingKey: SK
    ) throws where SK: JSONWebSigningKey {
        try self.init(payload: Payload(value: payload), algorithm: algorithm, keyIdStrategy: keyIdStrategy, using: signingKey)
    }
}

extension String {
    /// Encodes JWS to a Base64URL compact encoded string.
    ///
    /// - Parameter jws: JWS object to be encoded.
    ///
    /// - Throws: `EncodingError` if encoding fails.
    public init<Payload: ProtectedWebContainer>(_ jws: JSONWebSignature<Payload>) throws {
        let encoder = JSONEncoder.encoder
        if jws.signatures.first?.protected.base64 == false {
            encoder.userInfo[.jwsEncodedRepresentation] = JSONWebSignatureRepresentation.compactDetached
        } else {
            encoder.userInfo[.jwsEncodedRepresentation] = JSONWebSignatureRepresentation.compact
        }
        self = try String(String(decoding: encoder.encode(jws), as: UTF8.self).dropFirst().dropLast())
    }
}

extension JSONWebSignature: LosslessStringConvertible, CustomDebugStringConvertible {
    public init?(_ description: String) {
        guard let jws = try? JSONWebSignature<Payload>(from: description) else {
            return nil
        }
        self = jws
    }
    
    public var description: String {
        (try? String(self)) ?? ""
    }
    
    public var debugDescription: String {
        "Signatures: \(signatures.debugDescription)\nPayload: \(payload.encoded.urlBase64EncodedString())"
    }
}
