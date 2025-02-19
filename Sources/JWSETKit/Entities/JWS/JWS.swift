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
    ///   - strict: If `true` (default), the algorithm in the protected header will be used otherwise algorithm in unprotected header will be allowed.
    public func verifySignature(using keySet: JSONWebKeySet, strict: Bool = true) throws {
        guard !signatures.isEmpty else {
            throw CryptoKitError.authenticationFailure
        }
        for header in signatures {
            let message = header.signedData(payload)
            var algorithm = JSONWebSignatureAlgorithm(header.protected.algorithm)
            if !strict, algorithm == .none, let unprotected = header.unprotected {
                algorithm = JSONWebSignatureAlgorithm(unprotected.algorithm)
            }
            if let algorithm, let key = keySet.matches(for: header.protected.value).first as? any JSONWebValidatingKey {
                try key.verifySignature(header.signature, for: message, using: algorithm)
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
    ///   - strict: If `true` (default), the algorithm in the protected header will be used otherwise algorithm in unprotected header will be allowed.
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
    ///   - strict: If `true` (default), the algorithm in the protected header will be used otherwise algorithm in unprotected header will be allowed.
    public func verifySignature<S>(using keys: S, strict: Bool = true) throws where S: Sequence<any JSONWebValidatingKey> {
        try verifySignature(using: JSONWebKeySet(keys: .init(keys)), strict: strict)
    }
    
    /// Verifies all signatures in protected header(s) using given key.
    ///
    /// - Parameters:
    ///   - key: A `JSONWebValidatingKey` object that would be used for validation.
    ///   - strict: If `true` (default), the algorithm in the protected header will be used otherwise algorithm in unprotected header will be allowed.
    public func verifySignature(using key: some JSONWebValidatingKey, strict: Bool = true) throws {
        try verifySignature(using: [key], strict: strict)
    }
    
    /// Validates contents and required fields if applicable.
    public func validate() throws {
        try signatures.forEach { try $0.protected.validate() }
        try payload.validate()
    }
}

extension String {
    /// Encodes JWS to a Base64URL compact encoded string.
    ///
    /// - Parameter jws: JWS object to be encoded.
    ///
    /// - Throws: `EncodingError` if encoding fails.
    public init<Payload: ProtectedWebContainer>(jws: JSONWebSignature<Payload>) throws {
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
        (try? String(jws: self)) ?? ""
    }
    
    public var debugDescription: String {
        "Signatures: \(signatures.debugDescription)\nPayload: \(payload.encoded.urlBase64EncodedString())"
    }
}
