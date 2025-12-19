//
//  HMAC.swift
//
//
//  Created by Amir Abbas Mousavian on 9/7/23.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto

/// JSON Web Key (JWK) container for creating/verifying HMAC signatures.
@frozen
public struct JSONWebKeyHMAC<H: HashFunction>: MutableJSONWebKey, JSONWebSymmetricSigningKey, Sendable {
    public var storage: JSONWebValueStorage
    
    /// Returns a new concrete key using json data.
    ///
    /// - Parameter storage: Storage of key-values.
    public init(storage: JSONWebValueStorage) throws {
        self.storage = storage
        try validate()
    }
    
    private init(key: SymmetricKey) {
        self.storage = .init()
        self.keyType = .symmetric
        self.algorithm = .hmac(bitCount: H.Digest.byteCount * 8)
        self.keyValue = key.keyValue
    }
    
    /// Returns a new HMAC key with given symmetric key.
    ///
    /// - Parameter key: Symmetric key for operation.
    /// - Throws: `CryptoKitError.incorrectKeySize` if key size is less than hash byte count,
    ///     per[RFC 7518 section 3.2](https://www.rfc-editor.org/rfc/rfc7518#section-3.2) .

    public init(_ key: SymmetricKey) throws {
        guard H.Digest.byteCount <= key.bitCount / 8 else {
            throw CryptoKitError.incorrectKeySize
        }
        self.init(key: key)
    }
    
    public init() {
        self.init(key: SymmetricKey(size: .init(bitCount: H.Digest.byteCount * 8)))
    }
    
    public init(algorithm: some JSONWebAlgorithm) throws {
        guard JSONWebSignatureAlgorithm(algorithm).hashFunction == H.self else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        self.init()
    }
    
    public func signature<D: DataProtocol>(_ data: D, using _: JSONWebSignatureAlgorithm) throws -> Data {
        var hmac = try HMAC<H>(key: .init(self))
        hmac.update(data: data)
        let mac = hmac.finalize()
        return Data(mac)
    }
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using _: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        let isValid = try HMAC<H>.isValidAuthenticationCode(Data(signature), authenticating: data, using: .init(self))
        guard isValid else {
            throw CryptoKitError.authenticationFailure
        }
    }
}
