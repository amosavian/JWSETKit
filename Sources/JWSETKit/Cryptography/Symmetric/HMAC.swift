//
//  HMAC.swift
//
//
//  Created by Amir Abbas Mousavian on 9/7/23.
//

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

public struct JSONWebKeyHMAC<H: HashFunction>: JSONWebSigningKey {
    public var storage: JSONWebValueStorage

    public var symmetricKey: SymmetricKey {
        get throws {
            // swiftformat:disable:next redundantSelf
            guard let keyValue = self.keyValue, keyValue.count == H.Digest.byteCount else {
                throw CryptoKitError.incorrectKeySize
            }
            return SymmetricKey(data: keyValue)
        }
    }
    
    public var hashFunction: H.Type {
        H.self
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> JSONWebKeyHMAC {
        .init(storage: storage)
    }
    
    public init(storage: JSONWebValueStorage) {
        self.storage = storage
    }
    
    public init(_ key: SymmetricKey) throws {
        self.storage = .init()
        self.algorithm = "HS\(key.bitCount)"
        self.keyValue = key
    }
    
    private static func random() -> SymmetricKey {
        SymmetricKey(size: .init(bitCount: H.Digest.byteCount * 8))
    }
    
    public func signature<D: DataProtocol>(_ data: D, using _: JSONWebAlgorithm) throws -> Data {
        var hmac = try HMAC<H>(key: symmetricKey)
        hmac.update(data: data)
        let mac = hmac.finalize()
        return Data(mac)
    }
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using _: JSONWebAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        var hmac = try HMAC<H>(key: symmetricKey)
        hmac.update(data: data)
        let mac = hmac.finalize()
        guard Data(mac) == Data(signature) else {
            throw CryptoKitError.authenticationFailure
        }
    }
}
