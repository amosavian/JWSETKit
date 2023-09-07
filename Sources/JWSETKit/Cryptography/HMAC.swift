//
//  File.swift
//  
//
//  Created by Amir Abbas Mousavian on 9/7/23.
//

import Foundation
import CryptoKit

extension SymmetricKey: JsonWebKey {
    public var storage: JsonWebValueStorage {
        get {
            var result = JsonWebValueStorage()
            result["kty"] = "oct"
            withUnsafeBytes {
                result["k", true] = Data($0)
            }
            return result
        }
        mutating set {
            guard let data = newValue["k", true] else { return }
            self = SymmetricKey(data: data)
        }
    }
    
    public static func create(jsonWebKey: JsonWebValueStorage) throws -> SymmetricKey {
        guard let key = (jsonWebKey["k", true] as Data?) else {
            throw CryptoKitError.incorrectKeySize
        }
        return SymmetricKey(data: key)
    }
    
    public init() {
        self = .init(size: .bits128)
    }
    
    public func hash(into hasher: inout Hasher) {
        withUnsafeBytes {
            hasher.combine(bytes: $0)
        }
    }
}

public struct JsonWebKeyHMAC<H: HashFunction>: JsonWebSigningKey {
    public var storage: JsonWebValueStorage

    public var symmetricKey: SymmetricKey {
        get throws {
            guard let keyValue = self.keyValue, keyValue.count == H.Digest.byteCount else {
                throw CryptoKitError.incorrectKeySize
            }
            return SymmetricKey(data: keyValue)
        }
    }
    
    public var hashFunction: H.Type {
        H.self
    }
    
    public static func create(jsonWebKey: JsonWebValueStorage) throws -> JsonWebKeyHMAC {
        var result = JsonWebKeyHMAC()
        result.storage = jsonWebKey
        return result
    }
    
    public init() {
        self.storage = .init()
        self.algorithm = "HS\(H.Digest.byteCount * 8)"
        self.keyValue = Self.random()
    }
    
    public init(_ key: SymmetricKey) throws {
        self.storage = .init()
        self.algorithm = "HS\(key.bitCount)"
        self.keyValue = key
    }
    
    private static func random() -> SymmetricKey {
        SymmetricKey(size: .init(bitCount: H.Digest.byteCount * 8))
    }
    
    public func sign<D: DataProtocol>(_ data: D) throws -> Data {
        var hmac = try HMAC<H>(key: symmetricKey)
        hmac.update(data: data)
        let mac = hmac.finalize()
        return Data(mac)
    }
    
    public func validate<D: DataProtocol>(_ signature: D, for data: D) throws {
        var hmac = try HMAC<H>(key: symmetricKey)
        hmac.update(data: data)
        let mac = hmac.finalize()
        guard Data(mac) == Data(signature) else {
            throw CryptoKitError.authenticationFailure
        }
    }
}
