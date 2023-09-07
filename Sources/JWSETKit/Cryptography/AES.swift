//
//  File.swift
//  
//
//  Created by Amir Abbas Mousavian on 9/7/23.
//

import Foundation
import CryptoKit

import CryptoKit

public struct JsonWebKeyAESGCM: JsonWebDecryptingKey {
    public var storage: JsonWebValueStorage

    public var symmetricKey: SymmetricKey {
        get throws {
            guard let keyValue = self.keyValue else {
                throw CryptoKitError.incorrectKeySize
            }
            return SymmetricKey(data: keyValue)
        }
    }
    public static func create(jsonWebKey: JsonWebValueStorage) throws -> JsonWebKeyAESGCM {
        var result = JsonWebKeyAESGCM()
        result.storage = jsonWebKey
        return result
    }
    
    public init() {
        self.init(.bits128)
    }
    
    public init(_ keySize: SymmetricKeySize) {
        self.storage = .init()
        self.algorithm = "A\(keySize.bitCount)GCM"
        self.keyValue = Self.random()
    }
    
    public init(_ key: SymmetricKey) throws {
        self.storage = .init()
        self.algorithm = "A\(key.bitCount)GCM"
        self.keyValue = key
    }
    
    private static func random() -> SymmetricKey {
        SymmetricKey(size: .bits128)
    }
    
    public func decrypt<D>(_ data: D) throws -> Data where D : DataProtocol {
        try AES.GCM.open(.init(combined: data), using: symmetricKey)
    }
    
    public func encrypt<D>(_ data: D) throws -> SealedData where D : DataProtocol {
        try .init(AES.GCM.seal(data, using: symmetricKey))
    }
}
