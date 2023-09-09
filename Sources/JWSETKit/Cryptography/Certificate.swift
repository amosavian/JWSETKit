//
//  File.swift
//  
//
//  Created by Amir Abbas Mousavian on 9/9/23.
//

import Foundation

#if canImport(CommonCrypto)
import CommonCrypto

extension SecCertificate: JSONWebValidatingKey {
    public var storage: JSONWebValueStorage {
        get {
            try! publicKey.storage
        }
        set {
            preconditionFailure("Operation not allowed.")
        }
    }
    
    public func validate<D>(_ signature: D, for data: D, using algorithm: JSONWebAlgorithm) throws where D : DataProtocol {
        try publicKey.validate(signature, for: data, using: algorithm)
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> Self {
        fatalError("Not implemented.")
    }
    
    private var publicKey: SecKey {
        get throws {
            guard let key = SecCertificateCopyKey(self) else {
                throw JSONWebKeyError.keyNotFound
            }
            return key
        }
    }
}
#endif
