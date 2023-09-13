//
//  SecCertificate.swift
//
//
//  Created by Amir Abbas Mousavian on 9/9/23.
//

import CryptoKit
import Foundation
import X509
#if canImport(CommonCrypto)
import CommonCrypto

extension SecCertificate: JSONWebValidatingKey {
    public var storage: JSONWebValueStorage {
        get {
            var key = try! AnyJSONWebKey(storage: publicKey.storage)
            key.certificateChain = [self]
            return key.storage
        }
        set {
            preconditionFailure("Operation not allowed.")
        }
    }
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        try publicKey.verifySignature(signature, for: data, using: algorithm)
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> Self {
        let key = AnyJSONWebKey(storage: storage)
        guard let certificate = key.certificateChain.first else {
            throw JSONWebKeyError.keyNotFound
        }
        return try certificate.secCertificate() as! Self
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

extension SecCertificate: Expirable {
    public func verifyDate(_ currentDate: Date) throws {
        try Certificate(self).verifyDate(currentDate)
    }
}
#endif
