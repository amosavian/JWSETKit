//
//  SecCertificate.swift
//
//
//  Created by Amir Abbas Mousavian on 9/9/23.
//


import Foundation
#if canImport(CommonCrypto)
import X509
import CryptoKit
import CommonCrypto

extension SecCertificate: JSONWebValidatingKey {
    public var storage: JSONWebValueStorage {
        get {
            var key = try! AnyJSONWebKey(storage: publicKey.storage)
            key.certificateChain = try! [.init(self)]
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

extension Certificate {
    /// Casts `X509.Certificate` into `SecCertificate`.
    ///
    /// - Returns: A new `SecCertificate` instance.
    public func secCertificate() throws -> SecCertificate {
        guard let certificate = try SecCertificateCreateWithData(kCFAllocatorDefault, derRepresentation as CFData) else {
            throw CryptoKitASN1Error.invalidASN1Object
        }
        return certificate
    }
    
    /// Casts `SecCertificate` into `X509.Certificate`.
    ///
    /// - Parameter secCertificate: `SecCertificate` instance to be casted.
    public init(_ secCertificate: SecCertificate) throws {
        let der = SecCertificateCopyData(secCertificate) as Data
        try self.init(derEncoded: der)
    }
}
#endif
