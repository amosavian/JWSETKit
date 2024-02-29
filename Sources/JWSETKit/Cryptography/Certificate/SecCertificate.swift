//
//  SecCertificate.swift
//
//
//  Created by Amir Abbas Mousavian on 9/9/23.
//

import Foundation
#if canImport(CommonCrypto)
import CommonCrypto
import CryptoKit
import X509

extension SecCertificate: JSONWebValidatingKey {
    public var storage: JSONWebValueStorage {
        var key = AnyJSONWebKey(storage: (try? publicKey.storage) ?? .init())
        if let certificate = try? Certificate(self) {
            key.certificateChain = [certificate]
        }
        return key.storage
    }
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        try publicKey.verifySignature(signature, for: data, using: algorithm)
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> Self {
        let key = AnyJSONWebKey(storage: storage)
        guard let certificate = key.certificateChain.first, let result = try certificate.secCertificate() as? Self else {
            throw JSONWebKeyError.keyNotFound
        }
        return result
    }
    
    public var publicKey: SecKey {
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

extension SecTrust: JSONWebValidatingKey {
    public var storage: JSONWebValueStorage {
        var key = AnyJSONWebKey(storage: (try? certificateChain.first?.publicKey.storage) ?? .init())
        key.certificateChain = (try? certificateChain.compactMap(Certificate.init)) ?? []
        return key.storage
    }
    
    /// Certificate chain
    public var certificateChain: [SecCertificate] {
        get throws {
            if #available(iOS 15.0, macOS 12.0, watchOS 8.0, tvOS 15.0, *) {
                return (SecTrustCopyCertificateChain(self) as? [SecCertificate]) ?? []
            } else {
                let count = SecTrustGetCertificateCount(self)
                guard count > 0 else {
                    throw JSONWebKeyError.keyNotFound
                }
                return (0 ..< count).compactMap {
                    SecTrustGetCertificateAtIndex(self, $0)
                }
            }
        }
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> Self {
        let key = AnyJSONWebKey(storage: storage)
        let certificates = try key.certificateChain.map { try $0.secCertificate() }
        var result: SecTrust?
        SecTrustCreateWithCertificates(certificates as CFArray, SecPolicyCreateBasicX509(), &result)
        guard let result = result as? Self else {
            throw JSONWebKeyError.keyNotFound
        }
        return result
    }
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        try certificateChain.first?.verifySignature(signature, for: data, using: algorithm)
    }
}

extension SecTrust: Expirable {
    public func verifyDate(_ currentDate: Date) throws {
        try certificateChain.forEach { try $0.verifyDate(currentDate) }
    }
}

extension Certificate {
    /// Casts `X509.Certificate` into `SecCertificate`.
    ///
    /// - Returns: A new `SecCertificate` instance.
    public func secCertificate() throws -> SecCertificate {
        try SecCertificateCreateWithData(kCFAllocatorDefault, derRepresentation as CFData)!
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
