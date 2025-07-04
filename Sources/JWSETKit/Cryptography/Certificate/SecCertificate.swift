//
//  SecCertificate.swift
//
//
//  Created by Amir Abbas Mousavian on 9/9/23.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
#if canImport(CommonCrypto)
import CommonCrypto
import CryptoKit
import X509

extension Security.SecCertificate: Swift.Codable {}

extension SecCertificate: JSONWebValidatingKey {
    public var storage: JSONWebValueStorage {
        var key = (try? AnyJSONWebKey(publicKey)) ?? .init()
        if let certificate = try? Certificate(self) {
            key.certificateChain = [certificate]
        }
        return key.storage
    }
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        try publicKey.verifySignature(signature, for: data, using: algorithm)
    }
    
    /// Retrieves the public key for certificate.
    public var publicKey: SecKey {
        get throws {
            guard let key = SecCertificateCopyKey(self) else {
                throw JSONWebKeyError.keyNotFound
            }
            return key
        }
    }
    
    public func thumbprint<H>(format: JSONWebKeyFormat, using hashFunction: H.Type) throws -> H.Digest where H: HashFunction {
        try publicKey.thumbprint(format: format, using: hashFunction)
    }
}

extension JSONWebContainer where Self: SecCertificate {
    public init(storage: JSONWebValueStorage) throws {
        let key = AnyJSONWebKey(storage: storage)
        guard let certificate = key.certificateChain.first, let result = try SecCertificate.makeWithCertificate(certificate) as? Self else {
            throw JSONWebKeyError.keyNotFound
        }
        self = result
    }
}

extension SecCertificate: Expirable {
    public func verifyDate(_ currentDate: Date) throws {
        try Certificate(self).verifyDate(currentDate)
    }
}

extension Security.SecTrust: Swift.Codable {}

extension SecTrust: JSONWebValidatingKey {
    public var storage: JSONWebValueStorage {
        guard var key = (try? certificateChain.first?.publicKey).map(AnyJSONWebKey.init) else {
            return .init()
        }
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
                    return []
                }
                return (0 ..< count).compactMap {
                    SecTrustGetCertificateAtIndex(self, $0)
                }
            }
        }
    }
    
    /// Return the public key for a leaf certificate after it has been evaluated.
    public var publicKey: SecKey? {
        SecTrustCopyKey(self)
    }
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        try publicKey?.verifySignature(signature, for: data, using: algorithm)
    }
}

extension JSONWebContainer where Self: SecTrust {
    public init(storage: JSONWebValueStorage) throws {
        let key = AnyJSONWebKey(storage: storage)
        let certificates = try key.certificateChain.map(SecCertificate.makeWithCertificate)
        var result: SecTrust?
        SecTrustCreateWithCertificates(certificates as CFArray, SecPolicyCreateBasicX509(), &result)
        guard let result = result as? Self else {
            throw JSONWebKeyError.keyNotFound
        }
        self = result
    }
}

extension SecTrust: Expirable {
    public func verifyDate(_ currentDate: Date) throws {
        try certificateChain.forEach { try $0.verifyDate(currentDate) }
    }
}

public func == (lhs: Certificate, rhs: SecCertificate) -> Bool {
    lhs == (try? Certificate(rhs))
}

public func == (lhs: SecCertificate, rhs: Certificate) -> Bool {
    (try? Certificate(lhs)) == rhs
}
#endif
