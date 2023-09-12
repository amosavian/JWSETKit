//
//  X509Certificate.swift
//
//
//  Created by Amir Abbas Mousavian on 9/12/23.
//

import Foundation
import SwiftASN1
import X509
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
#if canImport(_Concurrency)
import _CryptoExtras
#endif
#if canImport(CommonCrypto)
import CommonCrypto
#endif

extension Certificate.PublicKey {
    public func jsonWebKey() throws -> any JSONWebValidatingKey {
        if let key = P256.Signing.PublicKey(self) {
            return key
        } else if let key = P256.Signing.PublicKey(self) {
            return key
        } else if let key = P384.Signing.PublicKey(self) {
            return key
        } else if let key = P521.Signing.PublicKey(self) {
            return key
        } else if let key = _RSA.Signing.PublicKey(self) {
            fatalError()
        } else {
            throw JSONWebKeyError.unknownKeyType
        }
    }
}

extension Certificate {
    public init(derEncoded: Data) throws {
        try self.init(derEncoded: [UInt8](derEncoded))
    }
    
    public var derRepresentation: Data {
        get throws {
            var derSerializer = DER.Serializer()
            try serialize(into: &derSerializer)
            return Data(derSerializer.serializedBytes)
        }
    }
    
#if canImport(CommonCrypto)
    public func secCertificate() throws -> SecCertificate {
        guard let certificate = try SecCertificateCreateWithData(kCFAllocatorDefault, derRepresentation as CFData) else {
            throw CryptoKitASN1Error.invalidASN1Object
        }
        return certificate
    }
    
    public init(_ secCertificate: SecCertificate) throws {
        let der = SecCertificateCopyData(secCertificate) as Data
        try self.init(derEncoded: der)
    }
#endif
}

extension Certificate: JSONWebValidatingKey {
    public var storage: JSONWebValueStorage {
        get {
            var key = try! AnyJSONWebKey(storage: publicKey.jsonWebKey().storage)
            key.certificateChain = [self]
            return key.storage
        }
        set {
            fatalError()
        }
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> X509.Certificate {
        let key = AnyJSONWebKey(storage: storage)
        guard let certificate = key.certificateChain.first else {
            throw JSONWebKeyError.keyNotFound
        }
        return certificate
    }
    
    public func validate<S, D>(_ signature: S, for data: D, using algorithm: JSONWebAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        try publicKey.jsonWebKey().validate(signature, for: data, using: algorithm)
    }
}
