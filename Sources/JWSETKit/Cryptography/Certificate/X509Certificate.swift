//
//  X509Certificate.swift
//
//
//  Created by Amir Abbas Mousavian on 9/12/23.
//

#if canImport(X509)
@_spi(FixedExpiryValidationTime)
import X509
#if canImport(CryptoExtras)
import CryptoExtras
#endif
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto
import SwiftASN1

extension X509.Certificate.PublicKey: Swift.Decodable, Swift.Encodable {}

extension Certificate.PublicKey: JSONWebValidatingKey, JSONWebKeyRSAType, JSONWebKeyCurveType, JSONWebKeyImportable, JSONWebKeyExportable {
    public var storage: JSONWebValueStorage {
        (try? jsonWebKey().storage) ?? .init()
    }
    
    public init(storage: JSONWebValueStorage) throws {
        let key = AnyJSONWebKey(storage: storage)
        
        switch (key.keyType, key.curve) {
        case (.some(.ellipticCurve), .some(.p256)):
            try self.init(P256.Signing.PublicKey(key))
        case (.some(.ellipticCurve), .some(.p384)):
            try self.init(P384.Signing.PublicKey(key))
        case (.some(.ellipticCurve), .some(.p521)):
            try self.init(P521.Signing.PublicKey(key))
        case (.some(.octetKeyPair), .some(.ed25519)):
            try self.init(Curve25519.Signing.PublicKey(key))
        case (.some(.rsa), _):
#if canImport(CommonCrypto)
            let der = try SecKey(key).externalRepresentation
            try self.init(derEncoded: der)
#elseif canImport(CryptoExtras)
            try self.init(_RSA.Signing.PublicKey(key))
#else
            #error("Unimplemented")
#endif
        default:
            throw JSONWebKeyError.unknownKeyType
        }
    }
    
    public init<D>(importing key: D, format: JSONWebKeyFormat) throws where D: DataProtocol {
        let decodedKey = try AnyJSONWebKey(importing: key, format: format)
        try self.init(storage: decodedKey.storage)
    }
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        switch algorithm {
        case .rsaSignaturePSSSHA256, .rsaSignaturePSSSHA384, .rsaSignaturePSSSHA512:
            return try jsonWebKey().verifySignature(signature, for: data, using: algorithm)
        default:
            guard try isValidSignature(signature, for: data, signatureAlgorithm: .init(algorithm)) else {
                throw CryptoKitError.authenticationFailure
            }
        }
    }
    
    /// Generates a key object from the public key inside certificate.
    ///
    /// - Returns: A public key to validate signatures.
    public func jsonWebKey() throws -> any JSONWebValidatingKey {
        if let key = P256.Signing.PublicKey(self) {
            return key
        } else if let key = P384.Signing.PublicKey(self) {
            return key
        } else if let key = P521.Signing.PublicKey(self) {
            return key
        } else if let key = _RSA.Signing.PublicKey(self) {
            return key
        } else if let key = Curve25519.Signing.PublicKey(self) {
            return key
        }
        guard let key = try AnyJSONWebKey(importing: subjectPublicKeyInfoBytes, format: .spki).specialized() as? any JSONWebValidatingKey else {
            throw JSONWebKeyError.unknownKeyType
        }
        return key
    }
    
    public func thumbprint<H>(format: JSONWebKeyFormat, using hashFunction: H.Type) throws -> H.Digest where H: HashFunction {
        try jsonWebKey().thumbprint(format: format, using: hashFunction)
    }
    
    public func exportKey(format: JSONWebKeyFormat) throws -> Data {
        guard let key = try jsonWebKey() as? any JSONWebKeyExportable else {
            throw JSONWebKeyError.operationNotAllowed
        }
        return try key.exportKey(format: format)
    }
}

extension X509.Certificate.PrivateKey: Swift.Decodable, Swift.Encodable {}

extension Certificate.PrivateKey: JSONWebSigningKey, JSONWebKeyRSAType, JSONWebKeyCurveType, JSONWebKeyImportable, JSONWebKeyExportable {
    public var storage: JSONWebValueStorage {
        (try? jsonWebKey().storage) ?? .init()
    }
    
    public init(algorithm: some JSONWebAlgorithm) throws {
        switch algorithm {
        case .ecdsaSignatureP256SHA256:
            self.init(P256.Signing.PrivateKey())
        case .ecdsaSignatureP384SHA384:
            self.init(P384.Signing.PrivateKey())
        case .ecdsaSignatureP521SHA512:
            self.init(P521.Signing.PrivateKey())
        case .eddsaSignature, .eddsa25519Signature:
            self.init(Curve25519.Signing.PrivateKey())
        case .rsaSignaturePSSSHA256, .rsaSignaturePSSSHA384, .rsaSignaturePSSSHA512,
             .rsaSignaturePKCS1v15SHA256, .rsaSignaturePKCS1v15SHA384, .rsaSignaturePKCS1v15SHA512:
#if canImport(CommonCrypto)
            let secKey = try SecKey(algorithm: algorithm)
            try self.init(secKey)
#elseif canImport(CryptoExtras)
            try self.init(_RSA.Signing.PrivateKey(keySize: .bits2048))
#else
            #error("Unimplemented")
#endif
        default:
            throw JSONWebKeyError.unknownAlgorithm
        }
    }
    
    public init(storage: JSONWebValueStorage) throws {
        let key = AnyJSONWebKey(storage: storage)
        
        switch (key.keyType, key.curve) {
        case (.some(.ellipticCurve), .some(.p256)):
            try self.init(P256.Signing.PrivateKey(key))
        case (.some(.ellipticCurve), .some(.p384)):
            try self.init(P384.Signing.PrivateKey(key))
        case (.some(.ellipticCurve), .some(.p521)):
            try self.init(P521.Signing.PrivateKey(key))
        case (.some(.octetKeyPair), .some(.ed25519)):
            try self.init(Curve25519.Signing.PrivateKey(key))
        case (.some(.rsa), _):
#if canImport(CommonCrypto)
            let secKey = try SecKey(key)
            try self.init(secKey)
#elseif canImport(CryptoExtras)
            try self.init(_RSA.Signing.PrivateKey(key))
#else
            #error("Unimplemented")
#endif
        default:
            throw JSONWebKeyError.unknownKeyType
        }
    }
    
    public init<D>(importing key: D, format: JSONWebKeyFormat) throws where D: DataProtocol {
        let decodedKey = try AnyJSONWebKey(importing: key, format: format)
        try self.init(storage: decodedKey.storage)
    }
    
    public func signature<D>(_ data: D, using algorithm: JSONWebSignatureAlgorithm) throws -> Data where D: DataProtocol {
        switch algorithm {
        case .rsaSignaturePSSSHA256, .rsaSignaturePSSSHA384, .rsaSignaturePSSSHA512:
            try jsonWebKey().signature(data, using: algorithm)
        default:
            try Data(
                sign(bytes: data, signatureAlgorithm: .init(algorithm))
                    .rawRepresentation
            )
        }
    }
    
    /// Generates a key object from the public key inside certificate.
    ///
    /// - Returns: A public key to validate signatures.
    public func jsonWebKey() throws -> any JSONWebSigningKey {
        let der = try serializeAsPEM().derBytes
        let pkcs8 = try PKCS8PrivateKey(derEncoded: der)
        switch try (pkcs8.keyType, pkcs8.keyCurve) {
        case (.ellipticCurve, .p256):
            return try P256.Signing.PrivateKey(derRepresentation: der)
        case (.ellipticCurve, .p384):
            return try P384.Signing.PrivateKey(derRepresentation: der)
        case (.ellipticCurve, .p521):
            return try P521.Signing.PrivateKey(derRepresentation: der)
        case (.octetKeyPair, .ed25519):
            return try Curve25519.Signing.PrivateKey(importing: der, format: .pkcs8)
        case (.rsa, _):
#if canImport(CommonCrypto)
            return try SecKey(derRepresentation: Data(der), keyType: .rsa)
#elseif canImport(CryptoExtras)
            return try _RSA.Signing.PrivateKey(derRepresentation: der)
#else
            #error("Unimplemented")
#endif
        default:
            throw JSONWebKeyError.unknownKeyType
        }
    }
    
    public func thumbprint<H>(format: JSONWebKeyFormat, using hashFunction: H.Type) throws -> H.Digest where H: HashFunction {
        try publicKey.jsonWebKey().thumbprint(format: format, using: hashFunction)
    }
    
    public func exportKey(format: JSONWebKeyFormat) throws -> Data {
        guard let key = try jsonWebKey() as? any JSONWebKeyExportable else {
            throw JSONWebKeyError.operationNotAllowed
        }
        return try key.exportKey(format: format)
    }
}

extension Certificate.SignatureAlgorithm {
    private static let mappings: [JSONWebSignatureAlgorithm: Self] = [
        .ecdsaSignatureP256SHA256: .ecdsaWithSHA256,
        .ecdsaSignatureP384SHA384: .ecdsaWithSHA384,
        .ecdsaSignatureP521SHA512: .ecdsaWithSHA512,
        .eddsaSignature: .ed25519,
        .eddsa25519Signature: .ed25519,
        .rsaSignaturePKCS1v15SHA256: .sha256WithRSAEncryption,
        .rsaSignaturePKCS1v15SHA384: .sha384WithRSAEncryption,
        .rsaSignaturePKCS1v15SHA512: .sha512WithRSAEncryption,
    ]
    
    init(_ algorithm: some JSONWebAlgorithm) throws {
        guard let result = Self.mappings[.init(algorithm)] else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        self = result
    }
}

extension X509.Certificate: Swift.Decodable, Swift.Encodable {}

extension Certificate: JSONWebValidatingKey {
    public var storage: JSONWebValueStorage {
        var key = AnyJSONWebKey(publicKey)
        key.certificateChain = [self]
        return key.storage
    }
    
    public init(storage: JSONWebValueStorage) throws {
        let key = AnyJSONWebKey(storage: storage)
        guard let certificate = key.certificateChain.first else {
            throw JSONWebKeyError.keyNotFound
        }
        self = certificate
    }
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        try publicKey.verifySignature(signature, for: data, using: algorithm)
    }
    
    public func thumbprint<H>(format: JSONWebKeyFormat, using hashFunction: H.Type) throws -> H.Digest where H: HashFunction {
        try publicKey.thumbprint(format: format, using: hashFunction)
    }
}

extension Certificate: Expirable {
    public func verifyDate(_ currentDate: Date) throws {
        if currentDate > notValidAfter {
            throw JSONWebValidationError.tokenExpired(expiry: notValidAfter)
        }
        if currentDate < notValidBefore {
            throw JSONWebValidationError.tokenInvalidBefore(notBefore: notValidBefore)
        }
    }
}

extension [Certificate] {
    @discardableResult
    public func verifyChain(currentDate: Date? = nil) async throws -> ValidatedCertificateChain {
        var verifier = Verifier(rootCertificates: .init(dropFirst()), policy: {
            if let currentDate {
                RFC5280Policy(fixedExpiryValidationTime: currentDate)
            } else {
                RFC5280Policy()
            }
        })
        let result = try await verifier.validate(chain: .init(self))
        switch result {
        case .validCertificate(let result):
            return result
        case .couldNotValidate:
            throw CryptoKitError.authenticationFailure
        }
    }
}

extension ValidatedCertificateChain: Swift.Decodable, Swift.Encodable {}

extension ValidatedCertificateChain: JSONWebValidatingKey {
    private var x509Chain: [Certificate] { [Certificate](self) }
    
    public var storage: JSONWebValueStorage {
        var key = AnyJSONWebKey(leaf.publicKey)
        key.certificateChain = x509Chain
        return key.storage
    }
    
    /// Return the public key for a leaf certificate after it has been evaluated.
    public var publicKey: Certificate.PublicKey {
        leaf.publicKey
    }
    
    public init(storage: JSONWebValueStorage) throws {
        let key = AnyJSONWebKey(storage: storage)
        self.init(uncheckedCertificateChain: key.certificateChain)
    }
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        try publicKey.verifySignature(signature, for: data, using: algorithm)
    }
}

extension ValidatedCertificateChain: Expirable {
    public func verifyDate(_ currentDate: Date) throws {
        try x509Chain.forEach { try $0.verifyDate(currentDate) }
    }
}
#endif
