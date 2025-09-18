//
//  JWK-EC.swift
//
//
//  Created by Amir Abbas Mousavian on 9/9/23.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto
#if canImport(P256K)
import P256K
#endif

/// JSON Web Key (JWK) container for different types of Elliptic-Curve public keys consists of P-256, P-384, P-521, Ed25519.
@frozen
public struct JSONWebECPublicKey: MutableJSONWebKey, JSONWebKeyCurveType, JSONWebValidatingKey, Sendable {
    public var storage: JSONWebValueStorage
    
    var signingKey: any JSONWebValidatingKey {
        get throws {
            // swiftformat:disable:next redundantSelf
            try Self.signingType(self.curve)
                .init(from: self)
        }
    }
    
    var keyAgreementKey: any JSONWebKey {
        get throws {
            // swiftformat:disable:next redundantSelf
            try Self.keyAgreementType(self.curve)
                .init(from: self)
        }
    }
    
    public init(storage: JSONWebValueStorage) throws {
        self.storage = storage
        try validate()
    }
    
    public init(from key: JSONWebECPrivateKey) {
        self.storage = key.storage
        self.privateKey = nil
    }
    
    static func signingType(_ curve: JSONWebKeyCurve?) throws -> any JSONWebValidatingKey.Type {
        switch curve {
        case .p256:
            return P256.Signing.PublicKey.self
        case .p384:
            return P384.Signing.PublicKey.self
        case .p521:
            return P521.Signing.PublicKey.self
        case .ed25519, .x25519:
            return Curve25519.Signing.PublicKey.self
#if canImport(P256K)
        case .secp256k1:
            return P256K.Signing.PublicKey.self
#endif
        default:
            throw JSONWebKeyError.unknownKeyType
        }
    }
    
    static func keyAgreementType(_ curve: JSONWebKeyCurve?) throws -> any JSONWebKey.Type {
        switch curve {
        case .p256:
            return P256.KeyAgreement.PublicKey.self
        case .p384:
            return P384.KeyAgreement.PublicKey.self
        case .p521:
            return P521.KeyAgreement.PublicKey.self
        case .ed25519, .x25519:
            return Curve25519.KeyAgreement.PublicKey.self
        default:
            throw JSONWebKeyError.unknownKeyType
        }
    }
    
    public func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        try signingKey.verifySignature(signature, for: data, using: algorithm)
    }
}

extension JSONWebKeyImportable {
    fileprivate init<D>(
        key: D, format: JSONWebKeyFormat,
        keyLengthTable: [Int: JSONWebKeyCurve],
        keyFinder: (_ curve: JSONWebKeyCurve) throws -> any JSONWebValidatingKey.Type
    ) throws where D: DataProtocol {
        let curve: JSONWebKeyCurve
        switch format {
        case .raw:
            guard let probableCurve = keyLengthTable[key.count] else {
                throw JSONWebKeyError.unknownAlgorithm
            }
            curve = probableCurve
        case .spki:
            let spki = try SubjectPublicKeyInfo(derEncoded: key)
            guard let probableCurve = spki.keyCurve else {
                throw JSONWebKeyError.unknownAlgorithm
            }
            curve = probableCurve
        case .pkcs8:
            let pkcs8 = try PKCS8PrivateKey(derEncoded: key)
            guard let probableCurve = pkcs8.keyCurve else {
                throw JSONWebKeyError.unknownAlgorithm
            }
            curve = probableCurve
        case .jwk:
            throw JSONWebKeyError.invalidKeyFormat
        }
        guard let type = try keyFinder(curve) as? any JSONWebKeyImportable.Type else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        try self = Self(from: type.init(importing: key, format: format))
    }
}

extension JSONWebECPublicKey: JSONWebKeyImportable, JSONWebKeyExportable {
    public init<D>(importing key: D, format: JSONWebKeyFormat) throws where D: DataProtocol {
        switch format {
        case .raw, .spki:
            try self.init(key: key, format: format, keyLengthTable: JSONWebKeyCurve.publicRawCurve, keyFinder: Self.signingType)
        case .jwk:
            self = try JSONDecoder().decode(Self.self, from: Data(key))
        default:
            throw JSONWebKeyError.invalidKeyFormat
        }
    }
    
    public func exportKey(format: JSONWebKeyFormat) throws -> Data {
        guard let underlyingKey = (try? signingKey) as? (any JSONWebKeyExportable) else {
            throw JSONWebKeyError.unknownKeyType
        }
        return try underlyingKey.exportKey(format: format)
    }
}

@available(iOS 17.0, macOS 14.0, watchOS 10.0, tvOS 17.0, *)
extension JSONWebECPublicKey: HPKEDiffieHellmanPublicKey {
    public typealias EphemeralPrivateKey = JSONWebECPrivateKey
    
    public init<D>(_ serialization: D, kem: HPKE.KEM) throws where D: ContiguousBytes {
        guard let curve = kem.curve, let keyType = try Self.keyAgreementType(curve) as? (any HPKEPublicKeySerialization.Type) else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        guard let key = try keyType.init(serialization, kem: kem) as? (any JSONWebKey) else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        try self.init(from: key)
    }
    
    public func hpkeRepresentation(kem: HPKE.KEM) throws -> Data {
        guard let key = try keyAgreementKey as? (any HPKEDiffieHellmanPublicKey) else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        return try key.hpkeRepresentation(kem: kem)
    }
}

/// JWK container for different types of Elliptic-Curve private keys consists of P-256, P-384, P-521, Ed25519.
public struct JSONWebECPrivateKey: MutableJSONWebKey, JSONWebKeyCurveType, JSONWebSigningKey, Sendable {
    public var storage: JSONWebValueStorage
    
    @EphemeralPublicKey
    private var ephemeralPublicKey
    
    public var publicKey: JSONWebECPublicKey {
        if let ephemeral = ephemeralPublicKey {
            return ephemeral
        }
        return JSONWebECPublicKey(from: self)
    }
    
    var signingKey: any JSONWebSigningKey {
        get throws {
            // swiftformat:disable:next redundantSelf
            try Self.signingType(self.curve)
                .init(from: self)
        }
    }
    
    public init(storage: JSONWebValueStorage) throws {
        self.storage = storage
        try validate()
    }
    
    public init(algorithm: some JSONWebAlgorithm) throws {
        try self.init(curve: algorithm.curve ?? .empty)
    }
    
    public init(curve: JSONWebKeyCurve) throws {
        self.storage = try Self
            .signingType(curve)
            .init(algorithm: .unsafeNone).storage
    }
    
    static func signingType(_ curve: JSONWebKeyCurve?) throws -> any JSONWebSigningKey.Type {
        switch curve {
        case .p256:
            return P256.Signing.PrivateKey.self
        case .p384:
            return P384.Signing.PrivateKey.self
        case .p521:
            return P521.Signing.PrivateKey.self
        case .ed25519, .x25519:
            return Curve25519.Signing.PrivateKey.self
#if canImport(P256K)
        case .secp256k1:
            return P256K.Signing.PrivateKey.self
#endif
        default:
            throw JSONWebKeyError.unknownKeyType
        }
    }
    
    public func signature<D>(_ data: D, using algorithm: JSONWebSignatureAlgorithm) throws -> Data where D: DataProtocol {
        try signingKey.signature(data, using: algorithm)
    }
    
    public func sharedSecretFromKeyAgreement(with publicKeyShare: JSONWebECPublicKey) throws -> Crypto.SharedSecret {
        guard let publicKeyCureve = publicKeyShare.curve else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        var privateKey = self
        if privateKey.curve != publicKeyCureve {
            // Regenerate private key for new algorithm.
            // Swift's HPKE implementation does not tell private key the KEM algorithm, but it will
            // be revealed when `sharedSecretFromKeyAgreement` is called.
            // We will regenerate the key for given curve and save the new public key in `ephemeralPublicKey`.
            privateKey = try .init(curve: publicKeyCureve)
            ephemeralPublicKey = privateKey.ephemeralPublicKey
        }
        // swiftformat:disable:next redundantSelf
        switch (privateKey.keyType, privateKey.curve) {
        case (JSONWebKeyType.ellipticCurve, .p256):
            return try P256.KeyAgreement.PrivateKey(from: self)
                .sharedSecretFromKeyAgreement(with: .init(from: publicKeyShare))
        case (JSONWebKeyType.ellipticCurve, .p384):
            return try P384.KeyAgreement.PrivateKey(from: self)
                .sharedSecretFromKeyAgreement(with: .init(from: publicKeyShare))
        case (JSONWebKeyType.ellipticCurve, .p521):
            return try P521.KeyAgreement.PrivateKey(from: self)
                .sharedSecretFromKeyAgreement(with: .init(from: publicKeyShare))
        case (JSONWebKeyType.octetKeyPair, .x25519):
            return try Curve25519.KeyAgreement.PrivateKey(from: self)
                .sharedSecretFromKeyAgreement(with: .init(from: publicKeyShare))
#if canImport(P256K)
        case (JSONWebKeyType.ellipticCurve, .secp256k1):
            let secret = try P256K.KeyAgreement.PrivateKey(from: self)
                .sharedSecretFromKeyAgreement(with: .init(from: publicKeyShare))
            return try Crypto.SharedSecret(from: secret.data)
#endif
        default:
            throw JSONWebKeyError.unknownKeyType
        }
    }
    
    public func validate() throws {
        // swiftformat:disable:next redundantSelf
        guard let keyType = self.keyType else {
            throw JSONWebKeyError.unknownKeyType
        }
        try checkRequiredFields(keyType.requiredFields + ["d"])
    }
}

extension JSONWebECPrivateKey: JSONWebKeyImportable, JSONWebKeyExportable {
    public init<D>(importing key: D, format: JSONWebKeyFormat) throws where D: DataProtocol {
        switch format {
        case .raw, .pkcs8:
            try self.init(key: key, format: format, keyLengthTable: JSONWebKeyCurve.privateRawCurve, keyFinder: Self.signingType)
        case .jwk:
            self = try JSONDecoder().decode(Self.self, from: Data(key))
        default:
            throw JSONWebKeyError.invalidKeyFormat
        }
    }
    
    public func exportKey(format: JSONWebKeyFormat) throws -> Data {
        guard let underlyingKey = (try? signingKey) as? (any JSONWebKeyExportable) else {
            throw JSONWebKeyError.unknownKeyType
        }
        return try underlyingKey.exportKey(format: format)
    }
}

@available(iOS 17.0, macOS 14.0, watchOS 10.0, tvOS 17.0, *)
extension JSONWebECPrivateKey: HPKEDiffieHellmanPrivateKeyGeneration {
    public init() {
        self = (try? .init(curve: .p256)).unsafelyUnwrapped
    }
}

@available(iOS 17.0, macOS 14.0, watchOS 10.0, tvOS 17.0, *)
extension JSONWebECPrivateKey: DiffieHellmanKeyAgreement {}

enum ECHelper {
    static func ecComponents(_ data: Data, keyLength: Int) throws -> [Data] {
        var data = data
        // Check if data is x.963 format, if so, remove the
        // first byte which is data compression type.
        if data.count % (keyLength / 8) == 1 {
            // Key data is uncompressed.
            guard data.removeFirst() == 0x04 else {
                throw Crypto.CryptoKitError.incorrectParameterSize
            }
        }
        return stride(from: 0, to: data.count, by: keyLength / 8).map {
            data.dropFirst($0).prefix(keyLength / 8)
        }
    }
    
    static func ecWebKey(data: Data, keyLength: Int, isPrivateKey: Bool) throws -> any JSONWebKey {
        let components = try ecComponents(data, keyLength: keyLength)
        var key: some (MutableJSONWebKey & JSONWebKeyCurveType) = AnyJSONWebKey()

        guard !components.isEmpty else {
            throw JSONWebKeyError.unknownKeyType
        }

        key.keyType = .ellipticCurve
        key.curve = .init(rawValue: "P-\(components[0].count * 8)")
        
        switch (components.count, isPrivateKey) {
        case (2, false):
            key.xCoordinate = components[0]
            key.yCoordinate = components[1]
            return try JSONWebECPublicKey(from: key)
        case (3, true):
            key.xCoordinate = components[0]
            key.yCoordinate = components[1]
            key.privateKey = components[2]
            return try JSONWebECPrivateKey(from: key)
        default:
            throw JSONWebKeyError.unknownKeyType
        }
    }
}

extension JSONWebKeyCurve {
    fileprivate static let publicRawCurve: [Int: Self] = [
        65: .p256, 32: .ed25519, 97: .p384, 133: .p521,
    ]
    
    fileprivate static let privateRawCurve: [Int: Self] = [
        97: .p256, 32: .ed25519, 145: .p384, 199: .p521,
    ]
}

@propertyWrapper private final class EphemeralPublicKey: @unchecked Sendable {
    var wrappedValue: JSONWebECPublicKey? {
        get { key }
        set { key = newValue }
    }

    var key: JSONWebECPublicKey?
}
