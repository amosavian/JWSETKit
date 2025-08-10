//
//  KeyParser.swift
//
//
//  Created by Amir Abbas Mousavian on 9/8/23.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto
import SwiftASN1

extension AnyJSONWebKey {
    /// Returns related specific type with available capabilities like signing,
    /// verify encrypting and decrypting regarding key type (`kty`) and curve.
    ///
    /// Returning type:
    ///   - `JSONWebRSAPublicKey` if key type is `RSA` and private key is **not** present.
    ///   - `JSONWebRSAPrivateKey` if key type is `RSA` and private key is present.
    ///   - `JSONWebECPublicKey`  if key type is `EC`/`OKP` and private key is **not** present.
    ///   - `JSONWebECPrivateKey` if key type is `EC`/`OKP` and private key is present.
    ///   - `JSONWebKeyHMAC` if key type is `oct` and algorithm is `HS256/384/512`.
    ///   - `JSONWebKeyAESGCM` if key type is `oct` and algorithm is `AEDGCM256/384/512`.
    ///   - `CryptKit.Symmetric` if key type is `oct` and no algorithm is present.
    ///   - `JSONWebCertificateChain` if no key type is present but `x5c` has certificates.
    public func specialized() -> any JSONWebKey {
        for specializer in AnyJSONWebKey.specializers {
            if let specialized = try? specializer.specialize(self) {
                return specialized
            }
        }
        return self
    }
    
    /// Deserializes JSON and converts to the most appropriate key.
    ///
    /// - Parameters:
    ///   - data: The key data to deserialize.
    ///   - format: The format of the key data.
    /// - Returns: Related specific key object.
    public static func deserialize(_ data: Data, format _: JSONWebKeyFormat) throws -> any JSONWebKey {
        let webKey = try JSONDecoder().decode(AnyJSONWebKey.self, from: data)
        return webKey.specialized()
    }
}

/// A specializer that can convert a `AnyJSONWebKey` to a specific `JSONWebKey` type.
public protocol JSONWebKeySpecializer {
    /// Specializes a `AnyJSONWebKey` to a specific `JSONWebKey` type, returns `nil` if key is not appropriate.
    ///
    /// - Parameter key: The key to specialize.
    /// - Returns: A specific `JSONWebKey` type, or `nil` if the key is not appropriate.
    static func specialize(_ key: AnyJSONWebKey) throws -> (any JSONWebKey)?
    
    /// Deserializes a key from a data, returns `nil` if key is not appropriate.
    ///
    /// - Parameters:
    ///   - key: The key data to deserialize.
    ///   - format: The format of the key data.
    ///   - Returns: A specific `JSONWebKey` type, or `nil` if the key is not appropriate.
    static func deserialize<D>(key: D, format: JSONWebKeyFormat) throws -> (any JSONWebKey)? where D: DataProtocol
}

protocol JSONWebKeySpecializerByType: JSONWebKeySpecializer {
    static var supportedKeyTypes: [JSONWebKeyType] { get }
    
    static var supportedKeyCurves: [JSONWebKeyCurve]? { get }
    
    static var supportedAlgorithms: [any JSONWebAlgorithm]? { get }
    
    static var objectIdentifierGroup: String? { get }
    
    static var publicKeyType: (any (JSONWebKeyImportable & JSONWebKeyExportable & SendableMetatype).Type)? { get }
    
    static var privateKeyType: (any (JSONWebKeyImportable & JSONWebKeyExportable & SendableMetatype).Type)? { get }
    
    static var privateKeyParameter: String { get }
}

extension JSONWebKeySpecializerByType {
    public static var supportedKeyCurves: [JSONWebKeyCurve]? { nil }
    static var supportedAlgorithms: [any JSONWebAlgorithm]? { nil }
    static var objectIdentifierGroup: String? { nil }
    
    static var asn1OIDGroup: ASN1ObjectIdentifier? {
        if let objectIdentifierGroup = objectIdentifierGroup,
           let oidGroup = try? ASN1ObjectIdentifier(dotRepresentation: objectIdentifierGroup)
        {
            return oidGroup
        }
        return nil
    }
}

extension JSONWebKeySpecializerByType {
    static func derKeyContainer<D>(key: D, format: JSONWebKeyFormat) throws -> (any DERKeyContainer)? where D: DataProtocol {
        switch format {
        case .pkcs8:
            try PKCS8PrivateKey(derEncoded: key)
        case .spki:
            try SubjectPublicKeyInfo(derEncoded: key)
        default:
            nil
        }
    }
    
    public static func derDeserialize<D>(key: D, format: JSONWebKeyFormat) throws -> (any JSONWebKey)? where D: DataProtocol {
        guard let derContainer = try derKeyContainer(key: key, format: format) else {
            return nil
        }
        guard try supportedKeyTypes.contains(derContainer.keyType) else { return nil }
        if let curve = derContainer.keyCurve {
            guard supportedKeyCurves?.contains(curve) ?? false else { return nil }
        }
        
        switch format {
        case .pkcs8:
            guard let privateKeyType = privateKeyType else { return nil }
            return try privateKeyType.init(importing: key, format: format)
        case .spki:
            guard let publicKeyType = publicKeyType else { return nil }
            return try publicKeyType.init(importing: key, format: format)
        default:
            return nil
        }
    }
    
    public static func specialize(_ key: AnyJSONWebKey) throws -> (any JSONWebKey)? {
        guard let keyType = key.keyType, supportedKeyTypes.contains(keyType) else { return nil }
        if let curve = key.curve {
            guard supportedKeyCurves?.contains(curve) ?? false else { return nil }
        }
        
        if let supportedAlgorithms = supportedAlgorithms, let algorithm = key.algorithm {
            guard supportedAlgorithms.contains(where: { $0.rawValue == algorithm.rawValue }) else {
                return nil
            }
        }
        
        if key.storage.contains(key: privateKeyParameter) {
            guard let privateKeyType = privateKeyType else { return nil }
            return try privateKeyType.init(key)
        } else if let publicKeyType = publicKeyType {
            return try publicKeyType.init(key)
        } else {
            return nil
        }
    }
    
    public static func deserialize<D>(key: D, format: JSONWebKeyFormat) throws -> (any JSONWebKey)? where D: DataProtocol {
        guard let derContainer = try derKeyContainer(key: key, format: format) else {
            return nil
        }
        guard try supportedKeyTypes.contains(derContainer.keyType) else { return nil }
        if let curve = derContainer.keyCurve {
            guard supportedKeyCurves?.contains(curve) ?? false else { return nil }
        }
        
        if let objectIdentifierGroup = asn1OIDGroup {
            guard derContainer.algorithmIdentifier.algorithm.oidComponents.starts(with: objectIdentifierGroup.oidComponents) else {
                return nil
            }
        }
        
        switch format {
        case .pkcs8:
            guard let privateKeyType = privateKeyType else { return nil }
            return try privateKeyType.init(importing: key, format: format)
        case .spki:
            guard let publicKeyType = publicKeyType else { return nil }
            return try publicKeyType.init(importing: key, format: format)
        default:
            return nil
        }
    }
}

enum JSONWebKeyRSASpecializer: JSONWebKeySpecializerByType {
    static let supportedKeyTypes: [JSONWebKeyType] = [.rsa]
    
    static let publicKeyType: (any (JSONWebKeyExportable & JSONWebKeyImportable & SendableMetatype).Type)? = JSONWebRSAPublicKey.self
    
    static let privateKeyType: (any (JSONWebKeyExportable & JSONWebKeyImportable & SendableMetatype).Type)? = JSONWebRSAPrivateKey.self
    
    static let privateKeyParameter: String = "d"
}

enum JSONWebKeyEllipticCurveSpecializer: JSONWebKeySpecializerByType {
    static let supportedKeyTypes: [JSONWebKeyType] = [.ellipticCurve]
    
    static let supportedKeyCurves: [JSONWebKeyCurve]? = [.p256, .p384, .p521]
    
    static let publicKeyType: (any (JSONWebKeyExportable & JSONWebKeyImportable & SendableMetatype).Type)? = JSONWebECPublicKey.self
    
    static let privateKeyType: (any (JSONWebKeyExportable & JSONWebKeyImportable & SendableMetatype).Type)? = JSONWebECPrivateKey.self
    
    static let privateKeyParameter: String = "d"
}

enum JSONWebKeyCurve25519Specializer: JSONWebKeySpecializerByType {
    static let supportedKeyTypes: [JSONWebKeyType] = [.octetKeyPair]
    
    static let supportedKeyCurves: [JSONWebKeyCurve]? = [.ed25519, .x25519]
    
    static let publicKeyType: (any (JSONWebKeyExportable & JSONWebKeyImportable & SendableMetatype).Type)? = JSONWebECPublicKey.self
    
    static let privateKeyType: (any (JSONWebKeyExportable & JSONWebKeyImportable & SendableMetatype).Type)? = JSONWebECPrivateKey.self
    
    static let privateKeyParameter: String = "d"
}

enum JSONWebKeyAlgorithmKeyPairSigningSpecializer: JSONWebKeySpecializerByType {
    static let supportedKeyTypes: [JSONWebKeyType] = [.algorithmKeyPair]
    
    static let supportedAlgorithms: [any JSONWebAlgorithm]? = [
        .mldsa65Signature,
        .mldsa87Signature,
    ]
    
    static let objectIdentifiers: [ASN1ObjectIdentifier]? = .AlgorithmIdentifier.moduleLatticeDSAs
    
    static let publicKeyType: (any (JSONWebKeyExportable & JSONWebKeyImportable & SendableMetatype).Type)? = JSONWebMLDSAPublicKey.self
    
    static let privateKeyType: (any (JSONWebKeyExportable & JSONWebKeyImportable & SendableMetatype).Type)? = JSONWebMLDSAPrivateKey.self
    
    static let privateKeyParameter: String = "priv"
}

enum JSONWebKeySymmetricSpecializer: JSONWebKeySpecializer {
    static func specialize(_ key: AnyJSONWebKey) throws -> (any JSONWebKey)? {
        guard key.keyType == .symmetric else { return nil }
        guard key.keyValue != nil else {
            throw CryptoKitError.incorrectKeySize
        }
        
        switch key.algorithm ?? .unsafeNone {
        case .aesEncryptionGCM128, .aesEncryptionGCM192, .aesEncryptionGCM256:
            return try JSONWebKeyAESGCM(key)
        case .aesKeyWrap128, .aesKeyWrap192, .aesKeyWrap256:
            return try JSONWebKeyAESKW(key)
        case .aesEncryptionCBC128SHA256:
            return try JSONWebKeyAESCBCHMAC<SHA256>(key)
        case .aesEncryptionCBC192SHA384:
            return try JSONWebKeyAESCBCHMAC<SHA384>(key)
        case .aesEncryptionCBC256SHA512:
            return try JSONWebKeyAESCBCHMAC<SHA512>(key)
        case .hmacSHA256:
            return try JSONWebKeyHMAC<SHA256>(key)
        case .hmacSHA384:
            return try JSONWebKeyHMAC<SHA384>(key)
        case .hmacSHA512:
            return try JSONWebKeyHMAC<SHA512>(key)
        default:
            return try SymmetricKey(key)
        }
    }
    
    static func deserialize<D>(key: D, format: JSONWebKeyFormat) throws -> (any JSONWebKey)? where D: DataProtocol {
        switch format {
        case .raw:
            return try AnyJSONWebKey(SymmetricKey(importing: key, format: .raw)).specialized()
        case .pkcs8, .spki, .jwk:
            return nil
        }
    }
}

enum JSONWebKeyCertificateChainSpecializer: JSONWebKeySpecializer {
    static func specialize(_ key: AnyJSONWebKey) throws -> (any JSONWebKey)? {
#if canImport(X509) || canImport(CommonCrypto)
        if !key.certificateChain.isEmpty {
            return try JSONWebCertificateChain(key)
        }
#endif
        return nil
    }
    
    static func deserialize<D>(key _: D, format _: JSONWebKeyFormat) throws -> (any JSONWebKey)? where D: DataProtocol {
        nil
    }
}

extension AnyJSONWebKey {
    static let specializers: AtomicValue<[any JSONWebKeySpecializer.Type]> = [
        JSONWebKeyRSASpecializer.self,
        JSONWebKeyEllipticCurveSpecializer.self,
        JSONWebKeyCurve25519Specializer.self,
        JSONWebKeyCertificateChainSpecializer.self,
        JSONWebKeyAlgorithmKeyPairSigningSpecializer.self,
        JSONWebKeySymmetricSpecializer.self,
    ]
    
    /// Registers a new key specializer.
    ///
    /// - Important: The specializer will be checked against before already registered ones,
    ///     to allow overriding default registry.
    ///
    /// - Parameter specializer: The specializer to register.
    public static func registerSpecializer<S>(_ specializer: S.Type) where S: JSONWebKeySpecializer {
        guard !specializers.contains(where: { $0 == specializer }) else { return }
        specializers.insert(specializer, at: 0)
    }
}
