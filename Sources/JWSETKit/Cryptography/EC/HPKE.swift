//
//  HPKE.swift
//  JWSETKit
//
//  Created by Amir Abbas Mousavian on 1/26/25.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto

@available(iOS 17.0, macOS 14.0, watchOS 10.0, tvOS 17.0, *)
extension HPKE.Ciphersuite {
    /// A cipher suite for HPKE that uses NIST P-256 elliptic curve key agreement, SHA-2 key derivation
    /// with a 256-bit digest, and the Advanced Encryption Standard cipher in Galois/Counter Mode with a key length of 128 bits.
    public static let P256_SHA256_AES_GCM_128: HPKE.Ciphersuite = .init(kem: .P256_HKDF_SHA256, kdf: .HKDF_SHA256, aead: .AES_GCM_128)
    
    /// A cipher suite for HPKE that uses X25519 elliptic curve key agreement, SHA-2 key derivation
    /// with a 256-bit digest, and the Advanced Encryption Standard cipher in Galois/Counter Mode with a key length of 128 bits.
    public static let Curve25519_SHA256_AES_GCM_128: HPKE.Ciphersuite = .init(kem: .Curve25519_HKDF_SHA256, kdf: .HKDF_SHA256, aead: .AES_GCM_128)
    
    public init(algorithm: some JSONWebAlgorithm) throws {
        switch JSONWebKeyEncryptionAlgorithm(algorithm) {
        case .hpkeP256SHA256AESGCM128:
            self = .P256_SHA256_AES_GCM_128
        case .hpkeP256SHA256AESGCM256:
            self = .P256_SHA256_AES_GCM_256
        case .hpkeP384SHA384AESGCM256:
            self = .P384_SHA384_AES_GCM_256
        case .hpkeP521SHA512AESGCM256:
            self = .P521_SHA512_AES_GCM_256
        case .hpkeCurve25519SHA256AESGCM128:
            self = .Curve25519_SHA256_AES_GCM_128
        case .hpkeCurve25519SHA256ChachaPoly:
            self = .Curve25519_SHA256_ChachaPoly
        default:
            throw JSONWebKeyError.unknownAlgorithm
        }
    }
    
    static func ~= (lhs: Self, rhs: Self) -> Bool {
        (lhs.kem, lhs.kdf, lhs.aead) == (rhs.kem, rhs.kdf, rhs.aead)
    }
}

@available(iOS 17.0, macOS 14.0, watchOS 10.0, tvOS 17.0, *)
extension HPKE.KEM {
    public var curve: JSONWebKeyCurve? {
        switch self {
        case .P256_HKDF_SHA256:
            .p256
        case .P384_HKDF_SHA384:
            .p384
        case .P521_HKDF_SHA512:
            .p521
        case .Curve25519_HKDF_SHA256:
            .x25519
#if compiler(>=6.2) || !canImport(CryptoKit)
        case .XWingMLKEM768X25519:
            .x25519
#endif
        @unknown default:
            nil
        }
    }
    
    public var hashFunction: (any HashFunction.Type)? {
        switch self {
        case .P256_HKDF_SHA256, .Curve25519_HKDF_SHA256:
            SHA256.self
        case .P384_HKDF_SHA384:
            SHA384.self
        case .P521_HKDF_SHA512:
            SHA512.self
#if compiler(>=6.2) || !canImport(CryptoKit)
        case .XWingMLKEM768X25519:
            SHA256.self
#endif
        @unknown default:
            nil
        }
    }
}

@available(iOS 17.0, macOS 14.0, watchOS 10.0, tvOS 17.0, *)
extension HPKE.KDF {
    public var hashFunction: (any HashFunction.Type)? {
        switch self {
        case .HKDF_SHA256:
            SHA256.self
        case .HKDF_SHA384:
            SHA384.self
        case .HKDF_SHA512:
            SHA512.self
        @unknown default:
            nil
        }
    }
}

@available(iOS 17.0, macOS 14.0, watchOS 10.0, tvOS 17.0, *)
extension Crypto.HPKE.Ciphersuite: @unchecked Swift.Sendable {}

@available(iOS 17.0, macOS 14.0, watchOS 10.0, tvOS 17.0, *)
struct JSONWebHPKESender: JSONWebSealingKey, JSONWebEncryptingKey {
    let storage: JSONWebValueStorage
    let sender: HPKE.Sender
    
    var encapsulatedKey: Data {
        sender.encapsulatedKey
    }
    
    init(storage _: JSONWebValueStorage) throws {
        throw JSONWebKeyError.operationNotAllowed
    }
    
    init<PK>(recipientKey: PK, recipientHeader: JOSEHeader, extraInfo: Data = Data()) throws where PK: HPKEDiffieHellmanPublicKey {
        guard let keyEncryptingAlgorithm = JSONWebKeyEncryptionAlgorithm(recipientHeader.algorithm) else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        guard let contentEncryptionAlgorithm = recipientHeader.encryptionAlgorithm else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        let info = Data("JOSE-HPKE rcpt".utf8) + [0xFF] + Data(contentEncryptionAlgorithm.rawValue.utf8) + [0xFF] + extraInfo
        self.sender = try .init(recipientKey: recipientKey, ciphersuite: .init(algorithm: keyEncryptingAlgorithm), info: info)
        if var recipientKey = (recipientKey as? any JSONWebKey).map(AnyJSONWebKey.init) {
            recipientKey.algorithm = keyEncryptingAlgorithm
            self.storage = recipientKey.storage
        } else {
            assertionFailure("Key must be conformed to JSONWebKey")
            self.storage = .init()
        }
    }
    
    func seal<D, IV, AAD, JWA>(_ data: D, iv _: IV?, authenticating: AAD?, using _: JWA) throws -> SealedData where D: DataProtocol, IV: DataProtocol, AAD: DataProtocol, JWA: JSONWebAlgorithm {
        var hpkeSender = sender
        if let authenticating {
            return try .init(combined: hpkeSender.seal(data, authenticating: authenticating), nonceLength: 0, tagLength: 0)
        } else {
            return try .init(combined: hpkeSender.seal(data), nonceLength: 0, tagLength: 0)
        }
    }
    
    func encrypt<D, JWA>(_ data: D, using algorithm: JWA) throws -> Data where D: DataProtocol, JWA: JSONWebAlgorithm {
        try seal(data, using: algorithm).ciphertext
    }
    
    static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.sender.encapsulatedKey == rhs.sender.encapsulatedKey
    }
    
    func hash(into hasher: inout Hasher) {
        hasher.combine(sender.encapsulatedKey)
    }
}

@available(iOS 17.0, macOS 14.0, watchOS 10.0, tvOS 17.0, *)
struct JSONWebHPKERecipient: JSONWebSealOpeningKey, JSONWebDecryptingKey {
    var publicKey: JSONWebHPKESender {
        fatalError()
    }
    
    typealias PublicKey = JSONWebHPKESender
    
    var storage: JSONWebValueStorage
    let recipient: HPKE.Recipient
    
    var exported: Data {
        (try? recipient.exportSecret(context: Data(), outputByteCount: 16).data) ?? Data()
    }
    
    init(storage _: JSONWebValueStorage) throws {
        throw JSONWebKeyError.operationNotAllowed
    }
    
    init(algorithm _: some JSONWebAlgorithm) throws {
        throw JSONWebKeyError.operationNotAllowed
    }
    
    init<SK>(privateKey: SK, recipientHeader: JOSEHeader, extraInfo: Data = Data(), encapsulatedKey: Data) throws where SK: HPKEDiffieHellmanPrivateKey {
        guard let keyEncryptingAlgorithm = JSONWebKeyEncryptionAlgorithm(recipientHeader.algorithm) else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        guard let contentEncryptionAlgorithm = recipientHeader.encryptionAlgorithm else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        let encapsulatedKeyData = switch recipientHeader.encryptionAlgorithm {
        case .integrated:
            encapsulatedKey
        default:
            recipientHeader.encapsulatedKey ?? .init()
        }
        
        let info = Data("JOSE-HPKE rcpt".utf8) + [0xFF] + Data(contentEncryptionAlgorithm.rawValue.utf8) + [0xFF] + extraInfo
        self.recipient = try HPKE.Recipient(
            privateKey: privateKey,
            ciphersuite: .init(algorithm: keyEncryptingAlgorithm),
            info: info,
            encapsulatedKey: encapsulatedKeyData
        )
        if var privateKey = (privateKey as? any JSONWebKey).map(AnyJSONWebKey.init) {
            privateKey.algorithm = keyEncryptingAlgorithm
            self.storage = privateKey.storage
        } else {
            assertionFailure("Key must be conformed to JSONWebKey")
            self.storage = .init()
        }
    }
    
    func open<AAD, JWA>(_ data: SealedData, authenticating: AAD?, using _: JWA) throws -> Data where AAD: DataProtocol, JWA: JSONWebAlgorithm {
        var recipient = recipient
        if let authenticating {
            return try recipient.open(data.ciphertext, authenticating: authenticating)
        } else {
            return try recipient.open(data.ciphertext)
        }
    }
    
    func decrypt<D, JWA>(_ data: D, using algorithm: JWA) throws -> Data where D: DataProtocol, JWA: JSONWebAlgorithm {
        try open(.init(combined: data, nonceLength: 0, tagLength: 0), using: algorithm)
    }
    
    static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.exported == rhs.exported
    }
    
    func hash(into hasher: inout Hasher) {
        hasher.combine(exported)
    }
}

extension JSONWebKeyEncryptionAlgorithm {
    @available(iOS 17.0, macOS 14.0, watchOS 10.0, tvOS 17.0, *)
    public init(_ cipherSuite: HPKE.Ciphersuite) throws {
        switch cipherSuite {
        case .P256_SHA256_AES_GCM_128:
            self = .hpkeP256SHA256AESGCM128
        case .P256_SHA256_AES_GCM_256:
            self = .hpkeP256SHA256AESGCM256
        case .P384_SHA384_AES_GCM_256:
            self = .hpkeP384SHA384AESGCM256
        case .P521_SHA512_AES_GCM_256:
            self = .hpkeP521SHA512AESGCM256
        case .Curve25519_SHA256_AES_GCM_128:
            self = .hpkeCurve25519SHA256AESGCM128
        case .Curve25519_SHA256_ChachaPoly:
            self = .hpkeCurve25519SHA256ChachaPoly
        default:
            throw JSONWebKeyError.unknownAlgorithm
        }
    }
}

extension JSONWebKeyEncryptionAlgorithm {
    /// Cipher suite for JOSE-HPKE using the DHKEM(P-256, HKDF-SHA256) KEM, the HKDF-SHA256 KDF
    /// and the AES-128-GCM AEAD
    @available(iOS 17.0, macOS 14.0, watchOS 10.0, tvOS 17.0, *)
    public static let hpkeP256SHA256AESGCM128: Self = .internalHpkeP256SHA256AESGCM128
    
    /// Cipher suite for JOSE-HPKE using the DHKEM(P-256, HKDF-SHA256) KEM, the HKDF-SHA256 KDF
    /// and the AES-256-GCM AEAD
    public static let hpkeP256SHA256AESGCM256: Self = .internalHpkeP256SHA256AESGCM256
    
    /// Cipher suite for JOSE-HPKE using the DHKEM(P-384, HKDF-SHA384) KEM, the HKDF-SHA384 KDF,
    /// and the AES-256-GCM AEAD
    @available(iOS 17.0, macOS 14.0, watchOS 10.0, tvOS 17.0, *)
    public static let hpkeP384SHA384AESGCM256: Self = .internalHpkeP384SHA384AESGCM256
    
    /// Cipher suite for JOSE-HPKE using the DHKEM(P-521, HKDF-SHA512) KEM, the HKDF-SHA512 KDF,
    /// and the AES-256-GCM AEAD
    @available(iOS 17.0, macOS 14.0, watchOS 10.0, tvOS 17.0, *)
    public static let hpkeP521SHA512AESGCM256: Self = .internalHpkeP521SHA512AESGCM256
    
    /// Cipher suite for JOSE-HPKE using the DHKEM(X25519, HKDF-SHA256) KEM, the HKDF-SHA256 KDF,
    /// and the AES-128-GCM AEAD
    @available(iOS 17.0, macOS 14.0, watchOS 10.0, tvOS 17.0, *)
    public static let hpkeCurve25519SHA256AESGCM128: Self = .internalHpkeCurve25519SHA256AESGCM128
    
    /// Cipher suite for JOSE-HPKE using the DHKEM(X25519, HKDF-SHA256) KEM, the HKDF-SHA256 KDF,
    /// and the ChaCha20Poly1305 AEAD
    @available(iOS 17.0, macOS 14.0, watchOS 10.0, tvOS 17.0, *)
    public static let hpkeCurve25519SHA256ChachaPoly: Self = .internalHpkeCurve25519SHA256ChachaPoly
    
    // These are for internal registration use.
    static let internalHpkeP256SHA256AESGCM128: Self = "HPKE-0"
    static let internalHpkeP384SHA384AESGCM256: Self = "HPKE-1"
    static let internalHpkeP521SHA512AESGCM256: Self = "HPKE-2"
    static let internalHpkeCurve25519SHA256AESGCM128: Self = "HPKE-3"
    static let internalHpkeCurve25519SHA256ChachaPoly: Self = "HPKE-4"
    static let internalHpkeP256SHA256AESGCM256: Self = "HPKE-7"
    
    /// Cipher suite for JOSE-HPKE using the DHKEM(P-256, HKDF-SHA256) KEM, the HKDF-SHA256 KDF
    /// and the AES-128-GCM AEAD
    @available(*, unavailable, renamed: "hpkeP256SHA256AESGCM128")
    public static let hpke0: Self = .internalHpkeP256SHA256AESGCM128
    
    /// Cipher suite for JOSE-HPKE using the DHKEM(P-384, HKDF-SHA384) KEM, the HKDF-SHA384 KDF,
    /// and the AES-256-GCM AEAD
    @available(*, unavailable, renamed: "hpkeP384SHA384AESGCM256")
    public static let hpke1: Self = .internalHpkeP384SHA384AESGCM256
    
    /// Cipher suite for JOSE-HPKE using the DHKEM(P-521, HKDF-SHA512) KEM, the HKDF-SHA512 KDF,
    /// and the AES-256-GCM AEAD
    @available(*, unavailable, renamed: "hpkeP521SHA512AESGCM256")
    public static let hpke2: Self = .internalHpkeP521SHA512AESGCM256
    
    /// Cipher suite for JOSE-HPKE using the DHKEM(X25519, HKDF-SHA256) KEM, the HKDF-SHA256 KDF,
    /// and the AES-128-GCM AEAD
    @available(*, unavailable, renamed: "hpkeCurve25519SHA256AESGCM128")
    public static let hpke3: Self = .internalHpkeCurve25519SHA256AESGCM128
    
    /// Cipher suite for JOSE-HPKE using the DHKEM(X448, HKDF-SHA512) KEM, the HKDF-SHA512 KDF,
    /// and the AES-256-GCM AEAD
    @available(*, unavailable, renamed: "hpkeCurve25519SHA256ChachaPoly")
    public static let hpke4: Self = .internalHpkeCurve25519SHA256ChachaPoly
    
    /// Cipher suite for JOSE-HPKE using the DHKEM(P-256, HKDF-SHA256) KEM, the HKDF-SHA256 KDF
    /// and the AES-256-GCM AEAD
    @available(*, unavailable, renamed: "hpkeP256SHA256AESGCM256")
    public static let hpke7: Self = .internalHpkeP256SHA256AESGCM256
}
