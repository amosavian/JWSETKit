//
//  Keys.swift
//
//
//  Created by Amir Abbas Mousavian on 9/5/23.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto

/// A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) [RFC7159](https://www.rfc-editor.org/rfc/rfc7159)
/// data structure that represents a cryptographic key.
@dynamicMemberLookup
public protocol JSONWebKey: JSONWebContainer, Expirable {
    /// Creates a thumbprint of current key specified in [RFC7638](https://www.rfc-editor.org/rfc/rfc7638).
    ///
    /// Valid formats for public keys are `spki` and `jwk`.  SPKI thumbprints are used in SSL-pinning.
    ///
    /// While it is possible to create a thumbprint for private keys, it is typically not useful to do so,
    /// as the thumbprint is a cryptographic hash of the key, and the private key contains all the information
    /// needed to compute the thumbprint. The public key is used to compute the thumbprint if private key is passed.
    ///
    /// - Important: A hash of a symmetric key has the potential to leak information about
    ///     the key value.  Thus, the JWK Thumbprint of a symmetric key should
    ///     typically be concealed from parties not in possession of the
    ///     symmetric key, unless in the application context, the cryptographic
    ///     hash used, such as SHA-256, is known to provide sufficient protection
    ///     against disclosure of the key value.
    ///
    /// - Parameters:
    ///   - format: Format of key that thumbprint will be calculated from.
    ///   - hashFunction: Algorithm of thumbprint hashing.
    ///
    /// - Returns: A new instance of thumbprint digest.
    func thumbprint<H>(format: JSONWebKeyFormat, using hashFunction: H.Type) throws -> H.Digest where H: HashFunction
    
    /// Creates a thumbprint `URI` of current key in `urn:ietf:params:oauth` namespace
    /// specified in [RFC9278](https://www.rfc-editor.org/rfc/rfc9278).
    ///
    /// Valid formats for public keys are `spki` and `jwk`.  SPKI thumbprints are used in SSL-pinning.
    ///
    /// While it is possible to create a thumbprint for private keys, it is typically not useful to do so,
    /// as the thumbprint is a cryptographic hash of the key, and the private key contains all the information
    /// needed to compute the thumbprint. The public key is used to compute the thumbprint if private key is passed.
    ///
    /// - Important: A hash of a symmetric key has the potential to leak information about
    ///     the key value.  Thus, the JWK Thumbprint of a symmetric key should
    ///     typically be concealed from parties not in possession of the
    ///     symmetric key, unless in the application context, the cryptographic
    ///     hash used, such as SHA-256, is known to provide sufficient protection
    ///     against disclosure of the key value.
    ///
    /// - Parameters:
    ///   - format: Format of key that thumbprint will be calculated from.
    ///   - hashFunction: Algorithm of thumbprint hashing.
    ///
    /// - Returns: A new instance of thumbprint digest in `urn:ietf:params:oauth` namespace.
    func thumbprintUri<H>(format: JSONWebKeyFormat, using hashFunction: H.Type) throws -> String where H: HashFunction
}

private func isEqualKey(_ lhs: (any JSONWebKey)?, _ rhs: (any JSONWebKey)?) -> Bool {
    guard let lhsThumbprint = try? lhs?.thumbprint(format: .jwk, using: SHA256.self),
          let rhsThumbprint = try? rhs?.thumbprint(format: .jwk, using: SHA256.self)
    else {
        return lhs == nil && rhs == nil
    }
    return lhsThumbprint == rhsThumbprint
}

@_documentation(visibility: private)
public func == <RHS: JSONWebKey>(lhs: any JSONWebKey, rhs: RHS) -> Bool {
    isEqualKey(lhs, rhs)
}

@_documentation(visibility: private)
public func == <RHS: JSONWebKey>(lhs: (any JSONWebKey)?, rhs: RHS) -> Bool {
    isEqualKey(lhs, rhs)
}

@_documentation(visibility: private)
public func == <RHS: JSONWebKey>(lhs: any JSONWebKey, rhs: RHS?) -> Bool {
    isEqualKey(lhs, rhs)
}

@_documentation(visibility: private)
public func == <RHS: JSONWebKey>(lhs: (any JSONWebKey)?, rhs: RHS?) -> Bool {
    isEqualKey(lhs, rhs)
}

@_documentation(visibility: private)
public func == <LHS: JSONWebKey>(lhs: LHS, rhs: any JSONWebKey) -> Bool {
    isEqualKey(lhs, rhs)
}

@_documentation(visibility: private)
public func == <LHS: JSONWebKey>(lhs: LHS, rhs: (any JSONWebKey)?) -> Bool {
    isEqualKey(lhs, rhs)
}

@_documentation(visibility: private)
public func == <LHS: JSONWebKey>(lhs: LHS?, rhs: any JSONWebKey) -> Bool {
    isEqualKey(lhs, rhs)
}

@_documentation(visibility: private)
public func == <LHS: JSONWebKey>(lhs: LHS?, rhs: (any JSONWebKey)?) -> Bool {
    isEqualKey(lhs, rhs)
}

@_documentation(visibility: private)
public func == <LHS: JSONWebKey, RHS: JSONWebKey>(lhs: LHS, rhs: RHS) -> Bool {
    isEqualKey(lhs, rhs)
}

/// A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) [RFC7159]
/// data structure that represents a cryptographic key.
@dynamicMemberLookup
public protocol MutableJSONWebKey: JSONWebKey, MutableJSONWebContainer {}

extension JSONWebValueStorage {
    fileprivate func normalizedField(_ key: String, blockSize _: Int? = nil) -> Self {
        var copy = self
        if let data = self[key] as Data? {
            copy[key] = data.drop(while: { $0 == 0 })
        }
        return copy
    }
}

extension JSONWebKey {
    var isAsymmetricPrivateKey: Bool {
        if self is any JSONWebPrivateKey {
            return true
        }
        
        // In case the key is not specialized we try to guess by parameters directly.
        // Both RSA and ECC has `"d"` parameter with different meaning.
        return storage.contains(key: "d") || storage.contains(key: "priv") || storage.contains(key: "seed")
    }
    
    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        self = try Self(storage: container.decode(JSONWebValueStorage.self))
    }
    
    @available(*, deprecated, renamed: "init(storage:)", message: "Use `init(storage:)` instead")
    public static func create(from storage: JSONWebValueStorage) throws -> Self {
        try Self(storage: storage)
    }
    
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(storage)
    }
    
    public func validate() throws {
        // swiftformat:disable:next redundantSelf
        guard let keyType = self.keyType else {
            throw JSONWebKeyError.unknownKeyType
        }
        try checkRequiredFields(keyType.requiredFields)
    }
    
    func checkRequiredFields(_ fields: String...) throws {
        try checkRequiredFields(fields)
    }
    
    func checkRequiredFields(_ fields: [String]) throws {
        for field in fields {
            if !storage.contains(key: field) {
                throw CryptoKitError.incorrectParameterSize
            }
        }
    }
    
    private static func jwkThumbprint<H>(of key: any JSONWebKey, using _: H.Type) throws -> H.Digest where H: HashFunction {
        // swiftformat:disable:next redundantSelf
        let keyFields = Set(key.keyType?.requiredFields ?? [])
        // Public key required values.
        let thumbprintKeys: Set<String> = Set([
            // Algorithm-specific keys
            "kty", "crv",
        ]).union(keyFields)
        let thumbprintStorage = key.storage
            .filter(thumbprintKeys.contains)
            .normalizedField("e")
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(thumbprintStorage)
        return H.hash(data: data)
    }
    
    public func thumbprint<H>(format: JSONWebKeyFormat, using hashFunction: H.Type) throws -> H.Digest where H: HashFunction {
        let key: any JSONWebKey
        switch self {
        case let self as any JSONWebSigningKey:
            key = self.publicKey
        case let self as any JSONWebDecryptingKey:
            key = self.publicKey
        default:
            key = self
        }
        switch format {
        case .spki:
            guard let self = key as? (any JSONWebKeyExportable) else {
                throw JSONWebKeyError.operationNotAllowed
            }
            let spki = try self.exportKey(format: .spki)
            return H.hash(data: spki)
        case .jwk:
            return try Self.jwkThumbprint(of: key, using: hashFunction)
        case .pkcs8, .raw:
            throw JSONWebKeyError.operationNotAllowed
        }
    }
    
    public func thumbprintUri<H>(format: JSONWebKeyFormat, using hashFunction: H.Type) throws -> String where H: HashFunction {
        let digest = try thumbprint(format: format, using: hashFunction)
        let digestValue = digest.data.urlBase64EncodedString()
        guard let hashFunction = H.self as? any NamedHashFunction.Type else {
            throw JSONWebKeyError.unknownAlgorithm
        }
        return "urn:ietf:params:oauth:\(format)-thumbprint:\(hashFunction.identifier):\(digestValue)"
    }
}

extension JSONWebKey {
    public func verifyDate(_ currentDate: Date) throws {
        // swiftformat:disable:next redundantSelf
        if let expiry = self.expiry, currentDate > expiry {
            throw JSONWebValidationError.tokenExpired(expiry: expiry)
        }
        // swiftformat:disable:next redundantSelf
        if let issuedAt = self.issuedAt, currentDate < issuedAt {
            throw JSONWebValidationError.tokenInvalidBefore(notBefore: issuedAt)
        }
    }
}

extension MutableJSONWebKey {
    /// Fill Key ID (`kid`) field with JWK's SHA256 thumbprint in URN format, if key is empty or nil.
    public mutating func populateKeyIdIfNeeded() {
        // swiftformat:disable:next redundantSelf
        guard self.keyId?.isEmpty ?? true else { return }
        guard let thumbprintUrn = try? thumbprintUri(format: .jwk, using: SHA256.self) else { return }
        // swiftformat:disable:next redundantSelf
        self.keyId = thumbprintUrn
    }
}

/// Private key of an asymmetric cryptography algorithm.
public protocol JSONWebPrivateKey<PublicKey>: JSONWebKey {
    associatedtype PublicKey: JSONWebKey
    
    /// Public key.
    var publicKey: PublicKey { get }
}

extension JSONWebPrivateKey where Self: Equatable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.publicKey == rhs.publicKey
    }
}
 
extension JSONWebPrivateKey where Self: Hashable {
    public func hash(into hasher: inout Hasher) {
        hasher.combine(publicKey)
    }
}

/// A JSON Web Key (JWK) able to encrypt plain-texts.
public protocol JSONWebEncryptingKey: JSONWebKey {
    /// Encrypts plain-text data using current key.
    ///
    /// - Parameters:
    ///   - data: Plain-text to be encrypted.
    ///   - algorithm: Algorithm of encryption.
    /// - Returns: Cipher-text data.
    func encrypt<D, JWA>(_ data: D, using algorithm: JWA) throws -> Data where D: DataProtocol, JWA: JSONWebAlgorithm
}

/// A JSON Web Key (JWK) able to decrypt cipher-texts.
public protocol JSONWebDecryptingKey: JSONWebEncryptingKey, JSONWebPrivateKey where PublicKey: JSONWebEncryptingKey {
    /// Generates new random key.
    init(algorithm: some JSONWebAlgorithm) throws
    
    /// Decrypts ciphered data using current key.
    ///
    /// - Parameters:
    ///   - data: Cipher-text that ought to be decrypted.
    ///   - algorithm: Algorithm of encryption.
    /// - Returns: Plain-text data
    func decrypt<D, JWA>(_ data: D, using algorithm: JWA) throws -> Data where D: DataProtocol, JWA: JSONWebAlgorithm
}

extension JSONWebDecryptingKey {
    public func encrypt<D, JWA>(_ data: D, using algorithm: JWA) throws -> Data where D: DataProtocol, JWA: JSONWebAlgorithm {
        try publicKey.encrypt(data, using: algorithm)
    }
}

/// A JSON Web Key (JWK) able to decrypt cipher-texts using a symmetric key.
public protocol JSONWebSymmetricDecryptingKey: JSONWebDecryptingKey, JSONWebKeySymmetric where PublicKey == Self {}

extension JSONWebKeySymmetric where Self: JSONWebPrivateKey {
    public var publicKey: Self { self }
    
    public init() throws {
        try self.init(.init(size: .bits256))
    }
}

/// A JSON Web Key (JWK) able to encrypt plain-texts with authentication-tag.
public protocol JSONWebSealingKey: JSONWebKey {
    /// Encrypts plain-text data using current key.
    ///
    /// - Parameters:
    ///   - data: Plain-text to be sealed.
    ///   - iv: Initial vector/Nouce.
    ///   - authenticating: Additional data to be authenticated.
    ///   - algorithm: Algorithm of encryption.
    /// - Returns: Cipher-text data with IV and authentication tag.
    func seal<D, IV, AAD, JWA>(
        _ data: D, iv: IV?,
        authenticating: AAD?,
        using algorithm: JWA
    ) throws -> SealedData where D: DataProtocol, IV: DataProtocol, AAD: DataProtocol, JWA: JSONWebAlgorithm
}

/// A JSON Web Key (JWK) able to decrypt plain-texts with authentication-tag.
public protocol JSONWebSealOpeningKey: JSONWebKey {
    /// Decrypts cipher-text data using current key.
    ///
    /// - Parameters:
    ///   - data: Plain-text to be decrypted.
    ///   - authenticating: Additional data to be authenticated.
    ///   - algorithm: Algorithm of encryption.
    /// - Returns: Cipher-text data with IV and authentication tag.
    func open<AAD, JWA>(_ data: SealedData, authenticating: AAD?, using algorithm: JWA) throws -> Data where AAD: DataProtocol, JWA: JSONWebAlgorithm
}

/// A JSON Web Key (JWK) able to encrypt/decrypt plain-texts with authentication-tag using symmetric key.
public protocol JSONWebSymmetricSealingKey: JSONWebKeySymmetric, JSONWebSealingKey, JSONWebSealOpeningKey {}

extension JSONWebSealingKey {
    /// Encrypts plain-text data using current key.
    ///
    /// - Parameters:
    ///   - data: Plain-text to be sealed.
    ///   - algorithm: Algorithm of encryption.
    /// - Returns: Cipher-text data with IV and authentication tag.
    func seal<D, JWA>(
        _ data: D, using algorithm: JWA
    ) throws -> SealedData where D: DataProtocol, JWA: JSONWebAlgorithm {
        try seal(data, iv: Data?.none, authenticating: Data?.none, using: algorithm)
    }
    
    /// Encrypts plain-text data using current key.
    ///
    /// - Parameters:
    ///   - data: Plain-text to be sealed.
    ///   - iv: Initial vector/Nouce.
    ///   - algorithm: Algorithm of encryption.
    /// - Returns: Cipher-text data with IV and authentication tag.
    func seal<D, IV, JWA>(
        _ data: D, iv: IV,
        using algorithm: JWA
    ) throws -> SealedData where D: DataProtocol, IV: DataProtocol, JWA: JSONWebAlgorithm {
        try seal(data, iv: iv, authenticating: Data?.none, using: algorithm)
    }
    
    /// Encrypts plain-text data using current key.
    ///
    /// - Parameters:
    ///   - data: Plain-text to be sealed.
    ///   - authenticating: Additional data to be authenticated.
    ///   - algorithm: Algorithm of encryption.
    /// - Returns: Cipher-text data with IV and authentication tag.
    func seal<D, AAD, JWA>(
        _ data: D, authenticating: AAD,
        using algorithm: JWA
    ) throws -> SealedData where D: DataProtocol, AAD: DataProtocol, JWA: JSONWebAlgorithm {
        try seal(data, iv: Data?.none, authenticating: authenticating, using: algorithm)
    }
}

extension JSONWebSealOpeningKey {
    /// Decrypts cipher-text data using current key.
    ///
    /// - Parameters:
    ///   - data: Plain-text to be decrypted.
    ///   - algorithm: Algorithm of encryption.
    /// - Returns: Cipher-text data with IV and authentication tag.
    func open<JWA>(_ data: SealedData, using algorithm: JWA) throws -> Data where JWA: JSONWebAlgorithm {
        try open(data, authenticating: Data?.none, using: algorithm)
    }
}

/// A JSON Web Key (JWK) able to validate a signaute.
public protocol JSONWebValidatingKey: JSONWebKey {
    /// Verifies the cryptographic signature of a block of data using a public key and specified algorithm.
    ///
    /// - Parameters:
    ///   - signature: The signature that must be validated.
    ///   - data: The data that was signed.
    ///   - algorithm: The algorithm that was used to create the signature.
    func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol
}

/// A JSON Web Key (JWK) able to generate a signature.
public protocol JSONWebSigningKey: JSONWebValidatingKey, JSONWebPrivateKey where PublicKey: JSONWebValidatingKey {
    /// Generates new random key.
    init(algorithm: some JSONWebAlgorithm) throws
    
    /// Creates the cryptographic signature for a block of data using a private key and specified algorithm.
    ///
    /// - Parameters:
    ///   - data: The data whose signature you want.
    ///   - algorithm: The signing algorithm to use.
    /// - Returns: The digital signature or throws error on failure.
    func signature<D>(_ data: D, using algorithm: JSONWebSignatureAlgorithm) throws -> Data where D: DataProtocol
}

extension JSONWebSigningKey {
    public func verifySignature<S, D>(_ signature: S, for data: D, using algorithm: JSONWebSignatureAlgorithm) throws where S: DataProtocol, D: DataProtocol {
        try publicKey.verifySignature(signature, for: data, using: algorithm)
    }
}

/// A JSON Web Key (JWK) able to generate a signature using a symmetric key.
public protocol JSONWebSymmetricSigningKey: JSONWebSigningKey, JSONWebKeySymmetric {}

/// A type-erased general container for a JSON Web Key (JWK).
///
/// - Note: To create a key able to do operations (sign, verify, encrypt, decrypt) use `specialized()` method.
@frozen
public struct AnyJSONWebKey: MutableJSONWebKey, JSONWebKeyRSAType, JSONWebKeyCurveType, JSONWebKeySymmetric, JSONWebKeyAlgorithmKeyPairType, Sendable {
    public var storage: JSONWebValueStorage
    
    /// Returns a new concrete key using json data.
    ///
    /// - Parameter storage: Storage of key-values.
    @inlinable
    public init(storage: JSONWebValueStorage) {
        self.storage = storage
    }
    
    /// A type-erased JWK value.
    ///
    /// - Parameter key: Key to wrap.
    @inlinable
    public init(_ key: any JSONWebKey) {
        self.storage = key.storage
    }
    
    /// Initializes `AnyJSONWebKey` from symmetric key parameters.
    ///
    /// - Parameter key: symmetric key that type-erased JWK must be initialized from
    public init(_ key: SymmetricKey) throws {
        self.storage = .init()
        self.keyType = .symmetric
        self.keyValue = key
    }
    
    @inlinable
    init() {
        self.storage = .init()
    }
}

extension JSONWebKey {
    @inlinable
    public init(from key: any JSONWebKey) throws {
        try self.init(storage: key.storage)
    }
    
    @inlinable
    public init(_ key: AnyJSONWebKey) throws {
        try self.init(storage: key.storage)
    }
}

extension AnyJSONWebKey: JSONWebKeyImportable, JSONWebKeyExportable {
    public init<D>(importing key: D, format: JSONWebKeyFormat) throws where D: DataProtocol {
        if format == .jwk {
            let key = try JSONDecoder().decode(AnyJSONWebKey.self, from: Data(key)).specialized()
            try key.validate()
            self.storage = key.storage
            return
        }
        for specializer in AnyJSONWebKey.specializers {
            if let specialized = try specializer.deserialize(key: key, format: format) {
                self.storage = specialized.storage
            }
        }
        throw JSONWebKeyError.unknownKeyType
    }
    
    public func exportKey(format: JSONWebKeyFormat) throws -> Data {
        guard let key = specialized() as? any JSONWebKeyExportable else {
            throw JSONWebKeyError.invalidKeyFormat
        }
        
        return try key.exportKey(format: format)
    }
}
