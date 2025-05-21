//
//  KeyAccessors.swift
//
//
//  Created by Amir Abbas Mousavian on 9/7/23.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto
import X509

/// The properties of the revocation.
public struct JSONWebKeyRevocation: Codable, Hashable, Sendable {
    /// Identifies the reason for the key revocation.
    public struct Reason: StringRepresentable {
        public let rawValue: String
        
        public init(rawValue: String) {
            self.rawValue = rawValue
        }
        
        /// General or unspecified reason for the JWK status change.
        public static let unspecified = Self(rawValue: "unspecified")
        
        /// The private key is believed to have been compromised.
        public static let compromised = Self(rawValue: "compromised")
        
        /// The JWK is no longer active.
        public static let superseded = Self(rawValue: "superseded")
    }
    
    enum CodingKeys: String, CodingKey {
        case revokedAt = "revoked_at"
        case reason
    }
    
    /// Time when the key was revoked or must be considered revoked, using the time format defined for the iat claim
    public let time: Date?
    
    /// Identifies the reason for the key revocation.
    public let reason: Reason?
    
    /// Creates a new instance of `JSONWebKeyRevocation`.
    public init(at time: Date? = nil, for reason: Reason? = nil) {
        self.time = time
        self.reason = reason
    }
    
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.time = try container.decodeIfPresent(Double.self, forKey: .revokedAt).map(Date.init(timeIntervalSince1970:))
        self.reason = try container.decodeIfPresent(JSONWebKeyRevocation.Reason.self, forKey: .reason)
    }
    
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent((time?.timeIntervalSince1970).map(Int.init), forKey: .revokedAt)
        try container.encodeIfPresent(reason, forKey: .reason)
    }
}

/// Registered JSON Web Key (JWK) general tokens in [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517).
public struct JSONWebKeyRegisteredParameters {
    /// The "`kty`" (key type) parameter identifies the cryptographic algorithm family
    /// used with the key, such as "RSA" or "EC".
    ///
    /// "`kty`" values should either be registered in the IANA "JSON Web Key Types" registry
    /// established by [JWA] or be a value that contains a Collision-Resistant Name.
    /// The "kty" value is a case-sensitive string.
    ///
    /// This member MUST be present in a JWK.
    public var keyType: JSONWebKeyType?
    
    /// The "`use`" (public key use) parameter identifies the intended use of the public key.
    /// The "`use`" parameter is employed to indicate whether a public key is used
    /// for encrypting data or verifying the signature on data.
    ///
    /// Values defined by this specification are:
    /// - "`sig`" (signature)
    /// - "`enc`" (encryption)
    ///
    /// Other values MAY be used.  The "`use`" value is a case-sensitive string.
    ///
    /// Use of the "`use`" member is OPTIONAL, unless the application requires its presence.
    public var keyUsage: JSONWebKeyUsage?
    
    /// The "`key_ops`" (key operations) parameter identifies the operation(s)
    /// for which the key is intended to be used.
    /// The "`key_ops`" parameter is intended for use cases in which public, private,
    /// or symmetric keys may be present.
    ///
    /// Its value is an array of key operation values.  Values defined by this specification are:
    /// - "`sign`" (compute digital signature or MAC)
    /// - "`verify`" (verify digital signature or MAC)
    /// - "`encrypt`" (encrypt content)
    /// - "`decrypt`" (decrypt content and validate decryption, if applicable)
    /// - "`wrapKey`" (encrypt key)
    /// - "`unwrapKey`" (decrypt key and validate decryption, if applicable)
    /// - "`deriveKey`" (derive key)
    /// - "`deriveBits`" (derive bits not to be used as a key)
    public var keyOperations: [JSONWebKeyOperation]
    
    /// The "alg" (algorithm) parameter identifies the algorithm intended for use with the key.
    /// The values used should either be registered in
    /// the IANA "JSON Web Signature and Encryption Algorithms" registry established
    /// by [JWA] or be a value that contains a Collision-Resistant Name.
    ///
    /// The "alg" value is a case-sensitive ASCII string.
    ///
    /// Use of this member is OPTIONAL.
    public var algorithm: (any JSONWebAlgorithm)?
    
    /// ECC curve or the subtype of key pair.
    public var curve: JSONWebKeyCurve?
    
    /// The "`kid`" (key ID) parameter is used to match a specific key.
    ///
    /// This is used, for instance, to choose among a set of keys within a JWK Set during key rollover.
    /// The structure of the "`kid`" value is unspecified.
    /// When "kid" values are used within a JWK Set, different keys within the JWK Set
    /// SHOULD use distinct "`kid`" values.  (One example in which different keys might use
    /// the same "`kid`" value is if they have different "`kty`" (key type) values
    /// but are considered to be equivalent alternatives by the application using them.)
    /// The "kid" value is a case-sensitive string.
    ///
    /// Use of this member is OPTIONAL.
    ///
    /// When used with JWS or JWE, the "kid" value is used to match a JWS or
    /// JWE "`kid`" Header Parameter value.
    public var keyId: String?
    
    /// The "`exp`" (expiration time) claim identifies the expiration time on or
    /// after which the key MUST NOT be accepted for processing.
    ///
    /// The processing of the "`exp`" claim requires that the current date/time MUST
    /// be before the expiration date/time listed in the "`exp`" claim.
    ///
    /// Implementers MAY provide for some small leeway, usually no more than a few minutes,
    /// to account for clock skew.
    ///
    /// Its value MUST be a number containing a `NumericDate` value.
    ///
    /// Use of this claim is OPTIONAL.
    public var expiry: Date?
    
    /// The "`iat`" (issued at) claim identifies the time at which the key was issued.
    ///
    /// This claim can be used to determine the age of the key.
    /// Its value MUST be a number containing a `NumericDate` value.
    ///
    /// Use of this claim is OPTIONAL.
    public var issuedAt: Date?
    
    /// Contains the properties of the revocation including time and reason..
    public var revoked: JSONWebKeyRevocation?
    
    /// The "`x5u`" (X.509 URL) Header Parameter is a URI that refers to a resource
    /// for the X.509 public key certificate or certificate chain corresponding
    /// to the key used to digitally sign the `JWS`.
    ///
    /// The identified resource MUST provide a representation of the certificate or
    /// certificate chain that conforms to RFC 5280 in PEM-encoded form,
    /// Section 6.1 of RFC 4945 [RFC4945].
    ///
    /// The certificate containing the public key corresponding to
    /// the key used to digitally sign the `JWS` MUST be the first certificate.
    /// certificates, with each subsequent certificate being the one used to certify the previous one.
    ///
    /// Use of this Header Parameter is OPTIONAL.
    public var certificateURL: URL?
    
    /// The "x5c" (X.509 certificate chain) Header Parameter contains
    /// the X.509 public key certificate or certificate chain [RFC5280] corresponding
    /// to the key used to digitally sign the JWS.
    ///
    /// The certificate or certificate chain is represented as a JSON array of certificate value strings.
    /// Each string in the array is a `base64-encoded` (Section 4 of [RFC4648]
    /// -- not base64url-encoded) DER [ITU.X690.2008] PKIX certificate value.
    public var certificateChain: [Certificate]
    
    /// The "`x5t`"/"`x5t#S256`" (X.509 certificate SHA-1/256 thumbprint)
    /// Header Parameter is a `base64url-encoded` SHA-1/256 thumbprint
    /// (a.k.a. digest) of the `DER` encoding of the X.509 certificate [RFC5280]
    /// corresponding to the key used to digitally sign the `JWS`.
    ///
    /// Note that certificate thumbprints are also sometimes known as certificate fingerprints.
    ///
    /// Use of this Header Parameter is OPTIONAL.
    public var certificateThumbprint: Data?
    
    fileprivate static let keys: [SendablePartialKeyPath<Self>: String] = [
        \.keyType: "kty", \.keyUsage: "use", \.keyOperations: "key_ops",
        \.algorithm: "alg", \.curve: "crv", \.keyId: "kid",
        \.certificateURL: "x5u", \.certificateChain: "x5c", \.certificateThumbprint: "x5t",
        \.expiry: "exp", \.issuedAt: "iat", \.revoked: "revoked",
    ]
}

/// Registered JSON Web Key (JWK) RSA tokens in [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517).
public struct JSONWebKeyRegisteredRSAParameters {
    /// RSA Public key modulus.
    public var modulus: Data?
    
    /// RSA public key exponent.
    public var exponent: Data?
    
    /// RSA private key private exponent.
    public var privateExponent: Data?
    
    /// RSA private key first prime factor.
    public var firstPrimeFactor: Data?
    
    /// RSA private key second prime factor.
    public var secondPrimeFactor: Data?
    
    /// RSA private key first factor CRT exponent.
    public var firstFactorCRTExponent: Data?
    
    /// RSA private key second factor CRT exponent.
    public var secondFactorCRTExponent: Data?
    
    /// RSA private key first CRT coefficient.
    public var firstCRTCoefficient: Data?
    
    fileprivate static let keys: [SendablePartialKeyPath<Self>: String] = [
        \.modulus: "n", \.exponent: "e",
        \.privateExponent: "d", \.firstPrimeFactor: "p", \.secondPrimeFactor: "q",
        \.firstFactorCRTExponent: "dp", \.secondFactorCRTExponent: "dq",
        \.firstCRTCoefficient: "qi", // \.otherPrimesInfo: "oth",
    ]
}

/// Registered JSON Web Key (JWK) EC/Ed tokens in [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517).
public struct JSONWebKeyRegisteredCurveParameters {
    /// ECC public key X coordinate component or the public key of key pair.
    public var xCoordinate: Data?
    
    /// ECC public keyY Coordinate.
    public var yCoordinate: Data?
    
    /// ECC Private Key.
    public var privateKey: Data?
    
    fileprivate static let keys: [SendablePartialKeyPath<Self>: String] = [
        \.xCoordinate: "x", \.yCoordinate: "y",
        \.privateKey: "d",
    ]
}

/// Registered JSON Web Key (JWK) symmetric tokens in [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517).
public struct JSONWebKeyRegisteredSymmetricParameters {
    /// Symmetric Key Value.
    public var keyValue: SymmetricKey?
    
    fileprivate static let keys: [SendablePartialKeyPath<Self>: String] = [
        \.keyValue: "k",
    ]
}

/// Registered JSON Web Key (JWK) for Algorithm Key Pair (AKP) tokens.
public struct JSONWebKeyRegisteredAKPParameters {
    /// Public Key Value.
    public var publicKey: Data?
    
    /// Private Key Value.
    public var privateKey: Data?
    
    /// Seed used to derive keys for an algorithm
    public var seed: Data?
    
    fileprivate static let keys: [SendablePartialKeyPath<Self>: String] = [
        \.publicKey: "pub", \.privateKey: "priv", \.seed: "seed",
    ]
}

extension String {
    @usableFromInline
    static let x5tS256 = "x5t#S256"
}

public protocol JSONWebKeyRSAType: JSONWebKey {}

public protocol JSONWebKeyCurveType: JSONWebKey {}

public protocol JSONWebKeyAlgorithmKeyPairType: JSONWebKey {}

extension JSONWebKey {
    @usableFromInline
    func stringKey<T>(_ keyPath: SendableKeyPath<JSONWebKeyRegisteredParameters, T>) -> String {
        if let key = JSONWebKeyRegisteredParameters.keys[keyPath] {
            return key
        }
        return keyPath.name.jsonWebKey
    }
    
    @_documentation(visibility: private)
    @inlinable
    public subscript<T: JSONWebValueStorage.ValueType>(dynamicMember keyPath: SendableKeyPath<JSONWebKeyRegisteredParameters, T?>) -> T? {
        storage[stringKey(keyPath)]
    }
    
    @_documentation(visibility: private)
    @inlinable
    public subscript<T: JSONWebValueStorage.ValueType>(dynamicMember keyPath: SendableKeyPath<JSONWebKeyRegisteredParameters, [T]>) -> [T] {
        storage[stringKey(keyPath)]
    }
    
    @_documentation(visibility: private)
    public subscript(dynamicMember keyPath: SendableKeyPath<JSONWebKeyRegisteredParameters, (any JSONWebAlgorithm)?>) -> (any JSONWebAlgorithm)? {
        storage[stringKey(keyPath)].map(AnyJSONWebAlgorithm.specialized)
    }
    
    @_documentation(visibility: private)
    public subscript(dynamicMember keyPath: SendableKeyPath<JSONWebKeyRegisteredParameters, Data?>) -> Data? {
        switch keyPath {
        case \.certificateThumbprint where storage.contains(key: .x5tS256):
            return storage[.x5tS256]
        default:
            return storage[stringKey(keyPath)]
        }
    }
}

extension MutableJSONWebKey {
    @_documentation(visibility: private)
    @inlinable
    public subscript<T: JSONWebValueStorage.ValueType>(dynamicMember keyPath: SendableKeyPath<JSONWebKeyRegisteredParameters, T?>) -> T? {
        get {
            storage[stringKey(keyPath)]
        }
        set {
            storage[stringKey(keyPath)] = newValue
        }
    }
    
    @_documentation(visibility: private)
    @inlinable
    public subscript<T: JSONWebValueStorage.ValueType>(dynamicMember keyPath: SendableKeyPath<JSONWebKeyRegisteredParameters, [T]>) -> [T] {
        get {
            storage[stringKey(keyPath)]
        }
        set {
            storage[stringKey(keyPath)] = newValue
        }
    }
    
    @_documentation(visibility: private)
    public subscript(dynamicMember keyPath: SendableKeyPath<JSONWebKeyRegisteredParameters, (any JSONWebAlgorithm)?>) -> (any JSONWebAlgorithm)? {
        get {
            storage[stringKey(keyPath)].map(AnyJSONWebAlgorithm.specialized)
        }
        set {
            storage[stringKey(keyPath)] = newValue?.rawValue
        }
    }
    
    @_documentation(visibility: private)
    public subscript(dynamicMember keyPath: SendableKeyPath<JSONWebKeyRegisteredParameters, Data?>) -> Data? {
        get {
            switch keyPath {
            case \.certificateThumbprint where storage.contains(key: .x5tS256):
                return storage[.x5tS256]
            default:
                return storage[stringKey(keyPath)]
            }
        }
        set {
            switch keyPath {
            case \.certificateThumbprint where newValue?.count == SHA256.byteCount:
                storage[.x5tS256] = newValue
            default:
                storage[stringKey(keyPath)] = newValue
            }
        }
    }
}

extension JSONWebKeyRSAType {
    @usableFromInline
    func stringKey<T>(_ keyPath: SendableKeyPath<JSONWebKeyRegisteredRSAParameters, T>) -> String {
        if let key = JSONWebKeyRegisteredRSAParameters.keys[keyPath] {
            return key
        }
        return keyPath.name.jsonWebKey
    }
    
    @_documentation(visibility: private)
    @inlinable
    public subscript<T: JSONWebValueStorage.ValueType>(dynamicMember keyPath: SendableKeyPath<JSONWebKeyRegisteredRSAParameters, T?>) -> T? {
        storage[stringKey(keyPath)]
    }
}

extension JSONWebKeyRSAType where Self: MutableJSONWebKey {
    @_documentation(visibility: private)
    @inlinable
    public subscript<T: JSONWebValueStorage.ValueType>(dynamicMember keyPath: SendableKeyPath<JSONWebKeyRegisteredRSAParameters, T?>) -> T? {
        get {
            storage[stringKey(keyPath)]
        }
        set {
            storage[stringKey(keyPath)] = newValue
        }
    }
}

extension JSONWebKeyCurveType {
    @usableFromInline
    func stringKey<T>(_ keyPath: SendableKeyPath<JSONWebKeyRegisteredCurveParameters, T>) -> String {
        if let key = JSONWebKeyRegisteredCurveParameters.keys[keyPath] {
            return key
        }
        return keyPath.name.jsonWebKey
    }
    
    @_documentation(visibility: private)
    @inlinable
    public subscript<T: JSONWebValueStorage.ValueType>(dynamicMember keyPath: SendableKeyPath<JSONWebKeyRegisteredCurveParameters, T?>) -> T? {
        storage[stringKey(keyPath)]
    }
}

extension JSONWebKeyCurveType where Self: MutableJSONWebKey {
    @_documentation(visibility: private)
    @inlinable
    public subscript<T: JSONWebValueStorage.ValueType>(dynamicMember keyPath: SendableKeyPath<JSONWebKeyRegisteredCurveParameters, T?>) -> T? {
        get {
            storage[stringKey(keyPath)]
        }
        set {
            storage[stringKey(keyPath)] = newValue
        }
    }
}

extension JSONWebKeySymmetric {
    @usableFromInline
    func stringKey<T>(_ keyPath: SendableKeyPath<JSONWebKeyRegisteredSymmetricParameters, T>) -> String {
        if let key = JSONWebKeyRegisteredSymmetricParameters.keys[keyPath] {
            return key
        }
        return keyPath.name.jsonWebKey
    }
    
    @_documentation(visibility: private)
    @inlinable
    public subscript<T: JSONWebValueStorage.ValueType>(dynamicMember keyPath: SendableKeyPath<JSONWebKeyRegisteredSymmetricParameters, T?>) -> T? {
        storage[stringKey(keyPath)]
    }
}

extension JSONWebKeySymmetric where Self: MutableJSONWebKey {
    @_documentation(visibility: private)
    @inlinable
    public subscript<T: JSONWebValueStorage.ValueType>(dynamicMember keyPath: SendableKeyPath<JSONWebKeyRegisteredSymmetricParameters, T?>) -> T? {
        get {
            storage[stringKey(keyPath)]
        }
        set {
            storage[stringKey(keyPath)] = newValue
        }
    }
}

extension JSONWebKeyAlgorithmKeyPairType {
    @usableFromInline
    func stringKey<T>(_ keyPath: SendableKeyPath<JSONWebKeyRegisteredAKPParameters, T>) -> String {
        if let key = JSONWebKeyRegisteredAKPParameters.keys[keyPath] {
            return key
        }
        return keyPath.name.jsonWebKey
    }
    
    @_documentation(visibility: private)
    @inlinable
    public subscript<T: JSONWebValueStorage.ValueType>(dynamicMember keyPath: SendableKeyPath<JSONWebKeyRegisteredAKPParameters, T?>) -> T? {
        storage[stringKey(keyPath)]
    }
}

extension JSONWebKeyAlgorithmKeyPairType where Self: MutableJSONWebKey {
    @_documentation(visibility: private)
    @inlinable
    public subscript<T: JSONWebValueStorage.ValueType>(dynamicMember keyPath: SendableKeyPath<JSONWebKeyRegisteredAKPParameters, T?>) -> T? {
        get {
            storage[stringKey(keyPath)]
        }
        set {
            storage[stringKey(keyPath)] = newValue
        }
    }
}
