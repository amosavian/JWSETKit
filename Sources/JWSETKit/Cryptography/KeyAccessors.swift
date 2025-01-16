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

/// Registered JSON Web Key (JWK) tokens in [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517).
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
    
    /// ECC curve or the subtype of key pair.
    public var curve: JSONWebKeyCurve?
    
    /// ECC public key X coordinate component or the public key of key pair.
    public var xCoordinate: Data?
    
    /// ECC public keyY Coordinate.
    public var yCoordinate: Data?
    
    /// ECC Private Key.
    public var privateKey: Data?
    
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
    
    /// Symmetric Key Value.
    public var keyValue: SymmetricKey?
    
    fileprivate static let keys: [PartialKeyPath<Self>: String] = [
        \.keyType: "kty", \.keyUsage: "use", \.keyOperations: "key_ops",
        \.algorithm: "alg", \.keyId: "kid", \.expiry: "exp", \.issuedAt: "iat",
        \.certificateURL: "x5u", \.certificateChain: "x5c", \.revoked: "revoked",
        \.certificateThumbprint: "x5t",
        \.curve: "crv", \.xCoordinate: "x", \.yCoordinate: "y",
        \.privateKey: "d", \.modulus: "n", \.exponent: "e",
        \.privateExponent: "d", \.firstPrimeFactor: "p", \.secondPrimeFactor: "q",
        \.firstFactorCRTExponent: "dp", \.secondFactorCRTExponent: "dq",
        \.firstCRTCoefficient: "qi", // \.otherPrimesInfo: "oth",
        \.keyValue: "k",
    ]
}

extension String {
    static let x5tS256 = "x5t#S256"
}

extension JSONWebKey {
    fileprivate func stringKey<T>(_ keyPath: KeyPath<JSONWebKeyRegisteredParameters, T>) -> String {
        if let key = JSONWebKeyRegisteredParameters.keys[keyPath] {
            return key
        }
        return keyPath.name.jsonWebKey
    }
    
    @_documentation(visibility: private)
    public subscript<T: JSONWebValueStorage.ValueType>(dynamicMember keyPath: KeyPath<JSONWebKeyRegisteredParameters, T?>) -> T? {
        storage[stringKey(keyPath)]
    }
    
    @_documentation(visibility: private)
    public subscript(dynamicMember keyPath: KeyPath<JSONWebKeyRegisteredParameters, [String]>) -> [String] {
        storage[stringKey(keyPath)]
    }
    
    @_documentation(visibility: private)
    public subscript(dynamicMember keyPath: KeyPath<JSONWebKeyRegisteredParameters, [JSONWebKeyOperation]>) -> [JSONWebKeyOperation] {
        storage[stringKey(keyPath)]
    }
    
    @_documentation(visibility: private)
    public subscript(dynamicMember keyPath: KeyPath<JSONWebKeyRegisteredParameters, (any JSONWebAlgorithm)?>) -> (any JSONWebAlgorithm)? {
        storage[stringKey(keyPath)].map(AnyJSONWebAlgorithm.specialized)
    }
    
    @_documentation(visibility: private)
    public subscript(dynamicMember keyPath: KeyPath<JSONWebKeyRegisteredParameters, [Certificate]>) -> [Certificate] {
        storage[stringKey(keyPath), false]
            .compactMap {
                try? .init(derEncoded: $0)
            }
    }
    
    @_documentation(visibility: private)
    public subscript(dynamicMember keyPath: KeyPath<JSONWebKeyRegisteredParameters, SymmetricKey?>) -> SymmetricKey? {
        (storage[stringKey(keyPath), true] as Data?).map(SymmetricKey.init(data:))
    }
    
    @_documentation(visibility: private)
    public subscript(dynamicMember keyPath: KeyPath<JSONWebKeyRegisteredParameters, Data?>) -> Data? {
        switch keyPath {
        case \.certificateThumbprint where storage.contains(key: .x5tS256):
            return storage[.x5tS256, true]
        default:
            return storage[stringKey(keyPath), true]
        }
    }
}

extension MutableJSONWebKey {
    @_documentation(visibility: private)
    public subscript<T: JSONWebValueStorage.ValueType>(dynamicMember keyPath: KeyPath<JSONWebKeyRegisteredParameters, T?>) -> T? {
        get {
            storage[stringKey(keyPath)]
        }
        set {
            storage[stringKey(keyPath)] = newValue
        }
    }
    
    @_documentation(visibility: private)
    public subscript(dynamicMember keyPath: KeyPath<JSONWebKeyRegisteredParameters, [String]>) -> [String] {
        get {
            storage[stringKey(keyPath)]
        }
        set {
            storage[stringKey(keyPath)] = newValue
        }
    }
    
    @_documentation(visibility: private)
    public subscript(dynamicMember keyPath: KeyPath<JSONWebKeyRegisteredParameters, [JSONWebKeyOperation]>) -> [JSONWebKeyOperation] {
        get {
            storage[stringKey(keyPath)]
        }
        set {
            storage[stringKey(keyPath)] = newValue
        }
    }
    
    @_documentation(visibility: private)
    public subscript(dynamicMember keyPath: KeyPath<JSONWebKeyRegisteredParameters, (any JSONWebAlgorithm)?>) -> (any JSONWebAlgorithm)? {
        get {
            storage[stringKey(keyPath)].map(AnyJSONWebAlgorithm.specialized)
        }
        set {
            storage[stringKey(keyPath)] = newValue?.rawValue
        }
    }
    
    @_documentation(visibility: private)
    public subscript(dynamicMember keyPath: KeyPath<JSONWebKeyRegisteredParameters, [Certificate]>) -> [Certificate] {
        get {
            storage[stringKey(keyPath), false]
                .compactMap {
                    try? .init(derEncoded: $0)
                }
        }
        set {
            storage[stringKey(keyPath), false] = newValue.compactMap {
                try? $0.derRepresentation
            }
        }
    }
    
    @_documentation(visibility: private)
    public subscript(dynamicMember keyPath: KeyPath<JSONWebKeyRegisteredParameters, SymmetricKey?>) -> SymmetricKey? {
        get {
            (storage[stringKey(keyPath), true] as Data?).map(SymmetricKey.init(data:))
        }
        set {
            storage[stringKey(keyPath), true] = newValue?.data
        }
    }
    
    @_documentation(visibility: private)
    public subscript(dynamicMember keyPath: KeyPath<JSONWebKeyRegisteredParameters, Data?>) -> Data? {
        get {
            switch keyPath {
            case \.certificateThumbprint where storage.contains(key: .x5tS256):
                return storage[.x5tS256, true]
            default:
                return storage[stringKey(keyPath), true]
            }
        }
        set {
            switch keyPath {
            case \.certificateThumbprint where newValue?.count == SHA256.byteCount:
                storage[.x5tS256, true] = newValue
            default:
                storage[stringKey(keyPath), true] = newValue
            }
        }
    }
}
