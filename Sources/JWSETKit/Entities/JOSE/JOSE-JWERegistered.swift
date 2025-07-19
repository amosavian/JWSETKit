//
//  JOSE-JWERegistered.swift
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

/// Registered parameters of JOSE header in [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html ).
public struct JoseHeaderJWERegisteredParameters: JSONWebContainerParameters {
    /// The "`enc`" (encryption algorithm) Header Parameter identifies
    /// the content encryption algorithm used to perform authenticated encryption
    /// on the plaintext to produce the ciphertext and the Authentication Tag.
    ///
    /// This algorithm MUST be an AEAD algorithm with a specified key length.
    ///
    /// The encrypted content is not usable if the "`enc`" value does not represent a supported algorithm.
    /// "`enc`" values should either be registered in
    /// the IANA "JSON Web Signature and Encryption Algorithms" registry established
    /// by [JWA] or be a value that contains a Collision-Resistant Name.
    ///
    /// The "enc" value is a case-sensitive ASCII string containing a `StringOrURI` value.
    ///
    /// This Header Parameter MUST be present and MUST be understood and processed by implementations.
    public var encryptionAlgorithm: JSONWebContentEncryptionAlgorithm?
    
    /// The "zip" (compression algorithm) applied to the plaintext before encryption, if any.
    ///
    /// The "zip" value defined by this specification is:
    /// -  "DEF" - Compression with the DEFLATE [RFC1951] algorithm
    public var compressionAlgorithm: JSONWebCompressionAlgorithm?
    
    /// The "`epk`" (ephemeral public key) value created by the originator for
    /// the use in key agreement algorithms.
    ///
    /// This key is represented as a JSON Web Key (JWK) public key value.
    /// It MUST contain only public key parameters and SHOULD contain only
    /// the minimum JWK parameters necessary to represent the key;
    /// other JWK parameters included can be checked for consistency and honored,
    /// or they can be ignored.
    public var ephemeralPublicKey: AnyJSONWebKey?
    
    /// The "`apu`" (agreement PartyUInfo) value for key agreement algorithms
    /// using it (such as "`ECDH-ES`"), represented as a `base64url`-encoded string.
    ///
    /// When used, the PartyUInfo value contains information about
    /// the producer.  Use of this Header Parameter is OPTIONAL.
    ///
    /// This Header Parameter MUST be understood and processed by
    /// implementations when these algorithms are used.
    public var agreementPartyUInfo: Data?
    
    /// The "`apv`" (agreement PartyVInfo) value for key agreement algorithms
    /// using it (such as "`ECDH-ES`"), represented as a `base64url` encoded string.
    ///
    /// When used, the PartyVInfo value contains information about
    /// the recipient.  Use of this Header Parameter is OPTIONAL.
    ///
    /// This Header Parameter MUST be understood and processed by
    /// implementations when these algorithms are used.
    public var agreementPartyVInfo: Data?
    
    /// The "`iv`" (initialization vector) Header Parameter value is the
    /// `base64url-encoded` representation of the 96-bit IV value used for the
    /// key encryption operation.
    ///
    /// This Header Parameter MUST be present and MUST be understood and
    /// processed by implementations when these algorithms are used.
    public var initialVector: Data?
    
    /// The "`tag`" (authentication tag) Header Parameter value is the
    /// `base64url-encoded` representation of the 128-bit Authentication Tag
    /// value resulting from the key encryption operation.
    ///
    /// This Header Parameter MUST be present and MUST be understood and processed by
    /// implementations when these algorithms are used.
    public var authenticationTag: Data?
    
    /// The "`p2s`" (`PBES2` salt input) Header Parameter encodes a Salt Input
    /// value, which is used as part of the `PBKDF2` salt value.
    ///
    /// The "`p2s`" value is `BASE64URL(Salt Input)`.
    ///
    /// This Header Parameter MUST be present and MUST be understood
    /// and processed by implementations when these algorithms are used.
    ///
    /// A Salt Input value containing 8 or more octets MUST be used.
    /// A new Salt Input value MUST be generated randomly for every
    /// encryption operation; see RFC 4086 for considerations on
    /// generating random values.  The salt value used is `(UTF8(Alg) || 0x00 || Salt Input)`,
    /// where Alg is the "`alg`" (algorithm) Header Parameter value.
    public var pbes2Salt: Data?
    
    /// The "`p2c`" (`PBES2` count) Header Parameter contains the `PBKDF2`
    /// iteration count, represented as a positive JSON integer.
    ///
    /// This Header Parameter MUST be present and MUST be understood and processed by
    /// implementations when these algorithms are used.
    ///
    /// The iteration count adds computational expense, ideally compounded by
    /// the possible range of keys introduced by the salt.  A minimum
    /// iteration count of 1000 is RECOMMENDED. (600,000 by OWASP as of 2023)
    public var pbes2Count: Int?
    
    @_documentation(visibility: private)
    public static let keys: [SendablePartialKeyPath<Self>: String] = [
        \.encryptionAlgorithm: "enc", \.compressionAlgorithm: "zip",
        \.ephemeralPublicKey: "epk", \.agreementPartyUInfo: "apu", \.agreementPartyVInfo: "apv",
        \.initialVector: "iv", \.authenticationTag: "tag",
        \.pbes2Salt: "p2s", \.pbes2Count: "p2c",
    ]
}

extension JOSEHeader {
    @_documentation(visibility: private)
    @inlinable
    public subscript<T: JSONWebValueStorage.ValueType>(dynamicMember keyPath: SendableKeyPath<JoseHeaderJWERegisteredParameters, T?>) -> T? {
        get {
            storage[stringKey(keyPath)]
        }
        set {
            storage[stringKey(keyPath)] = newValue
        }
    }
}
