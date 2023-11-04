//
//  JOSE-JWSRegistered.swift
//
//
//  Created by Amir Abbas Mousavian on 9/7/23.
//

import Foundation
import X509
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Registered parameters of JOSE header in [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html).
public struct JoseHeaderJWSRegisteredParameters: JSONWebContainerParameters {
    public typealias Container = JOSEHeader
    /// The "`alg`" (algorithm) Header Parameter identifies the cryptographic algorithm used to secure the JWS.
    ///
    /// The JWS Signature value is not valid if the "`alg`" value does not represent
    /// a supported algorithm or if there is not a key for use with that algorithm associated
    /// with the party that digitally signed or MACed the content.
    ///
    /// "`alg`" values should either be registered in the IANA
    /// "JSON Web Signature and Encryption Algorithms" registry established by [JWA]
    /// or be a value that contains a Collision-Resistant Name.
    ///
    /// The "`alg`" value is a case-sensitive ASCII string containing a `StringOrURI` value.
    ///
    /// This Header Parameter MUST be present and MUST be understood and processed by implementations.
    public var algorithm: any JSONWebAlgorithm
    
    /// The "`jku`" (JWK Set URL) Header Parameter is a URI  that
    /// refers to a resource for a set of JSON-encoded public keys,
    /// one of which corresponds to the key used to digitally sign the `JWS`.
    ///
    /// The keys MUST be encoded as a `JWK` Set.
    public var jsonWebKeySetUrl: URL?
    
    /// The "`jwk`" (JSON Web Key) Header Parameter is the public key that corresponds
    /// to the key used to digitally sign the `JWS`.
    ///
    /// This key is represented as a JSON Web Key [`JWK`].
    ///
    /// Use of this Header Parameter is OPTIONAL.
    public var key: (any JSONWebKey)?
    
    /// The "kid" (key ID) Header Parameter is a hint indicating which key was used to secure the JWS.
    ///
    /// This parameter allows originators to explicitly signal a change of key to recipients.
    /// The structure of the "`kid`" value is unspecified.
    /// Its value MUST be a case-sensitive string.
    ///
    /// Use of this Header Parameter is OPTIONAL.
    ///
    /// When used with a `JWK`, the "`kid`" value is used to match a `JWK` "`kid`" parameter value.
    public var keyId: String?
    
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
    
    /// The "`typ`" (type) Header Parameter is used by JWS applications
    /// to declare the media type [IANA.MediaTypes] of this complete JWS.
    ///
    /// This is intended for use by the application when more than one kind of object
    /// could be present in an application data structure that can contain a JWS;
    /// the application can use this value to disambiguate among the different
    /// kinds of objects that might be present.
    /// It will typically not be used by applications when the kind of object is already known.
    /// This parameter is ignored by JWS implementations;
    /// any processing of this parameter is performed by the JWS application.
    ///
    /// Use of this Header Parameter is OPTIONAL.
    public var type: JSONWebContentType?
    
    /// The "`cty`" (content type) Header Parameter is used by JWS applications
    /// to declare the media type [IANA.MediaTypes] of the secured content (the payload).
    ///
    /// This is intended for use by the application when more than one kind of object
    /// could be present in the JWS Payload;
    /// the application can use this value to disambiguate among the different kinds
    /// of objects that might be present.
    /// It will typically not be used by applications when the kind of object is already known.
    /// This parameter is ignored by JWS implementations; any processing of
    /// this parameter is performed by the JWS application.
    ///
    /// Use of this Header Parameter is OPTIONAL.
    public var contentType: JSONWebContentType?
    
    /// The "`crit`" (critical) Header Parameter indicates that extensions to this specification and/or [JWA]
    /// are being used that MUST be understood and processed.
    ///
    /// Its value is an array listing the Header Parameter names present in
    /// the JOSE Header that use those extensions.
    /// If any of the listed extension Header Parameters are not understood and
    /// supported by the recipient, then the JWS is invalid.
    ///
    /// Producers MUST NOT include Header Parameter names defined by this specification
    /// or [JWA] for use with JWS, duplicate names, or names that do not occur as
    /// Header Parameter names within the JOSE Header in the "crit" list.
    /// Producers MUST NOT use the empty list "[]" as the "crit" value.
    /// Recipients MAY consider the JWS to be invalid if the critical list contains
    /// any Header Parameter names defined by this specification or [JWA]
    /// for use with JWS or if any other constraints on its use are violated.
    /// When used, this Header Parameter MUST be integrity protected; therefore,
    /// it MUST occur only within the JWS Protected Header.
    ///
    /// Use of this Header Parameter is OPTIONAL.
    ///
    /// This Header Parameter MUST be understood and processed by implementations.
    public var critical: [String]
    
    /// The "`nonce`" header parameter provides a unique value that enables
    /// the verifier of a JWS to recognize when replay has occurred.
    ///
    /// The "`nonce`" header parameter MUST be carried in the protected header of the JWS.
    public var nonce: String?
    
    /// The "`url`" header parameter specifies the URL to which this JWS object is directed.
    ///
    /// The "`url`" header parameter MUST be carried in the protected header of the JWS.
    /// The value of the "`url`" header parameter MUST be a string representing the target URL.
    public var url: URL?
    
    /// The "`b64`"  header parameter specifies the payload is encoded with `Base64URL` or not.
    ///
    /// The value is `true` if not present
    public var base64: Bool?
    
    @_documentation(visibility: private)
    public static let keys: [PartialKeyPath<Self>: String] = [
        \.algorithm: "alg", \.jsonWebKeySetUrl: "jku",
        \.key: "jwk", \.keyId: "kid", \.certificateChain: "x5c",
        \.certificateURL: "x5u", \.certificateThumbprint: "x5t",
        \.type: "typ", \.contentType: "cty", \.critical: "crit",
        \.base64: "b64",
    ]
}

extension JOSEHeader {
    @_documentation(visibility: private)
    public subscript<T>(dynamicMember keyPath: KeyPath<JoseHeaderJWSRegisteredParameters, T?>) -> T? {
        get {
            storage[stringKey(keyPath)]
        }
        set {
            storage[stringKey(keyPath)] = newValue
        }
    }
    
    @_documentation(visibility: private)
    public subscript(dynamicMember keyPath: KeyPath<JoseHeaderJWSRegisteredParameters, [String]>) -> [String] {
        get {
            storage[stringKey(keyPath)]
        }
        set {
            storage[stringKey(keyPath)] = newValue
        }
    }
    
    @_documentation(visibility: private)
    public subscript(dynamicMember keyPath: KeyPath<JoseHeaderJWSRegisteredParameters, any JSONWebAlgorithm>) -> any JSONWebAlgorithm {
        get {
            storage[stringKey(keyPath)].map(AnyJSONWebAlgorithm.specialized) ?? .none
        }
        set {
            storage[stringKey(keyPath)] = newValue.rawValue
        }
    }
    
    @_documentation(visibility: private)
    public subscript(dynamicMember keyPath: KeyPath<JoseHeaderJWSRegisteredParameters, [Certificate]>) -> [Certificate] {
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
    public subscript(dynamicMember keyPath: KeyPath<JoseHeaderJWSRegisteredParameters, Data?>) -> Data? {
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
