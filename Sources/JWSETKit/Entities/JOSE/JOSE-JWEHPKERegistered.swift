//
//  JOSE-JWEHPKERegistered.swift
//  JWSETKit
//
//  Created by Amir Abbas Mousavian on 1/31/25.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto

/// Registered parameters of JOSE header in [Draft JOSE-HPKE](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt-11#section-10.2.1 ).
public struct JoseHeaderJWEHPKERegisteredParameters: JSONWebContainerParameters {
    public typealias Container = JOSEHeader
    /// An encapsulated key as defined in [Section 5.1.1 of RFC9180](https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1.1 ).
    public var encapsulatedKey: Data?
    
    /// A key identifier (`kid`) for the pre-shared key as defined in [Section 5.1.2 of RFC9180](https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1.2 ).
    var presharedKeyId: Data?
    
    @_documentation(visibility: private)
    public static let keys: [SendablePartialKeyPath<Self>: String] = [
        \.encapsulatedKey: "ek", \.presharedKeyId: "psk_id",
    ]
}

extension JOSEHeader {
    @_documentation(visibility: private)
    @inlinable
    public subscript<T: JSONWebValueStorage.ValueType>(dynamicMember keyPath: SendableKeyPath<JoseHeaderJWEHPKERegisteredParameters, T?>) -> T? {
        get {
            storage[stringKey(keyPath)]
        }
        set {
            storage[stringKey(keyPath)] = newValue
        }
    }
}
