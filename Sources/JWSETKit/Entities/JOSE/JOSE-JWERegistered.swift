//
//  JOSE-JWERegistered.swift
//
//
//  Created by Amir Abbas Mousavian on 9/7/23.
//

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

public struct JoseHeaderJWERegisteredParameters {
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
    public var encryptionAlgorithm: JSONWebAlgorithm?
    
    /// The "zip" (compression algorithm) applied to the plaintext before encryption, if any.
    ///
    /// The "zip" value defined by this specification is:
    /// -  "DEF" - Compression with the DEFLATE [RFC1951] algorithm
    public var compressionAlgorithm: JSONWebCompressionAlgorithm?
    
    fileprivate static let keys: [PartialKeyPath<Self>: String] = [
        \.encryptionAlgorithm: "enc", \.compressionAlgorithm: "zip",
    ]
}

extension JOSEHeader {
    private func stringKey<T>(_ keyPath: KeyPath<JoseHeaderJWERegisteredParameters, T>) -> String {
        if let key = JoseHeaderJWERegisteredParameters.keys[keyPath] {
            return key
        }
        return String(reflecting: keyPath).components(separatedBy: ".").last!.jsonWebKey
    }
    
    public subscript<T>(dynamicMember keyPath: KeyPath<JoseHeaderJWERegisteredParameters, T?>) -> T? {
        get {
            storage[stringKey(keyPath)]
        }
        set {
            storage[stringKey(keyPath)] = newValue
        }
    }
    
    public subscript(dynamicMember keyPath: KeyPath<JoseHeaderJWERegisteredParameters, [String]>) -> [String] {
        get {
            storage[stringKey(keyPath)]
        }
        set {
            storage[stringKey(keyPath)] = newValue
        }
    }
    
    public subscript(dynamicMember keyPath: KeyPath<JoseHeaderJWERegisteredParameters, JSONWebAlgorithm>) -> JSONWebAlgorithm {
        get {
            storage[stringKey(keyPath)] ?? .none
        }
        set {
            storage[stringKey(keyPath)] = newValue
        }
    }
}
