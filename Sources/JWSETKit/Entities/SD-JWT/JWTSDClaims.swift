//
//  JWTSDClaims.swift
//  JWSETKit
//
//  Created by Amir Abbas Mousavian on 9/11/25.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto

/// Selective disclosure parameters in JWT payload. [See this.](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/)
public struct JSONWebTokenClaimsSelectiveDisclosureParameters: JSONWebContainerParameters {
    /// Hash algorithm used to generate Disclosure digests and digest over presentation.
    ///
    /// The claim `_sd_alg` indicates the hash algorithm used by the Issuer to
    /// generate the digests as described in Section 4.2.  When used, this
    /// claim MUST appear at the top level of the SD-JWT payload.  It MUST
    /// NOT be used in any object nested within the payload.  If the `_sd_alg`
    /// claim is not present at the top level, a default value of `sha-256`
    /// MUST be used.
    public var disclosureHashAlgorithm: JSONWebHashAlgorithm?
    
    /// Digests of Disclosures for object properties.
    public var disclosureHashes: [Data]
    
    /// The `base64url`-encoded hash value over the Issuer-signed JWT and the selected Disclosures.
    public var selectiveDisclosureHash: Data?
    
    @_documentation(visibility: private)
    public static let keys: [SendablePartialKeyPath<Self>: String] = [
        \.disclosureHashAlgorithm: "_sd_alg", \.disclosureHashes: "_sd", \.selectiveDisclosureHash: "sd_hash",
    ]
}

extension JSONWebTokenClaims {
    @_documentation(visibility: private)
    @inlinable
    public subscript<T: JSONWebValueStorage.ValueType>(dynamicMember keyPath: SendableKeyPath<JSONWebTokenClaimsSelectiveDisclosureParameters, T?>) -> T? {
        get {
            storage[stringKey(keyPath)]
        }
        set {
            storage[stringKey(keyPath)] = newValue
        }
    }
    
    @_documentation(visibility: private)
    @inlinable
    public subscript<T: JSONWebValueStorage.ValueType>(dynamicMember keyPath: SendableKeyPath<JSONWebTokenClaimsSelectiveDisclosureParameters, [T]>) -> [T] {
        get {
            storage[stringKey(keyPath)]
        }
        set {
            storage[stringKey(keyPath)] = newValue
        }
    }
    
    @_documentation(visibility: private)
    @inlinable
    public subscript(dynamicMember keyPath: SendableKeyPath<JSONWebTokenClaimsSelectiveDisclosureParameters, JSONWebHashAlgorithm?>) -> JSONWebHashAlgorithm? {
        get {
            if let hashFunction = storage[stringKey(keyPath)]
                .map(JSONWebHashAlgorithm.init(rawValue:))
            {
                return hashFunction
            } else if storage.contains(key: "_sd") {
                return SHA256.identifier
            } else {
                return nil
            }
        }
        set {
            storage[stringKey(keyPath)] = newValue?.rawValue
        }
    }
}
