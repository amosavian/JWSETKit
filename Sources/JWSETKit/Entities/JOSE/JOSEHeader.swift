//
//  JOSEHeader.swift
//
//
//  Created by Amir Abbas Mousavian on 9/5/23.
//

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// For a JWS, the members of the JSON object(s) representing the JOSE Header
/// describe the digital signature or MAC applied to the JWS Protected Header
/// and the JWS Payload and optionally additional properties of the JWS.
@dynamicMemberLookup
public struct JOSEHeader: JSONWebContainer {
    public var storage: JSONWebValueStorage
    
    /// Initialzes a new JOSE header with given key/values.
    ///
    /// - Parameter storage: Header key/values.
    public init(storage: JSONWebValueStorage) {
        self.storage = storage
    }
    
    /// Initializes an empty JOSE header.
    public init() {
        self.storage = .init()
    }
    
    /// Initializes a JOSE header with given algorithm, type and key ID if exists.
    ///
    /// - Parameters:
    ///   - algorithm: Contains JWA to deremine signing/encryption algorithm.
    ///   - type: Payload type, usually `"JWT"` for JSON Web Token.
    ///   - keyId: Key ID that generated signature.
    public init(algorithm: JSONWebAlgorithm, type: String, keyId: String? = nil) {
        self.storage = .init()
        self.algorithm = algorithm
        self.type = type
        self.keyId = keyId
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> JOSEHeader {
        .init(storage: storage)
    }
}
