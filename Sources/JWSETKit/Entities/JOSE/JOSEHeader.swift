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
    
    public init(storage: JSONWebValueStorage) {
        self.storage = storage
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> JOSEHeader {
        .init(storage: storage)
    }
}
