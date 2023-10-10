//
//  JWEHeader.swift
//
//
//  Created by Amir Abbas Mousavian on 10/3/23.
//

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Represents a signature or MAC over the JWS Payload and the JWS Protected Header.
public struct JSONWebEncryptionHeader: Hashable, Codable {
    enum CodingKeys: CodingKey {
        case protected
        case unprotected
    }
    
    /// JWE Protected Header.
    ///
    /// JSON object that contains the Header Parameters that are integrity
    /// protected by the authenticated encryption operation.
    ///
    /// These parameters apply to all recipients of the JWE.  For the JWE
    /// Compact Serialization, this comprises the entire JOSE Header.  For
    /// the JWE JSON Serialization, this is one component of the JOSE Header.
    public var protected: ProtectedJSONWebContainer<JOSEHeader>
    
    /// JWE Shared Unprotected Header
    ///
    /// JSON object that contains the Header Parameters that apply to all
    /// recipients of the JWE that are not integrity protected.  This can
    /// only be present when using the JWE JSON Serialization.
    public var unprotected: JOSEHeader?
    
    /// Creates a new JWR header using components.
    ///
    /// - Parameters:
    ///   - header: JWE Protected Header.
    ///   - unprotected: JWE Shared Unprotected Header.
    public init(protected: ProtectedJSONWebContainer<JOSEHeader>, unprotected: JOSEHeader? = nil) throws {
        self.protected = protected
        self.unprotected = unprotected
    }
    
    /// Creates a new JWS header using components.
    ///
    /// - Parameters:
    ///   - header: JWE Protected Header in byte array representation.
    ///   - unprotected: JWE Shared Unprotected Header.
    public init(protected: Data, unprotected: JOSEHeader? = nil) throws {
        self.protected = try ProtectedJSONWebContainer<JOSEHeader>(encoded: protected)
        self.unprotected = unprotected
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        
        self.protected = try container.decode(ProtectedJSONWebContainer<JOSEHeader>.self, forKey: .protected)
        self.unprotected = try container.decodeIfPresent(JOSEHeader.self, forKey: .unprotected)
    }
    
    public func encode(to encoder: Encoder) throws {
        try protected.validate()
        
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(protected, forKey: .protected)
        try container.encodeIfPresent(unprotected, forKey: .unprotected)
    }
}
