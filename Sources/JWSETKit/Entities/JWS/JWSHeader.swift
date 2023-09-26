//
//  File.swift
//  
//
//  Created by Amir Abbas Mousavian on 9/27/23.
//

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Represents a signature or MAC over the JWS Payload and the JWS Protected Header.
public struct JSONWebSignatureHeader: Hashable, Codable {
    enum CodingKeys: CodingKey {
        case protected
        case header
        case signature
    }
    
    /// For a JWS, the members of the JSON object(s) representing the JOSE Header
    /// describe the digital signature or MAC applied to the JWS Protected Header
    /// and the JWS Payload and optionally additional properties of the JWS.
    public var header: ProtectedJSONWebContainer<JOSEHeader>
    
    /// The value JWS Unprotected Header.
    public var unprotectedHeader: JOSEHeader?
    
    /// Signature of protected header concatenated with payload.
    public var signature: Data
    
    /// Creates a new JWS header using components.
    ///
    /// - Parameters:
    ///   - header: JWS Protected Header.
    ///   - unprotectedHeader: JWS unsigned header.
    ///   - signature: Signature of protected header concatenated with payload.
    public init(header: JOSEHeader, unprotectedHeader: JOSEHeader? = nil, signature: Data) throws {
        self.header = try .init(value: header)
        self.unprotectedHeader = unprotectedHeader
        self.signature = signature
    }
    
    /// Creates a new JWS header using components.
    ///
    /// - Parameters:
    ///   - header: JWS Protected Header in byte array representation.
    ///   - unprotectedHeader: JWS unsigned header.
    ///   - signature: Signature of protected header concatenated with payload.
    public init(header: Data, unprotectedHeader: JOSEHeader? = nil, signature: Data) throws {
        self.header = try ProtectedJSONWebContainer<JOSEHeader>(protected: header)
        self.unprotectedHeader = unprotectedHeader
        self.signature = signature
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        
        self.header = try container.decode(ProtectedJSONWebContainer<JOSEHeader>.self, forKey: .protected)
        self.unprotectedHeader = try container.decodeIfPresent(JOSEHeader.self, forKey: .header)
        
        let signatureString = try container.decodeIfPresent(String.self, forKey: .signature) ?? .init()
        self.signature = Data(urlBase64Encoded: signatureString) ?? .init()
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(header, forKey: .protected)
        try container.encodeIfPresent(unprotectedHeader, forKey: .header)
        try container.encode(signature.urlBase64EncodedData(), forKey: .signature)
    }
}
