//
//  JWSHeader.swift
//
//
//  Created by Amir Abbas Mousavian on 9/27/23.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto

/// Represents a signature or MAC over the JWS Payload and the JWS Protected Header.
public struct JSONWebSignatureHeader: Hashable, Codable, Sendable {
    enum CodingKeys: CodingKey {
        case protected
        case header
        case signature
    }
    
    /// For a JWS, the members of the JSON object(s) representing the JOSE Header
    /// describe the digital signature or MAC applied to the JWS Protected Header
    /// and the JWS Payload and optionally additional properties of the JWS.
    public var protected: ProtectedJSONWebContainer<JOSEHeader>
    
    /// The value JWS Unprotected Header.
    public var unprotected: JOSEHeader?
    
    /// Signature of protected header concatenated with payload.
    public var signature: Data
    
    /// Creates a new JWS header using components.
    ///
    /// - Parameters:
    ///   - protected: JWS Protected Header.
    ///   - unprotected: JWS unsigned header.
    ///   - signature: Signature of protected header concatenated with payload.
    public init(protected: JOSEHeader, unprotected: JOSEHeader? = nil, signature: Data) throws {
        self.protected = try .init(value: protected)
        self.unprotected = unprotected
        self.signature = signature
    }
    
    /// Creates a new JWS header using components.
    ///
    /// - Parameters:
    ///   - protected: JWS Protected Header in byte array representation.
    ///   - unprotected: JWS unsigned header.
    ///   - signature: Signature of protected header concatenated with payload.
    public init(protected: Data, unprotected: JOSEHeader? = nil, signature: Data) throws {
        self.protected = try ProtectedJSONWebContainer<JOSEHeader>(encoded: protected)
        self.unprotected = unprotected
        self.signature = signature
    }
    
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        
        self.protected = try container.decodeIfPresent(ProtectedJSONWebContainer<JOSEHeader>.self, forKey: .protected) ?? .init(value: .init())
        self.unprotected = try container.decodeIfPresent(JOSEHeader.self, forKey: .header)
        
        let signatureString = try container.decodeIfPresent(String.self, forKey: .signature) ?? .init()
        self.signature = Data(urlBase64Encoded: signatureString) ?? .init()
    }
    
    public func encode(to encoder: any Encoder) throws {
        try protected.validate()
        
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(protected, forKey: .protected)
        try container.encodeIfPresent(unprotected, forKey: .header)
        try container.encode(signature.urlBase64EncodedString(), forKey: .signature)
    }
}

extension JSONWebSignatureHeader {
    func signedData(_ payload: some ProtectedWebContainer) -> Data {
        let protectedEncoded = !protected.storage.storageKeys.isEmpty ? protected.encoded.urlBase64EncodedData() : .init()
        if protected.critical.contains("b64"), protected.base64 == false {
            return protectedEncoded + Data(".".utf8) + payload.encoded
        } else {
            return protectedEncoded + Data(".".utf8) + payload.encoded.urlBase64EncodedData()
        }
    }
}
