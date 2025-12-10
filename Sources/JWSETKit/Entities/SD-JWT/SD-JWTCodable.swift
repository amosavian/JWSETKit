//
//  SD-JWTCodable.swift
//
//
//  Created by Amir Abbas Mousavian on 9/21/25.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// SD-JWT serialization formats as defined in the SD-JWT specification.
///
/// SD-JWTs can be serialized in multiple formats similar to JWS, but with additional
/// disclosure components separated by tilde (`~`) characters.
///
/// To change the representation of SD-JWT during encoding to flattened JSON:
/// ```swift
/// do {
///     var encoder = JSONEncoder()
///     encoder.userInfo[.sdJWTEncodedRepresentation] = JSONWebSelectiveDisclosureTokenRepresentation.jsonFlattened
///     try encoder.encode(sdJWT)
/// } catch {
///     print(error)
/// }
/// ```
public enum JSONWebSelectiveDisclosureTokenRepresentation: Sendable {
    /// Use compact serialization if possible, otherwise JSON serialization.
    ///
    /// - Important: This is default encoding format when using `JSONWebSelectiveDisclosureToken.encode(to:)`.
    ///              To use other encodings, change `.sdJWTEncodedRepresentation`
    ///              parameter in `userInfo`.
    case automatic
    
    /// Compact serialization: `<Issuer-JWT>~<Disclosure>~<Disclosure>~...~[<KB-JWT>]`
    ///
    /// This is the most common format for SD-JWTs. Components are separated by tilde characters.
    /// The last component is the key binding JWT if present, otherwise an empty string.
    case compact
    
    /// The SD-JWT JSON Serialization represents signed content with selective disclosures as a JSON object.
    ///
    /// The value can be a flattened representation if only one signature is present,
    /// or a fully general syntax if more than one signature is present.
    case json
    
    /// The flattened SD-JWT JSON Serialization syntax is based upon the general
    /// syntax but flattens it, optimizing it for the single digital signature case.
    ///
    /// Disclosures are placed in an unprotected header field.
    case jsonFlattened
    
    /// A JSON Serialization fully general syntax, with which content can be secured
    /// with more than one digital signature.
    ///
    /// Disclosures are placed in the first signature's unprotected header.
    case jsonGeneral
}

extension CodingUserInfoKey {
    /// Changes serialization format of SD-JWT.
    ///
    /// Default value is `.automatic` if not set.
    public static var sdJWTEncodedRepresentation: Self {
        .init(rawValue: #function).unsafelyUnwrapped
    }
}

extension JSONWebSelectiveDisclosureToken: Codable {
    private enum CodingKeys: String, CodingKey {
        case payload
        case signatures
    }
    
    public init(from decoder: any Decoder) throws {
        if let stringContainer = try? decoder.singleValueContainer(), let value = try? stringContainer.decode(String.self) {
            let components = value.split(separator: "~", omittingEmptySubsequences: false)
            guard !components.isEmpty else {
                throw DecodingError.dataCorrupted(.init(codingPath: [], debugDescription: "Invalid SD-JWT compact serialization"))
            }
            let issuerJWT = try JSONWebToken(from: String(components[0]))
            self.payload = issuerJWT.payload
            self.signatures = issuerJWT.signatures
            var disclosureComponents = Array(components.dropFirst())
            if !disclosureComponents.isEmpty {
                let lastComponent = String(disclosureComponents.last!)
                if lastComponent.isEmpty {
                    disclosureComponents.removeLast()
                    self.keyBinding = nil
                } else if lastComponent.hasPrefix("ey") {
                    self.keyBinding = try JSONWebToken(from: lastComponent)
                    disclosureComponents.removeLast()
                } else {
                    self.keyBinding = nil
                }
            } else {
                self.keyBinding = nil
            }
            self.disclosures = try disclosureComponents.compactMap { component in
                let disclosureString = String(component)
                guard !disclosureString.isEmpty else { return nil }
                return try JSONWebSelectiveDisclosure(encoded: disclosureString)
            }
            return
        }
        
        let jws = try JSONWebSignature<ProtectedJSONWebContainer<JSONWebTokenClaims>>(from: decoder)
        self.payload = jws.payload
        self.signatures = jws.signatures
        if let firstHeader = jws.signatures.first?.unprotected,
           let disclosureStrings: [String] = firstHeader.storage["disclosures"]
        {
            self.disclosures = try disclosureStrings.map { try JSONWebSelectiveDisclosure(encoded: $0) }
        } else {
            self.disclosures = []
        }
        if let firstHeader = jws.signatures.first?.unprotected,
           let kbJWTString: String = firstHeader.storage["kb_jwt"]
        {
            self.keyBinding = try JSONWebToken(from: kbJWTString)
        } else {
            self.keyBinding = nil
        }
    }
    
    public func encode(to encoder: any Encoder) throws {
        // Validate structure without requiring key binding during encoding
        // Key binding validation should be done explicitly by verifiers
        try validate(requireKeyBinding: false)
        let representation = encoder.userInfo[.sdJWTEncodedRepresentation] as? JSONWebSelectiveDisclosureTokenRepresentation ?? .automatic
        try encodeFunction(for: representation)(encoder)
    }
    
    fileprivate func bestRepresentation() -> JSONWebSelectiveDisclosureTokenRepresentation {
        switch signatures.count {
        case 0:
            return .compact
        case 1 where signatures.first?.unprotected == nil:
            return .compact
        default:
            return .json
        }
    }
    
    fileprivate func encodeFunction(for representation: JSONWebSelectiveDisclosureTokenRepresentation) -> (_ encoder: any Encoder) throws -> Void {
        var representation = representation
        if representation == .automatic {
            representation = bestRepresentation()
        }
        switch representation {
        case .automatic:
            fallthrough
        case .compact:
            return encodeAsCompact
        case .json:
            switch signatures.count {
            case 0, 1:
                return encodeAsFlattenedJSON
            default:
                return encodeAsCompleteJSON
            }
        case .jsonFlattened:
            return encodeAsFlattenedJSON
        case .jsonGeneral:
            return encodeAsCompleteJSON
        }
    }
    
    fileprivate func encodeAsCompact(_ encoder: any Encoder) throws {
        var components: [String] = []
        try components.append(String(jwt))
        for disclosure in disclosures {
            components.append(disclosure.encoded)
        }
        if let keyBinding {
            try components.append(String(keyBinding))
        } else {
            components.append("")
        }
        let compactString = components.joined(separator: "~")
        var container = encoder.singleValueContainer()
        try container.encode(compactString)
    }
    
    fileprivate func encodeAsFlattenedJSON(_ encoder: any Encoder) throws {
        guard let signature = signatures.first else {
            throw EncodingError.invalidValue(JSONWebSignatureHeader?.none as Any, .init(codingPath: encoder.codingPath + [CodingKeys.signatures], debugDescription: "SD-JWT must have at least one signature"))
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        if !payload.encoded.isEmpty {
            try container.encode(payload.encoded.urlBase64EncodedString(), forKey: .payload)
        }
        var headerContainer = encoder.container(keyedBy: JSONWebSignatureHeader.CodingKeys.self)
        try headerContainer.encode(signature.protected, forKey: .protected)
        var unprotectedStorage = signature.unprotected?.storage ?? JSONWebValueStorage()
        unprotectedStorage["disclosures"] = disclosures.map { $0.encoded }
        if let keyBinding {
            unprotectedStorage["kb_jwt"] = try String(keyBinding)
        }
        try headerContainer.encode(JOSEHeader(storage: unprotectedStorage), forKey: .header)
        try headerContainer.encode(signature.signature, forKey: .signature)
    }
    
    fileprivate func encodeAsCompleteJSON(_ encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        if !payload.encoded.isEmpty {
            try container.encode(payload.encoded.urlBase64EncodedString(), forKey: .payload)
        }
        var modifiedSignatures: [JSONWebSignatureHeader] = []
        for (index, signature) in signatures.enumerated() {
            if index == 0 {
                var unprotectedStorage = signature.unprotected?.storage ?? JSONWebValueStorage()
                unprotectedStorage["disclosures"] = disclosures.map { $0.encoded }
                if let keyBinding {
                    unprotectedStorage["kb_jwt"] = try String(keyBinding)
                }
                let modifiedSignature = try JSONWebSignatureHeader(
                    protected: signature.protected.encoded,
                    unprotected: JOSEHeader(storage: unprotectedStorage),
                    signature: signature.signature
                )
                modifiedSignatures.append(modifiedSignature)
            } else {
                modifiedSignatures.append(signature)
            }
        }
        try container.encode(modifiedSignatures, forKey: .signatures)
    }
}

extension String {
    /// Encodes SD-JWT to a compact serialization string.
    ///
    /// - Parameter sdJWT: SD-JWT object to be encoded.
    /// - Throws: `EncodingError` if encoding fails.
    public init(_ sdJWT: JSONWebSelectiveDisclosureToken) throws {
        let encoder = JSONEncoder.encoder
        encoder.userInfo[.sdJWTEncodedRepresentation] = JSONWebSelectiveDisclosureTokenRepresentation.compact
        self = try String(String(decoding: encoder.encode(sdJWT), as: UTF8.self).dropFirst().dropLast())
    }
}

extension JSONWebSelectiveDisclosureToken: LosslessStringConvertible, CustomDebugStringConvertible {
    public init?(_ description: String) {
        guard let sdJWT = try? JSONDecoder().decode(JSONWebSelectiveDisclosureToken.self, from: Data(description.utf8)) else {
            return nil
        }
        self = sdJWT
    }
    
    public var description: String {
        (try? String(self)) ?? ""
    }
    
    public var debugDescription: String {
        "Signatures: \(signatures.debugDescription)\nPayload: \(payload.encoded.urlBase64EncodedString())\nDisclosures: \(disclosures.count)\nKey Binding: \(keyBinding != nil ? "Present" : "None")"
    }
}

/// Allows encoding SD-JWT with configuration for representation style.
@available(macOS 12, iOS 15, tvOS 15, watchOS 8, *)
public struct JSONWebSelectiveDisclosureTokenCodableConfiguration: Sendable {
    /// Determines serialization format for SD-JWT.
    public let representation: JSONWebSelectiveDisclosureTokenRepresentation
    
    /// Creates a new instance of `JSONWebSelectiveDisclosureTokenCodableConfiguration`.
    ///
    /// - Parameter representation: Determines serialization format for SD-JWT.
    public init(representation: JSONWebSelectiveDisclosureTokenRepresentation) {
        self.representation = representation
    }
}

@available(macOS 12, iOS 15, tvOS 15, watchOS 8, *)
extension JSONWebSelectiveDisclosureToken: EncodableWithConfiguration {
    public typealias EncodingConfiguration = JSONWebSelectiveDisclosureTokenCodableConfiguration
    
    public func encode(to encoder: any Encoder, configuration: JSONWebSelectiveDisclosureTokenCodableConfiguration) throws {
        // Validate structure without requiring key binding during encoding
        // Key binding validation should be done explicitly by verifiers
        try validate(requireKeyBinding: false)
        try encodeFunction(for: configuration.representation)(encoder)
    }
}
