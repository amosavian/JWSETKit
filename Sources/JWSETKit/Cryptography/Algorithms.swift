//
//  Algorithms.swift
//  
//
//  Created by Amir Abbas Mousavian on 9/5/23.
//

import Foundation
import CryptoKit

/// JSON Web Signature and Encryption Algorithms
public struct JsonWebAlgorithm: RawRepresentable, Hashable, Codable, ExpressibleByStringLiteral {
    
    public let rawValue: String
    
    public init(rawValue: String) {
        self.rawValue = rawValue.trimmingCharacters(in: .whitespaces)
    }
    
    public init(stringLiteral value: StringLiteralType) {
        self.rawValue = value.trimmingCharacters(in: .whitespaces)
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        self.rawValue = try container.decode(String.self)
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

extension JsonWebAlgorithm {
    /// No digital signature or MAC performed.
    public static let none: Self = "none"
    
    /// HMAC using SHA-256.
    public static let hmacSHA256: Self = "HS256"
    
    /// HMAC using SHA-384.
    public static let hmacSHA384: Self = "HS384"
    
    /// HMAC using SHA-512.
    public static let hmacSHA512: Self = "HS512"
    
    /// RSASSA-PKCS1-v1.5 using SHA-256.
    public static let rsaSignaturePKCS1v15SHA256: Self = "RS256"
    
    /// RSASSA-PKCS1-v1.5 using SHA-384.
    public static let rsaSignaturePKCS1v15SHA384: Self = "RS384"
    
    /// RSASSA-PKCS1-v1.5 using SHA-512 .
    public static let rsaSignaturePKCS1v15SHA512: Self = "RS512"
    
    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256.
    public static let rsaSignaturePSSSHA256: Self = "PS256"
    
    /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384.
    public static let rsaSignaturePSSSHA384: Self = "PS384"
    
    /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512.
    public static let rsaSignaturePSSSHA512: Self = "PS512"
    
    /// ECDSA using P-256 and SHA-256.
    public static let ecdsaSignatureP256SHA256: Self = "ES256"
    
    /// ECDSA using P-384 and SHA-384.
    public static let ecdsaSignatureP384SHA384: Self = "ES384"
    
    /// ECDSA using P-521 and SHA-512.
    public static let ecdsaSignatureP512SHA512: Self = "ES512"
    
    /// RSAES-PKCS1-v1_5
    public static let rsaEncryptionPKCS1: Self = "RSA-OAEP"
    
    /// RSAES OAEP using default parameters.
    public static let rsaEncryptionOAEP: Self = "RSA-OAEP"
    
    /// RSAES OAEP using SHA-256 and MGF1 with SHA-256.
    public static let rsaEncryptionOAEPSHA256: Self = "RSA-OAEP-256"
    
    /// RSA-OAEP using SHA-384 and MGF1 with SHA-384.
    public static let rsaEncryptionOAEPSHA384: Self = "RSA-OAEP-384"
    
    /// RSA-OAEP using SHA-512 and MGF1 with SHA-512.
    public static let rsaEncryptionOAEPSHA512: Self = "RSA-OAEP-512"
    
    /// AES GCM using 128-bit key.
    public static let aesEncryptionGCM128: Self = "A128GCM"
    
    /// AES GCM using 192-bit key.
    public static let aesEncryptionGCM192: Self = "A192GCM"
    
    /// AES GCM using 256-bit key.
    public static let aesEncryptionGCM256: Self = "A256GCM"
    
    /// `AES_128_CBC_HMAC_SHA_256` authenticated encryption algorithm.
    public static let aesEncryptionCBC128SHA256: Self = "A128CBC-HS256"
    
    /// `AES_192_CBC_HMAC_SHA_384` authenticated encryption algorithm
    public static let aesEncryptionCBC192SHA384: Self = "A192CBC-HS384"
    
    /// `AES_256_CBC_HMAC_SHA_512` authenticated encryption algorithm.
    public static let aesEncryptionCBC256SHA512: Self = "A256CBC-HS512"
}

/// JSON Web Compression Algorithms.
public struct JsonWebCompressionAlgorithm: RawRepresentable, Hashable, Codable, ExpressibleByStringLiteral {
    public let rawValue: String
    
    public init(rawValue: String) {
        self.rawValue = rawValue.trimmingCharacters(in: .whitespaces)
    }
    
    public init(stringLiteral value: StringLiteralType) {
        self.rawValue = value.trimmingCharacters(in: .whitespaces)
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        self.rawValue = try container.decode(String.self)
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

extension JsonWebCompressionAlgorithm {
    /// Compression with the DEFLATE [RFC1951](https://www.rfc-editor.org/rfc/rfc1951) algorithm
    public static let deflate: Self = "DEF"
}
