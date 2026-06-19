//
//  Base64.swift
//
//
//  Created by Amir Abbas Mousavian on 9/5/23.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

extension Data {
    /// Returns a URL-safe Base-64 encoded `Data`.
    ///
    /// - Returns: The URL-safe Base-64 encoded data.
    public func urlBase64EncodedData() -> Data {
        var result = base64EncodedData()
        var padding = 0
        result.withUnsafeMutableBytes { buffer in
            let bytes = buffer.bindMemory(to: UInt8.self)
            for i in bytes.indices {
                switch bytes[i] {
                case UInt8(ascii: "+"): bytes[i] = UInt8(ascii: "-")
                case UInt8(ascii: "/"): bytes[i] = UInt8(ascii: "_")
                default: break
                }
            }
            while padding < bytes.count, bytes[bytes.count - 1 - padding] == UInt8(ascii: "=") {
                padding += 1
            }
        }
        result.removeLast(padding)
        return result
    }
}

extension RandomAccessCollection where Self.Element == UInt8 {
    /// Returns a URL-safe Base-64 encoded `Data`.
    ///
    /// - Returns: The URL-safe Base-64 encoded data.
    public func urlBase64EncodedData() -> Data {
        Data(self).urlBase64EncodedData()
    }
    
    /// Returns a URL-safe Base-64 encoded `Data` in String representation.
    ///
    /// - returns: The URL-safe Base-64 encoded data in string representation.
    public func urlBase64EncodedString() -> String {
        String(decoding: urlBase64EncodedData(), as: UTF8.self)
    }
}

extension Swift.UInt8: Swift.ExpressibleByUnicodeScalarLiteral {
    public init(unicodeScalarLiteral value: UnicodeScalar) {
        self = .init(value.value)
    }
}

extension Data {
    /// Initialize a `Data` from a URL-safe Base-64, UTF-8 encoded input.
    ///
    /// Returns nil when the input is not recognized as valid Base-64.
    ///
    /// - Parameters:
    ///   - urlBase64Encoded: URL-safe Base-64, UTF-8 encoded input data.
    ///   - options: Decoding options forwarded to `Data(base64Encoded:options:)`. The default
    ///     `.ignoreUnknownCharacters` skips embedded whitespace/newlines; pass `[]` for strict
    ///     decoding that rejects them (e.g. JWS/JWE compact parsing, RFC 7515 §7.1).
    public init?(urlBase64Encoded: some Collection<UInt8>, options: Data.Base64DecodingOptions = .ignoreUnknownCharacters) {
        var base64Encoded = Data(urlBase64Encoded)
        var significant = 0
        base64Encoded.withUnsafeMutableBytes { rawBuffer in
            let buffer = rawBuffer.bindMemory(to: UInt8.self)
            for index in buffer.indices {
                switch buffer[index] {
                case UInt8(ascii: "-"): buffer[index] = UInt8(ascii: "+")
                case UInt8(ascii: "_"): buffer[index] = UInt8(ascii: "/")
                default: break
                }
                switch buffer[index] {
                case UInt8(ascii: "A") ... UInt8(ascii: "Z"),
                     UInt8(ascii: "a") ... UInt8(ascii: "z"),
                     UInt8(ascii: "0") ... UInt8(ascii: "9"),
                     UInt8(ascii: "+"), UInt8(ascii: "-"),
                     UInt8(ascii: "_"), UInt8(ascii: "/"),
                     UInt8(ascii: "="):
                    significant += 1
                default:
                    break
                }
            }
        }
        let remainder = significant % 4
        if remainder != 0 {
            base64Encoded.append(contentsOf: repeatElement(UInt8(ascii: "="), count: 4 - remainder))
        }
        guard let value = Data(base64Encoded: base64Encoded, options: options) else {
            return nil
        }
        self = value
    }
}

extension RandomAccessCollection where Self.Element == UInt8, Self: RangeReplaceableCollection {
    /// Initialize a collection of bytes from a URL-safe Base-64, UTF-8 encoded input.
    ///
    /// Returns nil when the input is not recognized as valid Base-64.
    ///
    /// - Parameters:
    ///   - urlBase64Encoded: URL-safe Base-64, UTF-8 encoded input data.
    ///   - options: Decoding options forwarded to `Data(base64Encoded:options:)`. The default
    ///     `.ignoreUnknownCharacters` skips embedded whitespace/newlines; pass `[]` for strict
    ///     decoding that rejects them (e.g. JWS/JWE compact parsing, RFC 7515 §7.1).
    public init?(urlBase64Encoded: some Collection<UInt8>, options: Data.Base64DecodingOptions = .ignoreUnknownCharacters) {
        guard let value = Data(urlBase64Encoded: urlBase64Encoded, options: options) else {
            return nil
        }
        self.init(value)
    }
    
    /// Initialize a `Data` from a URL-safe Base-64 encoded String using the given options.
    ///
    /// Returns nil when the input is not recognized as valid Base-64.
    /// - Parameters:
    ///   - urlBase64Encoded: The string to parse.
    ///   - options: Decoding options forwarded to `Data(base64Encoded:options:)` (see the byte
    ///     overload). Defaults to `.ignoreUnknownCharacters`.
    @inlinable
    public init?(urlBase64Encoded: some StringProtocol, options: Data.Base64DecodingOptions = .ignoreUnknownCharacters) {
        self.init(urlBase64Encoded: urlBase64Encoded.utf8, options: options)
    }
}
