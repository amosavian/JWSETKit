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

extension DataProtocol {
    /// Returns a URL-safe Base-64 encoded `Data`.
    ///
    /// - returns: The URL-safe Base-64 encoded data.
    public func urlBase64EncodedData() -> Data {
        let result = Data(self).base64EncodedData()
            .compactMap { (byte: UInt8) -> UInt8? in
                switch byte {
                case "+":
                    return "-"
                case "/":
                    return "_"
                case "=":
                    return nil
                default:
                    return byte
                }
            }
        return Data(result)
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
    /// Initialize a `Data` from a URL-safe Base-64, UTF-8 encoded `Data`.
    ///
    /// Returns nil when the input is not recognized as valid Base-64.
    ///
    /// - parameter urlBase64Encoded: URL-safe Base-64, UTF-8 encoded input data.
    public init?(urlBase64Encoded: some Collection<UInt8>) {
        var base64Encoded = urlBase64Encoded.map { (byte: UInt8) -> UInt8 in
            switch byte {
            case "-":
                return "+"
            case "_":
                return "/"
            default:
                return byte
            }
        }
        if base64Encoded.count % 4 != 0 {
            base64Encoded.append(contentsOf: [UInt8](repeating: "=", count: 4 - base64Encoded.count % 4))
        }
        guard let value = Data(base64Encoded: .init(base64Encoded), options: [.ignoreUnknownCharacters]) else {
            return nil
        }
        self.init()
        self = value
    }
    
    /// Initialize a `Data` from a URL-safe Base-64 encoded String using the given options.
    ///
    /// Returns nil when the input is not recognized as valid Base-64.
    /// - parameter urlBase64Encoded: The string to parse.
    @inlinable
    public init?(urlBase64Encoded: some StringProtocol) {
        guard let value = Data(urlBase64Encoded: urlBase64Encoded.utf8) else { return nil }
        self = value
    }
}
