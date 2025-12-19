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

extension RandomAccessCollection where Self.Element == UInt8 {
    /// Returns a URL-safe Base-64 encoded `Data`.
    ///
    /// - returns: The URL-safe Base-64 encoded data.
    public func urlBase64EncodedData() -> Data {
        var result = Data(self).base64EncodedData()
        for i in 0 ..< result.count {
            switch result[i] {
            case "+":
                result[i] = "-"
            case "/":
                result[i] = "_"
            default:
                break
            }
        }
        while result.last == "=" {
            result.removeLast()
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

extension RandomAccessCollection where Self.Element == UInt8, Self: RangeReplaceableCollection {
    /// Initialize a `Data` from a URL-safe Base-64, UTF-8 encoded `Data`.
    ///
    /// Returns nil when the input is not recognized as valid Base-64.
    ///
    /// - parameter urlBase64Encoded: URL-safe Base-64, UTF-8 encoded input data.
    public init?(urlBase64Encoded: some Collection<UInt8>) {
        var base64Encoded = urlBase64Encoded.compactMap { (byte: UInt8) -> UInt8? in
            switch byte {
            case " ", 0x0D, 0x0A:
                return nil
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
        guard let value = Data(base64Encoded: .init(base64Encoded), options: []) else {
            return nil
        }
        self.init(value)
    }
    
    /// Initialize a `Data` from a URL-safe Base-64 encoded String using the given options.
    ///
    /// Returns nil when the input is not recognized as valid Base-64.
    /// - parameter urlBase64Encoded: The string to parse.
    @inlinable
    public init?(urlBase64Encoded: some StringProtocol) {
        self.init(urlBase64Encoded: urlBase64Encoded.utf8)
    }
}
