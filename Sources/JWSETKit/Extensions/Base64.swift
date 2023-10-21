//
//  Base64.swift
//
//
//  Created by Amir Abbas Mousavian on 9/5/23.
//

import Foundation

extension DataProtocol {
    /// Returns a URL-safe Base-64 encoded `Data`.
    ///
    /// - returns: The URL-safe Base-64 encoded data.
    public func urlBase64EncodedData() -> Data {
        let result = Data(self).base64EncodedData()
            .compactMap {
                switch $0 {
                case UInt8(ascii: "+"):
                    return UInt8(ascii: "-")
                case UInt8(ascii: "/"):
                    return UInt8(ascii: "_")
                case UInt8(ascii: "="):
                    return nil
                default:
                    return $0
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

extension Data {
    /// Initialize a `Data` from a URL-safe Base-64, UTF-8 encoded `Data`.
    ///
    /// Returns nil when the input is not recognized as valid Base-64.
    ///
    /// - parameter urlBase64Encoded: URL-safe Base-64, UTF-8 encoded input data.
    /// - parameter options: Decoding options. Default value is `[]`.
    public init?(urlBase64Encoded: any DataProtocol) {
        var urlBase64Encoded = urlBase64Encoded.compactMap {
            switch $0 {
            case UInt8(ascii: "-"):
                return UInt8(ascii: "+")
            case UInt8(ascii: "_"):
                return UInt8(ascii: "/")
            default:
                return $0
            }
        }
        if urlBase64Encoded.count % 4 != 0 {
            urlBase64Encoded.append(contentsOf: [UInt8](repeating: .init(ascii: "="), count: 4 - urlBase64Encoded.count % 4))
        }
        guard let value = Data(base64Encoded: .init(urlBase64Encoded), options: [.ignoreUnknownCharacters]) else {
            return nil
        }
        self.init()
        self = value
    }
    
    /// Initialize a `Data` from a URL-safe Base-64 encoded String using the given options.
    ///
    /// Returns nil when the input is not recognized as valid Base-64.
    /// - parameter urlBase64Encoded: The string to parse.
    /// - parameter options: Encoding options. Default value is `[]`.
    public init?(urlBase64Encoded: String) {
        guard let value = Data(urlBase64Encoded: Data(urlBase64Encoded.utf8)) else { return nil }
        self = value
    }
}

extension Data {
    init<T: FixedWidthInteger>(bigEndian value: T) {
        let count = T.bitWidth / 8
        var value = value.bigEndian
        let bytePtr = withUnsafePointer(to: &value) {
            $0.withMemoryRebound(to: UInt8.self, capacity: count) {
                UnsafeBufferPointer(start: $0, count: count)
            }
        }
        self = Data(bytePtr)
    }
}
