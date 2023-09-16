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
}

extension Data {
    /// Initialize a `Data` from a URL-safe Base-64, UTF-8 encoded `Data`.
    ///
    /// Returns nil when the input is not recognized as valid Base-64.
    ///
    /// - parameter urlBase64Encoded: URL-safe Base-64, UTF-8 encoded input data.
    /// - parameter options: Decoding options. Default value is `[]`.
    public init?(urlBase64Encoded: any DataProtocol, options: NSData.Base64DecodingOptions = []) {
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
        urlBase64Encoded.append(contentsOf: [UInt8](repeating: UInt8(ascii: "="), count: 3 - (urlBase64Encoded.count % 3)))
        guard let value = Data(base64Encoded: .init(urlBase64Encoded), options: options) else {
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
    public init?(urlBase64Encoded: String, options: NSData.Base64DecodingOptions = []) {
        guard let value = Data(urlBase64Encoded: Data(urlBase64Encoded.utf8), options: options) else { return nil }
        self = value
    }
}
