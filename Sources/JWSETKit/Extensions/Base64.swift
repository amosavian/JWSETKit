//
//  File.swift
//  
//
//  Created by Amir Abbas Mousavian on 9/5/23.
//

import Foundation

extension DataProtocol {
    public func urlBase64EncodedData(options: NSData.Base64EncodingOptions = []) -> Data {
        let result = Data(self).base64EncodedData(options: options)
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
    public init?(urlBase64Encoded: any DataProtocol, options: NSData.Base64DecodingOptions = []) {
        guard let value = Data(base64Encoded: .init(urlBase64Encoded), options: options) else {
            return nil
        }
        self.init()
        self = value
    }
}
