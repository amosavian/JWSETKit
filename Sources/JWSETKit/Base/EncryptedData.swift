//
//  File.swift
//  
//
//  Created by Amir Abbas Mousavian on 9/7/23.
//

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

public struct SealedData: DataProtocol, BidirectionalCollection {
    public let iv: Data?
    public let ciphertext: Data
    public let tag: Data?
    
    public var regions: [Data] {
        [iv, ciphertext, tag].compactMap({ $0 })
    }
    
    public var combined: Data {
        Data(regions.joined())
    }
    
    public var startIndex: Int {
        0
    }
    
    public var endIndex: Int {
        (iv?.count ?? 0) + ciphertext.count + (tag?.count ?? 0)
    }
    
    public subscript(position: Int) -> UInt8 {
        if position < (iv?.count ?? 0) {
            return iv?[position] ?? 0
        } else if position < (iv?.count ?? 0) + ciphertext.count {
            return ciphertext[position - (iv?.count ?? 0)]
        } else {
            return tag?[position] ?? 0
        }
    }
    
    public subscript(bounds: Range<Int>) -> Data {
        combined[bounds]
    }
    
    public init(iv: Data? = nil, ciphertext: Data, tag: Data? = nil) {
        self.iv = iv
        self.ciphertext = ciphertext
        self.tag = tag
    }
    
    public init(_ sealedBox: AES.GCM.SealedBox) {
        self.iv = Data(sealedBox.nonce)
        self.ciphertext = sealedBox.ciphertext
        self.tag = sealedBox.tag
    }
}

extension AES.GCM.SealedBox {
    public init(_ sealedData: SealedData) throws {
        self = try .init(
            nonce: .init(data: sealedData.iv ?? .init()),
            ciphertext: sealedData.ciphertext,
            tag: sealedData.tag ?? .init())
    }
}
