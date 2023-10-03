//
//  EncryptedData.swift
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

/// A container for AES ciphers, e.g. AES, RSA, etc.
public struct SealedData: DataProtocol, BidirectionalCollection, Hashable {
    /// The nonce used to encrypt the data.
    public let iv: Data?
    
    /// The encrypted data.
    public let ciphertext: Data
    
    /// An authentication tag.
    public let tag: Data?
    
    public var regions: [Data] {
        [iv, ciphertext, tag].compactMap { $0 }
    }
    
    /// A combined element composed of the nonce, encrypted data, and authentication tag.
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
    
    /// Creates a sealed box from the given tag, nonce, and ciphertext.
    ///
    /// - Parameters:
    ///   - iv: The nonce.
    ///   - ciphertext: The encrypted data.
    ///   - tag: The authentication tag.
    public init(iv: Data? = nil, ciphertext: Data, tag: Data? = nil) {
        self.iv = iv
        self.ciphertext = ciphertext
        self.tag = tag
    }
    
    /// Creates a sealed box from the given AES sealed box.
    ///
    /// - Parameters:
    ///   - sealedBox: Container for your data.
    public init(_ sealedBox: AES.GCM.SealedBox) {
        self.iv = Data(sealedBox.nonce)
        self.ciphertext = sealedBox.ciphertext
        self.tag = sealedBox.tag
    }
    
    public static func == (lhs: SealedData, rhs: SealedData) -> Bool {
        lhs.iv ?? .init() == rhs.iv ?? .init() && lhs.ciphertext == rhs.ciphertext && lhs.tag ?? .init() == rhs.tag ?? .init()
    }
}

extension AES.GCM.SealedBox {
    /// Creates a AES sealed box from the given sealed box.
    ///
    /// - Parameters:
    ///   - sealedBox: Container for your data.
    public init(_ sealedData: SealedData) throws {
        self = try .init(
            nonce: .init(data: sealedData.iv ?? .init()),
            ciphertext: sealedData.ciphertext,
            tag: sealedData.tag ?? .init()
        )
    }
}
