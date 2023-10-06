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

/// A container for AES ciphers, e.g. AES-GCM, AES-CBC-HMAC, etc.
public struct SealedData: DataProtocol, BidirectionalCollection, Hashable, Sendable {
    /// The nonce used to encrypt the data.
    public let iv: Data
    
    /// The encrypted data.
    public let ciphertext: Data
    
    /// An authentication tag.
    public let tag: Data
    
    public var regions: [Data] {
        [iv, ciphertext, tag].map { $0 }
    }
    
    /// A combined element composed of the nonce, encrypted data, and authentication tag.
    public var combined: Data {
        Data(regions.joined())
    }
    
    public var startIndex: Int {
        0
    }
    
    public var endIndex: Int {
        iv.count + ciphertext.count + tag.count
    }
    
    public subscript(position: Int) -> UInt8 {
        if position < iv.count {
            return iv[position]
        } else if position < iv.count + ciphertext.count {
            return ciphertext[position - iv.count]
        } else {
            return tag[position]
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
    public init(iv: Data, ciphertext: Data, tag: Data) {
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
        lhs.iv == rhs.iv && lhs.ciphertext == rhs.ciphertext && lhs.tag == rhs.tag
    }
}

extension AES.GCM.SealedBox {
    /// Creates a AES sealed box from the given sealed box.
    ///
    /// - Parameters:
    ///   - sealedBox: Container for your data.
    public init(_ sealedData: SealedData) throws {
        self = try .init(
            nonce: .init(data: sealedData.iv),
            ciphertext: sealedData.ciphertext,
            tag: sealedData.tag
        )
    }
}
