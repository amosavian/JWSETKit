//
//  EncryptedData.swift
//
//
//  Created by Amir Abbas Mousavian on 9/7/23.
//

import Foundation
import Crypto

/// A container for AES ciphers, e.g. AES-GCM, AES-CBC-HMAC, etc.
@frozen
public struct SealedData: DataProtocol, BidirectionalCollection, Hashable, Sendable {
    public typealias Nonce = Data
    
    /// The nonce used to encrypt the data.
    public let nonce: Nonce
    
    /// The encrypted data.
    public let ciphertext: Data
    
    /// An authentication tag.
    public let tag: Data
    
    public var regions: [Data] {
        [nonce, ciphertext, tag].map { $0 }
    }
    
    /// A combined element composed of the nonce, encrypted data, and authentication tag.
    public var combined: Data {
        Data(regions.joined())
    }
    
    public var startIndex: Int {
        0
    }
    
    public var endIndex: Int {
        nonce.count + ciphertext.count + tag.count
    }
    
    public subscript(position: Int) -> UInt8 {
        if position < nonce.count {
            return nonce[position]
        } else if position < nonce.count + ciphertext.count {
            return ciphertext[position - nonce.count]
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
    ///   - nonce: The nonce or initial vector.
    ///   - ciphertext: The encrypted data.
    ///   - tag: The authentication tag.
    public init<C: DataProtocol, T: DataProtocol>(nonce: Nonce, ciphertext: C, tag: T) {
        self.nonce = nonce
        self.ciphertext = .init(ciphertext)
        self.tag = .init(tag)
    }
    
    /// Creates a sealed box from the given AES sealed box.
    ///
    /// - Parameters:
    ///   - sealedBox: Container for your data.
    public init(_ sealedBox: AES.GCM.SealedBox) {
        self.nonce = Data(sealedBox.nonce)
        self.ciphertext = sealedBox.ciphertext
        self.tag = sealedBox.tag
    }
    
    /// Creates a sealed box from the given ChaChaPoly sealed box.
    /// - Parameters:
    ///  - sealedBox: Container for your data.
    public init(_ sealedBox: ChaChaPoly.SealedBox) {
        self.nonce = Data(sealedBox.nonce)
        self.ciphertext = sealedBox.ciphertext
        self.tag = sealedBox.tag
    }
    
    /// Creates a sealed box from the given AES sealed box.
    ///
    /// - Parameters:
    ///   - sealedBox: Container for your data.
    public init<D>(data: D, nonceLength: Int, tagLength: Int) throws where D: DataProtocol {
        guard nonceLength > 0, tagLength > 0, data.count >= nonceLength + tagLength else {
            throw CryptoKitError.incorrectParameterSize
        }
        self.nonce = Data(data.prefix(nonceLength))
        self.ciphertext = Data(data.dropFirst(nonceLength).dropLast(tagLength))
        self.tag = Data(data.suffix(tagLength))
    }
    
    public static func == (lhs: SealedData, rhs: SealedData) -> Bool {
        lhs.nonce == rhs.nonce && lhs.ciphertext == rhs.ciphertext && lhs.tag == rhs.tag
    }
}

extension AES.GCM.SealedBox {
    /// Creates a AES sealed box from the given sealed box.
    ///
    /// - Parameters:
    ///   - sealedBox: Container for your data.
    public init(_ sealedData: SealedData) throws {
        self = try .init(
            nonce: .init(data: sealedData.nonce),
            ciphertext: sealedData.ciphertext,
            tag: sealedData.tag
        )
    }
}

extension ChaChaPoly.SealedBox {
    /// Creates a ChaChaPoly sealed box from the given sealed box.
    ///
    /// - Parameters:
    ///   - sealedBox: Container for your data.
    public init(_ sealedData: SealedData) throws {
        self = try .init(
            nonce: .init(data: sealedData.nonce),
            ciphertext: sealedData.ciphertext,
            tag: sealedData.tag
        )
    }
}
