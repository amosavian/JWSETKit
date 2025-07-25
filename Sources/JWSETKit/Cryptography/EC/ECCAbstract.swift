//
//  ECCAbstract.swift
//
//
//  Created by Amir Abbas Mousavian on 9/10/23.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto

protocol CryptoECPublicKey: JSONWebKeyCurveType, JSONWebKeyRawRepresentable {
    static var curve: JSONWebKeyCurve { get }
}

extension CryptoECPublicKey {
    public var storage: JSONWebValueStorage {
        var result = AnyJSONWebKey()
        let rawRepresentation = rawRepresentation
        result.keyType = .ellipticCurve
        result.curve = Self.curve
        result.xCoordinate = rawRepresentation.prefix(rawRepresentation.count / 2)
        result.yCoordinate = rawRepresentation.suffix(rawRepresentation.count / 2)
        return result.storage
    }
    
    public init(storage: JSONWebValueStorage) throws {
        let keyData = AnyJSONWebKey(storage: storage)
        guard let x = keyData.xCoordinate, !x.isEmpty, let y = keyData.yCoordinate, y.count == x.count else {
            throw CryptoKitError.incorrectKeySize
        }
        try self.init(rawRepresentation: x + y)
    }
}

protocol CryptoECPrivateKey: JSONWebKeyCurveType, JSONWebPrivateKey, Hashable where PublicKey: CryptoECPublicKey {
    var rawRepresentation: Data { get }
    init(rawRepresentation: Data) throws
}

extension CryptoECPrivateKey {
    public var storage: JSONWebValueStorage {
        var result: some (MutableJSONWebKey & JSONWebKeyCurveType) = AnyJSONWebKey(publicKey)
        result.privateKey = rawRepresentation
        return result.storage
    }
    
    public init(storage: JSONWebValueStorage) throws {
        let keyData: some (MutableJSONWebKey & JSONWebKeyCurveType) = AnyJSONWebKey(storage: storage)
        guard let privateKey = keyData.privateKey, !privateKey.isEmpty else {
            throw CryptoKitError.incorrectKeySize
        }
        try self.init(rawRepresentation: privateKey)
    }
    
    public func thumbprint<H>(format: JSONWebKeyFormat, using hashFunction: H.Type) throws -> H.Digest where H: HashFunction {
        try publicKey.thumbprint(format: format, using: hashFunction)
    }
}

protocol CryptoECKeyPortable: JSONWebKeyImportable, JSONWebKeyExportable {
    var x963Representation: Data { get }
    var derRepresentation: Data { get }
    
    init<Bytes>(x963Representation: Bytes) throws where Bytes: ContiguousBytes
    init<Bytes>(derRepresentation: Bytes) throws where Bytes: RandomAccessCollection, Bytes.Element == UInt8
}

protocol CryptoECKeyPortableCompactRepresentable: CryptoECKeyPortable {
    @available(iOS 16.0, macOS 13.0, watchOS 9.0, tvOS 16.0, *)
    init<Bytes>(compressedRepresentation: Bytes) throws where Bytes: ContiguousBytes
}

extension CryptoECKeyPortable {
    public init<D>(importing key: D, format: JSONWebKeyFormat) throws where D: DataProtocol {
        switch format {
        case .raw:
            try self.init(x963Representation: key.asContiguousBytes)
        case .spki where Self.self is (any CryptoECPublicKey).Type,
             .pkcs8 where Self.self is (any CryptoECPrivateKey).Type:
            try self.init(derRepresentation: key)
        case .jwk:
            self = try JSONDecoder().decode(Self.self, from: Data(key))
        default:
            throw JSONWebKeyError.invalidKeyFormat
        }
    }
    
    public func exportKey(format: JSONWebKeyFormat) throws -> Data {
        switch format {
        case .raw:
            return x963Representation
        case .spki where self is any CryptoECPublicKey,
             .pkcs8 where self is any CryptoECPrivateKey:
            return derRepresentation
        case .jwk:
            return try jwkRepresentation
        default:
            throw JSONWebKeyError.invalidKeyFormat
        }
    }
}

extension CryptoECKeyPortableCompactRepresentable {
    private init<D>(importingRaw key: D) throws where D: DataProtocol {
        switch key.first {
        case 0x04:
            try self.init(x963Representation: key.asContiguousBytes)
        case 0x02, 0x03:
            if #available(iOS 16.0, macOS 13.0, watchOS 9.0, tvOS 16.0, *) {
                try self.init(compressedRepresentation: key.asContiguousBytes)
            } else {
                throw CryptoKitError.incorrectParameterSize
            }
        default:
            throw CryptoKitError.incorrectParameterSize
        }
    }
    
    public init<D>(importing key: D, format: JSONWebKeyFormat) throws where D: DataProtocol {
        switch format {
        case .raw:
            try self.init(importingRaw: key)
        case .spki where Self.self is (any CryptoECPublicKey).Type,
             .pkcs8 where Self.self is (any CryptoECPrivateKey).Type:
            try self.init(derRepresentation: key)
        case .jwk:
            self = try JSONDecoder().decode(Self.self, from: Data(key))
        default:
            throw JSONWebKeyError.invalidKeyFormat
        }
    }
}
