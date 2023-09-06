//
//  File 2.swift
//  
//
//  Created by Amir Abbas Mousavian on 9/6/23.
//

import Foundation
import AnyCodable

/// Storage for values in JOSE headers or JWT claims
@dynamicMemberLookup
public struct JsonWebValueStorage: Codable, Hashable {
    private var claims: [String: AnyCodable]
    
    public subscript<T>(dynamicMember member: String) -> T? {
        get {
            get(key: member, as: T.self)
        }
        set {
            updateValue(key: member, value: newValue)
        }
    }
    
    public subscript<T>(_ member: String) -> T? {
        get {
            get(key: member, as: T.self)
        }
        set {
            updateValue(key: member, value: newValue)
        }
    }
    
    public subscript(_ member: String) -> String? {
        get {
            get(key: member, as: String.self)
        }
        set {
            updateValue(key: member, value: newValue)
        }
    }
    
    public subscript(_ member: String) -> [String] {
        get {
            get(key: member, as: [String].self) ?? []
        }
        set {
            if newValue.isEmpty {
                remove(key: member)
            } else {
                updateValue(key: member, value: newValue)
            }
        }
    }
    
    public subscript(_ member: String) -> Bool {
        get {
            get(key: member, as: Bool.self) ?? false
        }
        set {
            updateValue(key: member, value: newValue)
        }
    }
    
    public subscript(_ member: String, urlEncoded: Bool = false) -> Data? {
        get {
            guard let value = self[member] as String? else { return nil }
            if urlEncoded {
                return Data(urlBase64Encoded: Data(value.utf8))
            } else {
                return Data(base64Encoded: value)
            }
        }
        set {
            if let value = urlEncoded ? newValue?.urlBase64EncodedData() : newValue?.base64EncodedData() {
                updateValue(key: member, value: value)
            } else {
                remove(key: member)
            }
        }
    }
    
    public init() {
        claims = [:]
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        self.claims = try container.decode([String : AnyCodable].self)
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(claims)
    }
    
    public mutating func remove(key: String) {
        claims.removeValue(forKey: key)
    }
    
    private func get<T>(key: String, as type: T.Type) -> T? {
        switch T.self {
        case is Date.Type:
            return (claims[key]?.value as? NSNumber)
                .map { Date(timeIntervalSince1970: $0.doubleValue) } as? T
        case is Decimal.Type:
            return (claims[key]?.value as? NSNumber)?.decimalValue as? T
        case let type as any UnsignedInteger.Type:
            return ((claims[key]?.value as? NSNumber)?.uint64Value)
                .map { type.init($0) } as? T
        case let type as any SignedInteger.Type:
            return ((claims[key]?.value as? NSNumber)?.int64Value)
                .map { type.init($0) } as? T
        case let type as any BinaryFloatingPoint.Type:
            return ((claims[key]?.value as? NSNumber)?.doubleValue)
                .map { type.init($0) } as? T
        case is URL.Type, is NSURL.Type:
            return (claims[key]?.value as? String)
                .map { URL(string: $0) } as? T
        case let type as any Decodable.Type:
            guard let value = claims[key]?.value else { return nil }
            if let value = value as? T {
                return value
            } else {
                let value = AnyCodable(value)
                guard let data = try? JSONEncoder().encode(value) else { return nil }
                return try? JSONDecoder().decode(type, from: data) as? T
            }
        case is Encodable.Type:
            return claims[key]?.value as? T
        default:
            assertionFailure("Unknown storage type")
            return nil
        }
    }
    
    private mutating func updateValue(key: String, value: Any?) {
        remove(key: key)
        
        switch value {
        case let value as Date:
            claims[key] = .init(Int(value.timeIntervalSince1970))
        case let value as any Decodable:
            claims[key] = .init(value)
        default:
            assertionFailure("Unknown storage type")
        }
    }
}
