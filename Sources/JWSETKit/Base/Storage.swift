//
//  File 2.swift
//
//
//  Created by Amir Abbas Mousavian on 9/6/23.
//

import AnyCodable
import Foundation

/// Storage for values in JOSE headers or JWT claims
@dynamicMemberLookup
public struct JSONWebValueStorage: Codable, Hashable, ExpressibleByDictionaryLiteral {
    private var claims: [String: AnyCodable]
    
    /// Returns value of given key.
    public subscript<T>(dynamicMember member: String) -> T? {
        get {
            get(key: member, as: T.self)
        }
        set {
            updateValue(key: member, value: newValue)
        }
    }
    
    /// Returns value of given key.
    public subscript<T>(_ member: String) -> T? {
        get {
            get(key: member, as: T.self)
        }
        set {
            updateValue(key: member, value: newValue)
        }
    }
    
    /// Returns value of given key.
    public subscript(_ member: String) -> String? {
        get {
            get(key: member, as: String.self)
        }
        set {
            updateValue(key: member, value: newValue)
        }
    }
    
    /// Returns values of given key.
    public subscript<T>(dynamicMember member: String) -> [T] {
        get {
            self[member]
        }
        set {
            self[member] = newValue
        }
    }
    
    /// Returns values of given key.
    public subscript<T>(_ member: String) -> [T] {
        get {
            guard let array = claims[member]?.value as? [Any] else { return [] }
            return array.compactMap { JSONWebValueStorage.cast(value: $0, as: T.self) }
        }
        set {
            if newValue.isEmpty {
                remove(key: member)
            } else {
                updateValue(key: member, value: newValue)
            }
        }
    }
    
    /// Returns value of given key.
    public subscript(_ member: String) -> Bool {
        get {
            get(key: member, as: Bool.self) ?? false
        }
        set {
            updateValue(key: member, value: newValue)
        }
    }
    
    /// Returns value of given key decoded using base64.
    public subscript(_ member: String, urlEncoded: Bool = false) -> Data? {
        get {
            guard let value = self[member] as String? else { return nil }
            if urlEncoded {
                return Data(urlBase64Encoded: value)
            } else {
                return Data(base64Encoded: value)
            }
        }
        set {
            updateValue(key: member, value: urlEncoded ?
                (newValue?.urlBase64EncodedData()).map { String(decoding: $0, as: UTF8.self) } :
                newValue?.base64EncodedString())
        }
    }
    
    /// Returns values of given key decoded using base64.
    public subscript(_ member: String, urlEncoded: Bool = false) -> [Data] {
        get {
            let values = self[member] as [String]
            if urlEncoded {
                return values.compactMap { Data(urlBase64Encoded: $0) }
            } else {
                return values.compactMap { Data(base64Encoded: $0) }
            }
        }
        set {
            self[member] = newValue.compactMap {
                urlEncoded ? String(decoding: $0.urlBase64EncodedData(), as: UTF8.self) : $0.base64EncodedString()
            }
        }
    }
    
    /// Initializes empty storage.
    public init() {
        self.claims = [:]
    }
    
    public init(dictionaryLiteral elements: (String, Any)...) {
        let elements = elements.map { ($0, AnyCodable($1)) }
        self.claims = .init(uniqueKeysWithValues: elements)
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let claims = try? container.decode([String: AnyCodable].self) {
            self.claims = claims
        } else if let base64url = try? container.decode(String.self),
                  let data = Data(urlBase64Encoded: base64url)
        {
            self.claims = try JSONDecoder().decode([String: AnyCodable].self, from: data)
        } else {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: ""))
        }
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(claims)
    }
    
    public static func == (lhs: JSONWebValueStorage, rhs: JSONWebValueStorage) -> Bool {
        let encoder = JSONEncoder()
        let decoder = JSONDecoder()
        let lhs = try? decoder.decode([String: AnyCodable].self, from: encoder.encode(lhs))
        let rhs = try? decoder.decode([String: AnyCodable].self, from: encoder.encode(rhs))
        return lhs == rhs
    }
    
    /// Removes value of given key from storage.
    public func contains(key: String) -> Bool {
        claims.keys.contains(key)
    }
    
    /// Removes value of given key from storage.
    public mutating func remove(key: String) {
        claims.removeValue(forKey: key)
    }
    
    fileprivate static func cast<T>(value: Any?, as type: T.Type) -> T? {
        guard let value = value else { return nil }
        switch T.self {
        case is Date.Type:
            return (value as? NSNumber)
                .map { Date(timeIntervalSince1970: $0.doubleValue) } as? T
        case is Decimal.Type:
            return (value as? NSNumber)?.decimalValue as? T
        case let type as any UnsignedInteger.Type:
            return ((value as? NSNumber)?.uint64Value)
                .map { type.init($0) } as? T
        case let type as any SignedInteger.Type:
            return ((value as? NSNumber)?.int64Value)
                .map { type.init($0) } as? T
        case let type as any BinaryFloatingPoint.Type:
            return ((value as? NSNumber)?.doubleValue)
                .map { type.init($0) } as? T
        case is URL.Type, is NSURL.Type:
            return (value as? String)
                .map { URL(string: $0) } as? T
        case is Locale.Type, is NSLocale.Type:
            return (value as? String)
                .map { Locale(bcp47: $0) } as? T
        case is (any JSONWebKey).Protocol:
            guard let data = try? JSONEncoder().encode(AnyCodable(value)) else { return nil }
            return try? AnyJSONWebKey.deserialize(data) as? T
        case let type as any Decodable.Type:
            if let value = value as? T {
                return value
            } else {
                let value = AnyCodable(value)
                guard let data = try? JSONEncoder().encode(value) else { return nil }
                return try? JSONDecoder().decode(type, from: data) as? T
            }
        case is Encodable.Type:
            return value as? T
        default:
            assertionFailure("Unknown storage type")
            return nil
        }
    }
    
    private func get<T>(key: String, as _: T.Type) -> T? {
        JSONWebValueStorage.cast(value: claims[key]?.value, as: T.self)
    }
    
    private mutating func updateValue(key: String, value: Any?) {
        remove(key: key)
        guard let value = value else { return }
        
        switch value {
        case let value as Date:
            // Dates in JWT are `NumericDate` which is a JSON numeric value representing
            // the number of seconds from 1970-01-01T00:00:00Z UTC until
            // the specified UTC date/time, ignoring leap seconds.
            claims[key] = .init(Int(value.timeIntervalSince1970))
        case let value as UUID:
            // Standards such as ITU-T X.667 and RFC 4122 require them to be formatted
            // using lower-case letters.
            // The NSUUID class and UUID struct use upper-case letters when formatting.
            claims[key] = .init(value.uuidString.lowercased())
        case let value as Locale:
            // Locales in OIDC is formatted using BCP-47 while Apple uses CLDR/ICU formatting.
            claims[key] = .init(value.bcp47)
        case let value as any Decodable:
            claims[key] = .init(value)
        default:
            assertionFailure("Unknown storage type")
        }
    }
}

extension Locale {
    fileprivate var bcp47: String {
        if #available(macOS 13, iOS 16, tvOS 16, watchOS 9, *) {
            return identifier(.bcp47)
        } else {
            return identifier.replacingOccurrences(of: "_", with: "-")
        }
    }
    
    fileprivate init(bcp47: String) {
        if #available(macOS 13, iOS 16, tvOS 16, watchOS 9, *) {
            self.init(components: .init(identifier: bcp47))
        } else {
            self.init(identifier: bcp47.replacingOccurrences(of: "-", with: "_"))
        }
    }
}
