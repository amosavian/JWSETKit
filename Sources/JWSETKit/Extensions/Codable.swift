//
//  Codable.swift
//  JWSETKit
//
//  Created by Amir Abbas Mousavian on 1/22/25.
//

@usableFromInline
@frozen
struct AnyCodable: Codable, @unchecked Sendable {
    let value: (any Sendable)?
    
    var codableValue: JSONWebValueStorage.Value? {
        guard let value else {
            return nil
        }
        if let val = value as? [JSONWebValueStorage.Key: (any Codable)?] {
            return (val as! JSONWebValueStorage.Value)
        }
        return ([value] as? [JSONWebValueStorage.Value])?[0]
    }
    
    @usableFromInline
    init<T: Sendable>(_ value: T?) {
        if let value = value as? AnyCodable {
            self = value
        } else {
            self.value = value
        }
    }
    
    @usableFromInline
    init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        
        if container.decodeNil() {
            self.init(Self?.none)
        } else if let string = try? container.decode(String.self) {
            self.init(string)
        } else if let int = try? container.decode(Int.self) {
            self.init(int)
        } else if var unkeyed = try? decoder.unkeyedContainer() {
            var array: [(any Sendable)?] = []
            array.reserveCapacity(unkeyed.count ?? 0)
            while !unkeyed.isAtEnd {
                try array.append(unkeyed.decode(AnyCodable.self).value)
            }
            self.init(array)
        } else if let uint = try? container.decode(UInt.self) {
            self.init(uint)
        } else if let double = try? container.decode(Double.self) {
            self.init(double)
        } else if let bool = try? container.decode(Bool.self) {
            self.init(bool)
        } else if let keyed = try? decoder.container(keyedBy: AnyCodingKey.self) {
            var dictionary: [String: (any Sendable)?] = .init(minimumCapacity: keyed.allKeys.count)
            for key in keyed.allKeys {
                dictionary[key.stringValue] = try keyed.decode(AnyCodable.self, forKey: key).value
            }
            self.init(dictionary)
        } else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Value cannot be decoded")
        }
    }
    
    @usableFromInline
    func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        
        switch value {
        case nil:
            try container.encodeNil()
        case let value as String:
            try container.encode(value)
        case let value as Int:
            try container.encode(value)
        case let value as Bool:
            try container.encode(value)
        case let value as Double:
            try container.encode(value)
        case let value as any JSONWebFieldEncodable:
            let encodableValue = value.jsonWebValue as any Encodable
            try container.encode(encodableValue)
        case let value as [(any Sendable)?]:
            var container = encoder.unkeyedContainer()
            for element in value {
                try container.encode(AnyCodable(element))
            }
            return
        case let value as [String: (any Sendable)?]:
            var container = encoder.container(keyedBy: AnyCodingKey.self)
            for (key, element) in value {
                try container.encode(AnyCodable(element), forKey: AnyCodingKey(key))
            }
            return
        case let value as any Encodable:
            try container.encode(value)
        default:
            let context = EncodingError.Context(codingPath: container.codingPath, debugDescription: "Value cannot be encoded")
            throw EncodingError.invalidValue(value as Any, context)
        }
    }
}

extension AnyCodable: CustomReflectable {
    @usableFromInline
    var customMirror: Mirror {
        Mirror(reflecting: value as Any)
    }
}

@frozen
@usableFromInline
struct AnyCodingKey: CodingKey {
    @usableFromInline
    let stringValue: String
    
    @usableFromInline
    var intValue: Int? {
        nil
    }
    
    init(_ stringValue: String) {
        self.stringValue = stringValue
    }
    
    @usableFromInline
    init(stringValue: String) {
        self.stringValue = stringValue
    }
    
    @usableFromInline
    init(intValue: Int) {
        self.stringValue = String(intValue)
    }
}
