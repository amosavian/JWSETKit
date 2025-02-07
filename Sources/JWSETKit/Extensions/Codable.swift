//
//  Codable.swift
//  JWSETKit
//
//  Created by Amir Abbas Mousavian on 1/22/25.
//

struct AnyEncodable: Encodable {
    private let encodeClosure: (any Encoder) throws -> Void

    init<T: Encodable>(_ value: T) {
        self.encodeClosure = value.encode
    }

    func encode(to encoder: any Encoder) throws {
        try encodeClosure(encoder)
    }
}

extension Array where Element == any Encodable {
    func encodable() -> AnyEncodable {
        var encodableDict = [AnyEncodable]()
        for value in self {
            encodableDict.append(.init(value))
        }
        return AnyEncodable(encodableDict)
    }
}

extension Dictionary where Key == String, Value == any Encodable {
    func encodable() -> AnyEncodable {
        var encodableDict = [String: AnyEncodable]()
        for (key, value) in self {
            encodableDict[key] = AnyEncodable(value)
        }
        return AnyEncodable(encodableDict)
    }
}

@usableFromInline
@frozen
struct AnyCodable: Codable, @unchecked Sendable {
    let value: (any Sendable)?
    private var mirror: Mirror
    
    @usableFromInline
    init<T: Sendable>(_ value: T?) {
        if let value = value as? AnyCodable {
            self = value
        } else {
            self.value = value
        }
        self.mirror = value.customMirror
    }
    
    @usableFromInline
    init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()

        if container.decodeNil() {
            self.init(Self?.none)
        } else if let bool = try? container.decode(Bool.self) {
            self.init(bool)
        } else if let int = try? container.decode(Int.self) {
            self.init(int)
        } else if let uint = try? container.decode(UInt.self) {
            self.init(uint)
        } else if let double = try? container.decode(Double.self) {
            self.init(double)
        } else if let string = try? container.decode(String.self) {
            self.init(string)
        } else if let array = try? container.decode([AnyCodable].self) {
            self.init(array.map { $0.value })
        } else if let dictionary = try? container.decode([String: AnyCodable].self) {
            self.init(dictionary.mapValues { $0.value })
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
        case let value as any Encodable:
            try container.encode(value)
        case let value as any JSONWebFieldEncodable:
            try container.encode(value.jsonWebValue)
        case let value as [(any Sendable)?]:
            try container.encode(value.map { AnyCodable($0) })
        case let value as [String: (any Sendable)?]:
            try container.encode(value.mapValues { AnyCodable($0) })
        default:
            let context = EncodingError.Context(codingPath: container.codingPath, debugDescription: "Value cannot be encoded")
            throw EncodingError.invalidValue(value as Any, context)
        }
    }
}

extension AnyCodable: CustomReflectable {
    @usableFromInline
    var customMirror: Mirror {
        mirror
    }
}
