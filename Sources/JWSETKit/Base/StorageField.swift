//
//  StorageField.swift
//
//
//  Created by Amir Abbas Mousavian on 1/19/24.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto

protocol JSONWebFieldEncodable {
    associatedtype JSONWebFieldValueType: Codable & Hashable & Sendable
    var jsonWebValue: JSONWebFieldValueType { get }
}

protocol JSONWebFieldDecodable {
    static func castValue(_ value: Any?) -> Self?
}

extension Optional: JSONWebFieldEncodable where Wrapped: JSONWebFieldEncodable {
    var jsonWebValue: Wrapped.JSONWebFieldValueType? {
        self?.jsonWebValue
    }
}

extension Optional: JSONWebFieldDecodable where Wrapped: JSONWebFieldDecodable {
    static func castValue(_ value: Any?) -> Self? {
        Wrapped.castValue(value)
    }
}

extension Bool: JSONWebFieldDecodable {
    static func castValue(_ value: Any?) -> Bool? {
        switch value {
        case let value as Self:
            value
        case let value as String:
            Bool(value)
        case let value as any BinaryInteger:
            Int(value) != 0
        default:
            nil
        }
    }
}

extension JSONWebFieldEncodable where Self: RandomAccessCollection, Self.Element == UInt8 {
    var jsonWebValue: String {
        // Default encoding for data is `Base64URL`.
        urlBase64EncodedString()
    }
}

extension JSONWebFieldDecodable where Self: DataProtocol & RangeReplaceableCollection {
    static func castValue(_ value: Any?) -> Self? {
        switch value {
        case let value as Self:
            value
        case let value as String:
            Self(urlBase64Encoded: value)
        case let value as any Collection<UInt8>:
            Self(value)
        default:
            nil
        }
    }
}

extension Data: JSONWebFieldEncodable, JSONWebFieldDecodable {}

extension [UInt8]: JSONWebFieldEncodable, JSONWebFieldDecodable {}

extension Date: JSONWebFieldEncodable, JSONWebFieldDecodable {
    var jsonWebValue: Int {
        // Dates in JWT are `NumericDate` which is a JSON numeric value representing
        // the number of seconds from 1970-01-01T00:00:00Z UTC until
        // the specified UTC date/time, ignoring leap seconds.
        Int(timeIntervalSince1970)
    }
    
    static func castValue(_ value: Any?) -> Self? {
        switch value {
        case let value as any BinaryInteger:
            Date(timeIntervalSince1970: TimeInterval(value))
        case let value as any BinaryFloatingPoint:
            Date(timeIntervalSince1970: TimeInterval(value))
        case let value as Date:
            value
        case let value as String:
            if let value = TimeInterval(value) {
                Date(timeIntervalSince1970: value)
            } else {
                Date(iso8601: value)
            }
        default:
            nil
        }
    }
    
    @usableFromInline
    init?(iso8601 value: String) {
#if canImport(FoundationEssentials)
        if let value = try? Date.ISO8601FormatStyle.iso8601.parse(value) {
            self = value
            return
        }
#else
        if let value = ISO8601DateFormatter().date(from: value) {
            self = value
            return
        }
#endif
        return nil
    }
    
    @usableFromInline
    init?(iso8601Date value: String) {
#if canImport(FoundationEssentials)
        if let value = try? Date.ISO8601FormatStyle.iso8601.year().month().day().parse(value) {
            self = value
            return
        }
#else
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = .withFullDate
        if let value = formatter.date(from: value) {
            self = value
            return
        }
#endif
        return nil
    }
    
    @usableFromInline
    var iso8601: String {
#if canImport(FoundationEssentials)
        return Date.ISO8601FormatStyle.iso8601.format(self)
#else
        return ISO8601DateFormatter().string(from: self)
#endif
    }
    
    @usableFromInline
    var iso8601Date: String {
#if canImport(FoundationEssentials)
        return Date.ISO8601FormatStyle.iso8601.year().month().day().format(self)
#else
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = .withFullDate
        return formatter.string(from: self)
#endif
    }
}

extension Decimal: JSONWebFieldDecodable {
    static func castValue(_ value: Any?) -> Self? {
        switch value {
        case let value as any BinaryInteger:
            Decimal(exactly: value)
        case let value as any BinaryFloatingPoint:
            Decimal(Double(value))
        case let value as String:
            Decimal(string: value)
        default:
            nil
        }
    }
}

extension Locale: JSONWebFieldEncodable, JSONWebFieldDecodable {
    var jsonWebValue: String {
        // Locales in OIDC is formatted using BCP-47 while Apple uses CLDR/ICU formatting.
        bcp47
    }
    
    static func castValue(_ value: Any?) -> Self? {
        switch value {
        case let value as Self:
            value
        case let value as String:
            Locale(bcp47: value)
        default:
            nil
        }
    }
}

extension TimeZone: JSONWebFieldEncodable, JSONWebFieldDecodable {
    var jsonWebValue: String {
        // Timezone in OIDC is formatted using IANA formatting.
        identifier
    }
    
    static func castValue(_ value: Any?) -> Self? {
        switch value {
        case let value as Self:
            value
        case let value as String:
            TimeZone(identifier: value)
        default:
            nil
        }
    }
}

extension URL: JSONWebFieldEncodable, JSONWebFieldDecodable {
    var jsonWebValue: String {
        absoluteString
    }
    
    static func castValue(_ value: Any?) -> Self? {
        switch value {
        case let value as Self:
            value
        case let value as String:
            URL(string: value)
        default:
            nil
        }
    }
}

extension UUID: JSONWebFieldEncodable {
    var jsonWebValue: String {
        // Standards such as ITU-T X.667 and RFC 4122 require them to be formatted
        // using lower-case letters.
        // The NSUUID class and UUID struct use upper-case letters when formatting.
        uuidString.lowercased()
    }
}

extension SymmetricKey: JSONWebFieldEncodable, JSONWebFieldDecodable {
    var jsonWebValue: String {
        data.urlBase64EncodedString()
    }
    
    static func castValue(_ value: Any?) -> SymmetricKey? {
        switch value {
        case let value as Self:
            return value
        case let value as Data:
            return .init(data: value)
        case let value as String:
            guard let value = Data(urlBase64Encoded: value) else {
                return nil
            }
            return .init(data: value)
        default:
            return nil
        }
    }
}
