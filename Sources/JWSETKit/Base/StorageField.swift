//
//  StorageField.swift
//
//
//  Created by Amir Abbas Mousavian on 1/19/24.
//

import Foundation

protocol JSONWebFieldEncodable {
    var jsonWebValue: (any Encodable)? { get }
}

protocol JSONWebFieldDecodable {
    static func castValue(_ value: Any?) -> Self?
}

protocol JSONWebFieldDeserializable: Decodable {
    static func deseralize(data: Data) throws -> Self
}

extension Optional: JSONWebFieldEncodable where Wrapped: JSONWebFieldEncodable {
    var jsonWebValue: (any Encodable)? {
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
        case let value as Bool:
            return value
        case let value as String:
            return Bool(value)
        case let value as NSNumber:
            return value.boolValue
        default:
            return nil
        }
    }
}

extension Data: JSONWebFieldEncodable, JSONWebFieldDecodable {
    var jsonWebValue: (any Encodable)? {
        // Default encoding for data is `Base64URL`.
        urlBase64EncodedString()
    }
    
    static func castValue(_ value: Any?) -> Self? {
        (value as? String)
            .flatMap {
                Data(urlBase64Encoded: $0) ?? Data(base64Encoded: $0, options: [.ignoreUnknownCharacters])
            }
    }
}

extension [UInt8]: JSONWebFieldEncodable, JSONWebFieldDecodable {
    var jsonWebValue: (any Encodable)? {
        // Default encoding for data is `Base64URL`.
        urlBase64EncodedString()
    }
    
    static func castValue(_ value: Any?) -> Self? {
        Data.castValue(value).map([UInt8].init)
    }
}

extension Date: JSONWebFieldEncodable, JSONWebFieldDecodable {
    var jsonWebValue: (any Encodable)? {
        // Dates in JWT are `NumericDate` which is a JSON numeric value representing
        // the number of seconds from 1970-01-01T00:00:00Z UTC until
        // the specified UTC date/time, ignoring leap seconds.
        Int(timeIntervalSince1970)
    }
    
    static func castValue(_ value: Any?) -> Self? {
        (value as? NSNumber)
            .map { Date(timeIntervalSince1970: $0.doubleValue) }
    }
}

extension Decimal: JSONWebFieldDecodable {
    static func castValue(_ value: Any?) -> Self? {
        switch value {
        case let value as NSNumber:
            return value.decimalValue
        case let value as String:
            return Decimal(string: value)
        default:
            return nil
        }
    }
}

extension Locale: JSONWebFieldEncodable, JSONWebFieldDecodable {
    var jsonWebValue: (any Encodable)? {
        // Locales in OIDC is formatted using BCP-47 while Apple uses CLDR/ICU formatting.
        bcp47
    }
    
    static func castValue(_ value: Any?) -> Self? {
        (value as? String)
            .map { Locale(bcp47: $0) }
    }
}

extension TimeZone: JSONWebFieldEncodable, JSONWebFieldDecodable {
    var jsonWebValue: (any Encodable)? {
        // Timezone in OIDC is formatted using BCP-47 while Apple uses CLDR/ICU formatting.
        identifier
    }
    
    static func castValue(_ value: Any?) -> Self? {
        (value as? String)
            .flatMap { TimeZone(identifier: $0) }
    }
}

extension URL: JSONWebFieldDecodable {
    static func castValue(_ value: Any?) -> Self? {
        (value as? String)
            .flatMap { URL(string: $0) }
    }
}

extension UUID: JSONWebFieldEncodable {
    var jsonWebValue: (any Encodable)? {
        // Standards such as ITU-T X.667 and RFC 4122 require them to be formatted
        // using lower-case letters.
        // The NSUUID class and UUID struct use upper-case letters when formatting.
        uuidString.lowercased()
    }
}
