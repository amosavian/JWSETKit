//
//  Error.swift
//
//
//  Created by Amir Abbas Mousavian on 9/7/23.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// Error type thrown by JWSETKit framework.
public protocol JSONWebError: LocalizedError {
    /// Localized error description in given locale's language.
    func localizedError(for locale: Locale) -> String
}

extension JSONWebError {
    public var errorDescription: String? {
        localizedError(for: .current)
    }
}

/// Errors occurred during key creation or usage.
///
/// - Note: Localization of `errorDescription` can be changes by setting `jsonWebKeyLocale`.
public enum JSONWebKeyError: JSONWebError, Sendable {
    /// Given algorithm is unsupported in the framework.
    case unknownAlgorithm
    
    /// Key type is not defined.
    ///
    /// Supported key types are `"EC"`, `"RSA"`, `"oct"`.
    case unknownKeyType
    
    /// Decipherment of given cipher-text has failed.
    case decryptionFailed
    
    /// Key not found.
    case keyNotFound
    
    /// Operation is not allowed with given class/struct or key.
    case operationNotAllowed
    
    /// Key format is invalid.
    case invalidKeyFormat
    
    /// A localized message describing what error occurred.
    public func localizedError(for locale: Locale) -> String {
        switch self {
        case .unknownAlgorithm:
            return .init(localizingKey: "errorUnknownAlgorithm", locale: locale)
        case .unknownKeyType:
            return .init(localizingKey: "errorUnknownKeyType", locale: locale)
        case .decryptionFailed:
            return .init(localizingKey: "errorDecryptionFailed", locale: locale)
        case .keyNotFound:
            return .init(localizingKey: "errorKeyNotFound", locale: locale)
        case .operationNotAllowed:
            return .init(localizingKey: "errorOperationNotAllowed", locale: locale)
        case .invalidKeyFormat:
            return .init(localizingKey: "errorInvalidKeyFormat", locale: locale)
        }
    }
}

/// Validation errors including expired token.
///
/// - Note: Localization of `errorDescription` can be changes by setting `jsonWebKeyLocale`.
public enum JSONWebValidationError: JSONWebError, Sendable {
    /// Current date is after `"exp"` claim in token.
    case tokenExpired(expiry: Date)
    
    /// Current date is before `"nbf"` claim in token.
    case tokenInvalidBefore(notBefore: Date)
    
    /// Given audience is not enlisted in `"aud"` claim in token.
    case audienceNotIntended(String)
    
    /// A required field is missing.
    case missingRequiredField(key: String)
    
    /// A localized message describing what error occurred.
    public func localizedError(for locale: Locale) -> String {
        let dateFormatter = DateFormatter()
        dateFormatter.locale = locale
        dateFormatter.dateStyle = .medium
        dateFormatter.timeStyle = .medium
        switch self {
        case .tokenExpired(let date):
            return .init(localizingKey: "errorExpiredToken", locale: locale, dateFormatter.string(from: date))
        case .tokenInvalidBefore(let date):
            return .init(localizingKey: "errorNotBeforeToken", locale: locale, dateFormatter.string(from: date))
        case .audienceNotIntended(let audience):
            return .init(localizingKey: "errorInvalidAudience", locale: locale, audience)
        case .missingRequiredField(let key):
            return .init(localizingKey: "errorMissingField", locale: locale, key)
        }
    }
}
