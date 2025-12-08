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
            return .init(
                localizingKey: "errorUnknownAlgorithm",
                value: "Given signature/encryption algorithm is no supported.",
                locale: locale
            )
        case .unknownKeyType:
            return .init(
                localizingKey: "errorUnknownKeyType", value: "Key type is not supported.",
                locale: locale
            )
        case .decryptionFailed:
            return .init(
                localizingKey: "errorDecryptionFailed",
                value: "Decrypting cipher-text using given key is not possible.",
                locale: locale
            )
        case .keyNotFound:
            return .init(
                localizingKey: "errorKeyNotFound",
                value: "Failed to find given key.",
                locale: locale
            )
        case .operationNotAllowed:
            return .init(
                localizingKey: "errorOperationNotAllowed",
                value: "Operation Not Allowed.",
                locale: locale
            )
        case .invalidKeyFormat:
            return .init(
                localizingKey: "errorInvalidKeyFormat",
                value: "Invalid Key Format",
                locale: locale
            )
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
    
    /// Duplicate disclosure digest found in SD-JWT `_sd` array.
    case duplicateDisclosureDigest
    
    /// Disclosure has no matching digest reference in SD-JWT payload.
    case orphanDisclosure
    
    /// Key binding JWT is required but not present in the SD-JWT presentation.
    case keyBindingRequired
    
    /// Key binding JWT validation failed with an underlying error.
    case invalidKeyBinding
    
    private func formatDate(_ date: Date, locale: Locale) -> String {
#if canImport(Foundation.NSDateFormatter)
        let dateFormatter = DateFormatter()
        dateFormatter.locale = locale
        dateFormatter.dateStyle = .medium
        dateFormatter.timeStyle = .medium
        return dateFormatter.string(from: date)
#else
        return date.iso8601
#endif
    }
    
    /// A localized message describing what error occurred.
    public func localizedError(for locale: Locale) -> String {
        switch self {
        case .tokenExpired(let date):
            return .init(
                localizingKey: "errorExpiredToken",
                value: "Token is invalid after %@",
                locale: locale,
                formatDate(date, locale: locale)
            )
        case .tokenInvalidBefore(let date):
            return .init(
                localizingKey: "errorNotBeforeToken",
                value: "Token is invalid before %@",
                locale: locale,
                formatDate(date, locale: locale)
            )
        case .audienceNotIntended(let audience):
            return .init(
                localizingKey: "errorInvalidAudience",
                value: "Audience \"%@\" is not intended for the token.",
                locale: locale,
                audience
            )
        case .missingRequiredField(let key):
            return .init(
                localizingKey: "errorMissingField",
                value: "Required \"%@\" field is missing.",
                locale: locale,
                key
            )
        case .duplicateDisclosureDigest:
            return .init(
                localizingKey: "errorDuplicateDigest",
                value: "Duplicate disclosure digest found in SD-JWT.",
                locale: locale
            )
        case .orphanDisclosure:
            return .init(
                localizingKey: "errorOrphanDisclosure",
                value: "Disclosure has no matching digest in SD-JWT payload.",
                locale: locale
            )
        case .keyBindingRequired:
            return .init(
                localizingKey: "errorKeyBindingRequired",
                value: "Key binding JWT is required but not present.",
                locale: locale
            )
        case .invalidKeyBinding:
            return .init(
                localizingKey: "errorInvalidKeyBinding",
                value: "Key binding JWT validation failed",
                locale: locale
            )
        }
    }
}
