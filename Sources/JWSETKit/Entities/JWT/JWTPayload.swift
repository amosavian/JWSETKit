//
//  JWTPayload.swift
//
//
//  Created by Amir Abbas Mousavian on 9/5/23.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto

/// Claims and payload in a JWT.
public struct JSONWebTokenClaims: MutableJSONWebContainer, Sendable {
    public var storage: JSONWebValueStorage
    
    private static let numericClaims: Set<String> = ["iat", "exp", "nbf", "auth_time", "updated_at"]

    private static let booleanClaims: Set<String> = ["email_verified", "phone_number_verified"]
    
    public init(storage: JSONWebValueStorage) {
        self.storage = storage
    }
    
    public init(from decoder: any Decoder) throws {
        guard let container = try? decoder.container(keyedBy: AnyCodingKey.self) else {
            self.storage = try JSONWebValueStorage(from: decoder)
            try validate()
            return
        }
        var values: [String: any Sendable] = .init(minimumCapacity: container.allKeys.count)
        for key in container.allKeys {
            values[key.stringValue] = try Self.decodeValue(from: container, forKey: key)
        }
        self.storage = .init(values)
        try validate()
    }
    
    /// Fastpath for known claims' decoding
    private static func decodeValue(
        from container: KeyedDecodingContainer<AnyCodingKey>,
        forKey key: AnyCodingKey
    ) throws -> (any Sendable)? {
        if numericClaims.contains(key.stringValue) {
            if let value = try? container.decode(Int.self, forKey: key) { return value }
            if let value = try? container.decode(Double.self, forKey: key) { return value }
        } else if booleanClaims.contains(key.stringValue) {
            if let value = try? container.decode(Bool.self, forKey: key) { return value }
        }
        return try container.decode(AnyCodable.self, forKey: key).value
    }
}

/// A JWS object that contains JWT registered tokens.
public typealias JSONWebToken = JSONWebSignature<ProtectedJSONWebContainer<JSONWebTokenClaims>>

extension JSONWebTokenClaims {
    /// Verify that the given audience is included as one of the claim's intended audiences.
    ///
    /// - Parameter audience: The exact intended audience.
    public func verifyAudience(includes audience: String) throws {
        // swiftformat:disable:next redundantSelf
        guard self.audience.contains(audience) else {
            throw JSONWebValidationError.audienceNotIntended(audience)
        }
    }
}

extension JSONWebToken {
    /// Verify that the given audience is included as one of the claim's intended audiences.
    ///
    /// - Parameter audience: The exact intended audience.
    public func verifyAudience(includes audience: String) throws {
        try payload.value.verifyAudience(includes: audience)
    }
}

extension JSONWebTokenClaims: Expirable {
    /// Verifies the `exp` and `nbf` headers using current date.
    ///
    /// - Parameters:
    ///   - currentDate: The date that headers will be check against. Default is current system date.
    public func verifyDate(_ currentDate: Date) throws {
        // swiftformat:disable:next redundantSelf
        if let expiry = self.expiry, currentDate > expiry {
            throw JSONWebValidationError.tokenExpired(expiry: expiry)
        }
        // swiftformat:disable:next redundantSelf
        if let notBefore = self.notBefore, currentDate < notBefore {
            throw JSONWebValidationError.tokenInvalidBefore(notBefore: notBefore)
        }
    }
}

extension JSONWebToken {
    /// Verifies token validity and signature.
    ///
    /// - Parameters:
    ///   - keySet: A `JSONWebKeySet` object contains keys that would be used for validation.
    ///   - audience: The exact intended audience, if applicable.
    public func verify(using keySet: JSONWebKeySet, for audience: String? = nil) throws {
        try verifySignature(using: keySet)
        try verifyDate()
        if let audience {
            try verifyAudience(includes: audience)
        }
    }
    
    /// Verifies token validity and signature.
    ///
    /// - Parameters:
    ///   - keys: An array of `JSONWebValidatingKey` that would be used for validation.
    ///   - audience: The exact intended audience, if applicable.
    public func verify<S>(using keys: S, for audience: String? = nil) throws where S: Sequence, S.Element: JSONWebValidatingKey {
        try verify(using: JSONWebKeySet(keys: keys), for: audience)
    }
    
    /// Verifies token validity and signature.
    ///
    /// - Parameters:
    ///   - keys: An array of `JSONWebValidatingKey` that would be used for validation.
    ///   - audience: The exact intended audience, if applicable.
    public func verify<S>(using keys: S, for audience: String? = nil) throws where S: Sequence<any JSONWebValidatingKey> {
        try verify(using: JSONWebKeySet(keys: .init(keys)), for: audience)
    }
    
    /// Verifies token validity and signature.
    ///
    /// - Parameters:
    ///   - key: A `JSONWebValidatingKey` object that would be used for validation.
    ///   - audience: The exact intended audience, if applicable.
    public func verify(using key: some JSONWebValidatingKey, for audience: String? = nil) throws {
        try verify(using: JSONWebKeySet(key: key), for: audience)
    }
}

extension JSONWebTokenClaims {
    /// Sets JWT claims for Authorization token.
    /// Issuing time and `jti` are set by current date and random string.
    ///
    /// - Parameters:
    ///   - issuer: Issuer address or name
    ///   - audience: Aduience the token intended for
    ///   - subject: Identifies the principal that is the subject of the JWT.
    ///   - expiresIn: Time interval that token is valid.
    public func addBase(
        issuer: String, audience: [String] = [],
        authorizedParty: String? = nil, subject: String,
        expiresIn: TimeInterval
    ) -> Self {
        var result = self
        result.issuer = issuer
        result.audience = audience
        result.authorizedParty = authorizedParty
        result.subject = subject
        result.issuedAt = .init()
        result.expiry = .init(timeIntervalSinceNow: expiresIn)
        result.jwtUUID = .init()
        return result
    }
    
#if canImport(Darwin) || !canImport(FoundationEssentials)
    public func addUserInfo(
        person: PersonNameComponents,
        gender: String? = nil,
        birthdate: Date? = nil,
        zoneInfo: TimeZone? = nil,
        locale: Locale? = nil,
        address: JSONWebAddress? = nil
    ) -> Self {
        var result = self
#if canImport(Darwin)
        let formatter = PersonNameComponentsFormatter()
        formatter.locale = locale ?? .autoupdatingCurrent
        result.name = formatter.string(from: person)
#else
        result.name = [person.givenName, person.middleName, person.familyName]
            .compactMap(\.self)
            .joined(separator: " ")
#endif
        result.givenName = person.givenName
        result.familyName = person.familyName
        result.middleName = person.middleName
        result.nickname = person.nickname
        result.gender = gender
        result.birthdate = birthdate
        result.zoneInfo = zoneInfo
        result.locale = locale
        result.address = address
        return result
    }
#endif
    
    public func addUserInfo(
        name: String,
        givenName: String? = nil,
        familyName: String? = nil,
        middleName: String? = nil,
        nickname: String? = nil,
        gender: String? = nil,
        birthdate: Date? = nil,
        zoneInfo: TimeZone? = nil,
        locale: Locale? = nil,
        address: JSONWebAddress? = nil
    ) -> Self {
        var result = self
        result.name = name
        result.givenName = givenName
        result.familyName = familyName
        result.middleName = middleName
        result.nickname = nickname
        result.gender = gender
        result.birthdate = birthdate
        result.zoneInfo = zoneInfo
        result.locale = locale
        result.address = address
        return result
    }
    
    public func addProfile(_ profile: URL?, picture: URL? = nil, website: URL? = nil) -> Self {
        var result = self
        result.profileURL = profile
        result.pictureURL = picture
        result.websiteURL = website
        return result
    }
    
    public func addEmail(_ email: String, isVerified: Bool) -> Self {
        var result = self
        result.email = email
        result.isEmailVerified = isVerified
        return result
    }
    
    public func addPhoneNumber(_ phoneNumber: String, isVerified: Bool) -> Self {
        var result = self
        result.phoneNumber = phoneNumber
        result.isPhoneNumberVerified = isVerified
        return result
    }
}
