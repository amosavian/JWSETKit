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
    
    public init(storage: JSONWebValueStorage) {
        self.storage = storage
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
        try verify(using: JSONWebKeySet(keys: [key]), for: audience)
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
    
#if canImport(Foundation)
    public func addUserInfo(
        person: PersonNameComponents,
        gender: String? = nil,
        birthdate: Date? = nil,
        zoneInfo: TimeZone? = nil,
        locale: Locale? = nil,
        address: JSONWebAddress? = nil
    ) -> Self {
        var result = self
        let formatter = PersonNameComponentsFormatter()
        formatter.locale = locale ?? .autoupdatingCurrent
        result.name = formatter.string(from: person)
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
