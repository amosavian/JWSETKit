//
//  JWTOIDCStandard.swift
//
//
//  Created by Amir Abbas Mousavian on 9/6/23.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// The Address Claim represents a physical mailing address.
///
/// Implementations MAY return only a subset of the fields of an address,
/// depending upon the information available and the End-User's privacy preferences.
/// For example, the country and region might be returned without returning more fine-grained address information.
///
/// Implementations MAY return just the full address as a single string in the formatted sub-field,
/// or they MAY return just the individual component fields using the other sub-fields,
/// or they MAY return both. If both variants are returned, they SHOULD be describing the same address,
/// with the formatted address indicating how the component fields are combined.
public struct JSONWebAddress: Hashable, Codable, Sendable {
    enum CodingKeys: String, CodingKey {
        case formatted
        case streetAddress = "street_address"
        case locality
        case region
        case postalCode = "postal_code"
        case country
    }
    
    /// Full mailing address, formatted for display or use on a mailing label.
    ///
    /// This field MAY contain multiple lines, separated by newlines.
    /// Newlines can be represented either as a carriage return/line feed pair ("`\r\n`")
    /// or as a single line feed character ("`\n`").
    public var formatted: String?
    
    /// Full street address component, which MAY include house number, street name, Post Office Box,
    /// and multi-line extended street address information.
    ///
    /// This field MAY contain multiple lines, separated by newlines.
    /// Newlines can be represented either as a carriage return/line feed pair ("`\r\n`")
    /// or as a single line feed character ("`\n`").
    public var streetAddress: String?
    
    /// City or locality component.
    public var locality: String?
    
    /// State, province, prefecture, or region component.
    public var region: String?
    
    /// Zip code or postal code component.
    public var postalCode: String?
    
    /// Country name component.
    public var country: String?
    
    /// Initializes the Address Claim represents a physical mailing address.
    public init(formatted: String? = nil, streetAddress: String? = nil, locality: String? = nil, region: String? = nil, postalCode: String? = nil, country: String? = nil) {
        self.formatted = formatted
        self.streetAddress = streetAddress
        self.locality = locality
        self.region = region
        self.postalCode = postalCode
        self.country = country
    }
}

/// Claims registered in [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken2)
public struct JSONWebTokenClaimsPublicOIDCStandardParameters: JSONWebContainerParameters {
    /// End-User's full name in displayable form including all name parts, possibly including titles and suffixes,
    /// ordered according to the End-User's locale and preferences.
    public var name: String?
    
    /// Given name(s) or first name(s) of the End-User.
    ///
    /// Note that in some cultures, people can have multiple given names; all can be present,
    /// with the names being separated by space characters.
    public var givenName: String?
    
    /// Surname(s) or last name(s) of the End-User.
    ///
    /// Note that in some cultures, people can have multiple family names or no family name;
    /// all can be present, with the names being separated by space characters.
    public var familyName: String?
    
    /// Middle name(s) of the End-User.
    ///
    /// Note that in some cultures, people can have multiple middle names; all can be present,
    /// with the names being separated by space characters.
    /// Also note that in some cultures, middle names are not used.
    public var middleName: String?
    
    /// Casual name of the End-User that may or may not be the same as the ‍`given_name`.
    ///
    /// For instance, a `nickname` value of `Mike` might be returned alongside a `given_name` value of `Michael`.
    public var nickname: String?
    
    /// Shorthand name by which the End-User wishes to be referred to at the RP, such as janedoe or j.doe.
    ///
    /// This value MAY be any valid JSON string including special characters such as @, /, or whitespace.
    /// The RP MUST NOT rely upon this value being unique, as discussed in
    /// [Section 5.7](https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability).
    public var preferredUsername: String?
    
    /// URL of the End-User's profile page. The contents of this Web page SHOULD be about the End-User.
    public var profileURL: URL?
    
    /// URL of the End-User's profile picture.
    ///
    /// This URL MUST refer to an image file (for example, a PNG, JPEG, or GIF image file),
    /// rather than to a Web page containing an image.
    ///
    /// Note that this URL SHOULD specifically reference a profile photo of the End-User suitable
    /// for displaying when describing the End-User, rather than an arbitrary photo taken by the End-User.
    public var pictureURL: URL?
    
    /// URL of the End-User's Web page or blog.
    ///
    /// This Web page SHOULD contain information published by the End-User
    /// or an organization that the End-User is affiliated with.
    public var websiteURL: URL?
    
    /// End-User's preferred e-mail address.
    ///
    /// Its value MUST conform to the
    /// [RFC 5322](https://openid.net/specs/openid-connect-core-1_0.html#RFC5322)
    /// addr-spec syntax.
    ///
    /// The RP MUST NOT rely upon this value being unique, as discussed in
    /// [Section 5.7](https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability).
    public var email: String?
    
    /// `True` if the End-User's e-mail address has been verified; otherwise `false`.
    ///
    /// When this Claim Value is `true`, this means that the OP took affirmative steps
    /// to ensure that this e-mail address was controlled by the End-User
    /// at the time the verification was performed.
    ///
    /// The means by which an e-mail address is verified is context-specific,
    /// and dependent upon the trust framework or contractual agreements within which the parties are operating.
    public var isEmailVerified: Bool
    
    /// End-User's gender.
    ///
    /// Values defined by this specification are `female` and `male`.
    /// Other values MAY be used when neither of the defined values are applicable.
    public var gender: String?
    
    /// End-User's birthday, represented as an
    /// [ISO 8601:2004](https://openid.net/specs/openid-connect-core-1_0.html#ISO8601-2004)
    /// `YYYY-MM-DD` format.
    ///
    /// The year MAY be `0000`, indicating that it is omitted. To represent only the year, `YYYY` format is allowed.
    ///
    /// Note that depending on the underlying platform's date related function,
    /// providing just year can result in varying month and day, so the implementers need
    /// to take this factor into account to correctly process the dates.
    public var birthdate: Date?
    
    /// String from [zoneinfo](https://openid.net/specs/openid-connect-core-1_0.html#zoneinfo)
    /// time zone database representing the End-User's time zone.
    ///
    /// For example, `Europe/Paris` or `America/Los_Angeles`.
    public var zoneInfo: TimeZone?
    
    /// End-User's locale, represented as a
    /// BCP47 [RFC5646](https://openid.net/specs/openid-connect-core-1_0.html#RFC5646)
    /// language tag.
    ///
    /// This is typically an ISO 639-1 Alpha-2 [ISO639‑1](https://openid.net/specs/openid-connect-core-1_0.html#ISO639-1)
    /// language code in lowercase and
    /// an ISO 3166-1 Alpha-2 [ISO3166‑1](https://openid.net/specs/openid-connect-core-1_0.html#ISO3166-1)
    /// country code in uppercase, separated by a dash.
    /// For example, `en-US` or `fr-CA`. As a compatibility note, some implementations
    /// have used an underscore as the separator rather than a dash,
    /// for example, `en_US`; Relying Parties MAY choose to accept this locale syntax as well.
    public var locale: Locale?
    
    /// End-User's preferred telephone number.
    ///
    /// [E.164](https://openid.net/specs/openid-connect-core-1_0.html#E.164) is RECOMMENDED
    /// as the format of this Claim, for example, +1 (425) 555-1212 or +56 (2) 687 2400. If the phone number
    /// contains an extension, it is RECOMMENDED that the extension be represented using
    /// the [RFC3966](https://openid.net/specs/openid-connect-core-1_0.html#RFC3966)
    /// extension syntax, for example, +1 (604) 555-1234;ext=5678.
    public var phoneNumber: String?
    
    /// True if the End-User's phone number has been verified; otherwise false.
    ///
    /// When this Claim Value is `true`, this means that the OP took affirmative steps
    /// to ensure that this phone number was controlled by the End-User at the time
    /// the verification was performed.
    ///
    /// The means by which a phone number is verified is context-specific, and dependent
    /// upon the trust framework or contractual agreements within which the parties are operating.
    /// When `true`, the `phone_number` Claim MUST be in E.164 format and any extensions
    /// MUST be represented in RFC 3966 format.
    public var isPhoneNumberVerified: Bool
    
    /// End-User's preferred postal address.
    ///
    /// The value of the address member is
    /// a JSON [RFC4627](https://openid.net/specs/openid-connect-core-1_0.html#RFC4627)
    /// structure containing some or all of the members defined in Section 5.1.1.
    public var address: JSONWebAddress?
    
    /// Time the End-User's information was last updated.
    ///
    /// Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z as measured in UTC
    /// until the date/time.
    public var updatedAt: Date?
    
    @_documentation(visibility: private)
    public static let keys: [SendablePartialKeyPath<Self>: String] = [
        \.name: "name", \.givenName: "given_name", \.familyName: "family_name",
        \.middleName: "middle_name", \.nickname: "nickname", \.preferredUsername: "preferred_username",
        \.profileURL: "profile", \.pictureURL: "picture", \.websiteURL: "website",
        \.email: "email", \.isEmailVerified: "email_verified",
        \.gender: "gender", \.birthdate: "birthdate",
        \.zoneInfo: "zoneinfo", \.locale: "locale",
        \.phoneNumber: "phone_number", \.isPhoneNumberVerified: "phone_number_verified",
        \.address: "address", \.updatedAt: "updated_at",
    ]
    
    @_documentation(visibility: private)
    public static let localizableKeys: [SendablePartialKeyPath<Self>] = [
        \.name, \.givenName, \.familyName, \.middleName, \.nickname,
        \.profileURL, \.websiteURL,
    ]
}

extension JSONWebTokenClaims {
    public subscript<T: JSONWebValueStorage.ValueType>(_ keyPath: SendableKeyPath<JSONWebTokenClaimsPublicOIDCStandardParameters, T?>, locale: Locale) -> T? {
        get {
            storage[stringKey(keyPath, locale: locale)]
        }
        set {
            storage[stringKey(keyPath, force: true, locale: locale)] = newValue
        }
    }
    
    @_documentation(visibility: private)
    @inlinable
    public subscript<T: JSONWebValueStorage.ValueType>(dynamicMember keyPath: SendableKeyPath<JSONWebTokenClaimsPublicOIDCStandardParameters, T?>) -> T? {
        get {
            storage[stringKey(keyPath)]
        }
        set {
            storage[stringKey(keyPath)] = newValue
        }
    }
    
    @_documentation(visibility: private)
    @inlinable
    public subscript(dynamicMember keyPath: SendableKeyPath<JSONWebTokenClaimsPublicOIDCStandardParameters, Bool>) -> Bool {
        get {
            storage[stringKey(keyPath)] ?? false
        }
        set {
            storage[stringKey(keyPath)] = newValue
        }
    }
    
    @_documentation(visibility: private)
    public subscript(dynamicMember keyPath: SendableKeyPath<JSONWebTokenClaimsPublicOIDCStandardParameters, Date?>) -> Date? {
        get {
            let key = stringKey(keyPath)
            switch keyPath {
            case \.birthdate:
                return storage[key].flatMap(Date.init(iso8601Date:))
            default:
                return storage[key]
            }
        }
        set {
            let key = stringKey(keyPath)
            switch keyPath {
            case \.birthdate:
                storage[key] = newValue?.iso8601Date
            default:
                storage[key] = newValue
            }
        }
    }
}
