//
//  ProtectedContainerForwarding.swift
//  JWSETKit
//
//  Created by Amir Abbas Mousavian.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

// `protected.<field>` on a `ProtectedJSONWebContainer<C>` resolves, via the generic
// `TypedProtectedWebContainer` forwarder, to `value[keyPath: \C.<field>]`. When `C` exposes its
// fields through `@dynamicMemberLookup` (every JOSE container does), that keyPath is a *nested
// computed* keyPath wrapping `C`'s own dynamic subscript; applying it costs ~4–5× the time and
// allocates, vs calling the subscript directly. These per-container overloads accept the container's
// own parameter keyPath and forward to `value[dynamicMember:]` — one direct hop, no nested keyPath.
// They are more specific than the generic forwarder, so they win overload resolution, keeping
// `protected.<field>` at call sites with no penalty. The generic forwarder can't do this: it only
// knows `SendableKeyPath<Container, T>`, not that `Container` has a parameter-keyed dynamic subscript.

extension ProtectedJSONWebContainer where Container == JOSEHeader {
    @_documentation(visibility: private)
    public subscript<T: JSONWebValueStorage.ValueType>(dynamicMember keyPath: SendableKeyPath<JoseHeaderJWSRegisteredParameters, T?>) -> T? {
        value[dynamicMember: keyPath]
    }

    @_documentation(visibility: private)
    public subscript<T: JSONWebValueStorage.ValueType>(dynamicMember keyPath: SendableKeyPath<JoseHeaderJWSRegisteredParameters, [T]>) -> [T] {
        value[dynamicMember: keyPath]
    }

    @_documentation(visibility: private)
    public subscript(dynamicMember keyPath: SendableKeyPath<JoseHeaderJWSRegisteredParameters, Bool>) -> Bool {
        value[dynamicMember: keyPath]
    }

    @_documentation(visibility: private)
    public subscript(dynamicMember keyPath: SendableKeyPath<JoseHeaderJWSRegisteredParameters, (any JSONWebKey)?>) -> (any JSONWebKey)? {
        value[dynamicMember: keyPath]
    }

    @_documentation(visibility: private)
    public subscript(dynamicMember keyPath: SendableKeyPath<JoseHeaderJWSRegisteredParameters, (any JSONWebAlgorithm)?>) -> (any JSONWebAlgorithm)? {
        value[dynamicMember: keyPath]
    }

    @_documentation(visibility: private)
    public subscript(dynamicMember keyPath: SendableKeyPath<JoseHeaderJWSRegisteredParameters, Data?>) -> Data? {
        value[dynamicMember: keyPath]
    }

    @_documentation(visibility: private)
    public subscript(dynamicMember keyPath: SendableKeyPath<JoseHeaderJWSRegisteredParameters, [Data]>) -> [Data] {
        value[dynamicMember: keyPath]
    }
}

extension ProtectedJSONWebContainer where Container == JSONWebTokenClaims {
    @_documentation(visibility: private)
    public subscript<T: JSONWebValueStorage.ValueType>(dynamicMember keyPath: SendableKeyPath<JSONWebTokenClaimsRegisteredParameters, T?>) -> T? {
        value[dynamicMember: keyPath]
    }

    @_documentation(visibility: private)
    public subscript(dynamicMember keyPath: SendableKeyPath<JSONWebTokenClaimsRegisteredParameters, [String]>) -> [String] {
        value[dynamicMember: keyPath]
    }

    @_documentation(visibility: private)
    public subscript(dynamicMember keyPath: SendableKeyPath<JSONWebTokenClaimsRegisteredParameters, [URL]>) -> [URL] {
        value[dynamicMember: keyPath]
    }

    @_documentation(visibility: private)
    public subscript<T: JSONWebValueStorage.ValueType>(dynamicMember keyPath: SendableKeyPath<JSONWebTokenClaimsOAuthParameters, T?>) -> T? {
        value[dynamicMember: keyPath]
    }

    @_documentation(visibility: private)
    public subscript(dynamicMember keyPath: SendableKeyPath<JSONWebTokenClaimsOAuthParameters, [String]>) -> [String] {
        value[dynamicMember: keyPath]
    }

    @_documentation(visibility: private)
    public subscript<T: JSONWebValueStorage.ValueType>(dynamicMember keyPath: SendableKeyPath<JSONWebTokenClaimsPublicOIDCStandardParameters, T?>) -> T? {
        value[dynamicMember: keyPath]
    }

    @_documentation(visibility: private)
    public subscript(dynamicMember keyPath: SendableKeyPath<JSONWebTokenClaimsPublicOIDCStandardParameters, Bool>) -> Bool {
        value[dynamicMember: keyPath]
    }

    @_documentation(visibility: private)
    public subscript(dynamicMember keyPath: SendableKeyPath<JSONWebTokenClaimsPublicOIDCStandardParameters, Date?>) -> Date? {
        value[dynamicMember: keyPath]
    }

    @_documentation(visibility: private)
    public subscript<T: JSONWebValueStorage.ValueType>(dynamicMember keyPath: SendableKeyPath<JSONWebTokenClaimsPublicOIDCAuthParameters, T?>) -> T? {
        value[dynamicMember: keyPath]
    }

    @_documentation(visibility: private)
    public subscript(dynamicMember keyPath: SendableKeyPath<JSONWebTokenClaimsPublicOIDCAuthParameters, [String]>) -> [String] {
        value[dynamicMember: keyPath]
    }

    @_documentation(visibility: private)
    public subscript<T: JSONWebValueStorage.ValueType>(dynamicMember keyPath: SendableKeyPath<JSONWebTokenClaimsPopParameters, T?>) -> T? {
        value[dynamicMember: keyPath]
    }
}

extension ProtectedJSONWebContainer where Container == DPoPClaims {
    @_documentation(visibility: private)
    public subscript<T: JSONWebValueStorage.ValueType>(dynamicMember keyPath: SendableKeyPath<DPoPRegisteredParameters, T?>) -> T? {
        value[dynamicMember: keyPath]
    }
}
