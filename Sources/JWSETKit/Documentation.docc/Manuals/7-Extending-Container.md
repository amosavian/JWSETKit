# Extending Containers

It is possible to create new containers or add new claims to existing containers.

## Add New Claims

To extend existing container, e.g. ``JSONWebTokenClaims`` define a new `struct` 
with proposed new claims and add a `JSONWebTokenClaims.subscript(dynamicMember:)`
in order to access the claim.

```swift
struct JSONWebTokenClaimsJwkParameters: JSONWebContainerParameters {
    typealias Container = JOSEHeader
    var subJsonWebToken: (any JsonWebKey)?

    // Key lookup to convert claim to string key.
    static let keys: [PartialKeyPath<Self>: String] = [
        \.subJsonWebToken: "sub_jwk",
    ]
}

extension JSONWebTokenClaims {
    subscript<T>(dynamicMember keyPath: KeyPath<JSONWebTokenClaimsJwkParameters, T?>) -> T? {
        get {
            storage[stringKey(keyPath)]
        }
        set {
            storage[stringKey(keyPath)] = newValue
        }
    }
}
```

## Create New Container

It is possible to create a completely new container for new purpose, e.g. to
support [DPoP](https://datatracker.ietf.org/doc/html/rfc9449):

```swift
struct DPoPClaims: JSONWebContainer {
    var storage: JSONWebValueStorage
    
    init(storage: JSONWebValueStorage) {
        self.storage = storage
    }
    
    static func create(storage: JSONWebValueStorage) throws -> JSONWebTokenClaims {
        .init(storage: storage)
    }
}

public typealias DPoP = JSONWebSignature<ProtectedJSONWebContainer<DPoPClaims>>
```

then extend `DPoP` to support defined
[claims](https://datatracker.ietf.org/doc/html/rfc9449#section-4.2)

``` swift
public struct DPoPRegisteredParameters: JSONWebContainerParameters {
    public typealias Container = DPoPClaims
    
    public var jwtId: String?
    public var httpMethod: String?
    public var httpURL: URL?
    public var issuedAt: Date?
    public var accessTokenHash: Data?
    public var nonce: String?

    static let keys: [PartialKeyPath<Self>: String] = [
        \.jwtId: "jti", \.httpMethod: "htm", \.httpURL: "htu",
        \.issuedAt: "iat", \.accessTokenHash: "ath", \.nonce: "nonce",
    ]
}

extension DPoPClaims {
    @_documentation(visibility: private)
    public subscript<T>(dynamicMember keyPath: KeyPath<DPoPRegisteredParameters, T?>) -> T? {
        get {
            storage[stringKey(keyPath)]
        }
        set {
            storage[stringKey(keyPath)] = newValue
        }
    }
}
```

## Topics

### JOSE Headers

- ``JOSEHeader``

### JSON Web Token

- ``JSONWebToken``
