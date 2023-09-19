# Extending Containers

It is possible to create new containers or add new claims to existing containers.

## Add New Claims

To extend existing container, e.g. ``JSONWebTokenClaims`` define a new `struct` 
with proposed new claims and add a `JSONWebTokenClaims.subscript(dynamicMember:)`
in order to access the claim.

```swift
struct JSONWebTokenClaimsJwkParameters {
    var subJsonWebToken: (any JsonWebKey)?

    // Key lookup to convert claim to string key.
    fileprivate static let keys: [PartialKeyPath<Self>: String] = [
        \.subJsonWebToken: "sub_jwk",
    ]
}

extension JSONWebTokenClaims {
    private func stringKey<T>(_ keyPath: KeyPath<JSONWebTokenClaimsJwkParameters, T>) -> String {
        if let key = JSONWebTokenClaimsJwkParameters.keys[keyPath] {
            return key
        }
        return String(reflecting: keyPath).components(separatedBy: ".").last!
    }
    
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
@dynamicMemberLookup
struct DPoPClaims: JSONWebContainer {
    var storage: JSONWebValueStorage
    
    init(storage: JSONWebValueStorage) {
        self.storage = storage
    }
    
    static func create(storage: JSONWebValueStorage) throws -> JSONWebTokenClaims {
        .init(storage: storage)
    }
}

public typealias DPoP = JSONWebSignature<DPoPClaims>
```

then extend `DPoP` to support defined
[claims](https://datatracker.ietf.org/doc/html/rfc9449#section-4.2):

## Topics

### JOSE Headers

- ``JOSEHeader``

### JSON Web Token

- ``JSONWebToken``
