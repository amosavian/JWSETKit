//
//  DisclosurePayloadMerger.swift
//
//
//  Created by Amir Abbas Mousavian on 9/9/25.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto

/// Defines which claims should be selectively disclosable in an SD-JWT.
public struct DisclosurePolicy: Hashable, Sendable {
    /// Claims that are never selectively disclosed (always visible in JWT).
    public var alwaysVisible: Set<JSONPointer>
    
    /// Paths to claims that should be selectively disclosable.
    /// If nil, all claims except `alwaysVisible` are disclosable.
    public var disclosablePaths: Set<JSONPointer>?
    
    /// Standard JWT claims that are visible by default.
    ///
    /// Per RFC 9901 Section 9.7, these claims should typically remain disclosed:
    /// - `iss`: Issuer
    /// - `sub`: Subject
    /// - `iat`: Issued at
    /// - `exp`: Expiration time
    /// - `nbf`: Not before
    /// - `aud`: Audience
    /// - `jti`: JWT ID
    /// - `cnf`: Confirmation key (for key binding)
    /// - `_sd_alg`: SD-JWT hash algorithm
    /// - `_sd`: Selective disclosure hashes
    public static let standardVisibleClaims: Set<JSONPointer> = .init(JSONWebTokenClaimsRegisteredParameters.self)
        .union(Set<JSONPointer>(JSONWebTokenClaimsPopParameters.self))
        .union(Set<JSONPointer>(JSONWebTokenClaimsSelectiveDisclosureParameters.self))
    
    /// SD-JWT VC claims that should remain visible per SD-JWT VC specification.
    ///
    /// Per draft-ietf-oauth-sd-jwt-vc Section 3.2.2.2, these claims MUST NOT be selectively disclosed:
    /// - `vct`: Verifiable Credential Type (required, identifies the credential type)
    /// - `vct#integrity`: Hash value for integrity verification of the Type Metadata document
    /// - `status`: Credential status for revocation checking
    public static let sdJwtVcVisibleClaims: Set<JSONPointer> = [
        "/vct", "/vct#integrity", "/status",
    ]
    
    /// W3C Verifiable Credentials Data Model claims that should remain visible.
    ///
    /// These claims define the structure of W3C VCs:
    /// - `@context`: JSON-LD context
    /// - `type`: Credential type array
    /// - `credentialSubject`: Container for subject claims (the subject's claims inside may be selective)
    /// - `credentialStatus`: Status information for revocation
    /// - `credentialSchema`: Schema reference
    /// - `termsOfUse`: Terms and conditions
    /// - `evidence`: Evidence supporting the credential
    /// - `refreshService`: Service for credential refresh
    public static let w3cVcVisibleClaims: Set<JSONPointer> = [
        "/@context", "/type", "/credentialSubject", "/credentialStatus",
        "/credentialSchema", "/termsOfUse", "/evidence", "/refreshService",
    ]
    
    /// Combined visible claims for SD-JWT based Verifiable Credentials.
    ///
    /// Includes standard JWT claims, SD-JWT VC claims, and W3C VC structural claims.
    public static let defaultVisibleClaims: Set<JSONPointer> =
        standardVisibleClaims
            .union(sdJwtVcVisibleClaims)
            .union(w3cVcVisibleClaims)
    
    /// Creates a policy with custom always-visible claims and optional disclosable paths.
    public init(
        alwaysVisible: Set<JSONPointer> = Self.defaultVisibleClaims,
        disclosablePaths: Set<JSONPointer>? = nil
    ) {
        self.alwaysVisible = alwaysVisible
        self.disclosablePaths = disclosablePaths
    }
    
    /// Creates a policy that makes specific paths disclosable.
    public static func disclosable(_ paths: Set<JSONPointer>) -> DisclosurePolicy {
        DisclosurePolicy(disclosablePaths: paths)
    }
    
    /// Creates a policy that makes all claims disclosable except standard JWT claims.
    public static var standard: DisclosurePolicy {
        .init()
    }
    
    /// Creates a policy where only specified paths remain visible (inverse selection).
    public static func visible(_ paths: Set<JSONPointer>) -> DisclosurePolicy {
        .init(alwaysVisible: defaultVisibleClaims.union(paths))
    }
}

extension JSONWebValueStorage {
    /// Recursively collects all `_sd` disclosure hashes from the given storage including nested objects.
    ///
    /// This method traverses the entire storage structure to find all `_sd` arrays,
    /// as nested objects can have their own selective disclosures per RFC 9901.
    ///
    /// - Returns: An array of all disclosure hashes found at all nesting levels (may contain duplicates)
    func collectAllDisclosureHashes() -> [Data] {
        var hashes: [Data] = []
        collectDisclosureHashes(from: storage, into: &hashes)
        return hashes
    }
    
    private func collectDisclosureHashes(from value: Any, into hashes: inout [Data]) {
        if let dict = value as? [String: Any] {
            // Add _sd hashes from this level
            if let sdArray = dict["_sd"] as? [String] {
                for hashString in sdArray {
                    if let hashData = Data(urlBase64Encoded: hashString) {
                        hashes.append(hashData)
                    }
                }
            }
            // Recursively check nested values
            for (key, nested) in dict where key != "_sd" && key != "_sd_alg" {
                collectDisclosureHashes(from: nested, into: &hashes)
            }
        } else if let array = value as? [Any] {
            for element in array {
                // Array element disclosure
                if let marker = element as? [String: Any],
                   marker.count == 1,
                   let hashValue = marker["..."]
                {
                    if let hashData = hashValue as? Data {
                        hashes.append(hashData)
                    } else if let hashString = hashValue as? String,
                              let hashData = Data(urlBase64Encoded: hashString)
                    {
                        hashes.append(hashData)
                    }
                }
                collectDisclosureHashes(from: element, into: &hashes)
            }
        }
    }
}

// MARK: - Conceal Operations

extension JSONWebValueStorage {
    /// Conceals values at the specified paths, creating disclosures.
    ///
    /// - Parameters:
    ///   - paths: JSON Pointer paths to conceal
    ///   - hashFunction: Hash function for computing disclosure digests
    /// - Returns: List of created disclosures
    mutating func conceal(
        paths: Set<JSONPointer>,
        using hashFunction: any HashFunction.Type
    ) throws -> JSONWebSelectiveDisclosureList {
        var disclosures = try JSONWebSelectiveDisclosureList([], hashFunction: hashFunction)
        
        let groupedPaths = Dictionary(grouping: paths) { path -> JSONPointer in
            path.parent ?? JSONPointer()
        }
        for (parentPath, childPaths) in groupedPaths {
            try concealGroup(
                parentPath: parentPath,
                childPaths: childPaths,
                disclosures: &disclosures
            )
        }
        return disclosures
    }
    
    private mutating func concealGroup(
        parentPath: JSONPointer,
        childPaths: [JSONPointer],
        disclosures: inout JSONWebSelectiveDisclosureList
    ) throws {
        if parentPath.isRoot {
            try concealAtRoot(paths: childPaths, disclosures: &disclosures)
        } else {
            try concealNested(parentPath: parentPath, paths: childPaths, disclosures: &disclosures)
        }
    }
    
    private mutating func concealAtRoot(
        paths: [JSONPointer],
        disclosures: inout JSONWebSelectiveDisclosureList
    ) throws {
        var sdHashes: [String] = storage["_sd"] as? [String] ?? []
        
        for path in paths {
            guard let lastComponent = path.last, lastComponent.intValue == nil else { continue }
            
            let key = lastComponent.stringValue
            guard let value = storage[key] else { continue }
            
            let disclosure = try JSONWebSelectiveDisclosure(key, value: value)
            let hash = disclosures.append(disclosure)
            sdHashes.append(hash.urlBase64EncodedString())
            storage.removeValue(forKey: key)
        }
        
        if !sdHashes.isEmpty {
            storage["_sd"] = sdHashes
        }
    }
    
    private mutating func concealNested(
        parentPath: JSONPointer,
        paths: [JSONPointer],
        disclosures: inout JSONWebSelectiveDisclosureList
    ) throws {
        // Navigate to parent and modify in place
        guard let parent = self[parentPath] else { return }
        
        if var parentDict = parent as? [String: any Sendable] {
            var sdHashes: [String] = parentDict["_sd"] as? [String] ?? []
            
            for path in paths {
                guard let lastComponent = path.last else { continue }
                let key = lastComponent.stringValue
                
                guard lastComponent.intValue == nil, let value = parentDict[key] else { continue }
                
                let disclosure = try JSONWebSelectiveDisclosure(key, value: value)
                let hash = disclosures.append(disclosure)
                sdHashes.append(hash.urlBase64EncodedString())
                parentDict.removeValue(forKey: key)
            }
            
            if !sdHashes.isEmpty {
                parentDict["_sd"] = sdHashes
            }
            self[parentPath] = parentDict
        } else if var parentArray = parent as? [any Sendable] {
            // Handle array element concealment
            for path in paths {
                guard let lastComponent = path.last,
                      let index = lastComponent.intValue,
                      parentArray.indices.contains(index)
                else { continue }
                
                let value = parentArray[index]
                let disclosure = try JSONWebSelectiveDisclosure(nil, value: value)
                let hash = disclosures.append(disclosure)
                parentArray[index] = ["...": hash.urlBase64EncodedString()]
            }
            self[parentPath] = parentArray
        }
    }
    
    /// Conceals all claims except those in the always-visible set.
    ///
    /// - Parameters:
    ///   - policy: The disclosure policy defining which claims to conceal
    ///   - hashFunction: Hash function for computing disclosure digests
    /// - Returns: List of created disclosures
    mutating func conceal(
        policy: DisclosurePolicy,
        using hashFunction: any HashFunction.Type
    ) throws -> JSONWebSelectiveDisclosureList {
        if let explicitPaths = policy.disclosablePaths {
            return try conceal(paths: explicitPaths, using: hashFunction)
        }
        let allKeys = Set(storage.keys)
        let paths = Set(allKeys.map(JSONPointer.init(key:))).subtracting(policy.alwaysVisible)
        return try conceal(paths: paths, using: hashFunction)
    }
}

// MARK: - Disclose Operations

extension JSONWebValueStorage {
    /// Discloses values using the provided disclosure list.
    ///
    /// - Parameter disclosures: Disclosures to apply
    mutating func disclose(with disclosures: JSONWebSelectiveDisclosureList) throws {
        try storage.disclose(with: disclosures)
    }
    
    /// Returns a copy with disclosures applied.
    func disclosed(with disclosures: JSONWebSelectiveDisclosureList) throws -> JSONWebValueStorage {
        var result = self
        try result.disclose(with: disclosures)
        return result
    }
}

extension [String: any Sendable] {
    mutating func disclose(with disclosures: JSONWebSelectiveDisclosureList) throws {
        // Process _sd hashes at this level
        let disclosureHashes: [Data]
        if let dataHashes = self["_sd"] as? [Data] {
            disclosureHashes = dataHashes
        } else if let stringHashes = self["_sd"] as? [String] {
            disclosureHashes = stringHashes.compactMap { Data(urlBase64Encoded: $0) }
        } else {
            disclosureHashes = []
        }
        
        for hash in disclosureHashes {
            if let disclosure = disclosures[hash], let key = disclosure.key {
                self[key] = disclosure.value
            }
        }
        removeValue(forKey: "_sd")
        
        for (key, value) in self {
            if var nestedDict = value as? [String: any Sendable] {
                try nestedDict.disclose(with: disclosures)
                self[key] = nestedDict
            } else if var nestedArray = value as? [any Sendable] {
                try nestedArray.disclose(with: disclosures)
                self[key] = nestedArray
            }
        }
    }
    
    func disclosed(with disclosures: JSONWebSelectiveDisclosureList) throws -> [String: any Sendable] {
        var result = self
        try result.disclose(with: disclosures)
        return result
    }
}

extension [any Sendable] {
    mutating func disclose(with disclosures: JSONWebSelectiveDisclosureList) throws {
        self = try map { element in
            if let marker = element as? [String: any Sendable],
               marker.count == 1
            {
                // Check for array element disclosure marker {"...": hash}
                if let hash = JSONWebValueStorage.cast(value: marker["..."], as: Data.self) {
                    return disclosures[hash]?.value ?? element
                } else if let hashString = marker["..."] as? String,
                          let hash = Data(urlBase64Encoded: hashString)
                {
                    return disclosures[hash]?.value ?? element
                }
                var mutable = marker
                try mutable.disclose(with: disclosures)
                return mutable
            } else if var nestedDict = element as? [String: any Sendable] {
                try nestedDict.disclose(with: disclosures)
                return nestedDict
            } else if var nestedArray = element as? [any Sendable] {
                try nestedArray.disclose(with: disclosures)
                return nestedArray
            }
            return element
        }
    }
    
    func disclosed(with disclosures: JSONWebSelectiveDisclosureList) throws -> [any Sendable] {
        var result = self
        try result.disclose(with: disclosures)
        return result
    }
}

// MARK: - JWT Claims Extensions

extension JSONWebTokenClaims {
    /// Conceals values at the specified paths, creating disclosures.
    ///
    /// - Parameters:
    ///   - paths: JSON Pointer paths to conceal
    ///   - hashFunction: Hash function for computing disclosure digests
    /// - Returns: List of created disclosures
    public mutating func conceal(
        paths: Set<JSONPointer>,
        using hashFunction: any HashFunction.Type
    ) throws -> JSONWebSelectiveDisclosureList {
        try storage.conceal(paths: paths, using: hashFunction)
    }
    
    /// Conceals all claims according to the disclosure policy.
    ///
    /// - Parameters:
    ///   - policy: The disclosure policy defining which claims to conceal
    ///   - hashFunction: Hash function for computing disclosure digests
    /// - Returns: List of created disclosures
    public mutating func conceal(
        policy: DisclosurePolicy = .standard,
        using hashFunction: any HashFunction.Type
    ) throws -> JSONWebSelectiveDisclosureList {
        try storage.conceal(policy: policy, using: hashFunction)
    }
    
    /// Discloses values using the provided disclosure list.
    ///
    /// - Parameter disclosures: Disclosures to apply
    public mutating func disclose(with disclosures: JSONWebSelectiveDisclosureList) throws {
        try storage.disclose(with: disclosures)
    }
    
    /// Discloses values using the provided disclosures array.
    ///
    /// - Parameter disclosures: Array of disclosures to apply
    public mutating func disclose(with disclosures: [JSONWebSelectiveDisclosure]) throws {
        // swiftformat:disable:next redundantSelf
        guard let hashFunction = self.disclosureHashAlgorithm?.hashFunction else {
            return
        }
        try disclose(with: JSONWebSelectiveDisclosureList(disclosures, hashFunction: hashFunction))
    }
    
    /// Returns a copy with disclosures applied.
    public func disclosed(with disclosures: JSONWebSelectiveDisclosureList) throws -> JSONWebTokenClaims {
        var result = self
        try result.disclose(with: disclosures)
        return result
    }
}
