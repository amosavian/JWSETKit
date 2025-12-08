//
//  DisclosurePayloadMerger.swift
//
//
//  Created by Claude Code on 9/9/25.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto

extension JSONWebValueStorage {
    /// Recursively collects all `_sd` disclosure hashes from the given storage including nested objects.
    ///
    /// This method traverses the entire storage structure to find all `_sd` arrays,
    /// as nested objects can have their own selective disclosures per RFC 9901.
    ///
    /// - Parameter storage: The storage to recursively search for `_sd` arrays
    /// - Returns: An array of all disclosure hashes found at all nesting levels (may contain duplicates)
    func collectAllDisclosureHashes() -> [Data] {
        var hashes: [Data] = []

        // Add top-level _sd hashes
        let sdHashes: [String] = self["_sd"]
        for hashString in sdHashes {
            if let hashData = Data(urlBase64Encoded: hashString) {
                hashes.append(hashData)
            }
        }

        // Recursively traverse nested objects to find their _sd arrays
        for (key, value) in storage {
            // Skip the _sd and _sd_alg keys themselves to avoid double-counting
            if key == "_sd" || key == "_sd_alg" {
                continue
            }

            if let nestedStorage = value as? JSONWebValueStorage {
                hashes.append(contentsOf: nestedStorage.collectAllDisclosureHashes())
            } else if let nestedDict = value as? [String: any Sendable] {
                hashes.append(contentsOf: JSONWebValueStorage(nestedDict).collectAllDisclosureHashes())
            } else if let array = value as? [any Sendable] {
                // Recursively check array elements
                for element in array {
                    if let elementStorage = element as? JSONWebValueStorage {
                        hashes.append(contentsOf: elementStorage.collectAllDisclosureHashes())
                    } else if let elementDict = element as? [String: any Sendable] {
                        hashes.append(contentsOf: JSONWebValueStorage(elementDict).collectAllDisclosureHashes())
                    }
                }
            }
        }

        return hashes
    }
    
}

