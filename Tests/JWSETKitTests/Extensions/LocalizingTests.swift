//
//  LocalizingTests.swift
//
//
//  Created by Amir Abbas Mousavian on 9/16/23.
//

import Foundation
import Testing
@testable import JWSETKit

struct LocalizingTests {
    @Test
    func errorLocalizing() {
#if canImport(Darwin)
        let date = Date(timeIntervalSince1970: 0)
        
        let enLocale = Locale(identifier: "en-US")
        #expect(JSONWebKeyError.unknownAlgorithm.localizedError(for: enLocale) == "Given signature/encryption algorithm is no supported.")
        #expect(JSONWebValidationError.tokenExpired(expiry: date).localizedError(for: enLocale).hasPrefix("Token is invalid after "))
        
        let faLocale = Locale(identifier: "fa-IR")
        #expect(JSONWebKeyError.unknownAlgorithm.localizedError(for: faLocale) == "الگوریتم انتخابی برای امضا/رمز پشتیبانی نمی‌شود.")
        print(JSONWebValidationError.tokenExpired(expiry: date).localizedError(for: faLocale))
        #expect(JSONWebValidationError.tokenExpired(expiry: date).localizedError(for: faLocale).hasPrefix("توکن برای پس از"))
        
        #expect(JSONWebKeyError.unknownAlgorithm.errorDescription != nil)
#endif
    }

    @Test(arguments: ["en-US", "en", "fa-IR", "fa"].permutations.map { ($0, "fa") })
    func testBestMatchExactNoCountryIdentifierRegardlessOfOrder(candidates: [String], expected: String) {
        let candidateLocales = candidates.map(Locale.init(identifier:))

        #expect(Locale(identifier: expected).bestMatch(in: candidateLocales)?.identifier == expected)
    }

    @Test(arguments: ["en-IR", "en-US", "en", "fa-AF", "fa-IR", "fa"].permutations.map { ($0, "fa-IR") })
    func testBestMatchExactIdentifierRegardlessOfOrder(candidates: [String], expected: String) {
        let candidateLocales = candidates.map(Locale.init(identifier:))

        #expect(Locale(identifier: expected).bestMatch(in: candidateLocales)?.identifier == expected)
    }
}

private extension Collection {
    // A tiny helper for calculating permutations of the collection
    var permutations: [[Element]] {
        guard let first else { return [[]] }

        return Array(dropFirst()).permutations.flatMap { permutation in
            (0...permutation.count).map { index in
                var result = permutation
                result.insert(first, at: index)
                return result
            }
        }
    }
}
