//
//  LocalizingTests.swift
//
//
//  Created by Amir Abbas Mousavian on 9/16/23.
//

import Foundation
import Testing
@testable import JWSETKit

@Suite
struct LocalizingTests {
    @Test
    func testErrorLocalizing() throws {
#if canImport(Darwin)
        let date = Date(timeIntervalSince1970: 0)
        
        let enLocale = Locale(identifier: "en-US")
        #expect(JSONWebKeyError.unknownAlgorithm.localizedError(for: enLocale) == "Given signature/encryption algorithm is no supported.")
        #expect(JSONWebValidationError.tokenExpired(expiry: date).localizedError(for: enLocale).hasPrefix("Token is invalid after "))
        
        let faLocale = Locale(identifier: "fa-IR")
        #expect(JSONWebKeyError.unknownAlgorithm.localizedError(for: faLocale) == "الگوریتم انتخابی برای امضا/رمز پشتیبانی نمی‌شود.")
        #expect(JSONWebValidationError.tokenExpired(expiry: date).localizedError(for: faLocale).hasPrefix("توکن برای پس از"))
        
        #expect(JSONWebKeyError.unknownAlgorithm.errorDescription != nil)
#endif
    }
    
    @Test
    func testBestMatch() throws {
        #expect(Locale(bcp47: "fa-IR").identifier == "fa_IR")
        
        #expect(Locale(identifier: "fa-IR").bestMatch(in: [
            .init(identifier: "en-US"),
            .init(identifier: "en-IR"),
            .init(identifier: "fa-AF"),
            .init(identifier: "fa"),
        ])?.identifier == "fa")
    }
}
