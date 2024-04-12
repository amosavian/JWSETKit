//
//  LocalizingTests.swift
//
//
//  Created by Amir Abbas Mousavian on 9/16/23.
//

import XCTest
@testable import JWSETKit

final class LocalizingTests: XCTestCase {
    func testErrorLocalizing() throws {
#if canImport(Darwin)
        let date = Date(timeIntervalSince1970: 0)
        
        let enLocale = Locale(identifier: "en-US")
        XCTAssertEqual(JSONWebKeyError.unknownAlgorithm.localizedError(for: enLocale), "Given signature/encryption algorithm is no supported.")
        XCTAssert(JSONWebValidationError.tokenExpired(expiry: date).localizedError(for: enLocale).hasPrefix("Token is invalid after "))
        
        let faLocale = Locale(identifier: "fa-IR")
        XCTAssertEqual(JSONWebKeyError.unknownAlgorithm.localizedError(for: faLocale), "الگوریتم انتخابی برای امضا/رمز پشتیبانی نمی‌شود.")
        XCTAssert(JSONWebValidationError.tokenExpired(expiry: date).localizedError(for: faLocale).hasPrefix("توکن برای پس از"))
        
        XCTAssertNotNil(JSONWebKeyError.unknownAlgorithm.errorDescription)
#endif
    }
    
    func testBestMatch() throws {
        XCTAssertEqual(Locale(bcp47: "fa-IR").identifier, "fa_IR")
        
        XCTAssertEqual(Locale(identifier: "fa-IR").bestMatch(in: [
            .init(identifier: "en-US"),
            .init(identifier: "en-IR"),
            .init(identifier: "fa-AF"),
            .init(identifier: "fa"),
        ])?.identifier, "fa")
    }
}
