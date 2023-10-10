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
        let date = Date(timeIntervalSince1970: 0)
        
        JSONWebKit.locale = Locale(identifier: "en-US")
        XCTAssertEqual(JSONWebKeyError.unknownAlgorithm.errorDescription, "Given signature/encryption algorithm is no supported.")
        XCTAssert(JSONWebValidationError.tokenExpired(expiry: date).errorDescription!.hasPrefix("Token is invalid after "))
        
        JSONWebKit.locale = Locale(identifier: "fa-IR")
        XCTAssertEqual(JSONWebKeyError.unknownAlgorithm.errorDescription, "الگوریتم انتخابی برای امضا/رمز پشتیبانی نمی‌شود.")
        XCTAssert(JSONWebValidationError.tokenExpired(expiry: date).errorDescription!.hasPrefix("توکن برای پس از"))
        
        JSONWebKit.locale = .autoupdatingCurrent
        XCTAssertNotNil(JSONWebKeyError.unknownAlgorithm.errorDescription)
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
