//
//  LocalizingTests.swift
//  
//
//  Created by Amir Abbas Mousavian on 9/16/23.
//

import XCTest
@testable import JWSETKit

final class LocalizingTests: XCTestCase {
    func testExample() throws {
        let date = Date(timeIntervalSince1970: 0)
        
        jsonWebKeyLocale = .init(identifier: "en-US")
        XCTAssertEqual(JSONWebKeyError.unknownAlgorithm.errorDescription, "Given signature/encryption algorithm is no supported.")
        XCTAssert(JSONWebValidationError.tokenExpired(expiry: date).errorDescription!.hasPrefix("Token is invalid after "))
        
        jsonWebKeyLocale = .init(identifier: "fa-IR")
        XCTAssertEqual(JSONWebKeyError.unknownAlgorithm.errorDescription, "الگوریتم انتخابی برای امضا/رمز پشتیبانی نمی‌شود.")
        XCTAssert(JSONWebValidationError.tokenExpired(expiry: date).errorDescription!.hasPrefix("توکن برای پس از"))
    }
}
