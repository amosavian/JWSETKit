//
//  Expiry.swift
//
//
//  Created by Amir Abbas Mousavian on 9/12/23.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// The container has a expire date or a starting "not before" date.
public protocol Expirable {
    /// Verifies the current date/time is within the object start date and expiration date.
    ///
    /// - Parameter currentDate: current date/time that comparison takes against.
    func verifyDate(_ currentDate: Date) throws
}

extension Expirable {
    /// Verifies the current system date/time is within the object start date and expiration date.
    func verifyDate() throws {
        try verifyDate(.init())
    }
}
