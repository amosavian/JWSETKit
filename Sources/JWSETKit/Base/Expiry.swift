//
//  Expiry.swift
//
//
//  Created by Amir Abbas Mousavian on 9/12/23.
//

import Foundation

public protocol Expirable {
    func verifyDate(_ currentDate: Date) throws
}

extension Expirable {
    func verifyDate() throws {
        try verifyDate(.init())
    }
}
