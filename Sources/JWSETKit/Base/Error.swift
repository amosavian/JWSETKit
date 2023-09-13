//
//  Error.swift
//
//
//  Created by Amir Abbas Mousavian on 9/7/23.
//

import Foundation

/// Errors occured during key creation or usage.
public enum JSONWebKeyError: Error {
    case unknownAlgorithm
    case unknownKeyType
    case decryptionFailed
    case keyNotFound
    case operationNotAllowed
}

public enum JSONWebValidationError: LocalizedError {
    case tokenExpired(expiry: Date)
    case tokenInvalidBefore(notBefore: Date)
    
    public var errorDescription: String? {
        let dateFormatter = DateFormatter()
        dateFormatter.locale = .autoupdatingCurrent
        dateFormatter.dateStyle = .medium
        dateFormatter.timeStyle = .medium
        switch self {
        case .tokenExpired(let date):
            return "Token is invalid after \(dateFormatter.string(from: date))"
        case .tokenInvalidBefore(let date):
            return "Token is invalid before \(dateFormatter.string(from: date))"
        }
    }
}
