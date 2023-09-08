//
//  File.swift
//  
//
//  Created by Amir Abbas Mousavian on 9/7/23.
//

import Foundation

public enum JSONWebKeyError: Error {
    case unknownAlgorithm
    case unknownKeyType
    case decryptionFailed
}
