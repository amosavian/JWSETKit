//
//  File.swift
//  
//
//  Created by Amir Abbas Mousavian on 9/5/23.
//

import Foundation

@dynamicMemberLookup
public struct JSONWebTokenClaims: JSONWebContainer {
    public var storage: JSONWebValueStorage
    
    public init(storage: JSONWebValueStorage) {
        self.storage = storage
    }
    
    public static func create(storage: JSONWebValueStorage) throws -> JSONWebTokenClaims {
        .init(storage: storage)
    }
}

public typealias JSONWebToken = JSONWebSignature<JSONWebTokenClaims>
