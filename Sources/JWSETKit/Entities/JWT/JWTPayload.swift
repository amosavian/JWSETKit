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
    
    public init() {
        self.storage = .init()
    }
}

public typealias JSONWebToken = JSONWebSignature<JSONWebTokenClaims>
