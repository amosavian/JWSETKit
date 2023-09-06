//
//  File.swift
//  
//
//  Created by Amir Abbas Mousavian on 9/5/23.
//

import Foundation

@dynamicMemberLookup
public struct JsonWebTokenClaims: JsonWebContainer {
    public var storage: JsonWebValueStorage
    
    public init() {
        self.storage = .init()
    }
}
