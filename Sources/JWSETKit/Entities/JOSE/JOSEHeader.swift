//
//  File.swift
//  
//
//  Created by Amir Abbas Mousavian on 9/5/23.
//

import Foundation
import CryptoKit
import UniformTypeIdentifiers

@dynamicMemberLookup
public struct JOSEHeader: JsonWebContainer {
    public var storage: JsonWebValueStorage
    
    public init() {
        self.storage = .init()
        self.algorithm = .none
    }
}
