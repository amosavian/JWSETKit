//
//  File.swift
//  
//
//  Created by Amir Abbas Mousavian on 9/5/23.
//

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

@dynamicMemberLookup
public struct JOSEHeader: JSONWebContainer {
    public var storage: JSONWebValueStorage
    
    public init() {
        self.storage = .init()
        self.algorithm = .none
    }
    
    public init(encodedString: String) throws {
        let data = Data(urlBase64Encoded: Data(encodedString.utf8))!
        self.storage = try JSONDecoder().decode(JSONWebValueStorage.self, from: data)
    }
    
    public var encodedData: Data {
        try! JSONEncoder().encode(storage).urlBase64EncodedData()
    }
    
    public var encodedString: String {
        String(decoding: encodedData, as: UTF8.self)
    }
}
