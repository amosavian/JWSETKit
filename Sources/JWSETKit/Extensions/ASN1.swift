//
//  ASN1.swift
//
//
//  Created by Amir Abbas Mousavian on 9/9/23.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import SwiftASN1

extension ASN1Node.Content {
    var primitive: Data? {
        switch self {
        case .constructed:
            return nil
        case .primitive(let value):
            return Data(value)
        }
    }
    
    var sequence: [ASN1Node]? {
        switch self {
        case .constructed(let nodes):
            return Array(nodes)
        case .primitive:
            return nil
        }
    }
}

extension DER.Serializer {
    mutating func appendIntegers(_ array: [Data]) throws {
        try appendConstructedNode(identifier: .sequence) {
            for item in array {
                try $0.serialize(ArraySlice<UInt8>(item))
            }
        }
    }
}
