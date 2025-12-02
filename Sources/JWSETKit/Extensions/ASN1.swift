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
    var primitive: ArraySlice<UInt8>? {
        switch self {
        case .constructed:
            return nil
        case .primitive(let value):
            return value
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

extension DERImplicitlyTaggable {
    /// Initializes a DER serializable object from given data.
    ///
    /// - Parameter derEncoded: DER encoded object.
    @usableFromInline
    init<D>(derEncoded: D) throws where D: DataProtocol {
        try self.init(derEncoded: [UInt8](derEncoded))
    }
    
    /// DER serialized data representation of object.
    @usableFromInline
    var derRepresentation: Data {
        get throws {
            var derSerializer = DER.Serializer()
            try serialize(into: &derSerializer)
            return Data(derSerializer.serializedBytes)
        }
    }
}
