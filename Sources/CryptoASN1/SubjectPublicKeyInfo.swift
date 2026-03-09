//
//  SubjectPublicKeyInfo.swift
//  JWSETKit
//
//  Created by Amir Abbas Mousavian on 2026/3/9.
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto
import SwiftASN1

package struct SubjectPublicKeyInfo: DERImplicitlyTaggable, Hashable {
    package static var defaultIdentifier: ASN1Identifier {
        .sequence
    }
    
    package var algorithmIdentifier: RFC5480AlgorithmIdentifier
    
    package var key: ASN1BitString
    
    package init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        // The SPKI block looks like this:
        //
        // SubjectPublicKeyInfo  ::=  SEQUENCE  {
        //   algorithm         AlgorithmIdentifier,
        //   subjectPublicKey  BIT STRING
        // }
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let algorithmIdentifier = try RFC5480AlgorithmIdentifier(derEncoded: &nodes)
            let key = try ASN1BitString(derEncoded: &nodes)
            
            return SubjectPublicKeyInfo(algorithmIdentifier: algorithmIdentifier, key: key)
        }
    }
    
    private init(algorithmIdentifier: RFC5480AlgorithmIdentifier, key: ASN1BitString) {
        self.algorithmIdentifier = algorithmIdentifier
        self.key = key
    }
    
    package init(algorithmIdentifier: RFC5480AlgorithmIdentifier, key: [UInt8]) {
        self.algorithmIdentifier = algorithmIdentifier
        self.key = ASN1BitString(bytes: key[...])
    }
    
    package func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(algorithmIdentifier)
            try coder.serialize(key)
        }
    }
}

extension SubjectPublicKeyInfo: DERKeyContainer {
    package init(pkcs1: some RandomAccessCollection<UInt8>) {
        self.init(
            algorithmIdentifier: .rsaEncryption,
            key: [UInt8](pkcs1)
        )
    }
}
