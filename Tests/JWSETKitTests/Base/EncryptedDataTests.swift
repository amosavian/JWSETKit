//
//  EncryptedDataTests.swift
//
//
//  Created by Mojtaba Hosseini on 9/1/26.
//

import Foundation
import Testing
@testable import JWSETKit

struct EncryptedDataTests {
    @Test
    func sealedDataCollectionSubscript() {
        let nonce = Data([0x01, 0x02])
        let ciphertext = Data([0x03, 0x04, 0x05])
        let tag = Data([0x06, 0x07])
        let sealed = SealedData(nonce: nonce, ciphertext: ciphertext, tag: tag)
        
        #expect(sealed.count == 7)
        #expect(sealed[0] == 0x01)
        #expect(sealed[1] == 0x02)
        #expect(sealed[2] == 0x03)
        #expect(sealed[3] == 0x04)
        #expect(sealed[4] == 0x05)
        #expect(sealed[5] == 0x06)
        #expect(sealed[6] == 0x07)
        #expect(Array(sealed) == [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07])
    }
}
