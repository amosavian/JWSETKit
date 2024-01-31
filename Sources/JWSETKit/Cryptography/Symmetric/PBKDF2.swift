//
//  PBKDF2.swift
//
//
//  Created by Amir Abbas Mousavian on 10/11/23.
//

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
#if canImport(CommonCrypto)
import CommonCrypto
#endif

extension SymmetricKey {
    /// Generates a symmetric key using `PBKDF2` algorithm.
    ///
    /// - Parameters:
    ///   - password: The master password from which a derived key is generated.
    ///   - salt: A sequence of bits, known as a cryptographic salt.
    ///   - hashFunction: Pseudorandom function algorithm.
    ///   - iterations: Iteration count, a positive integer.
    ///
    /// - Returns: A symmetric key derived from parameters.
    @available(*, deprecated, renamed: "pbkdf2(password:salt:hashFunction:iterations:)", message: "Renamed function.")
    public static func pbkdf2<PD, SD, H>(
        pbkdf2Password password: PD, salt: SD, hashFunction: H.Type, iterations: Int
    ) throws -> SymmetricKey where PD: DataProtocol, SD: DataProtocol, H: HashFunction {
        try pbkdf2(password: password, salt: salt, hashFunction: hashFunction, iterations: iterations)
    }
    
    /// Generates a symmetric key using `PBKDF2` algorithm.
    ///
    /// - Parameters:
    ///   - password: The master password from which a derived key is generated.
    ///   - salt: A sequence of bits, known as a cryptographic salt.
    ///   - hashFunction: Pseudorandom function algorithm.
    ///   - iterations: Iteration count, a positive integer.
    ///
    /// - Returns: A symmetric key derived from parameters.
    public static func pbkdf2<PD, SD, H>(
        password: PD, salt: SD, hashFunction: H.Type, iterations: Int
    ) throws -> SymmetricKey where PD: DataProtocol, SD: DataProtocol, H: HashFunction {
#if canImport(CommonCrypto)
        return try ccPbkdf2(pbkdf2Password: password, salt: salt, hashFunction: hashFunction, iterations: iterations)
#else
        return try .init(data: PBKDF2.calculate(length: H.Digest.byteCount, password: password, salt: salt, hashFunction: H.self, rounds: iterations))
#endif
    }
}

// RFC 2898 Section 5.2
//
// FromSpec:
//
// PBKDF2 applies a pseudorandom function (see Appendix B.1 for an
// example) to derive keys. The length of the derived key is essentially
// unbounded. (However, the maximum effective search space for the
// derived key may be limited by the structure of the underlying
// pseudorandom function. See Appendix B.1 for further discussion.)
// PBKDF2 is recommended for new applications.
//
// PBKDF2 (P, S, c, dk_len)
//
// Options:        PRF        underlying pseudorandom function (h_len
//                            denotes the length in octets of the
//                            pseudorandom function output)
//
// Input:          P          password, an octet string
//                 S          salt, an octet string
//                 c          iteration count, a positive integer
//                 dk_len      intended length in octets of the derived
//                            key, a positive integer, at most
//                            (2^32 - 1) * h_len
//
// Output:         DK         derived key, a dk_len-octet string

// Based on Apple's CommonKeyDerivation, based originally on code by Damien Bergamini.

/// PBKDF2 is used to generate a key and salt from a password as defined in RFC 2898.
///
/// This is using a generic `HashFunction` from `swift-crypto`.
///
/// Example usage:
/// ```swift
/// let result = PBKDF2<SHA256>.hash(
///     length: 32,
///     password: "password".data(using: .utf8)!,
///     salt: "hash".data(using: .utf8)!,
///     rounds: 6
/// )
/// print(result)
/// ```
struct PBKDF2 {
    /// Generates a key from the given password and salt.
    /// - Parameters:
    ///   - length: The size for the generated key. Generally 16 or 32 bytes. Maximum size is `UInt32.max * Hash.Digest.byteCount`.
    ///   - password: The password used to generate the key, can be empty.
    ///   - salt: The salt used to generate the key, can be empty. Commonly 8 bytes long.
    ///   - rounds: Iteration count, must be greater than 9. Common values range from `1_000` to `100_00`.
    ///             Larger iteration counts improve security by increasing the time required to compute
    ///             the key. It is common to tune this parameter to achieve approximately 100ms.
    /// - Returns: The calculated key.
    static func calculate<P: DataProtocol, S: DataProtocol, Hash: HashFunction>(
        length: Int, password: P, salt: S, hashFunction: Hash.Type, rounds: Int
    ) throws -> Data {
        if rounds < 1 {
            throw CryptoKitError.incorrectParameterSize
        }

        let dkLength = length
        let hLen = Hash.Digest.byteCount

        // FromSpec:
        //
        //   1. If dk_len > maxInt(u32) * h_len, output "derived key too long" and
        //      stop.
        //
        if dkLength / hLen >= UInt32.max {
            // Counter starts at 1 and is 32 bit, so if we have to return more blocks, we would overflow
            throw CryptoKitError.incorrectParameterSize
        }

        // FromSpec:
        //
        //   2. Let l be the number of h_len-long blocks of bytes in the derived key,
        //      rounding up, and let r be the number of bytes in the last
        //      block
        //

        let blocksCount = Int((Double(dkLength) / Double(hLen)).rounded(.up))
        var r = dkLength % hLen
        if r == 0 {
            r = hLen
        }

        // FromSpec:
        //
        //   3. For each block of the derived key apply the function F defined
        //      below to the password P, the salt S, the iteration count c, and
        //      the block index to compute the block:
        //
        //                T_1 = F (P, S, c, 1) ,
        //                T_2 = F (P, S, c, 2) ,
        //                ...
        //                T_l = F (P, S, c, l) ,
        //
        //      where the function F is defined as the exclusive-or sum of the
        //      first c iterates of the underlying pseudorandom function PRF
        //      applied to the password P and the concatenation of the salt S
        //      and the block index i:
        //
        //                F (P, S, c, i) = U_1 \xor U_2 \xor ... \xor U_c
        //
        //  where
        //
        //            U_1 = PRF (P, S || INT (i)) ,
        //            U_2 = PRF (P, U_1) ,
        //            ...
        //            U_c = PRF (P, U_{c-1}) .
        //
        //  Here, INT (i) is a four-octet encoding of the integer i, most
        //  significant octet first.
        //
        //  4. Concatenate the blocks and extract the first dk_len octets to
        //  produce a derived key DK:
        //
        //            DK = T_1 || T_2 ||  ...  || T_l<0..r-1>

        var block = 0
        var dk = Data(repeating: 0, count: dkLength)
        let password = Data(password)
        while block < blocksCount {
            defer { block += 1 }
            var prevBlock: Data
            var newBlock: Data

            // U_1 = PRF (P, S || INT (i))
            var value = UInt32(block + 1).bigEndian
            let blockIndex = withUnsafeBytes(of: &value) { Data($0) } // Block index starts at 0001
            var ctx = HMAC<Hash>(key: SymmetricKey(data: password))
            ctx.update(data: salt)
            ctx.update(data: blockIndex)
            prevBlock = Data(ctx.finalize())

            // Choose portion of DK to write into (T_n) and initialize
            let offset = block * hLen
            let blockLen = if block != blocksCount - 1 { hLen } else { r }
            var dkBlock = dk[offset..<(offset + blockLen)]
            dkBlock = prevBlock[0..<dkBlock.count]

            for _ in 1..<rounds {
                // U_c = PRF (P, U_{c-1})
                var ctx = HMAC<Hash>(key: SymmetricKey(data: password))
                ctx.update(data: prevBlock)
                newBlock = Data(ctx.finalize())
                prevBlock = newBlock

                // F (P, S, c, i) = U_1 \xor U_2 \xor ... \xor U_c
                for (j, _) in dkBlock.enumerated() {
                    dkBlock[j] ^= Data(newBlock)[j]
                }
            }

            dk[offset..<(offset + blockLen)] = dkBlock
        }

        return dk
    }
}
