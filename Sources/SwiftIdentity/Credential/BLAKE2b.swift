/// BLAKE2b, RFC 7693, in Swift: the hash Argon2id is built on.
///
/// Here because swift-crypto doesn't offer it, and this package's rule is that it writes its own
/// primitives rather than take a C library (the amendment's §7 and §13.4). It's internal: the
/// only caller is ``Argon2id``, and a general-purpose hash is not this package's to publish.
///
/// One call hashes a whole input. Argon2 only ever hashes inputs it already holds, so there is no
/// streaming interface to get wrong. Nor is there a key: Argon2 never keys BLAKE2b, and a MAC
/// nobody calls is code nobody tests.
enum BLAKE2b {

    /// Why a hash wasn't computed.
    enum Failure: Error, Equatable {
        /// An output length outside 1...64 bytes.
        case outputLength(Int)
    }

    /// The block size, in bytes.
    static let blockBytes = 128
    /// The largest output, in bytes.
    static let maximumOutputBytes = 64

    /// The initialization vector: SHA-512's, as RFC 7693 §2.6 specifies.
    static let iv: [UInt64] = [
        0x6A09_E667_F3BC_C908, 0xBB67_AE85_84CA_A73B, 0x3C6E_F372_FE94_F82B, 0xA54F_F53A_5F1D_36F1,
        0x510E_527F_ADE6_82D1, 0x9B05_688C_2B3E_6C1F, 0x1F83_D9AB_FB41_BD6B, 0x5BE0_CD19_137E_2179,
    ]

    /// The message schedule, RFC 7693 §2.7: ten permutations of 0..<16, one per round, reused
    /// for rounds 10 and 11. Flat, so a round's row is `sigma[16 * (round % 10) + i]`.
    static let sigma: [Int] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
        11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
        7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
        9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
        2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
        12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
        13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
        6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
        10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
    ]

    /// The unkeyed BLAKE2b of `message`.
    ///
    /// - Parameters:
    ///   - message: The bytes to hash.
    ///   - outputLength: 1 to 64 bytes. It's a parameter of the hash, mixed into its state, so a
    ///     shorter output is a different hash rather than a truncated one.
    /// - Returns: `outputLength` bytes.
    /// - Throws: ``Failure``.
    static func hash(_ message: [UInt8], outputLength: Int) throws -> [UInt8] {
        guard (1...maximumOutputBytes).contains(outputLength) else { throw Failure.outputLength(outputLength) }

        // The parameter block, reduced to the fields unkeyed sequential hashing uses (§2.5):
        // digest length, fanout 1 and depth 1.
        var state = iv
        state[0] ^= 0x0101_0000 ^ UInt64(outputLength)

        // Every block but the last is compressed as it is; the last, which may be full and is
        // never empty unless the whole message is, is padded and marked final. The counter is the
        // number of message bytes consumed so far, padding excluded.
        let blocks = max(1, (message.count + blockBytes - 1) / blockBytes)
        for index in 0..<(blocks - 1) {
            let words = littleEndianWords(message, from: index * blockBytes)
            compress(&state, words, counter: UInt64((index + 1) * blockBytes), final: false)
        }
        let last = littleEndianWords(message, from: (blocks - 1) * blockBytes)
        compress(&state, last, counter: UInt64(message.count), final: true)

        return Array(littleEndianBytes(state).prefix(outputLength))
    }

    /// The compression function F, RFC 7693 §3.2. The counter's high word is always zero here:
    /// nothing this package hashes approaches 2^64 bytes.
    static func compress(_ state: inout [UInt64], _ block: [UInt64], counter: UInt64, final: Bool) {
        var v = state + iv
        v[12] ^= counter
        if final { v[14] = ~v[14] }

        for round in 0..<12 {
            let s = 16 * (round % 10)
            mix(&v, 0, 4, 8, 12, block[sigma[s]], block[sigma[s + 1]])
            mix(&v, 1, 5, 9, 13, block[sigma[s + 2]], block[sigma[s + 3]])
            mix(&v, 2, 6, 10, 14, block[sigma[s + 4]], block[sigma[s + 5]])
            mix(&v, 3, 7, 11, 15, block[sigma[s + 6]], block[sigma[s + 7]])
            mix(&v, 0, 5, 10, 15, block[sigma[s + 8]], block[sigma[s + 9]])
            mix(&v, 1, 6, 11, 12, block[sigma[s + 10]], block[sigma[s + 11]])
            mix(&v, 2, 7, 8, 13, block[sigma[s + 12]], block[sigma[s + 13]])
            mix(&v, 3, 4, 9, 14, block[sigma[s + 14]], block[sigma[s + 15]])
        }
        for index in 0..<8 {
            state[index] ^= v[index] ^ v[index + 8]
        }
    }

    /// The mixing function G, RFC 7693 §3.1, with its rotations of 32, 24, 16 and 63.
    static func mix(_ v: inout [UInt64], _ a: Int, _ b: Int, _ c: Int, _ d: Int, _ x: UInt64, _ y: UInt64) {
        v[a] = v[a] &+ v[b] &+ x
        v[d] = (v[d] ^ v[a]).rotatedRight(by: 32)
        v[c] = v[c] &+ v[d]
        v[b] = (v[b] ^ v[c]).rotatedRight(by: 24)
        v[a] = v[a] &+ v[b] &+ y
        v[d] = (v[d] ^ v[a]).rotatedRight(by: 16)
        v[c] = v[c] &+ v[d]
        v[b] = (v[b] ^ v[c]).rotatedRight(by: 63)
    }

    /// The 16 little-endian words of the block at `offset`, zero-padded past the end of `bytes`.
    static func littleEndianWords(_ bytes: [UInt8], from offset: Int) -> [UInt64] {
        var words = [UInt64](repeating: 0, count: 16)
        let end = min(bytes.count, offset + blockBytes)
        guard offset < end else { return words }
        for position in offset..<end {
            let relative = position - offset
            words[relative / 8] |= UInt64(bytes[position]) << (8 * UInt64(relative % 8))
        }
        return words
    }

    /// Words as little-endian bytes, eight per word.
    static func littleEndianBytes(_ words: [UInt64]) -> [UInt8] {
        var bytes: [UInt8] = []
        bytes.reserveCapacity(words.count * 8)
        for word in words {
            for shift in stride(from: 0, to: 64, by: 8) {
                bytes.append(UInt8(truncatingIfNeeded: word >> UInt64(shift)))
            }
        }
        return bytes
    }
}

extension UInt64 {
    /// The word rotated right by `count` bits, `0 < count < 64`.
    func rotatedRight(by count: UInt64) -> UInt64 {
        (self >> count) | (self << (64 - count))
    }
}
