import Foundation
import Testing
@testable import SwiftIdentity

/// BLAKE2b, which Argon2id is built on and swift-crypto doesn't offer.
///
/// Checked on its own, before Argon2id is: a wrong BLAKE2b makes every Argon2id vector fail at
/// once, and these say which of the two is at fault.
@Suite("BLAKE2b")
struct BLAKE2bTests {

    struct File: Decodable {
        let vectors: [Vector]
    }

    struct Vector: Decodable {
        let input: String
        let outLength: Int
        let out: String
    }

    @Test("RFC 7693 Appendix A: BLAKE2b-512 of \"abc\"")
    func rfc7693() throws {
        let file = try VectorFiles.json("blake2b-rfc7693.json", as: File.self)
        let vector = try #require(file.vectors.first)
        let expected = try #require(VectorFiles.bytes(hex: vector.out))
        #expect(try BLAKE2b.hash(Array(vector.input.utf8), outputLength: vector.outLength) == expected)
    }

    @Test("the official known answers: empty, short, one block exactly, and two blocks")
    func officialKnownAnswers() throws {
        let file = try VectorFiles.json("blake2b-kat.json", as: File.self)
        // Seven input lengths: 0, 1, 3, 127, 128 (one full block, which must not be padded into
        // a second), 129 and 255 (two blocks). Fewer would mean the import changed.
        #expect(file.vectors.map { $0.input.count / 2 } == [0, 1, 3, 127, 128, 129, 255])
        for vector in file.vectors {
            let input = try #require(VectorFiles.bytes(hex: vector.input))
            let expected = try #require(VectorFiles.bytes(hex: vector.out))
            let actual = try BLAKE2b.hash(input, outputLength: vector.outLength)
            #expect(actual == expected, "\(input.count)-byte input")
        }
    }

    @Test("an output length outside 1...64 is refused by name")
    func refusals() {
        #expect(throws: BLAKE2b.Failure.outputLength(0)) { try BLAKE2b.hash([], outputLength: 0) }
        #expect(throws: BLAKE2b.Failure.outputLength(65)) { try BLAKE2b.hash([], outputLength: 65) }
    }

    @Test("a shorter output is a different hash, not a truncation")
    func outputLengthIsAParameter() throws {
        // The output length is mixed into the first word of the state, so BLAKE2b-256 is not the
        // first half of BLAKE2b-512. Argon2's H' depends on exactly that.
        let long = try BLAKE2b.hash(Array("abc".utf8), outputLength: 64)
        let short = try BLAKE2b.hash(Array("abc".utf8), outputLength: 32)
        #expect(short.count == 32)
        #expect(Array(long.prefix(32)) != short)
    }
}
