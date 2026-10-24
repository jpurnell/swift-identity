#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import Foundation
import Testing
@testable import SwiftIdentity

/// Argon2id against RFC 9106 §5.3, which is the only vector the RFC gives for it.
///
/// The tag alone says only *that* something is wrong. The RFC also prints the first and last
/// words of memory after every pass, and those say *where*: a fault in the first pass's
/// data-independent addressing shows up after pass 0, one in the data-dependent indexing or the
/// XOR into existing blocks only after pass 1.
@Suite("Argon2id — RFC 9106")
struct Argon2idTests {

    struct File: Decodable {
        let vectors: [Vector]
    }

    struct Vector: Decodable {
        let version: Int
        let memoryKiB: Int
        let passes: Int
        let lanes: Int
        let tagLength: Int
        let password: String
        let salt: String
        let secret: String
        let associatedData: String
        let preHashingDigest: String
        let intermediate: [Pass]
        let tag: String
    }

    struct Pass: Decodable {
        let pass: Int
        let words: [Word]
    }

    struct Word: Decodable {
        let block: Int
        let word: Int
        let value: String
    }

    /// The vector's inputs, decoded.
    struct Inputs {
        let password: [UInt8]
        let salt: [UInt8]
        let secret: [UInt8]
        let associatedData: [UInt8]
    }

    static func vector() throws -> Vector {
        let file = try VectorFiles.json("argon2id-rfc9106.json", as: File.self)
        return try #require(file.vectors.first)
    }

    static func inputs(_ vector: Vector) throws -> Inputs {
        Inputs(
            password: try #require(VectorFiles.bytes(hex: vector.password)),
            salt: try #require(VectorFiles.bytes(hex: vector.salt)),
            secret: try #require(VectorFiles.bytes(hex: vector.secret)),
            associatedData: try #require(VectorFiles.bytes(hex: vector.associatedData))
        )
    }

    static func argon2(_ vector: Vector) throws -> Argon2id {
        try Argon2id(memoryKiB: vector.memoryKiB, iterations: vector.passes, parallelism: vector.lanes)
    }

    @Test("the vector is the one this implementation claims: Argon2id version 0x13")
    func versionMatches() throws {
        #expect(try Self.vector().version == Int(Argon2id.version))
    }

    @Test("RFC 9106 §5.3: the pre-hashing digest H0")
    func preHashingDigest() throws {
        let vector = try Self.vector()
        let inputs = try Self.inputs(vector)
        let digest = try Self.argon2(vector).preHash(
            password: inputs.password, salt: inputs.salt, secret: inputs.secret,
            associatedData: inputs.associatedData, tagLength: vector.tagLength
        )
        #expect(digest == VectorFiles.bytes(hex: vector.preHashingDigest))
    }

    @Test("RFC 9106 §5.3: the memory words after each pass")
    func intermediateWords() throws {
        let vector = try Self.vector()
        let inputs = try Self.inputs(vector)
        var observed: [Int: [UInt64]] = [:]
        _ = try Self.argon2(vector).hash(
            password: inputs.password, salt: inputs.salt, secret: inputs.secret,
            associatedData: inputs.associatedData, tagLength: vector.tagLength,
            afterEachPass: { pass, memory in observed[pass] = memory }
        )

        #expect(observed.count == vector.intermediate.count)
        for pass in vector.intermediate {
            let memory = try #require(observed[pass.pass], "no memory reported after pass \(pass.pass)")
            for word in pass.words {
                let expected = try #require(UInt64(word.value, radix: 16))
                let index = word.block * Argon2id.wordsPerBlock + word.word
                #expect(memory[index] == expected, "pass \(pass.pass), block \(word.block), word \(word.word)")
            }
        }
    }

    @Test("RFC 9106 §5.3: the tag")
    func tag() throws {
        let vector = try Self.vector()
        let inputs = try Self.inputs(vector)
        let tag = try Self.argon2(vector).hash(
            password: inputs.password, salt: inputs.salt, secret: inputs.secret,
            associatedData: inputs.associatedData, tagLength: vector.tagLength
        )
        #expect(tag == VectorFiles.bytes(hex: vector.tag))
    }

    @Test("H' longer than 64 bytes chains BLAKE2b, and a tag's length changes the whole tag")
    func longTags() throws {
        // A 32-byte tag isn't the prefix of a 100-byte one: T is hashed into H0. And a tag over
        // 64 bytes is built from several BLAKE2b outputs, which the RFC vector never reaches.
        let argon2 = try Argon2id(memoryKiB: 16, iterations: 1, parallelism: 1)
        let salt = [UInt8](repeating: 2, count: 16)
        let short = try argon2.hash(password: [1], salt: salt, tagLength: 32)
        let long = try argon2.hash(password: [1], salt: salt, tagLength: 100)
        #expect(long.count == 100)
        #expect(Array(long.prefix(32)) != short)
        #expect(Set(long).count > 16, "a 100-byte tag that is mostly repeated bytes isn't a hash")
    }
}

/// What Argon2id refuses: each by name, and none by crashing.
///
/// The RFC's minimums are correctness; the caps are this package's. Argon2's memory is a request
/// the caller makes of the server, and the caps are what keep a stored value or a configuration
/// from asking for more than a passphrase check should ever cost (amendment §7, "bounded work").
@Suite("Argon2id — parameters")
struct Argon2idParameterTests {

    @Test("memory below 8 KiB per lane is refused")
    func memoryBelowMinimum() {
        #expect(throws: Argon2id.Failure.memoryBelowMinimum(requested: 7, minimum: 8)) {
            try Argon2id(memoryKiB: 7, iterations: 1, parallelism: 1)
        }
        #expect(throws: Argon2id.Failure.memoryBelowMinimum(requested: 31, minimum: 32)) {
            try Argon2id(memoryKiB: 31, iterations: 1, parallelism: 4)
        }
    }

    @Test("memory above the cap is refused")
    func memoryAboveCap() {
        let over = Argon2id.maximumMemoryKiB + 1
        #expect(throws: Argon2id.Failure.memoryAboveMaximum(requested: over, maximum: Argon2id.maximumMemoryKiB)) {
            try Argon2id(memoryKiB: over, iterations: 1, parallelism: 1)
        }
    }

    @Test("zero iterations, or more than the cap, are refused")
    func iterations() {
        #expect(throws: Argon2id.Failure.iterationsBelowMinimum(requested: 0, minimum: 1)) {
            try Argon2id(memoryKiB: 64, iterations: 0, parallelism: 1)
        }
        let over = Argon2id.maximumIterations + 1
        #expect(throws: Argon2id.Failure.iterationsAboveMaximum(requested: over, maximum: Argon2id.maximumIterations)) {
            try Argon2id(memoryKiB: 64, iterations: over, parallelism: 1)
        }
    }

    @Test("zero lanes, or more than the cap, are refused")
    func parallelism() {
        #expect(throws: Argon2id.Failure.parallelismBelowMinimum(requested: 0, minimum: 1)) {
            try Argon2id(memoryKiB: 64, iterations: 1, parallelism: 0)
        }
        let over = Argon2id.maximumParallelism + 1
        #expect(throws: Argon2id.Failure.parallelismAboveMaximum(requested: over, maximum: Argon2id.maximumParallelism)) {
            try Argon2id(memoryKiB: 1024, iterations: 1, parallelism: over)
        }
    }

    @Test("a negative value is refused as below the minimum, not wrapped")
    func negatives() {
        #expect(throws: Argon2id.Failure.memoryBelowMinimum(requested: -1, minimum: 8)) {
            try Argon2id(memoryKiB: -1, iterations: 1, parallelism: 1)
        }
    }

    @Test("a salt under 8 bytes, or a tag outside the bounds, is refused at hashing")
    func hashingInputs() throws {
        let argon2 = try Argon2id(memoryKiB: 8, iterations: 1, parallelism: 1)
        #expect(throws: Argon2id.Failure.saltTooShort(length: 7, minimum: 8)) {
            try argon2.hash(password: [], salt: [UInt8](repeating: 0, count: 7))
        }
        let salt = [UInt8](repeating: 0, count: 8)
        #expect(throws: Argon2id.Failure.tagLengthOutOfRange(requested: 3, minimum: 4, maximum: Argon2id.maximumTagLength)) {
            try argon2.hash(password: [], salt: salt, tagLength: 3)
        }
        let long = Argon2id.maximumTagLength + 1
        #expect(throws: Argon2id.Failure.tagLengthOutOfRange(requested: long, minimum: 4, maximum: Argon2id.maximumTagLength)) {
            try argon2.hash(password: [], salt: salt, tagLength: long)
        }
    }

    @Test("the caps are the ones declared: 1 GiB, 32 passes, 16 lanes")
    func capsAreDeclared() {
        #expect(Argon2id.maximumMemoryKiB == 1_048_576)
        #expect(Argon2id.maximumIterations == 32)
        #expect(Argon2id.maximumParallelism == 16)
    }
}

/// Memory is the defence, so memory is what's checked.
///
/// An Argon2id that quietly used less memory than configured would pass the tag tests only if it
/// also matched the reference, which it couldn't; but a memory cap that rounded the wrong way
/// would pass every functional test. These check the size the derivation actually fills.
@Suite("Argon2id — memory")
struct Argon2idMemoryTests {

    static let salt = [UInt8](repeating: 2, count: 16)

    @Test("the derivation fills m KiB: m blocks of 1 KiB, when m is a multiple of 4p")
    func fillsConfiguredMemory() throws {
        let argon2 = try Argon2id(memoryKiB: 256, iterations: 1, parallelism: 2)
        var bytes = 0
        _ = try argon2.hash(password: [1], salt: Self.salt, afterEachPass: { _, memory in
            bytes = memory.count * 8
        })
        #expect(bytes == 256 * 1024)
        #expect(argon2.blockCount == 256)
    }

    @Test("otherwise m rounds down to a multiple of 4p, as RFC 9106 §3.2 says")
    func roundsDownToWholeSegments() throws {
        // 4 slices x 3 lanes = 12; 100 KiB holds 8 of those, 96 blocks.
        let argon2 = try Argon2id(memoryKiB: 100, iterations: 1, parallelism: 3)
        var bytes = 0
        _ = try argon2.hash(password: [1], salt: Self.salt, afterEachPass: { _, memory in
            bytes = memory.count * 8
        })
        #expect(argon2.blockCount == 96)
        #expect(bytes == 96 * 1024)
    }

    @Test("every block is written: none is left as it was allocated")
    func everyBlockIsFilled() throws {
        let argon2 = try Argon2id(memoryKiB: 64, iterations: 1, parallelism: 2)
        var zeroBlocks = -1
        _ = try argon2.hash(password: [1], salt: Self.salt, afterEachPass: { _, memory in
            zeroBlocks = stride(from: 0, to: memory.count, by: Argon2id.wordsPerBlock).filter { start in
                memory[start..<(start + Argon2id.wordsPerBlock)].allSatisfy { $0 == 0 }
            }.count
        })
        #expect(zeroBlocks == 0)
    }
}

/// The cost is the defence, so the cost is measured, loosely.
///
/// Measured as this thread's CPU time, not wall-clock time. The derivation runs synchronously on
/// one thread, so its CPU time is its work and nothing else's; wall-clock time on a loaded
/// machine is mostly the scheduler, and a wall-clock bound flips with the load average.
@Suite("Argon2id — the work is real", .serialized)
struct Argon2idWorkTests {

    /// CPU time consumed so far by the calling thread.
    static func threadCPUTime() -> Duration {
        var spec = timespec()
        guard clock_gettime(CLOCK_THREAD_CPUTIME_ID, &spec) == 0 else { return .zero }
        return .seconds(Int64(spec.tv_sec)) + .nanoseconds(Int64(spec.tv_nsec))
    }

    // TIMING: memory-hard work that costs nothing isn't happening.
    @Test("hashing 4 MiB takes real CPU time, and not unbounded time")
    func derivationTakesTime() throws {
        let argon2 = try Argon2id(memoryKiB: 4_096, iterations: 1, parallelism: 1)
        let started = Self.threadCPUTime()
        _ = try argon2.hash(password: [1], salt: [UInt8](repeating: 2, count: 16))
        let elapsed = Self.threadCPUTime() - started

        // A floor and a ceiling, both loose. 4,096 compressions of a 1 KiB block can't finish in
        // under a millisecond of CPU; if they did, the blocks aren't being filled. And they
        // shouldn't take a minute, even unoptimized: that's a denial-of-service lever (amendment
        // §12).
        // TIMING: intentional. The cost is the defence, so the cost is what is asserted.
        #expect(elapsed > .milliseconds(1), "4 MiB took \(elapsed) of CPU: the memory isn't being filled")
        #expect(elapsed < .seconds(60), "4 MiB took \(elapsed) of CPU")
    }
}

/// Argon2id against an independent implementation, case for case.
///
/// `argon2id-differential.txt` is written by `Harness/Argon2id/generate.py`, which is never a
/// package dependency; its header names the reference and its version. The cases vary lanes,
/// passes, memory that isn't a multiple of 4p, empty passwords, secrets and associated data, and
/// tag lengths either side of H's 64 bytes, none of which the single RFC vector reaches.
@Suite("Argon2id — differential")
struct Argon2idDifferentialTests {

    @Test("every seeded case matches the reference's tag")
    func differential() throws {
        let cases = try Argon2idCase.cases(in: "argon2id-differential.txt")
        for vector in cases {
            #expect(try vector.ours() == vector.tag, "\(vector.label)")
        }
        // The generator writes 64; fewer means the file was cut short.
        #expect(cases.count == 64)
        #expect(Set(cases.map(\.parallelism)) == [1, 2, 3, 4])
    }
}
