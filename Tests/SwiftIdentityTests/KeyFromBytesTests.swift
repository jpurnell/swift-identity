import Foundation
import SwiftDeterminism
import Testing
@testable import SwiftIdentity

/// The sealing key and the pepper from bytes rather than a file, for a key kept somewhere a file
/// isn't, such as the Apple Keychain. The size rule is the file's; the owner-only rule is a file's
/// alone.
@Suite("Keys from bytes")
struct KeyFromBytesTests {

    /// A key file written the usual way, and its bytes.
    static func keyFile(seed: UInt64) throws -> (url: URL, bytes: Data) {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("keybytes-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("key")
        var generator = SplitMix64(seed: seed)
        try SealingKey.create(at: url, using: &generator)
        return (url, try Data(contentsOf: url))
    }

    @Test("A sealing key from bytes opens what the same key from its file sealed")
    func sealingKeyFromBytes() throws {
        let file = try Self.keyFile(seed: 1)
        let fromFile = try SealingKey(contentsOf: file.url)
        let fromBytes = try SealingKey(data: file.bytes)
        var generator = SplitMix64(seed: 2)
        let sealed = try fromFile.seal(Array("otp key".utf8), context: "ada", using: &generator)
        #expect(try fromBytes.open(sealed, context: "ada") == Array("otp key".utf8))
    }

    @Test("A pepper from bytes has the identifier the same pepper from its file has")
    func pepperFromBytes() throws {
        let file = try Self.keyFile(seed: 3)
        #expect(try Pepper(data: file.bytes).identifier == Pepper(contentsOf: file.url).identifier)
    }

    @Test("Bytes that aren't 32 are refused, for both keys", arguments: [0, 16, 31, 33, 64])
    func wrongSize(_ count: Int) {
        let bytes = Data(repeating: 7, count: count)
        #expect(throws: KeyFileFailure.wrongSize(count)) { try SealingKey(data: bytes) }
        #expect(throws: KeyFileFailure.wrongSize(count)) { try Pepper(data: bytes) }
    }
}
