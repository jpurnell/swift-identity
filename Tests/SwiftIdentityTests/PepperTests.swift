import Foundation
import SwiftDeterminism
import Testing
@testable import SwiftIdentity

/// A pepper: one more keyed pass over a digest, with a key that never sits beside the digests.
@Suite("Pepper")
struct PepperTests {

    static func pepper(seed: UInt64) throws -> Pepper {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("pepper-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("pepper.key")
        var generator = SplitMix64(seed: seed)
        try Pepper.create(at: url, using: &generator)
        return try Pepper(contentsOf: url)
    }

    static let ada = Passphrase(subjectID: "ada", secret: "correct horse battery staple")

    static func verifier(_ scheme: any PassphraseScheme, seed: UInt64) throws -> PassphraseVerifier {
        var generator = SplitMix64(seed: seed)
        let schemes = PassphraseSchemes([scheme], writing: scheme)
        return try PassphraseVerifier(for: ada, using: &generator, parameters: "\(PassphraseVerifier.roundFloor)", schemes: schemes)
    }

    @Test("P15: a peppered digest verifies with its pepper, and is a different digest than without it")
    func pepperedVerifies() throws {
        let pepper = try Self.pepper(seed: 1)
        let peppered = PepperedScheme(PBKDF2SHA256C1(), pepper: pepper)
        let withPepper = try Self.verifier(peppered, seed: 2)
        let without = try Self.verifier(PBKDF2SHA256C1(), seed: 2)
        #expect(withPepper.salt == without.salt)
        #expect(withPepper.digest != without.digest)
        #expect(withPepper.matches(Self.ada))
        #expect(!withPepper.matches(Passphrase(subjectID: "ada", secret: "wrong")))
    }

    @Test("P15: the stored form names the pepper by fingerprint, never by value")
    func identifierNamesThePepper() throws {
        let pepper = try Self.pepper(seed: 3)
        let peppered = PepperedScheme(PBKDF2SHA256C1(), pepper: pepper)
        #expect(peppered.identifier == "pbkdf2-sha256-c1+p\(pepper.identifier)")
        #expect(pepper.identifier.count == 16)
        let verifier = try Self.verifier(peppered, seed: 4)
        #expect(verifier.encoded.hasPrefix("pbkdf2-sha256-c1+p\(pepper.identifier)$"))
    }

    @Test("P15: without the pepper, or with another, a peppered digest doesn't verify")
    func needsItsPepper() throws {
        let pepper = try Self.pepper(seed: 5)
        let other = try Self.pepper(seed: 6)
        let verifier = try Self.verifier(PepperedScheme(PBKDF2SHA256C1(), pepper: pepper), seed: 7)
        // The standard set doesn't know the scheme: fails closed.
        #expect(PassphraseVerifier(encoded: verifier.encoded) == nil)
        // Another pepper is another identifier: fails closed too.
        let otherSchemes = PassphraseSchemes([PepperedScheme(PBKDF2SHA256C1(), pepper: other)],
                                             writing: PepperedScheme(PBKDF2SHA256C1(), pepper: other))
        #expect(PassphraseVerifier(encoded: verifier.encoded, schemes: otherSchemes) == nil)
    }

    @Test("P15: adding a pepper, or rotating it, marks existing digests for upgrade")
    func upgrades() throws {
        let first = try Self.pepper(seed: 8)
        let second = try Self.pepper(seed: 9)
        let plain = try Self.verifier(PBKDF2SHA256C1(), seed: 10)
        let peppered = PassphraseSchemes([PBKDF2SHA256C1(), PepperedScheme(PBKDF2SHA256C1(), pepper: first)],
                                         writing: PepperedScheme(PBKDF2SHA256C1(), pepper: first))
        #expect(plain.needsUpgrade(to: peppered))
        let underFirst = try Self.verifier(PepperedScheme(PBKDF2SHA256C1(), pepper: first), seed: 11)
        let rotated = PassphraseSchemes([PepperedScheme(PBKDF2SHA256C1(), pepper: first), PepperedScheme(PBKDF2SHA256C1(), pepper: second)],
                                        writing: PepperedScheme(PBKDF2SHA256C1(), pepper: second))
        #expect(underFirst.needsUpgrade(to: rotated))
        // During a rotation the old pepper still verifies.
        let decoded = try #require(PassphraseVerifier(encoded: underFirst.encoded, schemes: rotated))
        #expect(decoded.matches(Self.ada))
    }

    @Test("P15: the pepper comes from the caller's generator, an approved RBG in production")
    func pepperFromGenerator() throws {
        #expect(try Self.pepper(seed: 12).identifier == Self.pepper(seed: 12).identifier)
        #expect(try Self.pepper(seed: 12).identifier != Self.pepper(seed: 13).identifier)
    }

    @Test("P15: a pepper file anyone else can read is refused, and one isn't overwritten")
    func pepperFileRules() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("pepper-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("pepper.key")
        var generator = SplitMix64(seed: 14)
        try Pepper.create(at: url, using: &generator)
        #expect(throws: KeyFileFailure.alreadyExists) { try Pepper.create(at: url, using: &generator) }
        try FileManager.default.setAttributes([.posixPermissions: 0o640], ofItemAtPath: url.path)
        #expect(throws: KeyFileFailure.readableByOthers) { try Pepper(contentsOf: url) }
    }
}
