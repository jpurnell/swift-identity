import SwiftDeterminism
import Testing
@testable import SwiftIdentity

/// Versioned derivation schemes: what a stored digest's first field promises.
///
/// 0.6.x wrote `pbkdf2-sha256`, over the raw secret. From the amendment on, new digests are
/// `pbkdf2-sha256-c1`, over the canonical secret (``PassphraseCanonicalization/c1``). The old
/// ones keep verifying, and are never written again.
@Suite("PassphraseScheme")
struct PassphraseSchemeTests {

    static let rounds = PassphraseVerifier.roundFloor

    static func verifier(_ secret: String, subject: String = "ada", seed: UInt64) throws -> PassphraseVerifier {
        var generator = SplitMix64(seed: seed)
        return try PassphraseVerifier(
            for: Passphrase(subjectID: subject, secret: secret), using: &generator, rounds: rounds
        )
    }

    // MARK: - Canonicalized digests

    @Test("P6: a passphrase set with one é matches when typed with the other")
    func canonicalEquivalentsMatch() throws {
        let verifier = try Self.verifier("caf\u{E9} au lait", seed: 1)
        #expect(verifier.matches(Passphrase(subjectID: "ada", secret: "cafe\u{301} au lait")))
    }

    @Test("P6: new digests are written under the canonicalized scheme")
    func newDigestsAreC1() throws {
        let verifier = try Self.verifier("correct horse battery staple", seed: 2)
        #expect(verifier.scheme.identifier == "pbkdf2-sha256-c1")
        #expect(verifier.encoded.hasPrefix("pbkdf2-sha256-c1$"))
        #expect(PassphraseSchemes.standard.writing.identifier == "pbkdf2-sha256-c1")
    }

    @Test("P6: fullwidth and no-break characters are their own characters, not folded")
    func compatibilityCharactersStayDistinct() throws {
        let verifier = try Self.verifier("AB CD", seed: 3)
        #expect(!verifier.matches(Passphrase(subjectID: "ada", secret: "\u{FF21}\u{FF22} CD")))
        #expect(!verifier.matches(Passphrase(subjectID: "ada", secret: "AB\u{A0}CD")))
        #expect(verifier.matches(Passphrase(subjectID: "ada", secret: "AB CD")))
    }

    @Test("P4: a secret that can't be canonicalized is refused at issuance, with its position")
    func uncanonicalizableSecretsAreRefused() {
        var generator = SplitMix64(seed: 4)
        #expect(throws: PassphraseVerifier.Failure.refused(.controlCharacter(position: 3))) {
            try PassphraseVerifier(
                for: Passphrase(subjectID: "ada", secret: "abc\u{0}def"), using: &generator, rounds: Self.rounds
            )
        }
    }

    @Test("and one presented at sign-in matches nothing")
    func uncanonicalizablePresentationsDoNotMatch() throws {
        let verifier = try Self.verifier("abcdef", seed: 5)
        #expect(!verifier.matches(Passphrase(subjectID: "ada", secret: "abc\u{0}def")))
    }

    @Test("the subject is mixed in byte for byte, never canonicalized")
    func theSubjectIsNotCanonicalized() throws {
        // Only the secret is canonicalized. A subject ID is an identifier, compared exactly.
        let verifier = try Self.verifier("correct horse", subject: "jose\u{301}", seed: 6)
        #expect(!verifier.matches(Passphrase(subjectID: "jos\u{E9}", secret: "correct horse")))
        #expect(verifier.matches(Passphrase(subjectID: "jose\u{301}", secret: "correct horse")))
    }

    @Test("P7: every character counts; nothing is truncated")
    func nothingIsTruncated() throws {
        let long = String(repeating: "word ", count: 200)
        let verifier = try Self.verifier(long + "a", seed: 7)
        #expect(!verifier.matches(Passphrase(subjectID: "ada", secret: long + "b")))
        #expect(verifier.matches(Passphrase(subjectID: "ada", secret: long + "a")))
    }

    // MARK: - Legacy digests

    @Test("a 0.6.x digest still verifies against the raw secret")
    func legacyStillVerifies() throws {
        var generator = SplitMix64(seed: 8)
        let legacy = try PassphraseVerifier(
            for: Passphrase(subjectID: "ada", secret: "caf\u{E9}"),
            using: &generator, rounds: Self.rounds, scheme: PBKDF2SHA256Legacy()
        )
        #expect(legacy.encoded.hasPrefix("pbkdf2-sha256$"))
        let decoded = try #require(PassphraseVerifier(encoded: legacy.encoded))
        #expect(decoded.scheme.identifier == "pbkdf2-sha256")
        #expect(decoded.matches(Passphrase(subjectID: "ada", secret: "caf\u{E9}")))
        // Byte-exact, as it always was: that's why it needs upgrading.
        #expect(!decoded.matches(Passphrase(subjectID: "ada", secret: "cafe\u{301}")))
    }

    @Test("a legacy digest is never what the standard schemes write")
    func legacyIsNeverWritten() {
        #expect(PassphraseSchemes.standard.accepts("pbkdf2-sha256"))
        #expect(PassphraseSchemes.standard.writing.identifier != "pbkdf2-sha256")
    }

    // MARK: - Upgrades

    @Test("P14b: a legacy digest, or one below today's cost, needs upgrading")
    func needsUpgrade() throws {
        var generator = SplitMix64(seed: 9)
        let legacy = try PassphraseVerifier(
            for: Passphrase(subjectID: "ada", secret: "x"), using: &generator,
            rounds: PassphraseVerifier.defaultRounds, scheme: PBKDF2SHA256Legacy()
        )
        #expect(legacy.needsUpgrade(to: .standard))

        let cheap = try Self.verifier("x", seed: 10)
        #expect(cheap.needsUpgrade(to: .standard), "below defaultRounds")

        let current = try PassphraseVerifier(
            for: Passphrase(subjectID: "ada", secret: "x"), using: &generator
        )
        #expect(!current.needsUpgrade(to: .standard))
    }

    @Test("P14b: the scheme and its cost are stored with each digest")
    func schemeAndCostAreStored() throws {
        let verifier = try Self.verifier("x", seed: 11)
        let fields = verifier.encoded.split(separator: "$")
        #expect(fields.count == 4)
        #expect(fields[0] == "pbkdf2-sha256-c1")
        #expect(fields[1] == "\(Self.rounds)")
    }

    @Test("P14a: the salt is 128 bits, above NIST's 32, and stored")
    func saltIsLongEnoughAndStored() throws {
        let verifier = try Self.verifier("x", seed: 12)
        #expect(verifier.salt.count * 8 >= 32)
        #expect(verifier.salt.count == 16)
        let decoded = try #require(PassphraseVerifier(encoded: verifier.encoded))
        #expect(decoded.salt == verifier.salt)
    }

    // MARK: - Unknown schemes

    @Test("an unknown scheme fails closed, never falling back to a default")
    func unknownSchemesFailClosed() {
        // Argon2id isn't accepted until its gate passes (§9); a `-k1` digest never existed.
        #expect(PassphraseVerifier(encoded: "argon2id-c1$600000$c2FsdA$ZGlnZXN0") == nil)
        #expect(PassphraseVerifier(encoded: "pbkdf2-sha256-k1$600000$c2FsdA$ZGlnZXN0") == nil)
        #expect(!PassphraseSchemes.standard.accepts("pbkdf2-sha256-k1"))
    }

    // MARK: - Schemes from outside

    /// A scheme a deployment might add. It derives; it never compares.
    struct Reversed: PassphraseScheme {
        let identifier = "test-reversed-c1"
        let canonicalization: PassphraseCanonicalization? = .c1
        func isValid(parameters: String) -> Bool { parameters == "1" }
        func derive(_ material: [UInt8], parameters: String, salt: [UInt8]) throws -> [UInt8] {
            Array((material + salt).reversed())
        }
    }

    @Test("a scheme from outside the package plugs in through PassphraseSchemes")
    func thirdPartySchemes() throws {
        let schemes = PassphraseSchemes([PBKDF2SHA256C1(), Reversed()], writing: Reversed())
        var generator = SplitMix64(seed: 13)
        let verifier = try PassphraseVerifier(
            for: Passphrase(subjectID: "ada", secret: "cafe\u{301}"),
            using: &generator, parameters: "1", schemes: schemes
        )
        #expect(verifier.encoded.hasPrefix("test-reversed-c1$1$"))
        let decoded = try #require(PassphraseVerifier(encoded: verifier.encoded, schemes: schemes))
        #expect(decoded.matches(Passphrase(subjectID: "ada", secret: "caf\u{E9}")))
        // The standard set doesn't know it, so it fails closed there.
        #expect(PassphraseVerifier(encoded: verifier.encoded) == nil)
    }

    @Test("a scheme's own parameter check is enforced when decoding")
    func schemeParametersAreValidated() throws {
        let schemes = PassphraseSchemes([Reversed()], writing: Reversed())
        #expect(PassphraseVerifier(encoded: "test-reversed-c1$2$c2FsdA$ZGlnZXN0", schemes: schemes) == nil)
    }
}
