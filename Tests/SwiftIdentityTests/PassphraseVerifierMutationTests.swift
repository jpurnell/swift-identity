import Testing
@testable import SwiftIdentity

/// What mutation testing found the verifier and scheme tests didn't pin down.
///
/// Each test here was written against a mutant that survived the existing suites
/// (`Harness/Mutation/REPORT.md`): it fails with that mutant applied and passes without it.
extension PassphraseVerifierTests {

    /// A stored value, one field at a time, so a test can vary exactly one.
    static func stored(
        scheme: String = "pbkdf2-sha256-c1", parameters: String = "600000",
        salt: [UInt8] = Array(0..<16), digest: [UInt8] = Array(repeating: 7, count: 32)
    ) -> String {
        "\(scheme)$\(parameters)$\(Base64URL.encode(salt))$\(Base64URL.encode(digest))"
    }

    // MARK: - The stored form

    @Test("a stored value with an empty fifth field is malformed, not four fields and a stray separator")
    func emptyFieldsAreFields() throws {
        let valid = Self.stored()
        #expect(PassphraseVerifier(encoded: valid)?.encoded == valid)
        // Empty fields count. Skipping them would read a line with a stray `$` as a verifier,
        // which makes "is this exactly what we wrote?" a question with two answers.
        #expect(PassphraseVerifier(encoded: valid + "$") == nil)
        #expect(PassphraseVerifier(encoded: "$" + valid) == nil)
        #expect(PassphraseVerifier(encoded: valid.replacingOccurrences(of: "$600000$", with: "$$600000$")) == nil)
    }

    // MARK: - Equality

    @Test("two verifiers are equal exactly when every stored field is")
    func equalityIsEveryField() throws {
        let base = try #require(PassphraseVerifier(encoded: Self.stored()))
        #expect(base == (try #require(PassphraseVerifier(encoded: Self.stored()))))

        // One field different at a time: an equality that ignored any one field, or that
        // accepted a match on some of them, would call one of these equal.
        let scheme = try #require(PassphraseVerifier(encoded: Self.stored(scheme: "pbkdf2-sha256")))
        let parameters = try #require(PassphraseVerifier(encoded: Self.stored(parameters: "600001")))
        let salt = try #require(PassphraseVerifier(encoded: Self.stored(salt: Array(1..<17))))
        let digest = try #require(PassphraseVerifier(encoded: Self.stored(digest: Array(repeating: 8, count: 32))))
        #expect(base != scheme)
        #expect(base != parameters)
        #expect(base != salt)
        #expect(base != digest)
    }

    // MARK: - A derivation that fails

    /// A scheme whose derivation always throws, for the path `matches` must close.
    struct Failing: PassphraseScheme {
        struct Broken: Error {}
        let identifier = "test-failing-c1"
        let canonicalization: PassphraseCanonicalization? = .c1
        func isValid(parameters: String) -> Bool { parameters == "1" }
        func derive(_ material: [UInt8], parameters: String, salt: [UInt8]) throws -> [UInt8] {
            throw Broken()
        }
    }

    @Test("a derivation that throws matches nothing")
    func aFailedDerivationMatchesNothing() throws {
        let schemes = PassphraseSchemes([], writing: Failing())
        let verifier = try #require(
            PassphraseVerifier(encoded: Self.stored(scheme: "test-failing-c1", parameters: "1"), schemes: schemes)
        )
        #expect(!verifier.matches(Self.ada))
    }
}

extension PassphraseSchemeTests {

    @Test("a scheme that declares no cost policy is never below its current cost")
    func noCostPolicyMeansNoUpgrade() throws {
        let schemes = PassphraseSchemes([], writing: Reversed())
        #expect(!Reversed().isBelowCurrentCost("1"))
        let verifier = try #require(
            PassphraseVerifier(encoded: PassphraseVerifierTests.stored(scheme: "test-reversed-c1", parameters: "1"),
                               schemes: schemes)
        )
        #expect(!verifier.needsUpgrade(to: schemes))
    }

    @Test("a legacy digest is below current cost however many rounds it has")
    func legacyIsAlwaysBelowCost() throws {
        let legacy = PBKDF2SHA256Legacy()
        #expect(legacy.isBelowCurrentCost("\(PassphraseVerifier.defaultRounds)"))
        #expect(legacy.isBelowCurrentCost("\(PassphraseVerifier.defaultRounds * 2)"))
        // Even where legacy is what's written, so the identifier can't be the reason.
        let schemes = PassphraseSchemes([], writing: legacy)
        let verifier = try #require(
            PassphraseVerifier(encoded: PassphraseVerifierTests.stored(scheme: "pbkdf2-sha256"), schemes: schemes)
        )
        #expect(verifier.needsUpgrade(to: schemes))
    }

    @Test("pbkdf2-sha256-c1 derives PBKDF2-HMAC-SHA256's own 32 bytes: a known answer")
    func pbkdf2KnownAnswer() throws {
        // From Python's `hashlib.pbkdf2_hmac("sha256", b"ada|correct horse battery staple",
        // bytes(range(16)), 210000)`: an implementation that isn't this one.
        let expected = "3991180f83bd5e655f8f46393481603cc61fcb41cb1760f4e35dfc99beb3a64d"
        let verifier = try PassphraseVerifier(
            for: PassphraseVerifierTests.ada, scheme: PBKDF2SHA256C1(),
            parameters: "\(PassphraseVerifier.roundFloor)", salt: Array(0..<16)
        )
        #expect(verifier.digest.count == 32)
        #expect(verifier.digest.map(Hex.byte).joined() == expected)
    }

    @Test("the writing scheme is accepted even when the list leaves it out")
    func writingIsAlwaysAccepted() {
        let schemes = PassphraseSchemes([], writing: PBKDF2SHA256C1())
        #expect(schemes.accepts("pbkdf2-sha256-c1"))
        #expect(!schemes.accepts("pbkdf2-sha256"))
    }
}
