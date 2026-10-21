import SwiftDeterminism
import Testing
@testable import SwiftIdentity

/// What is stored for a passphrase, and what it costs to check one.
///
/// A passphrase is the only credential kind a person could plausibly guess, which is the entire
/// reason this type exists and the reason it is deliberately slow. Every other kind is compared
/// against a fast hash, and that is not an oversight — see ``BearerKey``.
@Suite("PassphraseVerifier")
struct PassphraseVerifierTests {

    static let ada = Passphrase(subjectID: "ada", secret: "correct horse battery staple")


    // MARK: - Round trip

    @Test("a passphrase verifies against a verifier made from it")
    func aPassphraseMatchesItsOwnVerifier() throws {
        var generator = SplitMix64(seed: 1)
        let verifier = try PassphraseVerifier(for: Self.ada, using: &generator)
        #expect(verifier.matches(Self.ada))
    }

    @Test("and a different passphrase does not")
    func aDifferentPassphraseDoesNot() throws {
        var generator = SplitMix64(seed: 2)
        let verifier = try PassphraseVerifier(for: Self.ada, using: &generator)
        #expect(!verifier.matches(Passphrase(subjectID: "ada", secret: "wrong")))
    }

    @Test("nor the same words claimed by a different subject")
    func theSubjectIsBoundIntoTheVerifier() throws {
        var generator = SplitMix64(seed: 3)
        let verifier = try PassphraseVerifier(for: Self.ada, using: &generator)

        // Two people choosing the same words must not authenticate as each other — and a
        // verifier line moved to another subject in the file must stop working, which is the
        // property that makes the roster safe to edit by hand.
        #expect(!verifier.matches(Passphrase(subjectID: "grace", secret: Self.ada.secret)))
    }

    @Test("two verifiers for one passphrase differ, because the salt is fresh each time")
    func saltsAreNotReused() throws {
        // One generator, drawn twice: successive draws must differ, which is what "fresh salt"
        // means. Two generators seeded alike would prove the opposite of the point.
        var generator = SplitMix64(seed: 4)
        let first = try PassphraseVerifier(for: Self.ada, using: &generator)
        let second = try PassphraseVerifier(for: Self.ada, using: &generator)

        #expect(first.salt != second.salt)
        #expect(first.digest != second.digest)
        // Both still verify: the salt is stored, not remembered.
        #expect(first.matches(Self.ada))
        #expect(second.matches(Self.ada))
    }

    // MARK: - The stored form

    @Test("it encodes to one self-describing field, so the file's shape does not change")
    func encodingIsASingleField() throws {
        var generator = SplitMix64(seed: 5)
        let verifier = try PassphraseVerifier(for: Self.ada, using: &generator)
        let encoded = verifier.encoded

        // `pbkdf2-sha256$<rounds>$<salt>$<digest>`. One field keeps the verifiers file at
        // `<subject> <kind> <verifier> <expires>` for every kind, and the algorithm prefix is
        // what lets a later, better KDF be told apart from this one rather than guessed at.
        #expect(encoded.hasPrefix("pbkdf2-sha256$"))
        #expect(encoded.split(separator: "$").count == 4)
        #expect(!encoded.contains(" "))
    }

    @Test("and decodes back to the same verifier")
    func encodingRoundTrips() throws {
        var generator = SplitMix64(seed: 6)
        let verifier = try PassphraseVerifier(for: Self.ada, using: &generator)
        let decoded = try #require(PassphraseVerifier(encoded: verifier.encoded))

        #expect(decoded.rounds == verifier.rounds)
        #expect(decoded.salt == verifier.salt)
        #expect(decoded.digest == verifier.digest)
        #expect(decoded.matches(Self.ada))
    }

    @Test("the round count is stored, so raising it later does not invalidate what exists")
    func roundsAreStoredNotAssumed() throws {
        var generator = SplitMix64(seed: 7)
        let verifier = try PassphraseVerifier(for: Self.ada, using: &generator, rounds: 250_000)
        let decoded = try #require(PassphraseVerifier(encoded: verifier.encoded))

        #expect(decoded.rounds == 250_000)
        #expect(decoded.matches(Self.ada))
        // A verifier written at a lower cost still verifies. Re-deriving at the new cost is a
        // rotation, not a parse failure.
        #expect(PassphraseVerifier.defaultRounds > 250_000)
    }

    // MARK: - Refusals

    @Test("a round count below the floor is refused, not quietly accepted")
    func tooFewRoundsAreRefused() {
        var generator = SplitMix64(seed: 8)
        // swift-crypto enforces 210,000 itself, and this surfaces the refusal rather than
        // letting a caller discover it as an opaque CryptoKit error.
        #expect(throws: PassphraseVerifier.Failure.roundsBelowFloor(requested: 1_000, floor: 210_000)) {
            try PassphraseVerifier(for: Self.ada, using: &generator, rounds: 1_000)
        }
    }

    @Test("a malformed stored value is refused rather than half-read")
    func malformedEncodingsAreRefused() {
        #expect(PassphraseVerifier(encoded: "") == nil)
        #expect(PassphraseVerifier(encoded: "pbkdf2-sha256$600000$onlythree") == nil)
        #expect(PassphraseVerifier(encoded: "pbkdf2-sha256$notanumber$c2FsdA$ZGlnZXN0") == nil)
        #expect(PassphraseVerifier(encoded: "pbkdf2-sha256$600000$!!!$ZGlnZXN0") == nil)
        #expect(PassphraseVerifier(encoded: "pbkdf2-sha256$100$c2FsdA$ZGlnZXN0") == nil)
    }

    @Test("an algorithm this package does not implement is refused by name")
    func unknownAlgorithmsAreRefused() {
        // The prefix exists so that argon2id, when it arrives, is a different verifier rather
        // than a silently mis-derived one.
        #expect(PassphraseVerifier(encoded: "argon2id$600000$c2FsdA$ZGlnZXN0") == nil)
        #expect(PassphraseVerifier(encoded: "scrypt$600000$c2FsdA$ZGlnZXN0") == nil)
    }
}

/// The cost is the defence, so the cost is measured.
///
/// A KDF that is quietly fast is a KDF that is not doing its job, and nothing else in the suite
/// would notice: every functional test passes just as happily against one round as against six
/// hundred thousand.
@Suite("PassphraseVerifier — the work factor is real", .serialized)
struct PassphraseWorkFactorTests {

    // TIMING: the work factor is the defence, so its cost is the assertion.
    @Test("deriving at the default cost takes real time")
    func derivationIsSlow() throws {
        var generator = SplitMix64(seed: 99)
        let passphrase = Passphrase(subjectID: "ada", secret: "correct horse battery staple")

        let started = ContinuousClock.now
        _ = try PassphraseVerifier(for: passphrase, using: &generator)
        let elapsed = ContinuousClock.now - started

        // A floor, not a target. 600,000 rounds of PBKDF2-HMAC-SHA256 costs tens of
        // milliseconds on current hardware; anything under a millisecond means the rounds are
        // not happening, which is the failure this test exists for. The bound is loose enough
        // to survive a faster machine and tight enough to catch a missing work factor.
        // TIMING: intentional. The cost is the defence, so the cost is what is asserted.
        #expect(elapsed > .milliseconds(5), "derivation took \(elapsed) — the work factor is not being applied")
    }

    // TIMING: a stored round count that did not drive the cost would be decoration.
    @Test("and more rounds cost more, which is what makes the number meaningful")
    func costScalesWithRounds() throws {
        var generator = SplitMix64(seed: 99)
        let passphrase = Passphrase(subjectID: "ada", secret: "correct horse battery staple")

        /// The fastest of several runs.
        ///
        /// A first version of this compared single measurements and the gate caught it flipping
        /// fail→pass against a byte-identical package — a race, not a code change. Noise only
        /// ever *adds* time, so the minimum of several runs is the closest thing to the real
        /// cost that a loaded machine will give up.
        func fastest(of rounds: Int, runs: Int = 3) throws -> Duration {
            var best = Duration.seconds(3_600)
            for _ in 0..<runs {
                let started = ContinuousClock.now
                _ = try PassphraseVerifier(for: passphrase, using: &generator, rounds: rounds)
                best = min(best, ContinuousClock.now - started)
            }
            return best
        }

        let cheap = try fastest(of: PassphraseVerifier.roundFloor)
        let dear = try fastest(of: PassphraseVerifier.roundFloor * 4)

        // Four times the rounds for at least twice the time. Loose on purpose: the claim is that
        // the round count drives the cost at all, not that it does so with any particular
        // efficiency.
        // TIMING: intentional. A stored round count that changed nothing would pass every other test.
        #expect(dear > cheap * 2, "\(cheap) → \(dear): rounds are not driving the cost")
    }
}
