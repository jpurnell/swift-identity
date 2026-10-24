#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import Foundation
import Testing
@testable import SwiftIdentity

/// What mutation testing found the ledger tests didn't pin down.
///
/// Each test here was written against a mutant that survived the existing suites
/// (`Harness/Mutation/REPORT.md`): it fails with that mutant applied and passes without it. Most
/// are against ``LedgerBook`` directly, because the property is the book's and both ledgers
/// share it.
extension ThrottleLedgerTests {

    static func passphrase(salt: [UInt8]) throws -> PassphraseVerifier {
        try #require(PassphraseVerifier(
            encoded: "pbkdf2-sha256-c1$600000$\(Base64URL.encode(salt))$\(Base64URL.encode(Array(repeating: 7, count: 32)))"
        ))
    }

    static func oneTimeCode(sealed: [UInt8]) throws -> OneTimeCodeVerifier {
        try #require(OneTimeCodeVerifier(encoded: "totp-sha1-6-30$\(Base64URL.encode(sealed))", subjectID: "ada"))
    }

    /// A book holding `count` keys nobody will ask about.
    static func book(holding count: Int) -> LedgerBook {
        var book = LedgerBook()
        for index in 0..<count {
            book.entries[ThrottleKey(subjectID: "filler-\(index)", authenticator: "x")] = LedgerEntry(failures: 1)
        }
        return book
    }

    // MARK: - Keys

    @Test("a new passphrase is a new key, even when its salt is the same length as the old one's")
    func passphraseKeyHashesTheSalt() throws {
        let old = ThrottleKey.passphrase(subjectID: "ada", verifiers: [try Self.passphrase(salt: Array(0..<16))])
        let new = ThrottleKey.passphrase(subjectID: "ada", verifiers: [try Self.passphrase(salt: Array(16..<32))])
        #expect(old.subjectID == "ada")
        #expect(old.authenticator.hasPrefix("passphrase:"))
        // Rebinding is issuing a new verifier: it must not inherit the old one's count.
        #expect(old != new)
    }

    @Test("an enrolled app's key is the subject's own, and a re-enrolled app is a new one")
    func oneTimeCodeKeyHashesTheSealedKey() throws {
        let first = ThrottleKey.oneTimeCode(subjectID: "ada", verifiers: [try Self.oneTimeCode(sealed: Array(0..<40))])
        let second = ThrottleKey.oneTimeCode(subjectID: "ada", verifiers: [try Self.oneTimeCode(sealed: Array(40..<80))])
        #expect(first.subjectID == "ada")
        #expect(first.authenticator.hasPrefix("totp:"))
        #expect(first != ThrottleKey.unknownOneTimeCode)
        #expect(first != second)
        #expect(ThrottleKey.oneTimeCode(subjectID: "ada", verifiers: []) == ThrottleKey.unknownOneTimeCode)
    }

    // MARK: - Backoff

    @Test("a backoff refuses until the instant it ends, and not at that instant")
    func backoffEndsAtItsEnd() {
        let state = ThrottleState(consecutiveFailures: 5, refusedUntil: Self.start, isDisabled: false)
        #expect(state.refuses(at: Self.start.addingTimeInterval(-1)))
        #expect(!state.refuses(at: Self.start))
    }

    @Test("P13: the attempt that reaches the ceiling earns no backoff; the count alone refuses")
    func ceilingAttemptHasNoBackoff() throws {
        let policy = try ThrottlePolicy(threshold: 1, backoff: 1, ceiling: 3)
        var book = LedgerBook()
        for second in [0.0, 10, 20] {
            #expect(try book.beginAttempt(Self.ada, at: Self.start.addingTimeInterval(second), policy: policy))
        }
        let state = book.state(Self.ada, ceiling: policy.ceiling)
        #expect(state.consecutiveFailures == 3)
        #expect(state.isDisabled)
        #expect(state.refusedUntil == nil)
    }

    // MARK: - The entry limit

    @Test("a full book refuses an attempt on a new key, and admits one below the limit")
    func beginAttemptRespectsTheLimit() throws {
        var below = Self.book(holding: LedgerBook.maximumEntries - 1)
        #expect(try below.beginAttempt(Self.ada, at: Self.start, policy: .standard))
        #expect(below.entries.count == LedgerBook.maximumEntries)
        let full = below
        #expect(throws: ThrottleLedgerError.full(limit: LedgerBook.maximumEntries)) {
            var book = full
            _ = try book.beginAttempt(Self.grace, at: Self.start, policy: .standard)
        }
    }

    @Test("a failure involving new keys is refused if adding them all would pass the limit")
    func recordFailureRespectsTheLimit() throws {
        var book = Self.book(holding: LedgerBook.maximumEntries - 1)
        let nearlyFull = book
        #expect(throws: ThrottleLedgerError.full(limit: LedgerBook.maximumEntries)) {
            var attempt = nearlyFull
            _ = try attempt.recordFailure(involving: [Self.ada, Self.grace], at: Self.start, policy: .standard)
        }
        let (states, changed) = try book.recordFailure(involving: [Self.ada], at: Self.start, policy: .standard)
        #expect(changed)
        #expect(states.map(\.consecutiveFailures) == [1])
    }

    // MARK: - Writing only what changed

    @Test("a success with nothing to clear changes nothing, so the file ledger writes nothing")
    func successWithNothingToClear() throws {
        var book = LedgerBook()
        #expect(try book.consume(step: 7, for: Self.adaCode))
        let before = book
        let changed = book.recordSuccess(Self.adaCode)
        #expect(!changed)
        #expect(book == before)
    }

    @Test("disabling keys that are all disabled already changes nothing")
    func disableTogetherWhenAllDisabled() throws {
        let policy = try ThrottlePolicy(threshold: 1_000, backoff: 1, ceiling: 2)
        var book = LedgerBook()
        for _ in 0..<2 { _ = try book.recordFailure(involving: [Self.ada, Self.adaCode], at: Self.start, policy: policy) }
        #expect(book.entries[Self.ada]?.disabled == true)
        #expect(book.entries[Self.adaCode]?.disabled == true)
        let (disabled, changed) = book.disableTogether([Self.ada, Self.adaCode], ceiling: policy.ceiling)
        #expect(disabled)
        #expect(!changed)
    }

    @Test("P13: disabling together reaches a key the ledger already has, not only new ones")
    func disableTogetherReachesExistingKeys() throws {
        let policy = try ThrottlePolicy(threshold: 1_000, backoff: 1, ceiling: 2)
        var book = LedgerBook()
        for _ in 0..<2 { _ = try book.recordFailure(involving: [Self.ada], at: Self.start, policy: policy) }
        _ = try book.recordFailure(involving: [Self.adaCode], at: Self.start, policy: policy)
        #expect(book.entries[Self.adaCode]?.disabled == false)

        let (disabled, changed) = book.disableTogether([Self.ada, Self.adaCode], ceiling: policy.ceiling)
        #expect(disabled)
        #expect(changed)
        #expect(book.entries[Self.adaCode]?.disabled == true)
    }
}

extension FileThrottleLedgerTests {

    /// A valid, empty ledger padded at the front to exactly `size` bytes. Padded at the front so
    /// that reading fewer bytes than are there loses the closing brace, not just whitespace.
    static func paddedLedger(size: Int) -> Data {
        let document = Data(#"{"entries":[],"version":1}"#.utf8)
        return Data(repeating: UInt8(ascii: " "), count: size - document.count) + document
    }

    @Test("a ledger of exactly the size limit is read whole; one byte over is refused")
    func sizeLimitIsInclusive() async throws {
        let directory = try ThrottleLedgerTests.directory()
        defer { ThrottleLedgerTests.remove(directory) }
        let url = directory.appendingPathComponent("throttle-ledger")

        try Self.paddedLedger(size: FileThrottleLedger.maximumBytes).write(to: url)
        #expect(chmod(url.path, 0o600) == 0)
        let ledger = try FileThrottleLedger(url: url)
        #expect(try await ledger.state(ThrottleLedgerTests.ada) == .clear)

        try Self.paddedLedger(size: FileThrottleLedger.maximumBytes + 1).write(to: url)
        #expect(chmod(url.path, 0o600) == 0)
        #expect(throws: FileThrottleLedger.Failure.malformed(path: url.path)) {
            try FileThrottleLedger(url: url)
        }
    }
}
