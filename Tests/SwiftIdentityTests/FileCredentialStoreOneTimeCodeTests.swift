#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import Foundation
import SwiftDeterminism
import Testing
@testable import SwiftIdentity

/// One-time codes in the file store: each accepted once, counted before checked, and disabled at
/// the ceiling like a passphrase.
@Suite("FileCredentialStore — one-time codes")
struct FileCredentialStoreOneTimeCodeTests {

    /// A synthetic clock: a fixed origin the test advances, never the wall clock.
    // Justification: every access to `current` is serialised by `lock`, so the mutable state is never reached concurrently.
    final class Clock: @unchecked Sendable {
        private let lock = NSLock()
        private var current = Date(timeIntervalSince1970: 1_800_000_000)
        var instant: Date {
            lock.lock(); defer { lock.unlock() }
            return current
        }
        func advance(_ interval: TimeInterval) {
            lock.lock(); defer { lock.unlock() }
            current += interval
        }
    }

    /// Records audit events.
    actor Recorder: IdentityAudit {
        var events: [IdentityEvent] = []
        func record(_ event: IdentityEvent) async { events.append(event) }
    }

    struct Fixture {
        let directory: String
        let sealingKey: SealingKey
        let ada: OneTimeCodeVerifier
        let grace: OneTimeCodeVerifier
        let clock: Clock

        /// The code `verifier`'s app shows `offset` steps from now.
        func code(_ verifier: OneTimeCodeVerifier, offset: Int64 = 0) throws -> String {
            let step = try #require(verifier.parameters.step(at: clock.instant))
            return TOTP.code(key: try verifier.key(sealingKey: sealingKey), step: step + offset, parameters: verifier.parameters)
        }
    }

    static func write(_ text: String, to path: String) throws {
        try Data(text.utf8).write(to: URL(fileURLWithPath: path))
        #expect(chmod(path, 0o600) == 0)
    }

    static func fixture(seed: UInt64, extraLines: String = "") throws -> Fixture {
        let url = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("OneTimeCodeStore-\(UUID().uuidString)", isDirectory: true).standardized
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        #expect(chmod(url.path, 0o700) == 0)
        let directory = url.path

        var generator = SplitMix64(seed: seed)
        let keyURL = url.appendingPathComponent("sealing.key")
        try SealingKey.create(at: keyURL, using: &generator)
        let sealingKey = try SealingKey(contentsOf: keyURL)
        let ada = try OneTimeCodeVerifier(for: "ada", using: &generator, sealingKey: sealingKey)
        let grace = try OneTimeCodeVerifier(for: "grace", using: &generator, sealingKey: sealingKey)
        let passphrase = try PassphraseVerifier(
            for: Passphrase(subjectID: "ada", secret: "correct horse battery staple"),
            using: &generator, rounds: PassphraseVerifier.roundFloor
        )

        try write("""
            ada    person  active
            grace  person  active
            """, to: (directory as NSString).appendingPathComponent("subjects"))
        try write("""
            ada    passphrase  \(passphrase.encoded)  -
            ada    totp        \(ada.encoded)         -
            grace  totp        \(grace.encoded)       -
            \(extraLines)
            """, to: (directory as NSString).appendingPathComponent("verifiers"))
        return Fixture(directory: directory, sealingKey: sealingKey, ada: ada, grace: grace, clock: Clock())
    }

    static func throttle(_ fixture: Fixture) throws -> FailureThrottle {
        let clock = fixture.clock
        // A threshold past the ceiling, so backoff never fires first and the ceiling is what's
        // measured.
        return FailureThrottle(
            policy: try ThrottlePolicy(threshold: 1_000, backoff: 1, ceiling: 100), now: { clock.instant }
        )
    }

    static func store(_ fixture: Fixture, audit: Recorder? = nil, throttle: FailureThrottle? = nil) throws -> FileCredentialStore {
        let clock = fixture.clock
        let throttle = try throttle ?? Self.throttle(fixture)
        return try FileCredentialStore(
            directory: fixture.directory, now: { clock.instant }, throttle: throttle, audit: audit,
            sealingKey: fixture.sealingKey
        )
    }

    // MARK: - Accepted once

    @Test("the current code proves the subject")
    func currentCodeVerifies() async throws {
        let fixture = try Self.fixture(seed: 1)
        let store = try Self.store(fixture)
        let code = try fixture.code(fixture.ada)
        #expect(await store.resolve(OneTimeCode(subjectID: "ada", code: code)) == .verified(Subject(id: "ada", kind: .person)))
    }

    @Test("O6: a code is accepted once, however many times it's presented while valid")
    func acceptedOnce() async throws {
        let fixture = try Self.fixture(seed: 2)
        let store = try Self.store(fixture)
        let presented = OneTimeCode(subjectID: "ada", code: try fixture.code(fixture.ada))
        #expect(await store.resolve(presented) == .verified(Subject(id: "ada", kind: .person)))
        #expect(await store.resolve(presented) == .refused(.unknown))
        fixture.clock.advance(10)
        #expect(await store.resolve(presented) == .refused(.unknown))
    }

    @Test("O6: once a later code is used, an earlier one is refused even inside the window")
    func earlierAfterLaterIsRefused() async throws {
        let fixture = try Self.fixture(seed: 3)
        let store = try Self.store(fixture)
        let later = OneTimeCode(subjectID: "ada", code: try fixture.code(fixture.ada, offset: 1))
        let earlier = OneTimeCode(subjectID: "ada", code: try fixture.code(fixture.ada, offset: 0))
        #expect(await store.resolve(later) == .verified(Subject(id: "ada", kind: .person)))
        #expect(await store.resolve(earlier) == .refused(.unknown))
    }

    @Test("one subject's code doesn't prove another")
    func codesAreBoundToTheirSubject() async throws {
        let fixture = try Self.fixture(seed: 4)
        let store = try Self.store(fixture)
        let gracesCode = try fixture.code(fixture.grace)
        #expect(await store.resolve(OneTimeCode(subjectID: "ada", code: gracesCode)) == .refused(.unknown))
    }

    // MARK: - The ceiling

    @Test("O8, P13: 100 wrong codes disable the app, and then the right code is refused")
    func ceilingDisables() async throws {
        let fixture = try Self.fixture(seed: 5)
        let store = try Self.store(fixture)
        let right = try fixture.code(fixture.ada)
        let wrong = right == "000000" ? "000001" : "000000"
        for _ in 0..<100 { _ = await store.resolve(OneTimeCode(subjectID: "ada", code: wrong)) }
        #expect(await store.resolve(OneTimeCode(subjectID: "ada", code: right)) == .refused(.throttled))
        // The passphrase is a different authenticator, and still works.
        #expect(await store.resolve(Passphrase(subjectID: "ada", secret: "correct horse battery staple"))
            == .verified(Subject(id: "ada", kind: .person)))
    }

    // MARK: - Startup

    @Test("one-time-code lines without a sealing key are refused at startup")
    func needsASealingKey() throws {
        let fixture = try Self.fixture(seed: 6)
        #expect(throws: FileCredentialStore.Failure.sealingKeyRequired) {
            try FileCredentialStore(directory: fixture.directory, throttle: FailureThrottle())
        }
    }

    @Test("O6, O8: one-time-code lines without a throttle are refused at startup")
    func needsAThrottle() throws {
        let fixture = try Self.fixture(seed: 7)
        #expect(throws: FileCredentialStore.Failure.throttleRequired) {
            try FileCredentialStore(directory: fixture.directory, sealingKey: fixture.sealingKey)
        }
    }

    @Test("O3: a sealing key that doesn't open a line is refused at startup, naming the line")
    func wrongSealingKeyIsFatal() throws {
        let fixture = try Self.fixture(seed: 8)
        let other = try Self.fixture(seed: 9)
        #expect(throws: FileCredentialStore.Failure.sealingKeyMismatch(line: 2)) {
            try FileCredentialStore(directory: fixture.directory, throttle: FailureThrottle(), sealingKey: other.sealingKey)
        }
    }

    @Test("a malformed one-time-code line is refused at startup")
    func malformedLineIsFatal() throws {
        let fixture = try Self.fixture(seed: 10, extraLines: "ada    totp        totp-sha1-6-30$!!!   -")
        #expect(throws: FileCredentialStore.Failure.malformedOneTimeCodeVerifier(line: 4)) {
            try FileCredentialStore(directory: fixture.directory, throttle: FailureThrottle(), sealingKey: fixture.sealingKey)
        }
    }

    // MARK: - Algorithms

    @Test("the store reports what it verified with, and the audit records it")
    func algorithmsAreReported() async throws {
        let fixture = try Self.fixture(seed: 11)
        let recorder = Recorder()
        let store = try Self.store(fixture, audit: recorder)

        let (byCode, codeAlgorithm) = await store.resolveVerifying(OneTimeCode(subjectID: "ada", code: try fixture.code(fixture.ada)))
        #expect(byCode == .verified(Subject(id: "ada", kind: .person)))
        #expect(codeAlgorithm == "totp-sha1-6-30")

        let (byPassphrase, passphraseAlgorithm) = await store.resolveVerifying(
            Passphrase(subjectID: "ada", secret: "correct horse battery staple"))
        #expect(byPassphrase == .verified(Subject(id: "ada", kind: .person)))
        #expect(passphraseAlgorithm == "pbkdf2-sha256-c1")

        let (_, refusedAlgorithm) = await store.resolveVerifying(Passphrase(subjectID: "ada", secret: "wrong"))
        #expect(refusedAlgorithm == nil)

        let algorithms = await recorder.events.map(\.algorithm)
        #expect(algorithms == ["totp-sha1-6-30", "pbkdf2-sha256-c1", nil])
    }

    // MARK: - Several authenticators at the ceiling

    static let right = Passphrase(subjectID: "ada", secret: "correct horse battery staple")
    static let wrong = Passphrase(subjectID: "ada", secret: "not the passphrase")

    @Test("P13: an attempt that disables one authenticator disables every one presented with it")
    func disabledTogether() async throws {
        let fixture = try Self.fixture(seed: 13)
        let throttle = try Self.throttle(fixture)
        let store = try Self.store(fixture, throttle: throttle)
        let authenticator = Authenticator(stores: [store], audit: nil, now: { fixture.clock.instant }, throttle: throttle)

        for _ in 0..<99 { _ = await store.resolve(Self.wrong) }
        // The 100th passphrase failure arrives with a code, the right one even: both go.
        let result = await authenticator.authenticate([Self.wrong, OneTimeCode(subjectID: "ada", code: try fixture.code(fixture.ada))])
        #expect(result == .refused(.unknown))

        fixture.clock.advance(60)
        #expect(await store.resolve(Self.right) == .refused(.throttled))
        #expect(await store.resolve(OneTimeCode(subjectID: "ada", code: try fixture.code(fixture.ada))) == .refused(.throttled))
    }

    @Test("an authenticator not presented in that attempt isn't disabled with it")
    func onlyThosePresented() async throws {
        let fixture = try Self.fixture(seed: 14)
        let throttle = try Self.throttle(fixture)
        let store = try Self.store(fixture, throttle: throttle)
        let authenticator = Authenticator(stores: [store], audit: nil, now: { fixture.clock.instant }, throttle: throttle)

        for _ in 0..<99 { _ = await store.resolve(Self.wrong) }
        _ = await authenticator.authenticate([Self.wrong])
        #expect(await store.resolve(Self.right) == .refused(.throttled))
        #expect(await store.resolve(OneTimeCode(subjectID: "ada", code: try fixture.code(fixture.ada)))
            == .verified(Subject(id: "ada", kind: .person)))
    }

    @Test("every credential in a set is checked, so each is counted, before the set is refused")
    func everyCredentialIsCounted() async throws {
        let fixture = try Self.fixture(seed: 15)
        let throttle = try Self.throttle(fixture)
        let store = try Self.store(fixture, throttle: throttle)
        let authenticator = Authenticator(stores: [store], audit: nil, now: { fixture.clock.instant }, throttle: throttle)
        let wrongCode = OneTimeCode(subjectID: "ada", code: (try fixture.code(fixture.ada)) == "000000" ? "000001" : "000000")

        _ = await authenticator.authenticate([Self.wrong, wrongCode])
        let codeKey = try #require(store.throttleKey(for: wrongCode))
        let passphraseKey = try #require(store.throttleKey(for: Self.wrong))
        #expect(try await throttle.state(codeKey).consecutiveFailures == 1)
        #expect(try await throttle.state(passphraseKey).consecutiveFailures == 1)
    }

    // MARK: - End to end

    @Test("a passphrase and a code, through the Authenticator, are multi-factor")
    func passphrasePlusCodeIsMultiFactor() async throws {
        let fixture = try Self.fixture(seed: 12)
        let store = try Self.store(fixture)
        let authenticator = Authenticator(stores: [store], audit: nil, now: { fixture.clock.instant })
        let authentication = await authenticator.authentication(for: [
            Passphrase(subjectID: "ada", secret: "correct horse battery staple"),
            OneTimeCode(subjectID: "ada", code: try fixture.code(fixture.ada)),
        ])
        #expect(authentication?.assurance == .multiFactor)
        #expect(authentication?.factors.map(\.algorithm) == ["pbkdf2-sha256-c1", "totp-sha1-6-30"])
    }
}
