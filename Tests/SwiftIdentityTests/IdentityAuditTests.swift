import Crypto
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import Foundation
import SwiftDeterminism
import Testing
@testable import SwiftIdentity

/// The audit hook, which existed as a protocol nobody could supply.
///
/// `Resolution` already tells the service **what** happened — that is what superseded the
/// original audit design and why this protocol sat unreachable. What `Resolution` does not say
/// is **who**: `refused(.honeypot)` reports that a tripwire fired and not which one, and for a
/// credential known to have leaked that is the entire question.
@Suite("IdentityAudit")
struct IdentityAuditTests {

    /// Collects events so a test asserts on values rather than on a log.
    actor Recorder: IdentityAudit {
        private(set) var events: [IdentityEvent] = []
        func record(_ event: IdentityEvent) async { events.append(event) }
    }

    private static let moment = Date(timeIntervalSince1970: 1_700_000_000)

    private static func digest(_ secret: String) -> String {
        SHA256.hash(data: Data(secret.utf8)).map { Hex.byte($0) }.joined()
    }

    private static func store(_ recorder: Recorder) throws -> FileCredentialStore {
        let url = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("IdentityAuditTests-\(UUID().uuidString)", isDirectory: true)
            .standardized
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        #expect(chmod(url.path, 0o700) == 0)

        var generator = SplitMix64(seed: 0x5EED)
        let verifier = try PassphraseVerifier(
            for: Passphrase(subjectID: "ada", secret: "a long enough phrase"),
            using: &generator, rounds: PassphraseVerifier.roundFloor
        ).encoded

        let roster = """
            ada       person  active
            departed  person  revoked
            decoy     service honeypot
            """
        let verifiers = """
            ada       bearer      \(digest("ada-key"))       -
            ada       passphrase  \(verifier)                -
            departed  bearer      \(digest("departed-key"))  -
            decoy     bearer      \(digest("leaked-key"))    -
            ada       capability  \(digest("stale-token"))   2020-01-01T00:00:00Z
            """
        for (name, text) in [(FileCredentialStore.subjectsFile, roster),
                             (FileCredentialStore.verifiersFile, verifiers)] {
            let path = url.appendingPathComponent(name).path
            try Data(text.utf8).write(to: URL(fileURLWithPath: path))
            #expect(chmod(path, 0o600) == 0)
        }

        return try FileCredentialStore(
            directory: url.path, now: { moment },
            throttle: FailureThrottle(now: { moment }), audit: recorder
        )
    }

    // MARK: - The case this exists for

    @Test("a honeypot names the credential's subject, which the resolution never does")
    func honeypotNamesItsSubject() async throws {
        // The whole point. `refused(.honeypot)` says a tripwire fired; it does not say which,
        // and a deployment holding several leaked credentials needs to know which one somebody
        // found. That fact lives only inside the store.
        let recorder = Recorder()
        let store = try Self.store(recorder)

        #expect(await store.resolve(BearerKey("leaked-key")) == .refused(.honeypot))

        let events = await recorder.events
        #expect(events.count == 1)
        #expect(events.first?.outcome == .honeypot)
        #expect(events.first?.subjectID == "decoy")
        #expect(events.first?.credentialKind == BearerKey.kind)
        #expect(events.first?.at == Self.moment)
    }

    // MARK: - Every other outcome

    @Test("a verification is recorded, naming the subject it proved")
    func verified() async throws {
        let recorder = Recorder()
        _ = try await Self.store(recorder).resolve(BearerKey("ada-key"))
        let event = try #require(await recorder.events.first)
        #expect(event.outcome == .verified)
        #expect(event.subjectID == "ada")
    }

    @Test("a revoked subject is named, so a refusal can be told from a guess")
    func revoked() async throws {
        let recorder = Recorder()
        _ = try await Self.store(recorder).resolve(BearerKey("departed-key"))
        let event = try #require(await recorder.events.first)
        #expect(event.outcome == .revoked)
        #expect(event.subjectID == "departed")
    }

    @Test("an expired credential is named")
    func expired() async throws {
        let recorder = Recorder()
        _ = try await Self.store(recorder).resolve(CapabilityToken("stale-token"))
        let event = try #require(await recorder.events.first)
        #expect(event.outcome == .expired)
        #expect(event.subjectID == "ada")
    }

    @Test("an unrecognised credential names nobody, because nobody was identified")
    func unknown() async throws {
        // Not "" and not a guess at what the caller might have meant. Nobody was identified,
        // and a subject id here would be the store inventing one.
        let recorder = Recorder()
        _ = try await Self.store(recorder).resolve(BearerKey("never-issued"))
        let event = try #require(await recorder.events.first)
        #expect(event.outcome == .unknown)
        #expect(event.subjectID == nil)
    }

    @Test("a throttled attempt names the subject it was throttled for")
    func throttled() async throws {
        // The one refusal that happens *without* checking the secret, so it is also the one
        // where the subject is known from the attempt rather than from a match.
        let recorder = Recorder()
        let store = try Self.store(recorder)
        for _ in 0..<8 {
            _ = await store.resolve(Passphrase(subjectID: "ada", secret: "wrong"))
        }
        let throttled = await recorder.events.filter { $0.outcome == .throttled }
        #expect(!throttled.isEmpty, "repeated failure must eventually refuse unchecked")
        #expect(throttled.allSatisfy { $0.subjectID == "ada" })
        #expect(throttled.allSatisfy { $0.credentialKind == Passphrase.kind })
    }

    // MARK: - What it must never carry

    @Test("no event carries the presented secret, in any field")
    func neverTheSecret() async throws {
        let recorder = Recorder()
        let store = try Self.store(recorder)
        for credential: any Credential in [
            BearerKey("ada-key"), BearerKey("never-issued"), BearerKey("leaked-key"),
            Passphrase(subjectID: "ada", secret: "a long enough phrase"),
            CapabilityToken("stale-token"),
        ] {
            _ = await store.resolve(credential)
        }

        let described = await recorder.events.map { String(describing: $0) }.joined()
        for secret in ["ada-key", "never-issued", "leaked-key", "a long enough phrase",
                       "stale-token"] {
            #expect(!described.contains(secret), "the event described \(secret)")
        }
    }

    @Test("exactly one event per resolution, so a count means what it looks like")
    func oneEventEach() async throws {
        let recorder = Recorder()
        let store = try Self.store(recorder)
        for _ in 0..<4 { _ = await store.resolve(BearerKey("ada-key")) }
        #expect(await recorder.events.count == 4)
    }

    @Test("a store given no audit behaves exactly as before")
    func auditIsOptional() async throws {
        let url = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("IdentityAuditTests-\(UUID().uuidString)", isDirectory: true)
            .standardized
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        #expect(chmod(url.path, 0o700) == 0)
        defer { try? FileManager.default.removeItem(at: url) }
        for (name, text) in [(FileCredentialStore.subjectsFile, "ada person active"),
                             (FileCredentialStore.verifiersFile,
                              "ada bearer \(Self.digest("k")) -")] {
            let path = url.appendingPathComponent(name).path
            try Data(text.utf8).write(to: URL(fileURLWithPath: path))
            #expect(chmod(path, 0o600) == 0)
        }

        let store = try FileCredentialStore(directory: url.path)
        #expect(await store.resolve(BearerKey("k")) == .verified(
            try #require(store.subject(id: "ada"))
        ))
    }

    // MARK: - Sessions

    @Test("a session store records the same events, including a revocation mid-session")
    func sessions() async throws {
        let recorder = Recorder()
        let roster = Subject(id: "ada", kind: .person, status: .revoked)
        let sessions = SessionStore(
            subjects: { $0 == "ada" ? roster : nil }, now: { Self.moment }, audit: recorder
        )
        var generator = SplitMix64(seed: 0x5EED)
        let minted = await sessions.mint(for: "ada", lifetime: 3_600, using: &generator)

        #expect(await sessions.resolve(minted.token) == .refused(.revoked))
        let event = try #require(await recorder.events.first)
        #expect(event.outcome == .revoked)
        #expect(event.subjectID == "ada")
        #expect(event.credentialKind == SessionToken.kind)
    }
}
