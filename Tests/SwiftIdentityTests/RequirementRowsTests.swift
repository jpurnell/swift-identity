import Darwin
import Foundation
import SwiftDeterminism
import Testing
@testable import SwiftIdentity

/// The remaining 800-63B-4 rows: what's absent by design, and what forces a change.
@Suite("Requirement rows: P9, P10, P17")
struct RequirementRowsTests {

    // MARK: - P10, P9: absences

    @Test("P10: a stored passphrase has nowhere to keep a hint or a security answer")
    func noHints() throws {
        var generator = SplitMix64(seed: 1)
        let verifier = try PassphraseVerifier(
            for: Passphrase(subjectID: "ada", secret: "correct horse battery staple"),
            using: &generator, rounds: PassphraseVerifier.roundFloor
        )
        // Exactly the scheme, its cost, the salt and the digest. A field added here is a field
        // someone will one day put a hint in.
        let fields = Set(Mirror(reflecting: verifier).children.compactMap(\.label))
        #expect(fields == ["scheme", "parameters", "salt", "digest"])
        let passphraseFields = Set(Mirror(reflecting: Passphrase(subjectID: "a", secret: "b")).children.compactMap(\.label))
        #expect(passphraseFields == ["subjectID", "secret"])
    }

    @Test("P9: no NIST profile can require a periodic change: a policy has no age at all")
    func noPeriodicChange() {
        for policy in [PassphrasePolicy.nist80063B4, .fips, .owasp] {
            let fields = Mirror(reflecting: policy).children.compactMap(\.label).map { $0.lowercased() }
            #expect(!fields.contains { $0.contains("age") || $0.contains("expir") || $0.contains("rotat") },
                    "\(fields)")
        }
    }

    // MARK: - P9: a forced change

    static func directory(verifiers: String) throws -> String {
        let url = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("RequirementRows-\(UUID().uuidString)", isDirectory: true).standardized
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        #expect(chmod(url.path, 0o700) == 0)
        for (name, text) in [("subjects", "ada person active\n"), ("verifiers", verifiers)] {
            let path = url.appendingPathComponent(name).path
            try Data(text.utf8).write(to: URL(fileURLWithPath: path))
            #expect(chmod(path, 0o600) == 0)
        }
        return url.path
    }

    @Test("P9: on evidence of compromise, an expiry in the past forces a change, and a new passphrase ends it")
    func compromiseForcesAChange() async throws {
        var generator = SplitMix64(seed: 2)
        let old = try PassphraseVerifier(
            for: Passphrase(subjectID: "ada", secret: "correct horse battery staple"),
            using: &generator, rounds: PassphraseVerifier.roundFloor
        )
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        // Marking the line expired is how an administrator forces the change: the right
        // passphrase is refused from then on, so the subject has to be issued a new one.
        let marked = try Self.directory(verifiers: "ada passphrase \(old.encoded) 2026-10-01T00:00:00Z\n")
        let store = try FileCredentialStore(directory: marked, now: { now })
        #expect(await store.resolve(Passphrase(subjectID: "ada", secret: "correct horse battery staple")) == .refused(.expired))

        let new = try PassphraseVerifier(
            for: Passphrase(subjectID: "ada", secret: "a different passphrase now"),
            using: &generator, rounds: PassphraseVerifier.roundFloor
        )
        let reissued = try Self.directory(verifiers: "ada passphrase \(old.encoded) 2026-10-01T00:00:00Z\nada passphrase \(new.encoded) -\n")
        let after = try FileCredentialStore(directory: reissued, now: { now })
        #expect(await after.resolve(Passphrase(subjectID: "ada", secret: "a different passphrase now"))
            == .verified(Subject(id: "ada", kind: .person)))
        #expect(await after.resolve(Passphrase(subjectID: "ada", secret: "correct horse battery staple")) == .refused(.expired))
    }

    // MARK: - P17: the same work either way

    /// PBKDF2, counting its derivations.
    // Justification: `value` is read and written only while holding `lock`, so it is never reached concurrently.
    final class Counter: @unchecked Sendable {
        private let lock = NSLock()
        private var value = 0
        var count: Int {
            lock.lock(); defer { lock.unlock() }
            return value
        }
        func increment() {
            lock.lock(); defer { lock.unlock() }
            value += 1
        }
    }

    struct Counting: PassphraseScheme {
        let counter: Counter
        let identifier = "test-counting-c1"
        let canonicalization: PassphraseCanonicalization? = .c1
        func isValid(parameters: String) -> Bool { PBKDF2SHA256C1().isValid(parameters: parameters) }
        func derive(_ material: [UInt8], parameters: String, salt: [UInt8]) throws -> [UInt8] {
            counter.increment()
            return try PBKDF2SHA256C1().derive(material, parameters: parameters, salt: salt)
        }
    }

    @Test("P17: an unknown subject costs one derivation, like a known one: existence isn't timed out")
    func unknownSubjectsDoTheWork() async throws {
        let counter = Counter()
        let schemes = PassphraseSchemes([Counting(counter: counter)], writing: Counting(counter: counter))
        var generator = SplitMix64(seed: 3)
        let verifier = try PassphraseVerifier(
            for: Passphrase(subjectID: "ada", secret: "correct horse battery staple"),
            using: &generator, parameters: "\(PassphraseVerifier.roundFloor)", schemes: schemes
        )
        let directory = try Self.directory(verifiers: "ada passphrase \(verifier.encoded) -\n")
        let store = try FileCredentialStore(directory: directory, schemes: schemes)
        let atStart = counter.count

        #expect(await store.resolve(Passphrase(subjectID: "ada", secret: "wrong")) == .refused(.unknown))
        let known = counter.count - atStart
        #expect(await store.resolve(Passphrase(subjectID: "nobody", secret: "wrong")) == .refused(.unknown))
        let unknown = counter.count - atStart - known
        #expect(known == 1)
        #expect(unknown == 1)
    }

    @Test("the store reads digests under the deployment's schemes, argon2id-c1 included")
    func storeTakesSchemes() async throws {
        var generator = SplitMix64(seed: 4)
        let policy = PassphrasePolicy.owasp
        let verifier = try PassphraseVerifier(
            for: Passphrase(subjectID: "ada", secret: "correct horse battery staple"),
            using: &generator, parameters: "m=64,t=1,p=1", schemes: policy.schemes
        )
        let directory = try Self.directory(verifiers: "ada passphrase \(verifier.encoded) -\n")
        #expect(throws: FileCredentialStore.Failure.malformedPassphraseVerifier(line: 1)) {
            try FileCredentialStore(directory: directory)
        }
        let store = try FileCredentialStore(directory: directory, schemes: policy.schemes)
        #expect(await store.resolve(Passphrase(subjectID: "ada", secret: "correct horse battery staple"))
            == .verified(Subject(id: "ada", kind: .person)))
    }
}
