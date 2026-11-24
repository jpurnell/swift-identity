import Foundation
import SwiftDeterminism
import Testing
@testable import SwiftIdentity

/// `IdentityDirectory.issuePassphrase`: the server makes the secret, keeps only its verifier, and a new one is a rebinding.
@Suite("IdentityDirectory.issuePassphrase")
struct IssuePassphraseTests {
    private typealias Support = AdministrationTestSupport
    private let moment = Date(timeIntervalSince1970: 1_800_000_000)
    /// The cost the tests pay: the floor, so a hash takes what the standard requires and no more.
    private let rounds = PassphraseVerifier.roundFloor

    private func store(_ path: String, throttle: FailureThrottle? = nil) throws -> FileCredentialStore {
        let at = moment
        return try FileCredentialStore(directory: path, now: { at }, throttle: throttle)
    }

    private func resolves(_ path: String, _ subject: String, _ secret: String, throttle: FailureThrottle? = nil) async throws -> Bool {
        if case .verified(let found) = await (try store(path, throttle: throttle)).resolve(Passphrase(subjectID: subject, secret: secret)) {
            return found.id == subject
        }
        return false
    }

    // MARK: A fresh directory

    @Test("On a fresh directory it makes the owner-only directory and files, the subject and a passphrase that verifies as that subject, and no bearer key")
    func freshDirectory() async throws {
        let path = try Support.absentDirectory()
        defer { Support.remove((path as NSString).deletingLastPathComponent) }
        var generator = SplitMix64(seed: 1)
        let issued = try IdentityDirectory(path: path).issuePassphrase(
            for: SubjectSpec(id: "owner", kind: .person), rounds: rounds, using: &generator)
        #expect(Support.mode(of: path) == 0o700)
        #expect(Support.mode(of: path + "/subjects") == 0o600)
        #expect(Support.mode(of: path + "/verifiers") == 0o600)
        #expect(try await resolves(path, "owner", issued.secret))
        let verifiers = try Support.read(path + "/verifiers")
        #expect(verifiers.contains("owner passphrase "))
        #expect(!verifiers.contains(" bearer "), "a passphrase subject is not given a bearer key it never asked for")
    }

    @Test("The secret is in no file, only its verifier, and the verifier is slow-hashed under the cost asked for")
    func secretNotStored() throws {
        let path = try Support.absentDirectory()
        defer { Support.remove((path as NSString).deletingLastPathComponent) }
        var generator = SplitMix64(seed: 2)
        let issued = try IdentityDirectory(path: path).issuePassphrase(
            for: SubjectSpec(id: "owner", kind: .person), rounds: rounds, using: &generator)
        for name in ["subjects", "verifiers"] {
            #expect(!(try Support.read(path + "/" + name)).contains(issued.secret))
        }
        #expect(try Support.read(path + "/verifiers").contains("$\(rounds)$"))
    }

    // MARK: The secret

    @Test("A secret is 256 bits as base64url, differs each time, and is the same for the same generator")
    func secretShape() throws {
        func issue(seed: UInt64) throws -> String {
            let path = try Support.absentDirectory()
            defer { Support.remove((path as NSString).deletingLastPathComponent) }
            var generator = SplitMix64(seed: seed)
            return try IdentityDirectory(path: path).issuePassphrase(
                for: SubjectSpec(id: "owner", kind: .person), rounds: rounds, using: &generator).secret
        }
        let first = try issue(seed: 7)
        #expect(first.utf8.count == 43)
        #expect(first.utf8.allSatisfy { ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x41 && $0 <= 0x5A) || ($0 >= 0x61 && $0 <= 0x7A) || $0 == 0x2D || $0 == 0x5F })
        #expect(try issue(seed: 7) == first)
        #expect(try issue(seed: 8) != first)
    }

    @Test("The issued value never prints the secret, in either description or by reflection")
    func redacted() throws {
        let path = try Support.absentDirectory()
        defer { Support.remove((path as NSString).deletingLastPathComponent) }
        var generator = SplitMix64(seed: 3)
        let issued = try IdentityDirectory(path: path).issuePassphrase(
            for: SubjectSpec(id: "owner", kind: .person), rounds: rounds, using: &generator)
        for text in [issued.description, issued.debugDescription, String(reflecting: issued), "\(issued)"] {
            #expect(!text.contains(issued.secret))
            #expect(text.contains("redacted"))
        }
    }

    // MARK: An existing directory

    @Test("Rotating replaces the subject's passphrase: the old secret is refused, the new one verifies, and every other line is untouched")
    func rotation() async throws {
        let path = try Support.absentDirectory()
        defer { Support.remove((path as NSString).deletingLastPathComponent) }
        let directory = IdentityDirectory(path: path)
        var generator = SplitMix64(seed: 4)
        let key = try directory.create(first: SubjectSpec(id: "spinner", kind: .service), using: &generator)
        let first = try directory.issuePassphrase(for: SubjectSpec(id: "owner", kind: .person), rounds: rounds, using: &generator)
        let before = try Support.read(path + "/verifiers")
        let others = before.split(whereSeparator: \.isNewline).filter { !$0.hasPrefix("owner passphrase ") }.map(String.init)

        let second = try directory.issuePassphrase(for: SubjectSpec(id: "owner", kind: .person), rounds: rounds, using: &generator)
        #expect(first.secret != second.secret)
        #expect(try await resolves(path, "owner", second.secret))
        #expect(!(try await resolves(path, "owner", first.secret)), "the old secret is gone")
        let after = try Support.read(path + "/verifiers")
        #expect(after.split(whereSeparator: \.isNewline).filter { !$0.hasPrefix("owner passphrase ") }.map(String.init) == others)
        #expect(after.components(separatedBy: "owner passphrase ").count == 2, "one passphrase line for the owner, not two")
        let bearer = await (try store(path)).resolve(BearerKey(key.key))
        #expect(bearer == .verified(Subject(id: "spinner", kind: .service, status: .active, attributes: [:])), "the bearer key still works")
    }

    @Test("A new subject in an existing directory is added with its passphrase; a name that is not a name is refused and nothing is written")
    func newSubjectAndBadName() async throws {
        let path = try Support.absentDirectory()
        defer { Support.remove((path as NSString).deletingLastPathComponent) }
        let directory = IdentityDirectory(path: path)
        var generator = SplitMix64(seed: 5)
        _ = try directory.create(first: SubjectSpec(id: "spinner", kind: .service), using: &generator)
        let issued = try directory.issuePassphrase(for: SubjectSpec(id: "owner", kind: .person), rounds: rounds, using: &generator)
        #expect(try await resolves(path, "owner", issued.secret))

        let snapshot = (try Support.read(path + "/subjects"), try Support.read(path + "/verifiers"))
        #expect(throws: AdministrationFailure.invalidName("bad name")) {
            _ = try directory.issuePassphrase(for: SubjectSpec(id: "bad name", kind: .person), rounds: rounds, using: &generator)
        }
        #expect(try Support.read(path + "/subjects") == snapshot.0 && Support.read(path + "/verifiers") == snapshot.1)
    }

    @Test("A cost below the standard's floor is refused, and nothing is written")
    func costFloor() throws {
        let path = try Support.absentDirectory()
        defer { Support.remove((path as NSString).deletingLastPathComponent) }
        var generator = SplitMix64(seed: 6)
        #expect(throws: AdministrationFailure.roundsBelowFloor(PassphraseVerifier.roundFloor)) {
            _ = try IdentityDirectory(path: path).issuePassphrase(
                for: SubjectSpec(id: "owner", kind: .person), rounds: PassphraseVerifier.roundFloor - 1, using: &generator)
        }
        #expect(!FileManager.default.fileExists(atPath: path + "/verifiers"))
    }

    @Test("A revoked subject is not revived by a new passphrase: it stays revoked and its secret is refused")
    func revokedStaysRevoked() async throws {
        let path = try Support.absentDirectory()
        defer { Support.remove((path as NSString).deletingLastPathComponent) }
        let directory = IdentityDirectory(path: path)
        var generator = SplitMix64(seed: 10)
        _ = try directory.issuePassphrase(for: SubjectSpec(id: "owner", kind: .person), rounds: rounds, using: &generator)
        try directory.revoke(subject: "owner")
        let again = try directory.issuePassphrase(for: SubjectSpec(id: "owner", kind: .person), rounds: rounds, using: &generator)
        #expect(!(try await resolves(path, "owner", again.secret)))
    }

    // MARK: The throttle, and a running store

    @Test("A new passphrase lifts the ceiling: disabled after the failures, enabled again by issuing")
    func issuingRebinds() async throws {
        let path = try Support.absentDirectory()
        defer { Support.remove((path as NSString).deletingLastPathComponent) }
        let directory = IdentityDirectory(path: path)
        var generator = SplitMix64(seed: 11)
        let first = try directory.issuePassphrase(for: SubjectSpec(id: "owner", kind: .person), rounds: rounds, using: &generator)
        let at = moment
        let throttle = FailureThrottle(policy: try ThrottlePolicy(threshold: 1, backoff: 1, ceiling: 2), now: { at })
        for guess in ["wrong-one", "wrong-two"] { _ = try await resolves(path, "owner", guess, throttle: throttle) }
        #expect(!(try await resolves(path, "owner", first.secret, throttle: throttle)), "disabled at the ceiling, even for the right secret")

        let second = try directory.issuePassphrase(for: SubjectSpec(id: "owner", kind: .person), rounds: rounds, using: &generator)
        #expect(try await resolves(path, "owner", second.secret, throttle: throttle), "a new passphrase is a new binding, and the count starts again")
    }

    @Test("A running reloading store picks the rotation up")
    func reloadingStoreSeesIt() async throws {
        let path = try Support.absentDirectory()
        defer { Support.remove((path as NSString).deletingLastPathComponent) }
        let directory = IdentityDirectory(path: path)
        var generator = SplitMix64(seed: 12)
        let first = try directory.issuePassphrase(for: SubjectSpec(id: "owner", kind: .person), rounds: rounds, using: &generator)
        let clock = Support.Clock()
        let running = try ReloadingCredentialStore(directory: path, interval: 1, now: { clock.now })
        guard case .verified = await running.resolve(Passphrase(subjectID: "owner", secret: first.secret)) else {
            Issue.record("the first secret did not verify")
            return
        }
        let second = try directory.issuePassphrase(for: SubjectSpec(id: "owner", kind: .person), rounds: rounds, using: &generator)
        clock.advance(5)
        guard case .verified = await running.resolve(Passphrase(subjectID: "owner", secret: second.secret)) else {
            Issue.record("the running store did not see the new secret")
            return
        }
        #expect(await running.resolve(Passphrase(subjectID: "owner", secret: first.secret)) != .verified(Subject(id: "owner", kind: .person, status: .active, attributes: [:])))
    }
}
