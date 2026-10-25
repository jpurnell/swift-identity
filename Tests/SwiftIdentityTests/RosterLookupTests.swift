#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import Foundation
import SwiftDeterminism
import Testing
@testable import SwiftIdentity

/// Looking a subject up by id — the shape ``SessionStore`` asks for in its initialiser.
///
/// Written because 0.2.0 shipped a `SessionStore` whose `subjects:` closure the bundled store
/// could not supply: the roster was private and nothing read it by id. A package that vends
/// both halves of a seam and cannot join them has not finished the seam.
@Suite("Roster lookup")
struct RosterLookupTests {

    private static func directory() throws -> String {
        let url = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("RosterLookupTests-\(UUID().uuidString)", isDirectory: true)
            .standardized
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        #expect(chmod(url.path, 0o700) == 0)
        return url.path
    }

    private static func store(_ directory: String) throws -> FileCredentialStore {
        let roster = """
            ada        person  active   tier=parent
            bridge     service active
            departed   person  revoked
            decoy      service honeypot
            """
        // Written at 0600 defeating the umask: the store refuses a world-readable roster, and
        // it is right to — a fixture that trips that check is the fixture's defect.
        for (name, text) in [(FileCredentialStore.subjectsFile, roster),
                             (FileCredentialStore.verifiersFile, "")] {
            let path = directory + "/" + name
            try Data(text.utf8).write(to: URL(fileURLWithPath: path))
            #expect(chmod(path, 0o600) == 0)
        }
        return try FileCredentialStore(directory: directory)
    }

    @Test("a roster subject is found by id, with its attributes")
    func findsSubject() throws {
        let path = try Self.directory()
        defer { try? FileManager.default.removeItem(at: URL(fileURLWithPath: path)) }
        let subject = try #require(try Self.store(path).subject(id: "ada"))

        #expect(subject.id == "ada")
        #expect(subject.kind == .person)
        #expect(subject.status == .active)
        #expect(subject.attributes["tier"] == "parent")
    }

    @Test("an id nobody has is nobody")
    func unknownSubject() throws {
        let path = try Self.directory()
        defer { try? FileManager.default.removeItem(at: URL(fileURLWithPath: path)) }
        #expect(try Self.store(path).subject(id: "nobody") == nil)
    }

    @Test("a revoked or honeypot subject is returned, carrying its status", arguments: [
        ("departed", Subject.Status.revoked), ("decoy", Subject.Status.honeypot),
    ])
    func statusIsReported(id: String, expected: Subject.Status) throws {
        // Returned rather than hidden, deliberately. `SessionStore` reads the status on every
        // resolution to end a live session; hiding the subject here would make a revocation
        // indistinguishable from a deleted roster line, and the session would be refused for
        // the wrong reason — or, worse, some future caller would read `nil` as "no objection".
        let path = try Self.directory()
        defer { try? FileManager.default.removeItem(at: URL(fileURLWithPath: path)) }
        let subject = try #require(try Self.store(path).subject(id: id))
        #expect(subject.status == expected)
    }

    @Test("a live session dies when the roster revokes its subject")
    func sessionStoreCanBeFedFromTheRoster() async throws {
        // The join this lookup exists for, asserted end to end rather than by inspection.
        let path = try Self.directory()
        defer { try? FileManager.default.removeItem(at: URL(fileURLWithPath: path)) }
        let store = try Self.store(path)

        let live = SessionStore(subjects: { store.subject(id: $0) })
        var generator = SplitMix64(seed: 0x5E5510)
        let minted = await live.mint(for: "ada", lifetime: 3_600, using: &generator)
        #expect(await live.resolve(minted.token) == .verified(try #require(store.subject(id: "ada"))))

        let revokedSession = await live.mint(for: "departed", lifetime: 3_600, using: &generator)
        #expect(await live.resolve(revokedSession.token) == .refused(.revoked))
    }
}

/// What a roster line is allowed to contain.
///
/// Written after a consumer lost a security-relevant attribute to a space. `vault.tier=parent
/// vault.scopes=19-coprock` parsed as three fields plus a fourth, and only the fourth was read
/// — so the subject silently authorised more than the line said. No error, no log, and a test
/// that happened not to cover the scope would never have found it.
@Suite("Roster line shape")
struct RosterLineTests {

    private static func store(_ roster: String) throws -> Result<FileCredentialStore, any Error> {
        let url = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("RosterLineTests-\(UUID().uuidString)", isDirectory: true)
            .standardized
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        #expect(chmod(url.path, 0o700) == 0)
        defer { try? FileManager.default.removeItem(at: url) }

        for (name, text) in [(FileCredentialStore.subjectsFile, roster),
                             (FileCredentialStore.verifiersFile, "")] {
            let path = url.appendingPathComponent(name).path
            try Data(text.utf8).write(to: URL(fileURLWithPath: path))
            #expect(chmod(path, 0o600) == 0)
        }
        return Result { try FileCredentialStore(directory: url.path) }
    }

    @Test("a line with a field nobody reads is refused at startup")
    func extraFieldIsFatal() throws {
        // Attributes are one comma-separated field. A space makes a fifth field, and the old
        // parser dropped it — which is the failure mode this package refuses everywhere else:
        // a setting that is written down, not applied, and does not say so.
        let result = try Self.store("ada person active tier=parent scopes=coprock")
        guard case .failure(let error) = result else {
            Issue.record("a fifth field must not be accepted")
            return
        }
        #expect(error as? FileCredentialStore.Failure == .malformed(path: "", line: 1)
            || String(describing: error).contains("malformed"))
    }

    @Test("the documented shape still parses, with several attributes")
    func commaSeparatedAttributesParse() throws {
        let result = try Self.store("ada person active tier=parent,scopes=coprock,site=north")
        guard case .success(let store) = result else {
            Issue.record("the documented shape must parse: \(result)")
            return
        }
        let subject = try #require(store.subject(id: "ada"))
        #expect(subject.attributes["tier"] == "parent")
        #expect(subject.attributes["scopes"] == "coprock")
        #expect(subject.attributes["site"] == "north")
    }

    @Test("a line with no attributes at all still parses")
    func noAttributes() throws {
        guard case .success(let store) = try Self.store("bridge service active") else {
            Issue.record("three fields is a complete line")
            return
        }
        #expect(store.subject(id: "bridge")?.attributes.isEmpty == true)
    }
}

/// What an attribute field is allowed to contain.
///
/// The second silent-drop found in one day, and the same shape as the first: attributes are
/// comma-separated pairs, so `scopes=a,b` parses as `scopes=a` plus a chunk with no `=` — and
/// the old parser skipped that chunk without a word. The list was truncated, the roster read
/// correctly to a human, and nothing said otherwise.
@Suite("Roster attributes")
struct RosterAttributeTests {

    private static func store(_ roster: String) throws -> Result<FileCredentialStore, any Error> {
        let url = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("RosterAttributeTests-\(UUID().uuidString)", isDirectory: true)
            .standardized
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        #expect(chmod(url.path, 0o700) == 0)
        defer { try? FileManager.default.removeItem(at: url) }

        for (name, text) in [(FileCredentialStore.subjectsFile, roster),
                             (FileCredentialStore.verifiersFile, "")] {
            let path = url.appendingPathComponent(name).path
            try Data(text.utf8).write(to: URL(fileURLWithPath: path))
            #expect(chmod(path, 0o600) == 0)
        }
        return Result { try FileCredentialStore(directory: url.path) }
    }

    @Test("an attribute chunk with no equals sign is refused at startup")
    func chunkWithoutEqualsIsFatal() throws {
        // `scopes=a,b` is the natural way to write a list and it cannot mean that here: the
        // comma already separates pairs. Truncating it in silence is the failure this refuses.
        let result = try Self.store("ada person active scopes=a,b")
        guard case .failure(let error) = result else {
            Issue.record("a chunk with no '=' must not be accepted")
            return
        }
        // Located, so the operator is told which line rather than that something somewhere is
        // wrong in a file they may have just added ten people to.
        #expect(error as? FileCredentialStore.Failure == .malformed(path: "", line: 1)
            || String(describing: error).contains("line: 1"))
    }

    @Test("an empty attribute chunk is refused too")
    func emptyChunkIsFatal() throws {
        for roster in ["ada person active tier=parent,", "ada person active ,tier=parent",
                       "ada person active tier=parent,,site=north"] {
            let refused: Bool
            if case .failure = try Self.store(roster) { refused = true } else { refused = false }
            #expect(refused, "a trailing or doubled comma must not be accepted: \(roster)")
        }
    }

    @Test("an attribute with an empty value is allowed, because absent and empty differ")
    func emptyValueIsAllowed() throws {
        // `tier=` says "this key is set to nothing", which is a claim a consumer may want to
        // distinguish from the key being missing. It is well-formed; it is just empty.
        guard case .success(let store) = try Self.store("ada person active tier=") else {
            Issue.record("an empty value is a well-formed pair")
            return
        }
        #expect(store.subject(id: "ada")?.attributes["tier"] == "")
    }

    @Test("well-formed attributes still parse, including several of them")
    func wellFormedStillParses() throws {
        guard case .success(let store) =
            try Self.store("ada person active tier=parent,site=north,scopes=a|b") else {
            Issue.record("the documented shape must parse")
            return
        }
        let subject = try #require(store.subject(id: "ada"))
        #expect(subject.attributes["tier"] == "parent")
        #expect(subject.attributes["site"] == "north")
        #expect(subject.attributes["scopes"] == "a|b")
    }

    @Test("a value containing an equals sign keeps all of it")
    func valueWithEquals() throws {
        // Split at the first `=` only, so a base64 value or a filter expression survives.
        guard case .success(let store) = try Self.store("ada person active filter=a=b") else {
            Issue.record("a value may contain '='")
            return
        }
        #expect(store.subject(id: "ada")?.attributes["filter"] == "a=b")
    }
}
