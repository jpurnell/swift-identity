import Foundation
import SwiftDeterminism
import Testing
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
@testable import SwiftIdentity

/// Adding, rotating, revoking and listing subjects and keys in the two files, checked by loading them back through the reader.
@Suite("IdentityDirectory")
struct IdentityDirectoryTests {
    private typealias Support = AdministrationTestSupport
    private let moment = Date(timeIntervalSince1970: 1_800_000_000)

    private func reader(_ path: String, at date: Date? = nil) throws -> FileCredentialStore {
        let at = date ?? moment
        return try FileCredentialStore(directory: path, now: { at })
    }

    private func resolution(_ path: String, _ key: String, at date: Date? = nil) async throws -> Resolution {
        await (try reader(path, at: date)).resolve(BearerKey(key))
    }

    private func fixture() throws -> (path: String, directory: IdentityDirectory, first: MintedKey, cleanup: String) {
        let path = try Support.absentDirectory()
        let directory = IdentityDirectory(path: path)
        var generator = SplitMix64(seed: 1)
        let first = try directory.create(first: SubjectSpec(id: "spinner", kind: .service, attributes: ["owner": "justin"]), using: &generator)
        return (path, directory, first, (path as NSString).deletingLastPathComponent)
    }

    @Test("create makes an owner-only directory and two owner-only files, and the minted key verifies as that subject")
    func create() async throws {
        let f = try fixture()
        defer { Support.remove(f.cleanup) }
        #expect(Support.mode(of: f.path) == 0o700)
        #expect(Support.mode(of: f.path + "/subjects") == 0o600)
        #expect(Support.mode(of: f.path + "/verifiers") == 0o600)
        guard case .verified(let subject) = try await resolution(f.path, f.first.key) else {
            Issue.record("the minted key did not verify")
            return
        }
        #expect(subject.id == "spinner")
        #expect(subject.kind == .service)
        #expect(subject.status == .active)
        #expect(subject.attributes["owner"] == "justin")
    }

    @Test("A minted key's text is in no file: only its digest is")
    func keyNotStored() throws {
        var g = SplitMix64(seed: 9)
        let f = try fixture()
        defer { Support.remove(f.cleanup) }
        let second = try f.directory.add(SubjectSpec(id: "winetaster", kind: .service), using: &g)
        for name in ["subjects", "verifiers"] {
            let text = try Support.read(f.path + "/" + name)
            #expect(!text.contains(f.first.key))
            #expect(!text.contains(second.key))
        }
        #expect(try Support.read(f.path + "/verifiers").contains(f.first.digest))
    }

    @Test("A second subject verifies beside the first, and a subject id cannot be taken twice")
    func addSubject() async throws {
        var g = SplitMix64(seed: 9)
        let f = try fixture()
        defer { Support.remove(f.cleanup) }
        let second = try f.directory.add(SubjectSpec(id: "winetaster", kind: .service), using: &g)
        for (key, id) in [(f.first.key, "spinner"), (second.key, "winetaster")] {
            guard case .verified(let subject) = try await resolution(f.path, key) else {
                Issue.record("\(id) did not verify")
                continue
            }
            #expect(subject.id == id)
        }
        #expect(throws: AdministrationFailure.alreadyExists("spinner")) {
            try f.directory.add(SubjectSpec(id: "spinner", kind: .service), using: &g)
        }
    }

    @Test("Rotation by overlap: a second key for a subject verifies beside the first, and expires on its date")
    func rotate() async throws {
        var g = SplitMix64(seed: 9)
        let f = try fixture()
        defer { Support.remove(f.cleanup) }
        let second = try f.directory.addKey(for: "spinner", expires: moment.addingTimeInterval(3_600), using: &g)
        #expect(try await resolution(f.path, f.first.key) == .verified(try #require(try reader(f.path).subject(id: "spinner"))))
        guard case .verified = try await resolution(f.path, second.key) else {
            Issue.record("the new key did not verify")
            return
        }
        let later = moment.addingTimeInterval(7_200)
        #expect(try await resolution(f.path, second.key, at: later) == .refused(.expired))
        guard case .verified = try await resolution(f.path, f.first.key, at: later) else {
            Issue.record("the old key should still verify")
            return
        }
    }

    @Test("Revoking one key by its digest prefix stops that key and leaves the other")
    func revokeKey() async throws {
        var g = SplitMix64(seed: 9)
        let f = try fixture()
        defer { Support.remove(f.cleanup) }
        let second = try f.directory.addKey(for: "spinner", expires: nil, using: &g)
        try f.directory.revokeKey(digestPrefix: String(f.first.digest.prefix(8)))
        #expect(try await resolution(f.path, f.first.key) == .refused(.unknown))
        guard case .verified = try await resolution(f.path, second.key) else {
            Issue.record("the other key should still verify")
            return
        }
    }

    @Test("A digest prefix that is too short, or matches nothing, is refused")
    func revokeKeyRefusals() throws {
        let f = try fixture()
        defer { Support.remove(f.cleanup) }
        #expect(throws: AdministrationFailure.prefixTooShort) { try f.directory.revokeKey(digestPrefix: String(f.first.digest.prefix(4))) }
        #expect(throws: AdministrationFailure.keyNotFound) { try f.directory.revokeKey(digestPrefix: "00000000") }
    }

    @Test("Revoking a subject makes its keys refuse as revoked")
    func revokeSubject() async throws {
        let f = try fixture()
        defer { Support.remove(f.cleanup) }
        try f.directory.revoke(subject: "spinner")
        #expect(try await resolution(f.path, f.first.key) == .refused(.revoked))
    }

    @Test("A key can be turned into a decoy: it refuses as a honeypot, which only the service sees")
    func honeypot() async throws {
        let f = try fixture()
        defer { Support.remove(f.cleanup) }
        try f.directory.setStatus(.honeypot, of: "spinner")
        #expect(try await resolution(f.path, f.first.key) == .refused(.honeypot))
    }

    @Test("list reports subjects in id order with each key's digest prefix and expiry, and never a key")
    func list() throws {
        var g = SplitMix64(seed: 9)
        let f = try fixture()
        defer { Support.remove(f.cleanup) }
        let expires = moment.addingTimeInterval(3_600)
        let rotated = try f.directory.addKey(for: "spinner", expires: expires, using: &g)
        _ = try f.directory.add(SubjectSpec(id: "alpha", kind: .service), using: &g)
        let listing = try f.directory.list()
        #expect(listing.map(\.id) == ["alpha", "spinner"])
        let spinner = try #require(listing.last)
        #expect(spinner.status == .active)
        #expect(spinner.keys.count == 2)
        #expect(spinner.keys.map(\.digestPrefix).contains(String(rotated.digest.prefix(8))))
        #expect(spinner.keys.contains { $0.expires != nil })
        let printed = "\(listing)"
        #expect(!printed.contains(f.first.key))
        #expect(!printed.contains(rotated.key))
    }

    @Test("An unusable name is refused: empty, spaces, commas, equals, a leading #, or longer than 64")
    func invalidNames() throws {
        var g = SplitMix64(seed: 9)
        let f = try fixture()
        defer { Support.remove(f.cleanup) }
        for name in ["", "has space", "a,b", "a=b", "#x", String(repeating: "a", count: 65)] {
            #expect(throws: AdministrationFailure.invalidName(name)) { try f.directory.add(SubjectSpec(id: name, kind: .service), using: &g) }
        }
    }

    @Test("A subject that is not there is not found, for a key, a revocation and a status")
    func notFound() throws {
        var g = SplitMix64(seed: 9)
        let f = try fixture()
        defer { Support.remove(f.cleanup) }
        #expect(throws: AdministrationFailure.notFound("ghost")) { try f.directory.addKey(for: "ghost", expires: nil, using: &g) }
        #expect(throws: AdministrationFailure.notFound("ghost")) { try f.directory.revoke(subject: "ghost") }
        #expect(throws: AdministrationFailure.notFound("ghost")) { try f.directory.setStatus(.honeypot, of: "ghost") }
    }

    @Test("Files that would not load are never written over: a corrupt verifiers file refuses every change and is left as it was")
    func corruptIsNotOverwritten() throws {
        var g = SplitMix64(seed: 9)
        let f = try fixture()
        defer { Support.remove(f.cleanup) }
        try SecureIdentityFiles.replace(f.path + "/verifiers", with: "garbage\n")
        #expect(throws: AdministrationFailure.self) { try f.directory.add(SubjectSpec(id: "other", kind: .service), using: &g) }
        #expect(try Support.read(f.path + "/verifiers") == "garbage\n")
    }

    @Test("A file anyone can read is refused before anything is changed")
    func permissiveRefused() throws {
        var g = SplitMix64(seed: 9)
        let f = try fixture()
        defer { Support.remove(f.cleanup) }
        #expect(chmod(f.path + "/verifiers", 0o644) == 0)
        #expect(throws: AdministrationFailure.files(.permissive(f.path + "/verifiers"))) {
            try f.directory.add(SubjectSpec(id: "other", kind: .service), using: &g)
        }
    }

    @Test("create refuses a directory that already holds identity files")
    func createRefusesExisting() throws {
        var g = SplitMix64(seed: 9)
        let f = try fixture()
        defer { Support.remove(f.cleanup) }
        #expect(throws: AdministrationFailure.self) {
            try f.directory.create(first: SubjectSpec(id: "again", kind: .service), using: &g)
        }
        #expect(try Support.read(f.path + "/subjects").contains("spinner"))
    }
}
