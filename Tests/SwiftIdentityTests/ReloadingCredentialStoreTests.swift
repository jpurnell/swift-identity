import Foundation
import SwiftDeterminism
import Testing
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
@testable import SwiftIdentity

/// A store that notices its files changed, keeps the last good copy when a replacement is bad, and says so once.
@Suite("ReloadingCredentialStore")
struct ReloadingCredentialStoreTests {
    private typealias Support = AdministrationTestSupport

    /// What the store reported, in order.
    // Justification: every access to `reports` is serialised by `lock`, so the mutable state is never reached concurrently.
    final class Reports: @unchecked Sendable {
        private let lock = NSLock()
        private var seen: [ReloadingCredentialStore.Report] = []

        func add(_ report: ReloadingCredentialStore.Report) {
            lock.lock(); defer { lock.unlock() }
            seen.append(report)
        }

        var all: [ReloadingCredentialStore.Report] {
            lock.lock(); defer { lock.unlock() }
            return seen
        }
    }

    private struct Rig {
        let path: String
        let directory: IdentityDirectory
        let first: MintedKey
        let clock = Support.Clock()
        let reports = Reports()
        let cleanup: String

        init() throws {
            path = try Support.absentDirectory()
            directory = IdentityDirectory(path: path)
            var generator = SplitMix64(seed: 1)
            first = try directory.create(first: SubjectSpec(id: "spinner", kind: .service), using: &generator)
            cleanup = (path as NSString).deletingLastPathComponent
        }

        func store(interval: TimeInterval = 1) throws -> ReloadingCredentialStore {
            let clock = self.clock
            let reports = self.reports
            return try ReloadingCredentialStore(
                directory: path, interval: interval, now: { clock.now }, onReload: { reports.add($0) })
        }
    }

    private func verifies(_ store: ReloadingCredentialStore, _ key: String) async -> Bool {
        if case .verified = await store.resolve(BearerKey(key)) { return true }
        return false
    }

    @Test("A key present at startup verifies")
    func startup() async throws {
        let rig = try Rig()
        defer { Support.remove(rig.cleanup) }
        #expect(await verifies(try rig.store(), rig.first.key))
    }

    @Test("A key added later is unknown until the interval has passed, then verifies, with no restart")
    func addedKey() async throws {
        var g = SplitMix64(seed: 9)
        let rig = try Rig()
        defer { Support.remove(rig.cleanup) }
        let store = try rig.store()
        let added = try rig.directory.add(SubjectSpec(id: "winetaster", kind: .service), using: &g)
        #expect(await verifies(store, added.key) == false, "inside the interval the old files are still served")
        rig.clock.advance(1.5)
        #expect(await verifies(store, added.key))
        #expect(rig.reports.all == [.reloaded])
    }

    @Test("A revocation takes effect after the interval")
    func revocation() async throws {
        let rig = try Rig()
        defer { Support.remove(rig.cleanup) }
        let store = try rig.store()
        try rig.directory.revoke(subject: "spinner")
        rig.clock.advance(1.5)
        #expect(await store.resolve(BearerKey(rig.first.key)) == .refused(.revoked))
    }

    @Test("A decoy made while running reports as a honeypot after the interval")
    func decoy() async throws {
        let rig = try Rig()
        defer { Support.remove(rig.cleanup) }
        let store = try rig.store()
        try rig.directory.setStatus(.honeypot, of: "spinner")
        rig.clock.advance(1.5)
        #expect(await store.resolve(BearerKey(rig.first.key)) == .refused(.honeypot))
    }

    @Test("A forced reload looks at once, and says whether anything changed")
    func forcedReload() async throws {
        var g = SplitMix64(seed: 9)
        let rig = try Rig()
        defer { Support.remove(rig.cleanup) }
        let store = try rig.store()
        #expect(await store.reload() == nil, "nothing changed")
        let added = try rig.directory.add(SubjectSpec(id: "winetaster", kind: .service), using: &g)
        #expect(await store.reload() == .reloaded)
        #expect(await verifies(store, added.key))
    }

    @Test("Nothing changed means nothing reported, however many resolves")
    func quiet() async throws {
        let rig = try Rig()
        defer { Support.remove(rig.cleanup) }
        let store = try rig.store()
        for _ in 0..<20 {
            rig.clock.advance(2)
            _ = await verifies(store, rig.first.key)
        }
        #expect(rig.reports.all.isEmpty)
    }

    @Test("A corrupt replacement keeps the last good store, is reported once, and a later good file recovers")
    func corruptReplacement() async throws {
        let rig = try Rig()
        defer { Support.remove(rig.cleanup) }
        let store = try rig.store()
        let good = try Support.read(rig.path + "/verifiers")
        try SecureIdentityFiles.replace(rig.path + "/verifiers", with: "garbage\n")
        for _ in 0..<10 {
            rig.clock.advance(2)
            #expect(await verifies(store, rig.first.key), "the last good store keeps serving")
        }
        let refusals = rig.reports.all.filter { if case .refused = $0 { true } else { false } }
        #expect(refusals.count == 1, "reported once, not on every resolve: \(rig.reports.all)")
        try SecureIdentityFiles.replace(rig.path + "/verifiers", with: good)
        rig.clock.advance(2)
        #expect(await verifies(store, rig.first.key))
        #expect(rig.reports.all.last == .reloaded)
    }

    @Test("A file made group-readable after startup is refused like a corrupt one, and the last good store keeps serving")
    func looseAfterStart() async throws {
        let rig = try Rig()
        defer { Support.remove(rig.cleanup) }
        let store = try rig.store()
        // A new inode, so the change is seen, with a mode the reader refuses.
        let text = try Support.read(rig.path + "/verifiers")
        try SecureIdentityFiles.replace(rig.path + "/verifiers", with: text)
        #expect(chmod(rig.path + "/verifiers", 0o644) == 0)
        rig.clock.advance(2)
        #expect(await verifies(store, rig.first.key))
        #expect(rig.reports.all.contains { if case .refused = $0 { true } else { false } })
    }

    @Test("A directory that cannot be loaded at startup is refused, not served empty")
    func startupFatal() throws {
        #expect(throws: FileCredentialStore.Failure.self) {
            try ReloadingCredentialStore(directory: "/nonexistent/identity")
        }
        #expect(throws: FileCredentialStore.Failure.self) {
            try ReloadingCredentialStore(directory: "relative/identity")
        }
    }

    @Test("It is a credential store like any other: the subject comes back through subject(for:)")
    func isACredentialStore() async throws {
        let rig = try Rig()
        defer { Support.remove(rig.cleanup) }
        let store: any CredentialStore = try rig.store()
        let subject = await store.subject(for: BearerKey(rig.first.key))
        #expect(subject?.id == "spinner")
        #expect(await store.subject(for: BearerKey("not-a-key")) == nil)
    }
}
