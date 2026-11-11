import Foundation
import SwiftDeterminism
import Testing
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
@testable import SwiftIdentity

/// The behaviors 0.10.0 added to ``ReloadingCredentialStore``: the throttle surviving a swap, a synchronous subject lookup that
/// follows the files, a torn read retried once, and a swap that is never seen half done.
@Suite("ReloadingCredentialStore, 0.10.0")
struct ReloadingCredentialStoreGapTests {
    private typealias Support = AdministrationTestSupport

    /// Counts calls and lets a test decide which ones fail.
    // Justification: every access to `calls` is serialised by `lock`, so the mutable state is never reached concurrently.
    final class Counter: @unchecked Sendable {
        private let lock = NSLock()
        private var calls = 0

        /// The number of this call, starting at 1.
        func next() -> Int {
            lock.lock(); defer { lock.unlock() }
            calls += 1
            return calls
        }

        var count: Int {
            lock.lock(); defer { lock.unlock() }
            return calls
        }
    }

    // Justification: every access to `seen` is serialised by `lock`, so the mutable state is never reached concurrently.
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

    private static func write(_ text: String, to path: String) throws {
        try SecureIdentityFiles.replace(path, with: text)
    }

    /// Two passphrase subjects, so a swap can be judged against a throttle that has counted.
    private static func passphraseDirectory() throws -> String {
        let dir = try Support.directory()
        var generator = SplitMix64(seed: 21)
        let ada = try PassphraseVerifier(
            for: Passphrase(subjectID: "ada", secret: "ada-secret"), using: &generator, rounds: PassphraseVerifier.roundFloor)
        try write("ada person active\n", to: dir + "/subjects")
        try write("ada passphrase \(ada.encoded) -\n", to: dir + "/verifiers")
        return dir
    }

    @Test("The throttle's failure count survives a swap, and a rebuilt store still throttles")
    func throttleSurvivesSwap() async throws {
        let dir = try Self.passphraseDirectory()
        defer { Support.remove(dir) }
        let clock = Support.Clock()
        let throttle = FailureThrottle(policy: ThrottlePolicy(threshold: 3, backoff: 60), now: { clock.now })
        let store = try ReloadingCredentialStore(directory: dir, now: { clock.now }, throttle: throttle)
        let wrong = Passphrase(subjectID: "ada", secret: "not it")
        for _ in 0..<3 { #expect(await store.resolve(wrong) == .refused(.unknown)) }
        // A roster change only, so the verifiers (and the key derived from their salts) are the same.
        try Self.write("ada person active\ngrace person active\n", to: dir + "/subjects")
        #expect(await store.reload() == .reloaded)
        #expect(await store.resolve(wrong) == .refused(.throttled), "the count came through the swap")
        #expect(store.subject(id: "grace")?.id == "grace", "and the swap did happen")
    }

    @Test("The synchronous subject lookup follows a replacement and a revocation, with no resolve in between")
    func syncSubjectFollowsFiles() throws {
        var g = SplitMix64(seed: 3)
        let path = try Support.absentDirectory()
        defer { Support.remove((path as NSString).deletingLastPathComponent) }
        let directory = IdentityDirectory(path: path)
        _ = try directory.create(first: SubjectSpec(id: "spinner", kind: .service), using: &g)
        let clock = Support.Clock()
        let store = try ReloadingCredentialStore(directory: path, interval: 2, now: { clock.now })
        #expect(store.subject(id: "spinner")?.status == .active)
        #expect(store.subject(id: "winetaster") == nil)
        _ = try directory.add(SubjectSpec(id: "winetaster", kind: .service), using: &g)
        try directory.revoke(subject: "spinner")
        #expect(store.subject(id: "spinner")?.status == .active, "inside the interval the old snapshot is served")
        clock.advance(2.5)
        #expect(store.subject(id: "spinner")?.status == .revoked, "a held session sees the revocation at the next check")
        #expect(store.subject(id: "winetaster")?.status == .active)
    }

    @Test("A file replaced by rename, same size and same modification time, is noticed by its inode")
    func renameReplace() async throws {
        var g = SplitMix64(seed: 5)
        let path = try Support.absentDirectory()
        defer { Support.remove((path as NSString).deletingLastPathComponent) }
        let directory = IdentityDirectory(path: path)
        _ = try directory.create(first: SubjectSpec(id: "spinner", kind: .service), using: &g)
        let store = try ReloadingCredentialStore(directory: path)
        let file = path + "/verifiers"
        let before = try #require(SecureIdentityFiles.stamp(of: file))
        try Self.write(try Support.read(file), to: file)
        var times = [timeval(tv_sec: before.seconds, tv_usec: 0), timeval(tv_sec: before.seconds, tv_usec: 0)]
        #expect(utimes(file, &times) == 0)
        let after = try #require(SecureIdentityFiles.stamp(of: file))
        #expect(after.size == before.size && after.seconds == before.seconds)
        #expect(after.inode != before.inode)
        #expect(await store.reload() == .reloaded)
    }

    @Test("A parse that fails once and then succeeds is a torn read: retried, adopted, and not reported as a refusal")
    func tornReadRetried() async throws {
        var g = SplitMix64(seed: 7)
        let path = try Support.absentDirectory()
        defer { Support.remove((path as NSString).deletingLastPathComponent) }
        let directory = IdentityDirectory(path: path)
        _ = try directory.create(first: SubjectSpec(id: "spinner", kind: .service), using: &g)
        let counter = Counter()
        let reports = Reports()
        let store = try ReloadingCredentialStore(
            directory: path, interval: 1, now: { Date() }, onReload: { reports.add($0) },
            builder: {
                // Call 1 is startup, call 2 is the torn read, call 3 is the retry.
                if counter.next() == 2 { return .failure(.unreadable(path: path, reason: "torn")) }
                return Result { try FileCredentialStore(directory: path) }
                    .mapError { _ in .unreadable(path: path, reason: "unexpected") }
            })
        _ = try directory.add(SubjectSpec(id: "winetaster", kind: .service), using: &g)
        #expect(await store.reload() == .reloaded)
        #expect(counter.count == 3)
        #expect(reports.all == [.reloaded])
        #expect(store.subject(id: "winetaster")?.id == "winetaster")
    }

    @Test("A parse that fails twice is a refusal, reported once, and the last good store keeps serving")
    func failsTwiceIsRefused() async throws {
        var g = SplitMix64(seed: 8)
        let path = try Support.absentDirectory()
        defer { Support.remove((path as NSString).deletingLastPathComponent) }
        let directory = IdentityDirectory(path: path)
        let first = try directory.create(first: SubjectSpec(id: "spinner", kind: .service), using: &g)
        let counter = Counter()
        let reports = Reports()
        let store = try ReloadingCredentialStore(
            directory: path, interval: 1, now: { Date() }, onReload: { reports.add($0) },
            builder: {
                if counter.next() > 1 { return .failure(.unreadable(path: path, reason: "broken")) }
                return Result { try FileCredentialStore(directory: path) }
                    .mapError { _ in .unreadable(path: path, reason: "unexpected") }
            })
        _ = try directory.add(SubjectSpec(id: "winetaster", kind: .service), using: &g)
        let report = await store.reload()
        #expect(report == .refused(.unreadable(path: path, reason: "broken")))
        #expect(counter.count == 3, "one startup build, then the attempt and exactly one retry")
        #expect(await store.reload() == nil, "the same files are not reported again")
        #expect(reports.all.count == 1)
        if case .verified = await store.resolve(BearerKey(first.key)) {} else { Issue.record("the last good store stopped serving") }
    }

    @Test("Resolves and lookups racing swaps only ever see one whole generation")
    func concurrentSwap() async throws {
        // Two complete generations in two directories. In A, `s` is active and `kA` is its key; in B, `s` is revoked and
        // `kB` is its key. A store holding A's verifiers and B's roster would say `kA` is revoked: that is the mixture.
        func generation(_ status: String, key: String) throws -> String {
            let dir = try Support.directory()
            try Self.write("s service \(status)\n", to: dir + "/subjects")
            try Self.write("s bearer \((FileCredentialStore.digest(of: BearerKey(key)) ?? []).map { Hex.byte($0) }.joined()) -\n", to: dir + "/verifiers")
            return dir
        }
        let a = try generation("active", key: "kA")
        let b = try generation("revoked", key: "kB")
        let live = try Support.directory()
        defer { Support.remove(a); Support.remove(b); Support.remove(live) }
        try Self.write("s service active\n", to: live + "/subjects")
        try Self.write("s bearer x -\n", to: live + "/verifiers")
        let counter = Counter()
        let store = try ReloadingCredentialStore(
            directory: live, interval: 1_000_000, now: { Date() }, onReload: { _ in },
            builder: {
                let source = counter.next() % 2 == 1 ? a : b
                return Result { try FileCredentialStore(directory: source) }
                    .mapError { _ in .unreadable(path: source, reason: "unexpected") }
            })
        let mixtures = await withTaskGroup(of: Int.self) { group -> Int in
            for _ in 0..<8 {
                group.addTask {
                    var bad = 0
                    for _ in 0..<300 {
                        switch await store.resolve(BearerKey("kA")) {
                        case .verified(let subject) where subject.status == .active: break
                        case .refused(.unknown): break
                        default: bad += 1
                        }
                        switch await store.resolve(BearerKey("kB")) {
                        case .refused(.revoked), .refused(.unknown): break
                        default: bad += 1
                        }
                    }
                    return bad
                }
            }
            group.addTask {
                for round in 0..<60 {
                    // A new inode each time, so every reload is a real swap.
                    try? Self.write("s service \(round % 2 == 0 ? "active" : "revoked")\n", to: live + "/subjects")
                    _ = await store.reload()
                }
                return 0
            }
            return await group.reduce(0, +)
        }
        #expect(mixtures == 0)
    }

    @Test("Startup is still fatal when a throttle is supplied, and a throttling store is a ThrottlingCredentialStore")
    func startupAndConformance() async throws {
        #expect(throws: FileCredentialStore.Failure.self) {
            try ReloadingCredentialStore(directory: "/nonexistent/identity", throttle: FailureThrottle())
        }
        let dir = try Self.passphraseDirectory()
        defer { Support.remove(dir) }
        let store: any ThrottlingCredentialStore = try ReloadingCredentialStore(directory: dir, throttle: FailureThrottle())
        let key = await store.throttleKey(for: Passphrase(subjectID: "ada", secret: "x"))
        let direct = try FileCredentialStore(directory: dir).throttleKey(for: Passphrase(subjectID: "ada", secret: "x"))
        #expect(key == direct, "the same key the wrapped store derives")
        #expect(key != .unknownPassphrase, "ada has a passphrase, so a derived key")
        let (resolution, algorithm) = await store.resolveVerifying(Passphrase(subjectID: "ada", secret: "ada-secret"))
        if case .verified = resolution { #expect(algorithm?.isEmpty == false) } else { Issue.record("passphrase did not verify") }
    }
}
