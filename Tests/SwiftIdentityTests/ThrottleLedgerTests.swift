#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import Foundation
import Testing
@testable import SwiftIdentity

/// Where consecutive failures are kept, and the ceiling NIST puts on them.
///
/// Every behavioural test here runs against both ledgers this package ships. A ledger is a
/// protocol so a deployment can supply its own, and the only way to say what a ledger must do is
/// to hold every implementation to the same list.
@Suite("ThrottleLedger")
struct ThrottleLedgerTests {

    /// The ledgers under test, named so a failure says which one.
    enum Kind: String, CaseIterable, CustomTestStringConvertible, Sendable {
        case memory
        case file

        var testDescription: String { rawValue }
    }

    static let ada = ThrottleKey(subjectID: "ada", authenticator: "passphrase:0011223344556677")
    static let adaCode = ThrottleKey(subjectID: "ada", authenticator: "totp")
    static let grace = ThrottleKey(subjectID: "grace", authenticator: "passphrase:8899aabbccddeeff")
    static let start = Date(timeIntervalSince1970: 1_800_000_000)
    /// After any backoff that failures at `start` can earn.
    static let later = start.addingTimeInterval(FailureThrottle.maximumBackoff + 1)

    /// A fresh owner-only directory, so a permission test can't be confused by the umask or by
    /// another test's file.
    static func directory() throws -> URL {
        let url = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("ThrottleLedgerTests-\(UUID().uuidString)", isDirectory: true)
            .standardized
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        #expect(chmod(url.path, 0o700) == 0)
        return url
    }

    static func remove(_ url: URL) {
        try? FileManager.default.removeItem(at: url)
    }

    /// A ledger of the given kind, and the directory to remove afterwards (nil for memory).
    static func ledger(
        _ kind: Kind, policy: ThrottlePolicy = .standard
    ) throws -> (any ThrottleLedger, URL?) {
        switch kind {
        case .memory:
            return (InMemoryThrottleLedger(policy: policy), nil)
        case .file:
            let directory = try directory()
            let ledger = try FileThrottleLedger(
                url: directory.appendingPathComponent("throttle-ledger"), policy: policy
            )
            return (ledger, directory)
        }
    }

    static func fail(_ ledger: any ThrottleLedger, _ key: ThrottleKey, times: Int) async throws {
        for _ in 0..<times { _ = try await ledger.recordFailure(key, at: start) }
    }

    // MARK: - The ceiling

    @Test("P13: the hundredth consecutive failure disables the authenticator", arguments: Kind.allCases)
    func ceilingDisables(kind: Kind) async throws {
        let (ledger, directory) = try Self.ledger(kind)
        defer { directory.map(Self.remove) }

        try await Self.fail(ledger, Self.ada, times: 99)
        #expect(try await !ledger.state(Self.ada).isDisabled, "99 is under the ceiling")

        let hundredth = try await ledger.recordFailure(Self.ada, at: Self.start)
        #expect(hundredth.isDisabled)
        #expect(hundredth.consecutiveFailures == 100)
        #expect(try await ledger.state(Self.ada).isDisabled)
    }

    @Test("P13: a disabled authenticator stays disabled long after any backoff has expired", arguments: Kind.allCases)
    func disabledOutlastsBackoff(kind: Kind) async throws {
        let (ledger, directory) = try Self.ledger(kind)
        defer { directory.map(Self.remove) }

        try await Self.fail(ledger, Self.ada, times: 100)
        let state = try await ledger.state(Self.ada)
        // A year on. Backoff ends by itself; disabling, by NIST's design, does not.
        #expect(state.refuses(at: Self.start.addingTimeInterval(365 * 86_400)))
    }

    @Test("P13: a success does not re-enable a disabled authenticator", arguments: Kind.allCases)
    func successDoesNotReEnable(kind: Kind) async throws {
        let (ledger, directory) = try Self.ledger(kind)
        defer { directory.map(Self.remove) }

        try await Self.fail(ledger, Self.ada, times: 100)
        // The throttle never lets a disabled authenticator get as far as a success. A ledger
        // that cleared on one anyway would be an unlock reachable by racing the refusal.
        try await ledger.recordSuccess(Self.ada)
        #expect(try await ledger.state(Self.ada).isDisabled)
    }

    @Test("P13: past the ceiling the count stops, so a guesser can't make the ledger grow", arguments: Kind.allCases)
    func countStopsAtTheCeiling(kind: Kind) async throws {
        let (ledger, directory) = try Self.ledger(kind)
        defer { directory.map(Self.remove) }

        try await Self.fail(ledger, Self.ada, times: 130)
        #expect(try await ledger.state(Self.ada).consecutiveFailures == 100)
    }

    @Test("P13: rebinding clears a disabled authenticator", arguments: Kind.allCases)
    func reboundClears(kind: Kind) async throws {
        let (ledger, directory) = try Self.ledger(kind)
        defer { directory.map(Self.remove) }

        try await Self.fail(ledger, Self.ada, times: 100)
        try await ledger.rebound(Self.ada)

        let state = try await ledger.state(Self.ada)
        #expect(!state.isDisabled)
        #expect(state.consecutiveFailures == 0)
        #expect(!state.refuses(at: Self.start))
    }

    @Test("P13: several authenticators failing together are all disabled", arguments: Kind.allCases)
    func severalInvolvedAllDisabled(kind: Kind) async throws {
        let (ledger, directory) = try Self.ledger(kind)
        defer { directory.map(Self.remove) }

        // The passphrase has failed alone 60 times before; the code has never failed. When the
        // passphrase reaches the ceiling in an attempt that involved both, §3.2.2 disables both.
        try await Self.fail(ledger, Self.ada, times: 60)
        for _ in 0..<40 {
            _ = try await ledger.recordFailure(involving: [Self.ada, Self.adaCode], at: Self.start)
        }

        #expect(try await ledger.state(Self.ada).isDisabled)
        #expect(try await ledger.state(Self.adaCode).isDisabled, "both were involved, so both are disabled")
        #expect(try await !ledger.state(Self.grace).isDisabled)
    }

    // MARK: - Backoff, below the ceiling

    @Test("below the ceiling, crossing the threshold backs off and the backoff ends", arguments: Kind.allCases)
    func backoffBelowTheCeiling(kind: Kind) async throws {
        let (ledger, directory) = try Self.ledger(kind, policy: ThrottlePolicy(threshold: 3, backoff: 60))
        defer { directory.map(Self.remove) }

        try await Self.fail(ledger, Self.ada, times: 3)
        let state = try await ledger.state(Self.ada)
        #expect(state.refuses(at: Self.start.addingTimeInterval(59)))
        #expect(!state.refuses(at: Self.start.addingTimeInterval(61)))
        #expect(!state.isDisabled)
    }

    @Test("P22: a success before the ceiling disregards the earlier failures", arguments: Kind.allCases)
    func successResets(kind: Kind) async throws {
        let (ledger, directory) = try Self.ledger(kind)
        defer { directory.map(Self.remove) }

        try await Self.fail(ledger, Self.ada, times: 99)
        try await ledger.recordSuccess(Self.ada)
        try await Self.fail(ledger, Self.ada, times: 99)

        // 198 failures, and still enabled: they were never 100 in a row.
        let state = try await ledger.state(Self.ada)
        #expect(!state.isDisabled)
        #expect(state.consecutiveFailures == 99)
    }

    @Test("one key's failures don't touch another's", arguments: Kind.allCases)
    func keysAreIndependent(kind: Kind) async throws {
        let (ledger, directory) = try Self.ledger(kind)
        defer { directory.map(Self.remove) }

        try await Self.fail(ledger, Self.ada, times: 100)
        #expect(try await ledger.state(Self.grace) == ThrottleState.clear)
        #expect(try await ledger.state(Self.adaCode) == ThrottleState.clear)
    }

    // MARK: - Counting before checking

    @Test("P13: an attempt is counted as a failure before it is checked", arguments: Kind.allCases)
    func attemptIsCountedFirst(kind: Kind) async throws {
        let (ledger, directory) = try Self.ledger(kind)
        defer { directory.map(Self.remove) }

        #expect(try await ledger.beginAttempt(Self.ada, at: Self.start))
        // Nothing reported back, and it is already a failure: a verifier that crashes, or a
        // caller that never reports, has still spent one of the hundred.
        #expect(try await ledger.state(Self.ada).consecutiveFailures == 1)
    }

    @Test("an attempt during a backoff is refused, and not counted", arguments: Kind.allCases)
    func attemptRefusedDuringBackoff(kind: Kind) async throws {
        let (ledger, directory) = try Self.ledger(kind, policy: ThrottlePolicy(threshold: 3, backoff: 60))
        defer { directory.map(Self.remove) }

        for _ in 0..<3 { #expect(try await ledger.beginAttempt(Self.ada, at: Self.start)) }
        #expect(try await !ledger.beginAttempt(Self.ada, at: Self.start.addingTimeInterval(59)))
        #expect(try await ledger.state(Self.ada).consecutiveFailures == 3, "a refusal is not an attempt")
        #expect(try await ledger.beginAttempt(Self.ada, at: Self.start.addingTimeInterval(61)))
    }

    @Test("P13: at 99 failures one attempt is admitted, and then the authenticator is disabled", arguments: Kind.allCases)
    func hundredthAttemptIsTheLast(kind: Kind) async throws {
        let (ledger, directory) = try Self.ledger(kind)
        defer { directory.map(Self.remove) }

        try await Self.fail(ledger, Self.ada, times: 99)
        #expect(try await ledger.beginAttempt(Self.ada, at: Self.later))
        // Reported disabled while it is checked, and if it fails, nothing more need be written:
        // the failure was counted on the way in.
        #expect(try await ledger.state(Self.ada).isDisabled)
        #expect(try await !ledger.beginAttempt(Self.ada, at: Self.start.addingTimeInterval(365 * 86_400)))
    }

    @Test("P22: the hundredth attempt, if it was right, clears the count", arguments: Kind.allCases)
    func hundredthAttemptCanSucceed(kind: Kind) async throws {
        let (ledger, directory) = try Self.ledger(kind)
        defer { directory.map(Self.remove) }

        try await Self.fail(ledger, Self.ada, times: 99)
        #expect(try await ledger.beginAttempt(Self.ada, at: Self.later))
        // Ninety-nine failures and then the right passphrase is not a hundred failures.
        try await ledger.recordSuccess(Self.ada)
        #expect(try await ledger.state(Self.ada) == ThrottleState.clear)
    }

    @Test("P13: concurrent attempts at 99 failures admit exactly one", arguments: Kind.allCases)
    func concurrentAttemptsAtTheEdge(kind: Kind) async throws {
        let (ledger, directory) = try Self.ledger(kind)
        defer { directory.map(Self.remove) }

        try await Self.fail(ledger, Self.ada, times: 99)
        let admitted = try await withThrowingTaskGroup(of: Bool.self) { group in
            for _ in 0..<20 {
                group.addTask { try await ledger.beginAttempt(Self.ada, at: Self.later) }
            }
            return try await group.reduce(0) { $0 + ($1 ? 1 : 0) }
        }
        #expect(admitted == 1)
    }

    // MARK: - One-time code steps

    @Test("a step is consumed once; an equal or earlier one is refused", arguments: Kind.allCases)
    func consumeIsAHighWaterMark(kind: Kind) async throws {
        let (ledger, directory) = try Self.ledger(kind)
        defer { directory.map(Self.remove) }

        #expect(try await ledger.consume(step: 60_000_000, for: Self.adaCode))
        #expect(try await !ledger.consume(step: 60_000_000, for: Self.adaCode), "a replay")
        // A set of used steps would accept this one, still inside the window. A high-water mark
        // doesn't.
        #expect(try await !ledger.consume(step: 59_999_999, for: Self.adaCode), "an earlier code")
        #expect(try await ledger.consume(step: 60_000_001, for: Self.adaCode))
        // Another key has its own mark.
        #expect(try await ledger.consume(step: 1, for: Self.grace))
    }

    @Test("a success keeps the consumed step, so a code can't be replayed after one", arguments: Kind.allCases)
    func successKeepsTheStep(kind: Kind) async throws {
        let (ledger, directory) = try Self.ledger(kind)
        defer { directory.map(Self.remove) }

        #expect(try await ledger.consume(step: 10, for: Self.adaCode))
        _ = try await ledger.recordFailure(Self.adaCode, at: Self.start)
        try await ledger.recordSuccess(Self.adaCode)
        #expect(try await !ledger.consume(step: 10, for: Self.adaCode))
    }

    // MARK: - Concurrency within one handle

    @Test("many concurrent failures through one handle are all counted", arguments: Kind.allCases)
    func concurrentFailuresOneHandle(kind: Kind) async throws {
        let (ledger, directory) = try Self.ledger(kind)
        defer { directory.map(Self.remove) }

        try await withThrowingTaskGroup(of: Void.self) { group in
            for _ in 0..<90 {
                group.addTask { _ = try await ledger.recordFailure(Self.ada, at: Self.start) }
            }
            try await group.waitForAll()
        }
        #expect(try await ledger.state(Self.ada).consecutiveFailures == 90)
    }
}

/// What only the file ledger has to get right: permissions, restarts, and other handles.
@Suite("FileThrottleLedger")
struct FileThrottleLedgerTests {

    static let ada = ThrottleLedgerTests.ada
    static let start = ThrottleLedgerTests.start

    static func mode(_ path: String) -> Int {
        var info = stat()
        guard stat(path, &info) == 0 else { return -1 }
        return Int(info.st_mode) & 0o7777
    }

    // MARK: - Persistence

    @Test("P13: a disabled authenticator stays disabled across a restart")
    func disabledSurvivesRestart() async throws {
        let directory = try ThrottleLedgerTests.directory()
        defer { ThrottleLedgerTests.remove(directory) }
        let url = directory.appendingPathComponent("throttle-ledger")

        let before = try FileThrottleLedger(url: url)
        try await ThrottleLedgerTests.fail(before, Self.ada, times: 100)

        // A new instance on the same file is what a restart is. The old per-process counter
        // forgot everything here, which made the ceiling a number a restart reset.
        let after = try FileThrottleLedger(url: url)
        #expect(try await after.state(Self.ada).isDisabled)
        #expect(try await after.state(Self.ada).consecutiveFailures == 100)
    }

    @Test("P13: a hundredth attempt that never reports back leaves the authenticator disabled across a restart")
    func unreportedHundredthSurvivesRestart() async throws {
        let directory = try ThrottleLedgerTests.directory()
        defer { ThrottleLedgerTests.remove(directory) }
        let url = directory.appendingPathComponent("throttle-ledger")

        let before = try FileThrottleLedger(url: url)
        try await ThrottleLedgerTests.fail(before, Self.ada, times: 99)
        #expect(try await before.beginAttempt(Self.ada, at: ThrottleLedgerTests.later))

        // The process dies mid-verification. Counted first, so a crash is a failure, not a
        // free attempt.
        let after = try FileThrottleLedger(url: url)
        #expect(try await after.state(Self.ada).isDisabled)
        #expect(try await !after.beginAttempt(Self.ada, at: ThrottleLedgerTests.later))
    }

    @Test("past the ceiling, a refused attempt writes nothing, and a success costs one write")
    func attemptWrites() async throws {
        let directory = try ThrottleLedgerTests.directory()
        defer { ThrottleLedgerTests.remove(directory) }
        let url = directory.appendingPathComponent("throttle-ledger")
        let ledger = try FileThrottleLedger(url: url)

        try await ThrottleLedgerTests.fail(ledger, Self.ada, times: 100)
        let inode = Self.inode(url.path)
        for _ in 0..<20 { #expect(try await !ledger.beginAttempt(Self.ada, at: Self.start)) }
        #expect(Self.inode(url.path) == inode, "a refusal wrote")

        let grace = ThrottleLedgerTests.grace
        #expect(try await ledger.beginAttempt(grace, at: Self.start))
        let reserved = Self.inode(url.path)
        #expect(reserved != inode, "the attempt is counted by a write")
        try await ledger.recordSuccess(grace)
        #expect(Self.inode(url.path) != reserved, "and the success that clears it is one more")
    }

    @Test("P13: past the ceiling, a refused attempt writes nothing")
    func noWritesPastTheCeiling() async throws {
        let directory = try ThrottleLedgerTests.directory()
        defer { ThrottleLedgerTests.remove(directory) }
        let url = directory.appendingPathComponent("throttle-ledger")

        let ledger = try FileThrottleLedger(url: url)
        try await ThrottleLedgerTests.fail(ledger, Self.ada, times: 100)
        let inode = Self.inode(url.path)

        // Every write replaces the file by rename, so an unchanged inode means no write. This is
        // the bound on write amplification §15.1 argued: a guesser can make the defender write
        // a hundred times per authenticator, and then never again.
        try await ThrottleLedgerTests.fail(ledger, Self.ada, times: 20)
        try await ledger.recordSuccess(Self.ada)
        _ = try await ledger.state(Self.ada)
        #expect(Self.inode(url.path) == inode)
    }

    static func inode(_ path: String) -> UInt64 {
        var info = stat()
        guard stat(path, &info) == 0 else { return 0 }
        return UInt64(info.st_ino)
    }

    // MARK: - Permissions and refusals, which are startup-fatal

    @Test("the ledger and its lock are created owner-only")
    func createdOwnerOnly() async throws {
        let directory = try ThrottleLedgerTests.directory()
        defer { ThrottleLedgerTests.remove(directory) }
        let url = directory.appendingPathComponent("throttle-ledger")

        let ledger = try FileThrottleLedger(url: url)
        _ = try await ledger.recordFailure(Self.ada, at: Self.start)

        #expect(Self.mode(url.path) == 0o600)
        #expect(Self.mode(url.path + FileThrottleLedger.lockSuffix) == 0o600)
    }

    @Test("a group- or world-readable ledger is refused at init")
    func permissiveFileRefused() async throws {
        let directory = try ThrottleLedgerTests.directory()
        defer { ThrottleLedgerTests.remove(directory) }
        let url = directory.appendingPathComponent("throttle-ledger")
        _ = try FileThrottleLedger(url: url)

        for mode: mode_t in [0o640, 0o604] {
            #expect(chmod(url.path, mode) == 0)
            #expect(throws: FileThrottleLedger.Failure.permissive(path: url.path, mode: String(mode, radix: 8))) {
                try FileThrottleLedger(url: url)
            }
        }
    }

    @Test("a lock file others can open is refused at init")
    func permissiveLockRefused() async throws {
        let directory = try ThrottleLedgerTests.directory()
        defer { ThrottleLedgerTests.remove(directory) }
        let url = directory.appendingPathComponent("throttle-ledger")
        _ = try FileThrottleLedger(url: url)

        // Anyone who can open the lock can hold it, and a held lock refuses every passphrase.
        let lock = url.path + FileThrottleLedger.lockSuffix
        #expect(chmod(lock, 0o666) == 0)
        #expect(throws: FileThrottleLedger.Failure.permissive(path: lock, mode: "666")) {
            try FileThrottleLedger(url: url)
        }
    }

    @Test("an unparseable ledger is refused at init, never read as empty")
    func unparseableRefused() async throws {
        let directory = try ThrottleLedgerTests.directory()
        defer { ThrottleLedgerTests.remove(directory) }
        let url = directory.appendingPathComponent("throttle-ledger")

        // Read as empty, a corrupted ledger would re-enable every disabled authenticator.
        try Data("not json".utf8).write(to: url)
        #expect(chmod(url.path, 0o600) == 0)
        #expect(throws: FileThrottleLedger.Failure.malformed(path: url.path)) {
            try FileThrottleLedger(url: url)
        }
    }

    @Test("a relative or climbing path is refused")
    func unsafePathRefused() throws {
        let relative = try #require(URL(string: "relative/ledger"))
        #expect(throws: FileThrottleLedger.Failure.unsafePath(path: "relative/ledger")) {
            try FileThrottleLedger(url: relative)
        }
        let climbing = URL(fileURLWithPath: "/tmp/../etc/ledger")
        #expect(throws: FileThrottleLedger.Failure.self) {
            try FileThrottleLedger(url: climbing)
        }
    }

    @Test("a ledger deleted after startup refuses rather than starting again from nothing")
    func deletedLedgerRefuses() async throws {
        let directory = try ThrottleLedgerTests.directory()
        defer { ThrottleLedgerTests.remove(directory) }
        let url = directory.appendingPathComponent("throttle-ledger")

        let ledger = try FileThrottleLedger(url: url)
        try await ThrottleLedgerTests.fail(ledger, Self.ada, times: 100)
        try FileManager.default.removeItem(at: url)

        await #expect(throws: FileThrottleLedger.Failure.self) {
            _ = try await ledger.state(Self.ada)
        }
    }

    // MARK: - Racing handles

    @Test("two handles on one file, racing, never lose a count")
    func racingHandles() async throws {
        let directory = try ThrottleLedgerTests.directory()
        defer { ThrottleLedgerTests.remove(directory) }
        let url = directory.appendingPathComponent("throttle-ledger")

        // Two instances in one process are two open file descriptions, so this exercises the
        // lock, not the actor: each actor serialises only its own calls.
        let first = try FileThrottleLedger(url: url)
        let second = try FileThrottleLedger(url: url)
        let keys = RaceWorker.keys

        try await withThrowingTaskGroup(of: Void.self) { group in
            for ledger in [first, second] {
                for key in keys {
                    group.addTask {
                        for _ in 0..<45 { _ = try await ledger.recordFailure(key, at: Self.start) }
                    }
                }
            }
            try await group.waitForAll()
        }
        for key in keys {
            #expect(try await first.state(key).consecutiveFailures == 90, "\(key.authenticator)")
        }
    }

    @Test("two processes on one file, racing, never lose a count", .enabled(if: RaceWorker.canRelaunch))
    func racingProcesses() async throws {
        let directory = try ThrottleLedgerTests.directory()
        defer { ThrottleLedgerTests.remove(directory) }
        let url = directory.appendingPathComponent("throttle-ledger")
        let ledger = try FileThrottleLedger(url: url)

        async let first = RaceWorker.launch(directory: directory, ledger: url)
        async let second = RaceWorker.launch(directory: directory, ledger: url)
        // A barrier, so the three writers overlap rather than running one after another while
        // the children are still starting up.
        try await RaceWorker.waitForReady(directory: directory, count: 2)
        try Data().write(to: directory.appendingPathComponent(RaceWorker.goMarker))
        try await RaceWorker.work(ledger)

        let statuses = try await [first, second]
        #expect(statuses == [0, 0], "a worker process failed")
        for key in RaceWorker.keys {
            #expect(try await ledger.state(key).consecutiveFailures == 3 * RaceWorker.rounds, "\(key.authenticator)")
        }
    }

    /// The other side of ``racingProcesses()``: runs only in a child process the parent launched.
    @Test("worker for the two-process race", .enabled(if: RaceWorker.isChild))
    func raceWorker() async throws {
        let environment = ProcessInfo.processInfo.environment
        let ledgerPath = try #require(environment[RaceWorker.ledgerVariable])
        let directoryPath = try #require(environment[RaceWorker.directoryVariable])
        let directory = URL(fileURLWithPath: directoryPath, isDirectory: true)

        let ledger = try FileThrottleLedger(url: URL(fileURLWithPath: ledgerPath))
        let ready = directory.appendingPathComponent("ready-\(getpid())")
        try Data().write(to: ready)
        try await RaceWorker.waitFor(directory.appendingPathComponent(RaceWorker.goMarker))
        try await RaceWorker.work(ledger)
    }
}

/// Launches this test binary again, filtered to ``FileThrottleLedgerTests/raceWorker()``.
///
/// A real second process, rather than a second actor, because the failure §12 names is the one
/// a second actor can't show: a lock taken on the wrong descriptor, or released by an unrelated
/// `close`, still excludes within one process for the wrong reasons. Done without a helper
/// executable in `Package.swift`: the test runner's own arguments say how to run it again.
enum RaceWorker {
    static let ledgerVariable = "SWIFTIDENTITY_RACE_LEDGER"
    static let directoryVariable = "SWIFTIDENTITY_RACE_DIRECTORY"
    static let goMarker = "go"
    static let rounds = 30
    static let keys = (0..<4).map { ThrottleKey(subjectID: "racer-\($0)", authenticator: "passphrase:race") }

    static var isChild: Bool { ProcessInfo.processInfo.environment[ledgerVariable] != nil }

    /// Whether the runner can be found and run again. False inside a child, so a worker never
    /// launches workers of its own.
    static var canRelaunch: Bool {
        guard !isChild, let runner = ProcessInfo.processInfo.arguments.first else { return false }
        return FileManager.default.isExecutableFile(atPath: runner)
    }

    /// This run's arguments with any filter or output path removed, filtered to the worker.
    static func relaunchArguments() -> [String] {
        let dropped: Set<String> = [
            "--filter", "--skip", "--xunit-output", "--event-stream-output-path",
            "--experimental-event-stream-output", "--attachments-path",
        ]
        var kept: [String] = []
        var skipNext = false
        for argument in ProcessInfo.processInfo.arguments.dropFirst() {
            if skipNext { skipNext = false; continue }
            if dropped.contains(argument) { skipNext = true; continue }
            kept.append(argument)
        }
        return kept + ["--filter", "raceWorker"]
    }

    /// Runs one worker to completion and returns its exit status.
    static func launch(directory: URL, ledger: URL) async throws -> Int32 {
        var environment = ProcessInfo.processInfo.environment
        environment[ledgerVariable] = ledger.path
        environment[directoryVariable] = directory.path
        return try await ProcessRunner.run(
            ProcessInfo.processInfo.arguments[0],
            arguments: relaunchArguments(),
            environment: environment,
            timeout: .seconds(120)
        )
    }

    static func waitForReady(directory: URL, count: Int) async throws {
        for _ in 0..<6_000 {
            let names = try FileManager.default.contentsOfDirectory(atPath: directory.path)
            if names.filter({ $0.hasPrefix("ready-") }).count >= count { return }
            try await Task.sleep(for: .milliseconds(10))
        }
        throw CancellationError()
    }

    static func waitFor(_ marker: URL) async throws {
        for _ in 0..<6_000 {
            if FileManager.default.fileExists(atPath: marker.path) { return }
            try await Task.sleep(for: .milliseconds(5))
        }
        throw CancellationError()
    }

    /// One writer's share: `rounds` failures on every key, interleaved.
    static func work(_ ledger: FileThrottleLedger) async throws {
        let at = Date(timeIntervalSince1970: 1_800_000_000)
        for _ in 0..<rounds {
            for key in keys { _ = try await ledger.recordFailure(key, at: at) }
        }
    }
}
