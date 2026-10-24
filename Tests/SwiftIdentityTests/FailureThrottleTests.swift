import Foundation
import Testing
@testable import SwiftIdentity

/// Counting failures per subject, and backing off rather than locking out.
///
/// The distinction is the whole design. A lockout is a denial-of-service primitive handed to
/// anyone who knows a subject id — in a household, one person shutting another out of the boiler
/// instructions by being annoying. Backoff costs a guesser time and costs the rightful holder a
/// wait that ends.
@Suite("FailureThrottle")
struct FailureThrottleTests {

    /// A clock the test moves, so no test waits for a real backoff to expire.
    // Justification: every access to `instant` is serialised by `lock`, so the mutable state is never reached concurrently.
    final class Clock: @unchecked Sendable {
        private let lock = NSLock()
        private var instant = Date(timeIntervalSince1970: 1_800_000_000)

        var now: Date {
            lock.lock(); defer { lock.unlock() }
            return instant
        }

        func advance(_ interval: TimeInterval) {
            lock.lock(); defer { lock.unlock() }
            instant += interval
        }
    }

    private static func throttle(
        threshold: Int = 3, backoff: TimeInterval = 60
    ) -> (FailureThrottle, Clock) {
        let clock = Clock()
        let throttle = FailureThrottle(
            policy: ThrottlePolicy(threshold: threshold, backoff: backoff),
            now: { clock.now }
        )
        return (throttle, clock)
    }

    // MARK: - Counting

    @Test("a subject under the threshold is not refused")
    func belowThresholdIsAllowed() async {
        let (throttle, _) = Self.throttle(threshold: 3)
        for _ in 0..<2 { await throttle.recordFailure(subjectID: "ada") }
        #expect(await !throttle.shouldRefuse(subjectID: "ada"))
    }

    @Test("crossing it refuses the next attempt without checking anything")
    func crossingTheThresholdRefuses() async {
        let (throttle, _) = Self.throttle(threshold: 3)
        for _ in 0..<3 { await throttle.recordFailure(subjectID: "ada") }
        #expect(await throttle.shouldRefuse(subjectID: "ada"))
    }

    @Test("a success clears the count, so a mistyped passphrase is not held against anyone")
    func successClearsTheCount() async {
        let (throttle, _) = Self.throttle(threshold: 3)
        for _ in 0..<2 { await throttle.recordFailure(subjectID: "ada") }
        await throttle.recordSuccess(subjectID: "ada")
        for _ in 0..<2 { await throttle.recordFailure(subjectID: "ada") }

        // Four failures in total, and still allowed: they were not consecutive.
        #expect(await !throttle.shouldRefuse(subjectID: "ada"))
    }

    // MARK: - Backoff, not lockout

    @Test("the refusal ends on its own")
    func backoffExpires() async {
        let (throttle, clock) = Self.throttle(threshold: 3, backoff: 60)
        for _ in 0..<3 { await throttle.recordFailure(subjectID: "ada") }
        #expect(await throttle.shouldRefuse(subjectID: "ada"))

        clock.advance(61)
        // The point of backoff over lockout: nobody has to be let back in by hand.
        #expect(await !throttle.shouldRefuse(subjectID: "ada"))
    }

    @Test("and each further failure costs more, which is what makes guessing pointless")
    func backoffGrowsExponentially() async {
        let (throttle, clock) = Self.throttle(threshold: 3, backoff: 60)
        for _ in 0..<3 { await throttle.recordFailure(subjectID: "ada") }

        clock.advance(61)
        await throttle.recordFailure(subjectID: "ada")     // fourth: 120s
        clock.advance(61)
        #expect(await throttle.shouldRefuse(subjectID: "ada"), "the second penalty must outlast the first")

        clock.advance(60)
        #expect(await !throttle.shouldRefuse(subjectID: "ada"))
    }

    @Test("the wait is bounded, because an unbounded one is a lockout with extra steps")
    func backoffIsCapped() async {
        let (throttle, clock) = Self.throttle(threshold: 3, backoff: 60)
        for _ in 0..<40 { await throttle.recordFailure(subjectID: "ada") }

        // Doubling forty times is a wait no person outlives. A ceiling keeps this a delay a
        // guesser cannot exhaust and a household can.
        clock.advance(FailureThrottle.maximumBackoff + 1)
        #expect(await !throttle.shouldRefuse(subjectID: "ada"))
    }

    // MARK: - Isolation

    @Test("one subject's failures do not touch another")
    func throttlingIsPerSubject() async {
        let (throttle, _) = Self.throttle(threshold: 3)
        for _ in 0..<10 { await throttle.recordFailure(subjectID: "ada") }

        #expect(await throttle.shouldRefuse(subjectID: "ada"))
        // Otherwise anyone who knows a subject id can shut that person out at will.
        #expect(await !throttle.shouldRefuse(subjectID: "grace"))
    }
}

/// The ceiling NIST puts on consecutive failures, and what happens when the ledger can't answer.
@Suite("FailureThrottle — the ceiling")
struct FailureThrottleCeilingTests {

    typealias Clock = FailureThrottleTests.Clock

    static let ada = ThrottleKey(subjectID: "ada", authenticator: "passphrase:0011223344556677")
    static let adaCode = ThrottleKey(subjectID: "ada", authenticator: "totp")

    private static func throttle(
        threshold: Int = 5, backoff: TimeInterval = 60
    ) -> (FailureThrottle, Clock) {
        let clock = Clock()
        let throttle = FailureThrottle(
            policy: ThrottlePolicy(threshold: threshold, backoff: backoff),
            now: { clock.now }
        )
        return (throttle, clock)
    }

    /// Fails `times` times, letting each backoff expire first, the way a patient guesser would.
    private static func fail(
        _ throttle: FailureThrottle, _ clock: Clock, _ key: ThrottleKey, times: Int
    ) async throws {
        for _ in 0..<times {
            clock.advance(FailureThrottle.maximumBackoff + 1)
            _ = try await throttle.recordFailure(key)
        }
    }

    @Test("P13: the hundredth failure disables, and the refusal never expires")
    func ceilingDisables() async throws {
        let (throttle, clock) = Self.throttle()
        try await Self.fail(throttle, clock, Self.ada, times: 99)

        // Every backoff waited out: 99 consecutive failures are still below the ceiling.
        clock.advance(FailureThrottle.maximumBackoff + 1)
        #expect(await !throttle.shouldRefuse(Self.ada))

        _ = try await throttle.recordFailure(Self.ada)
        clock.advance(FailureThrottle.maximumBackoff * 1_000)
        // Backoff ends by itself. Disabling, which §3.2.2 requires, doesn't.
        #expect(await throttle.shouldRefuse(Self.ada))
    }

    @Test("P22: a success before the ceiling resets the count")
    func successResets() async throws {
        let (throttle, clock) = Self.throttle()
        try await Self.fail(throttle, clock, Self.ada, times: 99)
        try await throttle.recordSuccess(Self.ada)
        try await Self.fail(throttle, clock, Self.ada, times: 99)

        clock.advance(FailureThrottle.maximumBackoff + 1)
        #expect(await !throttle.shouldRefuse(Self.ada))
    }

    @Test("P13: rebinding is the way back")
    func reboundClears() async throws {
        let ledger = InMemoryThrottleLedger()
        let clock = Clock()
        let throttle = FailureThrottle(ledger: ledger, now: { clock.now })
        try await Self.fail(throttle, clock, Self.ada, times: 100)
        #expect(await throttle.shouldRefuse(Self.ada))

        await ledger.rebound(Self.ada)
        #expect(await !throttle.shouldRefuse(Self.ada))
    }

    @Test("P13: several authenticators failing together are all disabled")
    func severalInvolved() async throws {
        let (throttle, clock) = Self.throttle()
        try await Self.fail(throttle, clock, Self.ada, times: 99)

        // One attempt involving both, and the passphrase reaches the ceiling: both are disabled,
        // though the code had failed only once.
        let states = try await throttle.recordFailure(involving: [Self.ada, Self.adaCode])
        #expect(states.allSatisfy { $0.isDisabled })
        #expect(await throttle.shouldRefuse(Self.adaCode))
    }

    @Test("P13: a ceiling is a policy, bounded by NIST's 100")
    func ceilingIsValidated() throws {
        #expect(ThrottlePolicy.standard.ceiling == 100)
        #expect(try ThrottlePolicy(threshold: 5, backoff: 60, ceiling: 1).ceiling == 1)
        #expect(try ThrottlePolicy(threshold: 5, backoff: 60, ceiling: 100).ceiling == 100)
        // "No more than 100": a deployment may be stricter, never looser.
        #expect(throws: ThrottlePolicy.Failure.ceilingOutOfRange(101)) {
            try ThrottlePolicy(threshold: 5, backoff: 60, ceiling: 101)
        }
        #expect(throws: ThrottlePolicy.Failure.ceilingOutOfRange(0)) {
            try ThrottlePolicy(threshold: 5, backoff: 60, ceiling: 0)
        }
    }

    @Test("a stricter ceiling disables sooner")
    func stricterCeiling() async throws {
        let clock = Clock()
        let policy = try ThrottlePolicy(threshold: 3, backoff: 60, ceiling: 10)
        let throttle = FailureThrottle(policy: policy, now: { clock.now })
        try await Self.fail(throttle, clock, Self.ada, times: 10)
        clock.advance(FailureThrottle.maximumBackoff + 1)
        #expect(await throttle.shouldRefuse(Self.ada))
    }

    /// Counts verifications that actually ran.
    actor Verifications {
        private(set) var count = 0
        func ran() { count += 1 }
    }

    @Test("P13: concurrent attempts at 99 failures run exactly one verification, then disabled")
    func burstAtTheCeiling() async throws {
        let directory = try ThrottleLedgerTests.directory()
        defer { ThrottleLedgerTests.remove(directory) }
        let ledger = try FileThrottleLedger(url: directory.appendingPathComponent("throttle-ledger"))
        let clock = Clock()
        let throttle = FailureThrottle(ledger: ledger, now: { clock.now })
        try await Self.fail(throttle, clock, Self.ada, times: 99)
        clock.advance(FailureThrottle.maximumBackoff + 1)

        // Twenty guesses at once. Checked-then-recorded, all twenty would pass the check before
        // any was recorded: twenty verifications against a limit of one.
        let verifications = Verifications()
        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<20 {
                group.addTask {
                    guard await throttle.beginAttempt(Self.ada) else { return }
                    await verifications.ran()      // a wrong guess: nothing more to report
                }
            }
        }
        #expect(await verifications.count == 1)
        #expect(try await ledger.state(Self.ada).isDisabled)
    }

    // MARK: - Failing closed

    /// A ledger that can never be reached: a full disk, a deleted file, a host that's down.
    struct UnreachableLedger: ThrottleLedger {
        struct Unreachable: Error {}

        func recordFailure(_ key: ThrottleKey, at time: Date) async throws -> ThrottleState { throw Unreachable() }
        func recordFailure(involving keys: [ThrottleKey], at time: Date) async throws -> [ThrottleState] {
            throw Unreachable()
        }
        func beginAttempt(_ key: ThrottleKey, at time: Date) async throws -> Bool { throw Unreachable() }
        func recordSuccess(_ key: ThrottleKey) async throws { throw Unreachable() }
        func state(_ key: ThrottleKey) async throws -> ThrottleState { throw Unreachable() }
        func rebound(_ key: ThrottleKey) async throws { throw Unreachable() }
        func consume(step: Int64, for key: ThrottleKey) async throws -> Bool { throw Unreachable() }
        func disableTogether(_ keys: [ThrottleKey]) async throws -> Bool { throw Unreachable() }
    }

    @Test("a ledger that can't disable together reports them disabled, failing closed")
    func unreachableLedgerDisablesTogether() async {
        let throttle = FailureThrottle(ledger: UnreachableLedger())
        #expect(await throttle.disableTogether([ThrottleKey(subjectID: "ada", authenticator: "a")]))
    }

    @Test("a ledger that throws refuses the attempt")
    func unreachableLedgerRefuses() async {
        let throttle = FailureThrottle(ledger: UnreachableLedger())
        // A throttle that fails open hands an attacker exactly the attempts it exists to deny:
        // knock the ledger over, then guess freely.
        #expect(await throttle.shouldRefuse(Self.ada))
        #expect(await throttle.shouldRefuse(subjectID: "ada"))
        #expect(await !throttle.beginAttempt(Self.ada))
    }
}
