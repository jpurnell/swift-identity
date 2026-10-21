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
