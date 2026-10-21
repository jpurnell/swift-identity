import Foundation

/// Counts consecutive failures per subject, and makes the next attempt wait.
///
/// ## Backoff, not lockout
///
/// A lockout is a denial-of-service primitive handed to anyone who knows a subject id. In a
/// household that means one person can shut another out of the boiler instructions by being
/// annoying, and nobody is let back in without an administrator. Backoff costs a guesser time
/// and costs the rightful holder a wait that ends by itself.
///
/// ## For passphrases, and nothing else
///
/// Every other credential kind here carries 128 bits or more of machine randomness. Throttling
/// those defends against nothing a guesser could ever exhaust, and buys a mechanism that can
/// itself be used to deny service — see §4e of the design proposal. The slow KDF is the primary
/// defence for the one guessable kind; this is the second line, not the first.
///
/// ## It does not survive a restart, deliberately
///
/// Persisting the counter would mean a store write on every failed attempt — an amplification a
/// guesser controls, where the cost of attacking is a disk write the defender pays. A restart
/// therefore clears the penalty, and the KDF is what remains. Recorded as the recommendation in
/// §4e and taken.
///
/// **And the counter is per-process.** A deployment running several instances behind one address
/// gives a guesser one allowance per instance. Stated rather than hidden: with a slow KDF doing
/// the real work, a shared counter would mean shared mutable state across processes, which is a
/// larger correctness risk than the attempts it would save.
public actor FailureThrottle {

    /// The longest a subject is made to wait.
    ///
    /// Doubling without a ceiling reaches a wait no person outlives, which is a lockout arrived
    /// at by arithmetic rather than by decision. An hour is long enough that guessing is
    /// hopeless and short enough that a household is not stuck.
    public static let maximumBackoff: TimeInterval = 3_600

    /// One subject's recent history.
    private struct Record {
        var consecutiveFailures: Int
        var refusedUntil: Date?
    }

    private let policy: ThrottlePolicy
    private let now: @Sendable () -> Date
    private var records: [String: Record] = [:]

    /// Creates a throttle.
    ///
    /// - Parameters:
    ///   - policy: How many failures are tolerated, and the first penalty.
    ///   - now: The clock, injected so a backoff can be tested without waiting for one.
    public init(policy: ThrottlePolicy = .standard, now: @escaping @Sendable () -> Date = { Date() }) {
        self.policy = policy
        self.now = now
    }

    /// Whether this subject's next attempt must be refused without checking it.
    ///
    /// - Parameter subjectID: The subject an attempt claims.
    /// - Returns: Whether to refuse unchecked.
    public func shouldRefuse(subjectID: String) -> Bool {
        guard let until = records[subjectID]?.refusedUntil else { return false }
        return until > now()
    }

    /// Records a failed attempt.
    ///
    /// - Parameter subjectID: The subject the attempt claimed.
    public func recordFailure(subjectID: String) {
        var record = records[subjectID] ?? Record(consecutiveFailures: 0, refusedUntil: nil)
        record.consecutiveFailures += 1

        if record.consecutiveFailures >= policy.threshold {
            // Doubles per failure past the threshold, capped. `exceeding` is 0 on the attempt
            // that crosses it, so the first penalty is exactly the configured backoff.
            let exceeding = record.consecutiveFailures - policy.threshold
            let multiplier = pow(2.0, Double(min(exceeding, 32)))
            let delay = min(policy.backoff * multiplier, Self.maximumBackoff)
            record.refusedUntil = now().addingTimeInterval(delay)
        }
        records[subjectID] = record
    }

    /// Records a successful attempt, clearing this subject's history.
    ///
    /// Consecutive failures, not cumulative: someone who mistypes twice a week for a year is not
    /// gradually locked out of their own house.
    ///
    /// - Parameter subjectID: The subject that authenticated.
    public func recordSuccess(subjectID: String) {
        records.removeValue(forKey: subjectID)
    }
}
