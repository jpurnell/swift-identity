#if canImport(os)
import os
#endif
import Foundation

/// Counts consecutive failures per authenticator, makes the next attempt wait, and disables the
/// authenticator at NIST's ceiling.
///
/// ## Backoff, then a ceiling
///
/// A lockout is a denial-of-service primitive handed to anyone who knows a subject id. In a
/// household that means one person can shut another out of the boiler instructions by being
/// annoying, and nobody is let back in without an administrator. Backoff costs a guesser time
/// and costs the rightful holder a wait that ends by itself.
///
/// Below ``ThrottlePolicy/ceiling`` that is still the whole behaviour. **At the ceiling the
/// authenticator is disabled** until it is rebound, because NIST SP 800-63B-4 §3.2.2 requires
/// it: "the verifier SHALL limit consecutive failed authentication attempts using a specific
/// authenticator on a single subscriber account to no more than 100 by disabling that
/// authenticator." That is a lockout, reached by a hundred consecutive failures slowed by the
/// backoff, and the risk is accepted in §15.1 of the assurance amendment: recovery is an
/// administrator issuing a new passphrase, and every refused attempt is audited as
/// ``IdentityEvent/Outcome/throttled``, so the attack is visible.
///
/// ## For passphrases, and nothing else
///
/// Every other credential kind here carries 128 bits or more of machine randomness. Throttling
/// those defends against nothing a guesser could ever exhaust, and buys a mechanism that can
/// itself be used to deny service — see §4e of the design proposal. The slow KDF is the primary
/// defence for the one guessable kind; this is the second line, not the first.
///
/// ## Where the counts live: a reversal, recorded
///
/// Through 0.6.3 this section read:
///
/// > **It does not survive a restart, deliberately.** Persisting the counter would mean a store
/// > write on every failed attempt — an amplification a guesser controls, where the cost of
/// > attacking is a disk write the defender pays. A restart therefore clears the penalty, and
/// > the KDF is what remains.
/// >
/// > **And the counter is per-process.** A deployment running several instances behind one
/// > address gives a guesser one allowance per instance. Stated rather than hidden: with a slow
/// > KDF doing the real work, a shared counter would mean shared mutable state across
/// > processes, which is a larger correctness risk than the attempts it would save.
///
/// Both were right for backoff and are wrong for a ceiling, and the ceiling is a SHALL. A
/// per-process ceiling of 100 is a ceiling of 300 for a deployment running three instances,
/// which is what the vault runs; a ceiling a restart clears is a ceiling of 100 per restart.
/// Neither is "no more than 100". So the counts moved into a ``ThrottleLedger``, and a
/// deployment that restarts or runs several instances gives this a ``FileThrottleLedger``.
///
/// What the old text worried about is answered rather than dismissed:
///
/// - **Write amplification is bounded.** A write happens only when a failure changes the
///   state, so at most one per failure up to the ceiling per authenticator, and none for the
///   refused attempts after it.
/// - **Shared mutable state across processes is the risk it said it was.** It is confined to
///   one type with one locking discipline, and tested with real racing processes.
///
/// The default ledger is still ``InMemoryThrottleLedger``, which keeps the old behaviour,
/// restart and per-process allowance included, for a deployment that hasn't chosen a file.
///
/// ## Failing closed
///
/// A ledger that throws refuses the attempt. A throttle that failed open would hand an
/// attacker exactly the attempts it exists to deny: knock the ledger over, then guess freely.
///
/// ## Counted before checked
///
/// A verifier calls ``beginAttempt(_:)`` before it derives anything, and that one atomic ledger
/// operation either refuses the attempt or counts it as a failure. Only a match is reported
/// afterwards, with ``recordSuccess(_:)``. Checking first and recording after, as this did
/// before the ceiling existed, left the derivation between two ledger operations, and a burst
/// of guesses at 99 failures all passed the check before any was recorded. Counted first,
/// exactly one is admitted, and a verifier that crashes mid-check has still spent its attempt.
///
/// The cost, in ledger writes: one per admitted attempt, whether it fails or not; one more for
/// a success, to clear the count; none for a refusal. So at most a hundred failed attempts'
/// worth per authenticator, then nothing.
public actor FailureThrottle {

    /// The longest a subject is made to wait, below the ceiling.
    ///
    /// Doubling without a ceiling reaches a wait no person outlives, which is a lockout arrived
    /// at by arithmetic rather than by decision. An hour is long enough that guessing is
    /// hopeless and short enough that a household is not stuck. The one lockout here is the
    /// one NIST requires, and it is reached by decision, at ``ThrottlePolicy/ceiling``.
    public static let maximumBackoff: TimeInterval = 3_600

    private let ledger: any ThrottleLedger
    private let now: @Sendable () -> Date

    /// Creates a throttle keeping its counts in memory, as it did before ledgers existed.
    ///
    /// The counts are per process and forgotten on restart; see ``InMemoryThrottleLedger``.
    ///
    /// - Parameters:
    ///   - policy: How many failures are tolerated, the first penalty, and the ceiling.
    ///   - now: The clock, injected so a backoff can be tested without waiting for one.
    public init(policy: ThrottlePolicy = .standard, now: @escaping @Sendable () -> Date = { Date() }) {
        self.ledger = InMemoryThrottleLedger(policy: policy)
        self.now = now
    }

    /// Creates a throttle keeping its counts in `ledger`.
    ///
    /// The policy is the ledger's, so there is one place it is set: disabling at the ceiling has
    /// to be decided where the count is kept.
    ///
    /// - Parameters:
    ///   - ledger: Where failures are kept, e.g. a ``FileThrottleLedger`` shared by every
    ///     instance on the host.
    ///   - now: The clock.
    public init(ledger: any ThrottleLedger, now: @escaping @Sendable () -> Date = { Date() }) {
        self.ledger = ledger
        self.now = now
    }

    // MARK: - By authenticator

    /// Refuses an attempt, or counts it as a failure before it is checked.
    ///
    /// Call this before deriving anything. On true, check the secret, and on a match call
    /// ``recordSuccess(_:)``; on a mismatch there is nothing more to do, because the failure is
    /// already counted. On false, refuse without checking. False also when the ledger can't be
    /// reached: a throttle fails closed.
    ///
    /// - Parameter key: The authenticator the attempt is using.
    /// - Returns: Whether the attempt may be checked.
    public func beginAttempt(_ key: ThrottleKey) async -> Bool {
        do {
            return try await ledger.beginAttempt(key, at: now())
        } catch {
            #if canImport(os)
            Self.logger.error("throttle ledger failed; refusing: \(String(describing: error), privacy: .public)")
            #endif
            return false
        }
    }

    /// Whether this authenticator's next attempt must be refused without checking it.
    ///
    /// True while a backoff runs, once the authenticator is disabled, and whenever the ledger
    /// can't be read. For reporting; a verifier admits attempts with ``beginAttempt(_:)``, since
    /// a check followed by a separate record lets a burst through between the two.
    ///
    /// - Parameter key: The authenticator an attempt is using.
    /// - Returns: Whether to refuse unchecked.
    public func shouldRefuse(_ key: ThrottleKey) async -> Bool {
        do {
            return try await ledger.state(key).refuses(at: now())
        } catch {
            #if canImport(os)
            Self.logger.error("throttle ledger failed; refusing: \(String(describing: error), privacy: .public)")
            #endif
            return true
        }
    }

    /// Records a failed attempt that ``beginAttempt(_:)`` did not count: one checked without
    /// it, or a failure learned of some other way.
    ///
    /// - Parameter key: The authenticator the attempt used.
    /// - Returns: The state afterwards.
    /// - Throws: Whatever the ledger throws. A caller treats that as a refusal.
    @discardableResult
    public func recordFailure(_ key: ThrottleKey) async throws -> ThrottleState {
        try await ledger.recordFailure(key, at: now())
    }

    /// Records one failed attempt that involved several authenticators, disabling all of them
    /// if any reaches the ceiling (§3.2.2: "both authenticators SHALL be disabled").
    ///
    /// Only passphrases are throttled today; this is the rule a multi-factor attempt, a
    /// passphrase and a one-time code together, is recorded under.
    ///
    /// - Parameter keys: Every authenticator the attempt used.
    /// - Returns: The state of each afterwards, in the order given.
    /// - Throws: Whatever the ledger throws.
    @discardableResult
    public func recordFailure(involving keys: [ThrottleKey]) async throws -> [ThrottleState] {
        try await ledger.recordFailure(involving: keys, at: now())
    }

    /// Records a successful attempt, disregarding earlier failures (§3.2.2, P22).
    ///
    /// Consecutive failures, not cumulative: someone who mistypes twice a week for a year is not
    /// gradually locked out of their own house.
    ///
    /// - Parameter key: The authenticator that succeeded.
    /// - Throws: Whatever the ledger throws.
    public func recordSuccess(_ key: ThrottleKey) async throws {
        try await ledger.recordSuccess(key)
    }

    /// The state of an authenticator, for reporting.
    ///
    /// - Parameter key: The authenticator.
    /// - Returns: Its state.
    /// - Throws: Whatever the ledger throws.
    public func state(_ key: ThrottleKey) async throws -> ThrottleState {
        try await ledger.state(key)
    }

    /// Disables every authenticator an attempt presented, if any of them is disabled.
    ///
    /// True also when the ledger can't be reached, so a caller treats the set as disabled: the
    /// throttle fails closed.
    ///
    /// - Parameter keys: Every throttled authenticator the attempt presented.
    /// - Returns: Whether they're all disabled now.
    public func disableTogether(_ keys: [ThrottleKey]) async -> Bool {
        do {
            return try await ledger.disableTogether(keys)
        } catch {
            #if canImport(os)
            Self.logger.error("throttle ledger failed to disable authenticators together: \(String(describing: error), privacy: .public)")
            #endif
            return true
        }
    }

    /// Uses a one-time-code step, if it's later than the last one used for `key`.
    ///
    /// False for a replay, for an earlier step, and when the ledger can't be reached: accepting
    /// a code the ledger couldn't record would let it be accepted again (§3.1.4.2).
    ///
    /// - Parameters:
    ///   - step: The step the code matched.
    ///   - key: The authenticator.
    /// - Returns: Whether the code may be accepted.
    public func consume(step: Int64, for key: ThrottleKey) async -> Bool {
        do {
            return try await ledger.consume(step: step, for: key)
        } catch {
            #if canImport(os)
            Self.logger.error("throttle ledger failed to record a one-time-code step; refusing: \(String(describing: error), privacy: .public)")
            #endif
            return false
        }
    }

    // MARK: - By subject, as through 0.6.3

    /// The key the subject-only methods count under: the subject, and the passphrase kind.
    ///
    /// - Parameter subjectID: The subject.
    /// - Returns: Its key.
    public static func key(subjectID: String) -> ThrottleKey {
        ThrottleKey(subjectID: subjectID, authenticator: Passphrase.kind)
    }

    /// Whether this subject's next attempt must be refused without checking it.
    ///
    /// Kept from before ledgers existed. It counts under ``key(subjectID:)``, which doesn't
    /// change when a passphrase is reissued, so prefer ``shouldRefuse(_:)`` with
    /// ``ThrottleKey/passphrase(subjectID:verifiers:)``.
    ///
    /// - Parameter subjectID: The subject an attempt claims.
    /// - Returns: Whether to refuse unchecked.
    public func shouldRefuse(subjectID: String) async -> Bool {
        await shouldRefuse(Self.key(subjectID: subjectID))
    }

    /// Records a failed attempt against ``key(subjectID:)``.
    ///
    /// A ledger failure is logged rather than thrown, to keep this signature; the next
    /// ``shouldRefuse(subjectID:)`` refuses if the ledger is still failing.
    ///
    /// - Parameter subjectID: The subject the attempt claimed.
    public func recordFailure(subjectID: String) async {
        do {
            try await recordFailure(Self.key(subjectID: subjectID))
        } catch {
            #if canImport(os)
            Self.logger.error("throttle ledger failed; not recorded: \(String(describing: error), privacy: .public)")
            #endif
        }
    }

    /// Records a successful attempt against ``key(subjectID:)``.
    ///
    /// - Parameter subjectID: The subject that authenticated.
    public func recordSuccess(subjectID: String) async {
        do {
            try await recordSuccess(Self.key(subjectID: subjectID))
        } catch {
            #if canImport(os)
            Self.logger.error("throttle ledger failed; not recorded: \(String(describing: error), privacy: .public)")
            #endif
        }
    }

    #if canImport(os)
    /// Where ledger failures are reported. The attempt is refused either way; this is how an
    /// operator learns why.
    private static let logger = Logger(subsystem: "org.roseclub.swiftidentity", category: "throttle")
    #endif
}
