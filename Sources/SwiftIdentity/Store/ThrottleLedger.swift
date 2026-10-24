import Crypto
import Foundation

/// Which authenticator, on which account, a failure counts against.
///
/// Keyed by subject *and* authenticator because NIST counts failures "using a specific
/// authenticator on a single subscriber account" (SP 800-63B-4 §3.2.2). A subject with a
/// passphrase and an authenticator app has two counts, and a guesser who exhausts one has not
/// touched the other.
public struct ThrottleKey: Sendable, Hashable, Codable {
    /// The subject the attempt claimed.
    public let subjectID: String
    /// The authenticator's identity on that account, e.g. `"passphrase:1f2e3d4c5b6a7980"` or
    /// `"totp"`.
    public let authenticator: String

    /// Creates a key.
    ///
    /// - Parameters:
    ///   - subjectID: The subject the attempt claimed.
    ///   - authenticator: The authenticator's identity on that account.
    public init(subjectID: String, authenticator: String) {
        self.subjectID = subjectID
        self.authenticator = authenticator
    }

    /// The key for a subject's passphrase, derived from the verifiers it currently has.
    ///
    /// ## Issuing a new passphrase rebinds it
    ///
    /// The authenticator part is `"passphrase:"` and the first eight bytes of a SHA-256 over
    /// the verifiers' salts. A new passphrase is a new verifier with a new salt, so it is a new
    /// key, and whatever the old key had accumulated, a disabled state included, is orphaned
    /// with the passphrase it described.
    ///
    /// That is what §3.2.2 asks for — "Authenticators that have been disabled SHALL be required
    /// to rebind to the subscriber account" — and it makes the rebinding a property of issuing
    /// rather than a step someone has to remember. Revisions 1 and 2 of the design had an
    /// `unlock` that cleared the count and left the same passphrase in place, which NIST doesn't
    /// allow and which this makes impossible to write by accident: there is no operation on the
    /// ledger that re-enables the passphrase a guesser was working on.
    /// ``ThrottleLedger/rebound(_:)`` remains, for an administrator clearing an orphaned entry
    /// or a ledger that keys authenticators some other way.
    ///
    /// The salts are hashed, not copied, so the ledger holds nothing derived from the secret;
    /// a salt is not secret, but it has no reason to be in a second file. Sorted first, so the
    /// order verifier lines happen to be written in doesn't change the key.
    ///
    /// - Parameters:
    ///   - subjectID: The subject.
    ///   - verifiers: Every passphrase verifier the subject currently has.
    /// - Returns: The key, or ``unknownPassphrase`` for a subject with none.
    public static func passphrase(subjectID: String, verifiers: [PassphraseVerifier]) -> ThrottleKey {
        guard !verifiers.isEmpty else { return unknownPassphrase }
        var hasher = SHA256()
        for salt in verifiers.map(\.salt).sorted(by: { $0.lexicographicallyPrecedes($1) }) {
            // Length-prefixed, so two salts can't run together into the same bytes as one.
            hasher.update(data: [UInt8(truncatingIfNeeded: salt.count >> 8), UInt8(truncatingIfNeeded: salt.count)])
            hasher.update(data: salt)
        }
        let fingerprint = hasher.finalize().prefix(8).map(Hex.byte).joined()
        return ThrottleKey(subjectID: subjectID, authenticator: "\(Passphrase.kind):\(fingerprint)")
    }

    /// The one key every passphrase attempt against a subject with no passphrase is counted
    /// under.
    ///
    /// Fixed in both halves, not just the authenticator. Keyed by the claimed subject ID, a
    /// guesser naming a fresh stranger on every attempt would add a ledger entry per name, and
    /// the ledger is a file the defender writes. There is no authenticator here to protect, so
    /// nothing is lost by counting them together.
    public static let unknownPassphrase = ThrottleKey(subjectID: "", authenticator: "\(Passphrase.kind):none")

    /// The key for a subject's authenticator apps, derived from their sealed keys.
    ///
    /// The same construction as ``passphrase(subjectID:verifiers:)``: enrolling a new app is a
    /// new key, sealed afresh, so it's a new throttle key, and a disabled app is rebound by
    /// replacing it. The sealed bytes are hashed; the key inside them is never seen here.
    ///
    /// - Parameters:
    ///   - subjectID: The subject.
    ///   - verifiers: Every one-time-code verifier the subject currently has.
    /// - Returns: The key, or ``unknownOneTimeCode`` for a subject with none.
    public static func oneTimeCode(subjectID: String, verifiers: [OneTimeCodeVerifier]) -> ThrottleKey {
        guard !verifiers.isEmpty else { return unknownOneTimeCode }
        var hasher = SHA256()
        for sealed in verifiers.map(\.sealed).sorted(by: { $0.lexicographicallyPrecedes($1) }) {
            hasher.update(data: [UInt8(truncatingIfNeeded: sealed.count >> 8), UInt8(truncatingIfNeeded: sealed.count)])
            hasher.update(data: sealed)
        }
        let fingerprint = hasher.finalize().prefix(8).map(Hex.byte).joined()
        return ThrottleKey(subjectID: subjectID, authenticator: "\(OneTimeCode.kind):\(fingerprint)")
    }

    /// Every one-time-code attempt against a subject with no app counts here, for the reason
    /// ``unknownPassphrase`` is fixed in both halves.
    public static let unknownOneTimeCode = ThrottleKey(subjectID: "", authenticator: "\(OneTimeCode.kind):none")
}

/// What a ledger knows about one key.
public struct ThrottleState: Sendable, Equatable, Codable {
    /// Failures since the last success, or since rebinding. Stops at the ceiling.
    public let consecutiveFailures: Int
    /// When the current backoff ends, or nil if none is owed.
    public let refusedUntil: Date?
    /// Whether the authenticator is disabled: refused until rebound, whatever the time.
    public let isDisabled: Bool

    /// Creates a state.
    ///
    /// - Parameters:
    ///   - consecutiveFailures: Failures since the last success or rebinding.
    ///   - refusedUntil: When the current backoff ends.
    ///   - isDisabled: Whether the authenticator is disabled.
    public init(consecutiveFailures: Int, refusedUntil: Date?, isDisabled: Bool) {
        self.consecutiveFailures = consecutiveFailures
        self.refusedUntil = refusedUntil
        self.isDisabled = isDisabled
    }

    /// No failures, no backoff, enabled: a key the ledger has never seen.
    public static let clear = ThrottleState(consecutiveFailures: 0, refusedUntil: nil, isDisabled: false)

    /// Whether an attempt at `time` must be refused without checking it.
    ///
    /// - Parameter time: When the attempt is being made.
    /// - Returns: True while disabled, or while a backoff is running.
    public func refuses(at time: Date) -> Bool {
        if isDisabled { return true }
        guard let refusedUntil else { return false }
        return refusedUntil > time
    }
}

/// Where ``FailureThrottle`` keeps consecutive failures, and one-time code steps.
///
/// **The throttle decides; the ledger remembers, with one exception.** Disabling at the ceiling
/// is decided here, because it has to be atomic with the count that reaches it: a throttle that
/// read the count and disabled in a second call would leave a window in which a success on
/// another process cleared a count that had already reached 100.
///
/// ## What every implementation must guarantee
///
/// - **Atomic across every handle on the same ledger.** Two processes recording failures at
///   once never lose one. For ``FileThrottleLedger`` that means across processes on a host.
/// - **Disabled stays disabled until ``rebound(_:)``.** Not a success, not elapsed time, not a
///   restart.
/// - **Throws rather than guessing.** A ledger that can't be read must not report a clear
///   state: ``FailureThrottle`` refuses on a throw, and that only works if a throw is what
///   happens.
/// - **Writes only on change.** At the ceiling a further failure changes nothing, so writes
///   nothing; a guesser can make the defender write a bounded number of times per
///   authenticator, and no more.
///
/// ## Counted before checked
///
/// A verifier calls ``beginAttempt(_:at:)`` before it checks anything. That one operation refuses
/// the attempt, or counts it as a failure, atomically; only a match is reported afterwards, with
/// ``recordSuccess(_:)``. Checking first and recording after would be two operations with the
/// derivation between them, and every attempt arriving in that gap would pass the check: a
/// burst of twenty guesses at 99 failures would be twenty verifications, where NIST allows one.
/// Counted first, exactly one is admitted.
public protocol ThrottleLedger: Sendable {
    /// Refuses an attempt, or counts it as a failure before it is checked, in one atomic step.
    ///
    /// Refused, writing nothing, while the key is disabled, in a backoff, or at the ceiling.
    /// Otherwise the count goes up by one and any backoff it earns starts at `time`, before the
    /// attempt's secret is examined. A failed attempt then needs nothing more; a match calls
    /// ``recordSuccess(_:)``, which clears it.
    ///
    /// The attempt that takes the count to the ceiling is the last one admitted. While it is
    /// being checked, and forever after if it fails or its process dies, the key reports
    /// disabled; only its own success, reported through ``recordSuccess(_:)``, clears it.
    ///
    /// - Parameters:
    ///   - key: The authenticator the attempt is using.
    ///   - time: When the attempt is being made.
    /// - Returns: True if the attempt may be checked, and has been counted.
    func beginAttempt(_ key: ThrottleKey, at time: Date) async throws -> Bool

    /// Atomically adds one failure and returns the new state.
    ///
    /// At the ceiling the state becomes disabled, and stays so until the authenticator is
    /// rebound. Past it, the count stops and nothing is written.
    ///
    /// - Parameters:
    ///   - key: The authenticator the attempt used.
    ///   - time: When the attempt was made, from which any backoff runs.
    /// - Returns: The state after recording.
    func recordFailure(_ key: ThrottleKey, at time: Date) async throws -> ThrottleState

    /// Atomically adds one failure to each key, for an attempt that involved them all.
    ///
    /// If any of them is disabled afterwards, all of them are. §3.2.2: "If both are involved in
    /// consecutive failed authentication attempts … both authenticators SHALL be disabled." One
    /// operation rather than one per key, so no other process sees the first disabled and the
    /// second not.
    ///
    /// - Parameters:
    ///   - keys: Every authenticator the attempt used.
    ///   - time: When the attempt was made.
    /// - Returns: The state of each key after recording, in the order given.
    func recordFailure(involving keys: [ThrottleKey], at time: Date) async throws -> [ThrottleState]

    /// Disregards earlier failures after a success (NIST §3.2.2, a SHOULD).
    ///
    /// Leaves a key disabled by ``recordFailure(_:at:)`` disabled. Nothing is admitted to a
    /// disabled authenticator, so no success can follow one, and a ledger that cleared on one
    /// anyway would be an unlock reachable by racing the refusal. The one success that clears a
    /// count at the ceiling is that of the attempt ``beginAttempt(_:at:)`` admitted to reach it.
    ///
    /// - Parameter key: The authenticator that succeeded.
    func recordSuccess(_ key: ThrottleKey) async throws

    /// The current state of a key; ``ThrottleState/clear`` for one never seen.
    ///
    /// - Parameter key: The authenticator.
    /// - Returns: Its state.
    func state(_ key: ThrottleKey) async throws -> ThrottleState

    /// Forgets everything about a key, its disabled state included.
    ///
    /// For when the authenticator is rebound through an administrative act, never as a
    /// standalone "unlock" of the same secret. For a passphrase, issuing a new one rebinds by
    /// itself, because the key changes with the salt (``ThrottleKey/passphrase(subjectID:verifiers:)``).
    ///
    /// - Parameter key: The authenticator being rebound.
    func rebound(_ key: ThrottleKey) async throws

    /// Records a one-time code's time step as used, if it is later than the last one used.
    ///
    /// A high-water mark, not a set: a code from an earlier step is refused even while it is
    /// still inside the window, which a set of used steps would accept. Atomic across handles,
    /// so a code used on one process is refused on every other.
    ///
    /// - Parameters:
    ///   - step: The time step the presented code was valid for.
    ///   - key: The authenticator the code came from.
    /// - Returns: True if `step` was later than any consumed before, and is now consumed.
    func consume(step: Int64, for key: ThrottleKey) async throws -> Bool

    /// Disables every key if any of them is disabled, in one atomic step.
    ///
    /// For an attempt that presented several authenticators, each counted on its own through
    /// ``beginAttempt(_:at:)``. §3.2.2: "If more than one authenticator is involved with an
    /// excessive number of authentication attempts … both authenticators SHALL be disabled."
    /// Disabling is the one way to reach that state other than the ceiling, and it needs one
    /// of the keys to have reached it.
    ///
    /// - Parameter keys: Every throttled authenticator the attempt presented.
    /// - Returns: Whether they're now all disabled.
    func disableTogether(_ keys: [ThrottleKey]) async throws -> Bool
}

/// Why a ledger refused an operation, independent of where it keeps its state.
public enum ThrottleLedgerError: Error, Equatable {
    /// The ledger holds as many keys as it may, and this operation would add another.
    ///
    /// A backstop rather than a limit anyone should meet: keys come from the roster, so the
    /// number of them is bounded by the number of subjects and the passphrases issued to them.
    case full(limit: Int)
}

/// One key's record, as every ledger in this package keeps it.
struct LedgerEntry: Equatable, Codable {
    var failures: Int = 0
    var refusedUntil: Date?
    var disabled = false
    /// The latest one-time code step consumed, kept across successes so a code can't be
    /// replayed after one.
    var consumedStep: Int64?

    /// The state, reporting a count at the ceiling as disabled: either its last admitted attempt
    /// is still being checked, or it failed.
    func state(ceiling: Int) -> ThrottleState {
        ThrottleState(
            consecutiveFailures: failures, refusedUntil: refusedUntil,
            isDisabled: disabled || failures >= ceiling
        )
    }

    /// Whether this records nothing, and can be dropped rather than stored.
    var isEmpty: Bool { failures == 0 && refusedUntil == nil && !disabled && consumedStep == nil }
}

/// The state of every key, and the operations on it, shared by both ledgers here.
///
/// Pure: each operation reports whether it changed anything, so the file ledger can skip the
/// write when it didn't.
struct LedgerBook: Equatable {
    /// How many keys a ledger may hold. See ``ThrottleLedgerError/full(limit:)``.
    static let maximumEntries = 100_000

    var entries: [ThrottleKey: LedgerEntry] = [:]

    func state(_ key: ThrottleKey, ceiling: Int) -> ThrottleState {
        entries[key]?.state(ceiling: ceiling) ?? .clear
    }

    /// Refuses, or counts the attempt as a failure before it is checked.
    mutating func beginAttempt(_ key: ThrottleKey, at time: Date, policy: ThrottlePolicy) throws -> Bool {
        let existing = entries[key]
        if let existing, existing.state(ceiling: policy.ceiling).refuses(at: time) { return false }
        guard existing != nil || entries.count < Self.maximumEntries else {
            throw ThrottleLedgerError.full(limit: Self.maximumEntries)
        }
        var entry = existing ?? LedgerEntry()
        entry.failures += 1
        // Below the ceiling, the backoff this failure earns. At it, none: the count alone
        // refuses everything after, and a backoff would only end.
        entry.refusedUntil = entry.failures < policy.ceiling
            ? policy.refusedUntil(afterFailures: entry.failures, at: time)
            : nil
        entries[key] = entry
        return true
    }

    /// Adds a failure to every key; if any ends disabled, disables them all.
    mutating func recordFailure(
        involving keys: [ThrottleKey], at time: Date, policy: ThrottlePolicy
    ) throws -> (states: [ThrottleState], changed: Bool) {
        let unique = Array(Set(keys))
        let adding = unique.filter { entries[$0] == nil }.count
        guard entries.count + adding <= Self.maximumEntries else {
            throw ThrottleLedgerError.full(limit: Self.maximumEntries)
        }

        var changed = false
        for key in unique {
            var entry = entries[key] ?? LedgerEntry()
            // Disabled is terminal until rebound, and the count stops with it. That is the
            // bound on write amplification: nothing here changes, so nothing is written.
            guard !entry.disabled else { continue }
            entry.failures = min(entry.failures + 1, policy.ceiling)
            if entry.failures >= policy.ceiling {
                entry.disabled = true
                entry.refusedUntil = nil
            } else {
                entry.refusedUntil = policy.refusedUntil(afterFailures: entry.failures, at: time)
            }
            entries[key] = entry
            changed = true
        }

        if unique.contains(where: { entries[$0]?.disabled == true }) {
            for key in unique where entries[key]?.disabled != true {
                var entry = entries[key] ?? LedgerEntry()
                entry.disabled = true
                entry.refusedUntil = nil
                entries[key] = entry
                changed = true
            }
        }
        return (keys.map { state($0, ceiling: policy.ceiling) }, changed)
    }

    mutating func recordSuccess(_ key: ThrottleKey) -> Bool {
        guard var entry = entries[key], !entry.disabled else { return false }
        guard entry.failures != 0 || entry.refusedUntil != nil else { return false }
        entry.failures = 0
        entry.refusedUntil = nil
        entries[key] = entry.isEmpty ? nil : entry
        return true
    }

    mutating func rebound(_ key: ThrottleKey) -> Bool {
        entries.removeValue(forKey: key) != nil
    }

    /// Disables all of `keys` if any is disabled. Writes only what it changes.
    mutating func disableTogether(_ keys: [ThrottleKey], ceiling: Int) -> (disabled: Bool, changed: Bool) {
        let unique = Array(Set(keys))
        guard unique.contains(where: { state($0, ceiling: ceiling).isDisabled }) else { return (false, false) }
        var changed = false
        for key in unique where entries[key]?.disabled != true {
            var entry = entries[key] ?? LedgerEntry()
            entry.disabled = true
            entry.refusedUntil = nil
            entries[key] = entry
            changed = true
        }
        return (true, changed)
    }

    mutating func consume(step: Int64, for key: ThrottleKey) throws -> Bool {
        let existing = entries[key]
        if let last = existing?.consumedStep, step <= last { return false }
        guard existing != nil || entries.count < Self.maximumEntries else {
            throw ThrottleLedgerError.full(limit: Self.maximumEntries)
        }
        var entry = existing ?? LedgerEntry()
        entry.consumedStep = step
        entries[key] = entry
        return true
    }
}

/// A ledger in this process's memory: what ``FailureThrottle`` did before ledgers existed.
///
/// **It forgets on restart, and it is per process.** A deployment running several instances
/// gives a guesser one ceiling per instance, and a restart re-enables every disabled
/// passphrase. That makes it unfit to enforce NIST's ceiling in any deployment that restarts or
/// runs more than one instance, which is most of them; use ``FileThrottleLedger``. It stays the
/// default because changing the default would make every existing ``FailureThrottle`` start
/// writing a file nobody had chosen a place for.
public actor InMemoryThrottleLedger: ThrottleLedger {
    private let policy: ThrottlePolicy
    private var book = LedgerBook()

    /// Creates an empty ledger.
    ///
    /// - Parameter policy: The backoff and ceiling failures are recorded under.
    public init(policy: ThrottlePolicy = .standard) {
        self.policy = policy
    }

    /// Adds one failure. See ``ThrottleLedger/recordFailure(_:at:)``.
    public func recordFailure(_ key: ThrottleKey, at time: Date) throws -> ThrottleState {
        try book.recordFailure(involving: [key], at: time, policy: policy).states.first ?? .clear
    }

    /// Adds one failure to each key. See ``ThrottleLedger/recordFailure(involving:at:)``.
    public func recordFailure(involving keys: [ThrottleKey], at time: Date) throws -> [ThrottleState] {
        try book.recordFailure(involving: keys, at: time, policy: policy).states
    }

    /// Refuses, or counts before checking. See ``ThrottleLedger/beginAttempt(_:at:)``.
    public func beginAttempt(_ key: ThrottleKey, at time: Date) throws -> Bool {
        try book.beginAttempt(key, at: time, policy: policy)
    }

    /// Clears the count unless disabled. See ``ThrottleLedger/recordSuccess(_:)``.
    public func recordSuccess(_ key: ThrottleKey) {
        _ = book.recordSuccess(key)
    }

    /// The current state. See ``ThrottleLedger/state(_:)``.
    public func state(_ key: ThrottleKey) -> ThrottleState {
        book.state(key, ceiling: policy.ceiling)
    }

    /// Forgets the key. See ``ThrottleLedger/rebound(_:)``.
    public func rebound(_ key: ThrottleKey) {
        _ = book.rebound(key)
    }

    /// Disables all if any is disabled. See ``ThrottleLedger/disableTogether(_:)``.
    public func disableTogether(_ keys: [ThrottleKey]) -> Bool {
        book.disableTogether(keys, ceiling: policy.ceiling).disabled
    }

    /// Consumes a step if it is later. See ``ThrottleLedger/consume(step:for:)``.
    public func consume(step: Int64, for key: ThrottleKey) throws -> Bool {
        try book.consume(step: step, for: key)
    }
}
