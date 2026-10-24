#if canImport(os)
import os
#endif
import Foundation
import SwiftIdentity

/// The bar any ``ThrottleLedger`` must clear: the in-memory and file ledgers here, a remote one,
/// or one written elsewhere.
///
/// Black-box, through the protocol only, and each requirement is shown (in this package's tests)
/// to catch a ledger broken in that one way. It needs the policy the ledger was made with, since
/// the ceiling and backoff are the ledger's, and a way to open **another handle to the same
/// ledger**: for a file ledger, a new instance on the same file, which is also what a restart
/// looks like; for an in-memory one, the same instance.
public struct ThrottleLedgerConformance: Sendable {

    /// What every ledger must do.
    public enum Requirement: String, Sendable, CaseIterable {
        case unseenKeyIsClear = "a key never seen is clear"
        case attemptsAreCountedBeforeChecking = "an admitted attempt is counted before it's checked"
        case backoffRefusesWithoutCounting = "a backoff refuses, and the refusal isn't counted"
        case ceilingDisables = "the ceiling disables the authenticator"
        case disabledStaysDisabled = "disabled stays disabled until rebound: not a success, not time"
        case successResetsBelowCeiling = "a success below the ceiling clears the count"
        case burstAtTheCeilingAdmitsOne = "a concurrent burst one below the ceiling admits exactly one"
        case concurrentAttemptsAreAllCounted = "concurrent attempts on two handles lose no count"
        case consumedStepsAreAHighWaterMark = "a one-time-code step is accepted once, and never an earlier one"
        case disablesTogether = "keys presented together are disabled together, and only then"
        case survivesRestart = "counts, disabled keys and steps survive a new handle"
    }

    /// What a ledger claims beyond the minimum.
    public struct Capabilities: OptionSet, Sendable {
        /// The underlying bit field.
        public let rawValue: Int
        /// Creates a capability set.
        public init(rawValue: Int) { self.rawValue = rawValue }
        /// A new handle sees what an earlier one recorded: it survives a restart.
        public static let persistent = Capabilities(rawValue: 1 << 0)
    }

    /// One requirement's outcome.
    public struct Result: Sendable {
        /// The requirement judged.
        public let requirement: Requirement
        /// How it was judged.
        public let verdict: ConformanceSuite.Verdict
        /// Why, for a person reading the report.
        public let detail: String
    }

    /// Every requirement's outcome.
    public struct Report: Sendable {
        /// One per requirement.
        public let results: [Result]
        /// The requirements the ledger failed.
        public var failures: [Result] { results.filter { $0.verdict == .failed } }
        /// The requirements that couldn't be judged.
        public var inconclusive: [Result] { results.filter { $0.verdict == .inconclusive } }
        /// No failure and nothing inconclusive.
        public var isConformant: Bool { failures.isEmpty && inconclusive.isEmpty }
        /// One line per requirement.
        public var summary: String {
            results.map { result in
                let mark = switch result.verdict {
                case .passed: "PASS"
                case .failed: "FAIL"
                case .gap: "GAP "
                case .inconclusive: "????"
                case .notClaimed: "n/a "
                }
                return "\(mark)  \(result.requirement.rawValue) — \(result.detail)"
            }.joined(separator: "\n")
        }
    }

    private let policy: ThrottlePolicy
    private let capabilities: Capabilities
    private let makeHandle: @Sendable () async throws -> any ThrottleLedger

    /// Prepares the suite.
    ///
    /// - Parameters:
    ///   - policy: The policy the ledger was made with.
    ///   - capabilities: What the ledger claims.
    ///   - makeHandle: Opens another handle to the same ledger.
    public init(
        policy: ThrottlePolicy, capabilities: Capabilities,
        makeHandle: @escaping @Sendable () async throws -> any ThrottleLedger
    ) {
        self.policy = policy
        self.capabilities = capabilities
        self.makeHandle = makeHandle
    }

    /// A time far enough after `base` that every backoff has ended: one past the longest.
    private static func spaced(_ index: Int) -> Date {
        base.addingTimeInterval(Double(index) * (FailureThrottle.maximumBackoff * 2 + 1))
    }

    private static let base = Date(timeIntervalSince1970: 1_800_000_000)

    /// Runs every requirement, each on its own fresh key.
    public func run() async -> Report {
        let ledger: any ThrottleLedger
        do {
            ledger = try await makeHandle()
        } catch {
            #if canImport(os)
            Self.logger.error("couldn't open the ledger under test: \(String(describing: error), privacy: .public)")
            #endif
            return Report(results: Requirement.allCases.map {
                Result(requirement: $0, verdict: .inconclusive, detail: "couldn't open the ledger: \(error)")
            })
        }
        let run = UUID().uuidString
        func key(_ requirement: Requirement, _ suffix: String = "") -> ThrottleKey {
            ThrottleKey(subjectID: "conformance-\(run)", authenticator: "\(requirement)\(suffix)")
        }

        var results: [Result] = []
        for requirement in Requirement.allCases {
            do {
                results.append(try await judge(requirement, on: ledger, key: { key(requirement, $0) }))
            } catch {
                #if canImport(os)
                Self.logger.error("the ledger under test threw on \(requirement.rawValue, privacy: .public): \(String(describing: error), privacy: .public)")
                #endif
                results.append(Result(requirement: requirement, verdict: .failed,
                                      detail: "the ledger threw: \(error)"))
            }
        }
        return Report(results: results)
    }

    private func judge(
        _ requirement: Requirement, on ledger: any ThrottleLedger, key: (String) -> ThrottleKey
    ) async throws -> Result {
        switch requirement {
        case .unseenKeyIsClear:
            return check(requirement, try await ledger.state(key("")) == .clear, "an unseen key wasn't clear")
        case .attemptsAreCountedBeforeChecking:
            let admitted = try await ledger.beginAttempt(key(""), at: Self.spaced(0))
            let count = try await ledger.state(key("")).consecutiveFailures
            return check(requirement, admitted && count == 1,
                         "admitted \(admitted), counted \(count) before any result was reported")
        case .backoffRefusesWithoutCounting:
            return try await backoff(on: ledger, key: key(""))
        case .ceilingDisables:
            try await fill(ledger, key(""), to: policy.ceiling)
            let state = try await ledger.state(key(""))
            let refused = try await !ledger.beginAttempt(key(""), at: Self.spaced(policy.ceiling + 10))
            return check(requirement, state.isDisabled && refused,
                         "at \(policy.ceiling) failures: disabled \(state.isDisabled), refused later \(refused)")
        case .disabledStaysDisabled:
            return try await staysDisabled(on: ledger, key: key(""))
        case .successResetsBelowCeiling:
            try await fill(ledger, key(""), to: 2)
            try await ledger.recordSuccess(key(""))
            let count = try await ledger.state(key("")).consecutiveFailures
            return check(requirement, count == 0, "after a success the count was \(count)")
        case .burstAtTheCeilingAdmitsOne:
            return try await burst(on: ledger, key: key(""))
        case .concurrentAttemptsAreAllCounted:
            return try await race(key(""))
        case .consumedStepsAreAHighWaterMark:
            let k = key("")
            let answers = [
                try await ledger.consume(step: 5, for: k), try await ledger.consume(step: 5, for: k),
                try await ledger.consume(step: 4, for: k), try await ledger.consume(step: 6, for: k),
            ]
            return check(requirement, answers == [true, false, false, true],
                         "steps 5, 5, 4, 6 answered \(answers); expected true, false, false, true")
        case .disablesTogether:
            return try await together(on: ledger, at: key("-at"), clear: key("-clear"), other: key("-other"))
        case .survivesRestart:
            return try await restart(on: ledger, key: key(""))
        }
    }

    /// `count` admitted attempts, each after the previous backoff ended.
    private func fill(_ ledger: any ThrottleLedger, _ key: ThrottleKey, to count: Int) async throws {
        for index in 0..<count { _ = try await ledger.beginAttempt(key, at: Self.spaced(index)) }
    }

    private func backoff(on ledger: any ThrottleLedger, key: ThrottleKey) async throws -> Result {
        let requirement = Requirement.backoffRefusesWithoutCounting
        guard policy.threshold < policy.ceiling else {
            return Result(requirement: requirement, verdict: .inconclusive,
                          detail: "the policy's threshold isn't below its ceiling, so there's no backoff to see")
        }
        // Up to the threshold at one instant: the last of them starts the backoff.
        let instant = Self.spaced(0)
        for _ in 0..<policy.threshold { _ = try await ledger.beginAttempt(key, at: instant) }
        let before = try await ledger.state(key).consecutiveFailures
        let admitted = try await ledger.beginAttempt(key, at: instant)
        let after = try await ledger.state(key).consecutiveFailures
        return check(requirement, !admitted && before == after,
                     "during the backoff: admitted \(admitted), count \(before) → \(after)")
    }

    /// Disabled by a recorded failure at the ceiling. Not by `beginAttempt` reaching it: the
    /// attempt that reaches the ceiling may still succeed (the 100th try right is 99 failures,
    /// which NIST allows), and its success is the one that legitimately clears the count.
    private func staysDisabled(on ledger: any ThrottleLedger, key: ThrottleKey) async throws -> Result {
        try await fill(ledger, key, to: policy.ceiling - 1)
        _ = try await ledger.recordFailure(key, at: Self.spaced(policy.ceiling))
        try await ledger.recordSuccess(key)
        let afterSuccess = try await ledger.state(key).isDisabled
        let afterTime = try await !ledger.beginAttempt(key, at: Self.spaced(policy.ceiling + 1_000))
        try await ledger.rebound(key)
        let afterRebound = try await ledger.state(key)
        return check(.disabledStaysDisabled, afterSuccess && afterTime && afterRebound == .clear,
                     "disabled after a success \(afterSuccess), refused much later \(afterTime), "
                         + "clear after rebound \(afterRebound == .clear)")
    }

    private func burst(on ledger: any ThrottleLedger, key: ThrottleKey) async throws -> Result {
        try await fill(ledger, key, to: policy.ceiling - 1)
        let instant = Self.spaced(policy.ceiling + 5)
        let admitted = try await withThrowingTaskGroup(of: Bool.self) { group in
            for _ in 0..<20 { group.addTask { try await ledger.beginAttempt(key, at: instant) } }
            var count = 0
            for try await answer in group where answer { count += 1 }
            return count
        }
        let disabled = try await ledger.state(key).isDisabled
        return check(.burstAtTheCeilingAdmitsOne, admitted == 1 && disabled,
                     "20 concurrent attempts at \(policy.ceiling - 1) failures admitted \(admitted); disabled \(disabled)")
    }

    private func race(_ key: ThrottleKey) async throws -> Result {
        let first = try await makeHandle()
        let second = try await makeHandle()
        let instant = Self.spaced(0)
        let admitted = try await withThrowingTaskGroup(of: Bool.self) { group in
            for index in 0..<16 {
                let handle = index.isMultiple(of: 2) ? first : second
                group.addTask { try await handle.beginAttempt(key, at: instant) }
            }
            var count = 0
            for try await answer in group where answer { count += 1 }
            return count
        }
        let counted = try await first.state(key).consecutiveFailures
        return check(.concurrentAttemptsAreAllCounted, admitted == counted && admitted > 0,
                     "\(admitted) attempts admitted across two handles, \(counted) counted")
    }

    private func together(
        on ledger: any ThrottleLedger, at disabledKey: ThrottleKey, clear: ThrottleKey, other: ThrottleKey
    ) async throws -> Result {
        // Neither disabled: nothing happens.
        let early = try await ledger.disableTogether([clear, other])
        let clearAfterEarly = try await !ledger.state(clear).isDisabled
        // One disabled: both are.
        try await fill(ledger, disabledKey, to: policy.ceiling)
        let late = try await ledger.disableTogether([disabledKey, clear])
        let clearAfterLate = try await ledger.state(clear).isDisabled
        let otherUntouched = try await !ledger.state(other).isDisabled
        return check(.disablesTogether, !early && clearAfterEarly && late && clearAfterLate && otherUntouched,
                     "none disabled → \(early); one disabled → \(late), partner disabled \(clearAfterLate), "
                         + "a key not presented untouched \(otherUntouched)")
    }

    private func restart(on ledger: any ThrottleLedger, key: ThrottleKey) async throws -> Result {
        guard capabilities.contains(.persistent) else {
            return Result(requirement: .survivesRestart, verdict: .notClaimed, detail: "not claimed")
        }
        let disabledKey = ThrottleKey(subjectID: key.subjectID, authenticator: key.authenticator + "-disabled")
        try await fill(ledger, key, to: 2)
        try await fill(ledger, disabledKey, to: policy.ceiling)
        _ = try await ledger.consume(step: 9, for: key)
        let reopened = try await makeHandle()
        let count = try await reopened.state(key).consecutiveFailures
        let disabled = try await reopened.state(disabledKey).isDisabled
        let replay = try await reopened.consume(step: 9, for: key)
        return check(.survivesRestart, count == 2 && disabled && !replay,
                     "after reopening: count \(count) (2 expected), disabled \(disabled), step replay accepted \(replay)")
    }

    #if canImport(os)
    /// A ledger that throws is a finding, reported in the result; logged too, so a suite run in
    /// CI leaves the error itself behind as well as the verdict.
    private static let logger = Logger(subsystem: "org.roseclub.swiftidentity", category: "ledger-conformance")
    #endif

    private func check(_ requirement: Requirement, _ condition: Bool, _ failure: String) -> Result {
        Result(requirement: requirement, verdict: condition ? .passed : .failed,
               detail: condition ? "as required" : failure)
    }
}
