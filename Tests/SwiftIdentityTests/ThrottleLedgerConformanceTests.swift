import Foundation
import Testing
@testable import SwiftIdentity
import SwiftIdentityConformance

/// The ledger suite, run against the two ledgers this package ships and against ledgers broken
/// in one specific way each, which it must catch.
@Suite("Conformance — throttle ledgers")
struct ThrottleLedgerConformanceTests {

    static let policy: ThrottlePolicy = {
        // Ceiling 10 keeps the suite fast; the requirements don't depend on the number.
        (try? ThrottlePolicy(threshold: 3, backoff: 60, ceiling: 10)) ?? .standard
    }()

    static func fileLedgerPath() throws -> String {
        let url = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("LedgerConformance-\(UUID().uuidString)", isDirectory: true).standardized
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        return url.appendingPathComponent("throttle.ledger").path
    }

    // MARK: - What ships

    @Test("the in-memory ledger passes every requirement it claims")
    func inMemoryConforms() async throws {
        let ledger = InMemoryThrottleLedger(policy: Self.policy)
        let suite = ThrottleLedgerConformance(policy: Self.policy, capabilities: []) { ledger }
        let report = await suite.run()
        print("\n--- in-memory ledger ---\n" + report.summary + "\n")
        #expect(report.isConformant, "\(report.summary)")
        #expect(report.results.first { $0.requirement == .survivesRestart }?.verdict == .notClaimed)
    }

    @Test("the file ledger passes every requirement, restarts included")
    func fileConforms() async throws {
        let path = try Self.fileLedgerPath()
        let policy = Self.policy
        let suite = ThrottleLedgerConformance(policy: policy, capabilities: [.persistent]) {
            try FileThrottleLedger(url: URL(fileURLWithPath: path), policy: policy)
        }
        let report = await suite.run()
        print("\n--- file ledger ---\n" + report.summary + "\n")
        #expect(report.isConformant, "\(report.summary)")
    }

    @Test("every requirement is reported")
    func everyRequirementReported() async {
        let ledger = InMemoryThrottleLedger(policy: Self.policy)
        let report = await ThrottleLedgerConformance(policy: Self.policy, capabilities: []) { ledger }.run()
        #expect(Set(report.results.map(\.requirement)) == Set(ThrottleLedgerConformance.Requirement.allCases))
    }

    // MARK: - Mutants

    /// A configurable broken ledger: correct, except for the one defect switched on.
    actor Mutant: ThrottleLedger {
        struct Defects: OptionSet, Sendable {
            let rawValue: Int
            /// Reads, yields, then writes: concurrent attempts lose counts.
            static let racy = Defects(rawValue: 1 << 0)
            /// A success clears a disabled key.
            static let successUnlocks = Defects(rawValue: 1 << 1)
            /// Consumed steps are a set, so an earlier step is still accepted.
            static let stepSet = Defects(rawValue: 1 << 2)
            /// disableTogether does nothing.
            static let neverDisablesTogether = Defects(rawValue: 1 << 3)
            /// Never refuses at the ceiling.
            static let noCeiling = Defects(rawValue: 1 << 4)
            /// Admits during a backoff.
            static let noBackoff = Defects(rawValue: 1 << 5)
            /// Counts after checking, not before: beginAttempt admits without counting.
            static let countsLate = Defects(rawValue: 1 << 6)
        }

        let defects: Defects
        let policy: ThrottlePolicy
        var failures: [ThrottleKey: Int] = [:]
        var until: [ThrottleKey: Date] = [:]
        var disabled: Set<ThrottleKey> = []
        var steps: [ThrottleKey: Set<Int64>] = [:]

        init(_ defects: Defects, policy: ThrottlePolicy) {
            self.defects = defects
            self.policy = policy
        }

        func stateNow(_ key: ThrottleKey) -> ThrottleState {
            let count = failures[key] ?? 0
            let atCeiling = !defects.contains(.noCeiling) && count >= policy.ceiling
            return ThrottleState(consecutiveFailures: count, refusedUntil: until[key],
                                 isDisabled: disabled.contains(key) || atCeiling)
        }

        func beginAttempt(_ key: ThrottleKey, at time: Date) async throws -> Bool {
            let current = stateNow(key)
            if current.isDisabled { return false }
            if !defects.contains(.noBackoff), let refusedUntil = current.refusedUntil, refusedUntil > time { return false }
            if defects.contains(.countsLate) { return true }
            let read = failures[key] ?? 0
            if defects.contains(.racy) { await Task.yield() }
            failures[key] = read + 1
            until[key] = policy.refusedUntil(afterFailures: read + 1, at: time)
            return true
        }

        func recordFailure(_ key: ThrottleKey, at time: Date) async throws -> ThrottleState {
            failures[key, default: 0] += 1
            return stateNow(key)
        }

        func recordFailure(involving keys: [ThrottleKey], at time: Date) async throws -> [ThrottleState] {
            var states: [ThrottleState] = []
            for key in keys { states.append(try await recordFailure(key, at: time)) }
            return states
        }

        func recordSuccess(_ key: ThrottleKey) async throws {
            if stateNow(key).isDisabled, !defects.contains(.successUnlocks) { return }
            failures[key] = 0
            until[key] = nil
            disabled.remove(key)
        }

        func state(_ key: ThrottleKey) async throws -> ThrottleState { stateNow(key) }

        func rebound(_ key: ThrottleKey) async throws {
            failures[key] = nil
            until[key] = nil
            disabled.remove(key)
        }

        func consume(step: Int64, for key: ThrottleKey) async throws -> Bool {
            if defects.contains(.stepSet) { return steps[key, default: []].insert(step).inserted }
            if let last = steps[key]?.max(), step <= last { return false }
            steps[key, default: []].insert(step)
            return true
        }

        func disableTogether(_ keys: [ThrottleKey]) async throws -> Bool {
            if defects.contains(.neverDisablesTogether) { return false }
            guard keys.contains(where: { stateNow($0).isDisabled }) else { return false }
            disabled.formUnion(keys)
            return true
        }
    }

    static func failures(of defects: Mutant.Defects) async -> Set<ThrottleLedgerConformance.Requirement> {
        let mutant = Mutant(defects, policy: policy)
        let report = await ThrottleLedgerConformance(policy: policy, capabilities: []) { mutant }.run()
        return Set(report.failures.map(\.requirement))
    }

    @Test("an unbroken mutant conforms, so each catch below is the defect's")
    func controlConforms() async {
        #expect(await Self.failures(of: []).isEmpty)
    }

    @Test("a ledger that loses counts under concurrency is caught")
    func catchesRace() async {
        #expect(await Self.failures(of: .racy).contains(.concurrentAttemptsAreAllCounted))
    }

    @Test("a ledger whose success unlocks a disabled key is caught")
    func catchesSuccessUnlock() async {
        #expect(await Self.failures(of: .successUnlocks).contains(.disabledStaysDisabled))
    }

    @Test("a ledger that keeps consumed steps as a set is caught")
    func catchesStepSet() async {
        #expect(await Self.failures(of: .stepSet).contains(.consumedStepsAreAHighWaterMark))
    }

    @Test("a ledger that never disables together is caught")
    func catchesNoDisableTogether() async {
        #expect(await Self.failures(of: .neverDisablesTogether).contains(.disablesTogether))
    }

    @Test("a ledger with no ceiling is caught")
    func catchesNoCeiling() async {
        #expect(await Self.failures(of: .noCeiling).contains(.ceilingDisables))
    }

    @Test("a ledger that admits during a backoff is caught")
    func catchesNoBackoff() async {
        #expect(await Self.failures(of: .noBackoff).contains(.backoffRefusesWithoutCounting))
    }

    @Test("a ledger that counts after checking is caught")
    func catchesLateCounting() async {
        let caught = await Self.failures(of: .countsLate)
        #expect(caught.contains(.attemptsAreCountedBeforeChecking))
        #expect(caught.contains(.burstAtTheCeilingAdmitsOne))
    }

    @Test("an in-memory ledger claiming to persist is caught")
    func catchesFalsePersistence() async {
        let policy = Self.policy
        let report = await ThrottleLedgerConformance(policy: policy, capabilities: [.persistent]) {
            InMemoryThrottleLedger(policy: policy)
        }.run()
        #expect(Set(report.failures.map(\.requirement)).contains(.survivesRestart))
    }
}
