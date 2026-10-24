import Foundation
import Testing
@testable import SwiftIdentity

/// What mutation testing found the Authenticator tests didn't pin down.
///
/// Written against a mutant that survived the existing suites (`Harness/Mutation/REPORT.md`): it
/// fails with that mutant applied and passes without it.
extension AuthenticatorTests {

    /// Refuses everything as throttled, and names one throttle key for it, touching no ledger:
    /// the request that was turned away while another one's last attempt is being checked.
    struct ThrottledStore: ThrottlingCredentialStore {
        let key: ThrottleKey
        func resolve(_ credential: any Credential) async -> Resolution { .refused(.throttled) }
        func throttleKey(for credential: any Credential) async -> ThrottleKey? { key }
    }

    @Test("P22: a lone credential turned away doesn't seal the in-flight last attempt's fate")
    func aLoneCredentialDisablesNothingTogether() async throws {
        let key = ThrottleKey(subjectID: "ada", authenticator: "passphrase:0011223344556677")
        let ledger: any ThrottleLedger = InMemoryThrottleLedger(
            policy: try ThrottlePolicy(threshold: 1_000, backoff: 1, ceiling: 3)
        )
        // Three admitted attempts: the third is the last, counted at the ceiling and not yet
        // reported. Its count refuses everyone else, but it isn't disabled, because it may be right.
        for _ in 0..<3 { #expect(try await ledger.beginAttempt(key, at: Self.instant)) }
        #expect(try await ledger.state(key).isDisabled)

        let authenticator = Authenticator(
            stores: [ThrottledStore(key: key)], audit: nil, now: { Self.instant },
            throttle: FailureThrottle(ledger: ledger, now: { Self.instant })
        )
        #expect(await authenticator.authenticate([Passphrase(subjectID: "ada", secret: "anything")])
            == .refused(.throttled))

        // The last attempt was right after all. Disabling "together" is for credentials presented
        // together; one alone has nothing to be disabled with, so the success still clears it.
        try await ledger.recordSuccess(key)
        #expect(try await ledger.state(key) == .clear)
    }
}
