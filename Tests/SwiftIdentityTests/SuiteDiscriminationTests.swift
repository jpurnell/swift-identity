import Foundation
import Testing
@testable import SwiftIdentity
import SwiftIdentityConformance

/// Tests of the conformance suite itself.
///
/// A suite is only worth its output if a broken store fails it. So each store below is broken in
/// one specific, plausible way, and the suite must catch **that** way — not merely score badly.
/// Without this, the six negative requirements were satisfied by a store that refuses
/// everything, which is the failure mode this file exists to prevent from returning.
@Suite("Conformance — does the suite discriminate?")
struct SuiteDiscriminationTests {

    // MARK: - Fixtures

    private static let ada = Subject(
        id: "ada", kind: .person, status: .active, attributes: ["site": "north-house"]
    )
    private static let formerMember = Subject(id: "former-member", kind: .person, status: .revoked)
    private static let leaked = Subject(id: "retired-agent", kind: .service, status: .honeypot)
    private static let grace = Subject(id: "grace", kind: .person, status: .active)

    private static let past = Date(timeIntervalSince1970: 1_000)
    private static let present = Date(timeIntervalSince1970: 2_000)

    private static func fixtures(
        capabilities: ConformanceSuite.Capabilities = .all
    ) -> ConformanceSuite.Fixtures {
        .init(
            capabilities: capabilities,
            active: .init(
                id: "ada",
                credential: BearerKey("active-secret"),
                attributes: ["site": "north-house"],
                algorithm: "reference-sha256"
            ),
            refusals: .init(
                revoked: BearerKey("former-member-secret"),
                honeypot: CapabilityToken("leaked-share-link"),
                expired: SessionToken("stale-session"),
                unknown: BearerKey("never-issued")
            ),
            throttling: .init(
                wrongPassphrase: Passphrase(subjectID: "ada", secret: "not-the-passphrase"),
                otherSubject: BearerKey("grace-secret"),
                threshold: 3
            ),
            externalForActiveSubject: ExternalAssertion(.init(issuer: "https://issuer.test/", subject: "abc")),
            canonicalPassphrase: Self.composedPassphrase
        )
    }

    /// The active subject's passphrase, with "é" as one code point. The suite presents it
    /// decomposed as well, and both must resolve.
    private static let composedPassphrase = Passphrase(subjectID: "ada", secret: "caf\u{E9} au lait")

    private static func referenceStore() -> ReferenceCredentialStore {
        ReferenceCredentialStore(
            subjects: [ada, formerMember, leaked, grace],
            credentials: [
                (BearerKey("active-secret"), "ada", nil),
                (ExternalAssertion(.init(issuer: "https://issuer.test/", subject: "abc")), "ada", nil),
                (BearerKey("former-member-secret"), "former-member", nil),
                (CapabilityToken("leaked-share-link"), "retired-agent", nil),
                (SessionToken("stale-session"), "ada", past),
                (BearerKey("grace-secret"), "grace", nil),
                (composedPassphrase, "ada", nil),
            ],
            throttle: ThrottlePolicy(threshold: 3, backoff: 60),
            now: { present }
        )
    }

    // MARK: - The design, measured against its own suite

    @Test("the proposed design passes every requirement it claims")
    func referenceImplementationConforms() async {
        let report = await ConformanceSuite(store: Self.referenceStore(), fixtures: Self.fixtures()).run()
        print("\n--- reference implementation ---\n" + report.summary + "\n")

        #expect(report.failures.isEmpty)
        #expect(report.inconclusive.isEmpty)
        #expect(report.isConformant)
    }

    // MARK: - Mutants the suite must catch

    /// Resolves every credential to the gracee subject: the "authentication is a formality" store.
    private struct AcceptsAnything: CredentialStore {
        func resolve(_ credential: any Credential) async -> Resolution {
            .verified(SuiteDiscriminationTests.ada)
        }
    }

    /// Looks credentials up correctly but never checks `status`.
    ///
    /// The most plausible mutant of the lot: revocation is a field somebody forgot to read.
    private actor IgnoresStatus: CredentialStore {
        func resolve(_ credential: any Credential) async -> Resolution {
            // Cast rather than switch: an existential cannot be pattern-matched by value, which
            // is precisely the ergonomic cost of an open `Credential`.
            if let key = credential as? BearerKey {
                if key.value == "active-secret" { return .verified(SuiteDiscriminationTests.ada) }
                if key.value == "former-member-secret" { return .verified(SuiteDiscriminationTests.formerMember) }
            }
            if let token = credential as? CapabilityToken, token.value == "leaked-share-link" {
                return .verified(SuiteDiscriminationTests.leaked)
            }
            return .refused(.unknown)
        }
    }

    /// Matches the secret without regard to which kind it was presented as.
    ///
    /// This is how a calendar feed URL becomes an API key.
    private actor IgnoresKind: CredentialStore {
        func resolve(_ credential: any Credential) async -> Resolution {
            // The defect being modelled: matches the secret whatever kind it arrives as, which
            // is how a calendar feed's URL becomes an API key.
            let presented: String? = switch credential {
            case let key as BearerKey: key.value
            case let token as CapabilityToken: token.value
            case let session as SessionToken: session.value
            default: nil
            }
            guard presented == "active-secret" else { return .refused(.unknown) }
            return .verified(SuiteDiscriminationTests.ada)
        }
    }

    /// Correct except that a credential's lifetime is never enforced.
    private actor IgnoresExpiry: CredentialStore {
        func resolve(_ credential: any Credential) async -> Resolution {
            if let key = credential as? BearerKey, key.value == "active-secret" {
                return .verified(SuiteDiscriminationTests.ada)
            }
            // The defect: a lifetime that is never enforced.
            if let session = credential as? SessionToken, session.value == "stale-session" {
                return .verified(SuiteDiscriminationTests.ada)
            }
            return .refused(.unknown)
        }
    }

    /// Refuses everything — the store that made the original suite look good.
    private struct RefusesEverything: CredentialStore {
        func resolve(_ credential: any Credential) async -> Resolution { .refused(.unknown) }
    }

    /// Reports a honeypot as an ordinary refusal: the tripwire that never trips.
    private struct SilentAboutHoneypots: CredentialStore {
        func resolve(_ credential: any Credential) async -> Resolution {
            if let key = credential as? BearerKey, key.value == "active-secret" {
                return .verified(SuiteDiscriminationTests.ada)
            }
            // The defect: a honeypot reported as an ordinary refusal, so the tripwire never trips.
            return .refused(.unknown)
        }
    }

    /// Leaks the reason to the caller by overriding the extension that exists to prevent it.
    private struct LeaksTheReason: CredentialStore {
        func resolve(_ credential: any Credential) async -> Resolution {
            if let key = credential as? BearerKey, key.value == "active-secret" {
                return .verified(SuiteDiscriminationTests.ada)
            }
            if let token = credential as? CapabilityToken, token.value == "leaked-share-link" {
                return .refused(.honeypot)
            }
            return .refused(.unknown)
        }

        func subject(for credential: any Credential) async -> Subject? {
            // The mistake this requirement exists to catch: handing back something for a
            // refusal, so the caller learns which credentials are watched.
            if let token = credential as? CapabilityToken, token.value == "leaked-share-link" {
                return SuiteDiscriminationTests.leaked
            }
            guard case .verified(let subject) = await resolve(credential) else { return nil }
            return subject
        }
    }

    /// Compares a passphrase byte for byte: 0.6.x's defect, the one the amendment fixes.
    private struct HashesRawPassphrases: CredentialStore {
        func resolve(_ credential: any Credential) async -> Resolution {
            if let key = credential as? BearerKey, key.value == "active-secret" {
                return .verified(SuiteDiscriminationTests.ada)
            }
            // The defect: scalars compared exactly, so a decomposed "é" is a different passphrase.
            if let passphrase = credential as? Passphrase, passphrase.subjectID == "ada",
               Array(passphrase.secret.unicodeScalars) == Array(SuiteDiscriminationTests.composedPassphrase.secret.unicodeScalars) {
                return .verified(SuiteDiscriminationTests.ada)
            }
            return .refused(.unknown)
        }

        func resolveVerifying(_ credential: any Credential) async -> (Resolution, algorithm: String?) {
            (await resolve(credential), algorithm: "reference-sha256")
        }
    }

    /// Resolves correctly but never says what it verified with.
    private struct ReportsNoAlgorithm: CredentialStore {
        func resolve(_ credential: any Credential) async -> Resolution {
            if let key = credential as? BearerKey, key.value == "active-secret" {
                return .verified(SuiteDiscriminationTests.ada)
            }
            return .refused(.unknown)
        }
    }

    /// Answers every attempt, however many have failed.
    private actor NeverThrottles: CredentialStore {
        func resolve(_ credential: any Credential) async -> Resolution {
            guard let key = credential as? BearerKey else { return .refused(.unknown) }
            if key.value == "active-secret" { return .verified(SuiteDiscriminationTests.ada) }
            if key.value == "grace-secret" { return .verified(SuiteDiscriminationTests.grace) }
            return .refused(.unknown)
        }
    }

    /// Throttles everyone once anyone fails — a lockout wearing a backoff's clothes.
    private actor LocksEveryoneOut: CredentialStore {
        private var failures = 0
        func resolve(_ credential: any Credential) async -> Resolution {
            if failures >= 3 { return .refused(.throttled) }
            if let key = credential as? BearerKey {
                if key.value == "active-secret" { return .verified(SuiteDiscriminationTests.ada) }
                if key.value == "grace-secret" { return .verified(SuiteDiscriminationTests.grace) }
            }
            failures += 1
            return .refused(.unknown)
        }
    }

    @Test("a store that compares passphrases byte for byte is caught")
    func catchesRawPassphrases() async {
        let report = await ConformanceSuite(store: HashesRawPassphrases(), fixtures: Self.fixtures()).run()
        #expect(Set(report.failures.map(\.requirement)).contains(.canonicallyEquivalentPassphrasesMatch))
    }

    @Test("a store that reports no algorithm is caught, when it claims to record them")
    func catchesMissingAlgorithm() async {
        let report = await ConformanceSuite(store: ReportsNoAlgorithm(), fixtures: Self.fixtures()).run()
        #expect(Set(report.failures.map(\.requirement)).contains(.algorithmIsReported))
    }

    @Test("claiming a capability without its fixture is inconclusive, not a pass")
    func claimedWithoutFixtureIsAGap() async {
        let bare = ConformanceSuite.Fixtures(
            capabilities: [.canonicalPassphrases, .algorithmRecords],
            active: .init(id: "ada", credential: BearerKey("active-secret")),
            refusals: Self.fixtures().refusals
        )
        let report = await ConformanceSuite(store: Self.referenceStore(), fixtures: bare).run()
        let inconclusive = Set(report.inconclusive.map(\.requirement))
        #expect(inconclusive.contains(.canonicallyEquivalentPassphrasesMatch))
        #expect(inconclusive.contains(.algorithmIsReported))
        #expect(!report.isConformant)
    }

    @Test("a store that accepts anything fails every refusal requirement")
    func catchesAcceptsAnything() async {
        let report = await ConformanceSuite(store: AcceptsAnything(), fixtures: Self.fixtures()).run()
        let failed = Set(report.failures.map(\.requirement))
        #expect(failed.contains(.revokedNeverResolves))
        #expect(failed.contains(.honeypotNeverResolves))
        #expect(failed.contains(.expiredNeverResolves))
        #expect(failed.contains(.unknownResolvesToNil))
        #expect(failed.contains(.kindsDoNotCross))
        #expect(!report.isConformant)
    }

    @Test("a store that forgets to check status is caught on revocation and the honeypot")
    func catchesIgnoredStatus() async {
        let report = await ConformanceSuite(store: IgnoresStatus(), fixtures: Self.fixtures()).run()
        let failed = Set(report.failures.map(\.requirement))
        #expect(failed.contains(.revokedNeverResolves))
        #expect(failed.contains(.honeypotNeverResolves))
        // And it is caught on indistinguishability too: it hands back a subject for a
        // credential it should refuse, which is exactly how a caller learns who exists.
        #expect(failed.contains(.failuresAreIndistinguishable))
    }

    @Test("a store that matches on value alone is caught crossing kinds")
    func catchesIgnoredKind() async {
        let report = await ConformanceSuite(store: IgnoresKind(), fixtures: Self.fixtures()).run()
        #expect(Set(report.failures.map(\.requirement)).contains(.kindsDoNotCross))
    }

    @Test("a store that never expires a credential is caught")
    func catchesIgnoredExpiry() async {
        let report = await ConformanceSuite(store: IgnoresExpiry(), fixtures: Self.fixtures()).run()
        #expect(Set(report.failures.map(\.requirement)).contains(.expiredNeverResolves))
    }

    @Test("a store that refuses everything is inconclusive, not conformant")
    func refusingEverythingProvesNothing() async {
        let report = await ConformanceSuite(store: RefusesEverything(), fixtures: Self.fixtures()).run()
        print("\n--- refuses everything ---\n" + report.summary + "\n")

        // The correction: these used to be passes.
        let inconclusive = Set(report.inconclusive.map(\.requirement))
        #expect(inconclusive.contains(.revokedNeverResolves))
        #expect(inconclusive.contains(.honeypotNeverResolves))
        #expect(inconclusive.contains(.expiredNeverResolves))
        #expect(inconclusive.contains(.unknownResolvesToNil))
        #expect(inconclusive.contains(.kindsDoNotCross))
        #expect(inconclusive.contains(.failuresAreIndistinguishable))
        // Throttling too: a store that refuses everything refuses the sixth attempt exactly as
        // it refused the first, which says nothing about whether it throttles.
        #expect(inconclusive.contains(.throttlingAfterRepeatedFailure))
        #expect(inconclusive.contains(.canonicallyEquivalentPassphrasesMatch))
        #expect(!report.isConformant)
    }

    @Test("a store that reports a honeypot as an ordinary refusal is caught")
    func catchesSilentHoneypot() async {
        let report = await ConformanceSuite(store: SilentAboutHoneypots(), fixtures: Self.fixtures()).run()
        #expect(Set(report.failures.map(\.requirement)).contains(.honeypotIsReportedToTheService))
    }

    @Test("P18: an implementer cannot leak the refusal reason, even by trying")
    func reasonCannotLeak() async {
        // `LeaksTheReason` declares its own `subject(for:)` that hands back the honeypot
        // subject. Through the protocol it never runs: the accessor lives only in an extension,
        // so it is statically dispatched and the extension's version wins.
        //
        // That is why this is not a conformance requirement. A requirement is something a store
        // could fail; this one is enforced by the type system, and the test that belongs here is
        // a demonstration of the guarantee rather than a check of anyone's diligence.
        let store: any CredentialStore = LeaksTheReason()
        #expect(await store.subject(for: CapabilityToken("leaked-share-link")) == nil)

        // The service, holding the concrete store, still learns what happened.
        #expect(await store.resolve(CapabilityToken("leaked-share-link")) == .refused(.honeypot))

        // And the suite agrees the store is sound, because it is.
        let report = await ConformanceSuite(store: store, fixtures: Self.fixtures()).run()
        #expect(!report.failures.map(\.requirement).contains(.honeypotNeverResolves))
    }

    @Test("a store that never throttles is caught")
    func catchesNoThrottling() async {
        let report = await ConformanceSuite(store: NeverThrottles(), fixtures: Self.fixtures()).run()
        #expect(Set(report.failures.map(\.requirement)).contains(.throttlingAfterRepeatedFailure))
    }

    @Test("a store that locks everyone out is caught, because backoff is not lockout")
    func catchesGlobalLockout() async {
        let report = await ConformanceSuite(store: LocksEveryoneOut(), fixtures: Self.fixtures()).run()
        #expect(Set(report.failures.map(\.requirement)).contains(.throttlingIsPerSubject))
    }

    @Test("a shim that does not claim honeypots is not punished for lacking one")
    func adapterWithoutHoneypots() async {
        // The Auth0 case: a provider can block a user but has no tripwire semantic.
        let report = await ConformanceSuite(
            store: Self.referenceStore(),
            fixtures: Self.fixtures(capabilities: [.revocation, .expiry])
        ).run()

        let notClaimed = Set(report.results.filter { $0.verdict == .notClaimed }.map(\.requirement))
        #expect(notClaimed.contains(.honeypotNeverResolves))
        #expect(notClaimed.contains(.externalIdentityMapsToLocalID))
        #expect(report.isConformant)
    }
}
