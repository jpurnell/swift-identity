import Foundation
import SwiftIdentity

/// The bar every ``CredentialStore`` must clear, shipped as a library rather than as tests.
///
/// A store written elsewhere — file-backed, database-backed, or standing in front of Keycloak —
/// runs *this* suite rather than its own. That is the mechanism behind the substitution
/// guarantee: if a provider-backed store cannot pass it unchanged, the protocol is wrong, and
/// that is discovered at design time instead of on the afternoon someone tries to swap.
public struct ConformanceSuite: Sendable {

    /// A behaviour a store must exhibit.
    public enum Requirement: String, Sendable, CaseIterable {
        case resolvesActiveSubject = "an active subject's credential resolves to it"
        case revokedNeverResolves = "a revoked subject never resolves"
        case honeypotNeverResolves = "a honeypot credential never resolves"
        case expiredNeverResolves = "an expired credential never resolves"
        case unknownResolvesToNil = "an unrecognised credential resolves to nothing"
        case kindsDoNotCross = "a value valid as one kind is not valid as another"
        case failuresAreIndistinguishable = "unknown, revoked and honeypot are alike to the caller"
        case externalIdentityMapsToLocalID = "a provider subject resolves to the same local id"
        case attributesRoundTrip = "consumer attributes survive unaltered"
        case honeypotIsReportedToTheService = "a honeypot is named to the service and hidden from the caller"
        case throttlingAfterRepeatedFailure = "repeated passphrase failure is refused unchecked"
        case throttlingIsPerSubject = "one subject's failures do not lock out another"
        case canonicallyEquivalentPassphrasesMatch = "a passphrase matches however its characters were encoded"
        case algorithmIsReported = "the store reports the algorithm it verified with"
    }

    /// How a requirement came out.
    public enum Verdict: String, Sendable {
        case passed
        case failed
        /// The store refused the credential — and refuses everything, so refusing *this* one
        /// proves nothing.
        ///
        /// This verdict is why the suite is worth running. Every negative requirement is
        /// satisfied by a store that never resolves anything, so without a positive control
        /// they cannot tell a correct implementation from a broken one. A negative result is
        /// only meaningful once the same store has been shown to resolve something.
        case inconclusive
        /// The store does not claim this optional behaviour.
        ///
        /// An adapter in front of an identity provider is the motivating case: Auth0 can block
        /// a user but has no notion of a honeypot, and punishing a shim for being a shim would
        /// make the suite an argument against ever adopting one.
        case notClaimed
        /// The current API offers no way to observe this, so the store cannot be judged on it.
        ///
        /// A gap is not a store's failure — it is the protocol's. Reported separately for
        /// exactly that reason: a suite that scored these as passes would be lying, and one
        /// that scored them as failures would blame the wrong party.
        case gap
    }

    /// One requirement's outcome.
    public struct Result: Sendable {
        /// The behaviour that was checked.
        public let requirement: Requirement
        /// How it came out.
        public let verdict: Verdict
        /// Why — what was observed, or why it could not be observed at all.
        public let detail: String
    }

    /// What the suite ran against.
    public struct Report: Sendable {
        /// Every requirement's outcome, in the order the suite ran them.
        public let results: [Result]
        /// Requirements the store did not meet.
        public var failures: [Result] { results.filter { $0.verdict == .failed } }
        /// Requirements the protocol cannot express — the design's gaps, not the store's.
        public var gaps: [Result] { results.filter { $0.verdict == .gap } }
        /// Requirements whose result proves nothing, because the store resolved nothing.
        public var inconclusive: [Result] { results.filter { $0.verdict == .inconclusive } }
        /// Whether the store cleared every requirement it claimed.
        ///
        /// Inconclusive counts against it: a store that refuses everything has not passed.
        public var isConformant: Bool { failures.isEmpty && inconclusive.isEmpty }

        /// A human-readable table, for a test to print when something is wrong.
        public var summary: String {
            let lines = results.map { result -> String in
                let mark: String
                switch result.verdict {
                case .passed: mark = "PASS"
                case .failed: mark = "FAIL"
                case .gap: mark = "GAP "
                case .inconclusive: mark = "????"
                case .notClaimed: mark = "n/a "
                }
                return "  \(mark)  \(result.requirement.rawValue) — \(result.detail)"
            }
            let counted = { (verdict: Verdict) in results.filter { $0.verdict == verdict }.count }
            return ([
                "\(results.count) requirements: \(counted(.passed)) passed, \(counted(.failed)) failed, "
                + "\(counted(.inconclusive)) inconclusive, \(counted(.notClaimed)) not claimed, "
                + "\(counted(.gap)) unverifiable",
            ] + lines).joined(separator: "\n")
        }
    }

    /// The credentials a store must be primed with before the suite can judge it.
    ///
    /// Supplied by the implementer because only they can mint a credential their store will
    /// recognise. The suite never creates one: that would require an administration protocol,
    /// which a provider-backed store is explicitly allowed not to have.
    /// Optional behaviours a store may or may not offer.
    ///
    /// Declared by the implementer, so that a provider-backed shim is measured on what it
    /// claims rather than on what a file-backed store happens to do.
    public struct Capabilities: OptionSet, Sendable {
        /// The underlying bit field.
        public let rawValue: Int
        /// Creates a capability set.
        public init(rawValue: Int) { self.rawValue = rawValue }
        /// The store distinguishes a revoked subject from an unknown one internally.
        public static let revocation = Capabilities(rawValue: 1 << 0)
        /// The store can hold a credential as a tripwire.
        public static let honeypot = Capabilities(rawValue: 1 << 1)
        /// The store enforces credential lifetimes.
        public static let expiry = Capabilities(rawValue: 1 << 2)
        /// The store maps an external issuer's subject onto a local id.
        public static let externalIdentity = Capabilities(rawValue: 1 << 3)
        /// The store slows repeated passphrase failures.
        public static let throttling = Capabilities(rawValue: 1 << 4)
        /// The store canonicalizes passphrases (NIST SP 800-63B-4's NFC), so "é" matches as one
        /// code point or two.
        public static let canonicalPassphrases = Capabilities(rawValue: 1 << 5)
        /// The store reports the algorithm it verified with, through `resolveVerifying(_:)`.
        public static let algorithmRecords = Capabilities(rawValue: 1 << 6)
        /// Everything a file-backed store is expected to do.
        public static let all: Capabilities = [
            .revocation, .honeypot, .expiry, .externalIdentity, .throttling,
            .canonicalPassphrases, .algorithmRecords,
        ]
    }

    /// The credentials a store must be primed with before the suite can judge it.
    ///
    /// Supplied by the implementer because only they can mint a credential their store will
    /// recognise. The suite never creates one: that would require an administration protocol,
    /// which a provider-backed store is explicitly allowed not to have.
    public struct Fixtures: Sendable {

        /// The subject the suite verifies against, and what proves it.
        public struct ActiveSubject: Sendable {
            /// The local id the credential must resolve to.
            public let id: String
            /// A credential the store recognises for this subject.
            public let credential: any Credential
            /// Attributes the subject is expected to carry back unaltered.
            public let attributes: [String: String]
            /// The algorithm the store should report verifying ``credential`` with, for a store
            /// claiming ``Capabilities/algorithmRecords``.
            public let algorithm: String?

            /// Describes the subject the suite will verify against.
            public init(
                id: String, credential: any Credential, attributes: [String: String] = [:],
                algorithm: String? = nil
            ) {
                self.id = id
                self.credential = credential
                self.attributes = attributes
                self.algorithm = algorithm
            }
        }

        /// One credential per reason a store must refuse.
        ///
        /// Grouped because they are meaningless apart: the suite compares the store's answers
        /// to each other, and a set missing one reason cannot show that the others are alike.
        public struct Refusals: Sendable {
            /// Belongs to a subject whose status is revoked.
            public let revoked: any Credential
            /// Held as a tripwire.
            public let honeypot: any Credential
            /// Past its lifetime.
            public let expired: any Credential
            /// Well formed, and never issued.
            public let unknown: any Credential

            /// Describes the four refusals.
            public init(
                revoked: any Credential,
                honeypot: any Credential,
                expired: any Credential,
                unknown: any Credential
            ) {
                self.revoked = revoked
                self.honeypot = honeypot
                self.expired = expired
                self.unknown = unknown
            }
        }

        /// What the throttling requirements need, for a store that claims them.
        public struct Throttling: Sendable {
            /// A wrong passphrase for the active subject, used to drive the counter without
            /// ever presenting a correct secret.
            public let wrongPassphrase: any Credential
            /// A valid credential for a *different* subject, proving the throttle is not global.
            public let otherSubject: any Credential
            /// How many failures the store's policy tolerates.
            public let threshold: Int

            /// Describes what is needed to exercise a throttle.
            public init(wrongPassphrase: any Credential, otherSubject: any Credential, threshold: Int) {
                self.wrongPassphrase = wrongPassphrase
                self.otherSubject = otherSubject
                self.threshold = threshold
            }
        }

        /// What this store claims to support.
        public let capabilities: Capabilities
        /// The subject the suite verifies against.
        public let active: ActiveSubject
        /// One credential per reason a store must refuse.
        public let refusals: Refusals
        /// Supplied only by a store claiming ``Capabilities/throttling``.
        public let throttling: Throttling?
        /// A credential proving the active subject through an external issuer, if the store
        /// claims ``Capabilities/externalIdentity``.
        public let externalForActiveSubject: (any Credential)?

        /// The active subject's proof, re-presented as a **different kind**.
        ///
        /// The suite cannot build this itself once ``Credential`` is open: a kind declared in
        /// the consumer's own package — a passkey assertion, a provider token — has no value the
        /// suite knows how to re-wrap, and only the implementer can say what "the same thing,
        /// offered as something else" means for it.
        ///
        /// Left nil, the suite falls back to re-presenting a ``BearerKey`` as a
        /// ``CapabilityToken``, which covers the built-in kinds and nothing else.
        public let activeAsAnotherKind: (any Credential)?

        /// A passphrase the store recognizes for the active subject, whose secret NFC and NFD
        /// encode differently (an accented letter, say). The suite presents it both ways.
        public let canonicalPassphrase: Passphrase?

        /// Describes a store to the suite.
        ///
        /// Grouped rather than flat: this took twelve parameters when every fixture sat at the
        /// top level, which is past the point where a call site can be read at a glance and
        /// past the point where the compiler can catch two credentials being swapped.
        public init(
            capabilities: Capabilities = .all,
            active: ActiveSubject,
            refusals: Refusals,
            throttling: Throttling? = nil,
            externalForActiveSubject: (any Credential)? = nil,
            activeAsAnotherKind: (any Credential)? = nil,
            canonicalPassphrase: Passphrase? = nil
        ) {
            self.capabilities = capabilities
            self.active = active
            self.refusals = refusals
            self.throttling = throttling
            self.externalForActiveSubject = externalForActiveSubject
            self.activeAsAnotherKind = activeAsAnotherKind
            self.canonicalPassphrase = canonicalPassphrase
        }
    }

    private let store: any CredentialStore
    private let fixtures: Fixtures

    /// Prepares the suite for one store.
    public init(store: any CredentialStore, fixtures: Fixtures) {
        self.store = store
        self.fixtures = fixtures
    }

    /// Runs every requirement.
    ///
    /// The active credential is resolved first, and its result gates everything else. A store
    /// that cannot resolve a subject it was primed with is not *refusing correctly* — it is
    /// refusing indiscriminately, and every negative requirement it then satisfies is
    /// meaningless. That distinction is the difference between a suite that measures something
    /// and one that congratulates a store for doing nothing.
    public func run() async -> Report {
        var results: [Result] = []

        let active = await store.subject(for: fixtures.active.credential)
        let resolvesAnything = active?.id == fixtures.active.id
        results.append(
            check(
                .resolvesActiveSubject,
                resolvesAnything,
                active == nil
                    ? "resolved to nothing"
                    : "resolved to '\(active?.id ?? "")', expected '\(fixtures.active.id)'"
            )
        )

        results.append(
            await negative(.revokedNeverResolves, fixtures.refusals.revoked, needs: .revocation,
                           control: resolvesAnything,
                           failure: "a revoked subject was returned")
        )
        results.append(
            await negative(.honeypotNeverResolves, fixtures.refusals.honeypot, needs: .honeypot,
                           control: resolvesAnything,
                           failure: "a honeypot credential returned a subject — that is a breach, not a tripwire")
        )
        results.append(
            await negative(.expiredNeverResolves, fixtures.refusals.expired, needs: .expiry,
                           control: resolvesAnything,
                           failure: "an expired credential was accepted")
        )
        results.append(
            await negative(.unknownResolvesToNil, fixtures.refusals.unknown, needs: [],
                           control: resolvesAnything,
                           failure: "an unrecognised credential returned a subject")
        )

        // The same proof, offered as a different kind. A store that compares values without
        // regard to kind lets a feed URL be used as an API key.
        //
        // The fixture supplies this when it can, because the suite cannot derive it for a kind
        // declared outside this package — which is the case `Credential` was made a protocol to
        // allow, and was reported as a gap until a real out-of-package store arrived and showed
        // that the gap was the suite's rather than the store's.
        if let crossed = fixtures.activeAsAnotherKind {
            results.append(
                await negative(.kindsDoNotCross, crossed, needs: [],
                               control: resolvesAnything,
                               failure: "the active subject's proof was accepted as another kind")
            )
        } else if let bearer = fixtures.active.credential as? BearerKey {
            results.append(
                await negative(.kindsDoNotCross, CapabilityToken(bearer.value), needs: [],
                               control: resolvesAnything,
                               failure: "a bearer value was accepted as a capability token")
            )
        } else {
            results.append(Result(requirement: .kindsDoNotCross, verdict: .gap,
                                  detail: "fixtures supplied neither a cross-kind credential nor a bearer to derive one"))
        }

        results.append(await indistinguishability(control: resolvesAnything))

        if fixtures.capabilities.contains(.externalIdentity), let external = fixtures.externalForActiveSubject {
            let viaProvider = await store.subject(for: external)
            results.append(check(.externalIdentityMapsToLocalID,
                                 viaProvider?.id == fixtures.active.id,
                                 "a provider subject resolved to '\(viaProvider?.id ?? "nothing")' "
                                 + "rather than the local id — durable records would be orphaned"))
        } else {
            results.append(Result(requirement: .externalIdentityMapsToLocalID, verdict: .notClaimed,
                                  detail: "no external identity claimed; untested until a provider is adopted"))
        }

        results.append(check(.attributesRoundTrip, active?.attributes == fixtures.active.attributes,
                             "attributes came back altered"))

        results.append(await honeypotReporting(control: resolvesAnything))
        // Before throttling, which deliberately leaves the active subject throttled: a
        // passphrase presented after it would be refused for that reason, not for its encoding.
        results.append(await canonicalPassphrases(control: resolvesAnything))
        results.append(await algorithmReporting())
        results.append(contentsOf: await throttling(control: resolvesAnything))
        return Report(results: results)
    }

    /// The fixture passphrase, presented composed and decomposed: both must resolve to the
    /// active subject. Judged first through the composed form, so a store that resolves neither
    /// is inconclusive rather than blamed for encoding.
    private func canonicalPassphrases(control resolvesAnything: Bool) async -> Result {
        let requirement = Requirement.canonicallyEquivalentPassphrasesMatch
        guard fixtures.capabilities.contains(.canonicalPassphrases) else {
            return Result(requirement: requirement, verdict: .notClaimed, detail: "not claimed")
        }
        // Claimed without the fixture that would test it: the claim can't be judged, which is
        // inconclusive. Not a gap: the protocol can express it; the fixtures didn't.
        guard let passphrase = fixtures.canonicalPassphrase else {
            return Result(requirement: requirement, verdict: .inconclusive,
                          detail: "claimed, but no canonicalPassphrase fixture was supplied")
        }
        let composed = passphrase.secret.precomposedStringWithCanonicalMapping
        let decomposed = passphrase.secret.decomposedStringWithCanonicalMapping
        guard Array(composed.unicodeScalars) != Array(decomposed.unicodeScalars) else {
            return Result(requirement: requirement, verdict: .inconclusive,
                          detail: "the fixture's secret encodes the same both ways, so it can't tell")
        }
        let viaComposed = await store.subject(for: Passphrase(subjectID: passphrase.subjectID, secret: composed))
        guard resolvesAnything, viaComposed?.id == fixtures.active.id else {
            return Result(requirement: requirement, verdict: .inconclusive,
                          detail: "the fixture passphrase didn't resolve even as given")
        }
        let viaDecomposed = await store.subject(for: Passphrase(subjectID: passphrase.subjectID, secret: decomposed))
        return check(requirement, viaDecomposed?.id == fixtures.active.id,
                     "the same passphrase, decomposed, was refused: the store compares raw bytes")
    }

    /// The algorithm reported for the active credential is the one the fixture names.
    private func algorithmReporting() async -> Result {
        let requirement = Requirement.algorithmIsReported
        guard fixtures.capabilities.contains(.algorithmRecords) else {
            return Result(requirement: requirement, verdict: .notClaimed, detail: "not claimed")
        }
        guard let expected = fixtures.active.algorithm else {
            return Result(requirement: requirement, verdict: .inconclusive,
                          detail: "claimed, but the active fixture names no algorithm")
        }
        let (resolution, algorithm) = await store.resolveVerifying(fixtures.active.credential)
        guard case .verified = resolution else {
            return Result(requirement: requirement, verdict: .inconclusive,
                          detail: "the active credential didn't resolve")
        }
        return check(requirement, algorithm == expected,
                     "reported \(algorithm ?? "no algorithm"), expected \(expected)")
    }

    /// A requirement that the store must *refuse* — meaningful only if it accepts something.
    private func negative(
        _ requirement: Requirement,
        _ credential: any Credential,
        needs capability: Capabilities,
        control resolvesAnything: Bool,
        failure: String
    ) async -> Result {
        guard capability.isEmpty || fixtures.capabilities.contains(capability) else {
            return Result(requirement: requirement, verdict: .notClaimed,
                          detail: "the store does not claim this behaviour")
        }
        let resolved = await store.subject(for: credential)
        guard resolved == nil else {
            return Result(requirement: requirement, verdict: .failed, detail: failure)
        }
        guard resolvesAnything else {
            return Result(
                requirement: requirement,
                verdict: .inconclusive,
                detail: "refused, but this store refuses everything — refusing this proves nothing"
            )
        }
        return Result(requirement: requirement, verdict: .passed, detail: "refused, and the store does resolve valid credentials")
    }

    /// Unknown, revoked and honeypot must be alike to the caller.
    ///
    /// Checked as a set rather than one at a time: the failure being guarded against is a store
    /// that returns *something different* for a subject that exists, which is only visible by
    /// comparing the answers to each other.
    private func indistinguishability(control resolvesAnything: Bool) async -> Result {
        let answers = [
            await store.subject(for: fixtures.refusals.unknown),
            await store.subject(for: fixtures.refusals.revoked),
            await store.subject(for: fixtures.refusals.honeypot),
        ]
        guard answers.allSatisfy({ $0 == nil }) else {
            return Result(requirement: .failuresAreIndistinguishable, verdict: .failed,
                          detail: "at least one refusal returned a subject, so the caller can tell them apart")
        }
        guard resolvesAnything else {
            return Result(requirement: .failuresAreIndistinguishable, verdict: .inconclusive,
                          detail: "all alike because all are refused — a store that resolves nothing is trivially uniform")
        }
        return Result(requirement: .failuresAreIndistinguishable, verdict: .passed,
                      detail: "all three refused identically, while valid credentials resolve")
    }

    /// A honeypot must be named to the service and invisible to the caller.
    ///
    /// Both halves matter and they pull in opposite directions, which is why this is one
    /// requirement rather than two: a store that hides the reason from everyone has no
    /// tripwire, and one that exposes it through `subject(for:)` has told an attacker which
    /// credentials are watched.
    private func honeypotReporting(control resolvesAnything: Bool) async -> Result {
        guard fixtures.capabilities.contains(.honeypot) else {
            return Result(requirement: .honeypotIsReportedToTheService, verdict: .notClaimed,
                          detail: "the store does not claim honeypots")
        }
        let resolution = await store.resolve(fixtures.refusals.honeypot)
        guard resolution == .refused(.honeypot) else {
            return Result(requirement: .honeypotIsReportedToTheService, verdict: .failed,
                          detail: "resolved as \(resolution), so the service cannot tell a tripwire "
                              + "from any other refusal — the leak would go unnoticed")
        }
        guard resolvesAnything else {
            return Result(requirement: .honeypotIsReportedToTheService, verdict: .inconclusive,
                          detail: "reported, but this store resolves nothing")
        }
        return Result(requirement: .honeypotIsReportedToTheService, verdict: .passed,
                      detail: "named to the service")
    }

    /// Repeated failure must be refused without the secret being checked.
    ///
    /// Gated behind the same positive control as the refusal requirements: a store that
    /// resolves nothing refuses a sixth attempt exactly as it refused the first, and calling
    /// that a throttling failure would blame it for the wrong thing.
    private func throttling(control resolvesAnything: Bool) async -> [Result] {
        guard fixtures.capabilities.contains(.throttling),
              let throttling = fixtures.throttling
        else {
            return [
                Result(requirement: .throttlingAfterRepeatedFailure, verdict: .notClaimed,
                       detail: "the store does not claim throttling"),
                Result(requirement: .throttlingIsPerSubject, verdict: .notClaimed,
                       detail: "the store does not claim throttling"),
            ]
        }

        guard resolvesAnything else {
            return [
                Result(requirement: .throttlingAfterRepeatedFailure, verdict: .inconclusive,
                       detail: "this store refuses everything, so a refusal after repeated failure "
                           + "says nothing about throttling"),
                Result(requirement: .throttlingIsPerSubject, verdict: .inconclusive,
                       detail: "this store resolves nothing for any subject"),
            ]
        }

        // One more than the threshold: the attempts up to it are answered normally, and the
        // next one must be refused unchecked.
        for _ in 0...throttling.threshold {
            _ = await store.resolve(throttling.wrongPassphrase)
        }
        let afterLimit = await store.resolve(throttling.wrongPassphrase)
        let throttled = afterLimit == .refused(.throttled)

        var results = [
            Result(
                requirement: .throttlingAfterRepeatedFailure,
                verdict: throttled ? .passed : .failed,
                detail: throttled
                    ? "refused unchecked after \(throttling.threshold) failures"
                    : "still answering \(afterLimit) after \(throttling.threshold + 2) failures — a guesser is unbounded"
            )
        ]

        // A throttle that stops everyone is a denial-of-service primitive handed to anyone who
        // knows a subject id.
        // A second subject is part of the throttling fixture rather than optional beside it,
        // so the isolation requirement can always be judged once throttling is claimed.
        do {
            let other = throttling.otherSubject
            let stillWorks = await store.subject(for: other) != nil
            results.append(
                Result(
                    requirement: .throttlingIsPerSubject,
                    verdict: stillWorks ? .passed : .failed,
                    detail: stillWorks
                        ? "another subject authenticates while this one is throttled"
                        : "another subject was locked out too — one person can shut out everyone else"
                )
            )
        }
        return results
    }

    private func check(_ requirement: Requirement, _ condition: Bool, _ failureDetail: String) -> Result {
        Result(
            requirement: requirement,
            verdict: condition ? .passed : .failed,
            detail: condition ? "as required" : failureDetail
        )
    }
}
