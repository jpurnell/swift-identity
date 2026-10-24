import Foundation
import Testing
@testable import SwiftIdentity

/// Several credentials, one subject, and a computed statement of how strongly it was proven.
@Suite("Authenticator")
struct AuthenticatorTests {

    static let instant = Date(timeIntervalSince1970: 1_800_000_000)

    /// A credential of a phishing-resistant kind, standing in for a passkey assertion.
    struct Assertion: Credential, Equatable {
        static let kind = "test-assertion"
        static let isPhishingResistant = true
        let value: String
    }

    /// A store that knows a fixed table, and the algorithm it verified each one with.
    struct TableStore: CredentialStore {
        let table: [String: (Resolution, String?)]

        func resolve(_ credential: any Credential) async -> Resolution {
            await resolveVerifying(credential).0
        }

        func resolveVerifying(_ credential: any Credential) async -> (Resolution, algorithm: String?) {
            guard let entry = table[Self.key(credential)] else { return (.refused(.unknown), nil) }
            return (entry.0, algorithm: entry.1)
        }

        static func key(_ credential: any Credential) -> String {
            switch credential {
            case let passphrase as Passphrase: "passphrase:\(passphrase.subjectID):\(passphrase.secret)"
            case let bearer as BearerKey: "bearer:\(bearer.value)"
            case let assertion as Assertion: "assertion:\(assertion.value)"
            default: "other"
            }
        }
    }

    /// Records audit events.
    actor Recorder: IdentityAudit {
        var events: [IdentityEvent] = []
        func record(_ event: IdentityEvent) async { events.append(event) }
    }

    static let ada = Subject(id: "ada", kind: .person)
    static let grace = Subject(id: "grace", kind: .person)

    static let store = TableStore(table: [
        "passphrase:ada:right": (.verified(ada), "pbkdf2-sha256-c1"),
        "passphrase:ada:second": (.verified(ada), "pbkdf2-sha256-c1"),
        "bearer:ada-key": (.verified(ada), nil),
        "bearer:grace-key": (.verified(grace), nil),
        "bearer:revoked-key": (.refused(.revoked), nil),
        "assertion:ada-passkey": (.verified(ada), "-7"),
    ])

    static func authenticator(_ audit: Recorder? = nil) -> Authenticator {
        Authenticator(stores: [store], audit: audit, now: { instant })
    }

    // MARK: - Factor classes

    @Test("a passphrase is knowledge; everything else defaults to possession")
    func factorClasses() {
        #expect(Passphrase.factorClass == .knowledge)
        #expect(BearerKey.factorClass == .possession)
        #expect(SessionToken.factorClass == .possession)
        #expect(Assertion.factorClass == .possession)
        #expect(!Passphrase.isPhishingResistant)
        #expect(Assertion.isPhishingResistant)
    }

    @Test("the factor class is read through an existential, not the static default")
    func factorClassIsDynamic() {
        let credential: any Credential = Passphrase(subjectID: "ada", secret: "x")
        #expect(credential.factorClassValue == .knowledge)
    }

    @Test("assurance levels are ordered")
    func assuranceIsOrdered() {
        #expect(Assurance.singleFactor < .multiFactor)
        #expect(Assurance.multiFactor < .phishingResistant)
    }

    // MARK: - Assurance is computed

    @Test("one credential is single-factor")
    func oneIsSingleFactor() async throws {
        let result = await Self.authenticator().authenticate([Passphrase(subjectID: "ada", secret: "right")])
        guard case .authenticated(let authentication) = result else {
            Issue.record("expected authentication, got \(result)")
            return
        }
        #expect(authentication.subject == Self.ada)
        #expect(authentication.assurance == .singleFactor)
        #expect(authentication.at == Self.instant)
        #expect(authentication.factors == [VerifiedFactor(kind: "passphrase", factorClass: .knowledge, algorithm: "pbkdf2-sha256-c1")])
    }

    @Test("knowledge and possession for one subject is multi-factor")
    func twoClassesAreMultiFactor() async {
        let result = await Self.authenticator().authenticate([
            Passphrase(subjectID: "ada", secret: "right"), BearerKey("ada-key"),
        ])
        guard case .authenticated(let authentication) = result else {
            Issue.record("expected authentication, got \(result)")
            return
        }
        #expect(authentication.assurance == .multiFactor)
        #expect(authentication.factors.map(\.kind) == ["passphrase", "bearer"])
    }

    @Test("two passphrases are still single-factor: assurance is computed, not counted")
    func twoOfOneClassIsSingleFactor() async {
        let result = await Self.authenticator().authenticate([
            Passphrase(subjectID: "ada", secret: "right"), Passphrase(subjectID: "ada", secret: "second"),
        ])
        guard case .authenticated(let authentication) = result else {
            Issue.record("expected authentication, got \(result)")
            return
        }
        #expect(authentication.assurance == .singleFactor)
    }

    @Test("multi-factor with a phishing-resistant credential is phishing-resistant")
    func phishingResistant() async {
        let result = await Self.authenticator().authenticate([
            Passphrase(subjectID: "ada", secret: "right"), Assertion(value: "ada-passkey"),
        ])
        guard case .authenticated(let authentication) = result else {
            Issue.record("expected authentication, got \(result)")
            return
        }
        #expect(authentication.assurance == .phishingResistant)
        #expect(authentication.factors.last?.algorithm == "-7")
    }

    @Test("a phishing-resistant credential alone is still single-factor")
    func phishingResistantAloneIsSingleFactor() async {
        let result = await Self.authenticator().authenticate([Assertion(value: "ada-passkey")])
        guard case .authenticated(let authentication) = result else {
            Issue.record("expected authentication, got \(result)")
            return
        }
        #expect(authentication.assurance == .singleFactor)
    }

    // MARK: - Refusals

    @Test("one refusal refuses the whole set, with its reason, for the service")
    func oneRefusalRefusesAll() async {
        let result = await Self.authenticator().authenticate([
            Passphrase(subjectID: "ada", secret: "right"), BearerKey("revoked-key"),
        ])
        #expect(result == .refused(.revoked))
        let wrong = await Self.authenticator().authenticate([
            BearerKey("ada-key"), Passphrase(subjectID: "ada", secret: "wrong"),
        ])
        #expect(wrong == .refused(.unknown))
    }

    @Test("no credentials prove nothing")
    func emptyIsRefused() async {
        #expect(await Self.authenticator().authenticate([]) == .refused(.unknown))
    }

    @Test("credentials for two subjects are refused as a mismatch, and audited")
    func subjectMismatch() async {
        let recorder = Recorder()
        let result = await Self.authenticator(recorder).authenticate([
            Passphrase(subjectID: "ada", secret: "right"), BearerKey("grace-key"),
        ])
        #expect(result == .refused(.subjectMismatch))
        let events = await recorder.events
        #expect(events == [IdentityEvent(
            outcome: .subjectMismatch, subjectID: nil, credentialKind: "passphrase+bearer", at: Self.instant
        )])
    }

    @Test("P18: the caller gets an Authentication or nothing, never a reason")
    func callerSeesNoReason() async {
        let authenticator = Self.authenticator()
        #expect(await authenticator.authentication(for: [BearerKey("grace-key"), BearerKey("ada-key")]) == nil)
        #expect(await authenticator.authentication(for: [BearerKey("revoked-key")]) == nil)
        let ok = await authenticator.authentication(for: [BearerKey("ada-key")])
        #expect(ok?.subject == Self.ada)
    }

    // MARK: - Stores

    @Test("the first store that recognizes a credential answers for it")
    func firstRecognizingStoreAnswers() async {
        let empty = TableStore(table: [:])
        let authenticator = Authenticator(stores: [empty, Self.store], audit: nil, now: { Self.instant })
        let result = await authenticator.authenticate([BearerKey("ada-key")])
        guard case .authenticated(let authentication) = result else {
            Issue.record("expected authentication, got \(result)")
            return
        }
        #expect(authentication.subject == Self.ada)
        // A store that refuses for a specific reason has recognized it: no later store is asked.
        let revoking = TableStore(table: ["bearer:ada-key": (.refused(.revoked), nil)])
        let ordered = Authenticator(stores: [revoking, Self.store], audit: nil, now: { Self.instant })
        #expect(await ordered.authenticate([BearerKey("ada-key")]) == .refused(.revoked))
    }

    @Test("a store that doesn't override resolveVerifying reports no algorithm")
    func defaultResolveVerifying() async {
        struct Plain: CredentialStore {
            func resolve(_ credential: any Credential) async -> Resolution { .verified(AuthenticatorTests.ada) }
        }
        let (resolution, algorithm) = await Plain().resolveVerifying(BearerKey("x"))
        #expect(resolution == .verified(Self.ada))
        #expect(algorithm == nil)
    }

    @Test("an audit event can carry the algorithm")
    func eventsCarryAlgorithms() {
        let event = IdentityEvent(
            outcome: .verified, subjectID: "ada", credentialKind: "passphrase", at: Self.instant,
            algorithm: "pbkdf2-sha256-c1"
        )
        #expect(event.algorithm == "pbkdf2-sha256-c1")
        #expect(IdentityEvent(outcome: .verified, subjectID: "ada", credentialKind: "bearer", at: Self.instant).algorithm == nil)
        #expect(IdentityEvent.Outcome.allCases.contains(.subjectMismatch))
    }
}
