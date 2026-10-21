import SwiftIdentityConformance
import Testing
@testable import SwiftIdentity

/// The suite has to judge "kinds do not cross" for a kind it has never heard of.
///
/// That is the whole point of ``Credential`` being a protocol: a consumer declares its own kind,
/// in its own package. The suite cannot re-wrap such a value — only the implementer knows what
/// "the same proof, offered as something else" means for it — so the fixture supplies it.
///
/// Reported as a gap until a real out-of-package store arrived and showed the gap was the
/// suite's rather than the store's.
@Suite("Conformance — a credential kind declared outside this package")
struct CrossKindFixtureTests {

    /// A kind that does not exist in this package, standing in for a consumer's own.
    struct DeviceAttestation: Credential, Equatable {
        static let kind = "device-attestation"
        let value: String
    }

    /// Recognises exactly one `DeviceAttestation`, and nothing else — the correct behaviour.
    struct RecognisesOneKind: CredentialStore {
        let accepted: String
        func resolve(_ credential: any Credential) async -> Resolution {
            guard let attestation = credential as? DeviceAttestation,
                  attestation.value == accepted else {
                return .refused(.unknown)
            }
            return .verified(Subject(id: "ada", kind: .person))
        }
    }

    /// Matches on the value and ignores the kind — how a feed URL becomes an API key.
    struct IgnoresTheKind: CredentialStore {
        let accepted: String
        func resolve(_ credential: any Credential) async -> Resolution {
            let value: String?
            switch credential {
            case let attestation as DeviceAttestation: value = attestation.value
            case let bearer as BearerKey: value = bearer.value
            default: value = nil
            }
            guard value == accepted else { return .refused(.unknown) }
            return .verified(Subject(id: "ada", kind: .person))
        }
    }

    static func fixtures(crossed: (any Credential)?) -> ConformanceSuite.Fixtures {
        .init(
            capabilities: [],
            active: .init(id: "ada", credential: DeviceAttestation(value: "proof")),
            refusals: .init(
                revoked: DeviceAttestation(value: "revoked"),
                honeypot: DeviceAttestation(value: "honeypot"),
                expired: DeviceAttestation(value: "expired"),
                unknown: DeviceAttestation(value: "unknown")
            ),
            activeAsAnotherKind: crossed
        )
    }

    @Test("without a cross-kind fixture the requirement is a gap, and says which fixture is missing")
    func withoutTheFixtureItIsAGap() async {
        let report = await ConformanceSuite(
            store: RecognisesOneKind(accepted: "proof"),
            fixtures: Self.fixtures(crossed: nil)
        ).run()

        let result = report.results.first { $0.requirement == .kindsDoNotCross }
        #expect(result?.verdict == .gap)
    }

    @Test("with one supplied, a correct store is judged and passes")
    func withTheFixtureACorrectStorePasses() async {
        let report = await ConformanceSuite(
            store: RecognisesOneKind(accepted: "proof"),
            fixtures: Self.fixtures(crossed: BearerKey("proof"))
        ).run()

        let result = report.results.first { $0.requirement == .kindsDoNotCross }
        #expect(result?.verdict == .passed, "\(report.summary)")
    }

    @Test("and a store that matches on value alone is caught — which is why the fixture exists")
    func withTheFixtureABrokenStoreFails() async {
        let report = await ConformanceSuite(
            store: IgnoresTheKind(accepted: "proof"),
            fixtures: Self.fixtures(crossed: BearerKey("proof"))
        ).run()

        let result = report.results.first { $0.requirement == .kindsDoNotCross }
        #expect(result?.verdict == .failed, "\(report.summary)")
        #expect(!report.isConformant)
    }
}
