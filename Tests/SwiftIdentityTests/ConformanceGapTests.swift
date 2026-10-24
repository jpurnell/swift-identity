import Foundation
import Testing
@testable import SwiftIdentity
import SwiftIdentityConformance

/// That nothing in the suite is unverifiable any more.
///
/// It used to report three requirements the protocol could not express, which is a polite way
/// of saying the design had holes and the suite could not see into them. Two were closed by
/// making the refusal reason visible to the service — `Resolution` — and the third, timing, was
/// removed from the suite because a black-box test genuinely cannot measure it, and pretending
/// otherwise was the least honest thing in the file.
///
/// This suite exists to keep it that way: a new unverifiable requirement fails a test here.
@Suite("Conformance — nothing unverifiable remains")
struct ConformanceGapTests {

    private struct RecognisesNothing: CredentialStore {
        func resolve(_ credential: any Credential) async -> Resolution { .refused(.unknown) }
    }

    private static var fixtures: ConformanceSuite.Fixtures {
        .init(
            active: .init(id: "ada", credential: BearerKey("bearer-secret"), attributes: ["site": "north-house"]),
            refusals: .init(revoked: BearerKey("revoked-secret"), honeypot: CapabilityToken("leaked-share-link"), expired: SessionToken("expired-session"), unknown: BearerKey("never-issued"))
        )
    }

    @Test("no requirement is unverifiable through the protocol")
    func noGapsRemain() async {
        let report = await ConformanceSuite(store: RecognisesNothing(), fixtures: Self.fixtures).run()
        #expect(report.gaps.isEmpty, "\(report.summary)")
    }

    @Test("what a store does not offer is unclaimed, which is not the gracee as unverifiable")
    func capabilitiesAreNotGaps() async {
        let report = await ConformanceSuite(store: RecognisesNothing(), fixtures: Self.fixtures).run()
        let unclaimed = Set(report.results.filter { $0.verdict == .notClaimed }.map(\.requirement))

        // These fixtures claim neither an external identity nor throttling. That is a
        // declaration by the store, not a hole in the protocol — and the difference is the
        // reason `notClaimed` exists as a separate verdict.
        #expect(unclaimed.contains(.externalIdentityMapsToLocalID))
        #expect(unclaimed.contains(.throttlingAfterRepeatedFailure))
    }

    @Test("every requirement is reported — a suite that silently skips one is worse than no suite")
    func everyRequirementIsReported() async {
        let report = await ConformanceSuite(store: RecognisesNothing(), fixtures: Self.fixtures).run()
        #expect(Set(report.results.map(\.requirement)) == Set(ConformanceSuite.Requirement.allCases))
    }
}

/// The one property the suite cannot check, checked where it can be.
///
/// Timing is not observable from outside a store, so it is addressed by construction: an
/// implementer uses ``ConstantTime/equals(_:_:)`` rather than `==`. These tests are about that
/// helper being correct, which is the part that can be tested.
@Suite("ConstantTime")
struct ConstantTimeTests {

    @Test("equal sequences compare equal")
    func equal() {
        #expect(ConstantTime.equals([1, 2, 3, 4], [1, 2, 3, 4]))
    }

    @Test("P17: a difference anywhere is found, including in the last byte")
    func differsAtEnd() {
        #expect(!ConstantTime.equals([1, 2, 3, 4], [1, 2, 3, 5]))
        #expect(!ConstantTime.equals([1, 2, 3, 4], [9, 2, 3, 4]))
    }

    @Test("different lengths are unequal")
    func lengths() {
        #expect(!ConstantTime.equals([1, 2, 3], [1, 2, 3, 4]))
        #expect(ConstantTime.equals([], []))
    }
}
