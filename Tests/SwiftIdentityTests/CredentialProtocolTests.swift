import Foundation
import Testing
@testable import SwiftIdentity

/// `Credential` as a protocol rather than a closed enum.
///
/// Chosen 2026-09-08 for the reason in §4b(5): a provider integration adding a kind we cannot
/// name today is a new type, where a new enum case would be source-breaking for every consumer
/// that switched over it.
///
/// The cost is that a store can no longer switch exhaustively, so the compiler stops saying
/// when a kind is unhandled. These tests are what replaces that guarantee.
@Suite("Credential as a protocol")
struct CredentialProtocolTests {

    @Test("each kind names itself, and the names are distinct")
    func kindsAreDistinct() {
        let kinds = [
            BearerKey.kind, CapabilityToken.kind, Passphrase.kind,
            SessionToken.kind, ExternalAssertion.kind,
        ]
        #expect(Set(kinds).count == kinds.count)
        #expect(BearerKey.kind == "bearer")
    }

    @Test("an instance reports its own kind without needing the type")
    func instanceReportsKind() {
        // Audit records carry the kind and must never carry the secret, so this has to be
        // reachable from a value the store is already holding.
        let credential: any Credential = BearerKey("secret")
        #expect(credential.kindName == "bearer")
    }

    @Test("a new kind is a new type, not a new case")
    func kindsAreOpen() {
        // The whole point of the protocol: this compiles without touching the package, which
        // is what keeps a provider integration from being a source break.
        struct HardwareToken: Credential {
            static let kind = "hardware-token"
            let serial: String
        }
        let credential: any Credential = HardwareToken(serial: "abc")
        #expect(credential.kindName == "hardware-token")
    }

    @Test("a passphrase carries the subject it claims to belong to")
    func passphraseCarriesSubject() {
        // Throttling is per-subject and a wrong passphrase identifies nobody on its own, so
        // there would be nothing to count failures against.
        let passphrase = Passphrase(subjectID: "ada", secret: "hunter2")
        #expect(passphrase.subjectID == "ada")
    }
}
