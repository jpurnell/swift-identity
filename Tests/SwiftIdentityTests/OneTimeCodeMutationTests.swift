import Foundation
import SwiftDeterminism
import Testing
@testable import SwiftIdentity

/// What mutation testing found the one-time-code tests didn't pin down.
///
/// Each test here was written against a mutant that survived the existing suites
/// (`Harness/Mutation/REPORT.md`): it fails with that mutant applied and passes without it.
extension OneTimeCodeTests {

    @Test("parameters are valid only when both the digits and the step are")
    func validityNeedsBoth() {
        #expect(OneTimeCodeParameters(algorithm: .sha1, digits: 6, period: 30).isValid)
        #expect(!OneTimeCodeParameters(algorithm: .sha1, digits: 6, period: 0).isValid)
        #expect(!OneTimeCodeParameters(algorithm: .sha1, digits: 6, period: 121).isValid)
        #expect(!OneTimeCodeParameters(algorithm: .sha1, digits: 9, period: 30).isValid)
        #expect(!OneTimeCodeParameters(algorithm: .sha1, digits: 5, period: 30).isValid)
    }

    @Test("an SHA-512 key is the hash's output length: 512 bits")
    func sha512KeyLength() {
        #expect(OneTimeCodeParameters(algorithm: .sha512, digits: 6, period: 30).keyLength * 8 == 512)
    }

    @Test("a stored value with a stray separator is malformed")
    func strayStoredSeparator() throws {
        let sealing = try Self.sealingKey(seed: 41)
        var generator = SplitMix64(seed: 42)
        let verifier = try OneTimeCodeVerifier(for: "ada", using: &generator, sealingKey: sealing)
        #expect(OneTimeCodeVerifier(encoded: verifier.encoded, subjectID: "ada")?.encoded == verifier.encoded)
        #expect(OneTimeCodeVerifier(encoded: verifier.encoded + "$", subjectID: "ada") == nil)
        #expect(OneTimeCodeVerifier(encoded: "$" + verifier.encoded, subjectID: "ada") == nil)
    }

    @Test("the enrollment secret is unpadded Base32, even for a key whose length needs padding")
    func enrollmentSecretIsUnpadded() throws {
        let sealing = try Self.sealingKey(seed: 43)
        var generator = SplitMix64(seed: 44)
        let parameters = OneTimeCodeParameters(algorithm: .sha256, digits: 6, period: 30)
        let verifier = try OneTimeCodeVerifier(for: "ada", using: &generator, sealingKey: sealing, parameters: parameters)
        let uri = try verifier.enrollmentURI(issuer: "Household Vault", account: "ada", sealingKey: sealing)
        let items = try #require(URLComponents(string: uri)?.queryItems)
        let secret = try #require(items.first { $0.name == "secret" }?.value)
        // 32 bytes is 256 bits: 51.2 Base32 characters, so 52, which padding would round to 56.
        // Key URI format leaves padding out, and some apps refuse it.
        #expect(secret.count == 52)
        #expect(!secret.contains("="))
        #expect(secret == Base32.encode(try verifier.key(sealingKey: sealing), padded: false))
    }
}
