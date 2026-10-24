import SwiftDeterminism
import Testing
@testable import SwiftIdentity

/// The `owasp` profile: 800-63B-4's rules with an Argon2id derivation, opted into.
///
/// It exists because the amendment's gate (§9) passed: the RFC vector, differential cases from
/// OpenSSL, phc-winner-argon2 and argon2-swift, timing within 2× of the reference, and memory
/// bounded as configured. It changes the derivation and nothing else, and it changes nothing
/// about the other profiles: PBKDF2 stays the default.
@Suite("PassphrasePolicy — owasp")
struct PassphrasePolicyOWASPTests {

    @Test("it writes argon2id-c1 at OWASP's minimum: m=19456 KiB, t=2, p=1")
    func writesArgon2id() {
        let policy = PassphrasePolicy.owasp
        #expect(policy.schemes.writing.identifier == "argon2id-c1")
        #expect(policy.parameters == "m=19456,t=2,p=1")
        #expect(policy.schemes.writing.isValid(parameters: policy.parameters))
    }

    @Test("it accepts the legacy scheme, pbkdf2-sha256-c1 and argon2id-c1, so existing digests verify")
    func accepts() {
        let schemes = PassphrasePolicy.owasp.schemes
        #expect(schemes.accepts("pbkdf2-sha256"))
        #expect(schemes.accepts("pbkdf2-sha256-c1"))
        #expect(schemes.accepts("argon2id-c1"))
    }

    @Test("every 800-63B-4 rule is the NIST profile's: lengths, byte cap, factor role, blocklists")
    func sameRules() {
        let owasp = PassphrasePolicy.owasp
        let nist = PassphrasePolicy.nist80063B4
        #expect(owasp.factorRole == nist.factorRole)
        #expect(owasp.minimumLength == nist.minimumLength)
        #expect(owasp.maximumLength == nist.maximumLength)
        #expect(owasp.maximumInputBytes == nist.maximumInputBytes)
        #expect(owasp.foldsCompatibilityForBlocklist == nist.foldsCompatibilityForBlocklist)
        #expect(owasp.blocklists.map(\.reason) == nist.blocklists.map(\.reason))
        #expect(owasp.blocklists.map { "\(type(of: $0))" } == nist.blocklists.map { "\(type(of: $0))" })
        #expect(owasp.guidance == nist.guidance)
    }

    @Test("and it refuses what the NIST profile refuses, for the same reasons",
          arguments: ["password1234567890", "short", "ada-ada-ada-ada!", "correct horse battery staple"])
    func sameVerdicts(_ secret: String) async {
        let context = PolicyContext(subjectID: "ada-ada-ada-ada", serviceName: "roseclub")
        let owasp = await PassphrasePolicy.owasp.evaluate(secret, context: context)
        let nist = await PassphrasePolicy.nist80063B4.evaluate(secret, context: context)
        #expect(owasp == nist)
    }

    @Test("a verifier it makes verifies, and is written under argon2id-c1 at its parameters")
    func verifierVerifies() throws {
        let policy = PassphrasePolicy.owasp
        var generator = SplitMix64(seed: 31)
        let verifier = try PassphraseVerifier(
            for: Passphrase(subjectID: "ada", secret: "cafe\u{301} au lait, twice over"),
            using: &generator, parameters: policy.parameters, schemes: policy.schemes
        )
        #expect(verifier.encoded.hasPrefix("argon2id-c1$m=19456,t=2,p=1$"))

        let decoded = try #require(PassphraseVerifier(encoded: verifier.encoded, schemes: policy.schemes))
        #expect(decoded.matches(Passphrase(subjectID: "ada", secret: "caf\u{E9} au lait, twice over")))
        #expect(!decoded.matches(Passphrase(subjectID: "ada", secret: "cafe au lait, twice over")))
        #expect(!decoded.needsUpgrade(to: policy.schemes))
        // The other profiles don't accept what it wrote.
        #expect(PassphraseVerifier(encoded: verifier.encoded, schemes: PassphrasePolicy.nist80063B4.schemes) == nil)
        #expect(PassphraseVerifier(encoded: verifier.encoded, schemes: PassphrasePolicy.fips.schemes) == nil)
    }

    @Test("a PBKDF2 digest from the NIST profile still verifies under it, and is upgraded to Argon2id")
    func pbkdf2Upgrades() throws {
        var generator = SplitMix64(seed: 32)
        let nist = PassphrasePolicy.nist80063B4
        let verifier = try PassphraseVerifier(
            for: Passphrase(subjectID: "ada", secret: "correct horse battery staple"),
            using: &generator, parameters: nist.parameters, schemes: nist.schemes
        )
        let decoded = try #require(PassphraseVerifier(encoded: verifier.encoded, schemes: PassphrasePolicy.owasp.schemes))
        #expect(decoded.matches(Passphrase(subjectID: "ada", secret: "correct horse battery staple")))
        #expect(decoded.needsUpgrade(to: PassphrasePolicy.owasp.schemes))
    }

    @Test("the NIST and FIPS profiles, and the standard schemes, still write PBKDF2 and refuse Argon2id")
    func othersUnchanged() {
        for policy in [PassphrasePolicy.nist80063B4, .fips] {
            #expect(policy.schemes.writing.identifier == "pbkdf2-sha256-c1")
            #expect(policy.parameters == "\(PassphraseVerifier.defaultRounds)")
            #expect(!policy.schemes.accepts("argon2id-c1"))
        }
        #expect(PassphraseSchemes.standard.writing.identifier == "pbkdf2-sha256-c1")
        #expect(!PassphraseSchemes.standard.accepts("argon2id-c1"))
    }
}

/// When an `argon2id-c1` digest costs less than the `owasp` profile now asks for.
@Suite("Argon2idC1 — current cost")
struct Argon2idC1CostTests {

    @Test("below OWASP's minimum, m < 19456 KiB or t < 2, is below the current cost",
          arguments: ["m=19455,t=2,p=1", "m=19456,t=1,p=1", "m=64,t=1,p=1", "m=65536,t=1,p=4", "m=4096,t=3,p=1"])
    func below(_ parameters: String) {
        #expect(Argon2idC1().isBelowCurrentCost(parameters))
    }

    @Test("at or above it is not, whatever the lanes",
          arguments: ["m=19456,t=2,p=1", "m=19456,t=2,p=4", "m=65536,t=3,p=4", "m=47104,t=2,p=1"])
    func atOrAbove(_ parameters: String) {
        #expect(!Argon2idC1().isBelowCurrentCost(parameters))
    }

    @Test("parameters that don't decode are below it: such a digest is never left as it is")
    func undecodable() {
        #expect(Argon2idC1().isBelowCurrentCost(""))
        #expect(Argon2idC1().isBelowCurrentCost("m=19456;t=2;p=1"))
    }
}
