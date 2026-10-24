import SwiftDeterminism
import Testing
@testable import SwiftIdentity

/// `argon2id-c1`: Argon2id over the canonical secret, as an opt-in scheme.
///
/// It plugs in through ``PassphraseSchemes`` like any scheme from outside the package, and it
/// isn't in ``PassphraseSchemes/standard``: the `owasp` profile is the only one that selects it
/// (amendment §4.4, §9), and PBKDF2 stays the default.
@Suite("Argon2idC1")
struct Argon2idC1Tests {

    /// Small, so the suite stays fast unoptimized; the parameters are the scheme's to carry, not
    /// a recommendation.
    static let parameters = "m=64,t=1,p=1"
    static let schemes = PassphraseSchemes([PBKDF2SHA256C1(), Argon2idC1()], writing: Argon2idC1())

    @Test("its identifier and canonicalization")
    func identity() {
        #expect(Argon2idC1().identifier == "argon2id-c1")
        #expect(Argon2idC1().canonicalization == .c1)
    }

    @Test("it derives Argon2id, 32 bytes, of the material with the salt, and no secret or AD")
    func derivation() throws {
        let material = Array("ada|correct horse".utf8)
        let salt = [UInt8](repeating: 7, count: 16)
        let expected = try Argon2id(memoryKiB: 64, iterations: 1, parallelism: 1)
            .hash(password: material, salt: salt, tagLength: 32)
        #expect(try Argon2idC1().derive(material, parameters: Self.parameters, salt: salt) == expected)
    }

    @Test("parameters are m=<KiB>,t=<passes>,p=<lanes>, canonical decimal, in that order")
    func validParameters() {
        let scheme = Argon2idC1()
        #expect(scheme.isValid(parameters: "m=64,t=1,p=1"))
        #expect(scheme.isValid(parameters: "m=19456,t=2,p=1"))
        #expect(scheme.isValid(parameters: "m=1048576,t=32,p=16"))
    }

    @Test("anything else is refused: reordered, padded, signed, missing, extra, or out of bounds",
          arguments: [
              "", "m=64", "m=64,t=1", "m=64,t=1,p=1,", "m=64,t=1,p=1,x=2",
              "t=1,m=64,p=1", "m=64,p=1,t=1", "M=64,t=1,p=1", "m=64;t=1;p=1",
              "m=064,t=1,p=1", "m=+64,t=1,p=1", "m=-64,t=1,p=1", "m= 64,t=1,p=1", "m=64 ,t=1,p=1",
              "m=6_4,t=1,p=1", "m=0x40,t=1,p=1", "m=,t=1,p=1", "m=64,t=,p=1",
              "m=7,t=1,p=1", "m=31,t=1,p=4", "m=1048577,t=1,p=1", "m=64,t=0,p=1", "m=64,t=33,p=1",
              "m=64,t=1,p=0", "m=1024,t=1,p=17", "m=99999999999999999999999,t=1,p=1",
              "m=６４,t=1,p=1",
          ])
    func invalidParameters(_ parameters: String) {
        #expect(!Argon2idC1().isValid(parameters: parameters))
    }

    @Test("deriving with invalid parameters throws rather than guessing")
    func deriveRefusesInvalidParameters() {
        #expect(throws: PassphraseVerifier.Failure.invalidParameters) {
            try Argon2idC1().derive([1], parameters: "m=7,t=1,p=1", salt: [UInt8](repeating: 0, count: 16))
        }
    }

    @Test("it round-trips through PassphraseVerifier with a deployment's own schemes")
    func roundTrip() throws {
        var generator = SplitMix64(seed: 21)
        let verifier = try PassphraseVerifier(
            for: Passphrase(subjectID: "ada", secret: "cafe\u{301} au lait"),
            using: &generator, parameters: Self.parameters, schemes: Self.schemes
        )
        #expect(verifier.encoded.hasPrefix("argon2id-c1$m=64,t=1,p=1$"))
        #expect(verifier.digest.count == 32)

        let decoded = try #require(PassphraseVerifier(encoded: verifier.encoded, schemes: Self.schemes))
        #expect(decoded == verifier)
        // Canonicalized: the other encoding of é matches.
        #expect(decoded.matches(Passphrase(subjectID: "ada", secret: "caf\u{E9} au lait")))
        #expect(!decoded.matches(Passphrase(subjectID: "ada", secret: "cafe au lait")))
        #expect(!decoded.matches(Passphrase(subjectID: "grace", secret: "caf\u{E9} au lait")))
        // m=64, t=1 is far below OWASP's minimum, which is what the scheme now compares against.
        #expect(decoded.needsUpgrade(to: Self.schemes))
    }

    @Test("invalid parameters are refused at issuance")
    func issuanceRefusesInvalidParameters() {
        var generator = SplitMix64(seed: 22)
        #expect(throws: PassphraseVerifier.Failure.invalidParameters) {
            try PassphraseVerifier(
                for: Passphrase(subjectID: "ada", secret: "x"),
                using: &generator, parameters: "m=64,t=0,p=1", schemes: Self.schemes
            )
        }
    }

    @Test("and a stored value with parameters out of bounds doesn't decode")
    func decodingRefusesInvalidParameters() throws {
        #expect(PassphraseVerifier(encoded: "argon2id-c1$m=2097152,t=1,p=1$c2FsdA$ZGlnZXN0", schemes: Self.schemes) == nil)
        // The same value within bounds decodes, so it's the parameters being refused.
        let decoded = try #require(
            PassphraseVerifier(encoded: "argon2id-c1$m=64,t=1,p=1$c2FsdA$ZGlnZXN0", schemes: Self.schemes)
        )
        #expect(decoded.scheme.identifier == "argon2id-c1")
        #expect(decoded.parameters == "m=64,t=1,p=1")
    }

    @Test("the standard schemes don't accept it: PBKDF2 stays the default")
    func notStandard() throws {
        #expect(!PassphraseSchemes.standard.accepts("argon2id-c1"))
        #expect(PassphraseSchemes.standard.writing.identifier == "pbkdf2-sha256-c1")

        var generator = SplitMix64(seed: 23)
        let verifier = try PassphraseVerifier(
            for: Passphrase(subjectID: "ada", secret: "x"),
            using: &generator, parameters: Self.parameters, schemes: Self.schemes
        )
        #expect(PassphraseVerifier(encoded: verifier.encoded) == nil)
        #expect(PassphraseVerifier(encoded: verifier.encoded, schemes: .standard) == nil)
    }
}
