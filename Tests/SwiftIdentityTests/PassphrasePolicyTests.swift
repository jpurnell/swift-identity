import Testing
@testable import SwiftIdentity

/// The rules for choosing a passphrase, applied when one is set or changed.
///
/// Never at sign-in: a policy checked at verification tells a guesser what the rules are. And
/// never a bare "invalid": NIST requires the reason for a blocklist rejection, and every other
/// violation is named too.
@Suite("PassphrasePolicy")
struct PassphrasePolicyTests {

    static let context = PolicyContext(subjectID: "ada", serviceName: "vault")

    /// A blocklist that knows a fixed set, for tests.
    struct Fixed: PassphraseBlocklist {
        let reason: BlocklistReason
        let entries: Set<String>
        func contains(_ canonical: String) async -> Bool { entries.contains(canonical) }
    }

    static func policy(
        role: PassphrasePolicy.FactorRole = .sole,
        blocklists: [any PassphraseBlocklist] = []
    ) -> PassphrasePolicy {
        var policy = PassphrasePolicy.nist80063B4
        policy.factorRole = role
        policy.blocklists = blocklists
        return policy
    }

    // MARK: - Length

    @Test("P1: a sole factor needs 15 characters")
    func soleFactorMinimum() async {
        let policy = Self.policy(role: .sole)
        #expect(await policy.evaluate(String(repeating: "x", count: 14), context: Self.context)
            == [.tooShort(minimum: 15, actual: 14)])
        #expect(await policy.evaluate("correct horse battery", context: Self.context) == [])
    }

    @Test("P1: part of multi-factor, 8")
    func multiFactorMinimum() async {
        let policy = Self.policy(role: .partOfMultiFactor)
        #expect(await policy.evaluate("seven77", context: Self.context) == [.tooShort(minimum: 8, actual: 7)])
        #expect(await policy.evaluate("eight888", context: Self.context) == [])
    }

    @Test("P5: length counts code points, after canonicalization")
    func lengthCountsCodePoints() async {
        let policy = Self.policy(role: .partOfMultiFactor)
        // 👨‍👩‍👧 is one grapheme and five code points; NIST counts code points.
        let family = "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}"
        #expect(await policy.evaluate(family, context: Self.context) == [.tooShort(minimum: 8, actual: 5)])
        // "e" + combining acute is two code points typed, one after NFC.
        let decomposed = String(repeating: "e\u{301}", count: 7)
        #expect(await policy.evaluate(decomposed, context: Self.context) == [.tooShort(minimum: 8, actual: 7)])
    }

    @Test("P2: at least 64 characters are accepted, and the maximum is 256")
    func maximumLength() async {
        let policy = Self.policy()
        #expect(policy.maximumLength >= 64)
        #expect(await policy.evaluate(String(repeating: "a", count: 64) + "b", context: Self.context) == [])
        #expect(await policy.evaluate(String(repeating: "ab", count: 128), context: Self.context) == [])
        #expect(await policy.evaluate(String(repeating: "ab", count: 128) + "c", context: Self.context)
            == [.tooLong(maximum: 256, actual: 257)])
    }

    @Test("over 1 KiB is refused before anything else looks at it")
    func byteCapComesFirst() async {
        let policy = Self.policy(blocklists: [Fixed(reason: .common, entries: [])])
        // 300 four-byte scalars: 1,200 bytes. Refused on bytes alone, before canonicalization
        // or a blocklist, so the reply says nothing else about it.
        let big = String(repeating: "\u{1F600}", count: 300)
        #expect(await policy.evaluate(big, context: Self.context) == [.tooManyBytes(maximum: 1_024)])
    }

    // MARK: - Characters

    @Test("P3: no composition rule can be expressed, and none is applied")
    func noCompositionRules() async {
        let policy = Self.policy()
        // All lower case, no digits, no symbols: fine.
        #expect(await policy.evaluate("correcthorsebatterystaple", context: Self.context) == [])
        // All digits: fine on composition (length is what matters).
        #expect(await policy.evaluate("381947265019283746", context: Self.context) == [])
    }

    @Test("P4: printing ASCII, space and Unicode are accepted")
    func everyPrintingCharacterIsAccepted() async {
        let policy = Self.policy(role: .partOfMultiFactor)
        let ascii = String((0x20...0x7E).compactMap(Unicode.Scalar.init).map(Character.init))
        #expect(await policy.evaluate(ascii, context: Self.context) == [])
        #expect(await policy.evaluate("pässwörd für straße 🔑", context: Self.context) == [])
    }

    @Test("a control character is named by position")
    func controlsAreViolations() async {
        let policy = Self.policy(role: .partOfMultiFactor)
        #expect(await policy.evaluate("abcd\u{0}efgh", context: Self.context)
            == [.refused(.controlCharacter(position: 4))])
    }

    // MARK: - Blocklists

    @Test("P8, P19: a common password is refused, and the reason says so")
    func commonPasswordsAreRefusedWithAReason() async {
        let policy = Self.policy(blocklists: [Fixed(reason: .common, entries: ["passwordpassword1"])])
        #expect(await policy.evaluate("passwordpassword1", context: Self.context) == [.blocklisted(.common)])
    }

    @Test("P8: the whole password is compared, never words inside it")
    func wholePasswordOnly() async {
        let policy = Self.policy(blocklists: [Fixed(reason: .common, entries: ["password"])])
        #expect(await policy.evaluate("password in a longer phrase", context: Self.context) == [])
    }

    @Test("P8: the blocklist sees the canonical form")
    func blocklistSeesCanonicalForm() async {
        let policy = Self.policy(blocklists: [Fixed(reason: .common, entries: ["caf\u{E9}caf\u{E9}caf\u{E9}caf\u{E9}"])])
        #expect(await policy.evaluate(String(repeating: "cafe\u{301}", count: 4), context: Self.context)
            == [.blocklisted(.common)])
    }

    @Test("P8, P19: context words and their derivatives are refused, as context")
    func contextWords() async {
        let policy = Self.policy(role: .partOfMultiFactor, blocklists: [ContextWords()])
        let context = PolicyContext(subjectID: "adalovelace", serviceName: "householdvault")
        #expect(await policy.evaluate("adalovelace", context: context) == [.blocklisted(.context)])
        #expect(await policy.evaluate("AdaLovelace1!", context: context) == [.blocklisted(.context)])
        #expect(await policy.evaluate("householdvault2026", context: context) == [.blocklisted(.context)])
        #expect(await policy.evaluate("adalovelaceadalovelace", context: context) == [.blocklisted(.context)])
        // A phrase that merely contains one isn't a derivative of it.
        #expect(await policy.evaluate("ada sails the lovelace", context: context) == [])
    }

    @Test("P8: the bundled list holds the common passwords, all 10,001 of them")
    func bundledCommonPasswords() async throws {
        let list = CommonPasswords.bundled()
        #expect(list.count == 10_001)
        #expect(list.reason == .common)
        #expect(try await list.contains("password"))
        #expect(try await list.contains("qwerty123"))
        // Case doesn't make a common password uncommon.
        #expect(try await list.contains("PassWord"))
        #expect(try await !list.contains("correct horse battery staple"))
    }

    @Test("P8, P19: the NIST profile refuses a common password, as common")
    func nistProfileUsesTheBundledList() async {
        var policy = PassphrasePolicy.nist80063B4
        policy.factorRole = .partOfMultiFactor
        #expect(await policy.evaluate("password1", context: Self.context) == [.blocklisted(.common)])
        #expect(await policy.evaluate("vault123", context: Self.context) == [.blocklisted(.context)])
    }

    /// A blocklist that can't answer: a breach service that's down, a missing resource.
    struct Unreachable: PassphraseBlocklist {
        struct Down: Error {}
        let reason = BlocklistReason.breached
        func contains(_ canonical: String) async throws -> Bool { throw Down() }
    }

    @Test("a blocklist that can't answer refuses, rather than being skipped")
    func unavailableBlocklistFailsClosed() async {
        let policy = Self.policy(blocklists: [Unreachable()])
        #expect(await policy.evaluate("correct horse battery staple", context: Self.context)
            == [.blocklistUnavailable(.breached)])
    }

    @Test("an NFKC-folded copy is compared too, only when asked")
    func compatibilityFoldingForTheBlocklist() async {
        var policy = Self.policy(blocklists: [Fixed(reason: .common, entries: ["passwordpassword1"])])
        let fullwidth = "\u{FF50}\u{FF41}\u{FF53}\u{FF53}\u{FF57}\u{FF4F}\u{FF52}\u{FF44}"
            + "\u{FF50}\u{FF41}\u{FF53}\u{FF53}\u{FF57}\u{FF4F}\u{FF52}\u{FF44}1"
        #expect(await policy.evaluate(fullwidth, context: Self.context) == [])
        policy.foldsCompatibilityForBlocklist = true
        #expect(await policy.evaluate(fullwidth, context: Self.context) == [.blocklisted(.common)])
    }

    @Test("every violation is reported, in order, not just the first")
    func everyViolationIsReported() async {
        let policy = Self.policy(blocklists: [Fixed(reason: .common, entries: ["short"])])
        #expect(await policy.evaluate("short", context: Self.context)
            == [.tooShort(minimum: 15, actual: 5), .blocklisted(.common)])
    }

    // MARK: - Guidance

    @Test("P20, P21: guidance is offered, including that devices may differ")
    func guidanceIsOffered() {
        let guidance = PassphrasePolicy.nist80063B4.guidance
        #expect(guidance.lines.count >= 3)
        #expect(guidance.lines.contains { $0.contains("15") })
        #expect(guidance.lines.contains { $0.localizedCaseInsensitiveContains("password manager") })
        #expect(guidance.lines.contains { $0.localizedCaseInsensitiveContains("device") })
    }

    @Test("guidance after a blocklist rejection discourages a trivial change")
    func guidanceAfterRejection() {
        let advice = PassphrasePolicy.nist80063B4.guidance.after(.blocklisted(.common))
        #expect(advice.localizedCaseInsensitiveContains("different"))
        #expect(!advice.isEmpty)
    }

    // MARK: - Profiles

    @Test("P14b: the NIST and FIPS profiles write PBKDF2 at today's cost")
    func profilesWritePBKDF2() {
        for policy in [PassphrasePolicy.nist80063B4, .fips] {
            #expect(policy.schemes.writing.identifier == "pbkdf2-sha256-c1")
            #expect(policy.parameters == "\(PassphraseVerifier.defaultRounds)")
        }
    }

    // MARK: - PCI DSS

    @Test("the PCI profile requires 12 characters with letters and digits (PCI DSS 4.0.1 §8.3.6)")
    func pciComposition() async {
        let policy = PassphrasePolicy.pciDSS4
        #expect(policy.minimumLength == 12)
        let context = PolicyContext(subjectID: "ada", serviceName: "vault")
        #expect(await policy.evaluate("correcthorsebattery", context: context) == [.pciRequiresLettersAndDigits])
        #expect(await policy.evaluate("381947265019283746", context: context) == [.pciRequiresLettersAndDigits])
        #expect(await policy.evaluate("correct horse 7 battery", context: context) == [])
        // Any script's letters and digits count, not only ASCII.
        #expect(await policy.evaluate("пароль слон 4 мост", context: context) == [])
        #expect(await policy.evaluate("short7", context: context) == [.tooShort(minimum: 12, actual: 6)])
    }

    @Test("P3: no NIST or FIPS profile can be made to apply the PCI rule")
    func compositionIsPCIOnly() async {
        // The rule isn't a public property, so it can't be switched on in a NIST profile; the
        // only way to it is choosing `pciDSS4`.
        for var policy in [PassphrasePolicy.nist80063B4, .fips] {
            policy.factorRole = .partOfMultiFactor
            #expect(!policy.appliesPCIComposition)
            #expect(await policy.evaluate("allletterslong", context: Self.context) == [])
        }
        #expect(PassphrasePolicy.pciDSS4.appliesPCIComposition)
    }

    @Test("the PCI profile's guidance says what it requires")
    func pciGuidance() {
        let lines = PassphrasePolicy.pciDSS4.guidance.lines
        #expect(lines.contains { $0.contains("12") })
        #expect(lines.contains { $0.localizedCaseInsensitiveContains("letter") && $0.localizedCaseInsensitiveContains("digit") })
        #expect(PassphrasePolicy.pciDSS4.guidance.after(.pciRequiresLettersAndDigits).localizedCaseInsensitiveContains("digit"))
    }

    @Test("P1: both profiles default to a sole factor, 15 characters")
    func profilesDefaultToSoleFactor() {
        #expect(PassphrasePolicy.nist80063B4.minimumLength == 15)
        #expect(PassphrasePolicy.fips.minimumLength == 15)
    }
}
