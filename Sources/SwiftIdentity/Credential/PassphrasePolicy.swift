#if canImport(os)
import os
#endif
import Foundation

/// The NIST SP 800-63B-4 rules for choosing a passphrase.
///
/// Applied when a passphrase is set or changed, **never at sign-in**, where it would tell a
/// guesser what the rules are. ``evaluate(_:context:)`` returns every violation by name: NIST
/// requires the reason for a blocklist rejection to be given (§3.1.1.2), and a bare "invalid"
/// helps nobody choose better.
///
/// That doesn't break this package's rule that refusals stay private. That rule is about
/// verification, where a reason helps a guesser. Here the person is choosing their own secret.
///
/// ## Composition rules: PCI only
///
/// 800-63B-4 forbids composition rules (§3.1.1.2 item 5: "SHALL NOT impose other composition
/// rules"), so no property here can require character classes. The one exception is the
/// ``pciDSS4`` profile, because PCI DSS requires letters and digits and a deployment under PCI
/// has to meet it. **It isn't recommended for anything else**: under NIST it's a violation, and it
/// makes passphrases weaker, because people satisfy it predictably ("Password1"). It's reachable
/// only by choosing that profile; ``appliesPCIComposition`` can be read but not set.
public struct PassphrasePolicy: Sendable {

    /// Whether the passphrase is the only factor, or one of several.
    public enum FactorRole: Sendable, Hashable {
        /// The only factor: at least 15 characters.
        case sole
        /// Only ever used with another factor: at least 8.
        case partOfMultiFactor
    }

    /// One way a candidate passphrase falls short. Positions and counts, never the secret.
    public enum Violation: Error, Sendable, Hashable {
        /// More than ``PassphrasePolicy/maximumInputBytes`` of UTF-8. Checked first, alone.
        case tooManyBytes(maximum: Int)
        /// It can't be canonicalized.
        case refused(PassphraseCanonicalization.Refusal)
        /// Fewer code points than the minimum, counted after canonicalization.
        case tooShort(minimum: Int, actual: Int)
        /// More code points than the maximum.
        case tooLong(maximum: Int, actual: Int)
        /// On a blocklist, and which kind: the reason NIST requires to be given.
        case blocklisted(BlocklistReason)
        /// A blocklist couldn't answer, so the passphrase isn't accepted: an unchecked blocklist
        /// fails closed. The host can say "try again"; nothing about the passphrase is implied.
        case blocklistUnavailable(BlocklistReason)
        /// The ``PassphrasePolicy/pciDSS4`` profile only: PCI DSS requires both a letter and a
        /// digit. NIST forbids this rule; no other profile reports it.
        case pciRequiresLettersAndDigits
    }

    /// NIST SP 800-63B-4, as a sole factor, PBKDF2-HMAC-SHA256 at 600,000 rounds. The default.
    public static let nist80063B4 = PassphrasePolicy(
        factorRole: .sole, maximumLength: 256, maximumInputBytes: 1_024,
        blocklists: [BundledCommonPasswords(), ContextWords()],
        schemes: .standard, parameters: "\(PassphraseVerifier.defaultRounds)"
    )

    /// The same rules, with only FIPS-approved algorithms. PBKDF2 is approved; this profile
    /// never selects anything else. Approved algorithms aren't a validated module: see the DocC.
    public static let fips = PassphrasePolicy(
        factorRole: .sole, maximumLength: 256, maximumInputBytes: 1_024,
        blocklists: [BundledCommonPasswords(), ContextWords()],
        schemes: PassphraseSchemes([PBKDF2SHA256Legacy(), PBKDF2SHA256C1()], writing: PBKDF2SHA256C1()),
        parameters: "\(PassphraseVerifier.defaultRounds)"
    )

    /// PCI DSS v4.0.1, requirement 8.3.6: at least 12 characters, containing both alphabetic and
    /// numeric characters. Otherwise the NIST rules: blocklists, the byte cap, the maximum, and
    /// PBKDF2.
    ///
    /// **For PCI deployments only. Not recommended under NIST SP 800-63B-4**, which forbids
    /// composition rules (§3.1.1.2 item 5). It exists because PCI requires the rule, not because
    /// this package endorses it: a composition rule pushes people to predictable passphrases.
    ///
    /// What it doesn't cover, and why: requirement 8.3.4 (locking out after repeated failures)
    /// and 8.3.9 (changing a sole-factor password every 90 days) are a throttle's and a store's
    /// business, not a choosing policy's, and their exact wording is in PCI SSC's licensed text,
    /// which this package's sources couldn't quote. Set them with ``ThrottlePolicy`` and your
    /// own reissue schedule, against the standard itself. 8.3.6 here was checked against several
    /// secondary sources that agree; the standard itself is the authority.
    public static let pciDSS4: PassphrasePolicy = {
        var policy = PassphrasePolicy.nist80063B4
        policy.appliesPCIComposition = true
        policy.minimumOverride = 12
        return policy
    }()

    /// Whether this policy requires a letter and a digit. True only for ``pciDSS4``, and not
    /// settable: a NIST profile can't be made to apply a rule NIST forbids.
    public private(set) var appliesPCIComposition = false
    /// A minimum fixed by the profile rather than the factor role; PCI's 12.
    private var minimumOverride: Int?

    /// Whether this passphrase is a sole factor or part of multi-factor.
    public var factorRole: FactorRole
    /// The most code points accepted. At least 64 (§3.1.1.2 item 2).
    public var maximumLength: Int
    /// The most UTF-8 bytes looked at, checked before any other work.
    public var maximumInputBytes: Int
    /// Compared against the whole canonical passphrase, in order.
    public var blocklists: [any PassphraseBlocklist]
    /// The schemes accepted, and the one a new digest is written under.
    public var schemes: PassphraseSchemes
    /// The writing scheme's cost field.
    public var parameters: String
    /// Also compare an NFKC-folded copy against the blocklists, so "ｐａｓｓｗｏｒｄ" is refused like
    /// "password". Off by default. It changes what's refused, never what's hashed.
    public var foldsCompatibilityForBlocklist = false

    /// A policy. The profiles are the usual starting points.
    public init(
        factorRole: FactorRole, maximumLength: Int, maximumInputBytes: Int,
        blocklists: [any PassphraseBlocklist], schemes: PassphraseSchemes, parameters: String
    ) {
        self.factorRole = factorRole
        self.maximumLength = maximumLength
        self.maximumInputBytes = maximumInputBytes
        self.blocklists = blocklists
        self.schemes = schemes
        self.parameters = parameters
    }

    /// The fewest code points: 15 for a sole factor, 8 as part of multi-factor (§3.1.1.2 item 1);
    /// 12 under ``pciDSS4``.
    public var minimumLength: Int {
        if let minimumOverride { return minimumOverride }
        return switch factorRole {
        case .sole: 15
        case .partOfMultiFactor: 8
        }
    }

    /// The advice to show whoever is choosing (§3.1.1.2).
    public var guidance: PassphraseGuidance {
        PassphraseGuidance(minimumLength: minimumLength, requiresLettersAndDigits: appliesPCIComposition)
    }

    /// Every way `secret` falls short, in order; empty when it's acceptable.
    ///
    /// The byte cap is checked first and alone, before canonicalization or any blocklist does
    /// work: a request can't make this spend more than it allows.
    ///
    /// - Parameters:
    ///   - secret: The candidate, as typed.
    ///   - context: Words that mustn't be the passphrase: the subject's and the service's.
    /// - Returns: The violations.
    public func evaluate(_ secret: String, context: PolicyContext) async -> [Violation] {
        guard secret.utf8.count <= maximumInputBytes else { return [.tooManyBytes(maximum: maximumInputBytes)] }

        let canonical: String
        switch PassphraseCanonicalization.c1.canonicalize(secret) {
        case .success(let value): canonical = value
        case .failure(let refusal): return [.refused(refusal)]
        }

        var violations: [Violation] = []
        let length = canonical.unicodeScalars.count
        if length < minimumLength { violations.append(.tooShort(minimum: minimumLength, actual: length)) }
        if length > maximumLength { violations.append(.tooLong(maximum: maximumLength, actual: length)) }
        if appliesPCIComposition, !Self.hasLetterAndDigit(canonical) {
            violations.append(.pciRequiresLettersAndDigits)
        }

        let candidates = foldsCompatibilityForBlocklist
            ? [canonical, canonical.precomposedStringWithCompatibilityMapping]
            : [canonical]
        for blocklist in blocklists {
            if let violation = await Self.check(candidates, against: blocklist, context: context) {
                violations.append(violation)
            }
        }
        return violations
    }

    /// PCI's "alphabetic and numeric", in any script: a Unicode letter and a decimal digit.
    private static func hasLetterAndDigit(_ text: String) -> Bool {
        let scalars = text.unicodeScalars
        return scalars.contains(where: \.properties.isAlphabetic)
            && scalars.contains { $0.properties.generalCategory == .decimalNumber }
    }

    /// The violation one blocklist finds, if any. A blocklist that throws fails closed.
    private static func check(
        _ candidates: [String], against blocklist: any PassphraseBlocklist, context: PolicyContext
    ) async -> Violation? {
        do {
            for candidate in candidates where try await blocklist.contains(candidate, context: context) {
                return .blocklisted(blocklist.reason)
            }
            return nil
        } catch {
            // An operator needs to know a blocklist is down; the passphrase itself is never logged.
            #if canImport(os)
            Logger(subsystem: "org.roseclub.swiftidentity", category: "passphrase-policy")
                .error("blocklist \(String(describing: blocklist.reason), privacy: .public) unavailable: \(String(describing: error), privacy: .public)")
            #endif
            return .blocklistUnavailable(blocklist.reason)
        }
    }
}

/// Words that mustn't be the passphrase, because a guesser would try them first.
public struct PolicyContext: Sendable, Hashable {
    /// The subject choosing.
    public var subjectID: String
    /// The service's name.
    public var serviceName: String
    /// Anything else a guesser would know: a display name, a household's name.
    public var otherWords: [String]

    /// A context.
    public init(subjectID: String, serviceName: String, otherWords: [String] = []) {
        self.subjectID = subjectID
        self.serviceName = serviceName
        self.otherWords = otherWords
    }

    /// Every word, as given.
    var words: [String] { [subjectID, serviceName] + otherWords }
}

/// Which kind of blocklist refused a passphrase: the reason NIST requires to be given.
public enum BlocklistReason: Sendable, Hashable {
    /// Commonly used, or expected.
    case common
    /// Found in a breach corpus.
    case breached
    /// The subject's or the service's name, or a derivative of one.
    case context
}

/// A list a candidate passphrase is compared against, whole (§3.1.1.2: "not substrings or words
/// that might be contained therein").
public protocol PassphraseBlocklist: Sendable {
    /// Which kind of list this is.
    var reason: BlocklistReason { get }
    /// Whether the whole canonical passphrase is on it. Throws when the list can't answer,
    /// which refuses the passphrase as ``PassphrasePolicy/Violation/blocklistUnavailable(_:)``.
    func contains(_ canonical: String) async throws -> Bool
    /// Whether it's on it, given the context. Defaults to ``contains(_:)``.
    func contains(_ canonical: String, context: PolicyContext) async throws -> Bool
}

extension PassphraseBlocklist {
    /// Ignores the context.
    public func contains(_ canonical: String, context: PolicyContext) async throws -> Bool {
        try await contains(canonical)
    }
}

/// A fixed list of common passwords, compared without regard to case.
///
/// Whole-password comparison only, as §3.1.1.2 requires. Case is ignored because a common
/// password with a capital letter is still the first thing a guesser tries.
public struct CommonPasswords: PassphraseBlocklist {
    /// ``BlocklistReason/common``.
    public let reason = BlocklistReason.common
    /// How many entries the list holds.
    public var count: Int { entries.count }
    private let entries: Set<String>

    /// A list from entries you supply.
    ///
    /// - Parameter entries: The passwords, in any case.
    public init(entries: some Sequence<String>) {
        self.entries = Set(entries.map { $0.lowercased() })
    }

    /// The list this package ships: SecLists' 10,000 most common passwords, MIT licensed, compiled
    /// in. Its provenance is `scripts/COMMON-PASSWORDS.md`.
    ///
    /// Compiled in, not a resource: SwiftPM's resource accessor stops the process when its bundle
    /// isn't beside the binary, and a deployment that copies only its executable would crash at
    /// the first passphrase check.
    public static func bundled() -> CommonPasswords {
        CommonPasswords(entries: CommonPasswordsList.text.split(whereSeparator: \.isNewline).map(String.init))
    }

    /// Whether `canonical`, lowercased, is on the list.
    public func contains(_ canonical: String) async throws -> Bool {
        entries.contains(canonical.lowercased())
    }
}

/// Why a blocklist couldn't answer.
public enum BlocklistFailure: Error, Sendable, Hashable {
    /// The list couldn't be read.
    case unavailable
}

/// The bundled list, built once per process on first use.
///
/// The profiles hold this rather than the list itself, so the 10,000 entries are only parsed by
/// a process that checks a passphrase.
public struct BundledCommonPasswords: PassphraseBlocklist {
    /// ``BlocklistReason/common``.
    public let reason = BlocklistReason.common

    private static let loaded = CommonPasswords.bundled()

    /// The bundled list.
    public init() {}

    /// Whether `canonical` is on the bundled list.
    public func contains(_ canonical: String) async throws -> Bool {
        try await Self.loaded.contains(canonical)
    }
}

/// The subject's and the service's names, "and derivatives thereof" (§3.1.1.2).
///
/// A derivative here is the word itself with digits and punctuation added at either end, any
/// capitalization, or the word repeated. That's what a person reaches for when told their name
/// isn't allowed. It isn't substring matching: a phrase that merely contains the name is fine.
public struct ContextWords: PassphraseBlocklist {
    /// ``BlocklistReason/context``.
    public let reason = BlocklistReason.context

    /// The blocklist; its words come from each evaluation's ``PolicyContext``.
    public init() {}

    /// Always false: without a context there are no words.
    public func contains(_ canonical: String) async -> Bool { false }

    /// Whether `canonical` is a context word or a derivative of one.
    public func contains(_ canonical: String, context: PolicyContext) async -> Bool {
        let core = Self.core(canonical)
        guard !core.isEmpty else { return false }
        for word in context.words {
            let target = word.lowercased()
            guard !target.isEmpty else { continue }
            if core == target { return true }
            // The word repeated: "adaada".
            if core.count.isMultiple(of: target.count),
               core == String(repeating: target, count: core.count / target.count) {
                return true
            }
        }
        return false
    }

    /// Lowercased, with digits, punctuation and spaces trimmed from both ends.
    static func core(_ text: String) -> String {
        let decoration = CharacterSet.decimalDigits.union(.punctuationCharacters)
            .union(.symbols).union(.whitespaces)
        return text.lowercased().trimmingCharacters(in: decoration)
    }
}

/// What to tell someone choosing a passphrase (§3.1.1.2: verifiers "SHALL offer guidance").
public struct PassphraseGuidance: Sendable, Hashable {
    /// Plain sentences, for the host to show. This package renders nothing.
    public let lines: [String]

    init(minimumLength: Int, requiresLettersAndDigits: Bool = false) {
        var lines = [
            "Use at least \(minimumLength) characters. Length matters more than anything else.",
            "A few unrelated words make a passphrase that's long and easy to remember.",
            "A password manager is welcome: paste or autofill whatever it generates.",
            "Don't use your name, this service's name, or a password you've used elsewhere.",
            "Any characters are allowed, including spaces and other languages. Some devices type "
                + "some characters differently, so if you'll sign in from several, check that "
                + "yours look the same on each.",
        ]
        if requiresLettersAndDigits {
            lines.insert("Include at least one letter and one digit; this service's payment-card "
                + "rules require both.", at: 1)
        }
        self.lines = lines
    }

    /// The advice to show after a particular rejection.
    ///
    /// - Parameter violation: Why the last choice was refused.
    /// - Returns: One sentence.
    public func after(_ violation: PassphrasePolicy.Violation) -> String {
        switch violation {
        case .blocklisted:
            "That one is too easy to guess. Choose something different, not the same with a number "
                + "or symbol added."
        case .tooShort(let minimum, _):
            "Use at least \(minimum) characters. Adding a word is the easiest way."
        case .tooLong(let maximum, _):
            "Use at most \(maximum) characters."
        case .tooManyBytes:
            "That's longer than this service accepts."
        case .refused:
            "It contains a character that can't be used, such as a control character."
        case .blocklistUnavailable:
            "That couldn't be checked just now. Please try again."
        case .pciRequiresLettersAndDigits:
            "Include at least one letter and one digit."
        }
    }
}
