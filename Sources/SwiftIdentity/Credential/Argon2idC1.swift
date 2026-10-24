/// Argon2id over the canonical secret: `argon2id-c1`, an opt-in scheme.
///
/// **Not in ``PassphraseSchemes/standard``, and not NIST's.** NIST SP 800-63B-4 asks for a scheme
/// from SP 800-132, which is PBKDF2; Argon2id is OWASP's first choice, and a deployment that wants
/// it opts in with ``PassphrasePolicy/owasp``, or by building its own ``PassphraseSchemes``,
/// knowing it is leaving NIST's list. That profile is the only one this package ships that
/// selects it, and only since the amendment's gate passed (§9: the RFC vector, differential runs
/// against OpenSSL, phc-winner-argon2 and argon2-swift, timing within 2× of the reference, memory
/// bounded as configured).
///
/// The stored parameters are `m=<KiB>,t=<passes>,p=<lanes>`, in that order, each a canonical
/// decimal within ``Argon2id``'s bounds. Anything else doesn't decode, so a stored value can't ask
/// for more memory than ``Argon2id/maximumMemoryKiB``. The derivation is a 32-byte Argon2id tag
/// of the material with the stored salt, and no secret or associated data.
///
/// ```swift
/// let schemes = PassphraseSchemes([PBKDF2SHA256C1(), Argon2idC1()], writing: Argon2idC1())
/// var generator = SystemRandomNumberGenerator()
/// let verifier = try PassphraseVerifier(
///     for: Passphrase(subjectID: "ada", secret: "correct horse battery staple"),
///     using: &generator, parameters: "m=19456,t=2,p=1", schemes: schemes
/// )
/// ```
public struct Argon2idC1: PassphraseScheme {
    /// `argon2id-c1`.
    public let identifier = "argon2id-c1"
    /// ``PassphraseCanonicalization/c1``.
    public let canonicalization: PassphraseCanonicalization? = .c1

    /// The tag length, in bytes: the same as the PBKDF2 schemes' digest.
    static let tagLength = 32
    /// OWASP's recommended minimum memory, in KiB: 19 MiB.
    static let owaspMinimumMemoryKiB = 19_456
    /// OWASP's recommended minimum passes at that memory.
    static let owaspMinimumIterations = 2
    /// OWASP's recommended minimum as stored parameters: what ``PassphrasePolicy/owasp`` writes.
    static let owaspMinimumParameters = "m=\(owaspMinimumMemoryKiB),t=\(owaspMinimumIterations),p=1"

    /// The scheme, with no state of its own.
    public init() {}

    /// `m=<KiB>,t=<passes>,p=<lanes>`, canonical decimals that ``Argon2id`` accepts.
    public func isValid(parameters: String) -> Bool { Self.argon2(parameters) != nil }

    /// Argon2id, 32 bytes, of `material` with `salt`, at the stored parameters.
    public func derive(_ material: [UInt8], parameters: String, salt: [UInt8]) throws -> [UInt8] {
        guard let argon2 = Self.argon2(parameters) else { throw PassphraseVerifier.Failure.invalidParameters }
        return try argon2.hash(password: material, salt: salt, tagLength: Self.tagLength)
    }

    /// Below OWASP's recommended minimum, the cost ``PassphrasePolicy/owasp`` writes: less than
    /// 19,456 KiB of memory or fewer than 2 passes. Lanes don't count; they divide the work
    /// without reducing it. Parameters that don't decode count as below, so such a digest is
    /// never left as it is.
    public func isBelowCurrentCost(_ parameters: String) -> Bool {
        guard let argon2 = Self.argon2(parameters) else { return true }
        return argon2.memoryKiB < Self.owaspMinimumMemoryKiB || argon2.iterations < Self.owaspMinimumIterations
    }

    /// The parameters as an ``Argon2id``, or nil if they aren't exactly the stored form or are
    /// out of bounds.
    static func argon2(_ parameters: String) -> Argon2id? {
        let fields = parameters.split(separator: ",", omittingEmptySubsequences: false)
        guard fields.count == 3,
              let memory = value(fields[0], named: "m"),
              let iterations = value(fields[1], named: "t"),
              let lanes = value(fields[2], named: "p") else { return nil }
        return Argon2id.validated(memoryKiB: memory, iterations: iterations, parallelism: lanes)
    }

    /// The canonical decimal after `name=`: no sign, no leading zero, no separators, ASCII only.
    /// Canonical so that one cost has one stored form.
    private static func value(_ field: Substring, named name: String) -> Int? {
        let prefix = name + "="
        guard field.hasPrefix(prefix) else { return nil }
        let digits = field.dropFirst(prefix.count)
        guard let number = Int(digits), "\(number)" == digits else { return nil }
        return number
    }
}
