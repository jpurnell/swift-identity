import Foundation

/// How strongly a subject was proven. Computed, never declared by a caller.
///
/// Ordered, and a struct so a level can be added between these without breaking anyone.
public struct Assurance: Sendable, Hashable, Comparable, Codable {
    /// The level's stable name.
    public let name: String
    let rank: Int

    /// One factor class, however many credentials.
    public static let singleFactor = Assurance(name: "single-factor", rank: 1)
    /// Two or more distinct factor classes, each resolving to the same subject.
    public static let multiFactor = Assurance(name: "multi-factor", rank: 2)
    /// Multi-factor, with at least one phishing-resistant credential.
    public static let phishingResistant = Assurance(name: "phishing-resistant", rank: 3)

    /// Lower is weaker.
    public static func < (lhs: Assurance, rhs: Assurance) -> Bool { lhs.rank < rhs.rank }
}

/// One credential that resolved: its kind, factor class, and the algorithm the store verified
/// it with. Names and identifiers only, never a value.
public struct VerifiedFactor: Sendable, Hashable, Codable {
    /// The credential's kind, such as `passphrase` or `webauthn`.
    public let kind: String
    /// Its factor class.
    public let factorClass: FactorClass
    /// An identifier from the method's own registry, never invented here: a passphrase scheme
    /// (`pbkdf2-sha256-c1`), an IANA COSE algorithm (`-7` for ES256, `-49` for ML-DSA-65), an
    /// SSH key type. Nil when the store doesn't say.
    public let algorithm: String?

    /// A verified factor.
    public init(kind: String, factorClass: FactorClass, algorithm: String?) {
        self.kind = kind
        self.factorClass = factorClass
        self.algorithm = algorithm
    }
}

/// The outcome of authenticating with one or more credentials.
public struct Authentication: Sendable, Equatable {
    /// The one subject every credential proved.
    public let subject: Subject
    /// The credentials that proved it, in the order presented.
    public let factors: [VerifiedFactor]
    /// How strongly, computed from ``factors``.
    public let assurance: Assurance
    /// When, from the authenticator's clock.
    public let at: Date
}

/// What authenticating produced, for the service: the reason stays here.
public enum AuthenticationResolution: Sendable, Equatable {
    /// Every credential proved the same active subject.
    case authenticated(Authentication)
    /// They didn't, and this is why. For the service, never the caller.
    case refused(IdentityEvent.Outcome)
}
