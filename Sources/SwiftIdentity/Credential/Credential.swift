import Foundation

/// A proof that someone is a subject.
///
/// A protocol rather than a closed enum, decided 2026-09-08. The kinds below are not the whole
/// set — a provider integration will want one nobody has named yet, and under an enum that is a
/// new case, which is source-breaking for every consumer that switched over it. Under a
/// protocol it is a new type in the consumer's own package, and nothing here has to move.
///
/// **What that costs, and who pays it.** A store can no longer switch exhaustively, so the
/// compiler stops saying when a kind is unhandled. The risk lands entirely on the store, and
/// the conformance suite is what replaces the guarantee: it asserts that a credential of one
/// kind never resolves as another, which is the failure an unhandled kind would produce.
///
/// The kinds are not interchangeable, and their differences are the reason this package exists:
/// two of them belong to clients that cannot use a browser at all, and exactly one is guessable.
public protocol Credential: Sendable {

    /// A stable name for this kind of proof.
    ///
    /// The discriminator that keeps a calendar feed's URL from being accepted as an API key: a
    /// store matches on kind **and** value, never on value alone. It also appears in audit
    /// records, which is why it is a name rather than a type identifier — a mangled Swift type
    /// name in a log is noise, and it changes when the type is moved.
    static var kind: String { get }

    /// What kind of evidence this is. Defaults to ``FactorClass/possession``, which is what every
    /// generated secret here is; ``Passphrase`` says ``FactorClass/knowledge``.
    ///
    /// A requirement with a default, not an extension member, so it's read through `any
    /// Credential` correctly. An extension-only member would answer the default for every
    /// existential, and assurance would be computed from the wrong class.
    static var factorClass: FactorClass { get }

    /// Whether the credential is bound to an origin or channel, so a phishing site can't relay
    /// it. Defaults to false. A WebAuthn assertion is true.
    static var isPhishingResistant: Bool { get }
}

extension Credential {
    /// This credential's kind, reachable from a value a store is already holding.
    public var kindName: String { Self.kind }

    /// ``FactorClass/possession``.
    public static var factorClass: FactorClass { .possession }

    /// False.
    public static var isPhishingResistant: Bool { false }

    /// This credential's factor class, reachable from a value.
    public var factorClassValue: FactorClass { Self.factorClass }

    /// Whether this credential's kind is phishing-resistant, reachable from a value.
    public var isPhishingResistantValue: Bool { Self.isPhishingResistant }
}

/// A generated key, presented in a header.
///
/// Verified against a hash with **no work factor**, deliberately. A slow KDF defends a
/// *guessable* secret; 256 bits of machine-generated randomness is not guessable, and the cost
/// would be paid on every request to defend against nothing. Written here so that a later
/// reader does not "fix" it.
public struct BearerKey: Credential, Equatable {
    /// This kind's stable name.
    public static let kind = "bearer"
    /// The presented key.
    public let value: String

    /// Wraps a presented key.
    public init(_ value: String) { self.value = value }
}

/// A token carried in a URL, for clients that cannot send a header at all.
///
/// A calendar client subscribing to an `.ics` feed is the motivating case, and it is a
/// permanent property of that client rather than a gap to be closed later. The URL *is* the
/// credential, so it needs enough entropy that guessing is hopeless, one per subscriber so
/// revoking one does not break everyone, and an awareness that it will end up in logs and in
/// browser history.
public struct CapabilityToken: Credential, Equatable {
    /// This kind's stable name.
    public static let kind = "capability"
    /// The token as it appears in the URL.
    public let value: String

    /// Wraps a presented token.
    public init(_ value: String) { self.value = value }
}

/// A human-chosen secret — the only kind a person could plausibly guess, and therefore the only
/// kind that needs a slow KDF and a failure counter.
public struct Passphrase: Credential, Equatable {
    /// This kind's stable name.
    public static let kind = "passphrase"
    /// Something the subject knows.
    public static let factorClass = FactorClass.knowledge
    /// Who the passphrase claims to belong to.
    ///
    /// Carried because throttling is per-subject, and a wrong passphrase identifies nobody on
    /// its own — there would be nothing to count failures against. A login form has a username
    /// field for the same reason.
    public let subjectID: String
    /// The presented secret.
    public let secret: String

    /// Wraps a presented passphrase and the subject it claims.
    public init(subjectID: String, secret: String) {
        self.subjectID = subjectID
        self.secret = secret
    }
}

/// Minted at login: short-lived, revocable, and never a durable identifier.
public struct SessionToken: Credential, Equatable {
    /// This kind's stable name.
    public static let kind = "session"
    /// The opaque session identifier.
    public let value: String

    /// Wraps a presented session token.
    public init(_ value: String) { self.value = value }
}

/// A subject claim asserted by an external issuer.
///
/// The kind an identity provider resolves to, once one is adopted. It carries the issuer as
/// well as the subject, because a `sub` is only unique within the issuer that minted it.
public struct ExternalAssertion: Credential, Equatable {
    /// This kind's stable name.
    public static let kind = "external"
    /// The provider's subject, scoped to its issuer.
    public let identity: ExternalIdentity

    /// Wraps an asserted external identity.
    public init(_ identity: ExternalIdentity) { self.identity = identity }
}
