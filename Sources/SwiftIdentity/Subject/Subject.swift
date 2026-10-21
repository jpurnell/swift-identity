import Foundation

/// Who is asking.
///
/// A subject outlives every credential that proves it and every token issued for it. That is
/// the whole reason this type exists rather than being read off a token: consumers write
/// ``id`` into durable records, and those records have to keep meaning something after the
/// credential is rotated, the provider is changed, or the person leaves.
public struct Subject: Sendable, Equatable, Identifiable {

    /// Whether a subject is a person or a machine.
    ///
    /// Not decoration. A record attributing work to a *service* is honest when a shared device
    /// is all the system authenticated; the same record naming a person would be a guess.
    public enum Kind: String, Sendable, Codable {
        case person
        case service
    }

    /// Whether a subject may authenticate at all, checked on every verification.
    public enum Status: String, Sendable, Codable {
        /// Verifies normally.
        case active
        /// Never verifies. The subject stays in the roster so that historical records naming
        /// it remain readable — deleting the subject would orphan them.
        case revoked
        /// Never verifies, and says so loudly.
        ///
        /// For a credential known to have leaked: mint a replacement, mark the old value
        /// `honeypot`, and the question "has anyone found it?" starts producing answers. It
        /// must never return data, because a honeypot that serves something is a breach.
        case honeypot
    }

    /// Chosen here and stable forever — what consumers write into durable records.
    public let id: String
    /// How an external provider's subject maps onto this one.
    ///
    /// Empty until an identity provider is adopted. Its presence from the start is what makes
    /// that adoption a configuration change rather than a data migration: the provider's
    /// opaque `sub` resolves to *this* `id`, and every record written before the switch still
    /// names the same subject.
    public let externalIdentities: Set<ExternalIdentity>
    /// Person or service.
    public let kind: Kind
    /// Whether this subject may authenticate.
    public let status: Status
    /// Consumer-defined claims, never interpreted here.
    ///
    /// A tier means something to a vault and nothing to an SEO service. The moment this package
    /// understands one of these keys it has begun to become that consumer's authorization
    /// system, which is the thing it is defined not to be.
    public let attributes: [String: String]

    /// Creates a subject.
    /// - Parameters:
    ///   - id: The stable local identifier.
    ///   - kind: Person or service.
    ///   - status: Whether it may authenticate. Defaults to ``Status/active``.
    ///   - externalIdentities: Provider subjects that map onto this one.
    ///   - attributes: Consumer-defined claims.
    public init(
        id: String,
        kind: Kind,
        status: Status = .active,
        externalIdentities: Set<ExternalIdentity> = [],
        attributes: [String: String] = [:]
    ) {
        self.id = id
        self.kind = kind
        self.status = status
        self.externalIdentities = externalIdentities
        self.attributes = attributes
    }
}

/// A subject as an external provider knows it.
///
/// Issuer-scoped, because a `sub` is only unique within the issuer that minted it.
public struct ExternalIdentity: Sendable, Hashable, Codable {
    /// The issuer, e.g. `https://example.eu.auth0.com/`.
    public let issuer: String
    /// The provider's opaque subject identifier.
    public let subject: String

    /// Creates an external identity.
    public init(issuer: String, subject: String) {
        self.issuer = issuer
        self.subject = subject
    }
}
