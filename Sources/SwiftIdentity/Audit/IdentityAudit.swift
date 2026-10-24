import Foundation

/// What happened, and to whom.
///
/// A protocol rather than a logger, so this package never decides what a log is. A household
/// wants a line in the system log; a commercial deployment wants rows in a table it can query;
/// a decision system wants neither, because a record of who read what is a record of a
/// household's reading habits and is not built casually.
public protocol IdentityAudit: Sendable {
    /// Records one verification attempt.
    func record(_ event: IdentityEvent) async
}

/// One verification attempt, described without ever naming the secret.
public struct IdentityEvent: Sendable, Equatable {

    /// How the attempt ended.
    ///
    /// `CaseIterable` so a consumer can prove its own classification of these is total —
    /// VaultMCP maps each to a log level and asserts that exactly one of them is loud enough to
    /// wake somebody. An exhaustive `switch` catches a new case at compile time; enumerating
    /// them is what lets a test say "and nothing else is a tripwire".
    public enum Outcome: String, Sendable, Equatable, CaseIterable {
        /// The credential proved an active subject.
        case verified
        /// Nothing matched.
        case unknown
        /// The subject exists and may not authenticate.
        case revoked
        /// A credential known to have leaked was presented. The interesting one.
        case honeypot
        /// The credential matched but its lifetime had run out.
        case expired
        /// Refused without being checked, because too many attempts had failed recently.
        case throttled
        /// Every credential presented together was valid, but they proved different subjects.
        ///
        /// Its own case rather than ``unknown`` (decided 2026-10-21): two valid credentials for
        /// two people, presented together, is an attack signal, and the audit should say so.
        case subjectMismatch
    }

    /// How it ended.
    public let outcome: Outcome
    /// The subject, when one was identified. Nil for ``Outcome/unknown``.
    public let subjectID: String?
    /// Which kind of proof was presented — never the proof itself.
    public let credentialKind: String
    /// When, supplied by the caller so this package reads no clock.
    public let at: Date
    /// The algorithm the store verified with, from the method's own registry (a passphrase
    /// scheme, a COSE or SSH algorithm), when it says. What makes "who still signs in with a
    /// classical key?" a query over the audit trail.
    public let algorithm: String?

    /// Creates an audit event.
    public init(outcome: Outcome, subjectID: String?, credentialKind: String, at: Date, algorithm: String? = nil) {
        self.outcome = outcome
        self.subjectID = subjectID
        self.credentialKind = credentialKind
        self.at = at
        self.algorithm = algorithm
    }
}
