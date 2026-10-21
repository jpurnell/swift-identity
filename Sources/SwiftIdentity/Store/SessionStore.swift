import Crypto
import Foundation

/// A session as it is handed back at login: the secret once, and what a consumer must persist.
public struct MintedSession: Sendable, Equatable {
    /// The token to give the client. **Returned once and never stored in the clear** — the store
    /// keeps only a digest, so this value cannot be recovered from it later.
    public let token: SessionToken
    /// Who the session belongs to.
    public let subjectID: String
    /// When it lapses without anyone ending it.
    public let expires: Date
}

/// Sessions minted at login: short-lived, revocable, and never a durable identifier.
///
/// ## Separate from the credential store on purpose
///
/// §4b(4) of the design: a deployment that later adopts an identity provider takes its sessions
/// from the provider and its capability tokens from here. Fusing the two would give that
/// provider's single-logout nothing to propagate into.
///
/// ## Status is read at every resolution, never snapshotted
///
/// This is the property the type is shaped around. A session that carried a copy of its subject
/// taken at login would keep working after that subject was revoked, until it happened to lapse
/// — so "revoked" would mean "revoked, eventually, probably". Instead the roster is consulted on
/// every resolution, and revoking a subject ends their sessions without anyone ending them.
///
/// The cost is a lookup per request, which is the cheaper half of that trade.
///
/// ## In memory, and therefore per process
///
/// Sessions do not survive a restart, and several instances do not share them. For a deployment
/// where that is wrong, this type is what a database-backed one should behave like — the tests
/// beside it are the specification.
public actor SessionStore: CredentialStore {

    /// The fewest bytes a session token is drawn from.
    ///
    /// 16 bytes — 128 bits. A session token authenticates on its own, with no second factor and
    /// no subject named alongside it, so it must be a value nobody can enumerate.
    public static let tokenByteCount = 16

    /// One live session.
    private struct Record {
        let subjectID: String
        let expires: Date
    }

    private let subjects: @Sendable (String) async -> Subject?
    private let now: @Sendable () -> Date
    /// Keyed by digest. The token itself is never held, so a reader of this process's memory
    /// finds nothing it can present.
    private var records: [[UInt8]: Record] = [:]
    private let audit: (any IdentityAudit)?

    /// Creates a session store over a roster.
    ///
    /// - Parameters:
    ///   - subjects: Looks up the **current** subject for an id. Called on every resolution, so
    ///     that a revocation reaches sessions already minted.
    ///   - now: The clock, injected so expiry is testable without waiting.
    ///   - audit: Told the outcome of every resolution.
    ///
    ///     **This fires once per request**, because a session is resolved on every one. A
    ///     consumer wanting a record of sign-ins should take it where the session is *minted*,
    ///     not here; what this is good for is the refusals — a live session ending because its
    ///     subject was revoked is an event, and it happens at a resolution rather than at a
    ///     login. Nothing is filtered here, for the reason `FileCredentialStore` gives.
    public init(
        subjects: @escaping @Sendable (String) async -> Subject?,
        now: @escaping @Sendable () -> Date = { Date() },
        audit: (any IdentityAudit)? = nil
    ) {
        self.subjects = subjects
        self.now = now
        self.audit = audit
    }

    /// Mints a session.
    ///
    /// - Parameters:
    ///   - subjectID: Who the session is for. Not checked here — a caller mints only after
    ///     verifying something, and the subject's standing is checked at every resolution
    ///     anyway, including the first.
    ///   - lifetime: How long it lasts.
    ///   - generator: The source the token is drawn from. Supplied rather than chosen, for the
    ///     same reason as everywhere else here: a predictable session token is a forgeable one,
    ///     and a library that picks silently makes that decision invisible.
    /// - Returns: The session, carrying the only copy of its token.
    public func mint<Generator: RandomNumberGenerator>(
        for subjectID: String,
        lifetime: TimeInterval,
        using generator: inout Generator
    ) -> MintedSession {
        let bytes = (0..<Self.tokenByteCount).map { _ in
            UInt8.random(in: .min ... .max, using: &generator)
        }
        let value = Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")

        let token = SessionToken(value)
        let expires = now().addingTimeInterval(lifetime)
        records[Self.digest(of: value)] = Record(subjectID: subjectID, expires: expires)
        return MintedSession(token: token, subjectID: subjectID, expires: expires)
    }

    /// Resolves a session token to the subject it currently proves.
    ///
    /// - Parameter credential: The proof presented. Anything that is not a ``SessionToken`` is
    ///   refused: a session id must not be usable wherever an API key is accepted.
    /// - Returns: The subject, or why not.
    public func resolve(_ credential: any Credential) async -> Resolution {
        guard let session = credential as? SessionToken else {
            return await report(.unknown, nil, credential)
        }

        let presented = Self.digest(of: session.value)
        var matched: Record?
        // Scanned rather than looked up, so the work does not depend on where the answer lies.
        // A dictionary lookup would be faster and would leak that position through timing — the
        // same reasoning as `FileCredentialStore`. For a roster of household size this is
        // nothing; a deployment with many thousands of live sessions should measure it.
        for (digest, record) in records where ConstantTime.equals(digest, presented) {
            matched = record
        }
        guard let record = matched else { return await report(.unknown, nil, credential) }

        // Expiry before status: a lapsed session is not evidence about its subject.
        if record.expires <= now() {
            return await report(.expired, record.subjectID, credential)
        }

        guard let subject = await subjects(record.subjectID) else {
            // The roster no longer has them at all, which is a different thing from revoked and
            // is named as such: the session is real and its subject has been deleted.
            return await report(.unknown, record.subjectID, credential)
        }
        switch subject.status {
        case .revoked: return await report(.revoked, subject.id, credential)
        case .honeypot: return await report(.honeypot, subject.id, credential)
        case .active: return await report(.verified, subject.id, credential, verified: subject)
        }
    }

    /// Records the outcome and returns the resolution, so the two cannot disagree.
    ///
    /// Every exit from ``resolve(_:)`` goes through here, for the reason `FileCredentialStore`
    /// gives: recording at each `return` means an outcome added later that forgets to, and a
    /// missing audit line looks exactly like a thing that did not happen.
    private func report(
        _ outcome: IdentityEvent.Outcome,
        _ subjectID: String?,
        _ credential: any Credential,
        verified subject: Subject? = nil
    ) async -> Resolution {
        await audit?.record(IdentityEvent(
            outcome: outcome, subjectID: subjectID,
            credentialKind: credential.kindName, at: now()
        ))
        guard let subject else { return .refused(outcome) }
        return .verified(subject)
    }

    /// Ends one session.
    ///
    /// - Parameter token: The session to end. Unknown tokens are not an error — a caller
    ///   signing out twice should not have to care.
    public func revoke(_ token: SessionToken) {
        records.removeValue(forKey: Self.digest(of: token.value))
    }

    /// Ends every session belonging to a subject.
    ///
    /// What a consumer calls when someone changes their passphrase, or when an administrator
    /// wants a person out now rather than at the next lapse.
    ///
    /// - Parameter subjectID: Whose sessions to end.
    public func revokeAll(forSubject subjectID: String) {
        records = records.filter { $0.value.subjectID != subjectID }
    }

    /// Drops sessions that have lapsed.
    ///
    /// Expired sessions already resolve to nothing; this only stops them accumulating. Nothing
    /// calls it on a timer here, because when to sweep is a deployment's decision.
    ///
    /// - Returns: How many were removed.
    @discardableResult
    public func removeExpired() -> Int {
        let instant = now()
        let before = records.count
        records = records.filter { $0.value.expires > instant }
        return before - records.count
    }

    /// SHA-256 of a token value.
    ///
    /// A fast hash, deliberately, and for the same reason as ``BearerKey``: a session token is
    /// 128 bits of machine randomness, not something anyone will guess, so a work factor would
    /// be paid on every request to defend against nothing.
    private static func digest(of value: String) -> [UInt8] {
        Array(SHA256.hash(data: Data(value.utf8)))
    }
}
