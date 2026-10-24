import Foundation

/// Resolves several credentials and requires that they prove one subject.
///
/// ## The rules
///
/// - Every credential must resolve, and all to the same ``Subject/id``. One refusal refuses the
///   whole set.
/// - A subject mismatch is refused **and audited**: two valid credentials for two people,
///   presented together, is an attack signal, not an accident.
/// - Assurance is computed, never declared. Multi-factor needs two *distinct* factor classes, so
///   two passphrases are still single-factor. Phishing-resistant additionally needs one
///   credential whose kind says so.
///
/// ## Several authenticators at the ceiling
///
/// Every credential in a set is checked, even after one is refused, so each throttled one is
/// counted for the attempt it was part of. Then, if any of them is disabled, all of them are
/// (§3.2.2: "both authenticators SHALL be disabled"), through ``FailureThrottle/disableTogether(_:)``.
/// That needs the `throttle` the stores share, and stores that say which key each credential
/// counts under (``ThrottlingCredentialStore``).
///
/// ## Multi-step methods
///
/// A passkey assertion answers a challenge the server issued first. The method's package issues
/// and remembers the challenge, and what reaches this type is the finished assertion: one
/// credential, resolved like any other. So this stays a struct; what varies between deployments
/// is the stores it's given.
public struct Authenticator: Sendable {
    private let stores: [any CredentialStore]
    private let audit: (any IdentityAudit)?
    private let now: @Sendable () -> Date
    private let throttle: FailureThrottle?

    /// An authenticator over `stores`.
    ///
    /// - Parameters:
    ///   - stores: Asked in order. The first that recognizes a credential answers for it: any
    ///     answer but ``IdentityEvent/Outcome/unknown`` counts as recognizing it.
    ///   - audit: Where a subject mismatch is recorded. Each store audits its own resolutions.
    ///   - now: The clock, injected so this package reads none.
    ///   - throttle: The throttle the stores count failures in, so authenticators presented
    ///     together are disabled together. Nil when no store throttles.
    public init(
        stores: [any CredentialStore], audit: (any IdentityAudit)?, now: @escaping @Sendable () -> Date,
        throttle: FailureThrottle? = nil
    ) {
        self.stores = stores
        self.audit = audit
        self.now = now
        self.throttle = throttle
    }

    /// For the service: the outcome, including why it was refused.
    ///
    /// - Parameter credentials: Everything presented, in order.
    /// - Returns: The authentication, or the reason it was refused.
    public func authenticate(_ credentials: [any Credential]) async -> AuthenticationResolution {
        guard !credentials.isEmpty else { return .refused(.unknown) }

        var subjects: [Subject] = []
        var factors: [VerifiedFactor] = []
        var refusal: IdentityEvent.Outcome?
        var keys: [ThrottleKey] = []
        // All of them, not stopping at the first refusal: each throttled one must be counted for
        // the attempt it was part of, or a guesser could shield one authenticator behind another.
        for credential in credentials {
            let (resolution, algorithm, key) = await resolve(credential)
            if let key { keys.append(key) }
            switch resolution {
            case .verified(let subject): subjects.append(subject)
            case .refused(let outcome): refusal = refusal ?? outcome
            }
            factors.append(VerifiedFactor(
                kind: credential.kindName, factorClass: credential.factorClassValue, algorithm: algorithm
            ))
        }
        if let throttle, keys.count > 1 {
            _ = await throttle.disableTogether(keys)
        }
        if let refusal { return .refused(refusal) }

        guard let subject = subjects.first, subjects.allSatisfy({ $0.id == subject.id }) else {
            await audit?.record(IdentityEvent(
                outcome: .subjectMismatch, subjectID: nil,
                credentialKind: credentials.map(\.kindName).joined(separator: "+"), at: now()
            ))
            return .refused(.subjectMismatch)
        }

        let assurance = Self.assurance(factors: factors, credentials: credentials)
        return .authenticated(Authentication(subject: subject, factors: factors, assurance: assurance, at: now()))
    }

    /// The first store's answer that isn't "unknown", or unknown; and the throttle key the
    /// credential was counted under, by the first store that throttles it.
    private func resolve(_ credential: any Credential) async -> (Resolution, String?, ThrottleKey?) {
        var key: ThrottleKey?
        for store in stores {
            let answer = await store.resolveVerifying(credential)
            if key == nil, let throttling = store as? any ThrottlingCredentialStore {
                key = await throttling.throttleKey(for: credential)
            }
            if answer.0 != .refused(.unknown) { return (answer.0, answer.algorithm, key) }
        }
        return (.refused(.unknown), nil, key)
    }

    /// Distinct factor classes decide multi-factor; one phishing-resistant kind lifts it further.
    static func assurance(factors: [VerifiedFactor], credentials: [any Credential]) -> Assurance {
        guard Set(factors.map(\.factorClass)).count >= 2 else { return .singleFactor }
        return credentials.contains(where: \.isPhishingResistantValue) ? .phishingResistant : .multiFactor
    }
}

extension Authenticator {
    /// For the caller: an ``Authentication`` or nothing.
    ///
    /// In an extension, so it's statically dispatched and can't be overridden to leak a reason,
    /// the same construction as ``CredentialStore/subject(for:)``.
    ///
    /// - Parameter credentials: Everything presented.
    /// - Returns: The authentication, or nil.
    public func authentication(for credentials: [any Credential]) async -> Authentication? {
        guard case .authenticated(let authentication) = await authenticate(credentials) else { return nil }
        return authentication
    }
}
