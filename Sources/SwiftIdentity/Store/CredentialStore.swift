import Foundation

/// What resolving a credential produced.
///
/// The reason a credential was refused exists here and **stops here**. It is available to the
/// service holding the store — which needs it to audit a tripwire, count a failure, or explain
/// itself in a log — and never to the remote caller, who gets an optional from
/// ``CredentialStore/subject(for:)`` and cannot tell one refusal from another.
///
/// That split is the whole point. An earlier draft returned `Subject?` from the protocol
/// itself, which made ``Subject/Status/honeypot`` a value that could be stored and never
/// observed: a tripwire with no wire.
public enum Resolution: Sendable, Equatable {
    /// The credential proved an active subject.
    case verified(Subject)
    /// It did not, and this is why — for the service's ears only.
    case refused(IdentityEvent.Outcome)
}

/// How many failures a subject may accumulate before attempts are refused unchecked, and the
/// ceiling at which an authenticator is disabled.
///
/// Applies to ``Passphrase`` alone. Throttling a 256-bit
/// generated key defends against nothing an attacker could ever exhaust, and buys a mechanism
/// that can itself be used to deny service.
///
/// **Backoff, then a ceiling.** Below ``ceiling`` this is backoff, not lockout: a lockout is a
/// denial-of-service primitive handed to anyone who knows a subject id — in a household, that
/// is one person shutting another out of the boiler instructions. At the ceiling it is a
/// lockout, because NIST SP 800-63B-4 §3.2.2 requires one: "no more than 100" consecutive
/// failures, "by disabling that authenticator". That trade was decided on 2026-10-21 (§15.1 of
/// the assurance amendment) and the risk it accepts is stated there.
public struct ThrottlePolicy: Sendable, Equatable {
    /// Failures tolerated before refusing unchecked.
    public let threshold: Int
    /// How long a subject stays throttled once the threshold is crossed.
    public let backoff: TimeInterval
    /// Consecutive failures at which the authenticator is disabled until it is rebound.
    public let ceiling: Int

    /// NIST's limit, and the default: "no more than 100" consecutive failures (§3.2.2).
    public static let nistCeiling = 100

    /// Why a policy was refused.
    public enum Failure: Error, Equatable {
        /// The ceiling was outside `1...100`. Above 100 is out of compliance; below 1 would
        /// disable an authenticator before anyone had used it.
        case ceilingOutOfRange(Int)
    }

    /// Creates a policy with NIST's ceiling of 100.
    ///
    /// - Parameters:
    ///   - threshold: Failures tolerated before refusing unchecked.
    ///   - backoff: The first penalty once the threshold is crossed; it doubles from there.
    public init(threshold: Int, backoff: TimeInterval) {
        self.threshold = threshold
        self.backoff = backoff
        self.ceiling = Self.nistCeiling
    }

    /// Creates a policy with a ceiling of your own, no looser than NIST's.
    ///
    /// - Parameters:
    ///   - threshold: Failures tolerated before refusing unchecked.
    ///   - backoff: The first penalty once the threshold is crossed; it doubles from there.
    ///   - ceiling: Consecutive failures that disable the authenticator, in `1...100`.
    /// - Throws: ``Failure/ceilingOutOfRange(_:)``. Thrown rather than clamped: a deployment
    ///   that asked for 200 and silently got 100 has a policy it never read.
    public init(threshold: Int, backoff: TimeInterval, ceiling: Int) throws {
        guard (1...Self.nistCeiling).contains(ceiling) else { throw Failure.ceilingOutOfRange(ceiling) }
        self.threshold = threshold
        self.backoff = backoff
        self.ceiling = ceiling
    }

    /// Five attempts, then a minute — slow enough to make guessing pointless against a
    /// passphrase with any entropy, short enough that a person who mistyped theirs is not
    /// locked out of their own house. Disabled at 100.
    public static let standard = ThrottlePolicy(threshold: 5, backoff: 60)

    /// When attempts may resume after this many consecutive failures, the latest at `time`, or
    /// nil if none is owed.
    ///
    /// Doubles per failure past the threshold, capped at ``FailureThrottle/maximumBackoff``.
    /// Shared by every ledger, so the arithmetic is written once.
    ///
    /// - Parameters:
    ///   - failures: Consecutive failures, including the one just recorded.
    ///   - time: When the latest one happened.
    /// - Returns: The end of the backoff, or nil below the threshold.
    public func refusedUntil(afterFailures failures: Int, at time: Date) -> Date? {
        guard failures >= threshold else { return nil }
        // `exceeding` is 0 on the attempt that crosses the threshold, so the first penalty is
        // exactly the configured backoff. Capped at 32 doublings before the multiply, so the
        // power can't overflow a Double into infinity.
        let exceeding = failures - threshold
        let multiplier = pow(2.0, Double(min(exceeding, 32)))
        let delay = min(backoff * multiplier, FailureThrottle.maximumBackoff)
        return time.addingTimeInterval(delay)
    }
}

/// Resolves a presented proof to the subject it proves.
///
/// **This is deliberately the only protocol a store must implement.** Everything else a store
/// could offer — enumerating subjects, creating them, reading attributes in bulk — is something
/// an identity provider may not expose, and each one would make swapping in Keycloak or Auth0
/// harder. Administration is a separate protocol a provider-backed store may decline entirely.
///
/// It is `async` for the same reason: resolving against a provider is a network call, and a
/// synchronous signature would have to be broken to allow one.
///
/// ## What an implementation must guarantee
///
/// Checked by `ConformanceSuite`, which any implementation is expected to pass unchanged:
///
/// - A credential of one kind never resolves as another.
/// - Every refusal is identical **to the caller** — same value, and no reason reachable through
///   ``subject(for:)``. A store that answers differently for a subject that exists has told an
///   attacker which subjects exist.
/// - A honeypot refuses *and* reports ``IdentityEvent/Outcome/honeypot`` in its resolution, so
///   the service can act on it. It is the one case where failing is the feature.
public protocol CredentialStore: Sendable {
    /// Resolves a credential, reporting the reason to the service.
    func resolve(_ credential: any Credential) async -> Resolution

    /// Resolves a credential and reports the algorithm the store verified it with.
    ///
    /// A requirement with a default, so every existing store keeps compiling and reports no
    /// algorithm. Dynamically dispatched on purpose, unlike ``subject(for:)``: a store must be
    /// able to say what it verified with. The algorithm comes from the store's own record (the
    /// registered key, the stored scheme), never from the credential, which could claim any.
    /// It reaches no caller: ``Authenticator`` folds it into ``Authentication``.
    func resolveVerifying(_ credential: any Credential) async -> (Resolution, algorithm: String?)
}

extension CredentialStore {
    /// ``resolve(_:)``, with no algorithm.
    public func resolveVerifying(_ credential: any Credential) async -> (Resolution, algorithm: String?) {
        (await resolve(credential), algorithm: nil)
    }

    /// The subject a presented credential proves, or nil.
    ///
    /// What a consumer calls. The reason never crosses this line — which is why it lives in an
    /// extension rather than in each implementation: indistinguishability is then a property of
    /// the protocol, not something every implementer has to remember.
    ///
    /// - Parameter credential: The proof presented by the caller.
    /// - Returns: The subject, or nil if the credential proves nothing usable.
    public func subject(for credential: any Credential) async -> Subject? {
        guard case .verified(let subject) = await resolve(credential) else { return nil }
        return subject
    }
}

/// A store that throttles some credentials, and can say under which key.
///
/// ``Authenticator`` asks, so that an attempt presenting several throttled authenticators can
/// disable them together when one reaches the ceiling (NIST SP 800-63B-4 §3.2.2). The key is
/// for the throttle only; it says nothing about whether the credential is valid.
public protocol ThrottlingCredentialStore: CredentialStore {
    /// The key `credential`'s attempts are counted under, or nil for a kind this store doesn't
    /// throttle.
    func throttleKey(for credential: any Credential) async -> ThrottleKey?
}

/// Comparisons that do not finish early.
///
/// Provided so that no implementer hand-rolls one. A `==` on two digests returns as soon as it
/// finds a difference, and the time it took is a measurement of how much of the secret was
/// guessed correctly.
///
/// Timing is the one property the conformance suite cannot check — a black-box test cannot see
/// which comparison a store used, and a statistical timing assertion is flaky enough to be
/// worse than none. So it is addressed by construction instead: use this.
public enum ConstantTime {
    /// Whether two byte sequences are equal, examining every byte regardless.
    ///
    /// The length check returns early and is safe to: digests are fixed-length, so a length
    /// difference means the input was not a digest at all.
    public static func equals(_ lhs: [UInt8], _ rhs: [UInt8]) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var difference: UInt8 = 0
        for index in lhs.indices {
            difference |= lhs[index] ^ rhs[index]
        }
        return difference == 0
    }
}
