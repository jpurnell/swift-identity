import Crypto
import Foundation
import SwiftIdentity

/// The design of `SubjectsAndCredentials.md`, made executable.
///
/// This exists to answer one question with evidence rather than argument: *does the proposed
/// design pass its own conformance suite?* It is in-memory and is not the production store —
/// but it is faithful on every point the suite measures, including storing digests rather than
/// secrets, because a reference that cheats teaches the wrong thing to whoever copies it.
///
/// Shipped rather than kept in tests, so a file-backed store or a shim in front of an identity
/// provider has something to compare against while it is being written.
public actor ReferenceCredentialStore: CredentialStore {

    /// One issued credential.
    private struct Record: Sendable {
        let digest: [UInt8]
        let kind: String
        let subjectID: String
        let expires: Date?
    }

    private let subjects: [String: Subject]
    private let records: [Record]
    private let throttle: ThrottlePolicy?
    private let now: @Sendable () -> Date

    /// Failed passphrase attempts, by subject, with the time of the most recent one.
    private var failures: [String: (count: Int, latest: Date)] = [:]

    /// Builds a store from subjects and the credentials issued against them.
    ///
    /// - Parameters:
    ///   - subjects: Every subject, by id.
    ///   - credentials: Credentials to issue, each with the subject it proves and an optional
    ///     expiry.
    ///   - throttle: Backoff for passphrase attempts, or nil to attempt every time.
    ///   - now: The clock, injected so expiry and backoff are testable without waiting.
    public init(
        subjects: [Subject],
        credentials: [(credential: any Credential, subjectID: String, expires: Date?)],
        throttle: ThrottlePolicy? = .standard,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.subjects = Dictionary(uniqueKeysWithValues: subjects.map { ($0.id, $0) })
        self.records = credentials.map {
            Record(
                digest: Self.digest(of: $0.credential),
                kind: $0.credential.kindName,
                subjectID: $0.subjectID,
                expires: $0.expires
            )
        }
        self.throttle = throttle
        self.now = now
    }

    /// Resolves a credential, reporting the reason to the service and nothing to the caller.
    ///
    /// The order is the design: throttle before doing any work, then match on **kind and digest
    /// together** so a value valid as one kind is not valid as another, then status, then
    /// expiry.
    public func resolve(_ credential: any Credential) async -> Resolution {
        await resolveVerifying(credential).0
    }

    /// Resolves a credential and names the algorithm: `reference-sha256`, for every kind, since
    /// this store holds a SHA-256 digest of each.
    public func resolveVerifying(_ credential: any Credential) async -> (Resolution, algorithm: String?) {
        let resolution = await check(credential)
        guard case .verified = resolution else { return (resolution, algorithm: nil) }
        return (resolution, algorithm: Self.algorithm)
    }

    /// What ``resolveVerifying(_:)`` reports.
    public static let algorithm = "reference-sha256"

    private func check(_ credential: any Credential) async -> Resolution {
        if let passphrase = credential as? Passphrase, isThrottled(passphrase.subjectID) {
            // Refused without checking the secret. Doing the comparison anyway would make the
            // throttle a suggestion rather than a limit.
            return .refused(.throttled)
        }

        let presented = Self.digest(of: credential)
        let kind = credential.kindName

        var matched: Record?
        // Every record of this kind is examined even after a match, so the work does not depend
        // on where in the list the answer lies.
        for record in records where record.kind == kind {
            if ConstantTime.equals(record.digest, presented) { matched = record }
        }

        guard let record = matched, let subject = subjects[record.subjectID] else {
            noteFailure(credential)
            return .refused(.unknown)
        }
        switch subject.status {
        case .revoked:
            return .refused(.revoked)
        case .honeypot:
            // The tripwire. Refused like everything else from the caller's side, and named here
            // so the service can log it loudly and find out whether the leak was ever used.
            return .refused(.honeypot)
        case .active:
            break
        }
        if let expires = record.expires, expires <= now() {
            return .refused(.expired)
        }

        clearFailures(credential)
        return .verified(subject)
    }

    // MARK: - Throttling

    private func isThrottled(_ subjectID: String) -> Bool {
        guard let throttle, let record = failures[subjectID], record.count >= throttle.threshold
        else { return false }
        return now().timeIntervalSince(record.latest) < throttle.backoff
    }

    private func noteFailure(_ credential: any Credential) {
        guard let passphrase = credential as? Passphrase else { return }
        let existing = failures[passphrase.subjectID]?.count ?? 0
        failures[passphrase.subjectID] = (existing + 1, now())
    }

    private func clearFailures(_ credential: any Credential) {
        guard let passphrase = credential as? Passphrase else { return }
        failures[passphrase.subjectID] = nil
    }

    // MARK: - Digests

    /// SHA-256 over the presented secret, so nothing is held in the clear.
    ///
    /// Kept as bytes rather than hex: the comparison is over bytes anyway, and rendering a
    /// digest as a string only creates something that can be logged by accident.
    private static func digest(of credential: any Credential) -> [UInt8] {
        // Tested by hand rather than switched over, which is the cost of an open protocol. An
        // unrecognised kind digests its own name and matches nothing — refusing is the correct
        // answer for a kind this store was never taught, and it is the failure the conformance
        // suite's kinds-do-not-cross requirement would catch if it were ever wrong.
        let secret: String
        switch credential {
        case let key as BearerKey:          secret = key.value
        case let token as CapabilityToken:  secret = token.value
        case let session as SessionToken:   secret = session.value
        case let passphrase as Passphrase:
            // The subject is part of the digest, so one person's passphrase cannot authenticate
            // as another even if they choose the same words. The secret is canonicalized first,
            // as NIST requires; one that can't be is digested as given and matches nothing issued.
            switch PassphraseCanonicalization.c1.canonicalize(passphrase.secret) {
            case .success(let canonical): secret = "\(passphrase.subjectID)|\(canonical)"
            case .failure: secret = "\u{0}uncanonicalizable:\(passphrase.subjectID)"
            }
        case let assertion as ExternalAssertion:
            secret = "\(assertion.identity.issuer)|\(assertion.identity.subject)"
        default:
            secret = "\u{0}unknown-kind:\(credential.kindName)"
        }
        return Array(SHA256.hash(data: Data(secret.utf8)))
    }
}
