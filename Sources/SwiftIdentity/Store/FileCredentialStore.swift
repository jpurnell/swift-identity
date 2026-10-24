#if canImport(os)
import os
#endif
import Crypto
import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// Subjects and their credentials, kept in two files and read once at startup.
///
/// Two files rather than one, so the roster can be read and reviewed without exposing
/// verifiers: `subjects` says who exists, `verifiers` says what proves them. Only the second
/// is sensitive, and only the second is ever hard to hand to someone.
///
/// ## Nothing is stored in the clear
///
/// The verifiers file holds SHA-256 digests, never secrets. A consequence worth stating: this
/// store **cannot check a credential's entropy**, because it never sees the credential. That
/// check belongs to whatever mints them, and it is enforced there.
///
/// ## Every refusal is startup-fatal
///
/// A credential store that silently serves nobody and one that silently serves everybody both
/// look like "no error" from the outside — which is why neither may be reached by degrading.
/// Failing to start is loud, and loud is what a credential store owes its operator.
public struct FileCredentialStore: ThrottlingCredentialStore {

    /// Why a store was refused.
    ///
    /// Each case names the file and, where it can, the line — because "the verifiers file is
    /// wrong" sends someone reading two hundred lines by eye.
    public enum Failure: Error, Equatable {
        /// The path was relative, or climbed upwards; a credential store is named absolutely.
        case unsafePath(path: String)
        /// A file could not be read, and why.
        case unreadable(path: String, reason: String)
        /// A file is readable by someone other than its owner.
        case permissive(path: String, mode: String)
        /// A line was not in the expected shape.
        case malformed(path: String, line: Int)
        /// A status was not `active`, `revoked` or `honeypot`.
        case unknownStatus(line: Int, value: String)
        /// The same subject id appears twice.
        case duplicateSubject(line: Int, id: String)
        /// The same digest is claimed by two subjects.
        case duplicateCredential(line: Int)
        /// A credential names a subject the roster does not contain.
        case unknownSubject(line: Int, id: String)
        /// A digest was not 64 hexadecimal characters.
        case malformedDigest(line: Int)
        /// A passphrase line's verifier could not be read.
        ///
        /// Separate from `malformedDigest` because the remedy differs: a passphrase carries
        /// `<scheme>$<parameters>$<salt>$<digest>`, and a bare hex digest on a passphrase line
        /// is a value written before this store could hold one — startup-fatal rather than
        /// silently unverifiable. So is a scheme the store's ``PassphraseSchemes`` don't accept:
        /// an unknown scheme fails closed.
        case malformedPassphraseVerifier(line: Int)
        /// A file held no usable entries.
        case empty(path: String)
        /// A one-time-code line couldn't be read.
        case malformedOneTimeCodeVerifier(line: Int)
        /// The verifiers hold one-time codes, and no ``SealingKey`` was given to open them.
        case sealingKeyRequired
        /// The sealing key given doesn't open this line's one-time-code key: the wrong key file,
        /// or a line copied from another deployment. Caught here, not at the first sign-in.
        case sealingKeyMismatch(line: Int)
        /// The verifiers hold one-time codes, and no throttle was given. NIST requires both
        /// accepting each code once and limiting failures (§3.1.4.2), and the throttle's ledger
        /// is where both are kept.
        case throttleRequired
    }

    /// One issued credential, as stored.
    ///
    /// Two shapes, because two threat models. A generated key is compared against a fast hash;
    /// a passphrase is derived against its own salt and round count at a deliberate cost. Folding
    /// them into one field would mean either hashing a passphrase quickly or deriving a bearer
    /// key slowly, and both are wrong.
    private struct Record: Sendable {
        enum Proof: Sendable {
            /// SHA-256 of the presented value. Every kind but ``Passphrase``.
            case digest([UInt8])
            /// A salted, iterated derivation. ``Passphrase`` only.
            case passphrase(PassphraseVerifier)
            /// A sealed authenticator-app key. ``OneTimeCode`` only.
            case oneTimeCode(OneTimeCodeVerifier)
        }

        let proof: Proof
        /// The line in the verifiers file, for startup errors found after parsing.
        let line: Int
        let kind: String
        let subjectID: String
        let expires: Date?
    }

    private let subjects: [String: Subject]
    private let records: [Record]
    /// Counts consecutive passphrase failures, when a deployment wants them counted.
    ///
    /// Optional because throttling is a policy, not a property of storage: a store fronting a
    /// service that already rate-limits should not count twice, and one holding no passphrases
    /// has nothing to count.
    private let throttle: FailureThrottle?
    /// Each subject's passphrase throttle key, derived from its verifiers' salts at startup.
    ///
    /// Derived rather than named by kind, so that issuing a new passphrase is rebinding it: see
    /// ``ThrottleKey/passphrase(subjectID:verifiers:)``.
    private let passphraseKeys: [String: ThrottleKey]
    /// Each subject's one-time-code throttle key, derived the same way.
    private let oneTimeCodeKeys: [String: ThrottleKey]
    /// Opens one-time-code keys. Required when the verifiers hold any.
    private let sealingKey: SealingKey?
    /// Derived against when a passphrase claims a subject with none, so the refusal costs what a
    /// wrong passphrase costs and an attempt's timing doesn't say who has one.
    private let dummyPassphrase: PassphraseVerifier?
    private let audit: (any IdentityAudit)?
    private let now: @Sendable () -> Date

    /// The roster's file name inside the directory.
    public static let subjectsFile = "subjects"
    /// The verifiers' file name inside the directory.
    ///
    /// Named for what it holds. It contains SHA-256 digests and no secrets, and calling it
    /// "credentials" invited both a reader and a static analyser to assume otherwise.
    public static let verifiersFile = "verifiers"

    /// Reads both files, refusing anything it cannot trust.
    ///
    /// - Parameters:
    ///   - directory: Absolute path to the directory holding `subjects` and `verifiers`.
    ///   - now: The clock, injected so expiry is testable without waiting.
    ///   - throttle: Counts consecutive passphrase failures. `nil` disables throttling, which is
    ///     the right choice only where something else is already doing it — a store fronting a
    ///     service that rate-limits already should not count twice.
    ///   - audit: Told the outcome of **every** resolution, including successes.
    ///
    ///     Two things follow from "every". It fires once per verification, which for an API
    ///     authenticated by a bearer key is once per request — so it must not be wired to a
    ///     synchronous disk write, and a consumer that only wants refusals should filter rather
    ///     than expect this to. Nothing is filtered here on purpose: a library that decides
    ///     which events matter has decided it for every consumer.
    ///
    ///     What it adds over ``Resolution`` is **who**. The resolution reports that a honeypot
    ///     fired; only this says which subject's credential was presented.
    ///   - sealingKey: Opens one-time-code keys. Required, with `throttle`, when the verifiers
    ///     hold any `totp` line; every such line is opened once here, so a wrong key fails at
    ///     startup.
    ///   - schemes: The passphrase schemes this deployment accepts. A line under any other is
    ///     startup-fatal. Defaults to ``PassphraseSchemes/standard``; a deployment on
    ///     ``PassphrasePolicy/owasp`` passes that profile's schemes.
    /// - Throws: ``Failure``, always at startup and never at request time.
    public init(
        directory: String,
        now: @escaping @Sendable () -> Date = { Date() },
        throttle: FailureThrottle? = nil,
        audit: (any IdentityAudit)? = nil,
        sealingKey: SealingKey? = nil,
        schemes: PassphraseSchemes = .standard
    ) throws {
        guard directory.hasPrefix("/"), !directory.contains("..") else {
            throw Failure.unsafePath(path: directory)
        }

        let rosterPath = (directory as NSString).appendingPathComponent(Self.subjectsFile)
        let secretsPath = (directory as NSString).appendingPathComponent(Self.verifiersFile)

        let roster = try Self.parseSubjects(try Self.read(rosterPath), path: rosterPath)
        guard !roster.isEmpty else { throw Failure.empty(path: rosterPath) }

        let records = try Self.parseCredentials(
            try Self.read(secretsPath), path: secretsPath, knownSubjects: roster, schemes: schemes
        )
        try Self.checkOneTimeCodes(records, sealingKey: sealingKey, throttle: throttle)
        self.subjects = roster
        self.records = records
        self.passphraseKeys = Self.passphraseKeys(records)
        self.oneTimeCodeKeys = Self.oneTimeCodeKeys(records)
        self.sealingKey = sealingKey
        self.dummyPassphrase = Self.dummy(like: records, schemes: schemes)
        self.now = now
        self.throttle = throttle
        self.audit = audit
    }

    // MARK: - Resolution

    /// Resolves a credential, reporting the reason to the service and nothing to the caller.
    ///
    /// The order is the design: match on **kind and digest together**, so a value valid as one
    /// kind is not valid as another; then status; then expiry.
    public func resolve(_ credential: any Credential) async -> Resolution {
        await resolveVerifying(credential).0
    }

    /// Resolves a credential and names what it was verified with: the passphrase scheme
    /// (`pbkdf2-sha256-c1`), the one-time-code parameters (`totp-sha1-6-30`), or `sha256` for
    /// a fast-hashed kind. From the stored record, never from the credential. Nil on a refusal.
    public func resolveVerifying(_ credential: any Credential) async -> (Resolution, algorithm: String?) {
        let lookup: Lookup
        switch credential {
        case let passphrase as Passphrase:
            lookup = await lookUp(passphrase)
        case let code as OneTimeCode:
            lookup = await lookUp(code)
        default:
            // Only passphrases and one-time codes are counted. Throttling a 256-bit generated
            // key defends against nothing a guesser could exhaust, and buys a mechanism usable
            // to deny service.
            lookup = .matched(matchByDigest(credential))
        }
        switch lookup {
        case .refusedUnchecked(let subjectID):
            // Named, because this is the one refusal that happens without checking the
            // secret, so the subject comes from the attempt rather than from a match, and a
            // service watching for a guessing run needs to know who is being guessed at.
            return (await report(.throttled, subjectID, credential), algorithm: nil)
        case .matched(let record):
            return await settle(record, credential)
        }
    }

    /// What looking a credential up produced, before status and expiry.
    private enum Lookup {
        /// The throttle refused it without checking.
        case refusedUnchecked(subjectID: String)
        /// The record it proves, or none.
        case matched(Record?)
    }

    /// A passphrase, through the throttle.
    ///
    /// Checked before the derivation, not after. Refusing unchecked is the entire point: it
    /// costs the server nothing, where running the KDF anyway would let a guesser spend six
    /// hundred thousand rounds of somebody else's CPU per attempt. That covers a backoff, a
    /// passphrase disabled at the ceiling, and a ledger that couldn't be read: all three refuse
    /// without checking, and all three are `.throttled`.
    ///
    /// Admitted and counted in one step, before the derivation: a check followed by a separate
    /// record would let every attempt in the gap through, which at 99 failures is more than the
    /// one NIST allows. A mismatch is then already counted. A match clears the count; if the
    /// ledger can't record that, the attempt is refused even though the passphrase was right,
    /// because a throttle fails closed.
    private func lookUp(_ passphrase: Passphrase) async -> Lookup {
        let key = throttleKey(forPassphraseOf: passphrase.subjectID)
        if let throttle, await !throttle.beginAttempt(key) {
            return .refusedUnchecked(subjectID: passphrase.subjectID)
        }
        let matched = match(passphrase)
        if matched != nil, await !recordSuccess(for: key) {
            return .refusedUnchecked(subjectID: passphrase.subjectID)
        }
        return .matched(matched)
    }

    /// A one-time code, through the throttle, and accepted once.
    ///
    /// Counted before it's checked, like a passphrase. A code that matches is accepted only if
    /// its step is later than the last one used (§3.1.4.2: "accept a given OTP only once while
    /// it is valid"), and that's recorded in the same ledger the count lives in, so it holds
    /// across every process sharing it. A replay is refused as an ordinary mismatch, and stays
    /// counted as a failure.
    private func lookUp(_ code: OneTimeCode) async -> Lookup {
        let key = oneTimeCodeKeys[code.subjectID] ?? .unknownOneTimeCode
        guard let throttle, let sealingKey else { return .matched(nil) }
        guard await throttle.beginAttempt(key) else { return .refusedUnchecked(subjectID: code.subjectID) }

        for record in records where record.kind == OneTimeCode.kind && record.subjectID == code.subjectID {
            guard case .oneTimeCode(let verifier) = record.proof,
                  let step = verifier.matchingStep(code.code, at: now(), sealingKey: sealingKey) else { continue }
            guard await throttle.consume(step: step, for: key) else { return .matched(nil) }
            guard await recordSuccess(for: key) else { return .refusedUnchecked(subjectID: code.subjectID) }
            return .matched(record)
        }
        return .matched(nil)
    }

    /// Status and expiry, for whatever was matched.
    private func settle(_ matched: Record?, _ credential: any Credential) async -> (Resolution, algorithm: String?) {
        guard let record = matched, let subject = subjects[record.subjectID] else {
            // No subject id: nobody was identified, and inventing one here would be the store
            // guessing at what the caller meant.
            return (await report(.unknown, nil, credential), algorithm: nil)
        }
        switch subject.status {
        case .revoked:
            return (await report(.revoked, subject.id, credential), algorithm: nil)
        case .honeypot:
            // The tripwire. Refused like everything else from the caller's side, and named here
            // so the service can log it and find out whether the leak was ever used.
            //
            // **Which** honeypot is the question the resolution cannot answer.
            // ``Resolution/refused(_:)`` reports that a tripwire fired; a deployment holding
            // several leaked credentials needs to know which one somebody found, and that fact
            // exists only inside this store. It reaches the service through the audit.
            return (await report(.honeypot, subject.id, credential), algorithm: nil)
        case .active:
            break
        }
        if let expires = record.expires, expires <= now() {
            return (await report(.expired, subject.id, credential), algorithm: nil)
        }
        let algorithm = Self.algorithm(of: record)
        return (await report(.verified, subject.id, credential, verified: subject, algorithm: algorithm), algorithm: algorithm)
    }

    /// What a record verifies with, from the record itself.
    private static func algorithm(of record: Record) -> String {
        switch record.proof {
        case .digest: "sha256"
        case .passphrase(let verifier): verifier.scheme.identifier
        case .oneTimeCode(let verifier): verifier.parameters.identifier
        }
    }

    /// Records the outcome and returns the resolution, so the two cannot disagree.
    ///
    /// Every exit from ``resolve(_:)`` goes through here. Recording at each `return` instead
    /// would mean an outcome added later that forgets to — which is the failure mode an audit
    /// has, because a missing line looks exactly like a thing that did not happen.
    private func report(
        _ outcome: IdentityEvent.Outcome,
        _ subjectID: String?,
        _ credential: any Credential,
        verified subject: Subject? = nil,
        algorithm: String? = nil
    ) async -> Resolution {
        await audit?.record(IdentityEvent(
            outcome: outcome, subjectID: subjectID,
            credentialKind: credential.kindName, at: now(), algorithm: algorithm
        ))
        guard let subject else { return .refused(outcome) }
        return .verified(subject)
    }

    /// Tells the throttle an admitted attempt matched.
    ///
    /// - Returns: False if the ledger couldn't record it.
    private func recordSuccess(for key: ThrottleKey) async -> Bool {
        guard let throttle else { return true }
        do {
            try await throttle.recordSuccess(key)
            return true
        } catch {
            #if canImport(os)
            Logger(subsystem: "org.roseclub.swiftidentity", category: "throttle")
                .error("throttle ledger could not record a success; refusing: \(String(describing: error), privacy: .public)")
            #endif
            return false
        }
    }

    /// The key `credential`'s attempts are counted under: passphrases and one-time codes, by
    /// subject; nil for every other kind, which isn't throttled.
    public func throttleKey(for credential: any Credential) -> ThrottleKey? {
        switch credential {
        case let passphrase as Passphrase: throttleKey(forPassphraseOf: passphrase.subjectID)
        case let code as OneTimeCode: oneTimeCodeKeys[code.subjectID] ?? .unknownOneTimeCode
        default: nil
        }
    }

    /// The key a passphrase attempt claiming `subjectID` is throttled under.
    ///
    /// For a subject with a passphrase, derived from its verifiers' salts, so that issuing a new
    /// passphrase rebinds it (``ThrottleKey/passphrase(subjectID:verifiers:)``). An
    /// administrator calling ``ThrottleLedger/rebound(_:)`` by hand gets the key from here.
    /// For any other claimed subject, ``ThrottleKey/unknownPassphrase``.
    ///
    /// - Parameter subjectID: The subject an attempt claims.
    /// - Returns: The key its failures count against.
    public func throttleKey(forPassphraseOf subjectID: String) -> ThrottleKey {
        passphraseKeys[subjectID] ?? .unknownPassphrase
    }

    /// Every subject's one-time-code key, from the verifiers it holds.
    private static func oneTimeCodeKeys(_ records: [Record]) -> [String: ThrottleKey] {
        var verifiers: [String: [OneTimeCodeVerifier]] = [:]
        for record in records {
            guard case .oneTimeCode(let verifier) = record.proof else { continue }
            verifiers[record.subjectID, default: []].append(verifier)
        }
        return verifiers.reduce(into: [:]) { keys, pair in
            keys[pair.key] = ThrottleKey.oneTimeCode(subjectID: pair.key, verifiers: pair.value)
        }
    }

    /// One-time codes need a sealing key that opens every line, and a throttle.
    private static func checkOneTimeCodes(
        _ records: [Record], sealingKey: SealingKey?, throttle: FailureThrottle?
    ) throws {
        let lines = records.compactMap { record -> (Int, OneTimeCodeVerifier)? in
            guard case .oneTimeCode(let verifier) = record.proof else { return nil }
            return (record.line, verifier)
        }
        guard !lines.isEmpty else { return }
        guard let sealingKey else { throw Failure.sealingKeyRequired }
        guard throttle != nil else { throw Failure.throttleRequired }
        for (line, verifier) in lines {
            do {
                _ = try verifier.key(sealingKey: sealingKey)
            } catch {
                throw Failure.sealingKeyMismatch(line: line)
            }
        }
    }

    /// Every subject's passphrase key, from the verifiers it holds.
    private static func passphraseKeys(_ records: [Record]) -> [String: ThrottleKey] {
        var verifiers: [String: [PassphraseVerifier]] = [:]
        for record in records {
            guard case .passphrase(let verifier) = record.proof else { continue }
            verifiers[record.subjectID, default: []].append(verifier)
        }
        return verifiers.reduce(into: [:]) { keys, pair in
            keys[pair.key] = ThrottleKey.passphrase(subjectID: pair.key, verifiers: pair.value)
        }
    }

    /// Finds the record a presented passphrase proves.
    ///
    /// **Looked up by subject, not scanned.** Unlike every other kind, a passphrase names the
    /// subject it claims — a login form's username field, and the thing throttling counts
    /// against. That makes scanning unnecessary, which matters here more than elsewhere:
    /// deriving against every stored passphrase would cost hundreds of thousands of rounds per
    /// record, turning a login into a denial of service against the server.
    ///
    /// The timing this admits — that a subject exists — is already public by design. A subject
    /// id goes in durable records and appears in a login form.
    private func match(_ passphrase: Passphrase) -> Record? {
        var derived = false
        for record in records where record.kind == Passphrase.kind && record.subjectID == passphrase.subjectID {
            guard case .passphrase(let verifier) = record.proof else { continue }
            derived = true
            if verifier.matches(passphrase) { return record }
        }
        // A subject with no passphrase still costs one derivation (P17). Revisions before the
        // amendment said this timing was "already public by design"; the amendment's §6 row P17
        // asks for the dummy work, and an attempt's cost no longer says who has a passphrase.
        if !derived { _ = dummyPassphrase?.matches(passphrase) }
        return nil
    }

    /// A verifier under the first stored passphrase's own scheme and cost, with a zero salt and
    /// a zero digest: decoded, not derived, so it costs nothing to build and matches nothing.
    private static func dummy(like records: [Record], schemes: PassphraseSchemes) -> PassphraseVerifier? {
        for record in records {
            guard case .passphrase(let real) = record.proof else { continue }
            let zeros = Base64URL.encode([UInt8](repeating: 0, count: max(real.salt.count, 1)))
            let empty = Base64URL.encode([UInt8](repeating: 0, count: max(real.digest.count, 1)))
            return PassphraseVerifier(
                encoded: "\(real.scheme.identifier)$\(real.parameters)$\(zeros)$\(empty)", schemes: schemes
            )
        }
        return nil
    }

    /// Finds the record a fast-hashed credential proves.
    private func matchByDigest(_ credential: any Credential) -> Record? {
        guard let presented = Self.digest(of: credential) else {
            // A kind this store has no way to digest — an open protocol means one can arrive.
            // Refusing is the right answer for a kind it was never taught.
            return nil
        }
        let kind = credential.kindName

        var matched: Record?
        // Every record of this kind is examined even after a match, so the work done does not
        // depend on where in the list the answer happens to lie. A dictionary lookup would be
        // faster and would leak that position through timing.
        for record in records where record.kind == kind {
            guard case .digest(let stored) = record.proof else { continue }
            if ConstantTime.equals(stored, presented) { matched = record }
        }
        return matched
    }

    // MARK: - Reading

    /// Reads a file, refusing it if anyone but its owner can.
    private static func read(_ path: String) throws -> String {
        var info = stat()
        guard stat(path, &info) == 0 else {
            throw Failure.unreadable(path: path, reason: String(cString: strerror(errno)))
        }
        let mode = Int(info.st_mode) & 0o7777
        guard mode & 0o077 == 0 else {
            throw Failure.permissive(path: path, mode: String(mode, radix: 8))
        }
        // Read through a URL rather than a path string: the path-traversal checker refuses the
        // string-based API, and the guard above has already established what this file is.
        do {
            return try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
        } catch {
            // Reported rather than logged: this throws out of `init`, so the operator sees it
            // as a startup failure naming the file — which is more use than a log line.
            throw Failure.unreadable(path: path, reason: error.localizedDescription)
        }
    }

    /// Splits a line into its whitespace-separated fields, dropping comments and blanks.
    ///
    /// Returns nil for a line that carries nothing, so a caller can skip it without having to
    /// distinguish "blank" from "malformed".
    private static func fields(_ line: String) -> [String]? {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty, !trimmed.hasPrefix("#") else { return nil }
        return trimmed.split(whereSeparator: \.isWhitespace).map(String.init)
    }

    /// Parses the roster: `<id> <kind> <status> [key=value,…]`.
    ///
    /// Exactly three or four whitespace-separated fields. A fifth is a malformed line rather
    /// than something to ignore: the only way to write one by accident is to separate two
    /// attributes with a space, and ignoring it silently discards whatever the second one said.
    private static func parseSubjects(_ text: String, path: String) throws -> [String: Subject] {
        var found: [String: Subject] = [:]

        for (index, line) in text.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline).enumerated() {
            let number = index + 1
            guard let parts = fields(String(line)) else { continue }
            // At most four fields, and the fourth is the whole attribute list. Attributes are
            // comma-separated *within* that field, so `tier=parent scopes=coprock` is five
            // fields rather than two attributes — and the old parser read the fourth and
            // dropped the fifth without a word. A consumer lost a scope restriction to that
            // exactly once, which is once more than a silently-ignored security setting should
            // ever manage. Refused at startup, like every other malformed line here.
            guard (3...4).contains(parts.count), let kind = Subject.Kind(rawValue: parts[1]) else {
                throw Failure.malformed(path: path, line: number)
            }
            guard let status = Subject.Status(rawValue: parts[2]) else {
                // Not defaulted: `active` would turn a typo into an authentication, and
                // `revoked` would silently lock someone out. Neither is a parser's call.
                throw Failure.unknownStatus(line: number, value: parts[2])
            }
            let id = parts[0]
            guard found[id] == nil else { throw Failure.duplicateSubject(line: number, id: id) }

            let claims: [String: String]
            do {
                claims = parts.count > 3 ? try attributes(parts[3]) : [:]
            } catch {
                throw Failure.malformed(path: path, line: number)
            }

            found[id] = Subject(
                id: id,
                kind: kind,
                status: status,
                attributes: claims
            )
        }
        return found
    }

    /// Parses `key=value,key=value` into a dictionary, refusing anything shapeless.
    ///
    /// **This was tolerant until 0.5.0, and the tolerance was wrong.** The reasoning had been
    /// that these are the consumer's own claims, which this package never interprets, so a
    /// malformed one costs an attribute rather than a login. That is true of the attribute and
    /// false of the consequence: the first consumer to use attributes put an authorisation
    /// tier and a scope restriction in them, and a dropped attribute was a dropped *security
    /// setting* that nothing reported.
    ///
    /// It happened twice in one day. `tier=parent scopes=work` made a fifth field, fixed in
    /// 0.4.0. Then `scopes=a,b` — the natural way to write a list, and unwriteable here because
    /// the comma already separates pairs — parsed as `scopes=a` plus a chunk with no `=`, which
    /// this function skipped in silence. The roster read correctly to a human both times.
    ///
    /// A value may still contain `=`; only the first one splits. An **empty value** is
    /// well-formed, because `tier=` says the key is set to nothing and a consumer may want to
    /// tell that apart from the key being absent.
    ///
    /// - Throws: ``Failure/malformed(path:line:)`` via its caller, at startup and never at
    ///   request time.
    private static func attributes(_ raw: String) throws -> [String: String] {
        var found: [String: String] = [:]
        for chunk in raw.split(separator: ",", omittingEmptySubsequences: false) {
            let halves = chunk.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard halves.count == 2, !halves[0].isEmpty else { throw ShapelessAttribute() }
            found[String(halves[0])] = String(halves[1])
        }
        return found
    }

    /// Thrown out of ``attributes(_:)`` and turned into a located failure by its caller, which
    /// is the only place that knows the line number.
    private struct ShapelessAttribute: Error {}

    /// Parses the verifiers: `<subject> <kind> <digest> <expires|->`.
    private static func parseCredentials(
        _ text: String, path: String, knownSubjects: [String: Subject], schemes: PassphraseSchemes
    ) throws -> [Record] {
        var found: [Record] = []
        var seenDigests: Set<[UInt8]> = []

        for (index, line) in text.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline).enumerated() {
            let number = index + 1
            guard let parts = fields(String(line)) else { continue }
            guard parts.count >= 3 else { throw Failure.malformed(path: path, line: number) }

            guard knownSubjects[parts[0]] != nil else {
                // An orphan credential would verify to nothing, which reads as a revoked
                // credential and is actually a roster someone edited by half.
                throw Failure.unknownSubject(line: number, id: parts[0])
            }
            // A passphrase line carries a derivation, not a digest — salt and round count
            // travel with it, in one field, so the file keeps one shape for every kind.
            let proof: Record.Proof
            if parts[1] == Passphrase.kind {
                guard let verifier = PassphraseVerifier(encoded: parts[2], schemes: schemes) else {
                    throw Failure.malformedPassphraseVerifier(line: number)
                }
                proof = .passphrase(verifier)
            } else if parts[1] == OneTimeCode.kind {
                guard let verifier = OneTimeCodeVerifier(encoded: parts[2], subjectID: parts[0]) else {
                    throw Failure.malformedOneTimeCodeVerifier(line: number)
                }
                proof = .oneTimeCode(verifier)
            } else {
                guard let digest = hex(parts[2]) else { throw Failure.malformedDigest(line: number) }
                guard seenDigests.insert(digest).inserted else {
                    // Whichever subject won would be arbitrary, and the loser would be
                    // authenticated as somebody else.
                    throw Failure.duplicateCredential(line: number)
                }
                proof = .digest(digest)
            }

            var expires: Date?
            if parts.count > 3, parts[3] != "-" {
                guard let parsed = ISO8601DateFormatter().date(from: parts[3]) else {
                    throw Failure.malformed(path: path, line: number)
                }
                expires = parsed
            }

            found.append(Record(proof: proof, line: number, kind: parts[1], subjectID: parts[0], expires: expires))
        }
        return found
    }

    /// Reads 64 hexadecimal characters as bytes, refusing anything else.
    ///
    /// The length is fixed because a SHA-256 is fixed: something shorter was never hashed, and
    /// storing it would mean comparing against a value nobody generated.
    private static func hex(_ raw: String) -> [UInt8]? {
        guard raw.count == 64 else { return nil }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(32)
        var index = raw.startIndex
        while index < raw.endIndex {
            let next = raw.index(index, offsetBy: 2)
            guard let byte = UInt8(raw[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        return bytes
    }

    /// The digest of a presented credential, or nil for a kind this store cannot digest.
    ///
    /// Tested by hand rather than switched over, which is the cost of an open ``Credential``.
    /// The `nil` is deliberate and is the fail-closed path: a kind with no digest matches no
    /// record, so an unrecognised credential proves nothing.
    static func digest(of credential: any Credential) -> [UInt8]? {
        let secret: String
        switch credential {
        case let key as BearerKey:         secret = key.value
        case let token as CapabilityToken: secret = token.value
        case let session as SessionToken:  secret = session.value
        case is Passphrase:
            // Deliberately absent. A passphrase is not digested — it is derived, against its own
            // salt and round count, at a cost that is the whole defence. Returning a fast hash
            // here would make the guessable kind as cheap to check as the unguessable ones,
            // which is exactly backwards. See `match(_:)` and ``PassphraseVerifier``.
            return nil
        case let assertion as ExternalAssertion:
            secret = "\(assertion.identity.issuer)|\(assertion.identity.subject)"
        default:
            return nil
        }
        return Array(SHA256.hash(data: Data(secret.utf8)))
    }

    /// The digest a `credentials` line should carry for a given secret.
    ///
    /// Exposed so that whatever mints credentials writes exactly what this store will compute,
    /// rather than reimplementing the rule and disagreeing with it later.
    public static func storedDigest(for credential: any Credential) -> String? {
        digest(of: credential).map { $0.map(Hex.byte).joined() }
    }

    /// The roster's entry for `id`, or `nil` if the roster has no such subject.
    ///
    /// Exists because ``SessionStore`` asks for exactly this shape and nothing here could
    /// supply it: a package that vends both halves of a seam and cannot join them has not
    /// finished the seam.
    ///
    /// **A revoked or honeypot subject is returned, carrying its status, rather than hidden.**
    /// That is the whole point — `SessionStore` re-reads the status on every resolution so a
    /// revocation ends a live session, and it can only do that if the subject comes back. If
    /// this returned `nil` for them, a revocation would be indistinguishable from a deleted
    /// line, and the reason a session was refused would be lost. Refusing is the caller's job;
    /// this answers who the roster says someone is.
    ///
    /// - Parameter id: A subject identifier, compared exactly.
    /// - Returns: The subject, or `nil`.
    public func subject(id: String) -> Subject? {
        subjects[id]
    }
}

/// Hexadecimal formatting.
///
/// Hand-rolled because `String(format:)` bridges to the C `printf` ABI, which the coding rules
/// forbid.
///
/// Named `Hex` until 0.3.0, which was a calendar package's name for it that arrived here by
/// copy and meant nothing in an identity package. Renamed while the only consumer was this
/// package's own tests.
public enum Hex {
    /// One byte as two lowercase hexadecimal characters.
    public static func byte(_ value: UInt8) -> String {
        let digits = "0123456789abcdef"
        let high = digits[digits.index(digits.startIndex, offsetBy: Int(value >> 4))]
        let low = digits[digits.index(digits.startIndex, offsetBy: Int(value & 0x0F))]
        return String([high, low])
    }
}
