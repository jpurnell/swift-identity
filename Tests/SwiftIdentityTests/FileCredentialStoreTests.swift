import Crypto
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import Foundation
import SwiftDeterminism
import SwiftIdentityConformance
import Testing
@testable import SwiftIdentity

/// The file-backed store: two files, read once at startup, refusing anything it cannot trust.
///
/// The refusals come first in this file because they are what fails dangerously. A store that
/// silently serves nobody and one that silently serves everybody both look like "no error".
@Suite("FileCredentialStore")
struct FileCredentialStoreTests {

    // MARK: - Fixtures

    private static func directory() throws -> String {
        let url = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("FileCredentialStoreTests-\(UUID().uuidString)", isDirectory: true)
            .standardized
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        #expect(chmod(url.path, 0o700) == 0)
        return url.path
    }

    private static func remove(_ path: String) {
        try? FileManager.default.removeItem(at: URL(fileURLWithPath: path))
    }

    /// Writes a file at `mode`, defeating the process umask — which would otherwise quietly
    /// clear the bits a permission test is trying to set.
    private static func write(_ text: String, to path: String, mode: mode_t = 0o600) throws {
        try Data(text.utf8).write(to: URL(fileURLWithPath: path))
        #expect(chmod(path, mode) == 0)
    }

    private static func digest(_ secret: String) -> String {
        SHA256.hash(data: Data(secret.utf8)).map { Hex.byte($0) }.joined()
    }

    /// A complete, valid pair of files.
    @discardableResult
    private static func seed(
        _ directory: String,
        subjects: String? = nil,
        credentials: String? = nil
    ) throws -> String {
        let roster = subjects ?? """
            # id            kind     status
            ada          person   active    site=north-house
            voice-bridge   service  active
            formerMember        person   revoked
            retired-agent       service  honeypot
            """
        let secrets = credentials ?? """
            # subject       kind        digest                              expires
            ada          bearer      \(digest("bearer-secret"))          -
            ada          capability  \(digest("feed-token"))             -
            ada          bearer      \(digest("expired-key"))            2020-01-01T00:00:00Z
            formerMember        bearer      \(digest("former-member-secret"))        -
            retired-agent       capability  \(digest("leaked-share-link"))  -
            """
        try write(roster, to: (directory as NSString).appendingPathComponent("subjects"))
        try write(secrets, to: (directory as NSString).appendingPathComponent("verifiers"))
        return directory
    }

    private static func store(_ directory: String) throws -> FileCredentialStore {
        try FileCredentialStore(directory: directory, now: { Date(timeIntervalSince1970: 1_800_000_000) })
    }

    // MARK: - Refusals, which are startup-fatal by design

    @Test("a relative path is refused: a credential store is named absolutely")
    func refusesRelativePath() {
        #expect(throws: FileCredentialStore.Failure.self) {
            try FileCredentialStore(directory: "credentials")
        }
    }

    @Test("a path that climbs is refused")
    func refusesTraversal() {
        #expect(throws: FileCredentialStore.Failure.self) {
            try FileCredentialStore(directory: "/tmp/../etc/credentials")
        }
    }

    @Test("a verifiers file anyone can read is refused, not quietly tightened")
    func refusesPermissiveCredentials() throws {
        let dir = try Self.directory()
        defer { Self.remove(dir) }
        try Self.seed(dir)
        #expect(chmod((dir as NSString).appendingPathComponent("verifiers"), 0o644) == 0)

        // Tightening it silently would hide that it was ever wrong, and the person who
        // loosened it deserves to be told rather than corrected behind their back.
        #expect(throws: FileCredentialStore.Failure.self) { try Self.store(dir) }
    }

    @Test("a missing file is refused rather than treated as an empty roster")
    func refusesMissingFile() throws {
        let dir = try Self.directory()
        defer { Self.remove(dir) }
        // An empty roster verifies nothing, which is indistinguishable from a store that is
        // working and has no subjects — so absence must be loud.
        #expect(throws: FileCredentialStore.Failure.self) { try Self.store(dir) }
    }

    @Test("a malformed line names its line number")
    func refusesMalformed() throws {
        let dir = try Self.directory()
        defer { Self.remove(dir) }
        try Self.seed(dir, subjects: """
            ada  person  active
            broken-line-with-no-status
            """)
        #expect(throws: FileCredentialStore.Failure.self) { try Self.store(dir) }
    }

    @Test("an unknown status is refused rather than defaulted")
    func refusesUnknownStatus() throws {
        let dir = try Self.directory()
        defer { Self.remove(dir) }
        // Defaulting to `active` would turn a typo into an authentication; defaulting to
        // `revoked` would silently lock someone out. Neither is a decision a parser should make.
        try Self.seed(dir, subjects: "ada  person  activ")
        #expect(throws: FileCredentialStore.Failure.self) { try Self.store(dir) }
    }

    @Test("a duplicate subject is refused rather than resolved arbitrarily")
    func refusesDuplicateSubject() throws {
        let dir = try Self.directory()
        defer { Self.remove(dir) }
        try Self.seed(dir, subjects: """
            ada  person  active
            ada  person  revoked
            """)
        #expect(throws: FileCredentialStore.Failure.self) { try Self.store(dir) }
    }

    @Test("one digest belonging to two subjects is refused")
    func refusesSharedDigest() throws {
        let dir = try Self.directory()
        defer { Self.remove(dir) }
        let shared = Self.digest("gracee-secret")
        try Self.seed(dir,
            subjects: """
                ada  person  active
                grace     person  active
                """,
            credentials: """
                ada  bearer  \(shared)  -
                grace     bearer  \(shared)  -
                """)
        // Whichever subject won would be arbitrary, and the loser would be authenticated as
        // someone else.
        #expect(throws: FileCredentialStore.Failure.self) { try Self.store(dir) }
    }

    @Test("a credential for a subject that does not exist is refused")
    func refusesOrphanCredential() throws {
        let dir = try Self.directory()
        defer { Self.remove(dir) }
        try Self.seed(dir,
            subjects: "ada  person  active",
            credentials: "ghost  bearer  \(Self.digest("x"))  -")
        #expect(throws: FileCredentialStore.Failure.self) { try Self.store(dir) }
    }

    @Test("a digest that is not a SHA-256 is refused")
    func refusesBadDigest() throws {
        let dir = try Self.directory()
        defer { Self.remove(dir) }
        try Self.seed(dir,
            subjects: "ada  person  active",
            credentials: "ada  bearer  not-a-digest  -")
        // The store holds digests, never secrets, so it cannot check entropy — but it can
        // refuse something that was plainly never hashed.
        #expect(throws: FileCredentialStore.Failure.self) { try Self.store(dir) }
    }

    // MARK: - Resolution

    @Test("a bearer key resolves to its subject, with attributes intact")
    func resolvesBearer() async throws {
        let dir = try Self.directory()
        defer { Self.remove(dir) }
        try Self.seed(dir)
        let subject = await (try Self.store(dir)).subject(for: BearerKey("bearer-secret"))
        #expect(subject?.id == "ada")
        #expect(subject?.attributes["site"] == "north-house")
        #expect(subject?.kind == .person)
    }

    @Test("a capability token resolves too — the kind that needs no header")
    func resolvesCapability() async throws {
        let dir = try Self.directory()
        defer { Self.remove(dir) }
        try Self.seed(dir)
        let store = try Self.store(dir)
        #expect(await store.subject(for: CapabilityToken("feed-token"))?.id == "ada")
    }

    @Test("a value valid as one kind is not valid as another")
    func kindsDoNotCross() async throws {
        let dir = try Self.directory()
        defer { Self.remove(dir) }
        try Self.seed(dir)
        // This is how a calendar feed's URL would become an API key.
        let store = try Self.store(dir)
        #expect(await store.subject(for: CapabilityToken("bearer-secret")) == nil)
        #expect(await store.subject(for: BearerKey("feed-token")) == nil)
    }

    @Test("revoked, honeypot, expired and unknown all refuse — and say why, to the service only")
    func refusalsAreReportedInternally() async throws {
        let dir = try Self.directory()
        defer { Self.remove(dir) }
        try Self.seed(dir)
        let store = try Self.store(dir)

        #expect(await store.resolve(BearerKey("former-member-secret")) == .refused(.revoked))
        #expect(await store.resolve(CapabilityToken("leaked-share-link")) == .refused(.honeypot))
        #expect(await store.resolve(BearerKey("expired-key")) == .refused(.expired))
        #expect(await store.resolve(BearerKey("never-issued")) == .refused(.unknown))

        // And all four are indistinguishable to the caller.
        for credential in [
            BearerKey("former-member-secret"), BearerKey("expired-key"), BearerKey("never-issued"),
        ] as [any Credential] {
            #expect(await store.subject(for: credential) == nil)
        }
        #expect(await store.subject(for: CapabilityToken("leaked-share-link")) == nil)
    }

    @Test("a kind the store was never taught matches nothing")
    func unknownKindRefuses() async throws {
        let dir = try Self.directory()
        defer { Self.remove(dir) }
        try Self.seed(dir)
        struct HardwareToken: Credential { static let kind = "hardware-token" }
        // The cost of an open protocol, failing closed: refusing is the right answer for a
        // kind this store has no record of.
        let store = try Self.store(dir)
        #expect(await store.subject(for: HardwareToken()) == nil)
    }

    // MARK: - The bar every store has to clear

    @Test("it passes the conformance suite")
    func conforms() async throws {
        let dir = try Self.directory()
        defer { Self.remove(dir) }
        try Self.seed(dir)

        let store = try Self.store(dir)
        let report = await ConformanceSuite(
            store: store,
            fixtures: .init(
                capabilities: [.revocation, .honeypot, .expiry],
                active: .init(
                    id: "ada",
                    credential: BearerKey("bearer-secret"),
                    attributes: ["site": "north-house"]
                ),
                refusals: .init(
                    revoked: BearerKey("former-member-secret"),
                    honeypot: CapabilityToken("leaked-share-link"),
                    expired: BearerKey("expired-key"),
                    unknown: BearerKey("never-issued")
                )
            )
        ).run()

        #expect(report.isConformant, "\n\(report.summary)")
        #expect(report.failures.isEmpty)
    }
}

/// A passphrase, all the way through the store.
///
/// The verifier has its own suite; this is the half that suite cannot reach — that a line in the
/// file resolves to a subject, and that the ways it can be wrong are startup-fatal rather than
/// quietly unverifiable.
@Suite("FileCredentialStore — passphrases")
struct FileCredentialStorePassphraseTests {

    private static func directory() throws -> String {
        let url = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("swiftidentity-passphrase-\(UUID().uuidString)")
            .standardized
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        #expect(chmod(url.path, 0o700) == 0)
        return url.path
    }

    private static func write(_ text: String, to path: String) throws {
        try Data(text.utf8).write(to: URL(fileURLWithPath: path))
        #expect(chmod(path, 0o600) == 0)
    }

    /// Removes a temporary directory through a URL.
    ///
    /// The path-traversal checker refuses `removeItem(atPath:)` and accepts the URL form, which
    /// is the same distinction `FileCredentialStore.read` is written around.
    private static func remove(_ path: String) {
        try? FileManager.default.removeItem(at: URL(fileURLWithPath: path))
    }

    /// Seeds a store holding one passphrase for `ada` and one for a revoked subject.
    ///
    /// Derived at the floor rather than the default: this exercises the same code path at a
    /// third of the cost, and the cost itself is asserted in `PassphraseWorkFactorTests`.
    private static func seed(_ directory: String) throws -> String {
        var generator = SplitMix64(seed: 11)
        let ada = try PassphraseVerifier(
            for: Passphrase(subjectID: "ada", secret: "correct horse battery staple"),
            using: &generator, rounds: PassphraseVerifier.roundFloor
        )
        let retired = try PassphraseVerifier(
            for: Passphrase(subjectID: "formerMember", secret: "old words"),
            using: &generator, rounds: PassphraseVerifier.roundFloor
        )

        try write("""
            ada            person   active
            formerMember   person   revoked
            """, to: (directory as NSString).appendingPathComponent("subjects"))
        try write("""
            ada            passphrase  \(ada.encoded)      -
            formerMember   passphrase  \(retired.encoded)  -
            """, to: (directory as NSString).appendingPathComponent("verifiers"))
        return directory
    }

    @Test("a passphrase in the file resolves to the subject that owns it")
    func aPassphraseResolves() async throws {
        let directory = try Self.seed(try Self.directory())
        defer { Self.remove(directory) }

        let store = try FileCredentialStore(directory: directory)
        let subject = try #require(
            await store.subject(for: Passphrase(subjectID: "ada", secret: "correct horse battery staple"))
        )
        #expect(subject.id == "ada")
    }

    @Test("the wrong words do not")
    func theWrongPassphraseIsRefused() async throws {
        let directory = try Self.seed(try Self.directory())
        defer { Self.remove(directory) }

        let store = try FileCredentialStore(directory: directory)
        let resolution = await store.resolve(Passphrase(subjectID: "ada", secret: "wrong"))
        #expect(resolution == .refused(.unknown))
    }

    @Test("nor the right words claimed by the wrong subject")
    func aPassphraseIsBoundToItsSubject() async throws {
        let directory = try Self.seed(try Self.directory())
        defer { Self.remove(directory) }

        let store = try FileCredentialStore(directory: directory)
        // `formerMember` presenting ada's words. The subject is derived into the verifier, so
        // this fails on the arithmetic rather than on a name comparison someone could forget.
        let resolution = await store.resolve(
            Passphrase(subjectID: "formerMember", secret: "correct horse battery staple")
        )
        #expect(resolution == .refused(.unknown))
    }

    @Test("a revoked subject's passphrase is refused, and says so to the service")
    func aRevokedSubjectsPassphraseIsRefused() async throws {
        let directory = try Self.seed(try Self.directory())
        defer { Self.remove(directory) }

        let store = try FileCredentialStore(directory: directory)
        let resolution = await store.resolve(Passphrase(subjectID: "formerMember", secret: "old words"))
        #expect(resolution == .refused(.revoked))
    }

    @Test("a passphrase line carrying a bare digest is startup-fatal")
    func aDigestOnAPassphraseLineIsRefused() throws {
        let directory = try Self.directory()
        defer { Self.remove(directory) }

        try Self.write("ada person active", to: (directory as NSString).appendingPathComponent("subjects"))
        // Sixty-four hex characters: valid for every other kind, and meaningless here. Written
        // before this store could hold a passphrase, it would otherwise sit in the file looking
        // correct and verifying nothing.
        try Self.write(
            "ada passphrase \(String(repeating: "a", count: 64)) -",
            to: (directory as NSString).appendingPathComponent("verifiers")
        )

        #expect(throws: FileCredentialStore.Failure.malformedPassphraseVerifier(line: 1)) {
            try FileCredentialStore(directory: directory)
        }
    }

    @Test("the fast digest path refuses passphrases outright")
    func theFastPathIsClosedToPassphrases() {
        // The guessable kind must never be checkable at the speed of the unguessable ones. If
        // this ever returns bytes, a passphrase has a fast path again and the work factor is
        // decoration.
        #expect(FileCredentialStore.digest(of: Passphrase(subjectID: "ada", secret: "x")) == nil)
        // And the kinds that should have one still do, at the length a SHA-256 actually is.
        #expect(FileCredentialStore.digest(of: BearerKey("x"))?.count == 32)
    }
}

/// The store claiming throttling, and being measured on the claim.
///
/// `ThrottlePolicy` existed as a declaration from the first release: a type describing a defence
/// nothing implemented. The conformance suite reported both throttling requirements as
/// `notClaimed`, honestly, and that is the state this closes.
@Suite("FileCredentialStore — throttling, claimed and measured")
struct FileCredentialStoreThrottlingTests {

    private static func directory() throws -> String {
        let url = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("swiftidentity-throttle-\(UUID().uuidString)")
            .standardized
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        #expect(chmod(url.path, 0o700) == 0)
        return url.path
    }

    private static func write(_ text: String, to path: String) throws {
        try Data(text.utf8).write(to: URL(fileURLWithPath: path))
        #expect(chmod(path, 0o600) == 0)
    }

    private static func remove(_ path: String) {
        try? FileManager.default.removeItem(at: URL(fileURLWithPath: path))
    }

    /// Two subjects with passphrases, so isolation can be judged rather than assumed.
    private static func seed(_ directory: String) throws -> String {
        var generator = SplitMix64(seed: 21)
        let ada = try PassphraseVerifier(
            for: Passphrase(subjectID: "ada", secret: "ada-secret"),
            using: &generator, rounds: PassphraseVerifier.roundFloor
        )
        let grace = try PassphraseVerifier(
            for: Passphrase(subjectID: "grace", secret: "grace-secret"),
            using: &generator, rounds: PassphraseVerifier.roundFloor
        )

        try write("""
            ada     person  active   site=north-house
            grace   person  active
            """, to: (directory as NSString).appendingPathComponent("subjects"))
        try write("""
            ada     passphrase  \(ada.encoded)    -
            grace   passphrase  \(grace.encoded)  -
            """, to: (directory as NSString).appendingPathComponent("verifiers"))
        return directory
    }

    @Test("repeated failure is refused unchecked, and says throttled rather than unknown")
    func repeatedFailureIsThrottled() async throws {
        let dir = try Self.seed(try Self.directory())
        defer { Self.remove(dir) }

        let store = try FileCredentialStore(
            directory: dir,
            throttle: FailureThrottle(policy: ThrottlePolicy(threshold: 3, backoff: 60))
        )
        let wrong = Passphrase(subjectID: "ada", secret: "not it")

        for _ in 0..<3 {
            #expect(await store.resolve(wrong) == .refused(.unknown))
        }
        // The reason changes, and only the service sees it: `subject(for:)` still returns nil
        // either way. What the operator gains is the difference between "someone is guessing"
        // and "someone mistyped".
        #expect(await store.resolve(wrong) == .refused(.throttled))
    }

    @Test("and a throttled subject does not lock anybody else out")
    func throttlingIsPerSubject() async throws {
        let dir = try Self.seed(try Self.directory())
        defer { Self.remove(dir) }

        let store = try FileCredentialStore(
            directory: dir,
            throttle: FailureThrottle(policy: ThrottlePolicy(threshold: 3, backoff: 60))
        )
        for _ in 0..<5 {
            _ = await store.resolve(Passphrase(subjectID: "ada", secret: "not it"))
        }

        let grace = try #require(
            await store.subject(for: Passphrase(subjectID: "grace", secret: "grace-secret"))
        )
        #expect(grace.id == "grace")
    }

    @Test("a bearer key is never throttled, however often it is wrong")
    func generatedKeysAreNotThrottled() async throws {
        let dir = try Self.seed(try Self.directory())
        defer { Self.remove(dir) }

        let store = try FileCredentialStore(
            directory: dir,
            throttle: FailureThrottle(policy: ThrottlePolicy(threshold: 3, backoff: 60))
        )
        for _ in 0..<20 {
            // Never `.throttled`: rate-limiting 256 bits of machine randomness defends against
            // nothing a guesser could exhaust, and buys a mechanism usable to deny service.
            #expect(await store.resolve(BearerKey("wrong")) == .refused(.unknown))
        }
    }

    @Test("it passes the conformance suite with throttling claimed")
    func conformsWithThrottling() async throws {
        let dir = try Self.seed(try Self.directory())
        defer { Self.remove(dir) }

        let store = try FileCredentialStore(
            directory: dir,
            throttle: FailureThrottle(policy: ThrottlePolicy(threshold: 3, backoff: 60))
        )
        let report = await ConformanceSuite(
            store: store,
            fixtures: .init(
                // Expiry and external identity are still honestly declined; this roster holds
                // neither. What has changed is that throttling is no longer among them.
                capabilities: [.throttling],
                active: .init(
                    id: "ada",
                    credential: Passphrase(subjectID: "ada", secret: "ada-secret"),
                    attributes: ["site": "north-house"]
                ),
                refusals: .init(
                    revoked: Passphrase(subjectID: "nobody", secret: "x"),
                    honeypot: Passphrase(subjectID: "nobody", secret: "x"),
                    expired: Passphrase(subjectID: "nobody", secret: "x"),
                    unknown: Passphrase(subjectID: "nobody", secret: "x")
                ),
                throttling: .init(
                    wrongPassphrase: Passphrase(subjectID: "ada", secret: "not it"),
                    otherSubject: Passphrase(subjectID: "grace", secret: "grace-secret"),
                    threshold: 3
                ),
                activeAsAnotherKind: BearerKey("ada-secret")
            )
        ).run()

        #expect(report.isConformant, "\n\(report.summary)")
        #expect(report.failures.isEmpty, "\n\(report.summary)")

        // `isConformant` is also true when everything was declined, so the claim is asserted
        // directly: both throttling requirements must have been *judged*, and passed. Without
        // this the test would keep passing if the capability were quietly dropped.
        let judged = report.results.filter {
            $0.requirement == .throttlingAfterRepeatedFailure
                || $0.requirement == .throttlingIsPerSubject
        }
        #expect(judged.count == 2)
        #expect(judged.allSatisfy { $0.verdict == .passed }, "\n\(report.summary)")
    }

    // MARK: - The ceiling (P13)

    @Test("P13: a disabled passphrase is refused unchecked, and audited as throttled")
    func disabledPassphraseIsRefused() async throws {
        let dir = try Self.seed(try Self.directory())
        defer { Self.remove(dir) }

        let ledger = InMemoryThrottleLedger()
        let recorder = IdentityAuditTests.Recorder()
        let store = try FileCredentialStore(
            directory: dir, throttle: FailureThrottle(ledger: ledger), audit: recorder
        )
        let key = store.throttleKey(forPassphraseOf: "ada")
        for _ in 0..<100 { _ = try await ledger.recordFailure(key, at: Date()) }

        // The right passphrase, and still refused: disabled means the secret is never checked.
        let right = Passphrase(subjectID: "ada", secret: "ada-secret")
        #expect(await store.resolve(right) == .refused(.throttled))
        let last = try #require(await recorder.events.last)
        #expect(last.outcome == .throttled)
        #expect(last.subjectID == "ada")

        // Disabling one person's passphrase is not disabling everyone's.
        #expect(await store.subject(for: Passphrase(subjectID: "grace", secret: "grace-secret"))?.id == "grace")
    }

    @Test("P13: concurrent guesses at 99 failures get one verification, and the rest are throttled")
    func burstAtTheCeilingThroughTheStore() async throws {
        let dir = try Self.seed(try Self.directory())
        defer { Self.remove(dir) }

        let ledger = InMemoryThrottleLedger()
        let recorder = IdentityAuditTests.Recorder()
        let store = try FileCredentialStore(
            directory: dir, throttle: FailureThrottle(ledger: ledger), audit: recorder
        )
        let key = store.throttleKey(forPassphraseOf: "ada")
        for _ in 0..<99 { _ = try await ledger.recordFailure(key, at: Date.distantPast) }

        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<20 {
                group.addTask { _ = await store.resolve(Passphrase(subjectID: "ada", secret: "guess")) }
            }
        }
        // `.unknown` is the outcome of a guess that was checked; `.throttled`, of one that wasn't.
        let outcomes = await recorder.events.map(\.outcome)
        #expect(outcomes.filter { $0 == .unknown }.count == 1)
        #expect(outcomes.filter { $0 == .throttled }.count == 19)
        #expect(await ledger.state(key).isDisabled)
    }

    @Test("P13: issuing a new passphrase rebinds it")
    func reissueRebinds() async throws {
        let dir = try Self.seed(try Self.directory())
        defer { Self.remove(dir) }
        let ledgerURL = URL(fileURLWithPath: dir).appendingPathComponent("throttle-ledger")

        let ledger = try FileThrottleLedger(url: ledgerURL)
        let before = try FileCredentialStore(directory: dir, throttle: FailureThrottle(ledger: ledger))
        let oldKey = before.throttleKey(forPassphraseOf: "ada")
        for _ in 0..<100 { _ = try await ledger.recordFailure(oldKey, at: Date()) }
        #expect(await before.resolve(Passphrase(subjectID: "ada", secret: "ada-secret")) == .refused(.throttled))

        // An administrator issues a new passphrase: a new verifier, so a new salt. Nobody
        // touches the ledger, and nobody has to remember to.
        var generator = SplitMix64(seed: 99)
        let reissued = try PassphraseVerifier(
            for: Passphrase(subjectID: "ada", secret: "a new one entirely"),
            using: &generator, rounds: PassphraseVerifier.roundFloor
        )
        let grace = try #require(
            String(data: try Data(contentsOf: URL(fileURLWithPath: (dir as NSString)
                .appendingPathComponent("verifiers"))), encoding: .utf8)?
                .split(whereSeparator: \.isNewline).last.map(String.init)
        )
        try Self.write("""
            ada     passphrase  \(reissued.encoded)    -
            \(grace)
            """, to: (dir as NSString).appendingPathComponent("verifiers"))

        let after = try FileCredentialStore(
            directory: dir, throttle: FailureThrottle(ledger: try FileThrottleLedger(url: ledgerURL))
        )
        #expect(after.throttleKey(forPassphraseOf: "ada") != oldKey, "a new passphrase is a new authenticator")
        #expect(await after.subject(for: Passphrase(subjectID: "ada", secret: "a new one entirely"))?.id == "ada")
        // The old entry is orphaned, still disabled, and refers to a passphrase that no longer
        // exists anywhere.
        #expect(try await ledger.state(oldKey).isDisabled)
    }

    @Test("a ledger that fails refuses even the right passphrase")
    func failingLedgerRefuses() async throws {
        let dir = try Self.seed(try Self.directory())
        defer { Self.remove(dir) }

        let store = try FileCredentialStore(
            directory: dir, throttle: FailureThrottle(ledger: FailureThrottleCeilingTests.UnreachableLedger())
        )
        #expect(await store.resolve(Passphrase(subjectID: "ada", secret: "ada-secret")) == .refused(.throttled))
    }

    @Test("every subject without a passphrase shares one fixed key, so naming strangers can't grow the ledger")
    func unknownSubjectsShareAKey() async throws {
        let dir = try Self.seed(try Self.directory())
        defer { Self.remove(dir) }

        let store = try FileCredentialStore(directory: dir)
        #expect(store.throttleKey(forPassphraseOf: "nobody") == ThrottleKey.unknownPassphrase)
        #expect(store.throttleKey(forPassphraseOf: "stranger") == ThrottleKey.unknownPassphrase)
        #expect(store.throttleKey(forPassphraseOf: "ada") != store.throttleKey(forPassphraseOf: "grace"))
        #expect(store.throttleKey(forPassphraseOf: "ada").subjectID == "ada")
    }
}
