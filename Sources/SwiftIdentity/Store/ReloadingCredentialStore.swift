import Foundation

/// A credential store that notices its files changed, so a key can be added, rotated or revoked while the service runs.
///
/// It wraps ``FileCredentialStore``, which reads its two files once and refuses to start on anything it cannot trust, and keeps
/// that property where it matters: **startup is still fatal**. After that it looks at the files' stamps at most once per
/// `interval`, on a resolve, and when they changed it builds a new store.
///
/// **A bad replacement is never adopted.** If the new files do not load (a typo in an edit, a file made readable by others, a
/// link put in its place) the last good store keeps serving, and the refusal is reported once through `onReload`. It is not
/// reported again for the same files, only if they change again. A store that fell over on a bad edit would be a denial of service
/// for whoever can write the file.
///
/// The interval is the bound on how long a revoked key can still verify. ``reload()`` looks at once, for an administrator who
/// has just made a change.
///
/// ## What 0.10.0 added
///
/// - **The throttle, sealing key and schemes are passed to every rebuilt store.** The same ``FailureThrottle`` object goes into
///   each one, so failure counts survive a swap. Without it, adopting this type would have switched throttling off.
/// - **``subject(id:)`` is synchronous**, for consumers that take a synchronous closure (a session store, passkey code). It
///   reads the current store under a lock and does the same interval check ``resolve(_:)`` does, so a revocation reaches a
///   held session at the next check even if nothing is resolving.
/// - **A parse that fails is tried once more before it is called a refusal**, because a reader can catch a file mid-write
///   (``SecureIdentityFiles/replace(_:with:)`` renames, so this is a second line of defence, not the first).
///
/// ## What a refusal looks like, and why it is not an audit event
///
/// A refusal reaches `onReload` once per change of the files, not on every check. A callback that fires every second for a
/// file nobody has touched is noise an operator learns to ignore; one that fires when the files change again says that the fix
/// did not take. It is deliberately not an ``IdentityEvent``: that type describes verification attempts, its ``IdentityEvent/Outcome``
/// is `CaseIterable` and consumers map every case to a log level, so a new case would change what 0.9.0 callers see.
public actor ReloadingCredentialStore: ThrottlingCredentialStore {

    /// What a look at the files led to.
    public enum Report: Sendable, Equatable {
        /// A changed pair of files loaded and is now being served.
        case reloaded
        /// A changed pair of files did not load; the last good store keeps serving.
        case refused(FileCredentialStore.Failure)
    }

    /// Builds a store from the files. A seam so a test can make a read fail without racing a writer.
    typealias Builder = @Sendable () -> Result<FileCredentialStore, FileCredentialStore.Failure>

    /// The state a look reads and a swap writes, behind one lock so a reader sees one whole generation.
    // Justification: every access to the mutable state is serialised by `lock`, so it is never reached concurrently.
    private final class Snapshot: @unchecked Sendable {
        private let lock = NSLock()
        private var current: FileCredentialStore
        private var stamps: [SecureIdentityFiles.Stamp?]
        private var refusedStamps: [SecureIdentityFiles.Stamp?]?
        private var lastCheck: Date
        private let directory: String
        private let interval: TimeInterval
        private let now: @Sendable () -> Date
        private let builder: Builder

        init(first: FileCredentialStore, directory: String, interval: TimeInterval, now: @escaping @Sendable () -> Date, builder: @escaping Builder) {
            self.current = first
            self.directory = directory
            self.interval = interval
            self.now = now
            self.builder = builder
            self.stamps = ReloadingCredentialStore.stamps(of: directory)
            self.refusedStamps = nil
            self.lastCheck = now()
        }

        /// The store to use, after a look if `force` or the interval has passed. The report is for the caller to deliver
        /// once the lock is released.
        func store(force: Bool) -> (FileCredentialStore, Report?) {
            lock.lock(); defer { lock.unlock() }
            let moment = now()
            guard force || moment.timeIntervalSince(lastCheck) >= interval else { return (current, nil) }
            lastCheck = moment
            let report = look()
            return (current, report)
        }

        private func look() -> Report? {
            let seen = ReloadingCredentialStore.stamps(of: directory)
            if seen == stamps { return nil }
            if let refused = refusedStamps, refused == seen { return nil }
            // A second attempt, because the first may have caught a file mid-write.
            let built = builder()
            let outcome: Result<FileCredentialStore, FileCredentialStore.Failure>
            switch built {
            case .success: outcome = built
            case .failure: outcome = builder()
            }
            switch outcome {
            case .success(let store):
                current = store
                stamps = seen
                refusedStamps = nil
                return .reloaded
            case .failure(let failure):
                refusedStamps = seen
                return .refused(failure)
            }
        }
    }

    private let snapshot: Snapshot
    private let onReload: @Sendable (Report) -> Void

    /// Loads the files, refusing anything ``FileCredentialStore`` refuses.
    ///
    /// - Parameters:
    ///   - directory: The absolute path of the directory holding `subjects` and `verifiers`.
    ///   - interval: The least time between looks at the files. One second by default.
    ///   - now: The clock, for expiry and for the interval; a test moves it.
    ///   - audit: Told the outcome of every resolution, as ``FileCredentialStore`` tells it.
    ///   - throttle: Counts consecutive passphrase failures. The same object goes into every rebuilt store, so the counts
    ///     survive a swap. `nil` disables throttling, as it does for ``FileCredentialStore``.
    ///   - sealingKey: Opens one-time-code keys, as for ``FileCredentialStore``.
    ///   - schemes: The passphrase schemes accepted, as for ``FileCredentialStore``.
    ///   - onReload: Told when a change was adopted and when one was refused, once per change of the files.
    /// - Throws: ``FileCredentialStore/Failure``, always at startup.
    public init(
        directory: String, interval: TimeInterval = 1, now: @escaping @Sendable () -> Date = { Date() },
        audit: (any IdentityAudit)? = nil, throttle: FailureThrottle? = nil, sealingKey: SealingKey? = nil,
        schemes: PassphraseSchemes = .standard, onReload: @escaping @Sendable (Report) -> Void = { _ in }
    ) throws(FileCredentialStore.Failure) {
        try self.init(
            directory: directory, interval: interval, now: now, onReload: onReload,
            builder: {
                Self.build(
                    directory: directory, now: now, throttle: throttle, audit: audit, sealingKey: sealingKey, schemes: schemes)
            })
    }

    init(
        directory: String, interval: TimeInterval, now: @escaping @Sendable () -> Date,
        onReload: @escaping @Sendable (Report) -> Void, builder build: @escaping Builder
    ) throws(FileCredentialStore.Failure) {
        switch build() {
        case .success(let store):
            self.snapshot = Snapshot(first: store, directory: directory, interval: interval, now: now, builder: build)
        case .failure(let failure):
            throw failure
        }
        self.onReload = onReload
    }

    /// Resolves a credential against the current files, looking at them first if the interval has passed.
    public func resolve(_ credential: any Credential) async -> Resolution {
        await current().resolve(credential)
    }

    /// Resolves a credential and names what it was verified with, as ``FileCredentialStore/resolveVerifying(_:)`` does.
    public func resolveVerifying(_ credential: any Credential) async -> (Resolution, algorithm: String?) {
        await current().resolveVerifying(credential)
    }

    /// The key a credential's attempts are counted under, from the current files.
    public nonisolated func throttleKey(for credential: any Credential) -> ThrottleKey? {
        current().throttleKey(for: credential)
    }

    /// The subject the current files name `id`, looking at them first if the interval has passed.
    ///
    /// Synchronous, for a session store or any consumer that takes a synchronous closure. A revoked or honeypot subject is
    /// returned carrying its status, as ``FileCredentialStore/subject(id:)`` returns it, so a revocation ends a held session at
    /// the next check.
    /// - Parameter id: A subject identifier, compared exactly.
    /// - Returns: The subject, or `nil`.
    public nonisolated func subject(id: String) -> Subject? {
        current().subject(id: id)
    }

    /// Looks at the files now, whatever the interval.
    /// - Returns: What it led to, or `nil` if nothing had changed since the last look.
    @discardableResult
    public func reload() -> Report? {
        let (_, report) = snapshot.store(force: true)
        deliver(report)
        return report
    }

    private nonisolated func current() -> FileCredentialStore {
        let (store, report) = snapshot.store(force: false)
        deliver(report)
        return store
    }

    private nonisolated func deliver(_ report: Report?) {
        guard let report else { return }
        onReload(report)
    }

    /// Builds a store from the files, naming any failure as a ``FileCredentialStore/Failure``. The store's own refusals pass
    /// through unchanged; anything else is carried into the failure's reason, so it is reported and never dropped.
    fileprivate static func build(
        directory: String, now: @escaping @Sendable () -> Date, throttle: FailureThrottle?, audit: (any IdentityAudit)?,
        sealingKey: SealingKey?, schemes: PassphraseSchemes
    ) -> Result<FileCredentialStore, FileCredentialStore.Failure> {
        Result {
            try FileCredentialStore(
                directory: directory, now: now, throttle: throttle, audit: audit, sealingKey: sealingKey, schemes: schemes)
        }.mapError { error in
            (error as? FileCredentialStore.Failure)
                ?? .unreadable(path: directory, reason: "the identity files could not be loaded: \(error)")
        }
    }

    fileprivate static func stamps(of directory: String) -> [SecureIdentityFiles.Stamp?] {
        [
            SecureIdentityFiles.stamp(of: directory + "/" + FileCredentialStore.subjectsFile),
            SecureIdentityFiles.stamp(of: directory + "/" + FileCredentialStore.verifiersFile),
        ]
    }
}
