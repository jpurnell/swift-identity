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
public actor ReloadingCredentialStore: CredentialStore {

    /// What a look at the files led to.
    public enum Report: Sendable, Equatable {
        /// A changed pair of files loaded and is now being served.
        case reloaded
        /// A changed pair of files did not load; the last good store keeps serving.
        case refused(FileCredentialStore.Failure)
    }

    private var current: FileCredentialStore
    private let directory: String
    private let interval: TimeInterval
    private let now: @Sendable () -> Date
    private let audit: (any IdentityAudit)?
    private let onReload: @Sendable (Report) -> Void
    private var stamps: [SecureIdentityFiles.Stamp?]
    private var refusedStamps: [SecureIdentityFiles.Stamp?]?
    private var lastCheck: Date

    /// Loads the files, refusing anything ``FileCredentialStore`` refuses.
    ///
    /// - Parameters:
    ///   - directory: The absolute path of the directory holding `subjects` and `verifiers`.
    ///   - interval: The least time between looks at the files. One second by default.
    ///   - now: The clock, for expiry and for the interval; a test moves it.
    ///   - audit: Told the outcome of every resolution, as ``FileCredentialStore`` tells it.
    ///   - onReload: Told when a change was adopted and when one was refused.
    /// - Throws: ``FileCredentialStore/Failure``, always at startup.
    public init(
        directory: String, interval: TimeInterval = 1, now: @escaping @Sendable () -> Date = { Date() },
        audit: (any IdentityAudit)? = nil, onReload: @escaping @Sendable (Report) -> Void = { _ in }
    ) throws(FileCredentialStore.Failure) {
        switch Self.build(directory: directory, now: now, audit: audit) {
        case .success(let store): self.current = store
        case .failure(let failure): throw failure
        }
        self.directory = directory
        self.interval = interval
        self.now = now
        self.audit = audit
        self.onReload = onReload
        self.stamps = Self.stamps(of: directory)
        self.refusedStamps = nil
        self.lastCheck = now()
    }

    /// Resolves a credential against the current files, looking at them first if the interval has passed.
    public func resolve(_ credential: any Credential) async -> Resolution {
        let moment = now()
        if moment.timeIntervalSince(lastCheck) >= interval {
            lastCheck = moment
            _ = look()
        }
        return await current.resolve(credential)
    }

    /// Looks at the files now, whatever the interval.
    /// - Returns: What it led to, or `nil` if nothing had changed since the last look.
    @discardableResult
    public func reload() -> Report? {
        lastCheck = now()
        return look()
    }

    private func look() -> Report? {
        let seen = Self.stamps(of: directory)
        if seen == stamps { return nil }
        if let refused = refusedStamps, refused == seen { return nil }
        switch Self.build(directory: directory, now: now, audit: audit) {
        case .success(let store):
            current = store
            stamps = seen
            refusedStamps = nil
            onReload(.reloaded)
            return .reloaded
        case .failure(let failure):
            refusedStamps = seen
            onReload(.refused(failure))
            return .refused(failure)
        }
    }

    /// Builds a store from the files, naming any failure as a ``FileCredentialStore/Failure``. The store's own refusals pass
    /// through unchanged; anything else is carried into the failure's reason, so it is reported and never dropped.
    private static func build(
        directory: String, now: @escaping @Sendable () -> Date, audit: (any IdentityAudit)?
    ) -> Result<FileCredentialStore, FileCredentialStore.Failure> {
        Result { try FileCredentialStore(directory: directory, now: now, audit: audit) }.mapError { error in
            (error as? FileCredentialStore.Failure)
                ?? .unreadable(path: directory, reason: "the identity files could not be loaded: \(error)")
        }
    }

    private static func stamps(of directory: String) -> [SecureIdentityFiles.Stamp?] {
        [
            SecureIdentityFiles.stamp(of: directory + "/" + FileCredentialStore.subjectsFile),
            SecureIdentityFiles.stamp(of: directory + "/" + FileCredentialStore.verifiersFile),
        ]
    }
}
