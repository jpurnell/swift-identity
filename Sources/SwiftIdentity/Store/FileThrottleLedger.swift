#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import Foundation

/// A ledger in one file per host, shared by every process on it.
///
/// What makes NIST's ceiling mean something: a count that survives a restart, and one count
/// for every instance on the host rather than one each. For several hosts, one keeps this file
/// and the others ask it (§4.5 of the assurance amendment, "Across hosts").
///
/// ## Every operation is one locked transaction
///
/// Each call takes an exclusive `flock(2)` on a companion lock file, reads the ledger, changes
/// it, writes a temporary file and renames it over the ledger, then releases the lock. Three
/// choices in that sentence are load-bearing, and each is the subtle way this goes wrong:
///
/// - **`flock`, not `fcntl`.** An `fcntl` lock belongs to the process, so two handles in one
///   process don't exclude each other, and closing *any* descriptor on the file releases it.
///   An `flock` lock belongs to the open file description, so each handle's open is its own
///   lock, and only closing that descriptor releases it.
/// - **A separate lock file.** The ledger is replaced by rename, so a lock on the ledger itself
///   would be on an inode the next writer no longer opens. The lock file is never replaced.
/// - **Rename, not rewrite.** A crash mid-write leaves the old ledger whole rather than half a
///   new one, and a half-written ledger would be refused at the next start.
///
/// ## Every refusal is startup-fatal, and after that every failure refuses
///
/// Like ``FileCredentialStore``: a path that is relative or climbs, a ledger or lock file
/// anyone but its owner can open, or a ledger that doesn't parse, throws from `init`. After
/// startup the same conditions throw from the operation, and ``FailureThrottle`` refuses the
/// attempt. A ledger read as empty because it was unreadable would re-enable every disabled
/// authenticator, which is the failure this exists to prevent.
///
/// ## What it costs
///
/// One write per admitted attempt, made before it is checked, so at most a hundred per
/// authenticator before it is disabled and none for the refusals after: a guesser can make the
/// defender write a hundred times and then never again. A refused attempt writes nothing. A
/// success costs one more write, clearing the count its own attempt added. Waiting for the lock blocks the calling thread
/// for as long as another process holds it, which is the length of one small read and write.
public actor FileThrottleLedger: ThrottleLedger {

    /// Why a ledger was refused, at startup or afterwards.
    public enum Failure: Error, Equatable {
        /// The path was relative, or climbed upwards; a ledger is named absolutely.
        case unsafePath(path: String)
        /// The ledger or its lock could not be opened or read, and why.
        case unreadable(path: String, reason: String)
        /// A file is readable or writable by someone other than its owner.
        case permissive(path: String, mode: String)
        /// The ledger did not parse, was not a regular file, or was implausibly large.
        case malformed(path: String)
        /// The ledger could not be written, and why.
        case unwritable(path: String, reason: String)
    }

    /// Appended to the ledger's path to name its lock file.
    public static let lockSuffix = ".lock"

    /// The largest ledger that will be read. Far above what ``LedgerBook/maximumEntries`` keys
    /// produce, and a bound on what a corrupted or substituted file can make this allocate.
    static let maximumBytes = 64 << 20

    /// The format written, and the only one read.
    static let formatVersion = 1

    private let path: String
    private let lockPath: String
    private let policy: ThrottlePolicy

    /// Opens a ledger, creating it owner-only if it doesn't exist.
    ///
    /// - Parameters:
    ///   - url: An absolute file URL for the ledger. Its lock file is created beside it.
    ///   - policy: The backoff and ceiling failures are recorded under. Every process sharing
    ///     the file should use the same one; the ceiling a failure is recorded under is the one
    ///     its own process holds.
    /// - Throws: ``Failure``, at startup rather than at the first attempt.
    public init(url: URL, policy: ThrottlePolicy = .standard) throws {
        let path = url.path
        guard url.isFileURL, path.hasPrefix("/"), !url.pathComponents.contains("..") else {
            throw Failure.unsafePath(path: path)
        }
        self.path = path
        self.lockPath = path + Self.lockSuffix
        self.policy = policy

        try Self.locked(lockPath) {
            if access(path, F_OK) == 0 {
                // Read now so a bad file is a startup failure, not the first sign-in's.
                _ = try Self.readBook(path)
            } else {
                try Self.writeBook(LedgerBook(), to: path)
            }
        }
    }

    // MARK: - ThrottleLedger

    /// Adds one failure. See ``ThrottleLedger/recordFailure(_:at:)``.
    public func recordFailure(_ key: ThrottleKey, at time: Date) throws -> ThrottleState {
        try recordFailure(involving: [key], at: time).first ?? .clear
    }

    /// Adds one failure to each key. See ``ThrottleLedger/recordFailure(involving:at:)``.
    public func recordFailure(involving keys: [ThrottleKey], at time: Date) throws -> [ThrottleState] {
        let policy = self.policy
        return try transact { book in
            try book.recordFailure(involving: keys, at: time, policy: policy)
        }
    }

    /// Refuses, or counts before checking. See ``ThrottleLedger/beginAttempt(_:at:)``.
    public func beginAttempt(_ key: ThrottleKey, at time: Date) throws -> Bool {
        let policy = self.policy
        return try transact { book in
            let admitted = try book.beginAttempt(key, at: time, policy: policy)
            // A refusal changes nothing, so writes nothing.
            return (admitted, admitted)
        }
    }

    /// Clears the count unless disabled. See ``ThrottleLedger/recordSuccess(_:)``.
    public func recordSuccess(_ key: ThrottleKey) throws {
        try transact { book in ((), book.recordSuccess(key)) }
    }

    /// The current state. See ``ThrottleLedger/state(_:)``.
    public func state(_ key: ThrottleKey) throws -> ThrottleState {
        let ceiling = policy.ceiling
        return try transact { book in (book.state(key, ceiling: ceiling), false) }
    }

    /// Forgets the key. See ``ThrottleLedger/rebound(_:)``.
    public func rebound(_ key: ThrottleKey) throws {
        try transact { book in ((), book.rebound(key)) }
    }

    /// Disables all if any is disabled. See ``ThrottleLedger/disableTogether(_:)``.
    public func disableTogether(_ keys: [ThrottleKey]) throws -> Bool {
        let ceiling = policy.ceiling
        return try transact { book in book.disableTogether(keys, ceiling: ceiling) }
    }

    /// Consumes a step if it is later. See ``ThrottleLedger/consume(step:for:)``.
    public func consume(step: Int64, for key: ThrottleKey) throws -> Bool {
        try transact { book in
            let consumed = try book.consume(step: step, for: key)
            return (consumed, consumed)
        }
    }

    // MARK: - The transaction

    /// Reads, changes and — only if something changed — writes, all under the lock.
    private func transact<T>(_ body: (inout LedgerBook) throws -> (T, Bool)) throws -> T {
        let path = self.path
        return try Self.locked(lockPath) {
            var book = try Self.readBook(path)
            let (result, changed) = try body(&book)
            if changed { try Self.writeBook(book, to: path) }
            return result
        }
    }

    /// Runs `body` holding an exclusive `flock` on the lock file.
    ///
    /// The descriptor is closed on every path, which is also what releases the lock; there is
    /// no separate unlock to forget.
    private static func locked<T>(_ lockPath: String, _ body: () throws -> T) throws -> T {
        let descriptor = open(lockPath, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0o600)
        guard descriptor >= 0 else { throw Failure.unreadable(path: lockPath, reason: errorText()) }
        defer { close(descriptor) }

        // Checked on the open descriptor, not the path, so the file checked is the file locked.
        // Anyone who can open the lock can hold it, and a held lock refuses every passphrase.
        try checkOwnerOnly(descriptor, path: lockPath)

        var interruptions = 0
        while flock(descriptor, LOCK_EX) != 0 {
            // Only an interrupted wait is retried, and only so often; anything else, or a signal
            // storm, refuses rather than proceeding unlocked.
            guard errno == EINTR, interruptions < 100 else {
                throw Failure.unreadable(path: lockPath, reason: errorText())
            }
            interruptions += 1
        }
        return try body()
    }

    /// Refuses a descriptor whose file is not a regular file only its owner can open.
    private static func checkOwnerOnly(_ descriptor: Int32, path: String) throws {
        var info = stat()
        guard fstat(descriptor, &info) == 0 else { throw Failure.unreadable(path: path, reason: errorText()) }
        guard (info.st_mode & S_IFMT) == S_IFREG else { throw Failure.malformed(path: path) }
        let mode = Int(info.st_mode) & 0o7777
        guard mode & 0o077 == 0 else { throw Failure.permissive(path: path, mode: String(mode, radix: 8)) }
    }

    // MARK: - Reading and writing

    /// One key's record, as it appears in the file.
    private struct Row: Codable {
        let subjectID: String
        let authenticator: String
        let entry: LedgerEntry
    }

    /// The file: a version, and the rows sorted so the same state is always the same bytes.
    private struct Document: Codable {
        let version: Int
        let entries: [Row]
    }

    private static func readBook(_ path: String) throws -> LedgerBook {
        let descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        guard descriptor >= 0 else { throw Failure.unreadable(path: path, reason: errorText()) }
        defer { close(descriptor) }
        try checkOwnerOnly(descriptor, path: path)

        // Through a handle on the descriptor already checked, which doesn't close it: the
        // `defer` above does, on every path.
        let bytes: Data
        do {
            bytes = try FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
                .read(upToCount: maximumBytes + 1) ?? Data()
        } catch {
            throw Failure.unreadable(path: path, reason: error.localizedDescription)
        }
        guard bytes.count <= maximumBytes else { throw Failure.malformed(path: path) }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        let document: Document
        do {
            document = try decoder.decode(Document.self, from: bytes)
        } catch {
            // Rethrown as the located failure, which is what reaches the operator: at startup
            // it is the reason the service didn't start.
            throw Failure.malformed(path: path)
        }
        // A version this code didn't write is refused rather than read as best it can: a
        // field it doesn't know might be the one that says "disabled".
        guard document.version == formatVersion else { throw Failure.malformed(path: path) }
        var book = LedgerBook()
        for row in document.entries {
            let key = ThrottleKey(subjectID: row.subjectID, authenticator: row.authenticator)
            // A key twice is a file nobody here wrote, and which row wins would be arbitrary.
            guard book.entries.updateValue(row.entry, forKey: key) == nil else {
                throw Failure.malformed(path: path)
            }
        }
        return book
    }

    private static func writeBook(_ book: LedgerBook, to path: String) throws {
        let rows = book.entries
            .map { Row(subjectID: $0.key.subjectID, authenticator: $0.key.authenticator, entry: $0.value) }
            .sorted { ($0.subjectID, $0.authenticator) < ($1.subjectID, $1.authenticator) }
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        encoder.outputFormatting = [.sortedKeys]
        let data: Data
        do {
            data = try encoder.encode(Document(version: formatVersion, entries: rows))
        } catch {
            throw Failure.unwritable(path: path, reason: String(describing: error))
        }

        let url = URL(fileURLWithPath: path)
        let temporary = url.deletingLastPathComponent()
            .appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString).tmp").path
        // Created owner-only and exclusively, so the file that becomes the ledger was never
        // readable by anyone else, even for the moment before the rename.
        let descriptor = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0o600)
        guard descriptor >= 0 else { throw Failure.unwritable(path: temporary, reason: errorText()) }

        var renamed = false
        defer { if !renamed { unlink(temporary) } }
        do {
            defer { close(descriptor) }
            do {
                let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
                try handle.write(contentsOf: data)
                // Durable before it is renamed into place, or a crash could leave a ledger
                // whose name points at nothing written.
                try handle.synchronize()
            } catch {
                throw Failure.unwritable(path: temporary, reason: error.localizedDescription)
            }
        }
        guard rename(temporary, path) == 0 else { throw Failure.unwritable(path: path, reason: errorText()) }
        renamed = true
    }

    private static func errorText() -> String {
        String(cString: strerror(errno))
    }
}
