import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// The file-system rules for identity files: owner-only, owned by the user running the service, never reached through a
/// symbolic link, and written so that a reader sees the old file or the new one and never half of either.
///
/// ``FileCredentialStore`` applies its own checks when it reads; this is the other half, for a service that also *changes* the
/// files while it runs, and for the stamps it uses to notice that someone else did.
public enum SecureIdentityFiles {

    /// A file's identity and modification time, to notice that it changed.
    ///
    /// A replaced file has a new inode, so a change is seen even when the size and the clock's second are the same.
    public struct Stamp: Equatable, Sendable {
        /// The file's inode.
        public let inode: UInt64
        /// The file's size in bytes.
        public let size: Int64
        /// Whole seconds of the modification time.
        public let seconds: Int
        /// The nanoseconds past that second.
        public let nanoseconds: Int
    }

    /// Why a path was refused. Each case names the path, never its contents.
    public enum Failure: Error, Equatable, Sendable {
        /// The path was relative, or climbed upwards; identity files are named absolutely.
        case unsafePath(String)
        /// The path could not be read: it is not there, or it could not be opened.
        case unreadable(String)
        /// The path is a symbolic link, whatever it points to.
        case symbolicLink(String)
        /// A directory where a file was expected, or a file where a directory was.
        case wrongKind(String)
        /// The path belongs to another user.
        case notOwned(String)
        /// The path can be entered or read by group or others.
        case permissive(String)
        /// Something is already at the path.
        case alreadyExists(String)
    }

    enum Kind {
        case file
        case directory
        case link
        case other
    }

    private static func examine(_ path: String) -> stat? {
        var info = stat()
        return lstat(path, &info) == 0 ? info : nil
    }

    private static func kind(of info: stat) -> Kind {
        switch Int(info.st_mode) & Int(S_IFMT) {
        case Int(S_IFREG): .file
        case Int(S_IFDIR): .directory
        case Int(S_IFLNK): .link
        default: .other
        }
    }

    private static func isSafe(_ path: String) -> Bool {
        path.hasPrefix("/") && !path.contains("..")
    }

    /// A path's modification stamp, or `nil` if there is nothing there (a link is itself, not what it points to).
    public static func stamp(of path: String) -> Stamp? {
        guard let info = examine(path) else { return nil }
        #if canImport(Darwin)
        let time = info.st_mtimespec
        #else
        let time = info.st_mtim
        #endif
        return Stamp(inode: UInt64(info.st_ino), size: Int64(info.st_size), seconds: Int(time.tv_sec), nanoseconds: Int(time.tv_nsec))
    }

    /// Refuses a path that is not an owner-only directory owned by this user.
    /// - Throws: ``Failure``.
    public static func requireDirectory(_ path: String) throws(Failure) {
        try require(.directory, at: path, owner: geteuid())
    }

    /// Refuses a path that is not an owner-only regular file owned by this user.
    /// - Throws: ``Failure``.
    public static func requireFile(_ path: String) throws(Failure) {
        try require(.file, at: path, owner: geteuid())
    }

    static func require(_ expected: Kind, at path: String, owner: uid_t) throws(Failure) {
        guard isSafe(path) else { throw .unsafePath(path) }
        guard let info = examine(path) else { throw .unreadable(path) }
        let actual = kind(of: info)
        guard actual != .link else { throw .symbolicLink(path) }
        guard actual == expected else { throw .wrongKind(path) }
        guard info.st_uid == owner else { throw .notOwned(path) }
        guard Int(info.st_mode) & 0o077 == 0 else { throw .permissive(path) }
    }

    /// Creates a directory that only the owner can enter, whatever the umask says. The parent must exist.
    /// - Throws: ``Failure/alreadyExists(_:)`` if something is there, otherwise ``Failure``.
    public static func makeDirectory(_ path: String) throws(Failure) {
        guard isSafe(path) else { throw .unsafePath(path) }
        guard mkdir(path, 0o700) == 0 else { throw errno == EEXIST ? .alreadyExists(path) : .unreadable(path) }
        guard chmod(path, 0o700) == 0 else { throw .unreadable(path) }
    }

    /// Writes `text` as a whole: to a new file only the owner can open, flushed, then renamed over the target.
    ///
    /// The new file is created exclusively and without following a link, so a planted link at its name is a failure and never a
    /// write through it. A link at the *target* is replaced by the file, and what it pointed to is untouched. A failure leaves no
    /// temporary file behind.
    /// - Throws: ``Failure``.
    public static func replace(_ path: String, with text: String) throws(Failure) {
        guard isSafe(path) else { throw .unsafePath(path) }
        let directory = (path as NSString).deletingLastPathComponent
        let name = (path as NSString).lastPathComponent
        let suffix = String(getpid()) + "-" + String(DispatchTime.now().uptimeNanoseconds, radix: 16)
        let temporary = directory + "/." + name + ".tmp-" + suffix
        let descriptor = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard descriptor >= 0 else { throw .unreadable(temporary) }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        do {
            try handle.write(contentsOf: Data(text.utf8))
            try handle.synchronize()
            try handle.close()
        } catch {
            unlink(temporary)
            throw .unreadable(path)
        }
        guard rename(temporary, path) == 0 else {
            unlink(temporary)
            throw .unreadable(path)
        }
    }
}
