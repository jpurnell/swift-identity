import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Fixtures for the administration and reload tests: real files in a temporary, owner-only directory.
enum AdministrationTestSupport {
    /// A fresh owner-only directory that exists (so a test can write into it).
    static func directory() throws -> String {
        let url = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("IdentityAdmin-\(UUID().uuidString)", isDirectory: true)
            .standardized
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        guard chmod(url.path, 0o700) == 0 else { throw CocoaError(.fileWriteNoPermission) }
        return url.path
    }

    /// A path inside a fresh temporary directory that does not exist yet (for `create`).
    static func absentDirectory() throws -> String {
        try directory() + "/identity"
    }

    static func remove(_ path: String) {
        try? FileManager.default.removeItem(at: URL(fileURLWithPath: path))
    }

    static func read(_ path: String) throws -> String {
        try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
    }

    /// The permission bits of a path, or nil.
    static func mode(of path: String) -> Int? {
        var info = stat()
        guard lstat(path, &info) == 0 else { return nil }
        return Int(info.st_mode) & 0o777
    }

    /// A clock the test moves.
    // Justification: every access to `instant` is serialised by `lock`, so the mutable state is never reached concurrently.
    final class Clock: @unchecked Sendable {
        private let lock = NSLock()
        private var instant = Date(timeIntervalSince1970: 1_800_000_000)

        var now: Date {
            lock.lock(); defer { lock.unlock() }
            return instant
        }

        func advance(_ interval: TimeInterval) {
            lock.lock(); defer { lock.unlock() }
            instant += interval
        }
    }
}
