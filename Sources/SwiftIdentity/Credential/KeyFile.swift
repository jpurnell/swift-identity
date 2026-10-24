import Foundation

/// Why a secret key file can't be used.
public enum KeyFileFailure: Error, Equatable {
    /// The file is readable or writable by its group or by others.
    case readableByOthers
    /// The file isn't 32 bytes.
    case wrongSize(Int)
    /// Creating found a file already there, and a key is never overwritten: replacing one
    /// orphans everything made under it.
    case alreadyExists
    /// The file couldn't be written.
    case cannotWrite
}

/// The rules for a 32-byte secret key held in its own file: the sealing key and the pepper.
///
/// Owner-only, exactly 32 bytes, never overwritten; anything else is refused when it's loaded,
/// the same startup-fatal rule the file store applies to its own files.
enum KeyFile {

    static func read(_ url: URL) throws -> Data {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        let mode = (attributes[.posixPermissions] as? Int) ?? 0o777
        guard mode & 0o077 == 0 else { throw KeyFileFailure.readableByOthers }
        let data = try Data(contentsOf: url)
        guard data.count == 32 else { throw KeyFileFailure.wrongSize(data.count) }
        return data
    }

    static func create<Generator: RandomNumberGenerator>(at url: URL, using generator: inout Generator) throws {
        guard !FileManager.default.fileExists(atPath: url.path) else { throw KeyFileFailure.alreadyExists }
        let bytes = (0..<32).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
        guard FileManager.default.createFile(
            atPath: url.path, contents: Data(bytes), attributes: [.posixPermissions: 0o600]
        ) else { throw KeyFileFailure.cannotWrite }
    }
}
