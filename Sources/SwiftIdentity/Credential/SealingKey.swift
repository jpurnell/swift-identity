import Crypto
import Foundation

/// The key that seals one-time-code keys at rest: AES-256-GCM, from a file held apart from the
/// identity store.
///
/// ## Why this exists, when everything else here is hashed
///
/// A one-time-code verifier recomputes the code, so it needs the key itself, not a digest of it.
/// NIST SP 800-63B-4 §3.1.4.2 requires those keys to be "strongly protected against
/// unauthorized disclosure". Sealing them under a key kept in a different file means a copy of
/// the identity store alone discloses nothing. It's the one secret this package stores that it
/// can't hash, and the DocC says so rather than letting it pass as another digest.
///
/// The file is 32 bytes, owner-only. Anything else is refused when it's loaded, the same
/// startup-fatal rule the file store applies to its own files.
public struct SealingKey: Sendable {

    /// Why a sealing key can't be used: the key-file rules every secret key here shares.
    public typealias Failure = KeyFileFailure

    let key: SymmetricKey

    /// Loads a sealing key, refusing a file anyone but its owner can reach.
    ///
    /// - Parameter url: The key file.
    /// - Throws: ``Failure``, or the error reading the file.
    public init(contentsOf url: URL) throws {
        key = SymmetricKey(data: try KeyFile.read(url))
    }

    /// Writes a new sealing key, owner-only, from a generator you supply.
    ///
    /// Never overwrites: replacing a sealing key orphans every key sealed under it.
    ///
    /// ```swift
    /// let url = URL(fileURLWithPath: "/etc/household/totp-sealing.key")
    /// var generator = SystemRandomNumberGenerator()
    /// try SealingKey.create(at: url, using: &generator)
    /// let sealingKey = try SealingKey(contentsOf: url)
    /// ```
    ///
    /// - Parameters:
    ///   - url: Where to write it.
    ///   - generator: An approved random bit generator in production (§3.2.12).
    /// - Throws: ``Failure``.
    public static func create<Generator: RandomNumberGenerator>(at url: URL, using generator: inout Generator) throws {
        try KeyFile.create(at: url, using: &generator)
    }

    /// Seals `plaintext`, bound to `context`: opening it with any other context fails.
    func seal<Generator: RandomNumberGenerator>(
        _ plaintext: [UInt8], context: String, using generator: inout Generator
    ) throws -> [UInt8] {
        let nonceBytes = (0..<12).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
        let nonce = try AES.GCM.Nonce(data: nonceBytes)
        let box = try AES.GCM.seal(plaintext, using: key, nonce: nonce, authenticating: Data(context.utf8))
        guard let combined = box.combined else { throw OneTimeCodeVerifier.Failure.sealingFailed }
        return Array(combined)
    }

    /// Opens what ``seal(_:context:using:)`` produced, if `context` matches.
    func open(_ sealed: [UInt8], context: String) throws -> [UInt8] {
        let box = try AES.GCM.SealedBox(combined: sealed)
        return Array(try AES.GCM.open(box, using: key, authenticating: Data(context.utf8)))
    }
}
