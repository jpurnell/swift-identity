#if canImport(os)
import os
#endif
import Crypto
import Foundation
import _CryptoExtras

/// What is stored for a passphrase, and what checking one costs.
///
/// ## Why this kind is slow on purpose
///
/// A passphrase is the only credential here a person could plausibly guess. Every other kind is
/// 128 bits or more of machine randomness, verified against a fast hash — deliberately, because
/// a work factor defends a guessable secret and buys nothing against a value no one will ever
/// enumerate. This is the kind that needs one.
///
/// So verification is **hundreds of thousands of rounds**, and that cost is the defence: it
/// scales with the attacker's hardware rather than with anyone's willingness to keep state.
/// Throttling is a second line, not the first.
///
/// ## `KDF.Insecure` is not a warning about this
///
/// swift-crypto files PBKDF2 under `Insecure` because it is weaker than scrypt or Argon2id at
/// equal cost, not because it is unfit or misused. It is what this package can reach on every
/// platform it targets; the stored form carries an algorithm name so that a better one is a
/// different verifier rather than a silently mis-derived one.
public struct PassphraseVerifier: Sendable, Equatable {

    /// Why a verifier could not be made.
    public enum Failure: Error, Equatable {
        /// Fewer rounds than the floor swift-crypto enforces.
        case roundsBelowFloor(requested: Int, floor: Int)
        /// The key derivation itself failed.
        case derivationFailed
    }

    /// The algorithm this type implements, as it appears in the stored value.
    public static let algorithm = "pbkdf2-sha256"

    /// The fewest rounds swift-crypto will derive with.
    public static let roundFloor = 210_000

    /// Rounds used for a new verifier.
    ///
    /// 600,000, which is OWASP's guidance for PBKDF2-HMAC-SHA256 as of their 2023 revision.
    /// Stored per verifier rather than assumed, so raising this number ages existing
    /// passphrases into a rotation rather than into a parse failure.
    public static let defaultRounds = 600_000

    /// How many rounds this verifier was derived with.
    public let rounds: Int
    /// The salt, unique to this verifier.
    public let salt: [UInt8]
    /// The derived key.
    public let digest: [UInt8]

    /// Derives a verifier for a passphrase, salting it from a generator you supply.
    ///
    /// There is deliberately no overload that picks the generator. This package declines to
    /// choose a deployment's randomness for the same reason it declines to choose where
    /// credentials live: a security decision hidden inside a library is invisible. In production
    /// that is one visible line —
    ///
    /// ```swift
    /// let passphrase = Passphrase(subjectID: "ada", secret: "correct horse battery staple")
    /// var generator = SystemRandomNumberGenerator()
    /// let verifier = try PassphraseVerifier(for: passphrase, using: &generator)
    /// ```
    ///
    /// — and in a test it is a seeded generator, which is what makes a salt assertable.
    ///
    /// - Parameters:
    ///   - passphrase: The passphrase and the subject claiming it.
    ///   - generator: The source the salt is drawn from.
    ///   - rounds: Iteration count. Defaults to ``defaultRounds``.
    /// - Throws: ``Failure``.
    public init<Generator: RandomNumberGenerator>(
        for passphrase: Passphrase,
        using generator: inout Generator,
        rounds: Int = PassphraseVerifier.defaultRounds
    ) throws {
        let salt = (0..<16).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
        try self.init(for: passphrase, rounds: rounds, salt: salt)
    }

    /// Derives a verifier against a salt you supply.
    ///
    /// Used to re-derive when checking, and by tests that need a fixed salt. A caller minting a
    /// new verifier should use ``init(for:rounds:)`` and let the salt be fresh.
    init(for passphrase: Passphrase, rounds: Int, salt: [UInt8]) throws {
        guard rounds >= Self.roundFloor else {
            throw Failure.roundsBelowFloor(requested: rounds, floor: Self.roundFloor)
        }
        self.rounds = rounds
        self.salt = salt
        self.digest = try Self.derive(passphrase, rounds: rounds, salt: salt)
    }

    /// Rebuilds a verifier from its stored form.
    ///
    /// - Parameter encoded: `pbkdf2-sha256$<rounds>$<salt>$<digest>`.
    /// - Returns: The verifier, or nil if the value is not one this package wrote.
    public init?(encoded: String) {
        let parts = encoded.split(separator: "$", omittingEmptySubsequences: false)
        guard parts.count == 4, parts[0] == Self.algorithm else { return nil }
        guard let rounds = Int(parts[1]), rounds >= Self.roundFloor else { return nil }
        guard let salt = Self.decode(String(parts[2])), !salt.isEmpty,
              let digest = Self.decode(String(parts[3])), !digest.isEmpty else { return nil }

        self.rounds = rounds
        self.salt = salt
        self.digest = digest
    }

    /// The stored form: one field, so the verifiers file keeps one shape for every kind.
    public var encoded: String {
        "\(Self.algorithm)$\(rounds)$\(Self.encode(salt))$\(Self.encode(digest))"
    }

    /// Whether `passphrase` derives to this verifier.
    ///
    /// - Parameter passphrase: The presented passphrase and the subject it claims.
    /// - Returns: Whether it matches.
    public func matches(_ passphrase: Passphrase) -> Bool {
        do {
            return ConstantTime.equals(
                try Self.derive(passphrase, rounds: rounds, salt: salt), digest
            )
        } catch {
            // A derivation that fails proves nothing, so it matches nothing. The rounds were
            // checked when this verifier was built, which is why there is no path here in
            // practice — and exactly why it is recorded rather than swallowed if there ever is.
            #if canImport(os)
            Logger(subsystem: "org.roseclub.swiftidentity", category: "passphrase")
                .fault("passphrase derivation failed: \(String(describing: error), privacy: .public)")
            #endif
            return false
        }
    }

    /// The derivation itself.
    ///
    /// The subject is mixed into the password rather than only into the salt. A random salt
    /// already stops two people with the same words colliding; binding the subject additionally
    /// means a verifier line **moved to another subject** in the file stops working, which is
    /// what makes a hand-edited roster safe to hand-edit.
    private static func derive(_ passphrase: Passphrase, rounds: Int, salt: [UInt8]) throws -> [UInt8] {
        let material = Data("\(passphrase.subjectID)|\(passphrase.secret)".utf8)
        do {
            let key = try KDF.Insecure.PBKDF2.deriveKey(
                from: material, salt: salt, using: .sha256, outputByteCount: 32, rounds: rounds
            )

            // Copied into a buffer that already exists, rather than returned out of the block.
            // `Array($0)` is a copy too and is safe, but it is indistinguishable to a reader —
            // and to the checker — from returning the pointer itself. This form says which one
            // it is. `SymmetricKey` offers no way to reach its bytes without a with-block.
            var derived = [UInt8](repeating: 0, count: 32)
            key.withUnsafeBytes { buffer in
                for (offset, byte) in buffer.enumerated() where offset < derived.count {
                    derived[offset] = byte
                }
            }
            return derived
        } catch {
            throw Failure.derivationFailed
        }
    }

    /// Unpadded base64url, so a stored value never contains `$` or `=`.
    private static func encode(_ bytes: [UInt8]) -> String {
        Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private static func decode(_ text: String) -> [UInt8]? {
        let alphabet = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        guard !text.isEmpty, text.allSatisfy(alphabet.contains) else { return nil }
        var standard = text.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        standard += String(repeating: "=", count: (4 - standard.count % 4) % 4)
        return Data(base64Encoded: standard).map(Array.init)
    }
}
