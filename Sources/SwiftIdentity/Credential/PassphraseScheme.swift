import Crypto
import Foundation
import _CryptoExtras

/// One way of deriving a passphrase digest, named by the first field of the stored form.
///
/// A scheme derives bytes and never compares them: the comparison stays in
/// ``PassphraseVerifier``, in constant time, so a scheme written outside this package can't skip
/// it. An identifier is never reused for a different derivation; a changed derivation is a new
/// identifier, which is how a stored digest says exactly what produced it.
///
/// Schemes are values rather than types, so a set of them is an ordinary `Sendable` array.
public protocol PassphraseScheme: Sendable {
    /// The stored form's first field, such as `pbkdf2-sha256-c1`.
    var identifier: String { get }
    /// The canonicalization applied to the secret before derivation, or nil for none (only the
    /// legacy 0.6.x scheme has none).
    var canonicalization: PassphraseCanonicalization? { get }
    /// Whether a stored cost field is one this scheme will derive with. Checked on decoding, so
    /// a stored value can't choose a cost the deployment never would.
    func isValid(parameters: String) -> Bool
    /// The digest of `material` (the subject ID, a separator and the secret, as bytes).
    func derive(_ material: [UInt8], parameters: String, salt: [UInt8]) throws -> [UInt8]
    /// Whether a digest at `parameters` costs less than this scheme now asks for.
    func isBelowCurrentCost(_ parameters: String) -> Bool
}

extension PassphraseScheme {
    /// Never, unless a scheme says otherwise.
    public func isBelowCurrentCost(_ parameters: String) -> Bool { false }
}

/// PBKDF2-HMAC-SHA256 over the canonical secret: what this package writes.
///
/// NIST SP 800-63B-4 §3.1.1.2 asks for "an approved password hashing scheme published in the
/// latest revision of [SP800-132]", which is PBKDF2. The cost is the round count, stored.
public struct PBKDF2SHA256C1: PassphraseScheme {
    /// `pbkdf2-sha256-c1`.
    public let identifier = "pbkdf2-sha256-c1"
    /// ``PassphraseCanonicalization/c1``.
    public let canonicalization: PassphraseCanonicalization? = .c1

    /// The scheme, with no state of its own.
    public init() {}

    /// A decimal round count at or above ``PassphraseVerifier/roundFloor``.
    public func isValid(parameters: String) -> Bool { PBKDF2SHA256.isValid(parameters) }

    /// PBKDF2-HMAC-SHA256, 32 bytes, at the stored round count.
    public func derive(_ material: [UInt8], parameters: String, salt: [UInt8]) throws -> [UInt8] {
        try PBKDF2SHA256.derive(material, parameters: parameters, salt: salt)
    }

    /// Below ``PassphraseVerifier/defaultRounds``.
    public func isBelowCurrentCost(_ parameters: String) -> Bool {
        (Int(parameters) ?? 0) < PassphraseVerifier.defaultRounds
    }
}

/// PBKDF2-HMAC-SHA256 over the raw secret, as 0.6.x wrote it.
///
/// Accepted so that existing digests keep verifying; ``PassphraseSchemes/standard`` never writes
/// it. A digest under it always needs upgrading, because it compares the secret byte for byte.
public struct PBKDF2SHA256Legacy: PassphraseScheme {
    /// `pbkdf2-sha256`.
    public let identifier = "pbkdf2-sha256"
    /// None: the raw secret, byte for byte.
    public let canonicalization: PassphraseCanonicalization? = nil

    /// The scheme, with no state of its own.
    public init() {}

    /// A decimal round count at or above ``PassphraseVerifier/roundFloor``.
    public func isValid(parameters: String) -> Bool { PBKDF2SHA256.isValid(parameters) }

    /// PBKDF2-HMAC-SHA256, 32 bytes, at the stored round count.
    public func derive(_ material: [UInt8], parameters: String, salt: [UInt8]) throws -> [UInt8] {
        try PBKDF2SHA256.derive(material, parameters: parameters, salt: salt)
    }

    /// Always: a legacy digest is upgraded whatever its cost, because it isn't canonicalized.
    public func isBelowCurrentCost(_ parameters: String) -> Bool { true }
}

/// The derivation both PBKDF2 schemes share.
enum PBKDF2SHA256 {

    static func isValid(_ parameters: String) -> Bool {
        guard let rounds = Int(parameters) else { return false }
        return rounds >= PassphraseVerifier.roundFloor && "\(rounds)" == parameters
    }

    static func derive(_ material: [UInt8], parameters: String, salt: [UInt8]) throws -> [UInt8] {
        guard let rounds = Int(parameters) else { throw PassphraseVerifier.Failure.derivationFailed }
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
            throw PassphraseVerifier.Failure.derivationFailed
        }
    }
}

/// The schemes a deployment accepts, and the one it writes.
///
/// Passed in, never global, so two stores in one process can differ and a test can't leak a
/// scheme into another test.
public struct PassphraseSchemes: Sendable {
    /// Accepted for verification, by identifier.
    let accepted: [String: any PassphraseScheme]
    /// The scheme new digests are written under.
    public let writing: any PassphraseScheme

    /// The legacy 0.6.x scheme (verify only) and `pbkdf2-sha256-c1`, which is written.
    public static let standard = PassphraseSchemes(
        [PBKDF2SHA256Legacy(), PBKDF2SHA256C1()], writing: PBKDF2SHA256C1()
    )

    /// A set of schemes. `writing` is accepted too, whether or not it's listed.
    public init(_ schemes: [any PassphraseScheme], writing: any PassphraseScheme) {
        var accepted: [String: any PassphraseScheme] = [:]
        for scheme in schemes { accepted[scheme.identifier] = scheme }
        accepted[writing.identifier] = writing
        self.accepted = accepted
        self.writing = writing
    }

    /// Whether a digest under `identifier` can be verified.
    public func accepts(_ identifier: String) -> Bool { accepted[identifier] != nil }

    /// The scheme named `identifier`, or nil: an unknown scheme fails closed.
    func scheme(named identifier: String) -> (any PassphraseScheme)? { accepted[identifier] }
}
