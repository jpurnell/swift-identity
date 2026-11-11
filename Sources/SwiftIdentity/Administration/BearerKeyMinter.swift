import Crypto
import Foundation

/// A freshly minted bearer key and the digest the verifiers file keeps for it.
///
/// The key is shown to the person who asked for it once, and nowhere else: this type does not print it, in either description.
public struct MintedKey: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    /// The key itself. Hand it over once; it is not stored anywhere.
    public let key: String
    /// The SHA-256 digest the verifiers file holds (64 hexadecimal characters).
    public let digest: String

    /// A description that names the digest's start and never the key.
    public var description: String { "MintedKey(digest: \(digest.prefix(8))…, key: <redacted>)" }

    /// The same, so a debugger or `String(reflecting:)` cannot print the key either.
    public var debugDescription: String { description }
}

/// Makes bearer keys: 256 random bits as base64url, so a key is a valid header value and never needs quoting.
///
/// There is deliberately no work factor on how a key is checked: 256 bits of machine-generated randomness is not guessable, so a
/// slow hash would be paid on every request to defend against nothing (see ``BearerKey``).
public struct BearerKeyMinter: Sendable {
    private let prefix: String

    /// - Parameter prefix: Text put in front of the key, such as `ijs_`; empty by default. Letters, digits, `-` and `_` only.
    public init(prefix: String = "") {
        self.prefix = prefix
    }

    /// A new key from the generator the caller supplies.
    ///
    /// The generator is a parameter so that a test can make a reproducible key. A real service passes `SystemRandomNumberGenerator()`
    /// once, at its own entry point, and nowhere in between.
    public func mint<Generator: RandomNumberGenerator>(using generator: inout Generator) -> MintedKey {
        var bytes = [UInt8]()
        bytes.reserveCapacity(32)
        for _ in 0..<32 { bytes.append(UInt8.random(in: UInt8.min...UInt8.max, using: &generator)) }
        let encoded = Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        let key = prefix + encoded
        let digest = SHA256.hash(data: Data(key.utf8)).map { Hex.byte($0) }.joined()
        return MintedKey(key: key, digest: digest)
    }
}
