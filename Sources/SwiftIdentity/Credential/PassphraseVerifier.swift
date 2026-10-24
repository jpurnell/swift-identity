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
///
/// ## Schemes
///
/// The stored form's first field names a ``PassphraseScheme``. New digests are
/// `pbkdf2-sha256-c1`: the secret is canonicalized first (``PassphraseCanonicalization/c1``), so
/// the same passphrase matches however a device encoded it. Digests 0.6.x wrote, `pbkdf2-sha256`,
/// keep verifying against the raw secret and are never written again; ``needsUpgrade(to:)`` says
/// which ones to re-derive. A scheme the deployment's ``PassphraseSchemes`` doesn't accept fails
/// closed: the stored value doesn't decode.
public struct PassphraseVerifier: Sendable, Equatable {

    /// Why a verifier could not be made.
    public enum Failure: Error, Equatable {
        /// Fewer rounds than the floor swift-crypto enforces.
        case roundsBelowFloor(requested: Int, floor: Int)
        /// The key derivation itself failed.
        case derivationFailed
        /// The secret can't be canonicalized under the scheme being written. The position, never
        /// the character.
        case refused(PassphraseCanonicalization.Refusal)
        /// Parameters the scheme being written won't derive with.
        case invalidParameters
    }

    /// The legacy 0.6.x scheme's identifier, which this type still reads.
    public static let algorithm = "pbkdf2-sha256"

    /// The fewest rounds swift-crypto will derive with.
    public static let roundFloor = 210_000

    /// Rounds used for a new verifier.
    ///
    /// 600,000, which is OWASP's guidance for PBKDF2-HMAC-SHA256 as of their 2023 revision.
    /// Stored per verifier rather than assumed, so raising this number ages existing
    /// passphrases into a rotation rather than into a parse failure.
    public static let defaultRounds = 600_000

    /// The scheme this verifier was derived under.
    public let scheme: any PassphraseScheme
    /// The scheme's cost field, as stored: for PBKDF2, the round count.
    public let parameters: String
    /// The salt, unique to this verifier.
    public let salt: [UInt8]
    /// The derived key.
    public let digest: [UInt8]

    /// How many rounds this verifier was derived with, for the PBKDF2 schemes.
    public var rounds: Int? { Int(parameters) }

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
    ///   - scheme: A PBKDF2 scheme. Defaults to the one ``PassphraseSchemes/standard`` writes.
    /// - Throws: ``Failure``.
    public init<Generator: RandomNumberGenerator>(
        for passphrase: Passphrase,
        using generator: inout Generator,
        rounds: Int = PassphraseVerifier.defaultRounds,
        scheme: any PassphraseScheme = PassphraseSchemes.standard.writing
    ) throws {
        guard rounds >= Self.roundFloor else {
            throw Failure.roundsBelowFloor(requested: rounds, floor: Self.roundFloor)
        }
        let salt = Self.salt(using: &generator)
        try self.init(for: passphrase, scheme: scheme, parameters: "\(rounds)", salt: salt)
    }

    /// Derives a verifier under whichever scheme `schemes` writes, with that scheme's parameters.
    ///
    /// - Parameters:
    ///   - passphrase: The passphrase and the subject claiming it.
    ///   - generator: The source the salt is drawn from.
    ///   - parameters: The cost field, in the writing scheme's own format.
    ///   - schemes: The deployment's schemes.
    /// - Throws: ``Failure``.
    public init<Generator: RandomNumberGenerator>(
        for passphrase: Passphrase,
        using generator: inout Generator,
        parameters: String,
        schemes: PassphraseSchemes
    ) throws {
        let salt = Self.salt(using: &generator)
        try self.init(for: passphrase, scheme: schemes.writing, parameters: parameters, salt: salt)
    }

    /// Derives a verifier against a salt you supply.
    ///
    /// Used by the public initializers, and by tests that need a fixed salt.
    init(for passphrase: Passphrase, scheme: any PassphraseScheme, parameters: String, salt: [UInt8]) throws {
        guard scheme.isValid(parameters: parameters) else { throw Failure.invalidParameters }
        let material: [UInt8]
        switch Self.material(passphrase, scheme: scheme) {
        case .success(let bytes): material = bytes
        case .failure(let refusal): throw Failure.refused(refusal)
        }
        self.scheme = scheme
        self.parameters = parameters
        self.salt = salt
        self.digest = try scheme.derive(material, parameters: parameters, salt: salt)
    }

    /// Rebuilds a verifier from its stored form.
    ///
    /// - Parameters:
    ///   - encoded: `<scheme>$<parameters>$<salt>$<digest>`.
    ///   - schemes: The schemes this deployment accepts. Defaults to ``PassphraseSchemes/standard``.
    /// - Returns: The verifier, or nil if the value isn't one an accepted scheme wrote.
    public init?(encoded: String, schemes: PassphraseSchemes = .standard) {
        let parts = encoded.split(separator: "$", omittingEmptySubsequences: false)
        guard parts.count == 4, let scheme = schemes.scheme(named: String(parts[0])) else { return nil }
        let parameters = String(parts[1])
        guard scheme.isValid(parameters: parameters) else { return nil }
        guard let salt = Base64URL.decode(String(parts[2])), !salt.isEmpty,
              let digest = Base64URL.decode(String(parts[3])), !digest.isEmpty else { return nil }

        self.scheme = scheme
        self.parameters = parameters
        self.salt = salt
        self.digest = digest
    }

    /// The stored form: one field, so the verifiers file keeps one shape for every kind.
    public var encoded: String {
        "\(scheme.identifier)$\(parameters)$\(Base64URL.encode(salt))$\(Base64URL.encode(digest))"
    }

    /// Whether `passphrase` derives to this verifier.
    ///
    /// A secret that can't be canonicalized under this verifier's scheme matches nothing.
    ///
    /// - Parameter passphrase: The presented passphrase and the subject it claims.
    /// - Returns: Whether it matches.
    public func matches(_ passphrase: Passphrase) -> Bool {
        guard case .success(let material) = Self.material(passphrase, scheme: scheme) else { return false }
        do {
            return ConstantTime.equals(
                try scheme.derive(material, parameters: parameters, salt: salt), digest
            )
        } catch {
            // A derivation that fails proves nothing, so it matches nothing. The parameters were
            // checked when this verifier was built, which is why there is no path here in
            // practice — and exactly why it is recorded rather than swallowed if there ever is.
            #if canImport(os)
            Logger(subsystem: "org.roseclub.swiftidentity", category: "passphrase")
                .fault("passphrase derivation failed: \(String(describing: error), privacy: .public)")
            #endif
            return false
        }
    }

    /// Whether this digest should be re-derived: it's under a scheme other than the one
    /// `schemes` writes, or below that scheme's current cost. A writable store re-derives after
    /// the next successful match; a read-only one reports it.
    ///
    /// - Parameter schemes: The deployment's schemes.
    /// - Returns: Whether to re-derive.
    public func needsUpgrade(to schemes: PassphraseSchemes) -> Bool {
        scheme.identifier != schemes.writing.identifier || scheme.isBelowCurrentCost(parameters)
    }

    /// Two verifiers are equal when they'd store the same value.
    public static func == (lhs: PassphraseVerifier, rhs: PassphraseVerifier) -> Bool {
        lhs.scheme.identifier == rhs.scheme.identifier && lhs.parameters == rhs.parameters
            && lhs.salt == rhs.salt && lhs.digest == rhs.digest
    }

    /// What's derived: the subject, a separator, and the secret, canonicalized if the scheme says.
    ///
    /// The subject is mixed into the password rather than only into the salt. A random salt
    /// already stops two people with the same words colliding; binding the subject additionally
    /// means a verifier line **moved to another subject** in the file stops working, which is
    /// what makes a hand-edited roster safe to hand-edit. Only the secret is canonicalized: the
    /// subject ID is an identifier, compared byte for byte.
    private static func material(
        _ passphrase: Passphrase, scheme: any PassphraseScheme
    ) -> Result<[UInt8], PassphraseCanonicalization.Refusal> {
        var secret = passphrase.secret
        if let canonicalization = scheme.canonicalization {
            switch canonicalization.canonicalize(secret) {
            case .success(let canonical): secret = canonical
            case .failure(let refusal): return .failure(refusal)
            }
        }
        return .success(Array("\(passphrase.subjectID)|".utf8) + Array(secret.utf8))
    }

    /// 128 bits of salt from the caller's generator.
    private static func salt<Generator: RandomNumberGenerator>(using generator: inout Generator) -> [UInt8] {
        (0..<16).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
    }
}
