#if canImport(os)
import os
#endif
import Crypto
import Foundation

/// A code from an authenticator app (RFC 6238 TOTP), with the subject it claims.
///
/// Something the subject has: the app holding the key. Not phishing-resistant (NIST SP
/// 800-63B-4 §3.1.4: "OTP authentication is not phishing-resistant"), because a code typed into
/// a phishing site works on the real one for the rest of its window.
public struct OneTimeCode: Credential, Equatable {
    /// This kind's stable name.
    public static let kind = "totp"
    /// The subject the code claims, as a login form's username field says.
    public let subjectID: String
    /// The code as typed.
    public let code: String

    /// Wraps a presented code and the subject it claims.
    public init(subjectID: String, code: String) {
        self.subjectID = subjectID
        self.code = code
    }
}

/// How codes are computed: the hash, the number of digits, and the length of a step.
public struct OneTimeCodeParameters: Sendable, Hashable {

    /// The HMAC hash.
    public enum Algorithm: String, Sendable, Hashable, CaseIterable {
        /// HMAC-SHA-1: RFC 6238's default, and the one every authenticator app supports. Still
        /// approved for HMAC (SP 800-131A).
        case sha1
        /// HMAC-SHA-256.
        case sha256
        /// HMAC-SHA-512.
        case sha512
    }

    /// The hash.
    public let algorithm: Algorithm
    /// Digits per code: 6 to 8.
    public let digits: Int
    /// Seconds per step: 1 to 120 (§3.1.4.1: the nonce "SHALL be changed at least once every two
    /// minutes").
    public let period: Int

    /// HMAC-SHA-1, 6 digits, 30-second steps.
    public static let standard = OneTimeCodeParameters(algorithm: .sha1, digits: 6, period: 30)

    /// Parameters. ``isValid`` says whether a verifier will use them.
    public init(algorithm: Algorithm, digits: Int, period: Int) {
        self.algorithm = algorithm
        self.digits = digits
        self.period = period
    }

    /// Reads an identifier such as `totp-sha1-6-30`.
    public init?(identifier: String) {
        let parts = identifier.split(separator: "-", omittingEmptySubsequences: false)
        guard parts.count == 4, parts[0] == "totp",
              let algorithm = Algorithm(rawValue: String(parts[1])),
              let digits = Int(parts[2]), let period = Int(parts[3]) else { return nil }
        self.init(algorithm: algorithm, digits: digits, period: period)
        guard isValid, self.identifier == identifier else { return nil }
    }

    /// `totp-<hash>-<digits>-<period>`: the algorithm recorded for a verification (§4.6).
    public var identifier: String { "totp-\(algorithm.rawValue)-\(digits)-\(period)" }

    /// Whether a verifier will use these: 6 to 8 digits, a step of 1 to 120 seconds.
    public var isValid: Bool { (6...8).contains(digits) && (1...120).contains(period) }

    /// Key bytes for a new verifier: the hash's output length, so 160 bits for SHA-1.
    public var keyLength: Int {
        switch algorithm {
        case .sha1: 20
        case .sha256: 32
        case .sha512: 64
        }
    }

    /// The step `date` falls in, counting from the Unix epoch (T0 = 0), or nil for a date no
    /// step can represent (not finite, or out of range).
    public func step(at date: Date) -> Int64? {
        guard period > 0 else { return nil }
        let steps = (date.timeIntervalSince1970 / Double(period)).rounded(.down)
        guard steps.isFinite else { return nil }
        return Int64(exactly: steps)
    }
}

/// RFC 6238 over RFC 4226's dynamic truncation.
enum TOTP {

    static func code(key: [UInt8], step: Int64, parameters: OneTimeCodeParameters) -> String {
        // The step as eight big-endian bytes, by shifting rather than through a pointer.
        let counterValue = UInt64(bitPattern: step)
        let counter = (0..<8).map { UInt8(truncatingIfNeeded: counterValue >> UInt64(56 - 8 * $0)) }
        let mac = hmac(key: key, message: counter, algorithm: parameters.algorithm)
        guard let last = mac.last else { return "" }
        let offset = Int(last & 0x0F)
        guard offset + 3 < mac.count else { return "" }
        let binary = (UInt32(mac[offset] & 0x7F) << 24) | (UInt32(mac[offset + 1]) << 16)
            | (UInt32(mac[offset + 2]) << 8) | UInt32(mac[offset + 3])
        var modulus: UInt32 = 1
        for _ in 0..<parameters.digits { modulus *= 10 }
        let value = String(binary % modulus)
        return String(repeating: "0", count: max(0, parameters.digits - value.count)) + value
    }

    private static func hmac(key: [UInt8], message: [UInt8], algorithm: OneTimeCodeParameters.Algorithm) -> [UInt8] {
        let symmetric = SymmetricKey(data: key)
        switch algorithm {
        case .sha1: return Array(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: symmetric))
        case .sha256: return Array(HMAC<SHA256>.authenticationCode(for: message, using: symmetric))
        case .sha512: return Array(HMAC<SHA512>.authenticationCode(for: message, using: symmetric))
        }
    }
}

/// What's stored for one authenticator app: its key, sealed, and its parameters.
///
/// The stored form is `<identifier>$<sealed key>`, one field like a passphrase digest. The key is
/// sealed under a ``SealingKey`` and bound to the subject, so a line moved to another subject
/// stops opening, as a passphrase digest stops matching.
public struct OneTimeCodeVerifier: Sendable, Equatable {

    /// Why a verifier can't be made or used.
    public enum Failure: Error, Equatable {
        /// The sealed key doesn't open: a different sealing key, or a different subject.
        case cannotOpen
        /// Sealing failed.
        case sealingFailed
        /// The parameters aren't ones a verifier will use.
        case invalidParameters
        /// An issuer or account name containing `:`, which the URI format reserves.
        case invalidLabel
    }

    /// The subject the key is bound to.
    public let subjectID: String
    /// How codes are computed.
    public let parameters: OneTimeCodeParameters
    let sealed: [UInt8]

    /// A new verifier: a fresh key from your generator, sealed.
    ///
    /// - Parameters:
    ///   - subjectID: Who the authenticator app belongs to.
    ///   - generator: An approved random bit generator in production (§3.2.12); seeded in tests.
    ///   - sealingKey: The key the app's key is sealed under.
    ///   - parameters: Defaults to ``OneTimeCodeParameters/standard``.
    /// - Throws: ``Failure``.
    public init<Generator: RandomNumberGenerator>(
        for subjectID: String,
        using generator: inout Generator,
        sealingKey: SealingKey,
        parameters: OneTimeCodeParameters = .standard
    ) throws {
        guard parameters.isValid else { throw Failure.invalidParameters }
        let key = (0..<parameters.keyLength).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
        self.subjectID = subjectID
        self.parameters = parameters
        do {
            self.sealed = try sealingKey.seal(
                key, context: Self.context(subjectID, parameters), using: &generator
            )
        } catch {
            throw Failure.sealingFailed
        }
    }

    /// Rebuilds a verifier from its stored form, for the subject whose line it is.
    ///
    /// - Parameters:
    ///   - encoded: `<identifier>$<sealed key>`.
    ///   - subjectID: The subject the stored line belongs to.
    /// - Returns: The verifier, or nil if the value isn't one this type wrote.
    public init?(encoded: String, subjectID: String) {
        let parts = encoded.split(separator: "$", omittingEmptySubsequences: false)
        guard parts.count == 2, let parameters = OneTimeCodeParameters(identifier: String(parts[0])),
              let sealed = Base64URL.decode(String(parts[1])), !sealed.isEmpty else { return nil }
        self.subjectID = subjectID
        self.parameters = parameters
        self.sealed = sealed
    }

    /// The stored form.
    public var encoded: String { "\(parameters.identifier)$\(Base64URL.encode(sealed))" }

    /// The step `code` was valid for, if it matches within `window` steps of `date`.
    ///
    /// Every step in the window is checked, in constant time, whether or not an earlier one
    /// matched. The caller still has to consume the step (`ThrottleLedger`) before accepting: a
    /// code is accepted only once (§3.1.4.2).
    ///
    /// - Parameters:
    ///   - code: As typed: exactly ``OneTimeCodeParameters/digits`` ASCII digits.
    ///   - date: Now.
    ///   - sealingKey: The key this verifier's key is sealed under.
    ///   - window: Steps either side of now: 0 to 2, default 1 (§3.1.4.2's clock drift and entry
    ///     time).
    /// - Returns: The matching step, or nil.
    public func matchingStep(_ code: String, at date: Date, sealingKey: SealingKey, window: Int = 1) -> Int64? {
        let digits = Array(code.unicodeScalars)
        guard digits.count == parameters.digits, digits.allSatisfy({ ("0"..."9").contains($0) }),
              (0...2).contains(window) else { return nil }
        let key: [UInt8]
        do {
            key = try self.key(sealingKey: sealingKey)
        } catch {
            // Not a wrong code: the deployment's sealing key doesn't open this verifier, which is
            // an operator's problem to see. The subject is named; the key never is.
            #if canImport(os)
            Logger(subsystem: "org.roseclub.swiftidentity", category: "totp")
                .fault("one-time-code key for \(subjectID, privacy: .private) didn't open: \(String(describing: error), privacy: .public)")
            #endif
            return nil
        }

        guard let now = parameters.step(at: date) else { return nil }
        var matched: Int64?
        for offset in Int64(-window)...Int64(window) {
            let candidate = TOTP.code(key: key, step: now + offset, parameters: parameters)
            if ConstantTime.equals(Array(candidate.utf8), Array(code.utf8)) { matched = now + offset }
        }
        return matched
    }

    /// The `otpauth://totp/…` URI an authenticator app scans.
    ///
    /// It carries the key in the clear, so show it once, at enrollment, as a QR code or text, and
    /// never store it. Ask for one code back before saving the verifier, so a mis-scanned key is
    /// caught then rather than at the next sign-in.
    ///
    /// - Parameters:
    ///   - issuer: The service's name, as the app will show it.
    ///   - account: The subject's name, as the app will show it.
    ///   - sealingKey: The key this verifier's key is sealed under.
    /// - Returns: The URI.
    /// - Throws: ``Failure``.
    public func enrollmentURI(issuer: String, account: String, sealingKey: SealingKey) throws -> String {
        guard !issuer.contains(":"), !account.contains(":") else { throw Failure.invalidLabel }
        var components = URLComponents()
        components.scheme = "otpauth"
        components.host = "totp"
        components.path = "/\(issuer):\(account)"
        components.queryItems = [
            URLQueryItem(name: "secret", value: Base32.encode(try key(sealingKey: sealingKey), padded: false)),
            URLQueryItem(name: "issuer", value: issuer),
            URLQueryItem(name: "algorithm", value: parameters.algorithm.rawValue.uppercased()),
            URLQueryItem(name: "digits", value: "\(parameters.digits)"),
            URLQueryItem(name: "period", value: "\(parameters.period)"),
        ]
        guard let uri = components.string else { throw Failure.invalidLabel }
        return uri
    }

    /// The key, opened.
    func key(sealingKey: SealingKey) throws -> [UInt8] {
        do {
            return try sealingKey.open(sealed, context: Self.context(subjectID, parameters))
        } catch {
            throw Failure.cannotOpen
        }
    }

    /// What the seal is bound to: the kind, the parameters, and the subject.
    private static func context(_ subjectID: String, _ parameters: OneTimeCodeParameters) -> String {
        "totp|\(parameters.identifier)|\(subjectID)"
    }
}
