#if canImport(os)
import os
#endif
import Crypto
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Passwords from previous breaches, looked up by k-anonymity range over Have I Been Pwned's
/// Pwned Passwords API.
///
/// NIST SP 800-63B-4 §3.1.1.2 says a blocklist includes "Passwords obtained from previous breach
/// corpuses". This is that list, without holding it: the breach corpus stays with a service that
/// speaks the range protocol, and only a hash prefix is sent to it.
///
/// ## The protocol
///
/// Have I Been Pwned's range search (<https://haveibeenpwned.com/API/v3#PwnedPasswords>):
///
/// 1. SHA-1 of the UTF-8 canonical passphrase, as 40 uppercase hex characters. SHA-1 is the
///    protocol's choice, not this package's: it's an index into a public corpus, never a stored
///    digest.
/// 2. `GET <base>/range/<first 5 characters>`. No API key is required.
/// 3. The response is one `SUFFIX:COUNT` line per hash with that prefix: the other 35 hex
///    characters, and how many times it was seen. The suffix is matched here, locally.
///
/// The request carries `Add-Padding: true`, so every response holds 800 to 1,000 lines whatever
/// the prefix and an observer can't learn anything from its size. The padding entries have a count
/// of 0 and are never a match.
///
/// ## What crosses the wire
///
/// Five hex characters of the hash: one of 1,048,576 buckets, each holding hundreds of breached
/// hashes. Never the passphrase, and never its full hash.
///
/// ## Off by default
///
/// Neither ``PassphrasePolicy/nist80063B4`` nor ``PassphrasePolicy/fips`` includes it, because it
/// sends something to a third party for every passphrase chosen. A deployment that wants it adds it:
///
/// ```swift
/// var policy = PassphrasePolicy.nist80063B4
/// policy.blocklists.append(BreachedPasswordRange.urlSession(timeout: .seconds(5)))
/// ```
///
/// ## When the service can't answer
///
/// A status other than 200, a body that doesn't parse, one over ``maximumResponseBytes``, or a
/// transport error all throw a ``Failure``, and the policy refuses the passphrase as
/// ``PassphrasePolicy/Violation/blocklistUnavailable(_:)``: an unchecked blocklist fails closed.
/// ``failsOpen`` is the opt-in alternative.
///
/// Parsing is strict. One malformed line makes the whole response malformed, never a line
/// silently skipped: a response that's partly wrong can't be trusted to be partly right.
public struct BreachedPasswordRange: PassphraseBlocklist {

    /// Sends a request and returns the body and response. Injected, so a host chooses the
    /// transport, and tests never touch the network.
    public typealias Fetch = @Sendable (URLRequest) async throws -> (Data, HTTPURLResponse)

    /// Why the range couldn't be checked.
    ///
    /// None of these carries the passphrase, its hash, or the request's URL, so each is safe to log.
    public enum Failure: Error, Sendable, Hashable {
        /// The service answered with a status other than 200.
        case status(Int)
        /// The body isn't a list of `SUFFIX:COUNT` lines. `line` is the first bad one, from 1; an
        /// empty body is line 1, and bytes outside ASCII are malformed wherever they appear.
        case malformed(line: Int)
        /// The body was larger than ``BreachedPasswordRange/maximumResponseBytes``.
        case oversize(maximumBytes: Int)
        /// The request didn't complete. The `URLError` code when there was one, and nothing else
        /// from the error: its description would include the URL.
        case transport(urlErrorCode: Int?)
        /// ``BreachedPasswordRange/urlSession(timeout:baseURL:minimumCount:failsOpen:session:)``
        /// was given a timeout that isn't positive. A misconfiguration rather than an outage, so it
        /// throws even when ``BreachedPasswordRange/failsOpen`` is set.
        case invalidTimeout
        /// The passphrase can't be canonicalized. ``PassphrasePolicy`` never asks about one; a
        /// direct caller might. Thrown even when failing open: it isn't an outage.
        case notCanonical
    }

    /// Have I Been Pwned's Pwned Passwords service, `https://api.pwnedpasswords.com`.
    public static let pwnedPasswords: URL = {
        var components = URLComponents()
        components.scheme = "https"
        components.host = "api.pwnedpasswords.com"
        // Assembled from two literals, so there's no path where this is nil. Were there one, the
        // fallback has no host, every fetch fails, and the policy fails closed.
        return components.url ?? URL(fileURLWithPath: "/")
    }()

    /// The largest body read: 2 MiB. A padded response is about 40 KB; anything this large isn't one.
    public static let maximumResponseBytes = 2 * 1_024 * 1_024

    /// ``BlocklistReason/breached``.
    public let reason = BlocklistReason.breached
    /// The service's root; requests go to `<baseURL>/range/<prefix>`.
    public let baseURL: URL
    /// The fewest sightings that count as breached. Never below 1, whatever was asked for: a
    /// padding entry, count 0, is never a match.
    public let minimumCount: Int
    /// Whether an unanswered lookup counts as not breached.
    ///
    /// Off by default: a lookup that fails throws, and the passphrase is refused as
    /// ``PassphrasePolicy/Violation/blocklistUnavailable(_:)`` until the service is back.
    ///
    /// On, a failure returns false and is logged. The trade: while the service is down, a breached
    /// passphrase can be accepted unchecked, and nothing tells the person choosing it. Choose it only
    /// when being unable to set a passphrase during an outage is the worse outcome, and keep the
    /// other blocklists, which don't depend on the network.
    public let failsOpen: Bool
    /// Whether requests ask for padding with `Add-Padding: true`. On by default.
    public let requestsPadding: Bool

    private let fetch: Fetch

    /// A range lookup over a transport you supply.
    ///
    /// - Parameters:
    ///   - baseURL: The service's root. Have I Been Pwned's, or a mirror speaking the same protocol.
    ///   - minimumCount: The fewest sightings that count as breached; values below 1 are treated as 1.
    ///   - failsOpen: Whether an unanswered lookup counts as not breached. See ``failsOpen``.
    ///   - requestsPadding: Whether to send `Add-Padding: true`.
    ///   - fetch: Sends the request. Its timeout is the caller's: this type never waits on its own.
    public init(
        baseURL: URL = BreachedPasswordRange.pwnedPasswords,
        minimumCount: Int = 1,
        failsOpen: Bool = false,
        requestsPadding: Bool = true,
        fetch: @escaping Fetch
    ) {
        self.baseURL = baseURL
        self.minimumCount = max(minimumCount, 1)
        self.failsOpen = failsOpen
        self.requestsPadding = requestsPadding
        self.fetch = fetch
    }

    /// A range lookup over `URLSession`.
    ///
    /// The timeout has no default. How long a person waits while choosing a passphrase is the
    /// deployment's decision, and a request without one could wait as long as the session allows.
    ///
    /// - Parameters:
    ///   - timeout: How long one request may take. Must be positive; otherwise every lookup throws
    ///     ``Failure/invalidTimeout``, without a request.
    ///   - baseURL: The service's root.
    ///   - minimumCount: The fewest sightings that count as breached.
    ///   - failsOpen: Whether an unanswered lookup counts as not breached. See ``failsOpen``.
    ///   - session: The session to send through.
    /// - Returns: The blocklist.
    public static func urlSession(
        timeout: Duration,
        baseURL: URL = BreachedPasswordRange.pwnedPasswords,
        minimumCount: Int = 1,
        failsOpen: Bool = false,
        session: URLSession = .shared
    ) -> BreachedPasswordRange {
        let (seconds, attoseconds) = timeout.components
        let interval = TimeInterval(seconds) + TimeInterval(attoseconds) / 1e18
        return BreachedPasswordRange(baseURL: baseURL, minimumCount: minimumCount, failsOpen: failsOpen) { request in
            guard interval > 0 else { throw Failure.invalidTimeout }
            var timed = request
            timed.timeoutInterval = interval
            let (data, response) = try await session.data(for: timed)
            guard let http = response as? HTTPURLResponse else { throw Failure.transport(urlErrorCode: nil) }
            return (data, http)
        }
    }

    /// Whether the canonical passphrase appears in the breach corpus at least ``minimumCount`` times.
    ///
    /// - Parameter canonical: The canonical passphrase. Canonicalized again, which changes nothing
    ///   for one that already is, so a direct caller's decomposed "é" hashes like a composed one.
    /// - Returns: Whether it's breached; false on a failure when ``failsOpen`` is set.
    /// - Throws: A ``Failure`` when the range can't be checked.
    public func contains(_ canonical: String) async throws -> Bool {
        guard case .success(let text) = PassphraseCanonicalization.c1.canonicalize(canonical) else {
            throw Failure.notCanonical
        }
        let hash = Self.sha1Hex(text)
        let prefix = String(hash.prefix(5))
        let suffix = String(hash.dropFirst(5))
        do {
            let counts = try await counts(prefix: prefix)
            return counts[suffix].map { $0 >= minimumCount } ?? false
        } catch let failure as Failure {
            guard failsOpen, failure != .invalidTimeout else { throw failure }
            Self.logFailOpen(failure)
            return false
        }
    }

    /// The range for `prefix`, as suffix to count.
    private func counts(prefix: String) async throws -> [String: Int] {
        var request = URLRequest(url: baseURL.appending(path: "range").appending(path: prefix))
        request.httpMethod = "GET"
        if requestsPadding { request.setValue("true", forHTTPHeaderField: "Add-Padding") }
        request.setValue("SwiftIdentity", forHTTPHeaderField: "User-Agent")

        let data: Data
        let response: HTTPURLResponse
        do {
            (data, response) = try await fetch(request)
        } catch let failure as Failure {
            throw failure
        } catch {
            throw Failure.transport(urlErrorCode: (error as? URLError)?.code.rawValue)
        }
        guard response.statusCode == 200 else { throw Failure.status(response.statusCode) }
        guard data.count <= Self.maximumResponseBytes else {
            throw Failure.oversize(maximumBytes: Self.maximumResponseBytes)
        }
        return try Self.parse(data)
    }

    /// Strictly parses a range body: `SUFFIX:COUNT` lines ending in LF or CRLF, the last line's
    /// ending optional. Suffixes are uppercased for matching.
    ///
    /// Read as bytes, not text: the protocol is ASCII, and anything outside it is malformed
    /// rather than decoded. Splitting on the LF byte also means CRLF is never one Character.
    static func parse(_ data: Data) throws -> [String: Int] {
        guard !data.isEmpty else { throw Failure.malformed(line: 1) }
        var lines = data.split(separator: lineFeed, omittingEmptySubsequences: false)
        if lines.last?.isEmpty == true { lines.removeLast() }

        var counts: [String: Int] = [:]
        for (index, raw) in lines.enumerated() {
            let line = raw.last == carriageReturn ? raw.dropLast() : raw
            guard let (suffix, count) = parseLine(line) else { throw Failure.malformed(line: index + 1) }
            counts[suffix] = max(counts[suffix] ?? 0, count)
        }
        return counts
    }

    private static let lineFeed = UInt8(ascii: "\n")
    private static let carriageReturn = UInt8(ascii: "\r")
    private static let colon = UInt8(ascii: ":")

    /// One `SUFFIX:COUNT` line: 35 hex digits, a colon, one or more decimal digits.
    private static func parseLine(_ line: Data) -> (String, Int)? {
        let parts = line.split(separator: colon, omittingEmptySubsequences: false)
        guard parts.count == 2 else { return nil }
        let suffix = parts[0], digits = parts[1]
        guard suffix.count == 35, suffix.allSatisfy(isHexDigit),
              !digits.isEmpty, digits.allSatisfy(isDecimalDigit)
        else { return nil }
        // Both are ASCII by now, so decoding can't fail; `Int` is nil only on overflow.
        guard let count = Int(String(decoding: digits, as: UTF8.self)) else { return nil }
        return (String(decoding: suffix, as: UTF8.self).uppercased(), count)
    }

    private static func isDecimalDigit(_ byte: UInt8) -> Bool {
        (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte)
    }

    private static func isHexDigit(_ byte: UInt8) -> Bool {
        isDecimalDigit(byte)
            || (UInt8(ascii: "A")...UInt8(ascii: "F")).contains(byte)
            || (UInt8(ascii: "a")...UInt8(ascii: "f")).contains(byte)
    }

    /// SHA-1 of the UTF-8 bytes, as 40 uppercase hex characters.
    static func sha1Hex(_ text: String) -> String {
        let table = Array("0123456789ABCDEF".unicodeScalars)
        var hex = String.UnicodeScalarView()
        // SECURITY: SHA-1 is dictated by the Pwned Passwords range protocol, an index into a public corpus, never a stored digest.
        for byte in Insecure.SHA1.hash(data: Data(text.utf8)) {
            hex.append(table[Int(byte >> 4)])
            hex.append(table[Int(byte & 0x0F)])
        }
        return String(hex)
    }

    /// Records a lookup that failed open. The failure only: never the passphrase or its hash.
    private static func logFailOpen(_ failure: Failure) {
        #if canImport(os)
        Logger(subsystem: "org.roseclub.swiftidentity", category: "passphrase-policy")
            .error("breached-password range unavailable, failing open: \(String(describing: failure), privacy: .public)")
        #endif
    }
}
