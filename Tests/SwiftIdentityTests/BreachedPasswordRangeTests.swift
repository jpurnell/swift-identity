import Crypto
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Testing
@testable import SwiftIdentity

/// The breach-corpus blocklist, over Have I Been Pwned's range API, with the network stubbed.
///
/// Nothing here touches the real service: every response comes from a stub, and every request
/// is recorded so the test can say exactly what would have crossed the wire.
@Suite("BreachedPasswordRange")
struct BreachedPasswordRangeTests {

    static let context = PolicyContext(subjectID: "ada", serviceName: "vault")
    static let breached = "correct horse battery staple, breached"

    /// SHA-1 of the UTF-8 bytes, uppercase hex, computed here rather than by the type under test.
    static func sha1Hex(_ text: String) -> String {
        // SECURITY: SHA-1 is dictated by the Pwned Passwords range protocol under test, never used as a digest.
        Insecure.SHA1.hash(data: Data(text.utf8)).map { byte in
            let hex = String(byte, radix: 16, uppercase: true)
            return hex.count == 1 ? "0" + hex : hex
        }.joined()
    }

    static func prefix(_ text: String) -> String { String(sha1Hex(text).prefix(5)) }
    static func suffix(_ text: String) -> String { String(sha1Hex(text).dropFirst(5)) }

    /// Every request a stub was handed.
    actor Recorder {
        private(set) var requests: [URLRequest] = []
        func record(_ request: URLRequest) { requests.append(request) }
    }

    enum StubFailure: Error { case offline }

    static func response(_ request: URLRequest, status: Int) -> HTTPURLResponse {
        let url = request.url ?? URL(fileURLWithPath: "/")
        // Failable only for an unusable status; the tests pass real ones. `HTTPURLResponse()`
        // is no fallback: Foundation on Linux has no such initializer.
        guard let response = HTTPURLResponse(
            url: url, statusCode: status, httpVersion: "HTTP/1.1", headerFields: nil) else {
            preconditionFailure("A test asked for an HTTP response with status \(status)")
        }
        return response
    }

    /// A blocklist whose fetch answers with `body` and `status`, recording each request.
    static func range(
        body: String, status: Int = 200, minimumCount: Int = 1, failsOpen: Bool = false,
        recorder: Recorder = Recorder()
    ) -> BreachedPasswordRange {
        BreachedPasswordRange(minimumCount: minimumCount, failsOpen: failsOpen) { request in
            await recorder.record(request)
            return (Data(body.utf8), Self.response(request, status: status))
        }
    }

    /// Filler lines that never match anything this suite looks up.
    static let filler = [
        "0018A45C4D1DEF81644B54AB7F969B88D65:1",
        "00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2",
        "011053FD0102E94D6AE2F8B83D76FAF94F6:13",
    ]

    static func body(_ lines: [String], separator: String = "\r\n") -> String {
        lines.joined(separator: separator)
    }

    static func policy(_ blocklist: BreachedPasswordRange) -> PassphrasePolicy {
        var policy = PassphrasePolicy.nist80063B4
        policy.blocklists = [blocklist]
        return policy
    }

    // MARK: - Matching

    @Test("P8, P19: a breached passphrase is refused, as breached")
    func breachedIsRefused() async throws {
        let range = Self.range(body: Self.body(Self.filler + ["\(Self.suffix(Self.breached)):52"]))
        #expect(range.reason == .breached)
        #expect(try await range.contains(Self.breached))
        #expect(await Self.policy(range).evaluate(Self.breached, context: Self.context)
            == [.blocklisted(.breached)])
    }

    @Test("a passphrase whose suffix isn't listed isn't breached")
    func unlistedIsNotBreached() async throws {
        let range = Self.range(body: Self.body(Self.filler))
        #expect(try await !range.contains(Self.breached))
        #expect(await Self.policy(range).evaluate(Self.breached, context: Self.context) == [])
    }

    @Test("suffixes match without regard to case, and LF or CRLF line endings both parse")
    func caseAndLineEndings() async throws {
        let line = "\(Self.suffix(Self.breached).lowercased()):3"
        #expect(try await Self.range(body: Self.body(Self.filler + [line], separator: "\n"))
            .contains(Self.breached))
        #expect(try await Self.range(body: Self.body([line] + Self.filler) + "\r\n")
            .contains(Self.breached))
    }

    @Test("a padded entry, count 0, isn't breached")
    func paddingIsNotBreached() async throws {
        let range = Self.range(body: Self.body(Self.filler + ["\(Self.suffix(Self.breached)):0"]))
        #expect(try await !range.contains(Self.breached))
        // Even when a deployment asks for a minimum below 1, padding never counts.
        let lax = Self.range(body: Self.body(["\(Self.suffix(Self.breached)):0"]), minimumCount: 0)
        #expect(try await !lax.contains(Self.breached))
    }

    @Test("minimumCount is respected")
    func minimumCount() async throws {
        let body = Self.body(Self.filler + ["\(Self.suffix(Self.breached)):4"])
        #expect(try await Self.range(body: body, minimumCount: 4).contains(Self.breached))
        #expect(try await !Self.range(body: body, minimumCount: 5).contains(Self.breached))
    }

    @Test("the canonical form is hashed: decomposed and composed é send the same prefix")
    func canonicalFormIsHashed() async throws {
        let composed = "caf\u{E9} au lait, s'il vous pla\u{EE}t"
        let decomposed = "cafe\u{301} au lait, s'il vous plai\u{302}t"
        #expect(composed.unicodeScalars.count != decomposed.unicodeScalars.count)

        let recorder = Recorder()
        let range = Self.range(body: Self.body(["\(Self.suffix(composed)):1"]), recorder: recorder)
        #expect(try await range.contains(composed))
        #expect(try await range.contains(decomposed))
        let paths = await recorder.requests.compactMap { $0.url?.lastPathComponent }
        #expect(paths == [Self.prefix(composed), Self.prefix(composed)])
    }

    // MARK: - What crosses the wire

    @Test("the request carries only the 5-character prefix, never the passphrase or its hash")
    func onlyThePrefixIsSent() async throws {
        let recorder = Recorder()
        let range = Self.range(body: Self.body(Self.filler), recorder: recorder)
        _ = try await range.contains(Self.breached)

        let requests = await recorder.requests
        #expect(requests.count == 1)
        let request = try #require(requests.first)
        let url = try #require(request.url)
        #expect(request.httpMethod == "GET")
        #expect(url.host == "api.pwnedpasswords.com")
        #expect(url.scheme == "https")
        #expect(url.path.hasSuffix("/range/\(Self.prefix(Self.breached))"))
        #expect(request.value(forHTTPHeaderField: "Add-Padding") == "true")
        #expect(request.httpBody == nil)

        // Everything the request says, in one string.
        let headers = (request.allHTTPHeaderFields ?? [:]).map { "\($0.key): \($0.value)" }
        let wire = ([url.absoluteString] + headers).joined(separator: "\n").uppercased()
        #expect(!wire.contains(Self.breached.uppercased()))
        #expect(!wire.contains(Self.sha1Hex(Self.breached)))
        #expect(!wire.contains(Self.suffix(Self.breached)))
        #expect(!wire.contains(String(Self.suffix(Self.breached).prefix(8))))
    }

    @Test("a base URL can name another HIBP-compatible service")
    func baseURLIsUsed() async throws {
        let recorder = Recorder()
        let mirror = try #require(URL(string: "https://mirror.example/pwned"))
        let range = BreachedPasswordRange(baseURL: mirror) { request in
            await recorder.record(request)
            return (Data(Self.body(Self.filler).utf8), Self.response(request, status: 200))
        }
        _ = try await range.contains(Self.breached)
        let url = try #require(await recorder.requests.first?.url)
        #expect(url.absoluteString == "https://mirror.example/pwned/range/\(Self.prefix(Self.breached))")
    }

    // MARK: - Failure

    /// Each way the service can fail to answer, as a body, a status, or a thrown error.
    static let failures: [(name: String, fetch: BreachedPasswordRange.Fetch)] = [
        ("non-200", { request in (Data(), Self.response(request, status: 503)) }),
        ("transport", { _ in throw StubFailure.offline }),
        ("empty body", { request in (Data(), Self.response(request, status: 200)) }),
        ("short suffix", { request in
            (Data("0018A45C4D1DEF81644B54AB7F969B88D6:1".utf8), Self.response(request, status: 200))
        }),
        ("non-hex suffix", { request in
            (Data("0018A45C4D1DEF81644B54AB7F969B88D6G:1".utf8), Self.response(request, status: 200))
        }),
        ("missing count", { request in
            (Data("0018A45C4D1DEF81644B54AB7F969B88D65".utf8), Self.response(request, status: 200))
        }),
        ("non-numeric count", { request in
            (Data("0018A45C4D1DEF81644B54AB7F969B88D65:x".utf8), Self.response(request, status: 200))
        }),
        ("negative count", { request in
            (Data("0018A45C4D1DEF81644B54AB7F969B88D65:-1".utf8), Self.response(request, status: 200))
        }),
        ("one bad line among good ones", { request in
            let lines = Self.filler + ["garbage"] + Self.filler
            return (Data(lines.joined(separator: "\r\n").utf8), Self.response(request, status: 200))
        }),
        ("a blank line in the middle", { request in
            let lines = Self.filler + [""] + Self.filler
            return (Data(lines.joined(separator: "\r\n").utf8), Self.response(request, status: 200))
        }),
        ("not UTF-8", { request in (Data([0xFF, 0xFE, 0x3A, 0x31]), Self.response(request, status: 200)) }),
        ("oversize", { request in
            let line = Data("0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n".utf8)
            let count = BreachedPasswordRange.maximumResponseBytes / line.count + 1
            return (Data((0..<count).flatMap { _ in line }), Self.response(request, status: 200))
        }),
    ]

    @Test("P8: every failure throws, and the policy refuses the passphrase as unavailable")
    func failuresFailClosed() async {
        for failure in Self.failures {
            let range = BreachedPasswordRange(fetch: failure.fetch)
            await #expect(throws: BreachedPasswordRange.Failure.self, "\(failure.name)") {
                try await range.contains(Self.breached)
            }
            #expect(await Self.policy(range).evaluate(Self.breached, context: Self.context)
                == [.blocklistUnavailable(.breached)], "\(failure.name)")
        }
    }

    @Test("with failsOpen, every failure answers not-breached")
    func failsOpenAnswersFalse() async throws {
        for failure in Self.failures {
            let range = BreachedPasswordRange(failsOpen: true, fetch: failure.fetch)
            #expect(try await !range.contains(Self.breached), "\(failure.name)")
            #expect(await Self.policy(range).evaluate(Self.breached, context: Self.context) == [],
                    "\(failure.name)")
        }
    }

    @Test("each failure is named")
    func failuresAreNamed() async {
        func failure(_ fetch: @escaping BreachedPasswordRange.Fetch) async -> BreachedPasswordRange.Failure? {
            do {
                _ = try await BreachedPasswordRange(fetch: fetch).contains(Self.breached)
                return nil
            } catch let failure as BreachedPasswordRange.Failure {
                return failure
            } catch {
                return nil
            }
        }
        #expect(await failure { (Data(), Self.response($0, status: 429)) } == .status(429))
        #expect(await failure { _ in throw URLError(.timedOut) }
            == .transport(urlErrorCode: URLError.Code.timedOut.rawValue))
        #expect(await failure { _ in throw StubFailure.offline } == .transport(urlErrorCode: nil))
        #expect(await failure { (Data("ok:1\r\nbad".utf8), Self.response($0, status: 200)) }
            == .malformed(line: 1))
        let lines = Self.body(Self.filler + ["bad"])
        #expect(await failure { (Data(lines.utf8), Self.response($0, status: 200)) } == .malformed(line: 4))
    }

    @Test("a response over the cap is refused, and one at the cap is read")
    func oversizeIsRefused() async throws {
        let cap = BreachedPasswordRange.maximumResponseBytes
        #expect(cap == 2 * 1_024 * 1_024)
        let head = "\(Self.suffix(Self.breached)):9\r\n"
        let fillerLine = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n"
        // The last line's count is zero-padded so the body lands on the cap exactly.
        let lastLine = "0018A45C4D1DEF81644B54AB7F969B88D65:1"
        let repeats = (cap - head.utf8.count - lastLine.utf8.count) / fillerLine.utf8.count
        let used = head.utf8.count + repeats * fillerLine.utf8.count
        let padding = String(repeating: "0", count: cap - used - lastLine.utf8.count)
        let text = head + String(repeating: fillerLine, count: repeats)
            + "0018A45C4D1DEF81644B54AB7F969B88D65:" + padding + "1"
        let atCap = Data(text.utf8)
        #expect(atCap.count == cap)
        let accepted = BreachedPasswordRange { (atCap, Self.response($0, status: 200)) }
        #expect(try await accepted.contains(Self.breached))

        let over = atCap + Data("\r\n".utf8)
        let refused = BreachedPasswordRange { (over, Self.response($0, status: 200)) }
        await #expect(throws: BreachedPasswordRange.Failure.oversize(maximumBytes: cap)) {
            try await refused.contains(Self.breached)
        }
    }

    // MARK: - Off by default

    @Test("off by default: neither profile includes it")
    func offByDefault() {
        #expect(!PassphrasePolicy.nist80063B4.blocklists.contains { $0.reason == .breached })
        #expect(!PassphrasePolicy.fips.blocklists.contains { $0.reason == .breached })
    }

    @Test("the URLSession convenience refuses a timeout that isn't positive, without a request")
    func urlSessionTimeoutMustBePositive() async {
        let range = BreachedPasswordRange.urlSession(timeout: .zero)
        await #expect(throws: BreachedPasswordRange.Failure.invalidTimeout) {
            try await range.contains(Self.breached)
        }
        let open = BreachedPasswordRange.urlSession(timeout: .seconds(-1), failsOpen: true)
        // A misconfiguration isn't an outage: it refuses even when failing open.
        await #expect(throws: BreachedPasswordRange.Failure.invalidTimeout) {
            try await open.contains(Self.breached)
        }
    }
}
