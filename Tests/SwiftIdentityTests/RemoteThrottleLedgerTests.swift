import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Testing
@testable import SwiftIdentity
import SwiftIdentityConformance

/// One host keeps the ledger; the others ask it over HTTPS. Here the "network" is a closure that
/// hands the request to the service in-process, so everything but the socket is real.
@Suite("RemoteThrottleLedger and ThrottleLedgerService")
struct RemoteThrottleLedgerTests {

    static let policy: ThrottlePolicy = (try? ThrottlePolicy(threshold: 3, backoff: 60, ceiling: 10)) ?? .standard
    static let host = Subject(id: "host-b", kind: .service)
    static let revokedHost = Subject(id: "host-c", kind: .service, status: .revoked)
    static let url = URL(string: "https://ledger.example/throttle") ?? URL(fileURLWithPath: "/")

    /// A synthetic clock the service reads.
    // Justification: every access to `current` is serialised by `lock`, so the mutable state is never reached concurrently.
    final class Clock: @unchecked Sendable {
        private let lock = NSLock()
        private var current = Date(timeIntervalSince1970: 1_800_000_000)
        var instant: Date {
            lock.lock(); defer { lock.unlock() }
            return current
        }
        func advance(_ interval: TimeInterval) {
            lock.lock(); defer { lock.unlock() }
            current += interval
        }
    }

    /// The clients store: BearerKey("host-b-key") is host-b; "host-c-key" is revoked.
    actor Clients: CredentialStore {
        var revoked: Set<String> = ["host-c-key"]
        var lookups = 0
        func revoke(_ key: String) { revoked.insert(key) }
        func resolve(_ credential: any Credential) async -> Resolution {
            lookups += 1
            guard let key = credential as? BearerKey else { return .refused(.unknown) }
            if revoked.contains(key.value) { return .refused(.revoked) }
            return key.value == "host-b-key" ? .verified(RemoteThrottleLedgerTests.host) : .refused(.unknown)
        }
    }

    static func service(
        _ ledger: any ThrottleLedger, clients: Clients, clock: Clock? = nil,
        maximumClockSkew: Duration? = nil, requestsPerSecond: Double = 10_000
    ) -> ThrottleLedgerService {
        let clock = clock ?? Clock()
        return ThrottleLedgerService(
            ledger: ledger, clients: clients, maximumClockSkew: maximumClockSkew,
            rateLimit: .init(requestsPerSecond: requestsPerSecond, burst: Int(min(requestsPerSecond, 100_000))),
            now: { clock.instant }
        )
    }

    /// A remote ledger whose transport is the service itself.
    static func remote(_ service: ThrottleLedgerService, key: String = "host-b-key") -> RemoteThrottleLedger {
        RemoteThrottleLedger(url: url, key: BearerKey(key)) { request in
            let response = await service.handle(LedgerRequest(
                authorization: request.value(forHTTPHeaderField: "Authorization"), body: request.httpBody ?? Data()
            ))
            let http = HTTPURLResponse(url: url, statusCode: response.status, httpVersion: "HTTP/1.1", headerFields: nil)
            guard let http else { throw URLError(.badServerResponse) }
            return (response.body, http)
        }
    }

    // MARK: - The bar

    @Test("the remote ledger passes the ledger suite, racing handles included")
    func remoteLedgerPassesLedgerSuite() async throws {
        let ledger = InMemoryThrottleLedger(policy: Self.policy)
        let service = Self.service(ledger, clients: Clients())
        let report = await ThrottleLedgerConformance(policy: Self.policy, capabilities: []) {
            Self.remote(service)
        }.run()
        print("\n--- remote ledger ---\n" + report.summary + "\n")
        #expect(report.isConformant, "\(report.summary)")
    }

    @Test("over a file ledger it survives a restart too")
    func remoteOverFileLedgerIsPersistent() async throws {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("RemoteLedger-\(UUID().uuidString)", isDirectory: true).standardized
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let path = directory.appendingPathComponent("throttle.ledger")
        let policy = Self.policy
        let clients = Clients()
        let report = await ThrottleLedgerConformance(policy: policy, capabilities: [.persistent]) {
            Self.remote(Self.service(try FileThrottleLedger(url: path, policy: policy), clients: clients))
        }.run()
        #expect(report.isConformant, "\(report.summary)")
    }

    // MARK: - Failing closed

    @Test("an unreachable ledger host refuses, never reports a clear state")
    func unreachableLedgerRefuses() async {
        let remote = RemoteThrottleLedger(url: Self.url, key: BearerKey("host-b-key")) { _ in
            throw URLError(.timedOut)
        }
        let key = ThrottleKey(subjectID: "ada", authenticator: "passphrase:x")
        await #expect(throws: (any Error).self) { try await remote.state(key) }
        let throttle = FailureThrottle(ledger: remote)
        #expect(await !throttle.beginAttempt(key))
    }

    @Test("a revoked client is refused, on the next request, not after a cache expires")
    func revokedLedgerClientIsRefused() async throws {
        let clients = Clients()
        let service = Self.service(InMemoryThrottleLedger(policy: Self.policy), clients: clients)
        let remote = Self.remote(service)
        let key = ThrottleKey(subjectID: "ada", authenticator: "passphrase:x")
        #expect(try await remote.state(key) == .clear)
        await clients.revoke("host-b-key")
        await #expect(throws: RemoteThrottleLedger.Failure.status(401)) { try await remote.state(key) }
        // Every request asked the store: nothing cached.
        #expect(await clients.lookups == 2)
    }

    @Test("an unknown or revoked client key is refused with 401, and the ledger isn't touched")
    func unauthenticatedIsRefused() async throws {
        let ledger = InMemoryThrottleLedger(policy: Self.policy)
        let service = Self.service(ledger, clients: Clients())
        let key = ThrottleKey(subjectID: "ada", authenticator: "passphrase:x")
        for bad in ["host-c-key", "nobody"] {
            await #expect(throws: RemoteThrottleLedger.Failure.status(401)) {
                _ = try await Self.remote(service, key: bad).beginAttempt(key, at: Date(timeIntervalSince1970: 1_800_000_000))
            }
        }
        #expect(await ledger.state(key) == .clear)
        let missing = await service.handle(LedgerRequest(authorization: nil, body: Data()))
        #expect(missing.status == 401)
    }

    // MARK: - Bounds

    @Test("a time outside the allowed clock skew is refused")
    func clockSkew() async throws {
        let clock = Clock()
        let service = Self.service(InMemoryThrottleLedger(policy: Self.policy), clients: Clients(),
                                   clock: clock, maximumClockSkew: .seconds(300))
        let remote = Self.remote(service)
        let key = ThrottleKey(subjectID: "ada", authenticator: "passphrase:x")
        #expect(try await remote.beginAttempt(key, at: clock.instant.addingTimeInterval(299)))
        await #expect(throws: RemoteThrottleLedger.Failure.status(400)) {
            _ = try await remote.beginAttempt(key, at: clock.instant.addingTimeInterval(3_600))
        }
        await #expect(throws: RemoteThrottleLedger.Failure.status(400)) {
            _ = try await remote.beginAttempt(key, at: clock.instant.addingTimeInterval(-3_600))
        }
    }

    @Test("the default service allows five minutes of skew")
    func defaultSkew() {
        #expect(ThrottleLedgerService.defaultMaximumClockSkew == .seconds(300))
    }

    @Test("each client is rate-limited on its own")
    func rateLimited() async throws {
        let clock = Clock()
        let service = Self.service(InMemoryThrottleLedger(policy: Self.policy), clients: Clients(),
                                   clock: clock, requestsPerSecond: 2)
        let remote = Self.remote(service)
        let key = ThrottleKey(subjectID: "ada", authenticator: "passphrase:x")
        _ = try await remote.state(key)
        _ = try await remote.state(key)
        await #expect(throws: RemoteThrottleLedger.Failure.status(429)) { try await remote.state(key) }
        clock.advance(1)
        #expect(try await remote.state(key) == .clear)
    }

    @Test("oversized requests are refused before parsing: a long subject ID, too many keys, a big body")
    func bounded() async throws {
        let service = Self.service(InMemoryThrottleLedger(policy: Self.policy), clients: Clients())
        let remote = Self.remote(service)
        let long = ThrottleKey(subjectID: String(repeating: "a", count: 257), authenticator: "passphrase:x")
        await #expect(throws: RemoteThrottleLedger.Failure.status(400)) { try await remote.state(long) }
        let many = (0..<17).map { ThrottleKey(subjectID: "s\($0)", authenticator: "passphrase:x") }
        await #expect(throws: RemoteThrottleLedger.Failure.status(400)) { _ = try await remote.disableTogether(many) }
        let big = await service.handle(LedgerRequest(authorization: "Bearer host-b-key", body: Data(count: 70_000)))
        #expect(big.status == 413)
        let garbage = await service.handle(LedgerRequest(authorization: "Bearer host-b-key", body: Data("{".utf8)))
        #expect(garbage.status == 400)
    }

    @Test("a request carries the bearer key in the header and nothing secret in the URL")
    func requestShape() async throws {
        let seen = Seen()
        let remote = RemoteThrottleLedger(url: Self.url, key: BearerKey("host-b-key")) { request in
            await seen.set(request)
            let http = HTTPURLResponse(url: Self.url, statusCode: 200, httpVersion: nil, headerFields: nil)
            guard let http else { throw URLError(.badServerResponse) }
            return (Data(#"{"state":{"consecutiveFailures":0,"isDisabled":false}}"#.utf8), http)
        }
        _ = try await remote.state(ThrottleKey(subjectID: "ada", authenticator: "passphrase:x"))
        let request = try #require(await seen.request)
        #expect(request.httpMethod == "POST")
        #expect(request.url == Self.url)
        #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer host-b-key")
        #expect(request.value(forHTTPHeaderField: "Content-Type") == "application/json")
    }

    actor Seen {
        var request: URLRequest?
        func set(_ request: URLRequest) { self.request = request }
    }

    @Test("the URLSession transport requires a positive timeout")
    func timeoutRequired() {
        #expect(throws: RemoteThrottleLedger.Failure.invalidTimeout) {
            try RemoteThrottleLedger.urlSession(url: Self.url, key: BearerKey("k"), timeout: .zero)
        }
    }
}
