#if canImport(os)
import os
#endif
import Foundation

// MARK: - Wire format

/// One ledger operation, as it crosses the wire. JSON, with dates as seconds since 1970.
enum LedgerOperation: Codable, Sendable {
    case beginAttempt(key: ThrottleKey, at: Date)
    case recordFailure(key: ThrottleKey, at: Date)
    case recordFailureInvolving(keys: [ThrottleKey], at: Date)
    case recordSuccess(key: ThrottleKey)
    case state(key: ThrottleKey)
    case rebound(key: ThrottleKey)
    case consume(step: Int64, key: ThrottleKey)
    case disableTogether(keys: [ThrottleKey])

    /// Every key the operation names, for bounds checks.
    var keys: [ThrottleKey] {
        switch self {
        case .beginAttempt(let key, _), .recordFailure(let key, _), .recordSuccess(let key),
             .state(let key), .rebound(let key), .consume(_, let key):
            [key]
        case .recordFailureInvolving(let keys, _), .disableTogether(let keys):
            keys
        }
    }

    /// The time the operation carries, for the skew check.
    var time: Date? {
        switch self {
        case .beginAttempt(_, let at), .recordFailure(_, let at), .recordFailureInvolving(_, let at): at
        default: nil
        }
    }
}

/// A ledger operation's answer. Exactly one field is set, the one the operation returns.
struct LedgerReply: Codable, Sendable {
    var admitted: Bool?
    var state: ThrottleState?
    var states: [ThrottleState]?
    var consumed: Bool?
    var disabled: Bool?
}

enum LedgerCoding {
    static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        encoder.outputFormatting = .sortedKeys
        return encoder
    }

    static func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        return decoder
    }
}

// MARK: - The service

/// An HTTP request to ``ThrottleLedgerService``, as the consumer's server received it.
public struct LedgerRequest: Sendable {
    /// The `Authorization` header: `Bearer <key>`.
    public let authorization: String?
    /// The body, unparsed.
    public let body: Data

    /// A request.
    public init(authorization: String?, body: Data) {
        self.authorization = authorization
        self.body = body
    }
}

/// What ``ThrottleLedgerService`` answers: a status and a JSON body.
public struct LedgerResponse: Sendable, Equatable {
    /// 200 with an answer; 400 malformed or out of bounds; 401 unauthenticated; 413 too large;
    /// 429 rate-limited; 500 the ledger failed.
    public let status: Int
    /// JSON, or empty on a refusal.
    public let body: Data
}

/// Serves a ledger to the instances on other hosts, so the ceiling is shared across them.
///
/// ## Mounted by the consumer
///
/// This package opens no socket. The consumer's server routes a POST to ``handle(_:)`` and
/// writes back the status and body, as it does SwiftWebAuthnIdentity's handlers. **TLS is the
/// server's job and is required**: subject IDs cross the wire.
///
/// ## Who may ask
///
/// Each request carries a ``BearerKey`` that `clients` must resolve, on every request, never
/// cached: revoking a host is an ordinary revocation, effective on its next request, and audited
/// like any other.
///
/// ## Bounds
///
/// A body over ``maximumBodyBytes`` is refused before it's parsed. Subject IDs and authenticator
/// names are capped, as is the number of keys in one request. Each client is rate-limited on its
/// own. A time more than `maximumClockSkew` from this host's clock is refused, so a host with a
/// wrong clock, or a hostile one, can't step past a backoff: keep the hosts' clocks synchronized.
///
/// ## A single point of failure, deliberately
///
/// If this host is unreachable, passphrase and one-time-code attempts on every other host are
/// refused: ``RemoteThrottleLedger`` throws, and ``FailureThrottle`` fails closed. Other kinds
/// aren't throttled, so they keep working. A ledger that failed open would be the first thing an
/// attacker knocked over. Run it on the host that already holds the identity store.
public struct ThrottleLedgerService: Sendable {

    /// A client's allowance: a token bucket, refilled continuously.
    public struct RateLimit: Sendable {
        /// Sustained requests per second, per client.
        public let requestsPerSecond: Double
        /// How many may arrive at once.
        public let burst: Int

        /// A rate limit.
        public init(requestsPerSecond: Double, burst: Int) {
            self.requestsPerSecond = requestsPerSecond
            self.burst = burst
        }

        /// 50 a second, bursts of 100: far more than sign-ins need, far less than a flood.
        public static let standard = RateLimit(requestsPerSecond: 50, burst: 100)
    }

    /// Five minutes.
    public static let defaultMaximumClockSkew: Duration = .seconds(300)
    /// The largest body read: 64 KiB.
    public static let maximumBodyBytes = 65_536
    /// The longest subject ID, in UTF-8 bytes.
    public static let maximumSubjectIDBytes = 256
    /// The longest authenticator name, in UTF-8 bytes.
    public static let maximumAuthenticatorBytes = 128
    /// The most keys one request may name.
    public static let maximumKeys = 16

    private let ledger: any ThrottleLedger
    private let clients: any CredentialStore
    private let maximumClockSkew: Duration?
    private let buckets: TokenBuckets
    private let now: @Sendable () -> Date

    /// A service over `ledger`.
    ///
    /// - Parameters:
    ///   - ledger: The ledger the hosts share, typically a ``FileThrottleLedger``.
    ///   - clients: Resolves the hosts' bearer keys.
    ///   - maximumClockSkew: How far a request's time may be from this host's clock. Nil trusts
    ///     the hosts' clocks entirely, which only a test should want.
    ///   - rateLimit: Each client's allowance.
    ///   - now: The clock.
    public init(
        ledger: any ThrottleLedger,
        clients: any CredentialStore,
        maximumClockSkew: Duration? = ThrottleLedgerService.defaultMaximumClockSkew,
        rateLimit: RateLimit = .standard,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.ledger = ledger
        self.clients = clients
        self.maximumClockSkew = maximumClockSkew
        self.buckets = TokenBuckets(limit: rateLimit)
        self.now = now
    }

    /// Answers one request.
    ///
    /// - Parameter request: The request as received.
    /// - Returns: The response to send.
    public func handle(_ request: LedgerRequest) async -> LedgerResponse {
        guard request.body.count <= Self.maximumBodyBytes else { return Self.refusal(413) }
        guard let client = await authenticate(request.authorization) else { return Self.refusal(401) }
        guard await buckets.take(for: client.id, at: now()) else { return Self.refusal(429) }
        let operation: LedgerOperation
        do {
            operation = try LedgerCoding.decoder().decode(LedgerOperation.self, from: request.body)
        } catch {
            #if canImport(os)
            Self.logger.notice("malformed ledger request from \(client.id, privacy: .public): \(String(describing: error), privacy: .public)")
            #endif
            return Self.refusal(400)
        }
        guard isWithinBounds(operation) else { return Self.refusal(400) }
        do {
            let reply = try await perform(operation)
            return LedgerResponse(status: 200, body: try LedgerCoding.encoder().encode(reply))
        } catch {
            #if canImport(os)
            Self.logger.error("ledger operation failed for \(client.id, privacy: .public): \(String(describing: error), privacy: .public)")
            #endif
            return Self.refusal(500)
        }
    }

    #if canImport(os)
    private static let logger = Logger(subsystem: "org.roseclub.swiftidentity", category: "ledger-service")
    #endif

    private static func refusal(_ status: Int) -> LedgerResponse { LedgerResponse(status: status, body: Data()) }

    /// The client a `Bearer` header proves, asked of `clients` every time.
    private func authenticate(_ header: String?) async -> Subject? {
        guard let header, header.hasPrefix("Bearer ") else { return nil }
        let value = String(header.dropFirst("Bearer ".count))
        guard !value.isEmpty else { return nil }
        return await clients.subject(for: BearerKey(value))
    }

    private func isWithinBounds(_ operation: LedgerOperation) -> Bool {
        let keys = operation.keys
        guard !keys.isEmpty, keys.count <= Self.maximumKeys else { return false }
        guard keys.allSatisfy({
            $0.subjectID.utf8.count <= Self.maximumSubjectIDBytes
                && $0.authenticator.utf8.count <= Self.maximumAuthenticatorBytes
        }) else { return false }
        if let maximumClockSkew, let time = operation.time {
            let skew = abs(time.timeIntervalSince(now()))
            let allowed = Double(maximumClockSkew.components.seconds)
            guard skew <= allowed else { return false }
        }
        return true
    }

    private func perform(_ operation: LedgerOperation) async throws -> LedgerReply {
        var reply = LedgerReply()
        switch operation {
        case .beginAttempt(let key, let at): reply.admitted = try await ledger.beginAttempt(key, at: at)
        case .recordFailure(let key, let at): reply.state = try await ledger.recordFailure(key, at: at)
        case .recordFailureInvolving(let keys, let at): reply.states = try await ledger.recordFailure(involving: keys, at: at)
        case .recordSuccess(let key): try await ledger.recordSuccess(key); reply.disabled = false
        case .state(let key): reply.state = try await ledger.state(key)
        case .rebound(let key): try await ledger.rebound(key); reply.disabled = false
        case .consume(let step, let key): reply.consumed = try await ledger.consume(step: step, for: key)
        case .disableTogether(let keys): reply.disabled = try await ledger.disableTogether(keys)
        }
        return reply
    }
}

/// Per-client token buckets.
actor TokenBuckets {
    private struct Bucket {
        var tokens: Double
        var at: Date
    }

    private let limit: ThrottleLedgerService.RateLimit
    private var buckets: [String: Bucket] = [:]

    init(limit: ThrottleLedgerService.RateLimit) { self.limit = limit }

    /// Takes a token for `client`, if one is left.
    func take(for client: String, at time: Date) -> Bool {
        let capacity = Double(max(limit.burst, 1))
        var bucket = buckets[client] ?? Bucket(tokens: capacity, at: time)
        let elapsed = max(0, time.timeIntervalSince(bucket.at))
        bucket.tokens = min(capacity, bucket.tokens + elapsed * max(limit.requestsPerSecond, 0))
        bucket.at = time
        guard bucket.tokens >= 1 else {
            buckets[client] = bucket
            return false
        }
        bucket.tokens -= 1
        buckets[client] = bucket
        return true
    }
}

// MARK: - The client

/// A ``ThrottleLedger`` on another host: every call is one HTTPS request to a
/// ``ThrottleLedgerService``.
///
/// Any failure throws: a timeout, a refusal, a reply it can't read. ``FailureThrottle`` then
/// refuses the attempt, so an unreachable ledger host fails closed. It never reports a clear
/// state it didn't receive.
public struct RemoteThrottleLedger: ThrottleLedger {

    /// Sends one request and returns the body and the response.
    public typealias Transport = @Sendable (URLRequest) async throws -> (Data, HTTPURLResponse)

    /// Why a call failed.
    public enum Failure: Error, Equatable {
        /// The service answered with this status.
        case status(Int)
        /// The service's reply wasn't the answer this call expects.
        case malformedReply
        /// A timeout that isn't positive.
        case invalidTimeout
    }

    private let url: URL
    private let key: BearerKey
    private let transport: Transport

    /// A remote ledger over a transport you supply.
    ///
    /// - Parameters:
    ///   - url: The service's endpoint, `https://`.
    ///   - key: This host's key, which the service's `clients` store resolves.
    ///   - transport: Sends a request.
    public init(url: URL, key: BearerKey, transport: @escaping Transport) {
        self.url = url
        self.key = key
        self.transport = transport
    }

    /// A remote ledger over `URLSession`, with a timeout you must choose.
    ///
    /// Required, not defaulted: every sign-in on this host waits on it, and the right number
    /// depends on the network between the hosts.
    ///
    /// - Parameters:
    ///   - url: The service's endpoint.
    ///   - key: This host's key.
    ///   - timeout: How long one call may take. Must be positive.
    ///   - session: The session. Defaults to the shared one.
    /// - Throws: ``Failure/invalidTimeout``.
    public static func urlSession(
        url: URL, key: BearerKey, timeout: Duration, session: URLSession = .shared
    ) throws -> RemoteThrottleLedger {
        let parts = timeout.components
        let seconds = Double(parts.seconds) + Double(parts.attoseconds) / 1e18
        guard seconds > 0 else { throw Failure.invalidTimeout }
        return RemoteThrottleLedger(url: url, key: key) { request in
            var timed = request
            timed.timeoutInterval = seconds
            let (data, response) = try await session.data(for: timed)
            guard let http = response as? HTTPURLResponse else { throw Failure.malformedReply }
            return (data, http)
        }
    }

    /// See ``ThrottleLedger/beginAttempt(_:at:)``.
    public func beginAttempt(_ key: ThrottleKey, at time: Date) async throws -> Bool {
        try await call(.beginAttempt(key: key, at: time), \.admitted)
    }

    /// See ``ThrottleLedger/recordFailure(_:at:)``.
    public func recordFailure(_ key: ThrottleKey, at time: Date) async throws -> ThrottleState {
        try await call(.recordFailure(key: key, at: time), \.state)
    }

    /// See ``ThrottleLedger/recordFailure(involving:at:)``.
    public func recordFailure(involving keys: [ThrottleKey], at time: Date) async throws -> [ThrottleState] {
        try await call(.recordFailureInvolving(keys: keys, at: time), \.states)
    }

    /// See ``ThrottleLedger/recordSuccess(_:)``.
    public func recordSuccess(_ key: ThrottleKey) async throws {
        _ = try await call(.recordSuccess(key: key), \.disabled)
    }

    /// See ``ThrottleLedger/state(_:)``.
    public func state(_ key: ThrottleKey) async throws -> ThrottleState {
        try await call(.state(key: key), \.state)
    }

    /// See ``ThrottleLedger/rebound(_:)``.
    public func rebound(_ key: ThrottleKey) async throws {
        _ = try await call(.rebound(key: key), \.disabled)
    }

    /// See ``ThrottleLedger/consume(step:for:)``.
    public func consume(step: Int64, for key: ThrottleKey) async throws -> Bool {
        try await call(.consume(step: step, key: key), \.consumed)
    }

    /// See ``ThrottleLedger/disableTogether(_:)``.
    public func disableTogether(_ keys: [ThrottleKey]) async throws -> Bool {
        try await call(.disableTogether(keys: keys), \.disabled)
    }

    /// One request, one answer.
    private func call<Value>(_ operation: LedgerOperation, _ field: KeyPath<LedgerReply, Value?>) async throws -> Value {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("Bearer \(key.value)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try LedgerCoding.encoder().encode(operation)

        let (data, response) = try await transport(request)
        guard response.statusCode == 200 else { throw Failure.status(response.statusCode) }
        let reply = try LedgerCoding.decoder().decode(LedgerReply.self, from: data)
        guard let value = reply[keyPath: field] else { throw Failure.malformedReply }
        return value
    }
}
