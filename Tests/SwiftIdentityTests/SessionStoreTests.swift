import Foundation
import SwiftDeterminism
import Testing
@testable import SwiftIdentity

/// Sessions: minted at login, revocable, and never a durable identifier.
///
/// The property that shapes the design is not minting or expiry — it is that **a session must
/// not outlive its subject's standing**. A store that answered from a snapshot taken at login
/// would let a revoked person keep working until their session lapsed, which makes revocation a
/// suggestion.
@Suite("SessionStore")
struct SessionStoreTests {

    /// A clock the test moves, so nothing waits for a real lifetime to run out.
    // Justification: every access to `instant` is serialised by `lock`, so the mutable state is never reached concurrently.
    final class Clock: @unchecked Sendable {
        private let lock = NSLock()
        private var instant = Date(timeIntervalSince1970: 1_800_000_000)

        var now: Date {
            lock.lock(); defer { lock.unlock() }
            return instant
        }

        func advance(_ interval: TimeInterval) {
            lock.lock(); defer { lock.unlock() }
            instant += interval
        }
    }

    /// A roster the test can revoke into, standing in for whatever holds subjects.
    // Justification: every access to `people` is serialised by `lock`, so the mutable state is never reached concurrently.
    final class Roster: @unchecked Sendable {
        private let lock = NSLock()
        private var people: [String: Subject]

        init(_ people: [Subject]) {
            self.people = Dictionary(uniqueKeysWithValues: people.map { ($0.id, $0) })
        }

        func subject(_ id: String) -> Subject? {
            lock.lock(); defer { lock.unlock() }
            return people[id]
        }

        func setStatus(_ status: Subject.Status, for id: String) {
            lock.lock(); defer { lock.unlock() }
            guard let existing = people[id] else { return }
            people[id] = Subject(id: existing.id, kind: existing.kind, status: status,
                                 attributes: existing.attributes)
        }
    }

    private static func store(
        _ roster: Roster = Roster([Subject(id: "ada", kind: .person, attributes: ["site": "north-house"])]),
        clock: Clock = Clock()
    ) -> (SessionStore, Roster, Clock) {
        (SessionStore(subjects: { roster.subject($0) }, now: { clock.now }), roster, clock)
    }

    // MARK: - Minting and resolving

    @Test("a minted session resolves to the subject it was minted for")
    func aMintedSessionResolves() async throws {
        let (store, _, _) = Self.store()
        var generator = SplitMix64(seed: 1)
        let session = await store.mint(for: "ada", lifetime: 3_600, using: &generator)

        let subject = try #require(await store.subject(for: session.token))
        #expect(subject.id == "ada")
        // The consumer's own claims come back with it, unaltered.
        #expect(subject.attributes["site"] == "north-house")
    }

    @Test("a token nobody minted resolves to nothing")
    func anUnmintedTokenIsRefused() async {
        let (store, _, _) = Self.store()
        #expect(await store.resolve(SessionToken("never-issued")) == .refused(.unknown))
    }

    @Test("and a credential of another kind is not a session")
    func anotherKindIsRefused() async {
        let (store, _, _) = Self.store()
        var generator = SplitMix64(seed: 2)
        let session = await store.mint(for: "ada", lifetime: 3_600, using: &generator)

        // The same value presented as a bearer key. A store that matched on value alone would
        // let a session id be used wherever an API key is accepted.
        #expect(await store.resolve(BearerKey(session.token.value)) == .refused(.unknown))
    }

    @Test("two sessions are never the same token")
    func tokensAreUnique() async {
        let (store, _, _) = Self.store()
        var generator = SplitMix64(seed: 3)
        let first = await store.mint(for: "ada", lifetime: 3_600, using: &generator)
        let second = await store.mint(for: "ada", lifetime: 3_600, using: &generator)
        #expect(first.token.value != second.token.value)
    }

    @Test("the token is long enough that guessing is hopeless")
    func tokensCarryEnoughEntropy() async {
        let (store, _, _) = Self.store()
        var generator = SplitMix64(seed: 4)
        let session = await store.mint(for: "ada", lifetime: 3_600, using: &generator)

        // 128 bits is the floor the design sets for a value that authenticates on its own.
        #expect(session.token.value.count >= 22)
    }

    // MARK: - Ending

    @Test("a session expires on its own")
    func sessionsExpire() async {
        let (store, _, clock) = Self.store()
        var generator = SplitMix64(seed: 5)
        let session = await store.mint(for: "ada", lifetime: 3_600, using: &generator)

        clock.advance(3_601)
        #expect(await store.resolve(session.token) == .refused(.expired))
    }

    @Test("and can be ended early")
    func sessionsCanBeRevoked() async {
        let (store, _, _) = Self.store()
        var generator = SplitMix64(seed: 6)
        let session = await store.mint(for: "ada", lifetime: 3_600, using: &generator)

        await store.revoke(session.token)
        #expect(await store.resolve(session.token) == .refused(.unknown))
    }

    @Test("ending one leaves the others alone, so signing out here is not signing out everywhere")
    func revokingOneSessionSparesTheRest() async {
        let (store, _, _) = Self.store()
        var generator = SplitMix64(seed: 7)
        let laptop = await store.mint(for: "ada", lifetime: 3_600, using: &generator)
        let phone = await store.mint(for: "ada", lifetime: 3_600, using: &generator)

        await store.revoke(laptop.token)
        #expect(await store.resolve(laptop.token) == .refused(.unknown))
        #expect(await store.subject(for: phone.token)?.id == "ada")
    }

    @Test("and all of a subject's sessions can be ended at once")
    func allSessionsCanBeRevoked() async {
        let (store, _, _) = Self.store()
        var generator = SplitMix64(seed: 8)
        let laptop = await store.mint(for: "ada", lifetime: 3_600, using: &generator)
        let phone = await store.mint(for: "ada", lifetime: 3_600, using: &generator)

        await store.revokeAll(forSubject: "ada")
        #expect(await store.resolve(laptop.token) == .refused(.unknown))
        #expect(await store.resolve(phone.token) == .refused(.unknown))
    }

    // MARK: - The property that shapes the design

    @Test("revoking the subject ends their sessions, without anyone ending them")
    func revokingASubjectEndsTheirSessions() async {
        let (store, roster, _) = Self.store()
        var generator = SplitMix64(seed: 9)
        let session = await store.mint(for: "ada", lifetime: 3_600, using: &generator)
        #expect(await store.subject(for: session.token)?.id == "ada")

        roster.setStatus(.revoked, for: "ada")

        // The status is read at every resolution, never snapshotted at login. Otherwise
        // revocation would take effect whenever the last session happened to lapse, and
        // "revoked" would mean "revoked, eventually, probably".
        #expect(await store.resolve(session.token) == .refused(.revoked))
    }

    @Test("and a honeypot subject's session reports itself")
    func aHoneypotSubjectsSessionIsReported() async {
        let roster = Roster([Subject(id: "ada", kind: .person, status: .honeypot)])
        let (store, _, _) = Self.store(roster)
        var generator = SplitMix64(seed: 10)
        let session = await store.mint(for: "ada", lifetime: 3_600, using: &generator)

        #expect(await store.resolve(session.token) == .refused(.honeypot))
    }

    @Test("a session for a subject the roster forgot resolves to nothing")
    func aSessionForAMissingSubjectIsRefused() async {
        let roster = Roster([Subject(id: "ada", kind: .person)])
        let (store, _, _) = Self.store(roster)
        var generator = SplitMix64(seed: 11)
        let session = await store.mint(for: "ghost", lifetime: 3_600, using: &generator)

        #expect(await store.resolve(session.token) == .refused(.unknown))
    }

    // MARK: - Housekeeping

    @Test("expired sessions can be swept, and sweeping spares the live ones")
    func expiredSessionsCanBeSwept() async {
        let (store, _, clock) = Self.store()
        var generator = SplitMix64(seed: 12)
        let short = await store.mint(for: "ada", lifetime: 60, using: &generator)
        let long = await store.mint(for: "ada", lifetime: 7_200, using: &generator)

        clock.advance(61)
        let removed = await store.removeExpired()

        #expect(removed == 1)
        #expect(await store.resolve(short.token) == .refused(.unknown))
        #expect(await store.subject(for: long.token)?.id == "ada")
    }
}
