import Foundation
import SwiftDeterminism
import Testing
@testable import SwiftIdentity

@Suite("BearerKeyMinter")
struct BearerKeyMinterTests {
    private func mint(_ minter: BearerKeyMinter = BearerKeyMinter(), seed: UInt64 = 5) -> MintedKey {
        var generator = SplitMix64(seed: seed)
        return minter.mint(using: &generator)
    }

    @Test("A key is 256 random bits as base64url: 43 characters of letters, digits, - and _")
    func shape() {
        let minted = mint()
        #expect(minted.key.count == 43)
        #expect(minted.key.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") })
    }

    @Test("A prefix is put in front of the key")
    func prefix() {
        let minted = mint(BearerKeyMinter(prefix: "ijs_"))
        #expect(minted.key.hasPrefix("ijs_"))
        #expect(minted.key.count == 47)
    }

    @Test("The digest is the one the file credential store keeps for that key")
    func digestMatchesTheStore() {
        let minted = mint()
        #expect(minted.digest == FileCredentialStore.storedDigest(for: BearerKey(minted.key)))
        #expect(minted.digest.count == 64)
    }

    @Test("Two keys differ, and a seeded generator makes a reproducible one")
    func distinctAndReproducible() {
        let minter = BearerKeyMinter()
        var shared = SplitMix64(seed: 3)
        #expect(minter.mint(using: &shared).key != minter.mint(using: &shared).key)
        var first = SplitMix64(seed: 77)
        var second = SplitMix64(seed: 77)
        #expect(minter.mint(using: &first).key == minter.mint(using: &second).key)
    }

    @Test("A minted key never appears in its own description or debug description")
    func redacted() {
        let minted = mint()
        #expect(!minted.description.contains(minted.key))
        #expect(!minted.debugDescription.contains(minted.key))
        #expect(!"\(minted)".contains(minted.key))
        #expect(!String(reflecting: minted).contains(minted.key))
    }
}
