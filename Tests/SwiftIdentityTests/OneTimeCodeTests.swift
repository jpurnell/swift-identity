import Foundation
import SwiftDeterminism
import Testing
@testable import SwiftIdentity

/// One-time codes from an authenticator app: RFC 6238 TOTP, with the key sealed at rest.
@Suite("OneTimeCode")
struct OneTimeCodeTests {

    static let vectors = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        .appendingPathComponent("Vectors")

    struct TOTPFile: Decodable {
        struct Vector: Decodable {
            let time: Int64
            let step: Int64
            let totp: String
            let algorithm: String
            let seedHex: String
        }
        let timeStep: Int
        let digits: Int
        let vectors: [Vector]
    }

    struct Base32File: Decodable {
        struct Vector: Decodable { let input: String; let output: String }
        let vectors: [Vector]
    }

    static func hex(_ text: String) -> [UInt8] {
        var bytes: [UInt8] = []
        var index = text.startIndex
        while index < text.endIndex {
            let next = text.index(index, offsetBy: 2, limitedBy: text.endIndex) ?? text.endIndex
            if let byte = UInt8(text[index..<next], radix: 16) { bytes.append(byte) }
            index = next
        }
        return bytes
    }

    /// A sealing key in a fresh owner-only file.
    static func sealingKey(seed: UInt64) throws -> SealingKey {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("swiftidentity-totp-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("sealing.key")
        var generator = SplitMix64(seed: seed)
        try SealingKey.create(at: url, using: &generator)
        return try SealingKey(contentsOf: url)
    }

    // MARK: - RFC 6238

    @Test("every RFC 6238 Appendix B vector: SHA-1, SHA-256 and SHA-512, 8 digits")
    func rfc6238Vectors() throws {
        let data = try Data(contentsOf: Self.vectors.appendingPathComponent("totp-rfc6238.json"))
        let file = try JSONDecoder().decode(TOTPFile.self, from: data)
        #expect(file.vectors.count == 18)
        for vector in file.vectors {
            let algorithm = try #require(OneTimeCodeParameters.Algorithm(rawValue: vector.algorithm.lowercased()))
            let parameters = OneTimeCodeParameters(algorithm: algorithm, digits: file.digits, period: file.timeStep)
            #expect(parameters.step(at: Date(timeIntervalSince1970: TimeInterval(vector.time))) == vector.step)
            #expect(TOTP.code(key: Self.hex(vector.seedHex), step: vector.step, parameters: parameters) == vector.totp,
                    "\(vector.algorithm) at \(vector.time)")
        }
    }

    @Test("Base32 matches every RFC 4648 §10 vector")
    func base32Vectors() throws {
        let data = try Data(contentsOf: Self.vectors.appendingPathComponent("base32-rfc4648.json"))
        let file = try JSONDecoder().decode(Base32File.self, from: data)
        #expect(file.vectors.count == 7)
        for vector in file.vectors {
            #expect(Base32.encode(Array(vector.input.utf8), padded: true) == vector.output)
        }
    }

    // MARK: - Parameters

    @Test("O1, O2: the default is HMAC-SHA-1, 6 digits, 30-second steps, named for the record")
    func defaults() {
        let standard = OneTimeCodeParameters.standard
        #expect(standard.algorithm == .sha1)
        #expect(standard.digits == 6)
        #expect(standard.period == 30)
        #expect(standard.period <= 120)
        #expect(standard.identifier == "totp-sha1-6-30")
    }

    @Test("O1: a new key is 160 bits for SHA-1, above the 112 NIST requires")
    func keyLength() throws {
        #expect(OneTimeCodeParameters.standard.keyLength * 8 == 160)
        #expect(OneTimeCodeParameters(algorithm: .sha256, digits: 6, period: 30).keyLength * 8 == 256)
        #expect(OneTimeCodeParameters.standard.keyLength * 8 >= 112)
    }

    @Test("O9: a one-time code is possession, and not phishing-resistant")
    func factorClass() {
        #expect(OneTimeCode.kind == "totp")
        #expect(OneTimeCode.factorClass == .possession)
        #expect(!OneTimeCode.isPhishingResistant)
    }

    @Test("O4: the key comes from the caller's generator, never from anywhere this package chose")
    func keyComesFromTheCallersGenerator() throws {
        let sealing = try Self.sealingKey(seed: 20)
        var first = SplitMix64(seed: 21)
        var again = SplitMix64(seed: 21)
        var other = SplitMix64(seed: 22)
        let a = try OneTimeCodeVerifier(for: "ada", using: &first, sealingKey: sealing)
        let b = try OneTimeCodeVerifier(for: "ada", using: &again, sealingKey: sealing)
        let c = try OneTimeCodeVerifier(for: "ada", using: &other, sealingKey: sealing)
        // The same generator state gives the same key: nothing else was mixed in. In production
        // that generator is `SystemRandomNumberGenerator`, an approved RBG (§3.2.12).
        #expect(try a.key(sealingKey: sealing) == b.key(sealingKey: sealing))
        #expect(try a.key(sealingKey: sealing) != c.key(sealingKey: sealing))
    }

    // MARK: - Sealing

    @Test("O3: the key is sealed: the stored form doesn't contain it")
    func keyIsSealed() throws {
        let sealing = try Self.sealingKey(seed: 1)
        var generator = SplitMix64(seed: 2)
        let verifier = try OneTimeCodeVerifier(for: "ada", using: &generator, sealingKey: sealing)
        let key = try verifier.key(sealingKey: sealing)
        #expect(key.count == 20)
        #expect(!verifier.encoded.contains(Base32.encode(key, padded: false)))
        #expect(verifier.encoded.hasPrefix("totp-sha1-6-30$"))
        let decoded = try #require(OneTimeCodeVerifier(encoded: verifier.encoded, subjectID: "ada"))
        #expect(try decoded.key(sealingKey: sealing) == key)
    }

    @Test("O3: a sealed key opens only for its own subject and its own sealing key")
    func sealIsBound() throws {
        let sealing = try Self.sealingKey(seed: 3)
        let other = try Self.sealingKey(seed: 4)
        var generator = SplitMix64(seed: 5)
        let verifier = try OneTimeCodeVerifier(for: "ada", using: &generator, sealingKey: sealing)
        #expect(throws: OneTimeCodeVerifier.Failure.cannotOpen) { try verifier.key(sealingKey: other) }
        // A line moved to another subject stops working.
        let moved = try #require(OneTimeCodeVerifier(encoded: verifier.encoded, subjectID: "grace"))
        #expect(throws: OneTimeCodeVerifier.Failure.cannotOpen) { try moved.key(sealingKey: sealing) }
    }

    @Test("a sealing key file readable by others is refused")
    func sealingKeyPermissions() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("swiftidentity-totp-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("sealing.key")
        var generator = SplitMix64(seed: 6)
        try SealingKey.create(at: url, using: &generator)
        let mode = try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? Int
        #expect(mode == 0o600)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: url.path)
        #expect(throws: SealingKey.Failure.readableByOthers) { try SealingKey(contentsOf: url) }
    }

    @Test("a sealing key file of the wrong size is refused")
    func sealingKeySize() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("swiftidentity-totp-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("sealing.key")
        try Data(repeating: 1, count: 16).write(to: url)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        #expect(throws: SealingKey.Failure.wrongSize(16)) { try SealingKey(contentsOf: url) }
    }

    // MARK: - Matching

    @Test("O7: a code matches within one step either side, and not beyond")
    func window() throws {
        let sealing = try Self.sealingKey(seed: 7)
        var generator = SplitMix64(seed: 8)
        let verifier = try OneTimeCodeVerifier(for: "ada", using: &generator, sealingKey: sealing)
        let key = try verifier.key(sealingKey: sealing)
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let step = try #require(OneTimeCodeParameters.standard.step(at: now))

        for offset in Int64(-1)...1 {
            let code = TOTP.code(key: key, step: step + offset, parameters: .standard)
            #expect(verifier.matchingStep(code, at: now, sealingKey: sealing) == step + offset)
        }
        for offset in [Int64(-2), 2] {
            let code = TOTP.code(key: key, step: step + offset, parameters: .standard)
            #expect(verifier.matchingStep(code, at: now, sealingKey: sealing) == nil)
        }
    }

    @Test("a date no step can represent has no step, and matches nothing")
    func unrepresentableDates() throws {
        #expect(OneTimeCodeParameters.standard.step(at: Date(timeIntervalSince1970: .infinity)) == nil)
        #expect(OneTimeCodeParameters.standard.step(at: Date(timeIntervalSince1970: .nan)) == nil)
        #expect(OneTimeCodeParameters.standard.step(at: Date(timeIntervalSince1970: 1e300)) == nil)
        #expect(OneTimeCodeParameters.standard.step(at: Date(timeIntervalSince1970: 59)) == 1)
        let sealing = try Self.sealingKey(seed: 13)
        var generator = SplitMix64(seed: 14)
        let verifier = try OneTimeCodeVerifier(for: "ada", using: &generator, sealingKey: sealing)
        #expect(verifier.matchingStep("123456", at: Date(timeIntervalSince1970: .infinity), sealingKey: sealing) == nil)
    }

    @Test("a malformed code matches nothing")
    func malformedCodes() throws {
        let sealing = try Self.sealingKey(seed: 9)
        var generator = SplitMix64(seed: 10)
        let verifier = try OneTimeCodeVerifier(for: "ada", using: &generator, sealingKey: sealing)
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        for code in ["", "12345", "1234567", "12345a", "١٢٣٤٥٦", " 123456"] {
            #expect(verifier.matchingStep(code, at: now, sealingKey: sealing) == nil, "\(code)")
        }
    }

    // MARK: - Enrollment

    @Test("the enrollment URI is what authenticator apps scan")
    func enrollmentURI() throws {
        let sealing = try Self.sealingKey(seed: 11)
        var generator = SplitMix64(seed: 12)
        let verifier = try OneTimeCodeVerifier(for: "ada", using: &generator, sealingKey: sealing)
        let key = try verifier.key(sealingKey: sealing)
        let uri = try verifier.enrollmentURI(issuer: "Household Vault", account: "ada", sealingKey: sealing)
        let components = try #require(URLComponents(string: uri))
        #expect(components.scheme == "otpauth")
        #expect(components.host == "totp")
        #expect(components.path == "/Household Vault:ada")
        let query = Dictionary(uniqueKeysWithValues: (components.queryItems ?? []).map { ($0.name, $0.value ?? "") })
        #expect(query["secret"] == Base32.encode(key, padded: false))
        #expect(query["issuer"] == "Household Vault")
        #expect(query["algorithm"] == "SHA1")
        #expect(query["digits"] == "6")
        #expect(query["period"] == "30")
    }
}
