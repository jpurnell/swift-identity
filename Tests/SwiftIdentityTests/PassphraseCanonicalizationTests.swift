import Foundation
import Testing
@testable import SwiftIdentity

/// What a passphrase becomes before it's hashed.
///
/// NIST SP 800-63B-4 §3.1.1.2 asks for UAX #15 §12.1's normalization process for stabilized
/// strings, with NFC. The motivating failure is a password that looks identical on two devices
/// and fails on one of them, because "é" arrived as one code point there and as two here.
@Suite("PassphraseCanonicalization")
struct PassphraseCanonicalizationTests {

    static let c1 = PassphraseCanonicalization.c1

    static func canonical(_ secret: String) throws -> String {
        try c1.canonicalize(secret).get()
    }

    // MARK: - NFC

    @Test("P6: composed and decomposed é canonicalize alike")
    func canonicalEquivalentsMatch() throws {
        let composed = "caf\u{E9}"
        let decomposed = "cafe\u{301}"
        // The precondition the test rests on: they really are different scalars.
        #expect(composed.unicodeScalars.count != decomposed.unicodeScalars.count)
        #expect(try Self.canonical(composed).unicodeScalars.elementsEqual(Self.canonical(decomposed).unicodeScalars))
    }

    @Test("P6: the form is NFC: a canonical singleton maps, Hangul jamo compose")
    func theFormIsNFC() throws {
        // U+212B ANGSTROM SIGN is a canonical singleton for U+00C5; NFC replaces it.
        #expect(Array(try Self.canonical("\u{212B}").unicodeScalars) == ["\u{C5}"])
        // Conjoining jamo ᄀ + ᅡ compose to 가 under NFC.
        #expect(Array(try Self.canonical("\u{1100}\u{1161}").unicodeScalars) == ["\u{AC00}"])
    }

    @Test("P6: compatibility characters stay distinct, because NFC isn't NFKC")
    func compatibilityCharactersAreNotFolded() throws {
        // Revisions 1–2 of the amendment had NFKC, which folds these. NIST says NFC.
        #expect(Array(try Self.canonical("\u{FF21}").unicodeScalars) == ["\u{FF21}"])   // fullwidth A
        #expect(Array(try Self.canonical("a\u{A0}b").unicodeScalars) == ["a", "\u{A0}", "b"])  // NBSP
        #expect(Array(try Self.canonical("\u{FB01}").unicodeScalars) == ["\u{FB01}"])   // ﬁ ligature
    }

    @Test("canonicalizing twice changes nothing")
    func canonicalizationIsIdempotent() throws {
        for secret in ["cafe\u{301}", "\u{212B}ngstr\u{F6}m", "\u{1100}\u{1161}\u{11A8}", "plain ascii"] {
            let once = try Self.canonical(secret)
            #expect(Array(try Self.canonical(once).unicodeScalars) == Array(once.unicodeScalars))
        }
    }

    // MARK: - What's kept as typed

    @Test("P4: leading and trailing spaces are part of the passphrase")
    func noTrimming() throws {
        #expect(try Self.canonical("  padded  ") == "  padded  ")
    }

    @Test("P4: case is kept")
    func noCaseMapping() throws {
        #expect(try Self.canonical("CorrectHorse") == "CorrectHorse")
    }

    @Test("P4: emoji sequences, right-to-left and Thai text are accepted whole")
    func unicodeIsAccepted() throws {
        let family = "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}"   // 👨‍👩‍👧, joined by ZWJ
        #expect(Array(try Self.canonical(family).unicodeScalars) == Array(family.unicodeScalars))
        let hebrew = "\u{5E9}\u{5DC}\u{5D5}\u{5DD} \u{5E2}\u{5D5}\u{5DC}\u{5DD}"
        #expect(try Self.canonical(hebrew) == hebrew)
        let thai = "\u{E2A}\u{E27}\u{E31}\u{E2A}\u{E14}\u{E35}"
        #expect(try Self.canonical(thai) == thai)
    }

    // MARK: - Refusals

    @Test("P6: an unassigned code point is refused, as UAX #15 §12.1 requires")
    func unassignedIsRefused() {
        // U+0378 is unassigned in every Unicode version to date.
        #expect(Self.c1.canonicalize("ab\u{378}") == .failure(.unassignedCodePoint(position: 2)))
        // U+FFFE is a noncharacter: General_Category=Unassigned, though it has an age.
        #expect(Self.c1.canonicalize("\u{FFFE}") == .failure(.unassignedCodePoint(position: 0)))
    }

    @Test("P6: a character newer than the pinned Unicode version is refused")
    func newerThanThePinIsRefused() throws {
        // U+2FFC was assigned in Unicode 15.1, after the pin. Refusing it is what keeps an
        // accepted passphrase's normalization stable across every runtime this package supports.
        let scalar = try #require(Unicode.Scalar(0x2FFC))
        let age = try #require(scalar.properties.age)
        #expect(age.major == 15 && age.minor == 1)
        #expect(Self.c1.canonicalize("x\(scalar)") == .failure(.unassignedCodePoint(position: 1)))
    }

    @Test("a character from the pinned version itself is accepted")
    func thePinnedVersionIsAccepted() throws {
        // U+1FA75 LIGHT BLUE HEART, assigned in 15.0.
        let scalar = try #require(Unicode.Scalar(0x1FA75))
        let age = try #require(scalar.properties.age)
        #expect(age.major == 15 && age.minor == 0)
        #expect(try Self.canonical("\(scalar)") == "\(scalar)")
    }

    @Test("P4: control characters are refused, never stripped")
    func controlsAreRefused() {
        #expect(Self.c1.canonicalize("a\u{0}b") == .failure(.controlCharacter(position: 1)))
        #expect(Self.c1.canonicalize("tab\there") == .failure(.controlCharacter(position: 3)))
        #expect(Self.c1.canonicalize("\u{7F}") == .failure(.controlCharacter(position: 0)))
        #expect(Self.c1.canonicalize("next\u{85}line") == .failure(.controlCharacter(position: 4)))
    }

    @Test("a refusal names a position, never the character")
    func refusalsCarryNoSecretMaterial() {
        // A refusal can reach a log. The position says where to look without saying what's there.
        let refusal = Self.c1.canonicalize("secret\u{0}")
        #expect(!String(describing: refusal).contains("secret"))
    }

    // MARK: - The pin

    @Test("the pinned version is 15.0, and the runtime knows at least that much")
    func thePinIsSatisfiedByTheRuntime() throws {
        #expect(Self.c1.unicodeMajor == 15 && Self.c1.unicodeMinor == 0)
        // A runtime older than the pin would refuse characters the pin admits, so the same
        // passphrase would work on one host and not another.
        let scalar = try #require(Unicode.Scalar(0x1FA75))
        let age = try #require(scalar.properties.age)
        #expect(age.major == 15 && age.minor == 0)
        #expect(Self.c1.identifier == "c1")
    }
}

/// NFC against Unicode's own conformance file, for the pinned version.
///
/// `NormalizationTest-15.0.0.txt` is stored as downloaded (see `Vectors/PROVENANCE.md`). Strings
/// are compared scalar by scalar: Swift's `==` on `String` is canonical equivalence, which would
/// make every one of these checks pass whether or not anything was normalized.
@Suite("PassphraseCanonicalization — Unicode conformance")
struct NormalizationConformanceTests {

    static func scalars(_ field: Substring) -> [Unicode.Scalar] {
        field.split(separator: " ").compactMap { UInt32($0, radix: 16).flatMap(Unicode.Scalar.init) }
    }

    static func nfc(_ scalars: [Unicode.Scalar]) -> [Unicode.Scalar] {
        var text = ""
        text.unicodeScalars.append(contentsOf: scalars)
        return Array(PassphraseCanonicalization.nfc(text).unicodeScalars)
    }

    @Test("P6: NFC agrees with an independent implementation, case for case")
    func differentialAgainstPython() throws {
        // `differential-nfc-python.txt`: 20,000 seeded inputs and CPython's NFC of each. See the
        // generator for how inputs are drawn. About 3,000 of them change under NFC, so an
        // implementation that returned its input unchanged would fail here.
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .appendingPathComponent("Vectors/differential-nfc-python.txt")
        let text = try String(contentsOf: url, encoding: .utf8)

        var cases = 0
        var changed = 0
        for line in text.split(whereSeparator: \.isNewline) where !line.hasPrefix("#") {
            let fields = line.split(separator: ";", omittingEmptySubsequences: false)
            guard fields.count == 2 else { continue }
            let input = Self.scalars(fields[0])
            let expected = Self.scalars(fields[1])
            #expect(Self.nfc(input) == expected, "NFC differs from CPython at \(line)")
            cases += 1
            if input != expected { changed += 1 }
        }
        #expect(cases == 20_000)
        #expect(changed == 3_118)
    }

    @Test("P6: every NormalizationTest.txt case holds for NFC")
    func conformanceFile() throws {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .appendingPathComponent("Vectors/NormalizationTest-15.0.0.txt")
        let text = try String(contentsOf: url, encoding: .utf8)

        var cases = 0
        var listedInPartOne = Set<UInt32>()
        var part = ""
        for line in text.split(whereSeparator: \.isNewline) {
            if line.hasPrefix("@Part") { part = String(line.prefix(6)); continue }
            guard !line.hasPrefix("#") else { continue }
            let fields = line.split(separator: ";", omittingEmptySubsequences: false)
            guard fields.count >= 5 else { continue }
            let c = (0..<5).map { Self.scalars(fields[$0]) }
            if part == "@Part1", let only = c[0].first, c[0].count == 1 { listedInPartOne.insert(only.value) }

            // UAX #15's conformance rules for NFC: c2 == NFC(c1) == NFC(c2) == NFC(c3), and
            // c4 == NFC(c4) == NFC(c5).
            #expect(Self.nfc(c[0]) == c[1], "NFC(c1) at \(line)")
            #expect(Self.nfc(c[1]) == c[1], "NFC(c2) at \(line)")
            #expect(Self.nfc(c[2]) == c[1], "NFC(c3) at \(line)")
            #expect(Self.nfc(c[3]) == c[3], "NFC(c4) at \(line)")
            #expect(Self.nfc(c[4]) == c[3], "NFC(c5) at \(line)")
            cases += 1
        }
        // Exact counts for the 15.0.0 file, so one that failed to parse can't pass by being empty.
        #expect(cases == 19_074)
        #expect(listedInPartOne.count == 17_029)

        // And the file's own rule for Part 1: any character assigned in 15.0 that it doesn't list
        // is left alone by NFC.
        let canonicalization = PassphraseCanonicalization.c1
        for value in UInt32(0)...0x10FFFF where !listedInPartOne.contains(value) {
            guard let scalar = Unicode.Scalar(value),
                  case .success = canonicalization.canonicalize(String(scalar)) else { continue }
            #expect(Self.nfc([scalar]) == [scalar], "U+\(String(value, radix: 16, uppercase: true)) changed under NFC")
        }
    }
}
