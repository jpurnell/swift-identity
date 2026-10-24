import Testing
@testable import SwiftIdentity

/// One differential case: `password;salt;secret;ad;m;t;p;tagLength;tag`, as every Argon2id
/// harness under `Harness/` writes them.
struct Argon2idCase: Sendable, CustomTestStringConvertible {
    let password: [UInt8]
    let salt: [UInt8]
    let secret: [UInt8]
    let associatedData: [UInt8]
    let memoryKiB: Int
    let iterations: Int
    let parallelism: Int
    let tagLength: Int
    let tag: [UInt8]
    /// The line it came from, for a failure message.
    let line: String

    var label: String { "m=\(memoryKiB) t=\(iterations) p=\(parallelism) T=\(tagLength): \(line)" }
    var testDescription: String { "m=\(memoryKiB) t=\(iterations) p=\(parallelism) T=\(tagLength)" }

    /// The file's header: its `#` lines, which name the generator and the reference.
    static func header(_ name: String) throws -> [String] {
        try VectorFiles.text(name).split(whereSeparator: \.isNewline)
            .filter { $0.hasPrefix("#") }.map(String.init)
    }

    /// Every case in a file in `Vectors/`.
    static func cases(in name: String) throws -> [Argon2idCase] {
        var cases: [Argon2idCase] = []
        for line in try VectorFiles.text(name).split(whereSeparator: \.isNewline) where !line.hasPrefix("#") {
            let fields = line.split(separator: ";", omittingEmptySubsequences: false)
            try #require(fields.count == 9, "malformed case: \(line)")
            let bytes = try (0..<4).map { try #require(VectorFiles.bytes(hex: fields[$0])) }
            let numbers = try (4..<8).map { try #require(Int(fields[$0])) }
            cases.append(Argon2idCase(
                password: bytes[0], salt: bytes[1], secret: bytes[2], associatedData: bytes[3],
                memoryKiB: numbers[0], iterations: numbers[1], parallelism: numbers[2],
                tagLength: numbers[3], tag: try #require(VectorFiles.bytes(hex: fields[8])),
                line: String(line)
            ))
        }
        return cases
    }

    /// This package's tag for the case.
    func ours() throws -> [UInt8] {
        try Argon2id(memoryKiB: memoryKiB, iterations: iterations, parallelism: parallelism).hash(
            password: password, salt: salt, secret: secret, associatedData: associatedData,
            tagLength: tagLength
        )
    }
}

/// Argon2id against phc-winner-argon2, the reference implementation, through its `argon2` CLI.
///
/// `argon2id-phc-winner-argon2.txt` is written by `Harness/Argon2id/generate-phc.py`, which
/// refuses to run unless the CLI first reproduces every eligible case of the OpenSSL file. The
/// CLI takes no secret or associated data, so neither appears here. The file ends with cases at
/// the deployment parameters, OWASP's minimum (m=19456, t=2, p=1) and RFC 9106's second
/// recommendation (m=65536, t=3, p=4), which the small seeded cases never reach.
@Suite("Argon2id — phc-winner-argon2")
struct Argon2idPHCReferenceTests {

    static let file = "argon2id-phc-winner-argon2.txt"

    @Test("the header names the generator, the reference and its version, and the check it passed")
    func provenance() throws {
        let header = try Argon2idCase.header(Self.file).joined(separator: "\n")
        #expect(header.contains("Generator: Harness/Argon2id/generate-phc.py"))
        #expect(header.contains("Reference: phc-winner-argon2"))
        #expect(header.contains("Known answers through the reference:"))
    }

    // One test case per vector, so the deployment-sized ones run alongside each other.
    @Test("every seeded case matches the reference's tag", arguments: try Argon2idCase.cases(in: file))
    func everyCase(_ vector: Argon2idCase) throws {
        #expect(try vector.ours() == vector.tag, "\(vector.label)")
    }

    @Test("the file holds every case the generator writes")
    func coverage() throws {
        let cases = try Argon2idCase.cases(in: Self.file)
        // The generator writes 48 small cases and 4 at deployment parameters; fewer means the
        // file was cut short.
        #expect(cases.count == 52)
        #expect(Set(cases.map(\.parallelism)) == [1, 2, 3, 4])
        #expect(cases.allSatisfy { $0.secret.isEmpty && $0.associatedData.isEmpty })
        let shapes = cases.map { [$0.memoryKiB, $0.iterations, $0.parallelism] }
        #expect(shapes.filter { $0 == [19_456, 2, 1] }.count == 2)
        #expect(shapes.filter { $0 == [65_536, 3, 4] }.count == 2)
    }
}

/// Argon2id against `mimiclone/argon2-swift`, a second, independent Swift implementation.
///
/// `argon2id-argon2-swift.txt` is written by `Harness/Argon2idSwift/generate.py`, through a
/// harness package that pins argon2-swift to an exact revision and is never a dependency of this
/// one. argon2-swift is pure Swift with its own BLAKE2b, so it shares no code with OpenSSL, the C
/// reference, or this package; and it takes a secret and associated data, so those get cases
/// here too. The generator refuses to run unless it first reproduces RFC 9106 §5.3.
@Suite("Argon2id — argon2-swift")
struct Argon2idSwiftReferenceTests {

    static let file = "argon2id-argon2-swift.txt"

    @Test("the header names the generator, the pinned revision, and the RFC check it passed")
    func provenance() throws {
        let header = try Argon2idCase.header(Self.file).joined(separator: "\n")
        #expect(header.contains("Generator: Harness/Argon2idSwift/generate.py"))
        #expect(header.contains("Reference: mimiclone/argon2-swift at revision 0f6581ee4051a9160f735e9b4b7f47431151b89d"))
        #expect(header.contains("RFC 9106 section 5.3 through the reference: reproduced."))
    }

    @Test("every seeded case matches argon2-swift's tag", arguments: try Argon2idCase.cases(in: file))
    func everyCase(_ vector: Argon2idCase) throws {
        #expect(try vector.ours() == vector.tag, "\(vector.label)")
    }

    @Test("the file holds every case the generator writes, secrets and associated data among them")
    func coverage() throws {
        let cases = try Argon2idCase.cases(in: Self.file)
        #expect(cases.count == 52)
        #expect(Set(cases.map(\.parallelism)) == [1, 2, 3, 4])
        #expect(cases.contains { !$0.secret.isEmpty })
        #expect(cases.contains { !$0.associatedData.isEmpty })
        let shapes = cases.map { [$0.memoryKiB, $0.iterations, $0.parallelism] }
        #expect(shapes.filter { $0 == [19_456, 2, 1] }.count == 2)
        #expect(shapes.filter { $0 == [65_536, 3, 4] }.count == 2)
    }
}
