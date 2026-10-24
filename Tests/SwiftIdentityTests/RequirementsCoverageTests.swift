import Foundation
import Testing

/// The requirements file and the tests that cite it, held to each other.
///
/// A compliance matrix nobody compiles drifts: a row is marked done and its test is later
/// renamed, or a test cites a row that was renumbered away. This suite makes both a failure.
@Suite("Requirements coverage")
struct RequirementsCoverageTests {

    struct Row: Equatable {
        let id: String
        let scope: String
        let status: String
    }

    static let testsDirectory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()

    static func rows() throws -> [Row] {
        let url = testsDirectory.appendingPathComponent("Requirements/NIST-SP-800-63B-4.md")
        let text = try String(contentsOf: url, encoding: .utf8)
        return text.split(whereSeparator: \.isNewline).compactMap { line in
            let cells = line.split(separator: "|", omittingEmptySubsequences: false)
                .map { $0.trimmingCharacters(in: .whitespaces) }
            // `| ID | Level | Section | Scope | Status | Requirement |` splits into eight cells,
            // the first and last empty.
            guard cells.count == 8, Self.isRequirementID(cells[1]) else { return nil }
            return Row(id: cells[1], scope: cells[4], status: cells[5])
        }
    }

    /// An ID is a capital letter and a digit, then anything up to the colon: `P6`, `P11a`, `O3`.
    static func isRequirementID<S: StringProtocol>(_ text: S) -> Bool {
        let scalars = Array(text.unicodeScalars)
        guard scalars.count >= 2 else { return false }
        return ("A"..."Z").contains(scalars[0]) && ("0"..."9").contains(scalars[1])
    }

    /// Every ID cited by a test display name of the form `"P6: …"` or `"P8, P19: …"`.
    static func citedIDs() throws -> Set<String> {
        let files = try FileManager.default.contentsOfDirectory(
            at: testsDirectory, includingPropertiesForKeys: nil
        ).filter { $0.pathExtension == "swift" }

        var cited = Set<String>()
        for file in files {
            let text = try String(contentsOf: file, encoding: .utf8)
            for line in text.split(whereSeparator: \.isNewline) {
                guard let start = line.range(of: "@Test(\"") else { continue }
                let rest = line[start.upperBound...]
                guard let colon = rest.firstIndex(of: ":") else { continue }
                // One ID or several, comma-separated: `"P8, P19: …"`.
                let ids = rest[..<colon].split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
                guard ids.allSatisfy({ Self.isRequirementID($0) && !$0.contains(" ") }) else { continue }
                cited.formUnion(ids)
            }
        }
        return cited
    }

    @Test("the requirements file parses, with every row in it")
    func theFileParses() throws {
        let rows = try Self.rows()
        // P1–P22 with P11 and P14 split, 24 rows, and O1–O9. A count, so a row lost to a
        // malformed line is a failure rather than a requirement that silently stopped being checked.
        #expect(rows.count == 33)
        #expect(Set(rows.map(\.id)).count == rows.count, "an ID appears twice")
        for row in rows {
            #expect(["package", "host"].contains(row.scope), "\(row.id): unknown scope \(row.scope)")
            #expect(["planned", "implemented", "n/a"].contains(row.status), "\(row.id): unknown status \(row.status)")
        }
    }

    @Test("every implemented requirement is cited by a test")
    func implementedRowsAreCited() throws {
        let cited = try Self.citedIDs()
        for row in try Self.rows() where row.scope == "package" && row.status == "implemented" {
            #expect(cited.contains(row.id), "\(row.id) is marked implemented but no test cites it")
        }
    }

    @Test("every cited requirement exists")
    func citedRowsExist() throws {
        let known = Set(try Self.rows().map(\.id))
        for id in try Self.citedIDs() {
            #expect(known.contains(id), "a test cites \(id), which the requirements file doesn't have")
        }
    }

    @Test("a cited requirement isn't still marked planned")
    func citedRowsAreNotPlanned() throws {
        let cited = try Self.citedIDs()
        for row in try Self.rows() where cited.contains(row.id) {
            #expect(row.status == "implemented", "\(row.id) is cited by a test but marked \(row.status)")
        }
    }
}
