import Foundation

/// Reading the known-answer files in `Vectors/`.
///
/// They're read by path from beside the test sources rather than bundled, for the reason the
/// package manifest gives: they're the reference, and a bundled copy could go stale.
enum VectorFiles {

    /// The `Vectors/` directory.
    static let directory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        .appendingPathComponent("Vectors")

    /// The contents of one file in `Vectors/`.
    static func data(_ name: String) throws -> Data {
        try Data(contentsOf: directory.appendingPathComponent(name))
    }

    /// A JSON file in `Vectors/`, decoded.
    static func json<Decoded: Decodable>(_ name: String, as type: Decoded.Type) throws -> Decoded {
        try JSONDecoder().decode(type, from: data(name))
    }

    /// A text file in `Vectors/`.
    static func text(_ name: String) throws -> String {
        try String(contentsOf: directory.appendingPathComponent(name), encoding: .utf8)
    }

    /// Lowercase or uppercase hex to bytes, or nil if it isn't hex. The empty string is no bytes.
    static func bytes<S: StringProtocol>(hex: S) -> [UInt8]? {
        let digits = Array(hex.utf8)
        guard digits.count % 2 == 0 else { return nil }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(digits.count / 2)
        var index = 0
        while index < digits.count {
            guard let high = nibble(digits[index]), let low = nibble(digits[index + 1]) else { return nil }
            bytes.append(high << 4 | low)
            index += 2
        }
        return bytes
    }

    private static func nibble(_ digit: UInt8) -> UInt8? {
        switch digit {
        case UInt8(ascii: "0")...UInt8(ascii: "9"): digit - UInt8(ascii: "0")
        case UInt8(ascii: "a")...UInt8(ascii: "f"): digit - UInt8(ascii: "a") + 10
        case UInt8(ascii: "A")...UInt8(ascii: "F"): digit - UInt8(ascii: "A") + 10
        default: nil
        }
    }
}
