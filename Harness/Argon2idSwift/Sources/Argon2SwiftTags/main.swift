// Reads Argon2id cases, one per line on stdin, and prints argon2-swift's tag for each.
//
// A case is `password;salt;secret;ad;m;t;p;tagLength`: byte strings in lowercase hex (empty for
// none), m in KiB, t passes, p lanes. The output is one lowercase-hex tag per line, in order. A
// line that doesn't parse, or that argon2-swift refuses, stops the run with a message, so a
// partial output can never be mistaken for a whole one.

import Foundation
import SwiftArgon2

enum CaseFailure: Error, CustomStringConvertible {
    case malformed(String)

    var description: String {
        switch self {
        case .malformed(let line): "malformed case: \(line)"
        }
    }
}

func bytes(hex: Substring) -> Data? {
    let digits = Array(hex.utf8)
    guard digits.count % 2 == 0 else { return nil }
    var result = Data()
    var index = 0
    while index < digits.count {
        guard let byte = UInt8(String(decoding: digits[index...(index + 1)], as: UTF8.self), radix: 16) else {
            return nil
        }
        result.append(byte)
        index += 2
    }
    return result
}

func hex(_ data: Data) -> String {
    data.map { byte in
        let digits = String(byte, radix: 16)
        return digits.count == 1 ? "0" + digits : digits
    }.joined()
}

func tag(for line: String) async throws -> String {
    let fields = line.split(separator: ";", omittingEmptySubsequences: false)
    guard fields.count == 8 else { throw CaseFailure.malformed(line) }
    let inputs = fields[0..<4].compactMap(bytes(hex:))
    let numbers = fields[4..<8].compactMap { UInt32($0) }
    guard inputs.count == 4, numbers.count == 4 else { throw CaseFailure.malformed(line) }
    let argon2 = try Argon2(params: Argon2Params(
        parallelism: numbers[2], tagLength: numbers[3], memorySize: numbers[0],
        iterations: numbers[1], variant: .argon2id
    ))
    let result = try await argon2.compute(
        password: inputs[0], salt: inputs[1],
        secret: inputs[2].isEmpty ? nil : inputs[2],
        associatedData: inputs[3].isEmpty ? nil : inputs[3]
    )
    return hex(result)
}

do {
    while let line = readLine(strippingNewline: true) {
        guard !line.isEmpty else { continue }
        print(try await tag(for: line))
    }
} catch {
    FileHandle.standardError.write(Data("argon2-swift-tags: \(error)\n".utf8))
    exit(1)
}
