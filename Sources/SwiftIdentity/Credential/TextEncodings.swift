import Foundation

/// Unpadded base64url, so a stored value never contains `$` or `=`.
///
/// Shared by every stored form here: passphrase digests and sealed one-time-code keys.
enum Base64URL {

    static func encode(_ bytes: [UInt8]) -> String {
        Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func decode(_ text: String) -> [UInt8]? {
        let alphabet = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        guard !text.isEmpty, text.allSatisfy(alphabet.contains) else { return nil }
        var standard = text.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        standard += String(repeating: "=", count: (4 - standard.count % 4) % 4)
        return Data(base64Encoded: standard).map(Array.init)
    }
}

/// RFC 4648 Base32, the alphabet authenticator apps read a key in.
enum Base32 {

    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

    /// Five bits per character, most significant first; `padded` adds `=` to a multiple of 8.
    static func encode(_ bytes: [UInt8], padded: Bool) -> String {
        var output = ""
        var buffer: UInt32 = 0
        var bits = 0
        for byte in bytes {
            buffer = (buffer << 8) | UInt32(byte)
            bits += 8
            while bits >= 5 {
                bits -= 5
                output.append(alphabet[Int((buffer >> UInt32(bits)) & 0x1F)])
            }
        }
        if bits > 0 {
            output.append(alphabet[Int((buffer << UInt32(5 - bits)) & 0x1F)])
        }
        if padded {
            output += String(repeating: "=", count: (8 - output.count % 8) % 8)
        }
        return output
    }
}
