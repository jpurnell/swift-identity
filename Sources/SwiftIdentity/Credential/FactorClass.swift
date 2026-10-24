import Foundation

/// What kind of evidence a credential is: NIST's three factor classes.
///
/// A struct rather than an enum, so a class can be added without breaking anyone who switched
/// over these, though NIST has had three for decades.
public struct FactorClass: Sendable, Hashable, Codable {
    /// The class's stable name, as it appears in audit records.
    public let name: String

    /// Something you know: a passphrase, a PIN.
    public static let knowledge = FactorClass(name: "knowledge")
    /// Something you have: a generated key, a session, a device key, an authenticator app.
    public static let possession = FactorClass(name: "possession")
    /// Something you are. Used only to unlock a possession factor, never alone (NIST SP
    /// 800-63B-4 §3.2.3).
    public static let inherence = FactorClass(name: "inherence")

    init(name: String) { self.name = name }
}
