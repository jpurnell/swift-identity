import Testing
@testable import SwiftIdentity

/// A placeholder suite.
///
/// The real tests arrive with the first type, and they are written before it — the refusals
/// first, because a credential store fails dangerously. See
/// `project/plans/proposals/SubjectsAndCredentials.md` §9.
@Suite("SwiftIdentity")
struct SwiftIdentityTests {

    @Test("the package builds and exposes its namespace")
    func namespaceExists() {
        #expect(SwiftIdentity.self == SwiftIdentity.self)
    }
}
