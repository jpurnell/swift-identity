import Testing
@testable import SwiftIdentity

/// What mutation testing found the policy tests didn't pin down.
///
/// Each test here was written against a mutant that survived the existing suites
/// (`Harness/Mutation/REPORT.md`): it fails with that mutant applied and passes without it.
extension PassphrasePolicyTests {

    @Test("exactly 1 KiB is looked at; the byte cap refuses only what's over it")
    func byteCapIsInclusive() async {
        let policy = Self.policy()
        // 256 four-byte scalars: 1,024 bytes and 256 code points, at both limits and over neither.
        let atCap = String(repeating: "\u{1F600}", count: 256)
        #expect(atCap.utf8.count == policy.maximumInputBytes)
        #expect(await policy.evaluate(atCap, context: Self.context) == [])
        #expect(await policy.evaluate(atCap + "a", context: Self.context) == [.tooManyBytes(maximum: 1_024)])
    }

    @Test("context words, asked without a context, contain nothing")
    func contextWordsWithoutAContext() async {
        #expect(!(await ContextWords().contains("ada")))
        #expect(!(await ContextWords().contains("")))
        // With one, the same word is refused: the no-context answer is about the context.
        #expect(await ContextWords().contains("ada", context: Self.context))
    }

    @Test("the PCI profile's composition rule comes straight after the length rule")
    func pciGuidanceOrder() {
        let nist = PassphrasePolicy.nist80063B4.guidance.lines
        let pci = PassphrasePolicy.pciDSS4.guidance.lines
        guard nist.count >= 2, pci.count == nist.count + 1 else {
            Issue.record("expected PCI guidance to be NIST's plus one line; got \(pci.count) and \(nist.count)")
            return
        }
        #expect(pci[0].contains("12"))
        #expect(pci[1].localizedCaseInsensitiveContains("digit"))
        #expect(Array(pci[2...]) == Array(nist[1...]))
    }
}
