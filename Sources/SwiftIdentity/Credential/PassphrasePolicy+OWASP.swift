extension PassphrasePolicy {

    /// NIST SP 800-63B-4's rules, with Argon2id as the derivation. Opt-in; not the default.
    ///
    /// **OWASP's first choice, and not on NIST's list.** OWASP's Password Storage Cheat Sheet
    /// recommends Argon2id first, and this profile writes it at OWASP's recommended minimum:
    /// m=19456 KiB (19 MiB), t=2, p=1, as ``Argon2idC1`` (`argon2id-c1`). NIST SP 800-63B-4
    /// §3.1.1.2 asks instead for "an approved password hashing scheme published in the latest
    /// revision of [SP800-132]", which is PBKDF2. So a deployment on this profile has left
    /// NIST's list for the derivation, and knows it.
    ///
    /// **Never part of ``nist80063B4`` or ``fips``,** and the default stays PBKDF2-HMAC-SHA256
    /// at 600,000 rounds. ``PassphraseSchemes/standard`` doesn't accept `argon2id-c1` at all. A
    /// deployment that wants NIST conformance, or FIPS-approved algorithms, stays on those.
    ///
    /// Everything else is ``nist80063B4``'s: a sole factor of at least 15 characters, at most
    /// 256, a 1 KiB byte cap, the bundled common-password list and the context words. It accepts
    /// `pbkdf2-sha256`, `pbkdf2-sha256-c1` and `argon2id-c1`, so digests written under the other
    /// profiles keep verifying, and ``PassphraseVerifier/needsUpgrade(to:)`` re-derives them under
    /// Argon2id at the next successful sign-in.
    ///
    /// Shipped once the amendment's gate passed (§9): the RFC 9106 vector, differential cases
    /// from OpenSSL, phc-winner-argon2 and argon2-swift, timing within 2× of the reference at
    /// deployment parameters, and memory bounded as configured.
    ///
    /// ```swift
    /// let policy = PassphrasePolicy.owasp
    /// var generator = SystemRandomNumberGenerator()
    /// let verifier = try PassphraseVerifier(
    ///     for: Passphrase(subjectID: "ada", secret: "correct horse battery staple"),
    ///     using: &generator, parameters: policy.parameters, schemes: policy.schemes
    /// )
    /// ```
    public static let owasp = PassphrasePolicy(
        factorRole: .sole, maximumLength: 256, maximumInputBytes: 1_024,
        blocklists: [BundledCommonPasswords(), ContextWords()],
        schemes: PassphraseSchemes(
            [PBKDF2SHA256Legacy(), PBKDF2SHA256C1(), Argon2idC1()], writing: Argon2idC1()
        ),
        parameters: Argon2idC1.owaspMinimumParameters
    )
}
