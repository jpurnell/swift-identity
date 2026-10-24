# Passphrase standards

What NIST SP 800-63B-4 requires of a passphrase, and where each requirement lives here.

## Overview

The rules come from **NIST SP 800-63B-4, the July 2025 edition**, checked sentence by sentence
against the published PDF (SHA-256 `d9ab8957…0afd`) rather than recalled. Three things the design
had from memory turned out wrong when it was checked, and the corrections are why this article
is careful to quote:

- Normalization is **NFC**, not NFKC.
- At the failure ceiling the passphrase is **disabled until a new one is issued**; there's no
  unlock.
- NIST names **SP 800-132 password hashing, which is PBKDF2**, and prefers nothing memory-hard.

The requirements file the tests cite is `Tests/SwiftIdentityTests/Requirements/NIST-SP-800-63B-4.md`.
A test cites a row by starting its name with the row's ID, and a test fails if an implemented row
has no citing test.

## No composition rules, and every password manager welcome

§3.1.1.2 forbids composition rules: "Verifiers and CSPs SHALL NOT impose other composition rules
(e.g., requiring mixtures of different character types)". So ``PassphrasePolicy`` can't express
one, and whatever a password manager generates is accepted: every printing character, spaces,
any language, emoji. The motivating failure was a real site rejecting Apple Passwords' output
because it allow-listed "special characters".

What matters is **length**: at least 15 code points as the only factor, at least 8 when the
passphrase is always used with another factor, at most 256. Code points, not characters as a
person sees them: NIST says "each Unicode code point SHALL be counted as a single character".

## Normalization

"é" can arrive as one code point or two, and a password manager on one device and a keyboard on
another may disagree. ``PassphraseCanonicalization`` applies the process §3.1.1.2 names, UAX #15's
normalization for stabilized strings with NFC:

1. A code point unassigned in Unicode 15.0 is refused, so no later Unicode can change how an
   accepted passphrase normalizes.
2. Control characters are refused, never stripped.
3. NFC. Fullwidth letters and no-break spaces stay what they are: that's the difference between
   NFC and NFKC.

It's checked against all 19,074 cases of Unicode's conformance file and 20,000 seeded cases from
CPython, which together caught Foundation's one-step NFC failing to compose a Hangul syllable with
a trailing consonant.

New digests are written under `pbkdf2-sha256-c1`. Digests 0.6 wrote, `pbkdf2-sha256`, keep
verifying byte for byte, and ``PassphraseVerifier/needsUpgrade(to:)`` says which to re-derive.

## Blocklists, with the reason

When a passphrase is chosen, it's compared, whole, against common passwords (SecLists' 10,000,
bundled), the subject's and service's names and their derivatives, and optionally a breach corpus
(``BreachedPasswordRange``, which sends only a 5-character hash prefix). NIST requires the reason
for a rejection to be given, so ``PassphrasePolicy/evaluate(_:context:)`` names every violation.
That's issuance; a sign-in refusal still says nothing.

```swift
import SwiftIdentity

let policy = PassphrasePolicy.nist80063B4
let violations = await policy.evaluate("password1", context: PolicyContext(subjectID: "ada", serviceName: "vault"))
// [.tooShort(minimum: 15, actual: 9), .blocklisted(.common)]
for violation in violations {
    print(policy.guidance.after(violation))
}
```

## Profiles

| Profile | Use | Derivation |
|---|---|---|
| ``PassphrasePolicy/nist80063B4`` | The default | PBKDF2-HMAC-SHA256, 600,000 rounds |
| ``PassphrasePolicy/fips`` | FIPS-approved algorithms only | PBKDF2 |
| ``PassphrasePolicy/owasp`` | OWASP's first choice; **not on NIST's list** | Argon2id, 19 MiB, 2 passes |
| ``PassphrasePolicy/pciDSS4`` | PCI deployments only; **not recommended under NIST** | PBKDF2 |

**On FIPS:** the profile uses only approved algorithms. That doesn't make a deployment FIPS
validated, which needs a CMVP-validated module in approved mode.

**On PCI:** PCI DSS 4.0.1 §8.3.6 requires 12 characters including a letter and a digit, which is a
composition rule. It's offered because PCI requires it, and only through that profile. Its
lockout and 90-day change rules are left to ``ThrottlePolicy`` and the deployment, against PCI's
own text.

**On Argon2id:** it's written here in pure Swift, and passed its gate before any profile could
select it: RFC 9106's vector and every intermediate word, then seeded differential runs against
OpenSSL, phc-winner-argon2 and argon2-swift, and a release build within 1.5× of the C reference.

## The failure ceiling

§3.2.2: no more than 100 consecutive failures per authenticator, "by disabling that
authenticator", which "SHALL be required to rebind". So a ``FailureThrottle`` with a persisted
``FileThrottleLedger`` backs off from the fifth failure and disables at the hundredth. Issuing a
new passphrase rebinds it, because the throttle key is derived from the passphrase's salt. Each
attempt is counted before it's checked, so a burst of guesses at 99 failures verifies exactly one.
Authenticators presented together are disabled together. Across hosts, ``ThrottleLedgerService``
shares the count.

The trade is stated, not hidden: anyone who knows a subject ID can disable that subject's
passphrase with 100 slowed guesses. The backoff makes that take a long time, and the audit trail's
`throttled` outcome makes it visible.

## Optional: a pepper

``PepperedScheme`` adds §3.1.1.2's keyed pass, with a ``Pepper`` kept in its own file, so a copy
of the verifiers file alone is useless to a guesser. It's not hardware-protected here; NIST
recommends that it be, where a deployment can.
