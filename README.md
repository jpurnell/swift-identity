# SwiftIdentity

**Who is asking, and are they still allowed to be here?**

Subjects — the people and services a system knows — and the credentials that prove them. So
that a name in a record is something the system verified, rather than something a caller typed.

```
Subject          who: a stable id, a kind, a status, consumer-defined attributes
Credential       the proof: bearer · capability · passphrase · one-time code · session · oauth subject
CredentialStore  a protocol; verification is constant-time and fails closed
Authenticator    several credentials, one subject, and how strongly it was proven
```

## Why this exists

The same hole turned up in four services at once. A decision log recording its owner as a
free-text `String`. A vault that could not say who completed a job, because every request
arrived on one shared token. A service intended to be commercial that could not revoke one
customer without revoking all of them. A guidelines server that could not tell organisations
apart.

The first design solved it inside one of those services. That was the wrong level, and its own
adversarial review said so.

## What it is not

**Not an OAuth library.** [SwiftOAuth](https://github.com/jpurnell/swift-oauth) is that, and
should stay spec-shaped. What OAuth does not model is the subject that outlives any one token —
and an authorization flow that never authenticates a person records which *application* asked,
never who.

**Not an entitlement system.** What a subject may *do* belongs to the consumer. Tiers, plans and
decision roles are the same shape only by coincidence.

**Not browser-only.** A shared speaker cannot follow a redirect; a calendar client cannot send
an `Authorization` header. A capability URL, a bearer key and an OAuth login must resolve to the
same subject, or identity is only true on the web.

## Status

**0.7.0**, pre-1.0, in use. On top of 0.6's subjects, credentials, stores, sessions, audit and
conformance suite:

- **Several factors.** `Authenticator` requires every credential presented together to prove one
  subject, and computes the assurance (single-factor, multi-factor, phishing-resistant) from the
  factor classes that did. One-time codes from an authenticator app (RFC 6238), with keys sealed
  at rest, make "passphrase plus a code" multi-factor anywhere, a terminal included.
- **Passphrases to NIST SP 800-63B-4**, checked against the published text: NFC normalization,
  length in code points, no composition rules, blocklists that give their reason, guidance,
  and a persisted 100-failure ceiling that disables until a new passphrase is issued, shared
  across processes and hosts. Profiles for NIST (the default), FIPS, OWASP (Argon2id, written here
  in pure Swift) and PCI DSS (which needs a composition rule NIST forbids, so it's PCI only).
- **Algorithm records**, so a deployment can find every classical credential later.

See the DocC articles *Passphrase standards*, *Signing in with several factors*, *Extending
SwiftIdentity* and *Threat model*.

## Requirements

Swift 6.2+ (tools-version 6.2), macOS 14, iOS 17 or visionOS 1. No C dependencies; swift-crypto
is the one runtime dependency.

## License

MIT — see [LICENSE](LICENSE).
