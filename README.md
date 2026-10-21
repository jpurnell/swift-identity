# SwiftIdentity

**Who is asking, and are they still allowed to be here?**

Subjects — the people and services a system knows — and the credentials that prove them. So
that a name in a record is something the system verified, rather than something a caller typed.

```
Subject          who: a stable id, a kind, a status, consumer-defined attributes
Credential       the proof: bearer · capability · passphrase · session · oauth subject
CredentialStore  a protocol; verification is constant-time and fails closed
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

**0.6.3: implemented and in use**, pre-1.0. `Subject`, the credential kinds above, `FileCredentialStore`,
`SessionStore`, `FailureThrottle`, `IdentityAudit`, and `SwiftIdentityConformance`, the suite any
store must pass unchanged, checked against nine deliberately broken stores. 105 tests. Its first
adopter outside this package is SwiftWebAuthn's `SwiftWebAuthnIdentity` product.

Being designed next: several credentials proving one subject (multi-factor), and passphrases to
NIST SP 800-63B-4.

## Requirements

Swift 6.2+. The tools-version is deliberately below the newest toolchain: the intended first
consumer deploys to a host running 6.3.3.

## License

MIT — see [LICENSE](LICENSE).
