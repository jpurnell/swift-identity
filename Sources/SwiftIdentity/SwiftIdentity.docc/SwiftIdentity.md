# ``SwiftIdentity``

Who is asking, and are they still allowed to be here?

## Overview

A name in a record is only worth what the system did to verify it. SwiftIdentity holds
**subjects** — the people and services a system knows — and the **credentials** that prove
them, so that `decisionOwner`, `completed_by`, and "which customer is this" stop being strings
somebody typed.

### Identity, not entitlement

This package answers *who*, and whether they may be here at all. What a subject may **do** — a
tier, a plan, a decision role — stays with the consumer. A family vault's tiers and a commercial
plan are the same shape only by coincidence, and a package that understood both would be
answering to whichever paid more.

### Not every client has a browser

A shared speaker cannot follow a redirect. A calendar client cannot send an `Authorization`
header at all. Those are permanent properties of those clients, not gaps to close later — so a
capability URL, a bearer key, and an OAuth login must resolve to the *same* subject, or identity
is only true on the web.

### How strongly, not only who

One credential proves a subject; several can prove it more strongly. ``Authenticator`` requires
every credential presented together to prove the same subject, and computes the ``Assurance``
from the factor classes that did — never from what a caller claims. Passphrases follow NIST SP
800-63B-4, verified against the published text, and one-time codes from an authenticator app make
"passphrase plus a code" multi-factor anywhere, a terminal included.

## Topics

### Articles

- <doc:PassphraseStandards>
- <doc:SigningInWithMultipleFactors>
- <doc:ExtendingSwiftIdentity>
- <doc:ThreatModel>

### Subjects

- ``Subject``
- ``ExternalIdentity``

### Credentials

- ``Credential``
- ``BearerKey``
- ``CapabilityToken``
- ``Passphrase``
- ``SessionToken``
- ``ExternalAssertion``
- ``OneTimeCode``
- ``FactorClass``

### Resolving credentials

- ``CredentialStore``
- ``Resolution``
- ``FileCredentialStore``
- ``SessionStore``
- ``MintedSession``
- ``ThrottlingCredentialStore``

### Several factors

- ``Authenticator``
- ``Authentication``
- ``AuthenticationResolution``
- ``Assurance``
- ``VerifiedFactor``

### Passphrases

- ``PassphraseVerifier``
- ``PassphraseCanonicalization``
- ``PassphraseScheme``
- ``PassphraseSchemes``
- ``PBKDF2SHA256C1``
- ``PBKDF2SHA256Legacy``
- ``Argon2idC1``
- ``Argon2id``
- ``Pepper``
- ``PepperedScheme``

### Choosing a passphrase

- ``PassphrasePolicy``
- ``PolicyContext``
- ``PassphraseGuidance``
- ``PassphraseBlocklist``
- ``BlocklistReason``
- ``BlocklistFailure``
- ``CommonPasswords``
- ``BundledCommonPasswords``
- ``ContextWords``
- ``BreachedPasswordRange``

### One-time codes

- ``OneTimeCodeParameters``
- ``OneTimeCodeVerifier``
- ``SealingKey``
- ``KeyFileFailure``

### Throttling

- ``FailureThrottle``
- ``ThrottlePolicy``
- ``ThrottleLedger``
- ``ThrottleKey``
- ``ThrottleState``
- ``ThrottleLedgerError``
- ``InMemoryThrottleLedger``
- ``FileThrottleLedger``
- ``ThrottleLedgerService``
- ``RemoteThrottleLedger``
- ``LedgerRequest``
- ``LedgerResponse``

### Audit

- ``IdentityAudit``
- ``IdentityEvent``

### Primitives

- ``ConstantTime``
- ``Hex``
- ``SwiftIdentity``
