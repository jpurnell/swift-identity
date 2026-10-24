# Threat model

What this package defends against, what it leaves to its consumer, and what it won't claim.

## Overview

The package resolves credentials to subjects. It does not authorize, render sign-in screens or
open sockets. Its defenses are the ones a resolver can own.

## Guessing

Only a passphrase, and a one-time code, can be guessed. Everything else is at least 128 bits of
machine randomness and isn't throttled, because throttling it would defend nothing and hand out a
way to deny service. Passphrases cost hundreds of thousands of PBKDF2 rounds each; both kinds are
counted before they're checked, back off, and are disabled at 100 consecutive failures, persisted
and shared across processes and hosts. A refusal costs the same work whether or not the claimed
subject has a passphrase, so timing doesn't say who does.

## Factors

Assurance is computed from the factor classes of credentials that resolved to one subject, never
declared by a caller, because a declaration is the first thing an attacker would forge. Two valid
credentials for two different subjects, presented together, are refused and audited as
`subjectMismatch`: that's an attack signal, not an accident.

## Secrets at rest

Every stored secret is a digest except one: a one-time-code key, which the verifier needs whole.
It's sealed with AES-256-GCM under a ``SealingKey`` in a separate file and bound to its subject,
so the verifiers file alone discloses nothing. An optional ``Pepper`` does the same for
passphrase digests.

## A shared ledger is a single point of failure, on purpose

If the ledger host is unreachable, passphrase and one-time-code sign-ins on every other host are
refused. A ledger that failed open would be the first thing an attacker knocked over.

## Quantum posture

Symmetric secrets and digests are quantum-resistant: Grover's search only square-roots the work.
Signature credentials (ES256 passkeys, IdP tokens) are classical and could be forged by a large
quantum computer at sign-in time. This package **never calls a sign-in quantum-safe**: a sign-in is
as strong as its weakest link, and the transport isn't visible from here. What it does is record,
for every verification, the algorithm the store verified with, so a deployment can find every
classical credential and require something else when it decides to.
