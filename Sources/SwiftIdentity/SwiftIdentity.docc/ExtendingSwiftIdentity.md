# Extending SwiftIdentity

Where a deployment supplies its own piece, and the bar that piece must clear.

## Overview

The package is open where a deployment has to choose, and closed where the answer is a security
property. The open points are protocols: ``Credential``, ``CredentialStore``, ``IdentityAudit``,
``PassphraseScheme``, ``PassphraseBlocklist`` and ``ThrottleLedger``. The closed ones are sets:
``Resolution``, ``IdentityEvent/Outcome`` and a subject's status, because a conformer that could
invent an outcome could invent one that leaks.

## A credential store

A store implements one requirement, ``CredentialStore/resolve(_:)``, and may report the algorithm
it verified with through ``CredentialStore/resolveVerifying(_:)``. It must pass the
`SwiftIdentityConformance` suite unchanged: kinds never cross, every refusal looks the same to a
caller, a honeypot is reported to the service. Claim the capabilities you offer; claiming one
without the fixture that tests it is inconclusive, never a pass.

## A passphrase scheme

A ``PassphraseScheme`` derives bytes; it never compares them, so a scheme from outside can't skip
the constant-time comparison. Give it an identifier no other derivation will ever use, decide its
canonicalization, and validate its stored parameters strictly. List it in a ``PassphraseSchemes``
you pass in; nothing is global.

```swift
import SwiftIdentity

let schemes = PassphraseSchemes([PBKDF2SHA256Legacy(), PBKDF2SHA256C1()], writing: PBKDF2SHA256C1())
print(schemes.accepts("pbkdf2-sha256-c1"), schemes.accepts("argon2id-c1"))
// true false
```

## A throttle ledger

A ``ThrottleLedger`` remembers; the throttle decides. Every operation must be atomic across every
handle on the same ledger, a disabled key must stay disabled until rebound, and a ledger that
can't answer must throw, never report a clear state. `ThrottleLedgerConformance` checks all of it
black-box, including a burst of concurrent attempts one below the ceiling admitting exactly one,
and, for a ledger that claims to persist, surviving a new handle. The in-memory, file and remote
ledgers here all pass it.
