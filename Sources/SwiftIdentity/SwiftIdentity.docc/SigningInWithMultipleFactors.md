# Signing in with several factors

A passphrase and a code from an authenticator app, proving one subject.

## Overview

``Authenticator`` takes every credential presented together, resolves each through the first
store that recognizes it, and requires them all to prove the same subject. The strength of the
result is computed: two distinct factor classes are multi-factor; one of them phishing-resistant,
a passkey, say, makes it phishing-resistant. Two passphrases are still single-factor.

## Enrolling an authenticator app

A one-time-code key is the one secret here that can't be hashed, because the verifier recomputes
codes from it. So it's sealed under a ``SealingKey`` held in a separate file, and bound to its
subject. The enrollment URI carries the key in the clear: show it once, as a QR code, and never
store it.

```swift
import Foundation
import SwiftIdentity

let directory = FileManager.default.temporaryDirectory.appendingPathComponent("enrol-\(UUID().uuidString)")
try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
let sealingURL = directory.appendingPathComponent("totp-sealing.key")

var generator = SystemRandomNumberGenerator()
try SealingKey.create(at: sealingURL, using: &generator)
let sealingKey = try SealingKey(contentsOf: sealingURL)

let verifier = try OneTimeCodeVerifier(for: "ada", using: &generator, sealingKey: sealingKey)
let uri = try verifier.enrollmentURI(issuer: "Household Vault", account: "ada", sealingKey: sealingKey)
// Show `uri` as a QR code, ask for one code back, and only then store `verifier.encoded`
// as a `totp` line in the verifiers file.
print(uri.hasPrefix("otpauth://totp/"))
```

## Verifying both

The file store reads `totp` lines when it's given the sealing key and a throttle, and refuses to
start without them: NIST requires each code to be accepted only once (§3.1.4.2) and failures to
be limited, and the throttle's ledger is where both are kept.

The shape of a sign-in, given a `store` built from the deployment's files:

```
let throttle = FailureThrottle(ledger: try FileThrottleLedger(url: ledgerURL))
let store = try FileCredentialStore(directory: path, throttle: throttle, sealingKey: sealingKey)
let authenticator = Authenticator(stores: [store], audit: audit, now: { Date() }, throttle: throttle)

if let signedIn = await authenticator.authentication(for: [
    Passphrase(subjectID: "ada", secret: typedPassphrase),
    OneTimeCode(subjectID: "ada", code: typedCode),
]) {
    // signedIn.assurance == .multiFactor
}
```

What a caller gets is an ``Authentication`` or nothing: the reason for a refusal goes to the
audit, never back to whoever is guessing. A code is consumed by its step, so a code once used, or
an earlier one, is refused everywhere the ledger is shared. A passphrase and a code presented
together are throttled together: when one reaches the ceiling in that attempt, both are disabled.
