# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet.

## [0.7.0] — 2026-10-23

The assurance and passphrase amendment (`AssuranceFactorsAndStandardPassphrases.md`, approved
2026-10-22, revision 4): several factors proving one subject, passphrases to NIST SP 800-63B-4
as published, one-time codes, and a failure ceiling shared across processes and hosts. 372 tests.

### Added

- **`PassphraseCanonicalization`**: NIST SP 800-63B-4's normalization, the stabilized-strings
  process of UAX #15 §12.1 with NFC. Code points unassigned in Unicode 15.0 (the pin) and control
  characters are refused, by position, never stripped. No case mapping, no trimming. Checked
  against all 19,074 cases of Unicode's `NormalizationTest.txt` for 15.0 and 20,000 seeded cases
  from CPython's `unicodedata`.
- **`PassphraseScheme`, `PassphraseSchemes`, `PBKDF2SHA256C1`, `PBKDF2SHA256Legacy`**: digests
  are versioned by scheme, and a deployment can add its own. A scheme derives; the constant-time
  comparison stays in `PassphraseVerifier`.
- **`PassphrasePolicy`**, with the `nist80063B4` and `fips` profiles: NIST SP 800-63B-4's rules for
  choosing a passphrase, applied at issuance only. 15 code points as a sole factor, 8 as part of
  multi-factor, at most 256; a 1 KiB byte cap checked before anything else; every violation named,
  including which blocklist refused it (NIST requires the reason). No composition rule can be
  expressed. `guidance` gives the advice NIST requires verifiers to offer, and `after(_:)` the advice
  for a particular rejection.
- **`PassphrasePolicy.pciDSS4`**: PCI DSS 4.0.1 §8.3.6, at least 12 characters with both a letter
  and a digit (any script). **For PCI deployments only, and not recommended under NIST SP
  800-63B-4**, which forbids composition rules. `appliesPCIComposition` is read-only, so no NIST or
  FIPS profile can be made to apply it; the new violation `.pciRequiresLettersAndDigits` is only
  ever reported by this profile. Lockout (§8.3.4) and 90-day change (§8.3.9) are left to
  `ThrottlePolicy` and the deployment, against the standard's own text.
- **Blocklists:** `PassphraseBlocklist` (whole-password comparison, may throw), `ContextWords` (the
  subject's and service's names and their derivatives), `CommonPasswords` and
  `BundledCommonPasswords`: SecLists' 10,000 most common passwords, MIT licensed, imported by
  `scripts/import-common-passwords.py` with provenance in `Resources/COMMON-PASSWORDS.md`. A
  blocklist that can't answer refuses the passphrase (`blocklistUnavailable`) rather than being
  skipped. `foldsCompatibilityForBlocklist` optionally also compares an NFKC-folded copy.
- **`BreachedPasswordRange`**: passwords "obtained from previous breach corpuses" (800-63B-4
  §3.1.1.2), by k-anonymity range lookup over Have I Been Pwned's Pwned Passwords API or a
  compatible service. SHA-1 of the canonical passphrase (the protocol's choice); only the 5-hex
  prefix is sent, the 35-hex suffix is matched locally, and `Add-Padding: true` is requested, with
  count-0 padding never a match. `minimumCount` sets the fewest sightings. The transport is
  injected; `urlSession(timeout:)` requires a timeout. A non-200 status, a malformed line, a body
  over 2 MiB or a transport error throws, so the policy refuses as `blocklistUnavailable(.breached)`;
  `failsOpen` is the documented opt-in alternative. Off by default: neither profile includes it.
- **Factors and assurance:** `FactorClass` (knowledge, possession, inherence), declared per
  credential kind through `Credential.factorClass` and `isPhishingResistant`, both requirements
  with defaults; `Assurance` (single-factor, multi-factor, phishing-resistant), always computed;
  `VerifiedFactor`, `Authentication`, `AuthenticationResolution`.
- **`Authenticator`**: resolves several credentials through the first store that recognizes each,
  requires one subject, and computes assurance. `authentication(for:)` is the caller's view, an
  `Authentication` or nil.
- **`CredentialStore.resolveVerifying(_:)`**: a requirement with a default that reports the
  algorithm a store verified with. Every existing store compiles unchanged and reports none.
- **`IdentityEvent.algorithm`**, optional, defaulting to nil.
- **One-time codes (RFC 6238 TOTP):** `OneTimeCode` (possession, not phishing-resistant),
  `OneTimeCodeParameters` (HMAC-SHA-1, 6 digits, 30 s by default; SHA-256/512 and 8 digits
  selectable; recorded as `totp-sha1-6-30`), and `OneTimeCodeVerifier`: a 160-bit key from the
  caller's generator, sealed at rest under a `SealingKey` (AES-256-GCM, a 32-byte owner-only file
  held apart from the store) and bound to its subject. `matchingStep(_:at:sealingKey:window:)`
  checks ±1 step in constant time; `enrollmentURI(issuer:account:sealingKey:)` is the
  `otpauth://` URI an app scans. Checked against RFC 6238 Appendix B (all 18 vectors) and RFC
  4648 §10 (Base32), imported by `import-totp.py`. Accepting each code once, and the failure
  ceiling, arrive with the ledger.
- **Conformance:** two requirements, `canonicallyEquivalentPassphrasesMatch` and
  `algorithmIsReported`, with capabilities `.canonicalPassphrases` and `.algorithmRecords` (both
  in `.all`) and fixtures `canonicalPassphrase` and `ActiveSubject.algorithm`. A capability
  claimed without its fixture is inconclusive, so it can't pass by omission. Each requirement has
  a mutant the suite is shown to catch. `ReferenceCredentialStore` canonicalizes passphrases and
  reports `reference-sha256`.
- **`FileCredentialStore` verifies one-time codes**: `totp` lines in the verifiers file, opened
  with a `sealingKey:` given at init. Each attempt is counted before it's checked, a matching
  code is accepted only if its step is later than the last one used (`ThrottleLedger.consume`,
  through the new `FailureThrottle.consume(step:for:)`, which fails closed), and the app is
  disabled at the ceiling under its own `ThrottleKey.oneTimeCode(subjectID:verifiers:)`, so
  enrolling a new app rebinds it. Startup-fatal: `totp` lines with no sealing key, no throttle,
  a sealing key that doesn't open a line (named), or a malformed line.
- **`FileCredentialStore.resolveVerifying(_:)`** reports what it verified with, from the record:
  the passphrase scheme, the one-time-code parameters, or `sha256`. Every audit event for a
  verification carries it.
- **Authenticators presented together are disabled together** (NIST SP 800-63B-4 §3.2.2):
  `Authenticator(…, throttle:)` checks every credential in a set, so each throttled one is counted,
  and when any is disabled it disables all of them through `FailureThrottle.disableTogether(_:)`
  (a new `ThrottleLedger` requirement, atomic in both ledgers; it fails closed). Stores say which
  key a credential counts under through `ThrottlingCredentialStore`, which `FileCredentialStore`
  adopts. `FailureThrottle.state(_:)` reads a key's state.
- **`ThrottleLedgerConformance`**, in `SwiftIdentityConformance`: the bar any `ThrottleLedger` must
  clear, black-box. Eleven requirements: counted before checked, backoff refuses uncounted, the
  ceiling disables and stays disabled until rebound, a burst one below the ceiling admits exactly
  one, concurrent attempts on two handles lose no count, one-time-code steps are a high-water
  mark, disabling together, and (for a `.persistent` ledger) surviving a new handle. Both shipped
  ledgers pass; each requirement has a broken ledger it is shown to catch.
- **`ThrottleLedgerService` and `RemoteThrottleLedger`**: one host keeps the ledger and the others
  reach it over HTTPS, so the ceiling is shared across hosts. The service is mounted by the
  consumer's server (no socket here; TLS required), resolves each host's `BearerKey` on every
  request (revocation is immediate), rate-limits per client, caps bodies (64 KiB), subject IDs,
  authenticator names and keys per request, and refuses a time more than `maximumClockSkew`
  (default 5 minutes) from its own clock. The remote ledger throws on any failure, so an
  unreachable ledger host fails closed. It passes `ThrottleLedgerConformance`, over memory and
  over a file ledger with restarts. `RemoteThrottleLedger.urlSession(url:key:timeout:)` requires
  a positive timeout.
- **`FileCredentialStore(…, schemes:)`**: the passphrase schemes a deployment accepts. Without
  it, a deployment on the `owasp` profile would have written `argon2id-c1` lines its own store
  refused at startup.
- **`Pepper` and `PepperedScheme`** (P15): a verifier-only secret key, from the caller's generator,
  in its own owner-only file, applied as HMAC-SHA-256 over any scheme's output. The identifier is
  the base's plus `+p<fingerprint>`, so a digest names the pepper it needs and adding or rotating
  one is reported by `needsUpgrade`. Not hardware-protected: a file, on every platform.
- **`KeyFileFailure`**: the 32-byte, owner-only, never-overwritten rules the sealing key and the
  pepper share. `SealingKey.Failure` is now an alias for it.
- **`PassphraseVerifier.needsUpgrade(to:)`**, `scheme` and `parameters`, and
  `init(for:using:parameters:schemes:)` / `init?(encoded:schemes:)`.
- **`ThrottleLedger`, `ThrottleKey`, `ThrottleState`, `InMemoryThrottleLedger`,
  `FileThrottleLedger`** (P13, P22): where `FailureThrottle` keeps its counts, keyed by subject
  *and* authenticator. `FileThrottleLedger` is one owner-only file per host, every operation a
  read-modify-rename under an `flock(2)` on a companion lock file, so every process on the host
  shares one count; tested with two real processes racing. A permissive or unparseable ledger is
  startup-fatal, like `FileCredentialStore`'s files. It writes only when the state changes.
- **NIST's ceiling** (P13): `ThrottlePolicy.ceiling`, default 100, validated to `1...100` by a
  new throwing `init(threshold:backoff:ceiling:)`. At the ceiling the authenticator is
  disabled, and stays disabled through backoff expiry, successes and restarts, until rebound.
  `FailureThrottle.recordFailure(involving:)` and `ThrottleLedger.recordFailure(involving:at:)`
  disable every authenticator an attempt involved when one reaches it.
- **`ThrottleKey.passphrase(subjectID:verifiers:)`**: a passphrase's key is derived from its
  verifiers' salts, so issuing a new passphrase rebinds it with no ledger step to remember.
  `ThrottleLedger.rebound(_:)` stays for explicit administrative use, and
  `FileCredentialStore.throttleKey(forPassphraseOf:)` says which key to rebind.
- **`ThrottleLedger.consume(step:for:)`**: an atomic high-water mark for one-time code steps,
  a protocol requirement rather than a defaulted extension.
- **`ThrottleLedger.beginAttempt(_:at:)` and `FailureThrottle.beginAttempt(_:)`** (P13): an
  attempt is refused, or counted as a failure, in one atomic step *before* it is checked; only a
  match is reported afterwards, with `recordSuccess`. Checking and then recording left the
  derivation between two ledger operations, so a burst of guesses at 99 failures all passed the
  check; now exactly one is admitted. A ledger write per admitted attempt, one more for a
  success, none for a refusal.
- `FailureThrottle.init(ledger:now:)` and key-based `shouldRefuse(_:)`, `recordFailure(_:)`,
  `recordSuccess(_:)`.
- **`Argon2id`**: RFC 9106 Argon2id (version 0x13) in pure Swift, on a pure-Swift BLAKE2b
  (internal; swift-crypto has none). Lanes, four sync points, secret and associated data.
  Parameters below RFC 9106's minimums or above the declared caps (1 GiB, 32 passes, 16 lanes)
  are refused by name before any memory is allocated. Matches the RFC 9106 §5.3 tag and the
  memory words it prints after each pass, and 64 seeded differential cases from OpenSSL's
  independent `ARGON2ID` KDF (`Harness/Argon2id/`, never a dependency). BLAKE2b is checked
  against RFC 7693 Appendix A and the official BLAKE2 known answers.
- **`Argon2idC1`**: the `argon2id-c1` scheme, Argon2id over the canonical secret with parameters
  stored as `m=<KiB>,t=<passes>,p=<lanes>`. **Not in `PassphraseSchemes.standard`**, which still
  refuses it. `isBelowCurrentCost` compares against OWASP's minimum, so a digest with m < 19456
  KiB or t < 2, or parameters that don't decode, is re-derived at the next sign-in.
- **The amendment's Argon2id gate (§9) passes.** Beyond the RFC 9106 vector and the 64 OpenSSL
  cases:
  - **phc-winner-argon2**, the reference, through its `argon2` CLI (Homebrew 20190702_1):
    `Harness/Argon2id/generate-phc.py` refuses to run unless the CLI first reproduces all 24
    OpenSSL cases it can express, then writes 52 seeded cases, 2 each at m=19456 t=2 p=1 and
    m=65536 t=3 p=4. All 52 match (`argon2id-phc-winner-argon2.txt`).
  - **`mimiclone/argon2-swift`**, pure Swift with its own BLAKE2b, wrapping no C: built by its
    own harness package, `Harness/Argon2idSwift`, pinned to revision `0f6581ee` (v1.0.4) and
    never a dependency. It must reproduce RFC 9106 §5.3 first; then 52 seeded cases, secrets and
    associated data among them, 2 each at the same deployment parameters. All 52 match
    (`argon2id-argon2-swift.txt`).
  - **Timing within 2× of the reference**, release build, CPU time, on an M1 Max under heavy
    load: 1.45× at m=19456 t=2 p=1 (36.3 ms against 25.0 ms) and 1.38× at m=65536 t=3 p=4
    (194.8 ms against 141.0 ms). `Harness/Argon2idTiming` measures it; `Harness/Argon2id/TIMING.md`
    records the machine, date and method. Measured on arm64 only; the deploy host is x86_64.
- **`PassphrasePolicy.owasp`**: NIST SP 800-63B-4's rules, every one the same as `nist80063B4`'s,
  with the derivation `argon2id-c1` at OWASP's recommended minimum, m=19456 KiB, t=2, p=1. It
  accepts `pbkdf2-sha256`, `pbkdf2-sha256-c1` and `argon2id-c1`, so existing digests verify and
  upgrade. Opt-in: OWASP's first choice, not on NIST's list (800-63B-4 names SP 800-132, which is
  PBKDF2). Never part of `nist80063B4` or `fips`, and **PBKDF2 stays the default.**

### Testing

- **Mutation testing**, by a harness written here (`Harness/Mutation/`, stdlib Python, seeded): up
  to 25 mutants per file across the verifier, schemes, canonicalization, Authenticator, ledgers,
  Argon2id, BLAKE2b, one-time codes and policy. Of 54 survivors, 32 were test gaps, now closed
  (among them: `PassphraseVerifier.==` had no test; a throttle key that hashed only the salt's
  length would have let a reissued passphrase inherit the old count; the ledger's entry limit
  was untested); 18 are equivalent and 4 need fault injection, each explained in `REPORT.md`.
  No product bug.

### Documentation

- Articles: **Passphrase standards** (each NIST rule and where it lives, the profiles, the
  corrections the published text forced), **Signing in with several factors** (enrolling an app,
  verifying a passphrase and a code), **Extending SwiftIdentity** (what a store, scheme or ledger
  must pass), and **Threat model** (guessing, factors, secrets at rest, the shared ledger, quantum
  posture). The catalogue's front page said "Nothing is implemented yet" through six releases; it
  now organizes every public type.

### Changed

- **iOS 17 and visionOS 1 are declared platforms**, beside macOS 14, to match SwiftCLIKit. Both
  were built before being declared.

- **New passphrase digests are `pbkdf2-sha256-c1`**, over the canonical secret, so "é" typed as
  one code point or two matches either way. Existing `pbkdf2-sha256` digests keep verifying,
  byte for byte as before, and are never written again.
- **An unknown scheme fails closed**: the stored value doesn't decode, which the file store
  already treats as startup-fatal.
- **`PassphraseVerifier.rounds` is now `Int?`**, read from the stored parameters; it's nil for a
  scheme whose cost isn't a round count. Source-breaking for a caller that used it as `Int`.
- `PassphraseVerifier.Failure` gains `.refused(_:)` and `.invalidParameters`.
- **`Authenticator` no longer stops at the first refusal**: it checks every credential, then
  refuses the set with the first refusal's reason. The answer is unchanged; the work isn't.
- **`ThrottleLedger` gains `disableTogether(_:)`**, a requirement: a ledger written outside this
  package must implement it.
- **`IdentityEvent.Outcome` gains `.subjectMismatch`.** Source-breaking for an exhaustive `switch`
  outside the package, accepted at 0.x (amendment §15.4). VaultMCP maps every outcome to a log
  level and will need a line for it.
- **`FailureThrottle` keeps its counts in a ledger, and its DocC records the reversal.** It
  said the counter "does not survive a restart, deliberately" and is "per-process". Both are
  quoted there and reversed for the ceiling: a per-process 100 is 300 across three instances,
  and NIST requires disabling (§15.1). The default ledger is still in memory, so behaviour
  below the ceiling is unchanged for a deployment that doesn't pass one.
- **A ledger that throws refuses the attempt**, audited as `.throttled`, even for the right
  passphrase. So is a disabled passphrase. The `Outcome` set is unchanged.
- **`FileCredentialStore` counts a passphrase attempt before deriving it**, through
  `beginAttempt`, rather than checking the throttle and recording the outcome afterwards.
- **`FileCredentialStore` throttles by passphrase key, not by subject ID.** Every attempt naming
  a subject with no passphrase counts under one fixed key, `ThrottleKey.unknownPassphrase`, so
  naming strangers can't grow a ledger file.
- `FailureThrottle.shouldRefuse(subjectID:)`, `recordFailure(subjectID:)` and
  `recordSuccess(subjectID:)` are now `async`; they were actor-isolated, so callers already
  awaited them.

### Fixed

- **The common-password list was a resource bundle, and SwiftPM's accessor stops the process when
  the bundle isn't beside the binary.** A deployment copying only its executable would have
  crashed at the first passphrase check; the gate's doc-run caught it when an article first
  evaluated a policy. The list is now generated as Swift source and compiled in;
  `CommonPasswords.bundled()` no longer throws, and the package ships no resources.

- **A passphrase claiming a subject with none was refused without a derivation**, so its timing
  said who had a passphrase. The amendment's P17 row asks for dummy work; the store now derives
  against a verifier with the first stored passphrase's scheme and cost, so either refusal costs
  the same. This reverses a comment that called the timing "already public by design".

- **The work-factor tests measured wall-clock time**, and on a machine with a load average over a
  hundred the gate caught one flipping fail→pass against an unchanged package. They now measure
  the thread's CPU time, which counts only the derivation's own work.

### Found

- **Foundation's `precomposedStringWithCanonicalMapping` isn't NFC on its own.** It leaves a
  precomposed Hangul LV syllable and a following trailing jamo apart ("가" + "ᆨ" should compose to
  "각"), and missed a Tibetan reordering. Unicode's conformance file caught it. NFC here is
  decomposition then composition, as UAX #15 defines it, which passes every case.

## [0.6.3] — 2026-10-21

No API changes. The release that makes the package publishable.

### Changed

- **Licensed MIT.** The repository had no license, which would have left a public copy with no
  permission to use it.
- **SwiftDeterminism resolves over HTTPS.** The `git@github.com:` URL worked only for a machine
  holding a GitHub SSH key, which no public consumer can be assumed to have. SwiftDeterminism is
  a public repository.
- **The README's status was a month stale.** It said "Design stage. Nothing is implemented"
  through six releases of implementation. It now says what exists.

## [0.6.2] — 2026-09-12

### Fixed

- **The package declared no platform floor**, so it inherited whatever minimum the building
  toolchain happened to use. `SHA256.hash(data:)` requires macOS 10.15, which compiled cleanly on
  a Swift 6.4 toolchain and failed outright on the 6.3.3 one the first consumer's deploy host
  runs:

      error: 'hash(data:)' is only available in macOS 10.15 or newer

  It had built locally for three days and could never have built there. Nothing surfaced it until
  something was actually deployed, which is the argument for deploying early rather than for
  building carefully.

  Now `.macOS(.v14)`, matching the consumers that exist rather than claiming a floor nobody
  tests.

## [0.6.1] — 2026-09-12

### Added

- **`IdentityEvent.Outcome` is `CaseIterable`.** A consumer classifying every outcome — mapping
  each to a log level, say — can now prove the classification is total. An exhaustive `switch`
  already catches a new case at compile time; enumerating them is what lets a test assert the
  other half: that exactly one outcome is loud enough to wake somebody.

## [0.6.0] — 2026-09-12

**The audit seam is reachable.**

### Added

- **`FileCredentialStore` and `SessionStore` both take an `audit:`.** `IdentityAudit` has been a
  public protocol since 0.1.0 with no parameter anywhere that accepts one — a hook nobody could
  hang anything on.

  It sat unused because `Resolution` had solved most of what the original design wanted from it:
  the resolution already tells the service **what** happened. What it cannot tell them is
  **who**. `refused(.honeypot)` reports that a tripwire fired; a deployment holding several
  leaked credentials needs to know *which one* somebody found, and that fact exists only inside
  the store. The same is true of a revoked subject and of a throttled one — the subject being
  guessed at is exactly what a service watching for a guessing run wants.

  Every exit from `resolve` goes through one reporting function rather than recording at each
  `return`. An outcome added later that forgets to record would be invisible, because a missing
  audit line looks exactly like a thing that did not happen.

  **It fires on every resolution, including successes**, which for an API authenticated by a
  bearer key is once per request. Nothing is filtered here: a library that decides which events
  matter has decided it for every consumer. A consumer wanting only refusals should filter, and
  should not wire this to a synchronous disk write.

  `nil` by default, so every existing call site behaves exactly as before.

## [0.5.0] — 2026-09-11

**The second silent-drop in one day, and the end of the tolerance that allowed both.**

### Changed

- **A shapeless attribute chunk is now startup-fatal.** Attributes are comma-separated pairs, so
  `scopes=a,b` — the natural way to write a list, and unwriteable here because the comma already
  separates pairs — parsed as `scopes=a` plus a chunk with no `=`, and the parser skipped that
  chunk in silence. The list was truncated, the roster read correctly to a human, and nothing
  said otherwise.

  This is the same failure as 0.4.0's fifth field, one level down, found the same afternoon by
  the same consumer writing the same file.

  **The tolerance was justified in a comment, and the justification was wrong.** It read: *these
  are the consumer's own claims, which this package never interprets, so a malformed one costs an
  attribute, not a login.* True of the attribute and false of the consequence — the first
  consumer to use attributes put an authorisation tier and a scope restriction in them, so a
  dropped attribute was a dropped **security setting**. A package that will not default an
  unknown status, and will not accept a passphrase stored as a bare digest, should not have been
  shrugging at this.

  A value may still contain `=`; only the first one splits. An **empty value is still
  well-formed**, because `tier=` says the key is set to nothing, and a consumer may want to tell
  that apart from the key being absent.

  **This can break a roster that currently loads**, which is the intent — a file it breaks on is
  a file that is not doing what its author wrote.

## [0.4.0] — 2026-09-11

**A roster line can no longer say something nobody reads.**

### Changed

- **A subject line with a fifth field is now startup-fatal.** The roster is
  `<id> <kind> <status> [key=value,…]`, where the attributes are one comma-separated field. The
  old parser read the fourth field and dropped anything after it in silence, so writing
  `tier=parent scopes=19-coprock` — a space instead of a comma — parsed the tier, discarded the
  scope restriction, and reported nothing.

  VaultMCP's web view lost a scope restriction to exactly that, and the only reason it surfaced
  was a test that happened to assert the scope. A security setting that is written down, not
  applied, and does not say so is the failure mode this package refuses everywhere else; it
  should never have been reachable here.

  **This can break a roster that currently loads.** That is the intent: a file it breaks on is a
  file that is not doing what its author wrote. The failure is at startup, never at request
  time, like every other malformed line.

## [0.3.0] — 2026-09-11

**What the first real consumer found.** VaultMCP's web view began integrating against 0.2.0 and
hit both of these on the first day. Neither would have been free to fix later.

### Added

- **`FileCredentialStore.subject(id:)`.** `SessionStore`'s initialiser asks for
  `(String) async -> Subject?` and nothing in this package could answer it: the roster was
  private and nothing read it by id. A package that vends both halves of a seam and cannot join
  them has not finished the seam.

  It returns revoked and honeypot subjects, carrying their status, rather than hiding them. That
  is the point rather than an oversight — `SessionStore` re-reads status on every resolution so
  that a revocation ends a live session, and it can only do that if the subject comes back.
  Returning `nil` for them would make a revocation indistinguishable from a deleted roster line,
  and a later caller would read `nil` as "no objection".

### Changed

- **`ICSHex` is now `Hex`.** A calendar package's name for a hex formatter, arrived here by copy,
  public API in a package that has nothing to do with iCalendar. Renamed while the only uses were
  this package's own tests.

  **This is source-breaking**, which is why it is a minor bump under 0.x rather than a patch. A
  consumer calling `ICSHex.byte` renames the call; there is no behaviour change. It happens now
  because the cost of this rename only ever grows.

## [0.2.0] — 2026-09-10

**Phase 2: humans.** The kind a person types, the counter that makes guessing it pointless, and
the session that follows a successful one.

Additive: every 0.1.0 API keeps its shape, and `FileCredentialStore`'s new `throttle` parameter
defaults to none. One behaviour did change — a passphrase stored as a bare SHA-256 digest is now
**startup-fatal** rather than silently unverifiable. No deployment holds one, because no store
could accept a passphrase before this.

### Added

- **`PassphraseVerifier`, and the slow path the design has promised since §4e.** A passphrase is
  the only credential kind here a person could plausibly guess, and it is now the only one
  verified at a cost: PBKDF2-HMAC-SHA256, 600,000 rounds by default — OWASP's 2023 figure — with
  a floor of 210,000 that swift-crypto enforces itself.

  Every other kind is still compared against a fast hash. That is not an oversight: a work factor
  defends a guessable secret and buys nothing against 256 bits of machine randomness, where it
  would be paid on every request to defend against nothing.

  **The fast path is now closed to passphrases outright.** `FileCredentialStore.digest(of:)`
  returns nil for one, so a passphrase cannot be checked at the speed of the kinds that need no
  protecting.

  **The stored form is one self-describing field** — `pbkdf2-sha256$<rounds>$<salt>$<digest>` —
  so the verifiers file keeps `<subject> <kind> <verifier> <expires>` for every kind. The round
  count travels with each verifier rather than being assumed, so raising it ages existing
  passphrases into a rotation rather than a parse failure. The algorithm prefix is what lets a
  better KDF later be told apart from this one rather than silently mis-derived.

  **The subject is derived into the verifier**, not merely stored beside it. A random salt
  already stops two people choosing the same words from colliding; binding the subject
  additionally means a verifier line moved to another subject in the file stops working — which
  is what makes a hand-edited roster safe to hand-edit.

  **A passphrase is found by the subject it names, not by scanning.** Unlike every other kind it
  carries a subject id, so there is nothing to search — which matters here more than elsewhere:
  deriving against every stored passphrase would cost hundreds of thousands of rounds per record
  and turn a login into a denial of service against the server.

  A bare hex digest on a passphrase line is **startup-fatal**, under its own named failure. Such
  a value was written before this store could hold a passphrase, and would otherwise sit in the
  file looking correct and verifying nothing.

  Two tests measure the work factor rather than assuming it. Every functional test would pass
  just as happily against one round as against six hundred thousand.

- **`FailureThrottle`, so `ThrottlePolicy` stops being a type describing a defence nothing
  implemented.** Consecutive passphrase failures are counted per subject; crossing the threshold
  refuses the next attempt **unchecked**, which is the point — running the KDF anyway would let a
  guesser spend six hundred thousand rounds of somebody else's CPU per attempt.

  **Backoff, not lockout.** A lockout is a denial-of-service primitive handed to anyone who knows
  a subject id: in a household, one person shutting another out of the boiler instructions by
  being annoying, with nobody let back in without an administrator. The penalty doubles per
  failure and **is capped at an hour** — doubling without a ceiling reaches a wait no person
  outlives, which is a lockout arrived at by arithmetic rather than by decision.

  A success clears the count, because the failures that matter are consecutive: someone who
  mistypes twice a week for a year is not gradually locked out of their own house.

  **Passphrases only.** A bearer key is never throttled however often it is wrong, and there is a
  test that presents a wrong one twenty times to prove it.

  **It does not survive a restart, deliberately** — persisting would mean a store write per failed
  attempt, an amplification a guesser controls. And the counter is **per process**: a deployment
  running several instances gives a guesser one allowance each. Both are §4e's recommendations,
  taken and written down rather than discovered later.

  The store now **claims `.throttling` in the conformance suite and is judged on it** — both
  requirements measured and passed, asserted directly, since `isConformant` is also true for a
  store that declines everything.

- **`SessionStore` and `MintedSession` — Phase 2 complete.** Sessions minted at login,
  short-lived, revocable one at a time or all at once, and never a durable identifier.

  **The subject's status is read at every resolution, never snapshotted at login.** This is the
  property the type is shaped around: a session carrying a copy of its subject would keep working
  after that subject was revoked, until it happened to lapse, so "revoked" would mean "revoked,
  eventually, probably". Revoking a subject now ends their sessions without anyone ending them,
  and a honeypot subject's session reports itself like any other presentation.

  Separate from `CredentialStore` per §4b(4): a deployment that later adopts an identity provider
  takes its sessions from the provider and its capability tokens from here, and fusing the two
  would give that provider's single logout nothing to propagate into.

  Tokens are 128 bits from a generator the caller supplies, and **only a digest is stored** — the
  value is returned once and cannot be recovered from the store. Digests are compared by scanning
  rather than by lookup, for the same reason `FileCredentialStore` does: a dictionary would be
  faster and would leak the answer's position through timing.

### Fixed

- **A timing test that was actually flaky**, caught by the gate rather than by a failure: it
  reported the assertion flipping fail→pass against a byte-identical package, which is a race and
  not a code change. It compared single measurements; it now compares the fastest of several
  runs, since noise only ever adds time.

## [0.1.0] — 2026-09-08

First tagged version. Cut because the package acquired its first consumer: `SwiftWebAuthn`'s
adapter product resolves a passkey assertion to a `Subject`, and a consumer pinned to a branch
is a consumer with no way to say which version it was built against.

**Phase 1 only.** The passphrase KDF, sessions and throttling are designed and not implemented;
`ThrottlePolicy` exists as a declaration. Nothing here should be read as a claim that a
passphrase is safely stored, because no store yet accepts one.

### Fixed

- **The conformance suite could not judge a credential kind declared outside this package.**
  `kinds do not cross` was checked by re-presenting a `BearerKey` as a `CapabilityToken`, which
  the suite could only build for the kinds defined here — so any consumer that declared its own
  kind, which is the case `Credential` was made a protocol to allow, got a `gap` on the one
  requirement most worth testing for it.

  `Fixtures` now accepts `activeAsAnotherKind`, because only the implementer can say what "the
  same proof, offered as something else" means for their kind. The old derivation remains the
  fallback.

  Found by the first real out-of-package store rather than by inspection, which is what the
  suite was built to do — and the gap turned out to be the suite's, not the store's.

### Added

- **`FileCredentialStore` — Phase 1, and the first store that can actually hold anything.**
  Two files in a directory: `subjects` says who exists, `verifiers` says what proves them.
  Only the second is sensitive, so the roster can be handed to someone for review without
  exposing anything.

  It holds **SHA-256 digests and no secrets**, with one consequence worth stating: the store
  cannot check a credential's entropy, because it never sees the credential. That check belongs
  to whatever mints them.

  Every refusal is **startup-fatal** — a credential store that silently serves nobody and one
  that silently serves everybody both look like "no error" from outside. Ten named failures, each carrying the file and, where it can, the line.
  Two are worth calling out: an unknown status is refused rather than defaulted, because
  `active` would turn a typo into an authentication and `revoked` would silently lock someone
  out; and one digest claimed by two subjects is refused, because whichever won would be
  arbitrary and the loser would be authenticated as somebody else.

  It clears the conformance suite it was written against.

- **`Credential` is a protocol rather than an enum.** A provider integration adding a kind
  nobody has named yet is a new type in the consumer's own package, where a new enum case is
  source-breaking for everyone who switched over it. The cost — a store can no longer switch
  exhaustively — lands on the store, and the conformance suite already asserts the behaviour
  that would be lost.


### Scaffolding

- Package scaffolded from development-guidelines v2.2.0.
- `project/plans/proposals/SubjectsAndCredentials.md` — the design: subjects, credential kinds
  that are not all browser-shaped, status as a verb (`active` / `revoked` / `honeypot`), and the
  line between identity and entitlement.
- `project/master_plan.md` — mission, the split against SwiftOAuth, and the roadmap.

The proposal came before the code, which is why the code it produced is the shape it is.

[Unreleased]: https://github.com/jpurnell/swift-identity/compare/0.7.0...HEAD
[0.7.0]: https://github.com/jpurnell/swift-identity/releases/tag/0.7.0
[0.6.3]: https://github.com/jpurnell/swift-identity/releases/tag/0.6.3
[0.6.2]: https://github.com/jpurnell/SwiftIdentity/releases/tag/0.6.2
[0.6.1]: https://github.com/jpurnell/SwiftIdentity/releases/tag/0.6.1
[0.6.0]: https://github.com/jpurnell/SwiftIdentity/releases/tag/0.6.0
[0.5.0]: https://github.com/jpurnell/SwiftIdentity/releases/tag/0.5.0
[0.4.0]: https://github.com/jpurnell/SwiftIdentity/releases/tag/0.4.0
[0.3.0]: https://github.com/jpurnell/SwiftIdentity/releases/tag/0.3.0
[0.2.0]: https://github.com/jpurnell/SwiftIdentity/releases/tag/0.2.0
[0.1.0]: https://github.com/jpurnell/SwiftIdentity/releases/tag/0.1.0
