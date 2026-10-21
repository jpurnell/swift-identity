# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet.

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

[Unreleased]: https://github.com/jpurnell/swift-identity/compare/0.6.3...HEAD
[0.6.3]: https://github.com/jpurnell/swift-identity/releases/tag/0.6.3
[0.6.2]: https://github.com/jpurnell/SwiftIdentity/releases/tag/0.6.2
[0.6.1]: https://github.com/jpurnell/SwiftIdentity/releases/tag/0.6.1
[0.6.0]: https://github.com/jpurnell/SwiftIdentity/releases/tag/0.6.0
[0.5.0]: https://github.com/jpurnell/SwiftIdentity/releases/tag/0.5.0
[0.4.0]: https://github.com/jpurnell/SwiftIdentity/releases/tag/0.4.0
[0.3.0]: https://github.com/jpurnell/SwiftIdentity/releases/tag/0.3.0
[0.2.0]: https://github.com/jpurnell/SwiftIdentity/releases/tag/0.2.0
[0.1.0]: https://github.com/jpurnell/SwiftIdentity/releases/tag/0.1.0
