# Mutation report

Seed `20261023`, at most 25 mutants per file, sampled round-robin across operators. Produced by `python3 -I Harness/Mutation/mutate.py`; see README.md for the method.

*Generated* is every mutant the operators produce for the file; *sampled* is what ran. A
*stillborn* mutant didn't compile and counts for nothing. *Killed* includes timeouts. The
counts are the first run's; a survivor a new test now kills is listed below with both.

| File | Generated | Sampled | Stillborn | Killed | Survived | Not run |
|---|---:|---:|---:|---:|---:|---:|
| `PassphraseVerifier.swift` | 24 | 24 | 2 | 13 | 9 | 0 |
| `PassphraseScheme.swift` | 19 | 19 | 2 | 9 | 8 | 0 |
| `PassphraseCanonicalization.swift` | 6 | 6 | 0 | 6 | 0 | 0 |
| `Authenticator.swift` | 11 | 11 | 0 | 10 | 1 | 0 |
| `ThrottleLedger.swift` | 106 | 25 | 0 | 14 | 11 | 0 |
| `FileThrottleLedger.swift` | 56 | 25 | 2 | 12 | 11 | 0 |
| `Argon2id.swift` | 340 | 25 | 0 | 24 | 1 | 0 |
| `BLAKE2b.swift` | 302 | 25 | 0 | 24 | 1 | 0 |
| `OneTimeCode.swift` | 59 | 25 | 1 | 16 | 8 | 0 |
| `PassphrasePolicy.swift` | 35 | 25 | 4 | 17 | 4 | 0 |
| **Total** | 958 | 210 | 11 | 145 | 54 | 0 |

748 generated mutants were not sampled, most of them in `Argon2id.swift` and `BLAKE2b.swift`, whose constant tables dominate the generated set. A different `--seed` samples a different 25.

## Survivors by verdict

- **Equivalent**: 18
- **Test gap — test added**: 32
- **Untestable without fault injection — accepted, explained**: 4

## Survivors

### `Sources/SwiftIdentity/Credential/PassphraseVerifier.swift:151` — boolean: false -> true (col 78)

Mutant `PassphraseVerifier-151-boolean-1`, filter `PassphraseVerifierTests|PassphraseWorkFactorTests|PassphraseSchemeTests|PepperTests`. Survived the first run; now killed: a stored value with an empty fifth field is malformed, not four fields and a stray separator.

```diff
--- a/Sources/SwiftIdentity/Credential/PassphraseVerifier.swift:151
+++ b/Sources/SwiftIdentity/Credential/PassphraseVerifier.swift:151
@@ -1 +1 @@
-        let parts = encoded.split(separator: "$", omittingEmptySubsequences: false)
+        let parts = encoded.split(separator: "$", omittingEmptySubsequences: true)
```

**Test gap — test added.** Skipping empty fields would read `<valid>$`, `$<valid>` or `…$$…` as a four-field verifier. Killed by "a stored value with an empty fifth field is malformed…" (002781d).

### `Sources/SwiftIdentity/Credential/PassphraseVerifier.swift:189` — boolean: false -> true (col 20)

Mutant `PassphraseVerifier-189-boolean-11`, filter `PassphraseVerifierTests|PassphraseWorkFactorTests|PassphraseSchemeTests|PepperTests`. Survived the first run; now killed: a derivation that throws matches nothing.

```diff
--- a/Sources/SwiftIdentity/Credential/PassphraseVerifier.swift:189
+++ b/Sources/SwiftIdentity/Credential/PassphraseVerifier.swift:189
@@ -1 +1 @@
-            return false
+            return true
```

**Test gap — test added.** The catch path in `matches` was unreached: no scheme in the tests throws from `derive`. A test scheme that always throws now must match nothing (002781d).

### `Sources/SwiftIdentity/Credential/PassphraseVerifier.swift:205` — logical: && -> || (col 56)

Mutant `PassphraseVerifier-205-logical-17`, filter `PassphraseVerifierTests|PassphraseWorkFactorTests|PassphraseSchemeTests|PepperTests`. Survived the first run; now killed: two verifiers are equal exactly when every stored field is.

```diff
--- a/Sources/SwiftIdentity/Credential/PassphraseVerifier.swift:205
+++ b/Sources/SwiftIdentity/Credential/PassphraseVerifier.swift:205
@@ -1 +1 @@
-        lhs.scheme.identifier == rhs.scheme.identifier && lhs.parameters == rhs.parameters
+        lhs.scheme.identifier == rhs.scheme.identifier || lhs.parameters == rhs.parameters
```

**Test gap — test added.** `PassphraseVerifier.==` had no test at all in these suites. Killed by "two verifiers are equal exactly when every stored field is" (002781d), which varies one field at a time.

### `Sources/SwiftIdentity/Credential/PassphraseVerifier.swift:205` — relational: == -> != (col 31)

Mutant `PassphraseVerifier-205-relational-15`, filter `PassphraseVerifierTests|PassphraseWorkFactorTests|PassphraseSchemeTests|PepperTests`. Survived the first run; now killed: two verifiers are equal exactly when every stored field is.

```diff
--- a/Sources/SwiftIdentity/Credential/PassphraseVerifier.swift:205
+++ b/Sources/SwiftIdentity/Credential/PassphraseVerifier.swift:205
@@ -1 +1 @@
-        lhs.scheme.identifier == rhs.scheme.identifier && lhs.parameters == rhs.parameters
+        lhs.scheme.identifier != rhs.scheme.identifier && lhs.parameters == rhs.parameters
```

**Test gap — test added.** `PassphraseVerifier.==` had no test at all in these suites. Killed by "two verifiers are equal exactly when every stored field is" (002781d), which varies one field at a time.

### `Sources/SwiftIdentity/Credential/PassphraseVerifier.swift:205` — relational: == -> != (col 74)

Mutant `PassphraseVerifier-205-relational-16`, filter `PassphraseVerifierTests|PassphraseWorkFactorTests|PassphraseSchemeTests|PepperTests`. Survived the first run; now killed: two verifiers are equal exactly when every stored field is.

```diff
--- a/Sources/SwiftIdentity/Credential/PassphraseVerifier.swift:205
+++ b/Sources/SwiftIdentity/Credential/PassphraseVerifier.swift:205
@@ -1 +1 @@
-        lhs.scheme.identifier == rhs.scheme.identifier && lhs.parameters == rhs.parameters
+        lhs.scheme.identifier == rhs.scheme.identifier && lhs.parameters != rhs.parameters
```

**Test gap — test added.** `PassphraseVerifier.==` had no test at all in these suites. Killed by "two verifiers are equal exactly when every stored field is" (002781d), which varies one field at a time.

### `Sources/SwiftIdentity/Credential/PassphraseVerifier.swift:206` — logical: && -> || (col 13)

Mutant `PassphraseVerifier-206-logical-20`, filter `PassphraseVerifierTests|PassphraseWorkFactorTests|PassphraseSchemeTests|PepperTests`. Survived the first run; now killed: two verifiers are equal exactly when every stored field is.

```diff
--- a/Sources/SwiftIdentity/Credential/PassphraseVerifier.swift:206
+++ b/Sources/SwiftIdentity/Credential/PassphraseVerifier.swift:206
@@ -1 +1 @@
-            && lhs.salt == rhs.salt && lhs.digest == rhs.digest
+            || lhs.salt == rhs.salt && lhs.digest == rhs.digest
```

**Test gap — test added.** `PassphraseVerifier.==` had no test at all in these suites. Killed by "two verifiers are equal exactly when every stored field is" (002781d), which varies one field at a time.

### `Sources/SwiftIdentity/Credential/PassphraseVerifier.swift:206` — logical: && -> || (col 37)

Mutant `PassphraseVerifier-206-logical-21`, filter `PassphraseVerifierTests|PassphraseWorkFactorTests|PassphraseSchemeTests|PepperTests`. Survived the first run; now killed: two verifiers are equal exactly when every stored field is.

```diff
--- a/Sources/SwiftIdentity/Credential/PassphraseVerifier.swift:206
+++ b/Sources/SwiftIdentity/Credential/PassphraseVerifier.swift:206
@@ -1 +1 @@
-            && lhs.salt == rhs.salt && lhs.digest == rhs.digest
+            && lhs.salt == rhs.salt || lhs.digest == rhs.digest
```

**Test gap — test added.** `PassphraseVerifier.==` had no test at all in these suites. Killed by "two verifiers are equal exactly when every stored field is" (002781d), which varies one field at a time.

### `Sources/SwiftIdentity/Credential/PassphraseVerifier.swift:206` — relational: == -> != (col 25)

Mutant `PassphraseVerifier-206-relational-18`, filter `PassphraseVerifierTests|PassphraseWorkFactorTests|PassphraseSchemeTests|PepperTests`. Survived the first run; now killed: two verifiers are equal exactly when every stored field is.

```diff
--- a/Sources/SwiftIdentity/Credential/PassphraseVerifier.swift:206
+++ b/Sources/SwiftIdentity/Credential/PassphraseVerifier.swift:206
@@ -1 +1 @@
-            && lhs.salt == rhs.salt && lhs.digest == rhs.digest
+            && lhs.salt != rhs.salt && lhs.digest == rhs.digest
```

**Test gap — test added.** `PassphraseVerifier.==` had no test at all in these suites. Killed by "two verifiers are equal exactly when every stored field is" (002781d), which varies one field at a time.

### `Sources/SwiftIdentity/Credential/PassphraseVerifier.swift:206` — relational: == -> != (col 51)

Mutant `PassphraseVerifier-206-relational-19`, filter `PassphraseVerifierTests|PassphraseWorkFactorTests|PassphraseSchemeTests|PepperTests`. Survived the first run; now killed: two verifiers are equal exactly when every stored field is.

```diff
--- a/Sources/SwiftIdentity/Credential/PassphraseVerifier.swift:206
+++ b/Sources/SwiftIdentity/Credential/PassphraseVerifier.swift:206
@@ -1 +1 @@
-            && lhs.salt == rhs.salt && lhs.digest == rhs.digest
+            && lhs.salt == rhs.salt && lhs.digest != rhs.digest
```

**Test gap — test added.** `PassphraseVerifier.==` had no test at all in these suites. Killed by "two verifiers are equal exactly when every stored field is" (002781d), which varies one field at a time.

### `Sources/SwiftIdentity/Credential/PassphraseScheme.swift:30` — boolean: false -> true (col 68)

Mutant `PassphraseScheme-30-boolean-0`, filter `PassphraseVerifierTests|PassphraseWorkFactorTests|PassphraseSchemeTests|PepperTests`. Survived the first run; now killed: a scheme that declares no cost policy is never below its current cost.

```diff
--- a/Sources/SwiftIdentity/Credential/PassphraseScheme.swift:30
+++ b/Sources/SwiftIdentity/Credential/PassphraseScheme.swift:30
@@ -1 +1 @@
-    public func isBelowCurrentCost(_ parameters: String) -> Bool { false }
+    public func isBelowCurrentCost(_ parameters: String) -> Bool { true }
```

**Test gap — test added.** The protocol's default `isBelowCurrentCost` (never) was untested; every scheme in the tests overrode it or wasn't asked. Killed by "a scheme that declares no cost policy is never below its current cost" (002781d).

### `Sources/SwiftIdentity/Credential/PassphraseScheme.swift:56` — constant: 0 -> 1 (col 29)

Mutant `PassphraseScheme-56-constant-4`, filter `PassphraseVerifierTests|PassphraseWorkFactorTests|PassphraseSchemeTests|PepperTests`. Survived the first run; still survives.

```diff
--- a/Sources/SwiftIdentity/Credential/PassphraseScheme.swift:56
+++ b/Sources/SwiftIdentity/Credential/PassphraseScheme.swift:56
@@ -1 +1 @@
-        (Int(parameters) ?? 0) < PassphraseVerifier.defaultRounds
+        (Int(parameters) ?? 1) < PassphraseVerifier.defaultRounds
```

**Equivalent.** `Int(parameters) ?? 0` vs `?? 1`: the fallback is reached only for parameters that aren't an integer, and both 0 and 1 are below `defaultRounds`, so the answer (true) is the same. Such parameters can't reach a constructed verifier anyway: `isValid` rejects them on decode and on derive.

### `Sources/SwiftIdentity/Credential/PassphraseScheme.swift:82` — boolean: true -> false (col 68)

Mutant `PassphraseScheme-82-boolean-6`, filter `PassphraseVerifierTests|PassphraseWorkFactorTests|PassphraseSchemeTests|PepperTests`. Survived the first run; now killed: a legacy digest is below current cost however many rounds it has.

```diff
--- a/Sources/SwiftIdentity/Credential/PassphraseScheme.swift:82
+++ b/Sources/SwiftIdentity/Credential/PassphraseScheme.swift:82
@@ -1 +1 @@
-    public func isBelowCurrentCost(_ parameters: String) -> Bool { true }
+    public func isBelowCurrentCost(_ parameters: String) -> Bool { false }
```

**Test gap — test added.** Legacy's `isBelowCurrentCost` was only exercised where the identifier differed from the writing scheme's, which already forces an upgrade. Now tested directly and with legacy as the writing scheme (002781d).

### `Sources/SwiftIdentity/Credential/PassphraseScheme.swift:97` — constant: 32 -> 33 (col 78)

Mutant `PassphraseScheme-97-constant-11`, filter `PassphraseVerifierTests|PassphraseWorkFactorTests|PassphraseSchemeTests|PepperTests`. Survived the first run; still survives.

```diff
--- a/Sources/SwiftIdentity/Credential/PassphraseScheme.swift:97
+++ b/Sources/SwiftIdentity/Credential/PassphraseScheme.swift:97
@@ -1 +1 @@
-                from: material, salt: salt, using: .sha256, outputByteCount: 32, rounds: rounds
+                from: material, salt: salt, using: .sha256, outputByteCount: 33, rounds: rounds
```

**Equivalent.** Asking PBKDF2-HMAC-SHA256 for 33 bytes: its first 32 are the 32-byte output (block T1 is identical), and the copy loop keeps only `derived.count` = 32 of them. Confirmed with Python's hashlib: the 33-byte output is the 32-byte one plus `06`.

### `Sources/SwiftIdentity/Credential/PassphraseScheme.swift:104` — constant: 0 -> 1 (col 46)

Mutant `PassphraseScheme-104-constant-12`, filter `PassphraseVerifierTests|PassphraseWorkFactorTests|PassphraseSchemeTests|PepperTests`. Survived the first run; still survives.

```diff
--- a/Sources/SwiftIdentity/Credential/PassphraseScheme.swift:104
+++ b/Sources/SwiftIdentity/Credential/PassphraseScheme.swift:104
@@ -1 +1 @@
-            var derived = [UInt8](repeating: 0, count: 32)
+            var derived = [UInt8](repeating: 1, count: 32)
```

**Equivalent.** The buffer's fill value: every one of its 32 bytes is overwritten by the 32-byte key before it is returned.

### `Sources/SwiftIdentity/Credential/PassphraseScheme.swift:104` — constant: 32 -> 33 (col 56)

Mutant `PassphraseScheme-104-constant-13`, filter `PassphraseVerifierTests|PassphraseWorkFactorTests|PassphraseSchemeTests|PepperTests`. Survived the first run; now killed: pbkdf2-sha256-c1 derives PBKDF2-HMAC-SHA256's own 32 bytes: a known answer.

```diff
--- a/Sources/SwiftIdentity/Credential/PassphraseScheme.swift:104
+++ b/Sources/SwiftIdentity/Credential/PassphraseScheme.swift:104
@@ -1 +1 @@
-            var derived = [UInt8](repeating: 0, count: 32)
+            var derived = [UInt8](repeating: 0, count: 33)
```

**Test gap — test added.** A 33-byte digest (the 32-byte key plus a zero) would still self-verify. Killed by the PBKDF2 known-answer test, whose vector comes from Python's hashlib (002781d).

### `Sources/SwiftIdentity/Credential/PassphraseScheme.swift:106` — relational: < -> <= (col 72)

Mutant `PassphraseScheme-106-relational-14`, filter `PassphraseVerifierTests|PassphraseWorkFactorTests|PassphraseSchemeTests|PepperTests`. Survived the first run; still survives.

```diff
--- a/Sources/SwiftIdentity/Credential/PassphraseScheme.swift:106
+++ b/Sources/SwiftIdentity/Credential/PassphraseScheme.swift:106
@@ -1 +1 @@
-                for (offset, byte) in buffer.enumerated() where offset < derived.count {
+                for (offset, byte) in buffer.enumerated() where offset <= derived.count {
```

**Equivalent.** `offset < derived.count` vs `<=`: the key's buffer is 32 bytes, so `offset` never exceeds 31 and the bound is never the deciding test.

### `Sources/SwiftIdentity/Credential/PassphraseScheme.swift:136` — deletion: delete statement

Mutant `PassphraseScheme-136-deletion-17`, filter `PassphraseVerifierTests|PassphraseWorkFactorTests|PassphraseSchemeTests|PepperTests`. Survived the first run; now killed: a derivation that throws matches nothing; a legacy digest is below current cost however many rounds it has; a scheme that declares no cost policy is never below its current cost.

```diff
--- a/Sources/SwiftIdentity/Credential/PassphraseScheme.swift:136
+++ b/Sources/SwiftIdentity/Credential/PassphraseScheme.swift:136
@@ -1 +1 @@
-        accepted[writing.identifier] = writing
+        
```

**Test gap — test added.** "`writing` is accepted too, whether or not it's listed" was untested: every test listed it. Killed by "the writing scheme is accepted even when the list leaves it out" and the tests built on `PassphraseSchemes([], writing:)` (002781d).

### `Sources/SwiftIdentity/Authentication/Authenticator.swift:78` — relational: > -> >= (col 37)

Mutant `Authenticator-78-relational-1`, filter `AuthenticatorTests|FileCredentialStoreOneTimeCodeTests`. Survived the first run; now killed: P22: a lone credential turned away doesn't seal the in-flight last attempt's fate.

```diff
--- a/Sources/SwiftIdentity/Authentication/Authenticator.swift:78
+++ b/Sources/SwiftIdentity/Authentication/Authenticator.swift:78
@@ -1 +1 @@
-        if let throttle, keys.count > 1 {
+        if let throttle, keys.count >= 1 {
```

**Test gap — test added.** Not equivalent, though it looks like it. With one credential, `disableTogether` can only change a key whose count is at the ceiling but whose flag isn't set: a last admitted attempt still being checked by another request. The mutant flags it, and that attempt's success can then no longer clear it (P22). Killed by "P22: a lone credential turned away doesn't seal the in-flight last attempt's fate" (6c0411e).

### `Sources/SwiftIdentity/Store/ThrottleLedger.swift:58` — constant: 8 -> 9 (col 74)

Mutant `ThrottleLedger-58-constant-1`, filter `ThrottleLedgerTests|FileThrottleLedgerTests|ThrottleLedgerConformanceTests|FailureThrottle`. Survived the first run; still survives.

```diff
--- a/Sources/SwiftIdentity/Store/ThrottleLedger.swift:58
+++ b/Sources/SwiftIdentity/Store/ThrottleLedger.swift:58
@@ -1 +1 @@
-            hasher.update(data: [UInt8(truncatingIfNeeded: salt.count >> 8), UInt8(truncatingIfNeeded: salt.count)])
+            hasher.update(data: [UInt8(truncatingIfNeeded: salt.count >> 9), UInt8(truncatingIfNeeded: salt.count)])
```

**Equivalent.** The salt-length prefix's high byte, `count >> 8` vs `>> 9`: both are 0 for any salt under 256 bytes, and this package writes 16-byte salts. A stored salt of 256+ bytes would get a different, still deterministic and still per-salt key: no throttling property depends on the exact fingerprint.

### `Sources/SwiftIdentity/Store/ThrottleLedger.swift:59` — deletion: delete statement

Mutant `ThrottleLedger-59-deletion-3`, filter `ThrottleLedgerTests|FileThrottleLedgerTests|ThrottleLedgerConformanceTests|FailureThrottle`. Survived the first run; now killed: a new passphrase is a new key, even when its salt is the same length as the old one's.

```diff
--- a/Sources/SwiftIdentity/Store/ThrottleLedger.swift:59
+++ b/Sources/SwiftIdentity/Store/ThrottleLedger.swift:59
@@ -1 +1 @@
-            hasher.update(data: salt)
+            
```

**Test gap — test added.** Without hashing the salt, every passphrase with a 16-byte salt got the same key, so rebinding inherited the old count. Killed by "a new passphrase is a new key…" (8b7b788).

### `Sources/SwiftIdentity/Store/ThrottleLedger.swift:85` — negation: drop prefix ! (col 15)

Mutant `ThrottleLedger-85-negation-5`, filter `ThrottleLedgerTests|FileThrottleLedgerTests|ThrottleLedgerConformanceTests|FailureThrottle`. Survived the first run; now killed: an enrolled app's key is the subject's own, and a re-enrolled app is a new one.

```diff
--- a/Sources/SwiftIdentity/Store/ThrottleLedger.swift:85
+++ b/Sources/SwiftIdentity/Store/ThrottleLedger.swift:85
@@ -1 +1 @@
-        guard !verifiers.isEmpty else { return unknownOneTimeCode }
+        guard verifiers.isEmpty else { return unknownOneTimeCode }
```

**Test gap — test added.** `ThrottleKey.oneTimeCode` wasn't tested directly in these suites. Killed by "an enrolled app's key is the subject's own…" (8b7b788).

### `Sources/SwiftIdentity/Store/ThrottleLedger.swift:89` — deletion: delete statement

Mutant `ThrottleLedger-89-deletion-8`, filter `ThrottleLedgerTests|FileThrottleLedgerTests|ThrottleLedgerConformanceTests|FailureThrottle`. Survived the first run; now killed: an enrolled app's key is the subject's own, and a re-enrolled app is a new one.

```diff
--- a/Sources/SwiftIdentity/Store/ThrottleLedger.swift:89
+++ b/Sources/SwiftIdentity/Store/ThrottleLedger.swift:89
@@ -1 +1 @@
-            hasher.update(data: sealed)
+            
```

**Test gap — test added.** Same as the passphrase key: without hashing the sealed bytes, a re-enrolled app inherited the old key. Killed by the same test (8b7b788).

### `Sources/SwiftIdentity/Store/ThrottleLedger.swift:131` — relational: > -> >= (col 29)

Mutant `ThrottleLedger-131-relational-14`, filter `ThrottleLedgerTests|FileThrottleLedgerTests|ThrottleLedgerConformanceTests|FailureThrottle`. Survived the first run; now killed: a backoff refuses until the instant it ends, and not at that instant.

```diff
--- a/Sources/SwiftIdentity/Store/ThrottleLedger.swift:131
+++ b/Sources/SwiftIdentity/Store/ThrottleLedger.swift:131
@@ -1 +1 @@
-        return refusedUntil > time
+        return refusedUntil >= time
```

**Test gap — test added.** The backoff's end instant was untested. Killed by "a backoff refuses until the instant it ends, and not at that instant" (8b7b788).

### `Sources/SwiftIdentity/Store/ThrottleLedger.swift:304` — relational: < -> <= (col 48)

Mutant `ThrottleLedger-304-relational-30`, filter `ThrottleLedgerTests|FileThrottleLedgerTests|ThrottleLedgerConformanceTests|FailureThrottle`. Survived the first run; now killed: a full book refuses an attempt on a new key, and admits one below the limit.

```diff
--- a/Sources/SwiftIdentity/Store/ThrottleLedger.swift:304
+++ b/Sources/SwiftIdentity/Store/ThrottleLedger.swift:304
@@ -1 +1 @@
-        guard existing != nil || entries.count < Self.maximumEntries else {
+        guard existing != nil || entries.count <= Self.maximumEntries else {
```

**Test gap — test added.** `LedgerBook.maximumEntries` had no test at all. Killed by "a full book refuses an attempt on a new key, and admits one below the limit" (8b7b788).

### `Sources/SwiftIdentity/Store/ThrottleLedger.swift:311` — relational: < -> <= (col 45)

Mutant `ThrottleLedger-311-relational-36`, filter `ThrottleLedgerTests|FileThrottleLedgerTests|ThrottleLedgerConformanceTests|FailureThrottle`. Survived the first run; now killed: P13: the attempt that reaches the ceiling earns no backoff; the count alone refuses.

```diff
--- a/Sources/SwiftIdentity/Store/ThrottleLedger.swift:311
+++ b/Sources/SwiftIdentity/Store/ThrottleLedger.swift:311
@@ -1 +1 @@
-        entry.refusedUntil = entry.failures < policy.ceiling
+        entry.refusedUntil = entry.failures <= policy.ceiling
```

**Test gap — test added.** The comment's "at the ceiling, no backoff" was untested. Killed by "P13: the attempt that reaches the ceiling earns no backoff" (8b7b788).

### `Sources/SwiftIdentity/Store/ThrottleLedger.swift:324` — arithmetic: + -> - (col 29)

Mutant `ThrottleLedger-324-arithmetic-43`, filter `ThrottleLedgerTests|FileThrottleLedgerTests|ThrottleLedgerConformanceTests|FailureThrottle`. Survived the first run; now killed: a failure involving new keys is refused if adding them all would pass the limit.

```diff
--- a/Sources/SwiftIdentity/Store/ThrottleLedger.swift:324
+++ b/Sources/SwiftIdentity/Store/ThrottleLedger.swift:324
@@ -1 +1 @@
-        guard entries.count + adding <= Self.maximumEntries else {
+        guard entries.count - adding <= Self.maximumEntries else {
```

**Test gap — test added.** The limit on a multi-key failure. Killed by "a failure involving new keys is refused if adding them all would pass the limit" (8b7b788).

### `Sources/SwiftIdentity/Store/ThrottleLedger.swift:359` — early-return: guard else: return false -> true

Mutant `ThrottleLedger-359-early-return-69`, filter `ThrottleLedgerTests|FileThrottleLedgerTests|ThrottleLedgerConformanceTests|FailureThrottle`. Survived the first run; now killed: a success with nothing to clear changes nothing, so the file ledger writes nothing.

```diff
--- a/Sources/SwiftIdentity/Store/ThrottleLedger.swift:359
+++ b/Sources/SwiftIdentity/Store/ThrottleLedger.swift:359
@@ -1 +1 @@
-        guard entry.failures != 0 || entry.refusedUntil != nil else { return false }
+        guard entry.failures != 0 || entry.refusedUntil != nil else { return true }
```

**Test gap — test added.** `changed` is what decides whether the file ledger writes; a success with nothing to clear reported a change. Killed by "a success with nothing to clear changes nothing…" (8b7b788).

### `Sources/SwiftIdentity/Store/ThrottleLedger.swift:374` — boolean: false -> true (col 23)

Mutant `ThrottleLedger-374-boolean-82`, filter `ThrottleLedgerTests|FileThrottleLedgerTests|ThrottleLedgerConformanceTests|FailureThrottle`. Survived the first run; now killed: disabling keys that are all disabled already changes nothing.

```diff
--- a/Sources/SwiftIdentity/Store/ThrottleLedger.swift:374
+++ b/Sources/SwiftIdentity/Store/ThrottleLedger.swift:374
@@ -1 +1 @@
-        var changed = false
+        var changed = true
```

**Test gap — test added.** Same: disabling keys already disabled reported a change, a needless write. Killed by "disabling keys that are all disabled already changes nothing" (8b7b788).

### `Sources/SwiftIdentity/Store/ThrottleLedger.swift:375` — boolean: true -> false (col 59)

Mutant `ThrottleLedger-375-boolean-84`, filter `ThrottleLedgerTests|FileThrottleLedgerTests|ThrottleLedgerConformanceTests|FailureThrottle`. Survived the first run; now killed: P13: disabling together reaches a key the ledger already has, not only new ones; disabling keys that are all disabled already changes nothing.

```diff
--- a/Sources/SwiftIdentity/Store/ThrottleLedger.swift:375
+++ b/Sources/SwiftIdentity/Store/ThrottleLedger.swift:375
@@ -1 +1 @@
-        for key in unique where entries[key]?.disabled != true {
+        for key in unique where entries[key]?.disabled != false {
```

**Test gap — test added.** A real hole in coverage: the mutant skipped keys the ledger already held (enabled, with failures) and disabled only new ones. Killed by "P13: disabling together reaches a key the ledger already has" (8b7b788).

### `Sources/SwiftIdentity/Store/FileThrottleLedger.swift:175` — constant: 0 -> 1 (col 29)

Mutant `FileThrottleLedger-175-constant-12`, filter `ThrottleLedgerTests|FileThrottleLedgerTests|ThrottleLedgerConformanceTests|FailureThrottle`. Survived the first run; still survives.

```diff
--- a/Sources/SwiftIdentity/Store/FileThrottleLedger.swift:175
+++ b/Sources/SwiftIdentity/Store/FileThrottleLedger.swift:175
@@ -1 +1 @@
-        guard descriptor >= 0 else { throw Failure.unreadable(path: lockPath, reason: errorText()) }
+        guard descriptor >= 1 else { throw Failure.unreadable(path: lockPath, reason: errorText()) }
```

**Equivalent.** `open` returning descriptor 0 needs stdin closed; it's open in every process this runs in, so `>= 0` and `>= 1` decide alike. (In a daemon that closed stdin, the mutant would refuse a good lock file; the original is correct.)

### `Sources/SwiftIdentity/Store/FileThrottleLedger.swift:186` — relational: < -> > (col 49)

Mutant `FileThrottleLedger-186-relational-19`, filter `ThrottleLedgerTests|FileThrottleLedgerTests|ThrottleLedgerConformanceTests|FailureThrottle`. Survived the first run; still survives.

```diff
--- a/Sources/SwiftIdentity/Store/FileThrottleLedger.swift:186
+++ b/Sources/SwiftIdentity/Store/FileThrottleLedger.swift:186
@@ -1 +1 @@
-            guard errno == EINTR, interruptions < 100 else {
+            guard errno == EINTR, interruptions > 100 else {
```

**Untestable without fault injection — accepted, explained.** The `EINTR` retry bound on `flock`. Reaching it needs a signal delivered without `SA_RESTART` while `flock` blocks, a hundred times over; no test can arrange that in-process without a seam in the source.

### `Sources/SwiftIdentity/Store/FileThrottleLedger.swift:189` — arithmetic: += 1 -> += 0

Mutant `FileThrottleLedger-189-arithmetic-20`, filter `ThrottleLedgerTests|FileThrottleLedgerTests|ThrottleLedgerConformanceTests|FailureThrottle`. Survived the first run; still survives.

```diff
--- a/Sources/SwiftIdentity/Store/FileThrottleLedger.swift:189
+++ b/Sources/SwiftIdentity/Store/FileThrottleLedger.swift:189
@@ -1 +1 @@
-            interruptions += 1
+            interruptions += 0
```

**Untestable without fault injection — accepted, explained.** The same `EINTR` path: the counter only advances after an interrupted `flock`.

### `Sources/SwiftIdentity/Store/FileThrottleLedger.swift:220` — relational: >= -> > (col 26)

Mutant `FileThrottleLedger-220-relational-29`, filter `ThrottleLedgerTests|FileThrottleLedgerTests|ThrottleLedgerConformanceTests|FailureThrottle`. Survived the first run; still survives.

```diff
--- a/Sources/SwiftIdentity/Store/FileThrottleLedger.swift:220
+++ b/Sources/SwiftIdentity/Store/FileThrottleLedger.swift:220
@@ -1 +1 @@
-        guard descriptor >= 0 else { throw Failure.unreadable(path: path, reason: errorText()) }
+        guard descriptor > 0 else { throw Failure.unreadable(path: path, reason: errorText()) }
```

**Equivalent.** As 175: descriptor 0 is never free.

### `Sources/SwiftIdentity/Store/FileThrottleLedger.swift:229` — arithmetic: + -> - (col 47)

Mutant `FileThrottleLedger-229-arithmetic-33`, filter `ThrottleLedgerTests|FileThrottleLedgerTests|ThrottleLedgerConformanceTests|FailureThrottle`. Survived the first run; now killed: a ledger of exactly the size limit is read whole; one byte over is refused.

```diff
--- a/Sources/SwiftIdentity/Store/FileThrottleLedger.swift:229
+++ b/Sources/SwiftIdentity/Store/FileThrottleLedger.swift:229
@@ -1 +1 @@
-                .read(upToCount: maximumBytes + 1) ?? Data()
+                .read(upToCount: maximumBytes - 1) ?? Data()
```

**Test gap — test added.** Reading `maximumBytes - 1` truncated a valid ledger at exactly the limit. Killed by "a ledger of exactly the size limit is read whole; one byte over is refused" (8b7b788).

### `Sources/SwiftIdentity/Store/FileThrottleLedger.swift:229` — constant: 1 -> 2 (col 49)

Mutant `FileThrottleLedger-229-constant-34`, filter `ThrottleLedgerTests|FileThrottleLedgerTests|ThrottleLedgerConformanceTests|FailureThrottle`. Survived the first run; still survives.

```diff
--- a/Sources/SwiftIdentity/Store/FileThrottleLedger.swift:229
+++ b/Sources/SwiftIdentity/Store/FileThrottleLedger.swift:229
@@ -1 +1 @@
-                .read(upToCount: maximumBytes + 1) ?? Data()
+                .read(upToCount: maximumBytes + 2) ?? Data()
```

**Equivalent.** Reading up to `maximumBytes + 2` rather than `+ 1`: any file over the limit still yields more than `maximumBytes` bytes and is refused; any file within it is read whole either way.

### `Sources/SwiftIdentity/Store/FileThrottleLedger.swift:262` — relational: < -> > (col 56)

Mutant `FileThrottleLedger-262-relational-40`, filter `ThrottleLedgerTests|FileThrottleLedgerTests|ThrottleLedgerConformanceTests|FailureThrottle`. Survived the first run; still survives.

```diff
--- a/Sources/SwiftIdentity/Store/FileThrottleLedger.swift:262
+++ b/Sources/SwiftIdentity/Store/FileThrottleLedger.swift:262
@@ -1 +1 @@
-            .sorted { ($0.subjectID, $0.authenticator) < ($1.subjectID, $1.authenticator) }
+            .sorted { ($0.subjectID, $0.authenticator) > ($1.subjectID, $1.authenticator) }
```

**Equivalent.** Rows sorted descending instead of ascending. The documented property is "the same state is always the same bytes", which either order gives; nothing reads the order.

### `Sources/SwiftIdentity/Store/FileThrottleLedger.swift:281` — boolean: false -> true (col 23)

Mutant `FileThrottleLedger-281-boolean-46`, filter `ThrottleLedgerTests|FileThrottleLedgerTests|ThrottleLedgerConformanceTests|FailureThrottle`. Survived the first run; still survives.

```diff
--- a/Sources/SwiftIdentity/Store/FileThrottleLedger.swift:281
+++ b/Sources/SwiftIdentity/Store/FileThrottleLedger.swift:281
@@ -1 +1 @@
-        var renamed = false
+        var renamed = true
```

**Untestable without fault injection — accepted, explained.** `renamed` starting true would leak the temporary file when writing or renaming fails after it was created. Only an I/O failure in that window (ENOSPC, EIO, a failed `rename`) reaches it, and every route to one a test controls fails earlier, at `open` or at `readBook`. Closing it needs a fault-injection seam in `writeBook`.

### `Sources/SwiftIdentity/Store/FileThrottleLedger.swift:282` — negation: drop prefix ! (col 20)

Mutant `FileThrottleLedger-282-negation-47`, filter `ThrottleLedgerTests|FileThrottleLedgerTests|ThrottleLedgerConformanceTests|FailureThrottle`. Survived the first run; still survives.

```diff
--- a/Sources/SwiftIdentity/Store/FileThrottleLedger.swift:282
+++ b/Sources/SwiftIdentity/Store/FileThrottleLedger.swift:282
@@ -1 +1 @@
-        defer { if !renamed { unlink(temporary) } }
+        defer { if renamed { unlink(temporary) } }
```

**Equivalent.** Inverting the cleanup unlinks the temporary after a successful rename, when that name no longer exists (ENOENT, nothing removed), and skips it on failure, which is mutant 281's untestable window.

### `Sources/SwiftIdentity/Store/FileThrottleLedger.swift:290` — deletion: delete statement

Mutant `FileThrottleLedger-290-deletion-50`, filter `ThrottleLedgerTests|FileThrottleLedgerTests|ThrottleLedgerConformanceTests|FailureThrottle`. Survived the first run; still survives.

```diff
--- a/Sources/SwiftIdentity/Store/FileThrottleLedger.swift:290
+++ b/Sources/SwiftIdentity/Store/FileThrottleLedger.swift:290
@@ -1 +1 @@
-                try handle.synchronize()
+                
```

**Untestable without fault injection — accepted, explained.** Dropping `synchronize()` loses durability across a crash or power loss, which no in-process test observes: the page cache serves the same bytes.

### `Sources/SwiftIdentity/Store/FileThrottleLedger.swift:296` — boolean: true -> false (col 19)

Mutant `FileThrottleLedger-296-boolean-53`, filter `ThrottleLedgerTests|FileThrottleLedgerTests|ThrottleLedgerConformanceTests|FailureThrottle`. Survived the first run; still survives.

```diff
--- a/Sources/SwiftIdentity/Store/FileThrottleLedger.swift:296
+++ b/Sources/SwiftIdentity/Store/FileThrottleLedger.swift:296
@@ -1 +1 @@
-        renamed = true
+        renamed = false
```

**Equivalent.** As 282: after a successful rename, unlinking the temporary's old name removes nothing.

### `Sources/SwiftIdentity/Credential/Argon2id.swift:364` — constant: 0 -> 1 (col 22)

Mutant `Argon2id-364-constant-171`, filter `Argon2id|BLAKE2bTests`. Survived the first run; still survives.

```diff
--- a/Sources/SwiftIdentity/Credential/Argon2id.swift:364
+++ b/Sources/SwiftIdentity/Credential/Argon2id.swift:364
@@ -1 +1 @@
-        addressInput[0] = UInt64(pass)
+        addressInput[1] = UInt64(pass)
```

**Equivalent.** `addressInput[1] = pass` instead of `[0]` (then overwritten by `lane`), leaving `[0]` at its reset 0. Argon2id uses data-independent addressing only in pass 0 (slices 0 and 1), so `pass` is always 0 when the address block is built: the block is identical.

### `Sources/SwiftIdentity/Credential/BLAKE2b.swift:113` — relational: < -> <= (col 22)

Mutant `BLAKE2b-113-relational-285`, filter `Argon2id|BLAKE2bTests`. Survived the first run; still survives.

```diff
--- a/Sources/SwiftIdentity/Credential/BLAKE2b.swift:113
+++ b/Sources/SwiftIdentity/Credential/BLAKE2b.swift:113
@@ -1 +1 @@
-        guard offset < end else { return words }
+        guard offset <= end else { return words }
```

**Equivalent.** `offset < end` vs `<=`: when they're equal the loop `offset..<end` is empty and the zeroed words are returned either way.

### `Sources/SwiftIdentity/Credential/OneTimeCode.swift:61` — boolean: false -> true (col 81)

Mutant `OneTimeCode-61-boolean-2`, filter `OneTimeCodeTests|FileCredentialStoreOneTimeCodeTests`. Survived the first run; still survives.

```diff
--- a/Sources/SwiftIdentity/Credential/OneTimeCode.swift:61
+++ b/Sources/SwiftIdentity/Credential/OneTimeCode.swift:61
@@ -1 +1 @@
-        let parts = identifier.split(separator: "-", omittingEmptySubsequences: false)
+        let parts = identifier.split(separator: "-", omittingEmptySubsequences: true)
```

**Equivalent.** Skipping empty fields in `totp-…` can change what `split` returns, but the initializer then requires `self.identifier == identifier`, and a canonical identifier has no empty field, so every input the mutant would newly parse is still refused.

### `Sources/SwiftIdentity/Credential/OneTimeCode.swift:73` — logical: && -> || (col 57)

Mutant `OneTimeCode-73-logical-11`, filter `OneTimeCodeTests|FileCredentialStoreOneTimeCodeTests`. Survived the first run; now killed: parameters are valid only when both the digits and the step are.

```diff
--- a/Sources/SwiftIdentity/Credential/OneTimeCode.swift:73
+++ b/Sources/SwiftIdentity/Credential/OneTimeCode.swift:73
@@ -1 +1 @@
-    public var isValid: Bool { (6...8).contains(digits) && (1...120).contains(period) }
+    public var isValid: Bool { (6...8).contains(digits) || (1...120).contains(period) }
```

**Test gap — test added.** No test had exactly one of digits and step out of range. Killed by "parameters are valid only when both the digits and the step are" (40f6c3d).

### `Sources/SwiftIdentity/Credential/OneTimeCode.swift:80` — constant: 64 -> 65 (col 23)

Mutant `OneTimeCode-80-constant-14`, filter `OneTimeCodeTests|FileCredentialStoreOneTimeCodeTests`. Survived the first run; now killed: an SHA-512 key is the hash's output length: 512 bits.

```diff
--- a/Sources/SwiftIdentity/Credential/OneTimeCode.swift:80
+++ b/Sources/SwiftIdentity/Credential/OneTimeCode.swift:80
@@ -1 +1 @@
-        case .sha512: 64
+        case .sha512: 65
```

**Test gap — test added.** The SHA-512 key length was untested (SHA-1 and SHA-256 were). Killed by "an SHA-512 key is the hash's output length: 512 bits" (40f6c3d).

### `Sources/SwiftIdentity/Credential/OneTimeCode.swift:104` — arithmetic: + -> - (col 22)

Mutant `OneTimeCode-104-arithmetic-26`, filter `OneTimeCodeTests|FileCredentialStoreOneTimeCodeTests`. Survived the first run; still survives.

```diff
--- a/Sources/SwiftIdentity/Credential/OneTimeCode.swift:104
+++ b/Sources/SwiftIdentity/Credential/OneTimeCode.swift:104
@@ -1 +1 @@
-        guard offset + 3 < mac.count else { return "" }
+        guard offset - 3 < mac.count else { return "" }
```

**Equivalent.** `offset + 3 < mac.count`: `offset` is `last & 0x0F` ≤ 15 and the shortest HMAC is 20 bytes, so the guard always passes; `offset - 3` passes too.

### `Sources/SwiftIdentity/Credential/OneTimeCode.swift:104` — constant: 3 -> 4 (col 24)

Mutant `OneTimeCode-104-constant-27`, filter `OneTimeCodeTests|FileCredentialStoreOneTimeCodeTests`. Survived the first run; still survives.

```diff
--- a/Sources/SwiftIdentity/Credential/OneTimeCode.swift:104
+++ b/Sources/SwiftIdentity/Credential/OneTimeCode.swift:104
@@ -1 +1 @@
-        guard offset + 3 < mac.count else { return "" }
+        guard offset + 4 < mac.count else { return "" }
```

**Equivalent.** As 104: 15 + 4 = 19 < 20, so `+ 4` passes too.

### `Sources/SwiftIdentity/Credential/OneTimeCode.swift:104` — relational: < -> <= (col 26)

Mutant `OneTimeCode-104-relational-24`, filter `OneTimeCodeTests|FileCredentialStoreOneTimeCodeTests`. Survived the first run; still survives.

```diff
--- a/Sources/SwiftIdentity/Credential/OneTimeCode.swift:104
+++ b/Sources/SwiftIdentity/Credential/OneTimeCode.swift:104
@@ -1 +1 @@
-        guard offset + 3 < mac.count else { return "" }
+        guard offset + 3 <= mac.count else { return "" }
```

**Equivalent.** As 104: 18 ≤ 20, so `<=` passes too.

### `Sources/SwiftIdentity/Credential/OneTimeCode.swift:182` — boolean: false -> true (col 78)

Mutant `OneTimeCode-182-boolean-42`, filter `OneTimeCodeTests|FileCredentialStoreOneTimeCodeTests`. Survived the first run; now killed: a stored value with a stray separator is malformed.

```diff
--- a/Sources/SwiftIdentity/Credential/OneTimeCode.swift:182
+++ b/Sources/SwiftIdentity/Credential/OneTimeCode.swift:182
@@ -1 +1 @@
-        let parts = encoded.split(separator: "$", omittingEmptySubsequences: false)
+        let parts = encoded.split(separator: "$", omittingEmptySubsequences: true)
```

**Test gap — test added.** A stored verifier with a stray `$` was accepted. Killed by "a stored value with a stray separator is malformed" (40f6c3d).

### `Sources/SwiftIdentity/Credential/OneTimeCode.swift:251` — boolean: false -> true (col 104)

Mutant `OneTimeCode-251-boolean-58`, filter `OneTimeCodeTests|FileCredentialStoreOneTimeCodeTests`. Survived the first run; now killed: the enrollment secret is unpadded Base32, even for a key whose length needs padding.

```diff
--- a/Sources/SwiftIdentity/Credential/OneTimeCode.swift:251
+++ b/Sources/SwiftIdentity/Credential/OneTimeCode.swift:251
@@ -1 +1 @@
-            URLQueryItem(name: "secret", value: Base32.encode(try key(sealingKey: sealingKey), padded: false)),
+            URLQueryItem(name: "secret", value: Base32.encode(try key(sealingKey: sealingKey), padded: true)),
```

**Test gap — test added.** Only SHA-1 enrollment was tested, and a 20-byte key needs no Base32 padding. Killed by "the enrollment secret is unpadded Base32…" with a 32-byte key (40f6c3d).

### `Sources/SwiftIdentity/Credential/PassphrasePolicy.swift:151` — relational: <= -> < (col 33)

Mutant `PassphrasePolicy-151-relational-9`, filter `PassphrasePolicy`. Survived the first run; now killed: exactly 1 KiB is looked at; the byte cap refuses only what's over it.

```diff
--- a/Sources/SwiftIdentity/Credential/PassphrasePolicy.swift:151
+++ b/Sources/SwiftIdentity/Credential/PassphrasePolicy.swift:151
@@ -1 +1 @@
-        guard secret.utf8.count <= maximumInputBytes else { return [.tooManyBytes(maximum: maximumInputBytes)] }
+        guard secret.utf8.count < maximumInputBytes else { return [.tooManyBytes(maximum: maximumInputBytes)] }
```

**Test gap — test added.** The byte cap's boundary was untested. Killed by "exactly 1 KiB is looked at…" (40f6c3d).

### `Sources/SwiftIdentity/Credential/PassphrasePolicy.swift:330` — boolean: false -> true (col 63)

Mutant `PassphrasePolicy-330-boolean-23`, filter `PassphrasePolicy`. Survived the first run; now killed: context words, asked without a context, contain nothing.

```diff
--- a/Sources/SwiftIdentity/Credential/PassphrasePolicy.swift:330
+++ b/Sources/SwiftIdentity/Credential/PassphrasePolicy.swift:330
@@ -1 +1 @@
-    public func contains(_ canonical: String) async -> Bool { false }
+    public func contains(_ canonical: String) async -> Bool { true }
```

**Test gap — test added.** `ContextWords.contains(_:)` (no context) was never called. Killed by "context words, asked without a context, contain nothing" (40f6c3d).

### `Sources/SwiftIdentity/Credential/PassphrasePolicy.swift:362` — boolean: false -> true (col 63)

Mutant `PassphrasePolicy-362-boolean-33`, filter `PassphrasePolicy`. Survived the first run; still survives.

```diff
--- a/Sources/SwiftIdentity/Credential/PassphrasePolicy.swift:362
+++ b/Sources/SwiftIdentity/Credential/PassphrasePolicy.swift:362
@@ -1 +1 @@
-    init(minimumLength: Int, requiresLettersAndDigits: Bool = false) {
+    init(minimumLength: Int, requiresLettersAndDigits: Bool = true) {
```

**Equivalent.** The default argument of `PassphraseGuidance.init`'s `requiresLettersAndDigits`: its one caller, `PassphrasePolicy.guidance`, always passes it explicitly.

### `Sources/SwiftIdentity/Credential/PassphrasePolicy.swift:374` — constant: 1 -> 2 (col 46)

Mutant `PassphrasePolicy-374-constant-34`, filter `PassphrasePolicy`. Survived the first run; now killed: the PCI profile's composition rule comes straight after the length rule.

```diff
--- a/Sources/SwiftIdentity/Credential/PassphrasePolicy.swift:374
+++ b/Sources/SwiftIdentity/Credential/PassphrasePolicy.swift:374
@@ -1 +1 @@
-                + "rules require both.", at: 1)
+                + "rules require both.", at: 2)
```

**Test gap — test added.** Where the PCI line goes in the guidance was unpinned. Killed by "the PCI profile's composition rule comes straight after the length rule" (40f6c3d).
