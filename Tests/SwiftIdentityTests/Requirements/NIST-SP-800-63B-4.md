# Requirements: NIST SP 800-63B-4 passphrases

The requirements the passphrase tests cite, one ID per row. Verified 2026-10-22 against
NIST SP 800-63B-4, July 2025 edition (`NIST.SP.800-63B-4.pdf`, SHA-256
`d9ab89576b5ae2cfb3ba37781110788dea27a85a5079496dbfc1a79834670afd`). The quoted sentence for each
row is in the amendment, `project/plans/proposals/AssuranceFactorsAndStandardPassphrases.md` §6.1.

`RequirementsCoverageTests` reads this table:
- every row whose Scope is `package` and whose Status is `implemented` must be cited by at least
  one test, as a display name beginning `"<ID>: "`;
- every ID a test cites must exist here.

A row moves from `planned` to `implemented` in the same commit as the tests that cite it.

| ID | Level | Section | Scope | Status | Requirement |
|---|---|---|---|---|---|
| P1 | SHALL | 3.1.1.2 (1) | package | implemented | Minimum 15 characters as a single factor; at least 8 when only part of multi-factor |
| P2 | SHOULD | 3.1.1.2 (2) | package | implemented | Permit a maximum length of at least 64 characters |
| P3 | SHALL NOT | 3.1.1.1; 3.1.1.2 (5) | package | implemented | No composition rules beyond the blocklist |
| P4 | SHOULD | 3.1.1.2 (3), (4) | package | implemented | Accept all printing ASCII characters, the space, and Unicode |
| P5 | SHALL | 3.1.1.2 (4) | package | implemented | Each Unicode code point counts as one character when evaluating length |
| P6 | SHOULD | 3.1.1.2 | package | implemented | Normalization process for stabilized strings, NFC (UAX #15 §12.1), before hashing |
| P7 | SHALL | 3.1.1.2 (9) | package | implemented | Request the password in full and verify all of it; no truncation |
| P8 | SHALL | 3.1.1.2 | package | implemented | On establish or change, compare the whole password against a blocklist of common, expected and compromised values |
| P9 | SHALL NOT / SHALL | 3.1.1.2 (6) | package | implemented | No periodic change; force a change on evidence of compromise |
| P10 | SHALL NOT | 3.1.1.2 (7), (8) | package | implemented | No hint available to an unauthenticated claimant; no knowledge-based questions |
| P11a | SHALL | 3.1.1.2 | host | n/a | Allow password managers and autofill |
| P11b | SHOULD | 3.1.1.2 | host | n/a | Permit paste |
| P12 | SHOULD | 3.1.1.2 | host | n/a | Offer to display the password while it is entered |
| P13 | SHALL | 3.2.2 | package | implemented | No more than 100 consecutive failures per authenticator per account, by disabling it; rebinding required; several involved, all disabled |
| P14a | SHALL | 3.1.1.2 | package | implemented | Salted and hashed; salt at least 32 bits; salt and hash stored |
| P14b | SHOULD | 3.1.1.2 | package | implemented | An SP 800-132 scheme; cost as high as practical and raised over time; scheme and cost stored with each password |
| P15 | SHOULD | 3.1.1.2 | package | implemented | Keyed pass with a verifier-only secret key: approved RBG, stored apart from digests (SHALL if used); hardware-protected (SHOULD) |
| P16 | SHALL | 3.1.1.2 | host | n/a | Approved encryption and an authenticated protected channel |
| P17 | ASVS | n/a | package | implemented | No timing oracle |
| P18 | ASVS | n/a | package | implemented | Generic failure to the caller |
| P19 | SHALL | 3.1.1.2 | package | implemented | On a blocklist rejection, give the reason |
| P20 | SHALL | 3.1.1.2 | package | implemented | Offer guidance for choosing a strong password |
| P21 | SHOULD | 3.1.1.2 | package | implemented | Advise that some endpoints may represent some characters differently |
| P22 | SHOULD | 3.2.2 | package | implemented | After a success, disregard earlier failures for the authenticators used |

## One-time codes (§3.1.4)

Amendment §4.7 and §6.2 (revision 4).

| ID | Level | Section | Scope | Status | Requirement |
|---|---|---|---|---|---|
| O1 | SHALL | 3.1.4.1 | package | implemented | Key and algorithm provide at least 112 bits of security strength |
| O2 | SHALL | 3.1.4.1 | package | implemented | A clock-based nonce changes at least once every two minutes |
| O3 | SHALL | 3.1.4.2 | package | implemented | Keys strongly protected against unauthorized disclosure |
| O4 | SHALL | 3.1.4.2 | package | implemented | Approved cryptography for key establishment when binding |
| O5 | SHALL | 3.1.4.2 | host | n/a | Approved encryption and an authenticated protected channel when collecting the OTP |
| O6 | SHALL | 3.1.4.2 | package | implemented | Accept a given OTP only once while it is valid |
| O7 | SHALL | 3.1.4.2 | package | implemented | A defined lifetime from clock drift, network delay and entry time |
| O8 | SHALL | 3.1.4.2 | package | implemented | Rate limiting, because the output is under 64 bits |
| O9 | fact | 3.1.4 | package | implemented | Not phishing-resistant |
