# Bundled common-password blocklist

`Sources/SwiftIdentity/Credential/CommonPasswordsList.swift`, read by `CommonPasswords`. Produced by
`scripts/import-common-passwords.py`; never edited by hand. Compiled in, not a resource bundle, so
a deployment that copies only its executable still has it.

- Source: SecLists `Passwords/Common-Credentials/10k-most-common.txt`, commit `4c0fd59432ab8508edc23b3c880127edb12e34d5`
  (<https://raw.githubusercontent.com/danielmiessler/SecLists/4c0fd59432ab8508edc23b3c880127edb12e34d5/Passwords/Common-Credentials/10k-most-common.txt>), MIT licensed, Copyright (c) 2018 Daniel Miessler.
- Retrieved: 2026-10-22
- Source SHA-256: `68782d6a4a19a4768d5f15dd66bd534e7a33055cc755411e33f16d18c50fdcce`
- Stored file SHA-256: `bb6ba71b293203e60d94e5e3625d13a6494760def155af256e1e172c6f690df1`, 10001 entries
- Transformation: blank lines and duplicates dropped, order kept.
- Script SHA-256: `aee6d093d34d46d02d4f0831818b72de745c25746f209b30c938b267ebeff9d2`

Why this size: NIST SP 800-63B-4 §3.1.1.2 asks for a list "of sufficient size to prevent
subscribers from choosing passwords that attackers are likely to guess before reaching the
attempt limit", and warns that "excessively large blocklists are of little incremental security
benefit". The attempt limit here is 100.
