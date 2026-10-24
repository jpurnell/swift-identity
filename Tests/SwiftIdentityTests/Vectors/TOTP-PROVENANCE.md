# One-time-code vectors: provenance

`totp-rfc6238.json` and `base32-rfc4648.json`, produced by `import-totp.py`; never typed by hand.

## `base32-rfc4648.json`

- Source: <https://www.rfc-editor.org/rfc/rfc4648.txt>, retrieved 2026-10-22
- Source SHA-256: `84e14418f795d503be5f34bf23ce4ebaa119e9ec7c9f667d8caeb111385b178f`
- Stored file SHA-256: `709164dc0e270bfe31853e09f92c9924df9f6990e0ce6c5a07cd50e78423bf46`
- Extraction: the seven `BASE32("…") = "…"` lines of §10, by regex.

## `totp-rfc6238.json`

- Source: <https://www.rfc-editor.org/rfc/rfc6238.txt>, retrieved 2026-10-22
- Source SHA-256: `82947ed9064450850547f55959dc79d2de775f0fa33f7b3f9622fb6c93e69a7a`
- Stored file SHA-256: `886cac3cb3676647e25973fe3600b070bc56fbc720a699c17512eaa6cdeca0f6`
- Script SHA-256: `8b4fc8b601e770dfe1edb203b652c2b24853f0459d8690fd7d7e93b89666c139`
- Extraction: Appendix B's 18 table rows by regex; the three seeds from Appendix A's Java source
  (`seed`, `seed32`, `seed64`), concatenated as the source does. Time step 30 s, T0 = 0, 8 digits,
  as Appendix B states.
