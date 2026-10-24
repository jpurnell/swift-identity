"""Extracts the one-time-code test vectors: RFC 6238 Appendix B (TOTP) and RFC 4648 §10
(Base32, for the enrollment URI). Never typed by hand.

Downloads RFC 6238 (pinned SHA-256; stops if it changes), parses the Appendix B table rows
(`| <time> | <UTC> | <T hex> | <TOTP> | <mode> |`), and writes `totp-rfc6238.json` and
`TOTP-PROVENANCE.md` beside this script, with `base32-rfc4648.json` from RFC 4648 §10. The seeds are the ones the RFC's reference code
uses, stated in Appendix B's text: the ASCII string "12345678901234567890" for SHA1, repeated
to 32 bytes for SHA256 and 64 bytes for SHA512. They are extracted from the RFC's Java source
in Appendix A, not typed.

Run from the package root:  python3 -I Tests/SwiftIdentityTests/Vectors/import-totp.py
"""

import hashlib
import json
import os
import re
import sys
import urllib.request

URL = "https://www.rfc-editor.org/rfc/rfc6238.txt"
BASE32_URL = "https://www.rfc-editor.org/rfc/rfc4648.txt"
BASE32_SHA256 = "84e14418f795d503be5f34bf23ce4ebaa119e9ec7c9f667d8caeb111385b178f"
SOURCE_SHA256 = "82947ed9064450850547f55959dc79d2de775f0fa33f7b3f9622fb6c93e69a7a"
HERE = os.path.dirname(os.path.abspath(__file__))


def fetch(url, pinned):
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != pinned:
        sys.exit(f"{url} changed: {digest} != {pinned}")
    return data


def base32():
    """RFC 4648 §10's BASE32 lines: `BASE32("foo") = "MZXW6==="`."""
    text = fetch(BASE32_URL, BASE32_SHA256).decode("utf-8")
    pairs = re.findall(r'BASE32\("([a-z]*)"\) = "([A-Z2-7=]*)"', text)
    if len(pairs) != 7:
        sys.exit(f"expected 7 Base32 vectors, found {len(pairs)}")
    body = (json.dumps({"source": BASE32_URL, "sourceSHA256": BASE32_SHA256,
                        "vectors": [{"input": i, "output": o} for i, o in pairs]},
                       indent=2, sort_keys=True) + "\n").encode("utf-8")
    with open(os.path.join(HERE, "base32-rfc4648.json"), "wb") as handle:
        handle.write(body)
    return hashlib.sha256(body).hexdigest()


def main():
    base32_stored = base32()
    with urllib.request.urlopen(URL, timeout=60) as response:
        data = response.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != SOURCE_SHA256:
        sys.exit(f"RFC 6238 changed: {digest} != {SOURCE_SHA256}")
    text = data.decode("utf-8")

    # Seeds, from the Java reference implementation in Appendix A.
    seeds = {}
    for name, var in (("SHA1", "seed"), ("SHA256", "seed32"), ("SHA512", "seed64")):
        match = re.search(r'String ' + var + r' = "([0-9A-Fa-f]+)"\s*\+?\s*((?:\s*"[0-9A-Fa-f]+"\s*\+?\s*)*);', text)
        if match is None:
            sys.exit(f"seed {var} not found")
        pieces = [match.group(1)] + re.findall(r'"([0-9A-Fa-f]+)"', match.group(2))
        seeds[name] = "".join(pieces).lower()

    rows = re.findall(
        # The date is on the row's line and the time of day on the next, so a row is matched
        # by its first line alone.
        r"\|\s+(\d+)\s+\|\s+\d{4}-\d{2}-\d{2}\s+\|\s+([0-9A-F]{16})\s+\|\s+(\d{8})\s+\|\s+(SHA1|SHA256|SHA512)\s+\|",
        text,
    )
    if len(rows) != 18:
        sys.exit(f"expected 18 rows, found {len(rows)}")
    vectors = [
        {"time": int(t), "step": int(step, 16), "totp": code, "algorithm": mode, "seedHex": seeds[mode]}
        for t, step, code, mode in rows
    ]
    out = {
        "source": URL,
        "sourceSHA256": digest,
        "timeStep": 30,
        "t0": 0,
        "digits": 8,
        "vectors": vectors,
    }
    body = (json.dumps(out, indent=2, sort_keys=True) + "\n").encode("utf-8")
    with open(os.path.join(HERE, "totp-rfc6238.json"), "wb") as handle:
        handle.write(body)

    script = open(__file__, "rb").read()
    with open(os.path.join(HERE, "TOTP-PROVENANCE.md"), "w", encoding="utf-8", newline="\n") as handle:
        handle.write(f"""# One-time-code vectors: provenance

`totp-rfc6238.json` and `base32-rfc4648.json`, produced by `import-totp.py`; never typed by hand.

## `base32-rfc4648.json`

- Source: <{BASE32_URL}>, retrieved 2026-10-22
- Source SHA-256: `{BASE32_SHA256}`
- Stored file SHA-256: `{base32_stored}`
- Extraction: the seven `BASE32("…") = "…"` lines of §10, by regex.

## `totp-rfc6238.json`

- Source: <{URL}>, retrieved 2026-10-22
- Source SHA-256: `{digest}`
- Stored file SHA-256: `{hashlib.sha256(body).hexdigest()}`
- Script SHA-256: `{hashlib.sha256(script).hexdigest()}`
- Extraction: Appendix B's 18 table rows by regex; the three seeds from Appendix A's Java source
  (`seed`, `seed32`, `seed64`), concatenated as the source does. Time step 30 s, T0 = 0, 8 digits,
  as Appendix B states.
""")

if __name__ == "__main__":
    main()
