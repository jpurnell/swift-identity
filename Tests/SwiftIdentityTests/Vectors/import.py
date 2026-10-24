#!/usr/bin/env python3
"""Import known-answer test vectors from their primary sources.

Run from anywhere, in isolated mode:

    python3 -I Tests/SwiftIdentityTests/Vectors/import.py

Rule: no vector value in this directory is typed by hand. Every value is
downloaded from the primary source and extracted by this script. The only
constants below are source URLs, the pinned ACVP-Server commit, and the
SHA-256 of each source document, so that a changed upstream document fails
loudly instead of silently producing different vectors.

Downloads go to a fresh temporary directory outside the repository. Output
(the vector files and PROVENANCE.md) is written next to this script. Output
is deterministic: rerunning produces byte-identical files.
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

RETRIEVAL_DATE = "2026-10-22"

UNICODE_URL = "https://www.unicode.org/Public/15.0.0/ucd/NormalizationTest.txt"
RFC7914_URL = "https://www.rfc-editor.org/rfc/rfc7914.txt"
RFC9106_URL = "https://www.rfc-editor.org/rfc/rfc9106.txt"
RFC7693_URL = "https://www.rfc-editor.org/rfc/rfc7693.txt"

# The official BLAKE2 known-answer file. It covers unkeyed and keyed BLAKE2b over the inputs
# 00, 0001, ... up to 255 bytes; a bounded subset is imported, chosen for the block boundaries.
# Unkeyed only: Argon2 never keys BLAKE2b, so the package's BLAKE2b takes no key, and a keyed
# vector would test code that doesn't exist.
BLAKE2_REPO = "BLAKE2/BLAKE2"
BLAKE2_COMMIT = "ed1974ea83433eba7b2d95c5dcd9ac33cb847913"  # master HEAD on 2026-10-22
BLAKE2_KAT_URL = (
    f"https://raw.githubusercontent.com/{BLAKE2_REPO}/{BLAKE2_COMMIT}/testvectors/blake2-kat.json"
)
# Empty, one byte, one short of a block, exactly one block (not padded), one past it (the
# second block holds a single byte), and the longest the file has (two blocks).
BLAKE2_KAT_INPUT_LENGTHS = (0, 1, 3, 127, 128, 129, 255)

ACVP_REPO = "usnistgov/ACVP-Server"
ACVP_COMMIT = "975de31eb83d87039ec88934fdc47d8c312b892d"  # master HEAD on 2026-10-22
ACVP_DIR = "gen-val/json-files/PBKDF-1.0"
ACVP_PROMPT_URL = (
    f"https://raw.githubusercontent.com/{ACVP_REPO}/{ACVP_COMMIT}/{ACVP_DIR}/prompt.json"
)
ACVP_EXPECTED_URL = (
    f"https://raw.githubusercontent.com/{ACVP_REPO}/{ACVP_COMMIT}/{ACVP_DIR}/expectedResults.json"
)
ACVP_MAX_CASES = 40
ACVP_MAX_ITERATIONS = 10000

# SHA-256 of each source document as retrieved on RETRIEVAL_DATE.
# Computed with `shasum -a 256` over the downloaded documents; a mismatch
# aborts the import.
PINNED_SOURCE_SHA256 = {
    UNICODE_URL: "fb9ac8cc154a80cad6caac9897af55a4e75176af6f4e2bb6edc2bf8b1d57f326",
    RFC7914_URL: "df55932f8b6a5d271f36a634d91a25903724e189ba6c120bf7257cd47f10b197",
    RFC9106_URL: "855c06f060379e34285e83a217e9069b5c72e161a1e54df9af5cd88dbb231f31",
    RFC7693_URL: "c943754888364fe29bbd0bb3c71c6658ef392371497eaa4a9d9dde015b0721e5",
    BLAKE2_KAT_URL: "5031ac14800798ae15cee79c04d65e326a575f2c968c7e2846a79bd07a1c0e61",
    ACVP_PROMPT_URL: "97c6a5a81a7c7820adf992c90e76409c8cf656283d0a95eae514315c2872210c",
    ACVP_EXPECTED_URL: "7899e596e743ba3bf32ee1daa5ec47ae0264e159d28ef97c10d3e04f11b02a9f",
}

OUT_DIR = os.path.dirname(os.path.abspath(__file__))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch(url: str, workdir: str) -> bytes:
    """Download url with curl into workdir and return its bytes."""
    name = hashlib.sha256(url.encode()).hexdigest()[:16]
    path = os.path.join(workdir, name)
    subprocess.run(
        ["curl", "--silent", "--show-error", "--fail", "--location", "--output", path, url],
        check=True,
    )
    with open(path, "rb") as f:
        data = f.read()
    expected = PINNED_SOURCE_SHA256.get(url, "")
    actual = sha256_hex(data)
    if expected != actual:
        sys.exit(f"SHA-256 mismatch for {url}\n  pinned:   {expected}\n  received: {actual}")
    return data


def rfc_body(text: str) -> str:
    """Strip RFC pagination (form feeds, running headers and footers)."""
    lines = []
    for line in text.replace("\r\n", "\n").split("\n"):
        line = line.replace("\f", "")
        if re.match(r"^RFC \d+ .*\d{4}$", line):
            continue
        if re.search(r"\[Page \d+\]$", line):
            continue
        lines.append(line)
    return "\n".join(lines)


def section(text: str, start_heading: str, end_heading: str) -> str:
    start = re.search(r"^" + re.escape(start_heading), text, re.MULTILINE)
    end = re.search(r"^" + re.escape(end_heading), text, re.MULTILINE)
    if start is None or end is None or end.start() <= start.start():
        sys.exit(f"could not locate section {start_heading!r} .. {end_heading!r}")
    return text[start.start():end.start()]


HEX_PAIR = re.compile(r"\b[0-9a-fA-F]{2}\b")


def hex_bytes(fragment: str, expected_len: int, what: str) -> str:
    pairs = HEX_PAIR.findall(fragment)
    if len(pairs) != expected_len:
        sys.exit(f"{what}: expected {expected_len} bytes, found {len(pairs)}")
    return "".join(pairs).lower()


def write_json(name: str, obj) -> bytes:
    data = (json.dumps(obj, indent=2, ensure_ascii=True) + "\n").encode("ascii")
    with open(os.path.join(OUT_DIR, name), "wb") as f:
        f.write(data)
    return data


# ---------------------------------------------------------------- Unicode


def import_unicode(workdir: str) -> dict:
    data = fetch(UNICODE_URL, workdir)
    first_line = data.split(b"\n", 1)[0]
    if first_line != b"# NormalizationTest-15.0.0.txt":
        sys.exit(f"unexpected NormalizationTest header: {first_line!r}")
    name = "NormalizationTest-15.0.0.txt"
    with open(os.path.join(OUT_DIR, name), "wb") as f:
        f.write(data)
    return {
        "file": name,
        "url": UNICODE_URL,
        "source_sha256": sha256_hex(data),
        "stored_sha256": sha256_hex(data),
        "size": len(data),
        "how": "Stored byte-for-byte as downloaded (no transformation).",
    }


# ---------------------------------------------------------------- RFC 7914


PBKDF2_RE = re.compile(
    r'PBKDF2-HMAC-SHA-256 \(P="(?P<p>[^"]*)", S="(?P<s>[^"]*)",\s*'
    r"c=(?P<c>\d+), dkLen=(?P<len>\d+)\) =\s*(?P<hex>(?:[0-9a-f]{2}\s+)+)"
)


def import_rfc7914(workdir: str) -> dict:
    raw = fetch(RFC7914_URL, workdir)
    body = rfc_body(raw.decode("utf-8-sig"))
    sec = section(body, "11.  Test Vectors for PBKDF2 with HMAC-SHA-256", "12.  ")
    vectors = []
    for m in PBKDF2_RE.finditer(sec):
        dk_len = int(m.group("len"))
        vectors.append(
            {
                "password": m.group("p"),
                "salt": m.group("s"),
                "iterations": int(m.group("c")),
                "dkLen": dk_len,
                "dk": hex_bytes(m.group("hex"), dk_len, "RFC 7914 dk"),
            }
        )
    if len(vectors) != 2:
        sys.exit(f"RFC 7914 section 11: expected 2 vectors, found {len(vectors)}")
    name = "pbkdf2-sha256-rfc7914.json"
    out = write_json(
        name,
        {
            "source": RFC7914_URL,
            "section": "11. Test Vectors for PBKDF2 with HMAC-SHA-256",
            "sourceSha256": sha256_hex(raw),
            "retrieved": RETRIEVAL_DATE,
            "encoding": "password and salt are ASCII strings; dk is lowercase hex",
            "vectors": vectors,
        },
    )
    return {
        "file": name,
        "url": RFC7914_URL,
        "source_sha256": sha256_hex(raw),
        "stored_sha256": sha256_hex(out),
        "size": len(out),
        "how": "Section 11 located by heading; each `PBKDF2-HMAC-SHA-256 (P=..., S=..., "
        "c=..., dkLen=...) =` block parsed by regex; hex octets collected and their "
        "count checked against dkLen.",
    }


# ---------------------------------------------------------------- RFC 9106


def import_rfc9106(workdir: str) -> dict:
    raw = fetch(RFC9106_URL, workdir)
    body = rfc_body(raw.decode("utf-8-sig"))
    sec = section(body, "5.3.  Argon2id Test Vectors", "6.  IANA Considerations")

    def num(pattern: str) -> int:
        m = re.search(pattern, sec)
        if m is None:
            sys.exit(f"RFC 9106 5.3: missing {pattern!r}")
        return int(m.group(1))

    version = num(r"Argon2id version number (\d+)")
    memory_kib = num(r"Memory: (\d+) KiB")
    passes = num(r"Passes: (\d+)")
    lanes = num(r"Parallelism: (\d+) lanes")
    tag_len = num(r"Tag length: (\d+) bytes")

    def field(label: str, until: str) -> str:
        m = re.search(
            re.escape(label) + r"\[(\d+)\]:(.*?)(?=" + until + ")", sec, re.DOTALL
        )
        if m is None:
            sys.exit(f"RFC 9106 5.3: missing field {label!r}")
        return hex_bytes(m.group(2), int(m.group(1)), label)

    password = field("Password", r"Salt\[")
    salt = field("Salt", r"Secret\[")
    secret = field("Secret", r"Associated data\[")
    ad = field("Associated data", r"Pre-hashing digest:")

    m = re.search(r"Pre-hashing digest:(.*?)(?=After pass 0:)", sec, re.DOTALL)
    if m is None:
        sys.exit("RFC 9106 5.3: missing pre-hashing digest")
    prehash = hex_bytes(m.group(1), 64, "Pre-hashing digest")

    m = re.search(r"Tag:(.*)$", sec, re.DOTALL)
    if m is None:
        sys.exit("RFC 9106 5.3: missing tag")
    tag = hex_bytes(m.group(1), tag_len, "Tag")

    pass_chunks = re.split(r"After pass (\d+):", sec.split("Tag:")[0])
    intermediate = []
    for i in range(1, len(pass_chunks), 2):
        words = [
            {"block": int(b), "word": int(w), "value": v.lower()}
            for b, w, v in re.findall(
                r"Block (\d{4}) \[\s*(\d+)\]: ([0-9a-fA-F]{16})", pass_chunks[i + 1]
            )
        ]
        if len(words) != 8:
            sys.exit(f"RFC 9106 5.3 pass {pass_chunks[i]}: expected 8 words, found {len(words)}")
        intermediate.append({"pass": int(pass_chunks[i]), "words": words})
    if len(intermediate) != passes:
        sys.exit(f"RFC 9106 5.3: expected {passes} passes, found {len(intermediate)}")

    name = "argon2id-rfc9106.json"
    out = write_json(
        name,
        {
            "source": RFC9106_URL,
            "section": "5.3. Argon2id Test Vectors",
            "sourceSha256": sha256_hex(raw),
            "retrieved": RETRIEVAL_DATE,
            "encoding": "byte strings are lowercase hex; intermediate word values are "
            "64-bit words as printed by the RFC (block = memory block index, "
            "word = 64-bit word index within the 1 KiB block)",
            "vectors": [
                {
                    "type": "argon2id",
                    "version": version,
                    "memoryKiB": memory_kib,
                    "passes": passes,
                    "lanes": lanes,
                    "tagLength": tag_len,
                    "password": password,
                    "salt": salt,
                    "secret": secret,
                    "associatedData": ad,
                    "preHashingDigest": prehash,
                    "intermediate": intermediate,
                    "tag": tag,
                }
            ],
        },
    )
    return {
        "file": name,
        "url": RFC9106_URL,
        "source_sha256": sha256_hex(raw),
        "stored_sha256": sha256_hex(out),
        "size": len(out),
        "how": "Section 5.3 located by heading (pagination stripped); parameters, "
        "labelled hex fields, pre-hashing digest, the printed first/last-block words "
        "after each pass, and the tag parsed by regex; byte counts checked against the "
        "lengths the RFC prints in brackets.",
    }


# ---------------------------------------------------------------- RFC 7693


def import_rfc7693(workdir: str) -> dict:
    raw = fetch(RFC7693_URL, workdir)
    body = rfc_body(raw.decode("utf-8-sig"))
    sec = section(body, "Appendix A.  Example of BLAKE2b Computation", "Appendix B.  ")
    m = re.search(r'BLAKE2b-512\("abc"\) =(.*)$', sec, re.DOTALL)
    if m is None:
        sys.exit("RFC 7693 Appendix A: missing BLAKE2b-512(\"abc\")")
    digest = hex_bytes(m.group(1), 64, "RFC 7693 BLAKE2b-512")
    name = "blake2b-rfc7693.json"
    out = write_json(
        name,
        {
            "source": RFC7693_URL,
            "section": "Appendix A. Example of BLAKE2b Computation",
            "sourceSha256": sha256_hex(raw),
            "retrieved": RETRIEVAL_DATE,
            "encoding": "input is an ASCII string; out is lowercase hex",
            "vectors": [{"input": "abc", "outLength": 64, "out": digest}],
        },
    )
    return {
        "file": name,
        "url": RFC7693_URL,
        "source_sha256": sha256_hex(raw),
        "stored_sha256": sha256_hex(out),
        "size": len(out),
        "how": "Appendix A located by heading (pagination stripped); the hex octets after "
        "`BLAKE2b-512(\"abc\") =` collected and their count checked against 64.",
    }


# ---------------------------------------------------------------- BLAKE2 KAT


def import_blake2_kat(workdir: str) -> dict:
    raw = fetch(BLAKE2_KAT_URL, workdir)
    entries = json.loads(raw)
    cases = []
    for length in BLAKE2_KAT_INPUT_LENGTHS:
        found = [
            e
            for e in entries
            if e["hash"] == "blake2b" and not e["key"] and len(e["in"]) == 2 * length
        ]
        if len(found) != 1:
            sys.exit(f"BLAKE2 KAT: expected one unkeyed blake2b case of length {length}; "
                     f"found {len(found)}")
        e = found[0]
        if len(e["out"]) != 128:
            sys.exit(f"BLAKE2 KAT: blake2b output is not 64 bytes: {e['out']!r}")
        cases.append({"input": e["in"].lower(), "outLength": 64, "out": e["out"].lower()})
    name = "blake2b-kat.json"
    out = write_json(
        name,
        {
            "source": f"https://github.com/{BLAKE2_REPO}/blob/{BLAKE2_COMMIT}/testvectors/blake2-kat.json",
            "commit": BLAKE2_COMMIT,
            "sourceSha256": sha256_hex(raw),
            "retrieved": RETRIEVAL_DATE,
            "filter": "hash == blake2b, unkeyed, input lengths "
            + ", ".join(str(n) for n in BLAKE2_KAT_INPUT_LENGTHS),
            "encoding": "input and out are lowercase hex",
            "vectors": cases,
        },
    )
    return {
        "file": name,
        "url": BLAKE2_KAT_URL,
        "source_sha256": sha256_hex(raw),
        "stored_sha256": sha256_hex(out),
        "size": len(out),
        "how": "Parsed as JSON; unkeyed `blake2b` entries only, at input lengths "
        + ", ".join(str(n) for n in BLAKE2_KAT_INPUT_LENGTHS)
        + " bytes (exactly one entry each, checked); 64-byte outputs checked.",
    }


# ---------------------------------------------------------------- ACVP


def import_acvp(workdir: str) -> dict:
    prompt_raw = fetch(ACVP_PROMPT_URL, workdir)
    expected_raw = fetch(ACVP_EXPECTED_URL, workdir)
    prompt = json.loads(prompt_raw)
    expected = json.loads(expected_raw)
    algs = sorted({g["hmacAlg"] for g in prompt["testGroups"]})
    results = {
        (g["tgId"], t["tcId"]): t["derivedKey"]
        for g in expected["testGroups"]
        for t in g["tests"]
    }
    cases = []
    for g in sorted(prompt["testGroups"], key=lambda g: g["tgId"]):
        if g["hmacAlg"] != "SHA2-256":
            continue
        for t in sorted(g["tests"], key=lambda t: t["tcId"]):
            if t["iterationCount"] > ACVP_MAX_ITERATIONS:
                continue
            key = (g["tgId"], t["tcId"])
            if key not in results:
                sys.exit(f"ACVP: no expected result for tgId/tcId {key}")
            cases.append(
                {
                    "tgId": g["tgId"],
                    "tcId": t["tcId"],
                    "password": t["password"],
                    "salt": t["salt"].lower(),
                    "iterations": t["iterationCount"],
                    "keyLenBits": t["keyLen"],
                    "dk": results[key].lower(),
                }
            )
    cases = cases[:ACVP_MAX_CASES]
    info = {
        "url_prompt": ACVP_PROMPT_URL,
        "url_expected": ACVP_EXPECTED_URL,
        "prompt_sha256": sha256_hex(prompt_raw),
        "expected_sha256": sha256_hex(expected_raw),
        "hmac_algs": algs,
        "file": None,
    }
    name = "pbkdf2-sha256-acvp.json"
    path = os.path.join(OUT_DIR, name)
    if not cases:
        if os.path.exists(path):
            os.remove(path)
        return info
    out = write_json(
        name,
        {
            "source": f"https://github.com/{ACVP_REPO}/tree/{ACVP_COMMIT}/{ACVP_DIR}",
            "commit": ACVP_COMMIT,
            "retrieved": RETRIEVAL_DATE,
            "filter": f"hmacAlg == SHA2-256, iterationCount <= {ACVP_MAX_ITERATIONS}, "
            f"first {ACVP_MAX_CASES} by (tgId, tcId)",
            "encoding": "password is an ASCII string; salt and dk are lowercase hex",
            "vectors": cases,
        },
    )
    info.update(file=name, stored_sha256=sha256_hex(out), size=len(out))
    return info


# ---------------------------------------------------------------- provenance


def write_provenance(entries, acvp) -> None:
    with open(os.path.abspath(__file__), "rb") as f:
        script_sha = sha256_hex(f.read())
    cmd = "python3 -I Tests/SwiftIdentityTests/Vectors/import.py"
    lines = [
        "# Test Vector Provenance",
        "",
        "Every value in this directory was downloaded from its primary source and",
        "extracted by `import.py`. None was typed by hand. The script pins the",
        "SHA-256 of each source document and aborts on a mismatch, and its output",
        "is deterministic, so rerunning it reproduces these files byte for byte.",
        "",
        f"- Retrieval date: {RETRIEVAL_DATE}",
        f"- Command (from the package root): `{cmd}`",
        "  (this file is regenerated by the same command)",
        f"- `import.py` SHA-256 at generation: `{script_sha}`",
        "",
    ]
    for e in entries:
        lines += [
            f"## `{e['file']}`",
            "",
            f"- Source: <{e['url']}>",
            f"- Retrieved: {RETRIEVAL_DATE}",
            f"- Source document SHA-256: `{e['source_sha256']}`",
            f"- Stored file SHA-256: `{e['stored_sha256']}`",
            f"- Stored file size: {e['size']} bytes",
            f"- Produced by: `{cmd}`",
            f"- Extraction: {e['how']}",
            "",
        ]
    lines += [
        "## NIST ACVP PBKDF2 (`pbkdf2-sha256-acvp.json`)",
        "",
        f"- Repository: <https://github.com/{ACVP_REPO}>, commit `{ACVP_COMMIT}`",
        f"- prompt.json: <{acvp['url_prompt']}>",
        f"  - SHA-256: `{acvp['prompt_sha256']}`",
        f"- expectedResults.json: <{acvp['url_expected']}>",
        f"  - SHA-256: `{acvp['expected_sha256']}`",
        f"- Retrieved: {RETRIEVAL_DATE}",
        f"- hmacAlg values present in the sample: {', '.join(acvp['hmac_algs'])}",
    ]
    if acvp["file"] is None:
        lines += [
            "- **Not imported.** The PBKDF-1.0 sample vector set at this commit contains",
            "  no SHA2-256 test groups, so the SHA2-256 filter selects nothing and no",
            "  file is written. (Both historical revisions of `prompt.json` in the",
            "  repository were checked on the retrieval date; both are SHA2-224 only.)",
            "  SHA2-224 cases were deliberately not imported: SwiftIdentity uses",
            "  PBKDF2-HMAC-SHA-256.",
        ]
    else:
        lines += [
            f"- Stored file SHA-256: `{acvp['stored_sha256']}`",
            f"- Stored file size: {acvp['size']} bytes",
            f"- Produced by: `{cmd}`",
            "- Extraction: SHA2-256 groups only, joined to expectedResults.json by "
            f"(tgId, tcId), iterationCount <= {ACVP_MAX_ITERATIONS}, first "
            f"{ACVP_MAX_CASES} cases.",
        ]
    lines.append("")
    with open(os.path.join(OUT_DIR, "PROVENANCE.md"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines))


def main() -> None:
    workdir = tempfile.mkdtemp(prefix="swiftidentity-vectors-")
    try:
        entries = [
            import_unicode(workdir),
            import_rfc7914(workdir),
            import_rfc9106(workdir),
            import_rfc7693(workdir),
            import_blake2_kat(workdir),
        ]
        acvp = import_acvp(workdir)
        write_provenance(entries, acvp)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    main()
