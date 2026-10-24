#!/usr/bin/env python3
"""Differential Argon2id cases from mimiclone/argon2-swift, an independent Swift implementation.

The third differential reference for the amendment's gate (section 9), after OpenSSL
(`Harness/Argon2id/generate.py`) and phc-winner-argon2 (`Harness/Argon2id/generate-phc.py`).
argon2-swift is pure Swift with its own BLAKE2b and wraps no C, so it shares no code with either
of those or with this package. It's built by the package beside this script, which pins it to an
exact revision and is never a dependency of SwiftIdentity.

This draws seeded cases (password, salt, secret, associated data, m, t, p, tag length), runs the
`argon2-swift-tags` executable over them, and writes
`Tests/SwiftIdentityTests/Vectors/argon2id-argon2-swift.txt`, which the Swift tests check case for
case. Nothing in the vectors file is typed by hand; rerunning reproduces it byte for byte.

argon2-swift takes a secret and associated data, so before generating anything it must reproduce
RFC 9106 section 5.3, from the package's imported vector, or the script stops. After the small
cases it adds a few at deployment parameters: m=19456 KiB, t=2, p=1 and m=65536 KiB, t=3, p=4.

Run from the package root, in isolated mode:

    python3 -I Harness/Argon2idSwift/generate.py [--tags /path/to/argon2-swift-tags]

Without `--tags` it builds the executable in release first.
"""

import argparse
import json
import os
import random
import re
import subprocess
import sys

SEED = 20261024
CASES = 48
MAX_MEMORY_KIB = 256
DEPLOYMENT = ((19456, 2, 1, 2), (65536, 3, 4, 2))
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
VECTORS = os.path.join(ROOT, "Tests", "SwiftIdentityTests", "Vectors")
OUT = os.path.join(VECTORS, "argon2id-argon2-swift.txt")
RFC_VECTOR = os.path.join(VECTORS, "argon2id-rfc9106.json")
TAG_LENGTHS = (4, 16, 32, 32, 32, 63, 64, 65, 100, 128)


def build():
    subprocess.run(["swift", "build", "-c", "release", "--package-path", HERE], check=True)
    path = subprocess.run(["swift", "build", "-c", "release", "--package-path", HERE, "--show-bin-path"],
                          capture_output=True, text=True, check=True).stdout.strip()
    return os.path.join(path, "argon2-swift-tags")


def pinned_revision():
    """The revision Package.swift pins, which is what was built."""
    with open(os.path.join(HERE, "Package.swift"), encoding="utf-8") as handle:
        match = re.search(r'revision: "([0-9a-f]{40})"', handle.read())
    if not match:
        sys.exit("Package.swift pins no exact revision")
    return match.group(1)


def swift_version():
    output = subprocess.run(["swift", "--version"], capture_output=True, text=True, check=True)
    text = output.stdout + output.stderr
    match = re.search(r"Apple Swift version [^\s]+|Swift version [^\s]+", text)
    return match.group(0) if match else "unknown"


def tags(executable, cases):
    lines = "".join(";".join([password.hex(), salt.hex(), secret.hex(), ad.hex(), str(m), str(t),
                              str(p), str(length)]) + "\n"
                    for password, salt, secret, ad, m, t, p, length in cases)
    result = subprocess.run([executable], input=lines.encode("ascii"), capture_output=True, check=True)
    out = result.stdout.decode("ascii").split()
    if len(out) != len(cases):
        sys.exit(f"argon2-swift returned {len(out)} tags for {len(cases)} cases")
    for tag, case in zip(out, cases):
        if len(tag) != 2 * case[-1]:
            sys.exit(f"argon2-swift returned a tag of {len(tag) // 2} bytes, not {case[-1]}")
    return out


def check_rfc_vector(executable):
    with open(RFC_VECTOR, encoding="ascii") as handle:
        vector = json.load(handle)["vectors"][0]
    case = (bytes.fromhex(vector["password"]), bytes.fromhex(vector["salt"]),
            bytes.fromhex(vector["secret"]), bytes.fromhex(vector["associatedData"]),
            vector["memoryKiB"], vector["passes"], vector["lanes"], vector["tagLength"])
    tag = tags(executable, [case])[0]
    if tag != vector["tag"]:
        sys.exit(f"argon2-swift does not reproduce RFC 9106 5.3: {tag}")


def draw(rng):
    p = rng.choice((1, 1, 1, 2, 3, 4))
    m = rng.randint(8 * p, MAX_MEMORY_KIB)
    t = rng.choice((1, 1, 2, 3))
    password = rng.randbytes(rng.choice((0, 1, 5, 16, 32, 64, 100)))
    salt = rng.randbytes(rng.choice((8, 16, 16, 32)))
    secret = rng.randbytes(rng.choice((1, 8, 32))) if rng.random() < 0.25 else b""
    ad = rng.randbytes(rng.choice((1, 12, 40))) if rng.random() < 0.25 else b""
    return password, salt, secret, ad, m, t, p, rng.choice(TAG_LENGTHS)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tags", help="a built argon2-swift-tags executable")
    args = parser.parse_args()
    executable = args.tags or build()
    check_rfc_vector(executable)

    rng = random.Random(SEED)
    cases = [draw(rng) for _ in range(CASES)]
    for m, t, p, count in DEPLOYMENT:
        for _ in range(count):
            cases.append((rng.randbytes(16), rng.randbytes(16), b"", b"", m, t, p, 32))

    deployment = ", ".join(f"{n} at m={m} t={t} p={p}" for m, t, p, n in DEPLOYMENT)
    lines = [
        "# Differential Argon2id cases: password;salt;secret;ad;m;t;p;tagLength;tag",
        "# Byte strings are lowercase hex (empty for none); m is KiB, t passes, p lanes.",
        f"# Generator: Harness/Argon2idSwift/generate.py, seed {SEED}, {CASES} cases with "
        f"m <= {MAX_MEMORY_KIB} KiB, then {deployment}.",
        f"# Reference: mimiclone/argon2-swift at revision {pinned_revision()} (tag v1.0.4), "
        f"pure Swift, built in release with {swift_version()}.",
        "# RFC 9106 section 5.3 through the reference: reproduced.",
    ]
    for case, tag in zip(cases, tags(executable, cases)):
        password, salt, secret, ad, m, t, p, length = case
        lines.append(";".join([password.hex(), salt.hex(), secret.hex(), ad.hex(), str(m), str(t),
                               str(p), str(length), tag]))
    with open(OUT, "w", encoding="ascii", newline="\n") as handle:
        handle.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
