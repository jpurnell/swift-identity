#!/usr/bin/env python3
"""Differential Argon2id cases from phc-winner-argon2, the reference implementation.

The second of the amendment's differential references (section 9), after OpenSSL's ARGON2ID KDF
(`generate.py`). It draws seeded cases and asks the phc-winner-argon2 `argon2` CLI for each tag,
then writes them to `Tests/SwiftIdentityTests/Vectors/argon2id-phc-winner-argon2.txt`, which the
Swift tests check case for case. Nothing in the vectors file is typed by hand; rerunning
reproduces it byte for byte with the same CLI.

What the CLI can't take shapes the cases:
  - no secret (K) or associated data (X), so every case has neither;
  - the salt is a command-line argument, so it can't contain a NUL byte, and must be at least
    8 bytes;
  - the password is read from stdin into a 128-byte buffer, so it's 1 to 127 bytes.

**It refuses to run unless the CLI first reproduces known answers.** RFC 9106's only Argon2id
vector uses K and X, which the CLI can't take. So the known answers are the cases of
`argon2id-differential.txt`, computed by OpenSSL's independent implementation, that the CLI can
express: no K or X, a password of 1 to 127 bytes, a salt with no NUL. Every one of them must come
back from the CLI with OpenSSL's tag, or nothing is written.

After the small seeded cases it adds a few at deployment parameters: OWASP's minimum
(m=19456 KiB, t=2, p=1) and RFC 9106's second recommendation (m=65536 KiB, t=3, p=4).

Run from the package root, in isolated mode:

    python3 -I Harness/Argon2id/generate-phc.py [--argon2 /path/to/argon2]
"""

import argparse
import os
import random
import re
import shutil
import subprocess
import sys

SEED = 20261023
CASES = 48
MAX_MEMORY_KIB = 256
# (m, t, p, how many): the deployment parameters the gate names.
DEPLOYMENT = ((19456, 2, 1, 2), (65536, 3, 4, 2))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
VECTORS = os.path.join(ROOT, "Tests", "SwiftIdentityTests", "Vectors")
OUT = os.path.join(VECTORS, "argon2id-phc-winner-argon2.txt")
KNOWN = os.path.join(VECTORS, "argon2id-differential.txt")
TAG_LENGTHS = (4, 16, 32, 32, 32, 63, 64, 65, 100, 128)
MAX_PASSWORD = 127


class Argon2CLI:
    def __init__(self, path):
        self.path = path
        self.version = version_of(path)

    def tag(self, password, salt, m, t, p, length):
        if not 1 <= len(password) <= MAX_PASSWORD or b"\0" in salt or len(salt) < 8:
            raise ValueError("the argon2 CLI can't express this case")
        result = subprocess.run(
            [self.path.encode(), salt, b"-id", b"-t", str(t).encode(), b"-k", str(m).encode(),
             b"-p", str(p).encode(), b"-l", str(length).encode(), b"-r"],
            input=password, capture_output=True, check=True)
        tag = bytes.fromhex(result.stdout.decode("ascii").strip())
        if len(tag) != length:
            sys.exit(f"the CLI returned {len(tag)} bytes, not {length}")
        return tag


def version_of(path):
    """The installed version. The CLI has no --version, so it's read from the install."""
    real = os.path.realpath(path)
    match = re.search(r"/Cellar/argon2/([^/]+)/", real)
    if match:
        return f"Homebrew argon2 {match.group(1)} ({real})"
    brew = shutil.which("brew")
    if brew:
        listed = subprocess.run([brew, "list", "--versions", "argon2"], capture_output=True, text=True)
        if listed.returncode == 0 and listed.stdout.strip():
            return f"{listed.stdout.strip()} ({real})"
    sys.exit(f"can't determine the version of {real}; record it before generating")


def known_answers(cli):
    """Every OpenSSL case the CLI can express must come back with OpenSSL's tag."""
    checked = 0
    with open(KNOWN, encoding="ascii") as handle:
        header = [line.strip() for line in handle if line.startswith("#")]
    with open(KNOWN, encoding="ascii") as handle:
        for line in handle:
            if line.startswith("#"):
                continue
            fields = line.strip().split(";")
            password, salt, secret, ad = (bytes.fromhex(field) for field in fields[:4])
            m, t, p, length = (int(field) for field in fields[4:8])
            if secret or ad or not 1 <= len(password) <= MAX_PASSWORD or b"\0" in salt:
                continue
            tag = cli.tag(password, salt, m, t, p, length)
            if tag.hex() != fields[8]:
                sys.exit(f"the CLI disagrees with OpenSSL on {line.strip()}: {tag.hex()}")
            checked += 1
    if checked < 8:
        sys.exit(f"only {checked} known answers could be checked; refusing to generate")
    reference = next((line for line in header if line.startswith("# Reference:")), "# Reference: ?")
    return checked, reference[len("# Reference: "):].rstrip(".")


def draw_password(rng, short):
    length = rng.choice((1, 5, 16, 32, 64, 100, 127)) if not short else rng.choice((8, 16, 28))
    return rng.randbytes(length)


def draw_salt(rng):
    return bytes(rng.randint(1, 255) for _ in range(rng.choice((8, 16, 16, 32))))


def draw(rng):
    p = rng.choice((1, 1, 1, 2, 3, 4))
    m = rng.randint(8 * p, MAX_MEMORY_KIB)
    t = rng.choice((1, 1, 2, 3))
    return draw_password(rng, False), draw_salt(rng), m, t, p, rng.choice(TAG_LENGTHS)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--argon2", help="the phc-winner-argon2 `argon2` CLI to use")
    args = parser.parse_args()
    path = args.argon2 or shutil.which("argon2")
    if not path:
        sys.exit("no `argon2` CLI: install phc-winner-argon2 (`brew install argon2`)")
    cli = Argon2CLI(path)
    checked, openssl = known_answers(cli)

    rng = random.Random(SEED)
    cases = [draw(rng) for _ in range(CASES)]
    for m, t, p, count in DEPLOYMENT:
        for _ in range(count):
            cases.append((draw_password(rng, True), draw_salt(rng), m, t, p, 32))

    deployment = ", ".join(f"{n} at m={m} t={t} p={p}" for m, t, p, n in DEPLOYMENT)
    lines = [
        "# Differential Argon2id cases: password;salt;secret;ad;m;t;p;tagLength;tag",
        "# Byte strings are lowercase hex (empty for none); m is KiB, t passes, p lanes.",
        f"# Generator: Harness/Argon2id/generate-phc.py, seed {SEED}, {CASES} cases with "
        f"m <= {MAX_MEMORY_KIB} KiB, then {deployment}.",
        f"# Reference: phc-winner-argon2, the `argon2` CLI, {cli.version}.",
        "# The CLI takes no secret or associated data, so no case has either.",
        f"# Known answers through the reference: all {checked} cases of argon2id-differential.txt "
        f"it can express ({openssl}), reproduced.",
    ]
    for password, salt, m, t, p, length in cases:
        tag = cli.tag(password, salt, m, t, p, length)
        lines.append(";".join([password.hex(), salt.hex(), "", "", str(m), str(t), str(p),
                               str(length), tag.hex()]))
    with open(OUT, "w", encoding="ascii", newline="\n") as handle:
        handle.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
