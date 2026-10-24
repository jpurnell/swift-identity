#!/usr/bin/env python3
"""Differential Argon2id cases from an independent implementation.

The amendment's gate for Argon2id (section 9) asks for differential runs against independent
implementations, in a separate harness that is never a package dependency. This is that harness.
It draws seeded cases (password, salt, secret, associated data, m, t, p, tag length) and asks a
reference for each tag, then writes them to
`Tests/SwiftIdentityTests/Vectors/argon2id-differential.txt`, which the Swift tests check case
for case. Nothing in the vectors file is typed by hand; rerunning reproduces it byte for byte
with the same reference.

The reference is the first of these that is available, in this order:
  1. OpenSSL 3.2 or later (`--openssl`, or `openssl` on PATH), whose ARGON2ID KDF is its own C
     implementation. Preferred because it is the only one here that takes a secret (K) and
     associated data (X), so those inputs get differential cases too;
  2. `argon2-cffi`, the Python binding to phc-winner-argon2, the reference implementation;
  3. the `argon2` CLI from phc-winner-argon2.
With either of the last two, cases are drawn without K or X. Before generating anything a
reference that takes K and X must reproduce the RFC 9106 section 5.3 tag, from the package's
imported vector, or the script stops.

Run from the package root, in isolated mode:

    python3 -I Harness/Argon2id/generate.py [--openssl /path/to/openssl]
"""

import argparse
import json
import os
import random
import shutil
import subprocess
import sys

SEED = 20261022
CASES = 64
MAX_MEMORY_KIB = 256
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
VECTORS = os.path.join(ROOT, "Tests", "SwiftIdentityTests", "Vectors")
OUT = os.path.join(VECTORS, "argon2id-differential.txt")
RFC_VECTOR = os.path.join(VECTORS, "argon2id-rfc9106.json")
# Tag lengths around H's 64-byte boundary, where H' changes shape, and the scheme's 32.
TAG_LENGTHS = (4, 16, 32, 32, 32, 63, 64, 65, 100, 128)


class OpenSSL:
    def __init__(self, path):
        self.path = path
        self.supports_secret = True
        version = subprocess.run([path, "version"], capture_output=True, text=True, check=True)
        self.description = f"the ARGON2ID KDF of {version.stdout.strip()}"

    def tag(self, password, salt, secret, ad, m, t, p, length):
        args = [self.path, "kdf", "-keylen", str(length), "-binary",
                "-kdfopt", f"hexpass:{password.hex()}", "-kdfopt", f"hexsalt:{salt.hex()}",
                "-kdfopt", f"iter:{t}", "-kdfopt", f"memcost:{m}", "-kdfopt", f"lanes:{p}"]
        # OpenSSL refuses an empty hex option, so absent K and X are left out, which is the same.
        if secret:
            args += ["-kdfopt", f"hexsecret:{secret.hex()}"]
        if ad:
            args += ["-kdfopt", f"hexad:{ad.hex()}"]
        args.append("ARGON2ID")
        result = subprocess.run(args, capture_output=True, check=True)
        if len(result.stdout) != length:
            sys.exit(f"OpenSSL returned {len(result.stdout)} bytes, not {length}")
        return result.stdout


class Argon2CLI:
    def __init__(self, path):
        self.path = path
        self.supports_secret = False
        self.description = "the phc-winner-argon2 `argon2` CLI"

    def tag(self, password, salt, secret, ad, m, t, p, length):
        if secret or ad or (m & (m - 1)):
            raise ValueError("the argon2 CLI takes no K or X, and memory only as a power of two")
        result = subprocess.run(
            [self.path, salt.decode("latin-1"), "-id", "-t", str(t), "-k", str(m), "-p", str(p),
             "-l", str(length), "-r"],
            input=password, capture_output=True, check=True)
        return bytes.fromhex(result.stdout.decode().strip())


class Argon2CFFI:
    def __init__(self, module):
        self.module = module
        self.supports_secret = False
        self.description = f"argon2-cffi {module.__version__ if hasattr(module, '__version__') else '?'}"

    def tag(self, password, salt, secret, ad, m, t, p, length):
        if secret or ad:
            raise ValueError("argon2-cffi's low-level API takes no K or X")
        return self.module.low_level.hash_secret_raw(
            password, salt, time_cost=t, memory_cost=m, parallelism=p, hash_len=length,
            type=self.module.low_level.Type.ID)


def find_reference(openssl):
    if openssl:
        return OpenSSL(openssl)
    path = shutil.which("openssl")
    if path and probe(OpenSSL(path)):
        return OpenSSL(path)
    try:
        import argon2
        return Argon2CFFI(argon2)
    except ImportError:
        pass
    path = shutil.which("argon2")
    if path:
        return Argon2CLI(path)
    sys.exit("no Argon2id reference: install OpenSSL 3.2+ (`brew install openssl@3`), "
             "argon2-cffi (`pip3 install argon2-cffi`), or phc-winner-argon2 (`brew install argon2`)")


def probe(reference):
    try:
        reference.tag(b"p", b"saltsalt", b"", b"", 8, 1, 1, 32)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def check_rfc_vector(reference):
    """The reference must reproduce RFC 9106 section 5.3 before it judges anything."""
    with open(RFC_VECTOR, encoding="ascii") as handle:
        vector = json.load(handle)["vectors"][0]
    secret = bytes.fromhex(vector["secret"]) if reference.supports_secret else None
    if secret is None:
        return "not checked (this reference takes no secret or associated data)"
    tag = reference.tag(
        bytes.fromhex(vector["password"]), bytes.fromhex(vector["salt"]), secret,
        bytes.fromhex(vector["associatedData"]), vector["memoryKiB"], vector["passes"],
        vector["lanes"], vector["tagLength"])
    if tag.hex() != vector["tag"]:
        sys.exit(f"the reference does not reproduce RFC 9106 5.3: {tag.hex()}")
    return "reproduced"


def draw(rng, supports_secret):
    p = rng.choice((1, 1, 1, 2, 3, 4))
    m = rng.randint(8 * p, MAX_MEMORY_KIB)
    t = rng.choice((1, 1, 2, 3))
    password = rng.randbytes(rng.choice((0, 1, 5, 16, 32, 64, 100)))
    salt = rng.randbytes(rng.choice((8, 16, 16, 32)))
    secret = b""
    ad = b""
    if supports_secret and rng.random() < 0.25:
        secret = rng.randbytes(rng.choice((1, 8, 32)))
    if supports_secret and rng.random() < 0.25:
        ad = rng.randbytes(rng.choice((1, 12, 40)))
    return password, salt, secret, ad, m, t, p, rng.choice(TAG_LENGTHS)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--openssl", help="an OpenSSL 3.2+ binary to use as the reference")
    args = parser.parse_args()
    reference = find_reference(args.openssl)
    rfc = check_rfc_vector(reference)

    rng = random.Random(SEED)
    lines = [
        "# Differential Argon2id cases: password;salt;secret;ad;m;t;p;tagLength;tag",
        "# Byte strings are lowercase hex (empty for none); m is KiB, t passes, p lanes.",
        f"# Generator: Harness/Argon2id/generate.py, seed {SEED}, {CASES} cases, m <= {MAX_MEMORY_KIB} KiB.",
        f"# Reference: {reference.description}.",
        f"# RFC 9106 section 5.3 through the reference: {rfc}.",
    ]
    for _ in range(CASES):
        password, salt, secret, ad, m, t, p, length = draw(rng, reference.supports_secret)
        tag = reference.tag(password, salt, secret, ad, m, t, p, length)
        lines.append(";".join([password.hex(), salt.hex(), secret.hex(), ad.hex(),
                               str(m), str(t), str(p), str(length), tag.hex()]))
    with open(OUT, "w", encoding="ascii", newline="\n") as handle:
        handle.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
