"""Differential NFC cases from an independent implementation: CPython's unicodedata.

Writes `differential-nfc-python.txt`: one case per line, `input;expected` as space-separated hex
scalars, under a header recording the generator. The inputs are drawn with a fixed seed from
characters assigned in Unicode 15.0 (the package's pin), weighted towards the ones normalization
actually changes: combining marks, Hangul jamo and syllables, and characters with a canonical
decomposition. Nothing here is typed by hand; rerunning reproduces the file byte for byte, as long
as the Python reports the same Unicode version (checked below).

Run from the package root:  python3 -I Tests/SwiftIdentityTests/Vectors/differential-nfc.py
"""

import os
import random
import sys
import unicodedata

SEED = 20261022
CASES = 20000
PIN = (15, 0)
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "differential-nfc-python.txt")
DERIVED_AGE = os.path.join(HERE, "NormalizationTest-15.0.0.txt")


def assigned_in_pin():
    """Code points that normalization affects, as of Unicode 15.0.

    Python can't report a character's age, and its tables are newer than the pin. So the
    normalizing pool is every code point named in NormalizationTest-15.0.0.txt, which by
    construction were assigned in 15.0. The other pools (ASCII, Cyrillic, Hebrew, Thai, Hangul)
    are ranges assigned long before it.
    """
    pool = set()
    with open(DERIVED_AGE, encoding="utf-8") as handle:
        for line in handle:
            if line.startswith(("#", "@")) or ";" not in line:
                continue
            for field in line.split(";")[:5]:
                for token in field.split():
                    pool.add(int(token, 16))
    return sorted(pool)


def main():
    major, minor, _ = (int(part) for part in unicodedata.unidata_version.split("."))
    if (major, minor) < PIN:
        sys.exit(f"Python's Unicode {unicodedata.unidata_version} is older than the pin {PIN}")

    normalizing = assigned_in_pin()
    combining = [c for c in normalizing if unicodedata.combining(chr(c)) > 0]
    hangul = list(range(0x1100, 0x1113)) + list(range(0x1161, 0x1176)) + list(range(0x11A8, 0x11C3)) \
        + list(range(0xAC00, 0xAC00 + 600))
    plain = list(range(0x21, 0x7F)) + list(range(0x400, 0x450)) + list(range(0x5D0, 0x5EB)) \
        + list(range(0xE01, 0xE3B))

    rng = random.Random(SEED)
    pools = [(normalizing, 4), (combining, 3), (hangul, 3), (plain, 2)]
    weighted = [pool for pool, weight in pools for _ in range(weight)]

    lines = [
        "# Differential NFC cases: input;expected, hex scalars.",
        f"# Generator: differential-nfc.py, seed {SEED}, {CASES} cases.",
        f"# Expected values: CPython {sys.version.split()[0]} unicodedata.normalize('NFC'),"
        f" Unicode {unicodedata.unidata_version}.",
        "# Inputs drawn only from characters that predate Unicode 15.0 (see the script).",
    ]
    for _ in range(CASES):
        length = rng.randint(1, 8)
        scalars = [rng.choice(rng.choice(weighted)) for _ in range(length)]
        text = "".join(chr(s) for s in scalars)
        expected = unicodedata.normalize("NFC", text)
        lines.append(
            " ".join(f"{s:04X}" for s in scalars) + ";" + " ".join(f"{ord(c):04X}" for c in expected)
        )

    with open(OUT, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
