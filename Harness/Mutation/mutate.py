#!/usr/bin/env python3
"""Mutation testing for SwiftIdentity, without a mutation tool.

Run from the package root with an isolated interpreter:

    python3 -I Harness/Mutation/mutate.py --seed 20261023            # every target
    python3 -I Harness/Mutation/mutate.py --only PassphraseVerifier   # one target
    python3 -I Harness/Mutation/mutate.py --list                      # generate, don't run
    python3 -I Harness/Mutation/mutate.py --mutant <id>               # rerun one mutant

Each mutant is written over the real source file, built (`swift build --build-tests`) and
tested (`swift test --skip-build --filter <suites>`). The original is restored byte for byte in
a `finally`, and the restore is verified by SHA-256 before the next mutant starts; a mismatch
stops the run. A mutant that doesn't compile is *stillborn*, not killed.

Standard library only. See README.md beside this file.
"""

from __future__ import annotations

import argparse
import atexit
import dataclasses
import difflib
import hashlib
import json
import os
import random
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = Path(__file__).resolve().parent

# Target file -> the `swift test --filter` regex (Swift Testing matches it against the test ID,
# which is `SwiftIdentityTests.<TypeName>/<function>`, so these are type names, not display names).
TARGETS: dict[str, str] = {
    "Sources/SwiftIdentity/Credential/PassphraseVerifier.swift":
        "PassphraseVerifierTests|PassphraseWorkFactorTests|PassphraseSchemeTests|PepperTests",
    "Sources/SwiftIdentity/Credential/PassphraseScheme.swift":
        "PassphraseVerifierTests|PassphraseWorkFactorTests|PassphraseSchemeTests|PepperTests",
    "Sources/SwiftIdentity/Credential/PassphraseCanonicalization.swift":
        "PassphraseCanonicalizationTests|NormalizationConformanceTests",
    "Sources/SwiftIdentity/Authentication/Authenticator.swift":
        "AuthenticatorTests|FileCredentialStoreOneTimeCodeTests",
    "Sources/SwiftIdentity/Store/ThrottleLedger.swift":
        "ThrottleLedgerTests|FileThrottleLedgerTests|ThrottleLedgerConformanceTests|FailureThrottle",
    "Sources/SwiftIdentity/Store/FileThrottleLedger.swift":
        "ThrottleLedgerTests|FileThrottleLedgerTests|ThrottleLedgerConformanceTests|FailureThrottle",
    "Sources/SwiftIdentity/Credential/Argon2id.swift": "Argon2id|BLAKE2bTests",
    "Sources/SwiftIdentity/Credential/BLAKE2b.swift": "Argon2id|BLAKE2bTests",
    "Sources/SwiftIdentity/Credential/OneTimeCode.swift":
        "OneTimeCodeTests|FileCredentialStoreOneTimeCodeTests",
    "Sources/SwiftIdentity/Credential/PassphrasePolicy.swift": "PassphrasePolicy",
}

BUILD_TIMEOUT = 15 * 60
TEST_TIMEOUT = 5 * 60
PER_FILE = 25

# ---------------------------------------------------------------------------------------------
# Lexing: which characters of each line are code
# ---------------------------------------------------------------------------------------------


def code_masks(lines: list[str]) -> list[list[bool]]:
    """For every character, whether it is code: not a comment, not inside a string literal.

    Handles `//`, nested `/* */`, `"…"` with escapes, `\"\"\"` multi-line strings and raw `#"…"#`
    strings. An interpolation `\\(…)` inside a string counts as string: mutating inside it is
    legal Swift but rarely meaningful, and excluding it keeps the lexer honest.
    """
    masks: list[list[bool]] = []
    block_depth = 0
    in_multiline: str | None = None  # the closing delimiter, e.g. '"""' or '"""#'
    for line in lines:
        mask = [False] * len(line)
        i = 0
        n = len(line)
        while i < n:
            if in_multiline is not None:
                end = line.find(in_multiline, i)
                if end < 0:
                    i = n
                    break
                i = end + len(in_multiline)
                in_multiline = None
                continue
            if block_depth > 0:
                if line.startswith("/*", i):
                    block_depth += 1
                    i += 2
                elif line.startswith("*/", i):
                    block_depth -= 1
                    i += 2
                else:
                    i += 1
                continue
            if line.startswith("//", i):
                break
            if line.startswith("/*", i):
                block_depth = 1
                i += 2
                continue
            m = re.match(r'(#*)"""', line[i:])
            if m:
                in_multiline = '"""' + m.group(1)
                i += len(m.group(0))
                continue
            m = re.match(r'(#*)"', line[i:])
            if m:
                hashes = m.group(1)
                closing = '"' + hashes
                j = i + len(m.group(0))
                while j < n:
                    if not hashes and line[j] == "\\":
                        j += 2
                        continue
                    if line.startswith(closing, j):
                        j += len(closing)
                        break
                    j += 1
                i = j
                continue
            mask[i] = True
            i += 1
        masks.append(mask)
    return masks


def all_code(mask: list[bool], start: int, end: int) -> bool:
    return end <= len(mask) and all(mask[start:end])


# ---------------------------------------------------------------------------------------------
# Mutants
# ---------------------------------------------------------------------------------------------


@dataclasses.dataclass
class Mutant:
    id: str
    file: str
    line: int  # 1-based
    operator: str
    original: str  # the original line
    mutated: str  # the replacement line ('' for a deletion keeps the line count)
    description: str
    status: str = "pending"  # killed | survived | stillborn | timeout | pending
    seconds: float = 0.0
    detail: str = ""

    def diff(self) -> str:
        a = [self.original + "\n"]
        b = [self.mutated + "\n"]
        return "".join(difflib.unified_diff(a, b, f"a/{self.file}:{self.line}", f"b/{self.file}:{self.line}"))


SKIP_LINE = re.compile(r"^\s*(#if|#elseif|#else|#endif|import\s|@available|@_|#warning|#error)")
KEYWORD_START = re.compile(
    r"^(let|var|guard|if|else|return|case|default|switch|for|while|repeat|throw|func|init|deinit|"
    r"struct|class|enum|actor|extension|protocol|typealias|public|private|internal|fileprivate|"
    r"static|nonisolated|@|\}|\{|\)|\]|defer|do|catch|break|continue|fallthrough|where|#|\.|\+|-|\||&|\?|:)"
)


def sub_ops(line: str, mask: list[bool], pattern: str, table: dict[str, list[str]], operator: str):
    """Yield (mutated_line, description) for each code-position match of `pattern`."""
    for m in re.finditer(pattern, line):
        tok = m.group("op")
        s, e = m.start("op"), m.end("op")
        if not all_code(mask, s, e):
            continue
        for rep in table.get(tok, []):
            yield line[:s] + rep + line[e:], f"{tok} -> {rep} (col {s + 1})", operator


def balanced(text: str) -> bool:
    depth = 0
    for ch in text:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


def code_only(line: str, mask: list[bool]) -> str:
    return "".join(ch if mask[i] else ("S" if ch != " " else " ") for i, ch in enumerate(line))


def generate(rel: str) -> list[Mutant]:
    path = ROOT / rel
    lines = path.read_text(encoding="utf-8").split("\n")
    masks = code_masks(lines)
    out: list[Mutant] = []
    stem = Path(rel).stem

    guard_body = False  # inside the `{ … }` of a multi-line `guard … else {`
    guard_open = False  # inside a multi-line guard condition, waiting for `else {`
    for idx, line in enumerate(lines):
        mask = masks[idx]
        if SKIP_LINE.match(line) or not any(mask):
            continue
        stripped_code = code_only(line, mask).strip()
        cands: list[tuple[str, str, str]] = []

        # relational: only binary operators, which Swift requires to be space-delimited here
        rel_table = {"==": ["!="], "!=": ["=="], "<": ["<=", ">"], "<=": ["<"], ">": [">=", "<"], ">=": [">"]}
        cands += sub_ops(line, mask, r"(?<= )(?P<op>==|!=|<=|>=|<|>)(?= )", rel_table, "relational")
        # boolean literals
        cands += sub_ops(line, mask, r"\b(?P<op>true|false)\b", {"true": ["false"], "false": ["true"]}, "boolean")
        # logical
        cands += sub_ops(line, mask, r"(?<= )(?P<op>&&|\|\|)(?= )", {"&&": ["||"], "||": ["&&"]}, "logical")
        # negation: a prefix `!` (not `!=`, not a postfix force unwrap)
        for m in re.finditer(r"(?<=[\s(\[,])(?P<op>!)(?=[A-Za-z_(.$])", line):
            s = m.start("op")
            if all_code(mask, s, s + 1):
                cands.append((line[:s] + line[s + 1:], f"drop prefix ! (col {s + 1})", "negation"))
        # arithmetic, including the wrapping operators BLAKE2b and Argon2id are built from
        arith = {"+": ["-"], "-": ["+"], "*": ["/"], "/": ["*"], "&+": ["&-"], "&-": ["&+"], "&*": ["&+"]}
        # Not beside a string literal: `"…" + "…"` mutated to `-` can only ever be stillborn.
        for mutated, desc, op in sub_ops(line, mask, r"(?<= )(?P<op>&\+|&-|&\*|\+|-|\*|/)(?= )", arith, "arithmetic"):
            col = int(re.search(r"col (\d+)", desc).group(1)) - 1
            width = len(desc.split(" -> ")[0])
            before = line[:col].rstrip()
            after_at = col + width + 1
            if (before and not mask[len(before) - 1]) or (after_at < len(line) and not mask[after_at]):
                continue
            cands.append((mutated, desc, op))
        for m in re.finditer(r"(?P<op>(\+|-|&\+)= 1)\b", line):
            s, e = m.start("op"), m.end("op")
            if all_code(mask, s, e):
                cands.append((line[:s] + m.group("op")[:-1] + "0" + line[e:], f"{m.group('op')} -> {m.group('op')[:-1]}0", "arithmetic"))
        # integer constants: small decimal literals, not part of an identifier, a float, or hex
        for m in re.finditer(r"(?<![\w.$])(?P<op>\d+)(?![\w.]|\.\d)", line):
            s, e = m.start("op"), m.end("op")
            if not all_code(mask, s, e):
                continue
            value = int(m.group("op"))
            if value > 64:
                continue
            cands.append((line[:s] + str(value + 1) + line[e:], f"{value} -> {value + 1} (col {s + 1})", "constant"))

        # early return in a guard's else
        in_guard_else = False
        if re.search(r"\bguard\b", stripped_code) and re.search(r"\belse\s*\{.*\breturn\b", stripped_code):
            in_guard_else = True
        elif guard_body:
            in_guard_else = True
        if in_guard_else:
            m = re.search(r"\breturn\s+(?P<op>true|false|nil|0|1|\.\w+)\s*(\}|$)", line)
            if m and all_code(mask, m.start("op"), m.end("op")):
                s, e = m.start("op"), m.end("op")
                swaps = {"true": ["false"], "false": ["true"], "0": ["1"], "1": ["0"], "nil": []}
                reps = swaps.get(m.group("op"), [])
                for rep in reps:
                    cands.append((line[:s] + rep + line[e:], f"guard else: return {m.group('op')} -> {rep}", "early-return"))

        # statement deletion: one complete call or assignment statement on one line
        sc = stripped_code
        if sc and not KEYWORD_START.match(sc) and balanced(sc) and not sc.endswith(("{", "(", ",", "[", ".", "&&", "||", "+", "=")):
            is_assign = re.match(r"^[\w.\[\]\s$S]+?\s(=|\+=|-=|\*=|/=|\^=|\|=|&=|<<=|>>=|&\+=|&-=)\s.+$", sc)
            is_call = re.match(r"^(try\s+|await\s+|try\?\s+)*[\w.$]+(\[[^\]]*\])?(\.[\w]+)*\(.*\)$", sc)
            # Not `self.x = …` or `self.init(…)`: deleting a stored property's only assignment, or
            # the delegating init, can't compile, so it would only ever be stillborn. Not a line
            # the next line continues (`Logger(…)` then `.fault(…)`).
            continues = idx + 1 < len(lines) and lines[idx + 1].lstrip().startswith(".")
            initializes = re.match(r"^(try\s+)?(self|super)\.(init\(|\w+\s=\s)", sc)
            if (is_assign or is_call) and not initializes and not continues:
                indent = line[: len(line) - len(line.lstrip())]
                cands.append((indent, "delete statement", "deletion"))

        # guard-state bookkeeping for the next line
        if guard_body:
            if "}" in stripped_code:
                guard_body = False
        if re.search(r"\bguard\b", stripped_code):
            guard_open = True
        if guard_open and re.search(r"\belse\s*\{\s*$", stripped_code):
            guard_body = True
            guard_open = False
        elif guard_open and re.search(r"\belse\s*\{.*\}", stripped_code):
            guard_open = False

        # One mutant per distinct mutated line. `return false` in a guard's else is both a
        # boolean literal and an early return; it is reported once, as the early return.
        cands.sort(key=lambda c: c[2] != "early-return")
        seen = set()
        for mutated, desc, op in cands:
            if mutated == line or mutated in seen:
                continue
            seen.add(mutated)
            out.append(Mutant(
                id=f"{stem}-{idx + 1}-{op}-{len(out)}", file=rel, line=idx + 1, operator=op,
                original=line, mutated=mutated, description=desc,
            ))
    return out


def sample(mutants: list[Mutant], rng: random.Random, cap: int) -> list[Mutant]:
    """At most `cap` mutants, round-robin across operators so each one is represented."""
    by_op: dict[str, list[Mutant]] = {}
    for m in mutants:
        by_op.setdefault(m.operator, []).append(m)
    for group in by_op.values():
        rng.shuffle(group)
    ops = sorted(by_op)
    chosen: list[Mutant] = []
    while len(chosen) < cap and any(by_op.values()):
        for op in ops:
            if by_op[op] and len(chosen) < cap:
                chosen.append(by_op[op].pop())
    return sorted(chosen, key=lambda m: (m.line, m.id))


# ---------------------------------------------------------------------------------------------
# Running
# ---------------------------------------------------------------------------------------------

_PENDING_RESTORE: dict[Path, bytes] = {}


def _restore_all() -> None:
    for path, data in list(_PENDING_RESTORE.items()):
        path.write_bytes(data)
        if hashlib.sha256(path.read_bytes()).hexdigest() == hashlib.sha256(data).hexdigest():
            del _PENDING_RESTORE[path]


def _on_signal(signum, frame):  # noqa: ARG001
    _restore_all()
    sys.exit(128 + signum)


atexit.register(_restore_all)
signal.signal(signal.SIGINT, _on_signal)
signal.signal(signal.SIGTERM, _on_signal)
signal.signal(signal.SIGHUP, _on_signal)


def run(cmd: list[str], timeout: int) -> tuple[int | None, str, float]:
    start = time.monotonic()
    proc = subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, start_new_session=True)
    try:
        out, _ = proc.communicate(timeout=timeout)
        return proc.returncode, out, time.monotonic() - start
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        out, _ = proc.communicate()
        return None, out or "", time.monotonic() - start


def tests_ran(output: str) -> int:
    m = re.findall(r"Test run with (\d+) tests?", output)
    return int(m[-1]) if m else 0


def execute(m: Mutant, log_dir: Path) -> None:
    path = ROOT / m.file
    original = path.read_bytes()
    digest = hashlib.sha256(original).hexdigest()
    lines = original.decode("utf-8").split("\n")
    if lines[m.line - 1] != m.original:
        raise RuntimeError(f"{m.id}: line {m.line} no longer matches; regenerate")
    lines[m.line - 1] = m.mutated
    _PENDING_RESTORE[path] = original
    log = log_dir / f"{m.id}.log"
    try:
        path.write_bytes("\n".join(lines).encode("utf-8"))
        rc, out, secs = run(["swift", "build", "--build-tests"], BUILD_TIMEOUT)
        m.seconds = secs
        if rc is None:
            m.status, m.detail = "timeout", f"build exceeded {BUILD_TIMEOUT}s"
            log.write_text(out)
            return
        if rc != 0:
            m.status = "stillborn"
            errs = [ln for ln in out.splitlines() if re.search(r"\.swift:\d+:\d+: error:", ln)]
            errs = errs or [ln for ln in out.splitlines() if "error:" in ln]
            m.detail = errs[0].strip() if errs else "build failed"
            log.write_text(out)
            return
        rc, tout, tsecs = run(["swift", "test", "--skip-build", "--filter", TARGETS[m.file]], TEST_TIMEOUT)
        m.seconds += tsecs
        log.write_text(out + "\n==== test ====\n" + tout)
        if rc is None:
            m.status, m.detail = "timeout", f"tests exceeded {TEST_TIMEOUT}s (counted as killed)"
        elif rc != 0:
            failed = re.findall(r'Test (?:"([^"]+)"|(\S+)) (?:recorded an issue|failed)', tout)
            names = sorted({a or b for a, b in failed})
            m.status, m.detail = "killed", "; ".join(names[:3]) or f"exit {rc}"
        elif tests_ran(tout) == 0:
            raise RuntimeError(f"{m.id}: the filter ran no tests; the result would be meaningless")
        else:
            m.status, m.detail = "survived", f"{tests_ran(tout)} tests passed"
    finally:
        path.write_bytes(original)
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise SystemExit(f"FATAL: {m.file} did not restore byte for byte")
        _PENDING_RESTORE.pop(path, None)


# ---------------------------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------------------------


def write_reports(seed: int, results: dict[str, dict], json_path: Path) -> None:
    json_path.write_text(json.dumps({"seed": seed, "perFile": PER_FILE, "targets": results}, indent=2) + "\n")


def tally(survivors: list[dict], notes: dict) -> dict[str, int]:
    counts: dict[str, int] = {}
    for m in survivors:
        verdict = notes.get(m["id"], {}).get("class", "UNEXPLAINED")
        counts[verdict] = counts.get(verdict, 0) + 1
    return counts


def write_markdown(json_path: Path, notes_path: Path, md_path: Path) -> None:
    """REPORT.md from the JSON results and the hand-written survivor classifications."""
    data = load_results(json_path)
    notes = json.loads(notes_path.read_text()) if notes_path.exists() else {}
    seed = data.get("seed")
    rows = []
    survivors = []
    totals = {"generated": 0, "sampled": 0, "stillborn": 0, "killed": 0, "timeout": 0, "survived": 0, "pending": 0}
    for rel in TARGETS:
        entry = data.get("targets", {}).get(rel)
        if not entry:
            rows.append(f"| `{rel}` | not run | | | | | |")
            continue
        counts = {k: 0 for k in ("stillborn", "killed", "timeout", "survived", "pending")}
        for m in entry.get("mutants", []):
            first = m.get("firstStatus") or m["status"]  # the table reports the first run
            counts[first] = counts.get(first, 0) + 1
            if m["status"] == "survived" or m.get("firstStatus") == "survived":
                survivors.append(m)
        ran = len(entry.get("mutants", []))
        counts["pending"] += max(0, entry["sampled"] - ran)
        for k in counts:
            totals[k] += counts[k]
        totals["generated"] += entry["generated"]
        totals["sampled"] += entry["sampled"]
        killed = f"{counts['killed'] + counts['timeout']}" + (f" ({counts['timeout']} timeout)" if counts["timeout"] else "")
        rows.append(
            f"| `{Path(rel).name}` | {entry['generated']} | {entry['sampled']} | {counts['stillborn']} "
            f"| {killed} | {counts['survived']} | {counts['pending']} |"
        )
    lines = [
        "# Mutation report",
        "",
        f"Seed `{seed}`, at most {data.get('perFile', PER_FILE)} mutants per file, sampled round-robin across"
        " operators. Produced by `python3 -I Harness/Mutation/mutate.py`; see README.md for the method.",
        "",
        "*Generated* is every mutant the operators produce for the file; *sampled* is what ran. A",
        "*stillborn* mutant didn't compile and counts for nothing. *Killed* includes timeouts. The",
        "counts are the first run's; a survivor a new test now kills is listed below with both.",
        "",
        "| File | Generated | Sampled | Stillborn | Killed | Survived | Not run |",
        "|---|---:|---:|---:|---:|---:|---:|",
        *rows,
        f"| **Total** | {totals['generated']} | {totals['sampled']} | {totals['stillborn']} "
        f"| {totals['killed'] + totals['timeout']} | {totals['survived']} | {totals['pending']} |",
        "",
        f"{totals['generated'] - totals['sampled']} generated mutants were not sampled, most of them in"
        " `Argon2id.swift` and `BLAKE2b.swift`, whose constant tables dominate the generated set. A"
        " different `--seed` samples a different 25.",
        "",
        "## Survivors by verdict",
        "",
        *[f"- **{verdict}**: {count}" for verdict, count in sorted(tally(survivors, notes).items())],
        "",
        "## Survivors",
        "",
    ]
    if not survivors:
        lines.append("None.")
    for m in survivors:
        note = notes.get(m["id"], {})
        verdict = note.get("class", "UNEXPLAINED")
        now = "still survives" if m["status"] == "survived" else f"now {m['status']}: {m['detail']}"
        lines += [
            f"### `{m['file']}:{m['line']}` — {m['operator']}: {m['description']}",
            "",
            f"Mutant `{m['id']}`, filter `{m['filter']}`. Survived the first run; {now}.",
            "",
            "```diff",
            m["diff"].rstrip("\n"),
            "```",
            "",
            f"**{verdict}.** {note.get('why', '')}",
            "",
        ]
    md_path.write_text("\n".join(lines).rstrip("\n") + "\n")


def load_results(json_path: Path) -> dict:
    if json_path.exists():
        return json.loads(json_path.read_text())
    return {}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seed", type=int, default=20261023)
    ap.add_argument("--per-file", type=int, default=PER_FILE)
    ap.add_argument("--only", help="substring of the target paths to run")
    ap.add_argument("--list", action="store_true", help="print the sampled mutants and stop")
    ap.add_argument("--mutant", help="run one mutant id, and print its result")
    ap.add_argument("--json", default=str(OUT_DIR / "results.json"))
    ap.add_argument("--report", action="store_true",
                    help="write REPORT.md from results.json and survivors.json, and stop")
    args = ap.parse_args()

    if args.report:
        write_markdown(Path(args.json), OUT_DIR / "survivors.json", OUT_DIR / "REPORT.md")
        return 0

    if subprocess.run(["git", "diff", "--quiet", "--", "Sources"], cwd=ROOT).returncode != 0:
        print("Sources/ has uncommitted changes; refusing to mutate on top of them.", file=sys.stderr)
        return 2

    rng = random.Random(args.seed)
    json_path = Path(args.json)
    saved = load_results(json_path).get("targets", {})
    log_dir = OUT_DIR / ".logs"
    log_dir.mkdir(exist_ok=True)

    plan: dict[str, tuple[int, list[Mutant]]] = {}
    for rel in TARGETS:  # sampled in a fixed order, so one seed always picks the same mutants
        allm = generate(rel)
        plan[rel] = (len(allm), sample(allm, rng, args.per_file))

    if args.list:
        for rel, (total, chosen) in plan.items():
            print(f"== {rel}: {total} generated, {len(chosen)} sampled")
            for m in chosen:
                print(f"  {m.id}: {m.description}\n    - {m.original.strip()}\n    + {m.mutated.strip()}")
        return 0

    results: dict[str, dict] = saved
    for rel, (total, chosen) in plan.items():
        if args.only and args.only not in rel:
            continue
        entry = results.get(rel, {})
        done = {d["id"]: d for d in entry.get("mutants", [])}
        entry.update({"filter": TARGETS[rel], "generated": total, "sampled": len(chosen)})
        for m in chosen:
            if args.mutant and m.id != args.mutant:
                continue
            if m.id in done and done[m.id]["status"] != "pending" and not args.mutant:
                continue
            execute(m, log_dir)
            print(f"{m.status:9} {m.seconds:6.0f}s {m.id}: {m.description} -- {m.detail}", flush=True)
            record = dataclasses.asdict(m) | {"diff": m.diff(), "filter": TARGETS[rel]}
            first = done.get(m.id, {}).get("firstStatus") or done.get(m.id, {}).get("status")
            record["firstStatus"] = first if first and first != "pending" else m.status
            done[m.id] = record
            entry["mutants"] = [done[k] for k in sorted(done, key=lambda k: (done[k]["line"], k))]
            results[rel] = entry
            write_reports(args.seed, results, json_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
