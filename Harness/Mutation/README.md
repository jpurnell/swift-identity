# Mutation harness

Mutation testing of the verifier, canonicalization, `Authenticator`, Argon2id and the ledgers.
The bar the design sets: **no surviving mutant left unexplained.** No mutation tool is
installed and this package builds its own tools, so this is a small one: `mutate.py`, Python
standard library only.

## Running it

From the package root, with an isolated interpreter:

```sh
python3 -I Harness/Mutation/mutate.py --list                     # the sampled mutants, nothing run
python3 -I Harness/Mutation/mutate.py --seed 20261023            # every target; resumes from results.json
python3 -I Harness/Mutation/mutate.py --only Canonicalization     # one target file
python3 -I Harness/Mutation/mutate.py --mutant <id>              # rerun one mutant (after adding a test)
python3 -I Harness/Mutation/mutate.py --report                   # REPORT.md from results.json + survivors.json
```

It refuses to start if `Sources/` has uncommitted changes. A full run is about 200 mutants at
10–60 s each.

## What one mutant is

1. The target file is read; one line is replaced by its mutated form and written back **in
   place** (SwiftPM builds what's in `Sources/`, so a copy elsewhere would not be built).
2. `swift build --build-tests` (15-minute timeout). A failure is **stillborn**: the mutant
   couldn't exist, so it says nothing about the tests and is counted apart from killed ones.
3. `swift test --skip-build --filter <the target's suites>` (5-minute timeout). Any failing test
   is **killed**; a timeout is **timeout**, counted as killed and noted; all passing is
   **survived**. A filter that ran no tests stops the run rather than reporting a survivor.
4. The original bytes are written back in a `finally` and checked by SHA-256 before the next
   mutant; a mismatch stops the run. `SIGINT`, `SIGTERM`, `SIGHUP` and interpreter exit restore
   too.

Per-mutant build and test output lands in `.logs/` (ignored).

## Operators

| Operator | Mutation |
|---|---|
| relational | `==`↔`!=`, `<`→`<=`/`>`, `<=`→`<`, `>`→`>=`/`<`, `>=`→`>` |
| boolean | `true`↔`false` |
| logical | `&&`↔`\|\|` |
| negation | drop a prefix `!` |
| arithmetic | `+`↔`-`, `*`↔`/`, `&+`↔`&-`, `&*`→`&+`, `+= 1`→`+= 0` |
| constant | a decimal literal `n` ≤ 64 → `n + 1` |
| early-return | in a guard's `else`, `return true`↔`return false`, `0`↔`1` |
| deletion | blank one line holding a whole call or assignment statement |

What is never mutated: comments (`//`, nested `/* */`, doc comments), string literals
(including raw and multi-line ones, and their interpolations), `#if`/`#else`/`#endif`,
`import` and attribute lines. Binary operators are matched only when space-delimited, which is
how Swift tells a binary operator from a generic bracket or a prefix/postfix one. Arithmetic
beside a string literal (`"…" + "…"`) and deletions that can only be stillborn (`self.x = …`
in an initializer, `self.init(…)`, a line the next line continues with `.method`) are skipped
at generation. `nil` in a guard's `else` is not swapped for a value: there is no type-agnostic
replacement, and a guessed one is a stillborn mutant.

## Sampling

Every target file's mutants are generated, then at most 25 are chosen with
`random.Random(seed)`, round-robin across operators so a file with a hundred constant mutants
still gets its relational and deletion ones. Targets are sampled in a fixed order, so a seed
always selects the same mutants. The seed is recorded in `results.json` and `REPORT.md`.

## Survivors

`survivors.json` is written by hand: for each surviving mutant id, `class` (*equivalent*,
*test gap — test added*, or *bug — fixed*) and `why`. `--report` joins it to the results; a
survivor with no entry is printed as **UNEXPLAINED**. After adding a test for a gap, rerun the
mutant with `--mutant <id>` so the results show it killed.

## Known limits

- An operator's own declaration (`static func == (lhs:…`) is matched as a use, and its mutant
  is stillborn. Excluding it would change which mutants a recorded seed selects, so it stays,
  counted as stillborn.
- The lexer is line-based and simple: an interpolation inside a string is treated as string, so
  code in `"\(a + b)"` is never mutated.
- Equivalent mutants are decided by hand, in `survivors.json`, with the reason. The harness
  can't tell an equivalent mutant from a missing test; that's the point of writing it down.
