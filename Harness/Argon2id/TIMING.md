# Argon2id timing against the reference

The third part of the amendment's Argon2id gate (§9): timing within 2× of the reference at
deployment parameters. This is evidence, recorded by hand, not a unit test: unit tests run debug
builds, and the claim is about release builds.

## Result

**Within 2×: 1.45× at m=19456 KiB, t=2, p=1, and 1.38× at m=65536 KiB, t=3, p=4.**

| Parameters | SwiftIdentity, thread CPU | phc-winner-argon2, as it reports | Ratio |
|---|---|---|---|
| m=19456, t=2, p=1 | 36.3 ms (median 37.0) | 25.0 ms (median 26.0) | 1.45× (median 1.42×) |
| m=65536, t=3, p=4 | 194.8 ms (median 196.8) | 141.0 ms (median 142.0) | 1.38× (median 1.39×) |

Minimum of 9 runs each, interleaved, with the median beside it. At both parameter sets every
run's tag from this package equalled the CLI's, so the two columns time the same computation.
No optimization was needed to get here; the implementation timed is the one already on the
branch.

## Method

- **Machine:** Apple M1 Max, 10 cores, 32 GiB, macOS 27.0.1 (26A434). Shared and heavily
  loaded: load averages 63 to 68 while this ran.
- **Date:** 2026-10-23.
- **This package:** `Harness/Argon2idTiming`, a package of its own that depends on this checkout
  by path, built in release with Apple Swift 6.4 (swiftlang-6.4.0.34.1):

      swift run -c release --package-path Harness/Argon2idTiming argon2id-timing /opt/homebrew/bin/argon2 9

  Each run is timed as the calling thread's CPU time, `clock_gettime(CLOCK_THREAD_CPUTIME_ID)`,
  around `Argon2id.hash` alone. Lanes run one after another on that thread, so its CPU time is
  the whole derivation.
- **The reference:** phc-winner-argon2's `argon2` CLI, Homebrew `argon2` 20190702_1, as bottled.
  The figure used is the time the CLI prints, which is `clock()` around its `argon2_hash` call:
  process CPU time, summed over its lane threads, so p=4 is compared as total work, not as
  wall-clock time with four threads.
- **Why CPU time and minimums:** on a loaded machine wall-clock time is mostly the scheduler,
  and load only ever adds time, so the minimum is the closest to the cost of the work itself.

The harness also prints the CLI's whole-process CPU time from `getrusage(RUSAGE_CHILDREN)`:
50.8 ms and 273.3 ms, about twice what the CLI reports. That isn't start-up. The CLI verifies
the encoded hash it has just made, which runs Argon2id a second time outside its timer. Against
that figure this package would look 0.72× and 0.71× of the reference, which flatters it; the
CLI's own figure is the fair one.

## What would change it

The reference here is the portable build Homebrew ships. A reference built with platform SIMD
(phc-winner-argon2's `opt.c` is x86 SSE/AVX only) could be faster on x86_64, which is the deploy
host's architecture; this was measured on arm64. Re-run the harness there before relying on the
ratio for that host.
