# KSafe Benchmark

An Android app that benchmarks [KSafe](https://github.com/anifantakis/KSafe) against the most commonly used key-value storage libraries on Android. Results are printed to Logcat and rendered in a small Compose UI.

## What it compares

| Library | Encrypted? | Notes |
| --- | --- | --- |
| KSafe (Direct API) | optional | Hot in-memory cache, non-suspending |
| KSafe (Coroutine API) | optional | Suspends until the value is persisted |
| KSafe (Delegated API) | optional | Property delegate over the Direct API |
| SharedPreferences | no | Android baseline |
| EncryptedSharedPreferences | yes | `androidx.security.crypto` |
| DataStore Preferences | no | KSafe's underlying backend |
| MMKV | no | Tencent, mmap-based |
| Multiplatform Settings | no | Russell Wolf's KMP wrapper |
| KVault | yes | Liftric's encrypted KMP storage |

KSafe is exercised twice — once with `KSafeMemoryPolicy.ENCRYPTED` (decrypt on every read) and once with `PLAIN_TEXT` (decrypt once, cache plaintext) — so the trade-off between the two memory policies is visible.

## Benchmark phases

Each run executes the following in order:

1. **Read** — unencrypted and encrypted, fair comparison across all libraries.
2. **Write** — unencrypted and encrypted, fair comparison across all libraries.
3. **DataStore acceleration** — direct read of how much faster KSafe is than the DataStore backend it sits on top of.
4. **Direct vs Suspend API** — `getDirect`/`putDirect` (hot-cache) vs `get`/`put` (durable).
5. **Update** — overwriting existing keys with new values.
6. **Reinitialization (cold start)** — measures cache re-population time after the in-memory cache is wiped, vs. fresh-open time for the other libraries.
7. **Deletion** — total time to clear all stored keys per library.
8. **Cleanup verification** — confirms every library is empty before the run ends.

The iteration count is configurable from the UI dropdown: `1, 50, 100, 200, 500, 1000, 2000`. Default is `1000`.

## Sample results

From a `500`-iteration run on a physical device (your numbers will differ — these illustrate the shape, not absolute truth):

```
UNENCRYPTED READ
  SharedPreferences           0.0019 ms/op
  MMKV                        0.0030 ms/op
  Multiplatform Settings      0.0032 ms/op
  KSafe Delegated             0.0122 ms/op
  KSafe Direct                0.0150 ms/op
  KSafe Coroutine             0.3330 ms/op
  DataStore                   0.4623 ms/op

UNENCRYPTED WRITE
  KSafe Delegated             0.0125 ms/op
  KSafe Direct                0.0199 ms/op
  Multiplatform Settings      0.0249 ms/op
  SharedPreferences           0.0269 ms/op
  MMKV                        0.0318 ms/op
  DataStore                     6.00 ms/op
  KSafe Coroutine              27.30 ms/op

vs DataStore (KSafe's own backend)
  READ:   ~38x  faster
  WRITE:  ~482x faster
```

The headline takeaway from a typical run:

- KSafe's hot-cache APIs (`getDirect` / `putDirect`) are within a small constant factor of `SharedPreferences` and `MMKV`, while keeping a typed, KMP-friendly API.
- KSafe is dramatically faster than its own `DataStore` backend because reads hit memory and writes return as soon as the work is queued.
- The encrypted-read cost difference between `ENCRYPTED` and `PLAIN_TEXT` memory policies is large — pick `ENCRYPTED` for tokens/secrets, `PLAIN_TEXT` for hot, non-sensitive data.

## Running

Open the project in Android Studio (Ladybug or newer recommended) and run the `app` configuration on a physical device or emulator. The run uses:

- `compileSdk` / `targetSdk` 36, `minSdk` 24
- Java 11
- Kotlin + Jetpack Compose (Material 3)

From the UI: pick an iteration count, tap **Begin Test**, watch progress, then read either the on-screen tables or the `KSafeBenchmark` Logcat tag for the full report.

## Project layout

```
app/src/main/java/eu/anifantakis/ksafe_benchmark/
  MainActivity.kt        Compose UI, dropdown, progress, results
  BenchmarkRunner.kt     All benchmark phases and result formatting
  ui/                    Compose theme
```

The benchmark is intentionally single-file — every library is initialized, exercised, and cleaned up inside `BenchmarkRunner`.

## Methodology notes

- **Warmup.** For runs of 50+ iterations, 10% of the iteration count (minimum 10) is run as warmup before measurement. A `1`-iteration run skips warmup so you can observe a true cold call.
- **Fairness.** Read/write benchmarks use the same key set and the same value type across libraries. Encrypted vs unencrypted is not mixed in the headline tables.
- **Cold start.** KSafe's "reinit" measurement clears its internal caches via reflection rather than recreating the `DataStore` singleton — so you see cache re-population time, not DataStore construction time. The other libraries are reinstantiated fresh.
- **Cleanup.** Every library is wiped at the end of the run and the cleanup is verified, so consecutive runs do not contaminate each other.

## Caveats

These numbers are not a substitute for profiling your own workload. They are useful for relative comparison on a single device under controlled conditions; absolute numbers will move with device, OS version, thermal state, and storage condition.

KSafe is the subject of the benchmark — the goal of this repo is to make it easy to verify or reproduce KSafe's published performance characteristics, not to prove a specific library is "best." Run it on your target hardware and read the numbers in context.
