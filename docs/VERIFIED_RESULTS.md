# Verified small benchmark

This document is generated from `experiments/results/verified-small.csv` and `experiments/results/verified-small-coverage.csv`. It reports measurements produced by the modern implementation, not the historical presentation.

- Effective state dimension: **16 bits** (`N = 65,536`)
- Seeded independent trials: **30**
- Timing: `System.nanoTime()` end-to-end JVM measurements after a separate warm-up run
- Coverage: exact unique reduced states represented by the generated table chains, computed outside the timed path

## Summary

| Method | Exact recovery | Median exact coverage | Median offline | Median online | Median stored chains | Median distinct endpoints |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| exhaustive | 30/30 (100.0%) | 100.0% | 0.000 ms | 25.863 ms | 0 | 0 |
| hellman | 4/30 (13.3%) | 16.8% | 70.222 ms | 3.399 ms | 1024 | 690.5 |
| distinguished points | 3/30 (10.0%) | 15.4% | 59.311 ms | 1.790 ms | 1021 | 144.5 |

## Hellman observations

- Parameters: `m = 1024`, `t = 64`, so `m t / N = 1.000`.
- Independent-sample occupancy reference: `1 - exp(-m t / N) = 0.632` (63.2%).
- That 63.2% value is **not** an expected coverage formula for these iterated chains. States within a chain are linked by one fixed mapping, so chain merging makes the independent-sample model optimistic.
- Exact table coverage across the 30 generated tables: median 16.8%, range 16.4%–17.4%.
- Random-target exact recovery: 4/30 (13.3%).
- Median distinct endpoints: 690.5/1024; endpoint collisions and chain merging are directly visible.

## Distinguished-point observations

- Parameters: `1024` starts, `d = 6`, maximum chain length `256`.
- Uniform-state waiting-time reference: `2^d = 64` transitions.
- Exact stored-table coverage across the 30 generated tables: median 15.4%, range 15.1%–15.8%.
- Random-target exact recovery: 3/30 (10.0%).
- Stored chains across all trials: 30,619; truncated chains: 101.
- Median distinct distinguished endpoints: 144.5/1024; many chains merge onto the same distinguished endpoint.

## Limits

This is a small reproducibility benchmark, not a cryptanalytic security estimate. DES is obsolete; the state space is deliberately reduced; JVM timings are machine-dependent; and random-target recovery uses a finite sample. Exact coverage is included specifically so conclusions do not depend only on those 30 target samples.

See `METHODOLOGY.md` for the exact state model and `HISTORICAL_RESULTS.md` for the original presentation values.
