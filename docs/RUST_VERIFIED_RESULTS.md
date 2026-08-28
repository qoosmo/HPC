# Verified Rust results

This file records the first committed Rust benchmark run for the project.
The Rust implementation passed the shared Java/Rust semantic vectors before
these measurements were collected.

Timing values are machine-dependent. The Rust benchmark currently uses a
deterministic SplitMix64 experiment generator; it does **not yet** consume
the exact Java `SplittableRandom` trial plan. Therefore the Java and Rust
timings below should not yet be treated as an apples-to-apples speedup claim.

## Configuration

- effective state dimension: **16 bits**, `N = 65,536`;
- trials: **30**;
- seed: `20260828`;
- Hellman: `m = 1024`, `t = 64`;
- distinguished points: 1024 starts, `d = 6`, maximum chain length 256;
- a separate warm-up run is executed before measurements;
- exact coverage is computed outside each timed build/lookup interval.

## Results

| Method | Exact recovery | Median exact coverage | Median offline | Median online |
| --- | ---: | ---: | ---: | ---: |
| Exhaustive | 30/30 | 100.0% | 0.000 ms | 67.226 ms |
| Hellman | 4/30 | 16.8% | 175.755 ms | 8.383 ms |
| Distinguished points | 3/30 | 15.4% | 149.456 ms | 4.089 ms |

## Interpretation

The algorithmic quantities to compare first are exact recovery, endpoint
statistics, and exact coverage. A direct Java-versus-Rust timing claim is
deferred until both implementations consume one committed shared experiment
plan (identical targets and identical Hellman/DP start sets).

## Files

- `experiments/results/rust-verified-small.csv`
- `experiments/results/rust-verified-small-coverage.csv`
- `experiments/results/rust-verified-small-environment.txt`
