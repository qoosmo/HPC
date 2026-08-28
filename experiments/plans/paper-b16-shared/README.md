# Shared b=16 experiment plan

This directory is the canonical language-neutral workload for Java/Rust
semantic equivalence.

Both implementations consume the literal CSV files:

- `metadata.csv`
- `targets.csv`
- `hellman-starts.csv`
- `dp-starts.csv`

Configuration:

- `b = 16`, `N = 65,536`
- 30 trials
- Hellman: 1024 starts, chain length 64
- distinguished points: 1024 starts, `d = 6`, maximum chain length 256

The plan reproduces the SplitMix64 draw order used by the first Rust
verified-small experiment. The committed CSV files, not either language's PRNG,
are the canonical workload.
