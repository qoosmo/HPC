# Rust reference implementation

This crate is the Rust implementation track for the research project.

It currently implements:

- reduced DES effective-state encoding with canonical odd parity;
- DES/ECB with PKCS#5-compatible padding over the shared plaintext fixture;
- the historical effective-bit reduction;
- exhaustive search;
- fixed-length Hellman chains;
- bounded distinguished-point chains;
- exact coverage analysis;
- Java/Rust semantic reference vectors;
- a deterministic Rust experiment harness with CSV output.

## Test

```bash
cargo test --locked --manifest-path rust/Cargo.toml
```

## Smoke

```bash
cargo run --quiet --locked --manifest-path rust/Cargo.toml --bin tmto -- smoke
```

## Verified small run

```bash
cargo run --release --locked --manifest-path rust/Cargo.toml --bin tmto -- verified-small
```

This writes:

```text
experiments/results/rust-verified-small.csv
experiments/results/rust-verified-small-coverage.csv
```

The current Rust benchmark uses deterministic SplitMix64 trial generation.
Java/Rust performance comparison is intentionally deferred until both languages
consume a single committed shared experiment plan.
