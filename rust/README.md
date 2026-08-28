# Rust reference implementation

This crate is the first Rust port of the modern Java semantics.

It currently implements:

- reduced DES state encoding with canonical odd parity;
- DES/ECB encryption with PKCS#5-compatible padding;
- the historical effective-bit reduction;
- exhaustive search;
- Hellman chains;
- distinguished-point chains;
- exact state coverage;
- Java/Rust shared reference-vector tests.

This is a **correctness/equivalence implementation**, not yet a performance claim.

Run:

```bash
cargo test --manifest-path rust/Cargo.toml
cargo run --manifest-path rust/Cargo.toml --bin tmto -- smoke
```

The shared fixtures are in `../test-vectors/java-rust-reference.csv`.
