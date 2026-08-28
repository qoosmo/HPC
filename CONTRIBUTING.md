# Contributing

Contributions are welcome when they preserve the repository's evidence discipline, historical provenance, and reproducibility guarantees.

## Workflow

1. Create a focused branch.
2. Keep historical artifacts untouched unless the change is explicitly archival.
3. Add tests/evidence before changing an algorithmic or mathematical claim.
4. Run the relevant quality gates.
5. Open a pull request using the repository template.
6. Do not merge a performance claim until output and environment metadata are committed.

## Full check

```bash
./scripts/check-all.sh
```

## Java

```bash
mvn -B -ntp verify
```

Changes to state encoding, DES parity, reduction, table construction, or lookup require regression tests.

## Rust

```bash
cargo fmt --manifest-path rust/Cargo.toml --all -- --check
cargo clippy --locked --manifest-path rust/Cargo.toml --all-targets -- -D warnings
cargo test --locked --manifest-path rust/Cargo.toml
cargo build --release --locked --manifest-path rust/Cargo.toml --bin tmto
```

If shared Java/Rust semantics change, update `test-vectors/` and require both suites to pass.

## Paper claims

Classify every new claim as historical reconstruction, mathematically proved,
computationally verified, measured, conjectural, or future work.

Numerical claims must point to committed parameters, output, and environment
metadata. Direct Java/Rust performance comparisons require identical experiment
inputs.

## Historical assets

Normal modernization work must not modify:

- `docs/original-presentation.pdf`;
- `legacy/original-eclipse-prototype/`.

The presentation hash is enforced in CI.

## Licensing

Modern contributions intended for the dual-licensed software portion are
submitted under **MIT OR Apache-2.0**, subject to the boundary in `NOTICE`.

Do not copy third-party or historical material into the dual-licensed tree
unless rights and attribution are clear.
