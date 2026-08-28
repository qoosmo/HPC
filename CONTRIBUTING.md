# Contributing

Contributions are welcome when they preserve the repository's evidence discipline.

## Before changing an algorithm

- add or update tests;
- preserve the explicit reduced-state semantics;
- do not mix historical results with newly measured results;
- keep Java/Rust equivalence fixtures synchronized when shared semantics change.

## Before adding a paper claim

Classify it as historical, verified, measured, conjectural, or future work. A numerical result must point to a committed experiment or verification path.

## Java

```bash
mvn test
```

## Rust

```bash
cargo test --manifest-path rust/Cargo.toml
```

## Historical finite-field verification

```bash
python3 scripts/verify-historical-math.py
```

## Historical assets

Do not modify `docs/original-presentation.pdf` or the preserved Eclipse prototype as part of modernization work.
