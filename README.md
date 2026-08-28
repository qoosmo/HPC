# Representation and Time-Memory Tradeoffs in Symmetric Cryptography

[![CI](https://github.com/qoosmo/cryptanalytic-time-memory-tradeoffs/actions/workflows/ci.yml/badge.svg)](https://github.com/qoosmo/cryptanalytic-time-memory-tradeoffs/actions/workflows/ci.yml)

A reproducible research project in symmetric cryptography combining two themes:

1. **finite-field representation engineering for AES-like arithmetic** — polynomial and normal bases, tower-field isomorphisms, composite-field inversion, and non-LUT S-box structure;
2. **cryptanalytic time-memory tradeoffs** — exhaustive search, Hellman chains, distinguished points, exact table coverage, and functional-graph coalescence over deliberately reduced DES state spaces.

The project originated as an **M2P SCCI master's research project at Ensimag–UJF** by **Abdourahmane Sakho, Ali Mkhida, and Maad El Yadari**. The original research presentation and Eclipse prototype are preserved unchanged, while the modern repository adds a paper-oriented reconstruction, reproducible Java and Rust implementations, exact verification, and CI.

> **Scope.** DES is obsolete and is used only as a compact reproducibility fixture. Nothing in this repository claims to break full-size DES or AES, and none of the code should be used as production cryptography.

## Paper track

The repository is being developed toward an **IACR ePrint submission**.

**Working title**

> **Representation and Time-Memory Tradeoffs in Symmetric Cryptography: Finite-Field Basis Transformations for AES and Reproducible Hellman Experiments**

- [ePrint-style PDF](research-note/cryptanalytic-time-memory-tradeoffs.pdf)
- [LaTeX source](research-note/main.tex)
- [historical-math reconstruction map](research-note/HISTORICAL-MATH-SOURCE.md)
- [research questions and evidence policy](RESEARCH.md)
- [project roadmap](ROADMAP.md)
- [authors and provenance](AUTHORS.md)

The ePrint draft is an evolving research document. The authorship of a future submission will be finalized with the original project collaborators before submission.

## Two PDFs, permanently separated

| Artifact | Role |
| --- | --- |
| [`docs/original-presentation.pdf`](docs/original-presentation.pdf) | Original master's research presentation, preserved byte-for-byte with its original logos and layout |
| [`research-note/cryptanalytic-time-memory-tradeoffs.pdf`](research-note/cryptanalytic-time-memory-tradeoffs.pdf) | Current paper-oriented reconstruction and modern experimental report |

The original presentation is not rewritten or replaced.

Its preserved SHA-256 is:

```text
4003194fdfe82e84bcc32876c8d9ba5042d12dc5f14da726a4bd6e3edc2e6bec
```

## Historical mathematics reconstructed

The paper now reconstructs the recoverable mathematics from the original presentation, including:

- the concrete `GF(16) = GF(2)[X]/(X^4 + X^3 + X^2 + X + 1)` model;
- the normal basis `{α^8, α^4, α^2, α}`;
- the slide-derived `GF(16)` multiplication formula;
- Frobenius squaring as a coordinate permutation;
- the generator-based tower-field isomorphism construction;
- the exact historical `8×8` binary isomorphism matrix and its inverse;
- Hamming-weight interpretation of those binary maps as parallel XOR networks;
- the second `GF(16) -> GF(4)` composite-field layer;
- the non-LUT identity `γ^{-1} = γ^2` for nonzero `γ ∈ GF(4)`.

[`scripts/verify-historical-math.py`](scripts/verify-historical-math.py) independently checks the finite-field formulas and matrix identities.

Slides whose derivations were written only on the board during the original research presentation are explicitly marked as unrecoverable from the preserved PDF; the paper does not invent those missing proofs.

## Cryptanalytic model

For a reduced state `x`, a canonical DES key encoding `K(x)`, fixed plaintext `P`, encryption `E`, and reduction `R`, one chain transition is

```math
F(x) = R(E_{K(x)}(P)).
```

The modern state model uses **effective DES key bits**, not raw Java key-representation bytes:

```math
x \in \{0,\dots,2^b-1\}, \qquad 1 \le b \le 28.
```

The four variable DES bytes contribute seven effective bits each; odd parity is inserted canonically.

## Implementations

### Java 17 reference

The Java implementation under [`src/main/java/io/github/qoosmo/hpc`](src/main/java/io/github/qoosmo/hpc) contains:

- `ReducedDesKeySpace`
- `DesOracle`
- `LegacyReduction`
- `ExhaustiveSearch`
- `HellmanTable`
- `DistinguishedPointPredicate`
- `DistinguishedPointTable`
- `CoverageAnalyzer`
- `ExperimentRunner`
- `ExactCoverageRunner`

The Java suite remains the reference for the committed benchmark rows.

### Rust reference — added 28 August 2026

The Rust crate under [`rust/`](rust/) now implements the same core semantics:

- canonical reduced DES state encoding and odd parity;
- DES/ECB with PKCS#5-compatible padding over the same plaintext fixture;
- the historical effective-bit reduction;
- exhaustive search;
- fixed-length Hellman chains;
- bounded distinguished-point chains;
- exact state-coverage analysis;
- shared Java/Rust reference vectors.

This first Rust implementation is a **correctness/equivalence layer**, not yet a speed claim.

The shared vectors in [`test-vectors/java-rust-reference.csv`](test-vectors/java-rust-reference.csv) are checked by both languages.

## Verified Java benchmark

The committed benchmark uses `b = 16`, `N = 65,536`, 30 deterministic seeded trials, Hellman `(m,t)=(1024,64)`, and distinguished points with 1024 starts, `d=6`, maximum chain length 256.

| Method | Exact recovery | Median exact coverage | Median offline | Median online |
| --- | ---: | ---: | ---: | ---: |
| Exhaustive | 30/30 | 100.0% | 0.000 ms | 25.863 ms |
| Hellman | 4/30 | 16.8% | 70.222 ms | 3.399 ms |
| Distinguished points | 3/30 | 15.4% | 59.311 ms | 1.790 ms |

With `mt/N = 1`, the independent-sample occupancy reference is

```math
1-e^{-mt/N} \approx 63.2\%.
```

The measured Hellman coverage is only about 16–17% because the chains are iterates of one fixed map and therefore coalesce. The exact functional graph, not independent sampling, governs the table.

See [`docs/VERIFIED_RESULTS.md`](docs/VERIFIED_RESULTS.md).

## Reproduce

Java:

```bash
mvn test
./scripts/run-verified-small.sh
```

Rust:

```bash
cargo test --manifest-path rust/Cargo.toml
cargo run --manifest-path rust/Cargo.toml --bin tmto -- smoke
```

Historical finite-field reconstruction:

```bash
python3 scripts/verify-historical-math.py
```

## Repository layout

```text
.
├── README.md
├── AUTHORS.md
├── RESEARCH.md
├── ROADMAP.md
├── research-note/
│   ├── main.tex
│   ├── cryptanalytic-time-memory-tradeoffs.pdf
│   └── HISTORICAL-MATH-SOURCE.md
├── src/                         # Java 17 reference
├── rust/                        # Rust reference implementation
├── test-vectors/                # Java/Rust equivalence fixtures
├── experiments/results/         # curated benchmark evidence
├── scripts/
├── docs/
│   ├── original-presentation.pdf
│   ├── METHODOLOGY.md
│   ├── VERIFIED_RESULTS.md
│   ├── HISTORICAL_RESULTS.md
│   └── PROVENANCE.md
└── legacy/
    └── original-eclipse-prototype/
```

## Research discipline

The repository distinguishes:

- **historical reconstruction** — statements directly recoverable from the original research presentation;
- **modern verification** — identities or semantics checked by committed tests;
- **reproduced experiments** — measurements generated by committed scripts;
- **future work** — results that still require implementation or new experiments.

No benchmark or mathematical result is promoted into the paper without a reproducible source.

## License and reuse

A blanket repository license is intentionally not declared yet. The historical presentation and original prototype are coauthored research artifacts, so their reuse rights should not be inferred from the later modernization. Licensing of newly written Java/Rust code can be separated from the historical material after the original collaborators are contacted.
