# Representation and Time-Memory Tradeoffs in Symmetric Cryptography

[![CI](https://github.com/qoosmo/cryptanalytic-time-memory-tradeoffs/actions/workflows/ci.yml/badge.svg)](https://github.com/qoosmo/cryptanalytic-time-memory-tradeoffs/actions/workflows/ci.yml)
[![Java 17](https://img.shields.io/badge/reference-Java%2017-blue.svg)](src/main/java/io/github/qoosmo/hpc)
[![Rust](https://img.shields.io/badge/reference-Rust-orange.svg)](rust/)
[![Research](https://img.shields.io/badge/status-active%20research-6f42c1.svg)](RESEARCH.md)
[![ePrint](https://img.shields.io/badge/paper-ePrint%20draft-informational.svg)](research-note/cryptanalytic-time-memory-tradeoffs.pdf)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/modern%20software-MIT%20OR%20Apache--2.0-blue.svg)](#license)

**An [Algorizk Labs](https://algorizk.xyz) research artifact in cryptography, reproducible systems, and implementation-level verification.**

This repository develops two connected research directions in symmetric cryptography:

1. **finite-field representation engineering for AES-like arithmetic** — polynomial and normal bases, tower-field isomorphisms, composite-field inversion, and non-LUT S-box structure;
2. **cryptanalytic time-memory tradeoffs** — exhaustive search, Hellman chains, distinguished points, exact coverage, collision handling, and functional-graph coalescence over deliberately reduced DES state spaces.

The project originated as an **M2P SCCI master's research project at Ensimag–UJF** by **Abdourahmane Sakho, Ali Mkhida, and Maad El Yadari**. The original presentation and Eclipse prototype are preserved unchanged. The modern repository adds a paper-oriented mathematical reconstruction, independent Java and Rust reference implementations, deterministic experiments, cross-language fixtures, exact verification, and CI.

> **Scope.** DES is obsolete and is used here only as a compact reproducibility fixture. This repository does not claim to break full-size DES or AES and is not production cryptographic software.

## What this repository demonstrates

A result should be traceable through:

```text
mathematical statement
        ↓
reference semantics
        ↓
independent implementations
        ↓
committed evidence / experiment output
```

That evidence chain is the core of the repository and reflects the research engineering approach used at Algorizk Labs.

## Research highlights

### Historical finite-field mathematics

The paper reconstructs the recoverable mathematics from the original presentation:

- `GF(16) = GF(2)[X]/(X^4 + X^3 + X^2 + X + 1)`;
- normal basis `{α^8, α^4, α^2, α}`;
- the slide-derived `GF(16)` multiplication formula;
- Frobenius squaring as a coordinate permutation;
- the generator-based tower-field isomorphism construction;
- the exact historical `8×8` binary isomorphism matrix and inverse;
- Hamming-weight interpretation of the maps as XOR networks;
- the second `GF(16) -> GF(4)` composite-field layer;
- `γ^{-1}=γ^2` for nonzero `γ ∈ GF(4)`.

[`scripts/verify-historical-math.py`](scripts/verify-historical-math.py) independently checks the recoverable finite-field identities and matrix inverses.

### Cryptanalytic state model

For reduced state `x`, canonical DES key `K(x)`, fixed plaintext `P`, encryption `E`, and reduction `R`:

```math
F(x)=R(E_{K(x)}(P)).
```

The model uses effective DES key bits:

```math
x \in \{0,\dots,2^b-1\}, \qquad 1 \le b \le 28.
```

The four variable DES bytes contribute seven effective bits each; odd parity is inserted canonically.

### Independent Java and Rust implementations

The committed 16-bit experiments use 30 trials, Hellman `(m,t)=(1024,64)`, and distinguished points with 1024 starts, `d=6`, maximum chain length 256.

| Implementation | Method | Exact recovery | Median exact coverage |
| --- | --- | ---: | ---: |
| Java | Exhaustive | 30/30 | 100.0% |
| Java | Hellman | 4/30 | 16.8% |
| Java | Distinguished points | 3/30 | 15.4% |
| Rust | Exhaustive | 30/30 | 100.0% |
| Rust | Hellman | 4/30 | 16.8% |
| Rust | Distinguished points | 3/30 | 15.4% |

The matching recovery counts and coverage are a strong cross-implementation correctness signal. The current Java and Rust timing runs use different deterministic trial generators, so **no Java-vs-Rust speedup claim is made yet**. A shared experiment plan is the next comparison gate.

See [`docs/VERIFIED_RESULTS.md`](docs/VERIFIED_RESULTS.md) and [`docs/RUST_VERIFIED_RESULTS.md`](docs/RUST_VERIFIED_RESULTS.md).

### Functional-graph coalescence

With `mt/N = 1`, the independent-sample occupancy reference is

```math
1-e^{-mt/N} \approx 63.2\%.
```

The measured Hellman coverage is only about 16–17% in the committed configuration because the chains are iterates of one fixed map and therefore merge.

## Paper track

The repository is being developed toward an **IACR ePrint submission**.

> **Working title:** *Representation and Time-Memory Tradeoffs in Symmetric Cryptography: Finite-Field Basis Transformations for AES and Reproducible Hellman Experiments*

- [ePrint-style PDF](research-note/cryptanalytic-time-memory-tradeoffs.pdf)
- [LaTeX source](research-note/main.tex)
- [historical-math reconstruction map](research-note/HISTORICAL-MATH-SOURCE.md)
- [research questions and evidence policy](RESEARCH.md)
- [roadmap](ROADMAP.md)
- [authorship and provenance](AUTHORS.md)
- [citation metadata](CITATION.cff)

The future ePrint author list will be finalized with the original project collaborators before submission.

## Historical preservation

| Artifact | Role |
| --- | --- |
| [`docs/original-presentation.pdf`](docs/original-presentation.pdf) | Original master's research presentation |
| [`legacy/original-eclipse-prototype/`](legacy/original-eclipse-prototype/) | Original Eclipse/Java prototype |

Canonical presentation SHA-256:

```text
4003194fdfe82e84bcc32876c8d9ba5042d12dc5f14da726a4bd6e3edc2e6bec
```

CI checks this hash.

## Reproduce

Full local research checks:

```bash
./scripts/check-all.sh
```

Java:

```bash
mvn -B -ntp verify
./scripts/run-verified-small.sh
```

Rust:

```bash
cargo fmt --manifest-path rust/Cargo.toml --all -- --check
cargo clippy --locked --manifest-path rust/Cargo.toml --all-targets -- -D warnings
cargo test --locked --manifest-path rust/Cargo.toml
cargo run --release --locked --manifest-path rust/Cargo.toml --bin tmto -- verified-small
```

Historical mathematics:

```bash
python3 scripts/verify-historical-math.py
```

## CI quality gates

Every pull request is expected to pass:

1. historical presentation SHA-256 integrity;
2. historical finite-field verification;
3. Java 17 Maven verification;
4. Rust formatting;
5. warning-free Rust Clippy;
6. Rust tests;
7. Rust release build;
8. Java and Rust smoke experiments;
9. diff hygiene.

## Repository map

```text
.
├── README.md
├── AUTHORS.md
├── CITATION.cff
├── RESEARCH.md
├── ROADMAP.md
├── CONTRIBUTING.md
├── SECURITY.md
├── CODE_OF_CONDUCT.md
├── LICENSE-MIT
├── LICENSE-APACHE
├── NOTICE
├── research-note/               # evolving ePrint manuscript
├── src/                         # Java 17 reference
├── rust/                        # Rust reference + experiments
├── test-vectors/                # Java/Rust equivalence fixtures
├── experiments/results/         # committed benchmark evidence
├── scripts/                     # reproduction / verification
├── docs/                        # methodology, provenance, results, historical PDF
├── legacy/                      # preserved original prototype
└── .github/                     # CI, ownership, templates, Dependabot
```

## Research discipline

The repository distinguishes:

- **historical reconstruction**;
- **mathematical verification**;
- **reference semantics**;
- **measured experiments**;
- **future work**.

A benchmark or mathematical statement is not promoted into the paper without an identifiable evidence path.

## Related Algorizk research

This repository is part of a broader open R&D portfolio at **Algorizk Labs**:

- [Boolean Kernel Basis Filtration](https://github.com/qoosmo/kernel-basis-filtration) — kernel coordinates, low-degree filtration, Rust checks, and Lean formalization;
- [Multilinear Sumcheck](https://github.com/qoosmo/multilinear-sumcheck) — reproducible Rust implementation and protocol-oriented research artifact.

Algorizk Labs works at the boundary of **cryptography, mathematical algorithms, formal verification, arithmetic kernels, and hardware/software co-design**. See [algorizk.xyz](https://algorizk.xyz).

## Contributing and security

Read [`CONTRIBUTING.md`](CONTRIBUTING.md), [`SECURITY.md`](SECURITY.md), and [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## Citation

GitHub-readable citation metadata is provided in [`CITATION.cff`](CITATION.cff).

**Maintainer:** Ali Mkhida — Algorizk Labs
**ORCID:** [0009-0009-2101-9070](https://orcid.org/0009-0009-2101-9070)

## License

The **modern software, tests, build scripts, CI configuration, verification utilities, and modern reproducibility code** are available under either the MIT License or Apache License 2.0, at your option. See [`LICENSE-MIT`](LICENSE-MIT), [`LICENSE-APACHE`](LICENSE-APACHE), and [`NOTICE`](NOTICE).

The software licenses **do not relicense** the preserved historical presentation, preserved historical Eclipse prototype, or the evolving scholarly manuscript under `research-note/`.
