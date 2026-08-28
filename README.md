# Cryptanalytic Time-Memory Tradeoffs

[![CI](https://github.com/qoosmo/cryptanalytic-time-memory-tradeoffs/actions/workflows/ci.yml/badge.svg)](https://github.com/qoosmo/cryptanalytic-time-memory-tradeoffs/actions/workflows/ci.yml)

A reproducible study of **exhaustive search**, **Hellman time–memory tradeoffs**, and **distinguished-point chains** over deliberately reduced DES state spaces.

This repository began as an M2P SCCI project at Ensimag–UJF by
**Abdourahmane Sakho, Ali Mkhida, and Maad El Yadari**. The original Eclipse
prototype and presentation are preserved under [`legacy/`](legacy/) and
[`docs/original-presentation.pdf`](docs/original-presentation.pdf). The modern
Java 17 implementation separates the algorithms from the historical artifact
and adds tests, deterministic experiments, exact coverage analysis, and CI.

> **Scope.** DES is obsolete. The reduced key spaces in this repository exist
> only to make algorithmic tradeoffs reproducible on ordinary hardware. This is
> not production cryptographic software and is not a claim about breaking
> full-size DES or AES.

## Research note

The updated project is documented as an ePrint-style research note, separate
from the historical coursework presentation:

**Representation and Time-Memory Tradeoffs in Symmetric Cryptography: Finite-Field Basis Transformations for AES and Reproducible Hellman Experiments**

- [`research-note/cryptanalytic-time-memory-tradeoffs.pdf`](research-note/cryptanalytic-time-memory-tradeoffs.pdf)
- [`research-note/main.tex`](research-note/main.tex)

The note now reconstructs both parts of the historical project:

- finite-field representation mathematics for AES-like arithmetic: polynomial
  basis, normal basis, basis-change maps, field isomorphisms, composite-field
  inversion, the role of the fixed parameter `delta`, and non-LUT S-box
  computation;
- reproducible time-memory tradeoff experiments over reduced DES state spaces,
  formulated through the functional graph

```math
F(x)=R(E_{K(x)}(P)).
```

The original presentation remains a separate historical PDF with its own
layout and logos; the research note is the future ePrint candidate.

The original presentation remains a separate historical artifact and is not
silently rewritten into the research note.

## What is implemented

The modern code is under
[`src/main/java/io/github/qoosmo/hpc`](src/main/java/io/github/qoosmo/hpc).

| Component | Role |
| --- | --- |
| `ReducedDesKeySpace` | Explicit effective-bit DES state model with canonical odd parity |
| `DesOracle` | Deterministic DES encryption oracle over a fixed plaintext |
| `ExhaustiveSearch` | Baseline search over the entire configured state space |
| `LegacyReduction` | Reduction inspired by the historical prototype, expressed in effective DES bits |
| `HellmanTable` | Fixed-length Hellman chains with hashed endpoint lookup and collision-aware regeneration |
| `DistinguishedPointPredicate` | Configurable distinguished-state predicate |
| `DistinguishedPointTable` | Bounded distinguished-point chains with truncation and collision accounting |
| `ExperimentRunner` | Seeded end-to-end timing and recovery experiments |
| `CoverageAnalyzer` / `ExactCoverageRunner` | Exact unique-state coverage outside the timed benchmark path |

The test suite currently exercises state encoding, DES parity, deterministic
encryption, exhaustive recovery, Hellman lookup, distinguished-point recovery,
negative cases, truncation, deterministic experiment generation, and exact
coverage.

## Reduced DES state model

The historical prototype varied four raw DES bytes. A DES key is represented
with eight bytes, but one bit of each byte is a parity bit and does not
contribute an independent effective key bit.

The modern implementation therefore works with an explicit state

\[
x \in \{0,\ldots,2^b-1\}, \qquad 1 \le b \le 28,
\]

and maps it to four variable groups of seven effective DES bits. This avoids
calling four raw bytes a clean "32-bit entropy" key space.

For a fixed plaintext \(P\), one chain transition is

\[
x_{i+1}=R(E_{K(x_i)}(P)),
\]

where \(K(x_i)\) is the canonical DES key encoding, \(E\) is DES encryption,
and \(R\) is the reduced-state function.

See [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md) for the exact construction.

## Verified benchmark

The curated benchmark uses:

- effective state dimension: **16 bits**, \(N=65{,}536\);
- **30** deterministic seeded trials;
- Hellman: \(m=1024\) chains, \(t=64\);
- distinguished points: 1024 starts, difficulty \(d=6\), maximum chain length 256;
- a separate warm-up run before timing;
- exact table coverage computed independently of the timed path.

Results from the currently committed run:

| Method | Exact recovery | Median exact coverage | Median offline | Median online |
| --- | ---: | ---: | ---: | ---: |
| Exhaustive | 30/30 | 100.0% | 0.000 ms | 25.863 ms |
| Hellman | 4/30 | 16.8% | 70.222 ms | 3.399 ms |
| Distinguished points | 3/30 | 15.4% | 59.311 ms | 1.790 ms |

The low Hellman coverage is itself informative. With \(mt/N=1\), the familiar

\[
1-e^{-mt/N}\approx 63.2\%
\]

is an **independent-sample occupancy reference**, not the expected coverage of
these iterated chains. Because every chain repeatedly applies one fixed
mapping, chains merge. The measured Hellman tables cover only about
16–17% of the reduced state space in this configuration.

For distinguished points, the median table covers about 15% of the state
space, and many starts merge onto the same distinguished endpoint.

The full generated analysis is in
[`docs/VERIFIED_RESULTS.md`](docs/VERIFIED_RESULTS.md). Raw rows and machine/JDK
metadata are in [`experiments/results/`](experiments/results/).

## Reproduce

Requirements:

- Java 17 or newer;
- Maven 3.9+;
- Python 3 for the Markdown summary script.

Run the complete tests:

```bash
mvn test
```

Re-run the curated benchmark and regenerate its summary:

```bash
./scripts/run-verified-small.sh
```

The benchmark script writes:

```text
experiments/results/verified-small.csv
experiments/results/verified-small-coverage.csv
experiments/results/verified-small-environment.txt
docs/VERIFIED_RESULTS.md
```

Timing values are machine-dependent. Exact coverage and deterministic seeded
table construction are the more stable algorithmic outputs.

## Historical presentation and project

The preserved historical material includes topics beyond the modern Java
benchmark, including:

- canonical-basis to normal-basis transformations;
- finite-field isomorphisms;
- computations involving \(\delta\);
- non-LUT implementation ideas;
- a secret-key recovery section;
- an AES-throughput presentation section;
- the DES practical work represented by the Java prototype.

These topics come from the original coursework presentation. The modern Java
code in this repository **does not implement an AES hardware design**, so the
historical AES material is not presented as a benchmark result of the current
implementation.

Historical practical-work timing tables are transcribed separately in
[`docs/HISTORICAL_RESULTS.md`](docs/HISTORICAL_RESULTS.md). They are not mixed
with the newly reproduced measurements.

## Repository layout

```text
.
├── research-note/               # updated research note (LaTeX + PDF)
├── src/                         # modern Java 17 reference implementation/tests
├── experiments/results/         # curated CSV + environment metadata
├── scripts/                     # reproducible benchmark/summary commands
├── docs/
│   ├── METHODOLOGY.md
│   ├── VERIFIED_RESULTS.md
│   ├── HISTORICAL_RESULTS.md
│   ├── original-presentation.pdf
│   └── original-README.md
└── legacy/
    └── original-eclipse-prototype/
```

## Roadmap

The Java implementation is the current **reference implementation**. The next
implementation phase is a Rust port:

```text
Java reference semantics
        ↓
deterministic test vectors
        ↓
Rust implementation
        ↓
cross-language equivalence
        ↓
performance comparison
```

The Rust implementation should reproduce the same state encoding, chain
transitions, endpoints, exact coverage, and recovery decisions before any
performance claim is made.

## Provenance and reuse

The historical presentation and original Eclipse coursework are coauthored.
The modernized implementation and reproducibility layer were developed later
from that artifact. See [`docs/PROVENANCE.md`](docs/PROVENANCE.md).

A repository-wide open-source license is intentionally **not declared at this
stage**, because reuse rights for the coauthored historical material should not
be inferred from the modernization work.
