# Research program

## Core questions

### RQ1 — Representation engineering

How do polynomial, normal, and tower-field representations change the concrete XOR/multiplication/squaring cost of AES-like finite-field arithmetic?

Evidence target:

- exact basis/isomorphism matrices;
- algebraic verification;
- executable finite-field implementation;
- XOR-count/depth analysis;
- eventually synthesis or formal circuit evidence.

### RQ2 — Fixed-map Hellman coverage

For

```math
F(x)=R(E_{K(x)}(P)),
```

how does functional-graph coalescence change exact Hellman table coverage relative to independent-sample occupancy heuristics?

Evidence target:

- exact coverage;
- component/cycle statistics;
- endpoint multiplicities;
- parameter sweeps over `m`, `t`, and `b`.

### RQ3 — Distinguished points

How do distinguished-point difficulty, chain bounds, endpoint collisions, and truncation interact with represented-state coverage and online recovery work?

### RQ4 — Reduction families

How much coverage is recovered by table-dependent reductions, multiple Hellman tables, or rainbow-style column reductions compared with the current fixed reduction?

### RQ5 — Implementation equivalence and performance

Can Java and Rust reproduce identical state encodings, ciphertexts, reductions, chain endpoints, coverage, and recovery decisions before performance comparison?

## Current evidence

- original master's research presentation preserved exactly;
- historical finite-field equations reconstructed from the presentation;
- exhaustive verifier for the slide-derived `GF(16)` arithmetic and isomorphism matrices;
- Java 17 reference with automated tests;
- 30-trial Java benchmark and exact coverage results;
- initial Rust reference implementation;
- shared Java/Rust reference vectors.
- deterministic Rust experiment harness and measured 16-bit run;

## Evidence policy

A paper claim should be labeled internally as one of:

1. `HISTORICAL` — recoverable from the preserved original research artifact;
2. `VERIFIED` — checked by committed code/tests;
3. `MEASURED` — produced by a committed experiment with environment metadata;
4. `CONJECTURE` — plausible but not established;
5. `FUTURE` — explicitly not yet implemented or measured.

The ePrint draft should not silently convert categories 4 or 5 into results.
