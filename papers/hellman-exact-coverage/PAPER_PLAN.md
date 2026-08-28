# ePrint Paper 1 — Exact Coverage of Hellman and Distinguished-Point Tables

## Working title

**Exact Finite-State Coverage of Hellman and Distinguished-Point Time–Memory
Tradeoffs: A Reproducible Study on Reduced-DES Mappings**

## Scientific positioning

This paper must **not** claim that chain merging, coalescence, coverage loss,
false alarms, the matrix stopping rule, distinguished points, or rainbow
reductions are new. Those phenomena and their analyses are established in the
TMTO literature.

The paper's contribution is a reproducible, exact finite-state study of a
concrete DES-derived iteration map, with:

1. exact state-space coverage rather than proxy counts;
2. comparison with established random-function coverage theory;
3. full functional-graph measurements for finite reduced state spaces;
4. bounded distinguished-point measurements including truncation;
5. independent Java and Rust implementations;
6. shared experiment plans before any cross-language timing claim;
7. raw committed outputs and environment metadata.

## Critical literature correction

For a Hellman matrix with random-function assumptions, Ma and Hong (2009)
define expected coverage rate ECR and give the recurrence

    s_0 = 0,
    s_{k+1} = 1 - exp(-m/N) exp(-s_k),
    ECR(N,m,t) = (N/(m t)) s_t.

For the repository's current configuration

    N = 65,536
    m = 1,024
    t = 64

this predicts approximately

    s_t = 0.1665143
    expected distinct coverage ≈ 16.6514% of N.

The measured Hellman median is about 16.8%, so the current experiment is
consistent with established random-function theory. The old independent
occupancy number 1-exp(-mt/N) is only an intentionally naive baseline and must
not be presented as the expected Hellman coverage.

Also note that the standard Hellman matrix-stopping regime is m t^2 ≈ N.
The current stress configuration has m t = N and m t^2 = 64 N. This distinction
must be explicit.

## Modular paper parts

### Part A — Front matter
- `sections/00-abstract.tex`
- title/authorship/keywords in `main.tex`
- finalize only after all experiment tables are frozen

### Part B — Motivation and literature
- `sections/01-introduction.tex`
- `sections/02-related-work.tex`

### Part C — Formal model and theory
- `sections/03-model.tex`
- `sections/04-theory.tex`
- define N,m,t, reductions, tables, coverage, false alarms, DP stopping
- reproduce the Ma–Hong random-function baseline
- distinguish standard matrix stopping from our parameter sweeps

### Part D — Implementations and experimental method
- `sections/05-implementation.tex`
- `sections/06-experiments.tex`
- shared Java/Rust trial plan is mandatory before speed comparison
- record exact commit/toolchain/machine metadata

### Part E — Results
- `sections/07-results.tex`
- random-function baseline vs DES-derived mapping
- coverage-vs-chain-shape
- DP difficulty/truncation
- endpoint multiplicity/merging/cycles
- Java/Rust semantic equality
- timing only after identical experiment plan

### Part F — Interpretation and reproducibility
- `sections/08-discussion.tex`
- `sections/09-reproducibility.tex`
- `sections/10-conclusion.tex`

## Required experiment matrix before submission

At minimum:

- b ∈ {12, 14, 16, 18};
- multiple (m,t) pairs at equal precomputation budget m t;
- standard matrix-stopping points m t^2 ≈ N;
- the current stress point (m,t)=(1024,64) at b=16;
- random-function maps with the same N and starts;
- DES-derived maps with the same experiment plan;
- distinguished-point d ∈ {4,6,8} with multiple chain bounds.

For each run record:

- exact covered states;
- coverage fraction;
- exact recovery;
- distinct endpoints;
- endpoint multiplicity;
- chain merges;
- cycle/self-intersection statistics where available;
- DP truncations;
- candidates / false alarms;
- offline and online work;
- memory entries;
- environment metadata.

## Submission gates

1. Literature claims checked against primary sources.
2. No "new" claim for known TMTO phenomena.
3. Shared Java/Rust experiment plans committed.
4. Random-function theory baseline implemented and checked.
5. All paper numbers generated from committed outputs.
6. Abstract/contributions rewritten after final results.
7. Authorship/provenance explicitly resolved before submission.
8. PDF compiled twice, references resolved, no warnings affecting content.
9. PDF visually inspected.
10. Submit to Cryptology ePrint Archive; posting time remains subject to editor approval.
