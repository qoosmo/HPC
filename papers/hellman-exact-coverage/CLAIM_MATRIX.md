# Claim matrix

| Candidate statement | Status | Evidence / literature | Paper treatment |
|---|---|---|---|
| Hellman chains merge and lose coverage | Known | Hellman 1980; Ma–Hong 2009; Avoine–Junod–Oechslin 2008 | Related work, not novelty |
| `1-exp(-mt/N)` is expected Hellman coverage | False as a Hellman model | Independent-sampling heuristic only | Explicitly reject as Hellman prediction |
| Ma–Hong recurrence predicts current `b=16,m=1024,t=64` coverage | Verified computationally | `analysis/hellman_coverage_theory.py` | Theory baseline |
| Current measured Hellman coverage is ≈16.8% | Measured | committed Java/Rust result files | Result |
| Random-function theory predicts ≈16.6514% | Literature + computed | Ma–Hong recurrence | Result comparison |
| Reduced-DES map follows random-function Hellman coverage across tested grid | Measured | 840-row DES/random sweep + Ma--Hong comparison | Result, limited to tested maps/parameters |
| Java and Rust are semantically identical for the committed b=16 shared plan | Verified | byte-identical 30-trial semantic CSV outputs | Result / implementation evidence |
| Java is faster/slower than Rust | Not established | current trial generators differ | Do not claim |
| Bounded DP truncation is explained by short-bound fresh-sample behavior plus exact finite-graph reachability floors | Measured / exact finite-state | 540-row DP sweep + whole-state reverse reachability | Result, not a claim of new DP technique |
| Finite-field/AES representation work belongs in this paper | No | separate research direction | Remove except historical note if needed |
