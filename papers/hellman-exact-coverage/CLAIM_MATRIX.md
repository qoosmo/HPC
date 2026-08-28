# Claim matrix

| Candidate statement | Status | Evidence / literature | Paper treatment |
|---|---|---|---|
| Hellman chains merge and lose coverage | Known | Hellman 1980; Ma–Hong 2009; Avoine–Junod–Oechslin 2008 | Related work, not novelty |
| `1-exp(-mt/N)` is expected Hellman coverage | False as a Hellman model | Independent-sampling heuristic only | Explicitly reject as Hellman prediction |
| Ma–Hong recurrence predicts current `b=16,m=1024,t=64` coverage | Verified computationally | `analysis/hellman_coverage_theory.py` | Theory baseline |
| Current measured Hellman coverage is ≈16.8% | Measured | committed Java/Rust result files | Result |
| Random-function theory predicts ≈16.6514% | Literature + computed | Ma–Hong recurrence | Result comparison |
| Reduced-DES map follows random-function coverage across parameter grid | Open | needs sweeps | Potential contribution |
| Java and Rust are semantically identical for the committed b=16 shared plan | Verified | byte-identical 30-trial semantic CSV outputs | Result / implementation evidence |
| Java is faster/slower than Rust | Not established | current trial generators differ | Do not claim |
| DP truncation/collision behavior matches established theory | Open | needs theory + sweeps | Potential contribution |
| Finite-field/AES representation work belongs in this paper | No | separate research direction | Remove except historical note if needed |
