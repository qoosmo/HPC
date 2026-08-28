# Roadmap to ePrint

## Completed

- [x] Preserve the original master's research presentation unchanged.
- [x] Preserve the original Eclipse/Java prototype.
- [x] Correct the reduced DES state model to effective key bits.
- [x] Implement reproducible Java exhaustive/Hellman/distinguished-point experiments.
- [x] Add exact table-coverage analysis.
- [x] Reconstruct recoverable historical finite-field mathematics.
- [x] Add a finite-field reconstruction verifier.
- [x] Create an ePrint-style LaTeX paper draft.
- [x] Add the first Rust reference implementation.
- [x] Add shared Java/Rust reference vectors.
- [x] Add a deterministic Rust experiment harness with exact coverage output.
- [x] Commit a first measured Rust 16-bit/30-trial benchmark with environment metadata.

## Immediate

- [x] Get the Rust reference implementation CI green on the canonical GitHub branch.
- [ ] Get the new Rust experiment harness CI green on its PR.
- [ ] Extend cross-language vectors to table lookup, collision, truncation, and coverage cases.
- [ ] Implement the historical `GF(16)` and tower-field arithmetic as executable Rust modules.
- [ ] Implement the AES non-LUT S-box path and compare against the standard S-box.
- [ ] Add exact functional-graph statistics for the 16-bit state space.
- [ ] Sweep Hellman `m,t` and distinguished-point parameters.
- [ ] Add multiple-reduction and rainbow-table baselines.

## Paper-quality evidence

- [ ] Separate deterministic algorithmic results from machine-dependent timing.
- [ ] Add confidence intervals or full distributions where random targets are sampled.
- [ ] Add CPU/environment metadata for Rust benchmarks.
- [ ] Compare Java/Rust only after semantic equivalence gates pass.
- [ ] Re-run every table/figure from a single reproducibility command.
- [ ] Get original collaborators' review and authorship decision.
- [ ] External technical review.
- [ ] Prepare IACR ePrint source bundle and submission metadata.

## Possible later work

- [ ] SIMD/parallel Rust implementation.
- [ ] Hardware implementation of the finite-field path.
- [ ] Formal verification of selected field identities/circuit maps.
- [ ] Larger reduced state spaces where exact enumeration remains feasible.
