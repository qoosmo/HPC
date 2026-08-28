## Summary

Describe the research, implementation, documentation, or infrastructure change.

## Evidence

- [ ] Java verification passes (`mvn -B -ntp verify`) or is not affected.
- [ ] Rust format/tests/Clippy pass or are not affected.
- [ ] Historical finite-field verifier passes or is not affected.
- [ ] `git diff --check` passes.
- [ ] New numerical claims point to committed output and environment metadata.
- [ ] New mathematical claims are identified as proved, computationally checked, conjectural, or future work.

## Historical integrity

- [ ] `docs/original-presentation.pdf` is unchanged.
- [ ] Preserved files under `legacy/` are unchanged unless this PR is explicitly archival.

## Cross-language semantics

- [ ] Shared Java/Rust fixtures were updated if common semantics changed.
- [ ] No Java-vs-Rust speedup claim is made unless both implementations consume the same experiment plan.

## Licensing / provenance

- [ ] New files are compatible with the licensing boundary in `NOTICE`.
- [ ] Third-party material and historical authorship are attributed.
