# Contributing

This repository is primarily a reproducibility and research artifact.

Before proposing a change:

1. keep historical files under `legacy/` and the original presentation
   unchanged;
2. do not replace historical claims with modern claims or vice versa;
3. add tests for algorithmic changes;
4. run `mvn test`;
5. run `git diff --check`;
6. if benchmark methodology changes, regenerate the curated result set and
   explain why the new measurements are comparable.

Performance claims should be backed by committed experiment output and recorded
environment metadata.
