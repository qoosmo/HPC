# Provenance

## Original research project

This repository originates from an **M2P SCCI master's research project at Ensimag–UJF** developed by:

- Abdourahmane Sakho
- Ali Mkhida
- Maad El Yadari

The preserved presentation documents a research project in cryptography covering finite-field representation changes, AES-oriented arithmetic, and practical key-recovery/time-memory-tradeoff experiments.

## Preserved historical artifacts

The canonical historical assets are:

- `docs/original-presentation.pdf`
- `docs/original-README.md`
- `legacy/original-eclipse-prototype/Hpc/`

The presentation is preserved byte-for-byte. Its SHA-256 is:

```text
4003194fdfe82e84bcc32876c8d9ba5042d12dc5f14da726a4bd6e3edc2e6bec
```

The original Java source is preserved with its historical encoding and Eclipse metadata rather than silently rewritten.

## Modern research layer

The modern repository adds, separately from the historical artifacts:

- a Java 17 reference implementation;
- corrected effective-bit DES state semantics;
- deterministic tests and experiments;
- exact coverage analysis;
- a slide-by-slide mathematical reconstruction;
- an ePrint-style research note;
- a Rust reference implementation;
- Java/Rust equivalence fixtures;
- continuous integration.

## Historical limits

Some original slides contain only `PROOF ON BOARD`. Missing board derivations are not reconstructed from imagination and are explicitly treated as unavailable historical material.

## Reuse

No repository-wide open-source license is currently declared because the historical artifacts are coauthored. A future licensing split can license newly written implementation code independently while keeping historical assets under their original rights.
