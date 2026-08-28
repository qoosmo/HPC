# Provenance

## Original coursework artifact

The repository originated from an M2P SCCI project at Ensimag–UJF credited in
the original presentation to:

- Abdourahmane Sakho
- Ali Mkhida
- Maad El Yadari

The original assets are preserved as:

- `original-presentation.pdf`;
- `original-README.md`;
- `../legacy/original-eclipse-prototype/Hpc/`.

The original Java source is preserved with its historical file encoding and
Eclipse project metadata rather than silently rewritten in place.

## Modern reproducibility layer

The modern source tree under `../src/` is a separate Java 17 implementation
created to make the practical-work algorithms testable and reproducible.

It introduces:

- an explicit effective DES state model;
- deterministic tests;
- indexed Hellman endpoint lookup;
- bounded distinguished-point chains;
- exact candidate verification;
- seeded experiment generation;
- exact state-coverage analysis;
- machine/JDK metadata for curated runs;
- continuous integration.

## Historical claims versus reproduced claims

The original presentation contains timing tables and broader hardware/AES
material. Those claims are preserved for provenance in
`HISTORICAL_RESULTS.md`.

`VERIFIED_RESULTS.md` contains only measurements produced by the modern
implementation and its checked-in experiment scripts.

No historical throughput claim is treated as a result of the modern Java code.
