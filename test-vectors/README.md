# Java/Rust equivalence vectors

`java-rust-reference.csv` is a deterministic cross-language fixture for the
reduced-DES semantics used by this repository.

Each row fixes:

- effective state dimension;
- reduced state;
- canonical DES key bytes including odd parity;
- DES/ECB/PKCS#5-compatible ciphertext of the common plaintext fixture;
- reduced state after applying the historical reduction;
- a fixed chain length;
- the resulting chain endpoint.

The fixture is consumed by both the Java and Rust test suites. It is a
correctness gate, not a performance benchmark.
