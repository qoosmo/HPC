# Historical mathematics reconstruction

Canonical historical source:

```text
docs/original-presentation.pdf
```

SHA-256:

```text
4003194fdfe82e84bcc32876c8d9ba5042d12dc5f14da726a4bd6e3edc2e6bec
```

The PDF is preserved unchanged.

## Reconstructed slide groups

| Slides | Content used in the paper |
| --- | --- |
| 4–5 | AES S-box: affine map after inversion; first tower-field isomorphism |
| 6–8 | `GF(16)` normal basis, exact multiplication formula, squaring permutation |
| 10–12 | generator-based isomorphism construction; exact `8×8` binary map and inverse |
| 14–15 | parallel matrix implementation and Hamming-weight optimization objective |
| 17–19 | second `GF(16) -> GF(4)` factorization and non-LUT inversion observation |
| 20 | secret-key recovery slide says `PROOF ON BOARD`; no recoverable proof in the PDF |
| 21 | AES 200 MHz slide says `PROOF ON BOARD`; no recoverable derivation in the PDF |

## Independent verification

`scripts/verify-historical-math.py` checks:

1. the slide-derived `GF(16)` multiplication formula on all 256 input pairs;
2. the squaring permutation on all 16 elements;
3. both inverse identities for the historical `8×8` binary matrices;
4. the displayed matrix Hamming weights.

No missing board-only result is promoted into the paper.
